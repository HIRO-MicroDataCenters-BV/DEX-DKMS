"""
DKMS-DEX Bridge: Minimal OIDC Provider for KERI-based authentication.

Acts as an upstream OIDC identity provider that DEX connects to via its
built-in OIDC connector. Users authenticate by proving control of a
KERI AID (Autonomic Identifier) — the bridge resolves the AID via OOBI
on configured witnesses and verifies an Ed25519 signature of a challenge nonce.
"""

import base64
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import httpx
import jwt
import uvicorn
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

log = logging.getLogger("dkms-bridge")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_cfg_path = Path(__file__).parent / "config.yaml"
with open(_cfg_path) as f:
    CONFIG = yaml.safe_load(f)

ISSUER = CONFIG["issuer"]
WITNESSES: list[str] = CONFIG.get("witnesses", ["http://localhost:3232"])

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="DKMS-DEX Bridge", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

# ---------------------------------------------------------------------------
# RSA signing key (for OIDC ID tokens)
# ---------------------------------------------------------------------------

_rsa_private_key: rsa.RSAPrivateKey
_rsa_public_numbers: rsa.RSAPublicNumbers
_kid: str


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """Decode base64url without padding."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _init_rsa():
    global _rsa_private_key, _rsa_public_numbers, _kid

    key_path = CONFIG.get("rsa_key_path")
    if key_path:
        pem = Path(key_path).read_bytes()
        _rsa_private_key = serialization.load_pem_private_key(pem, password=None)
    else:
        _rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    _rsa_public_numbers = _rsa_private_key.public_key().public_numbers()
    pub_der = _rsa_private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    _kid = hashlib.sha256(pub_der).hexdigest()[:16]


_init_rsa()

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------


@dataclass
class PendingChallenge:
    challenge: str
    redirect_uri: str
    client_id: str
    scope: str
    nonce: str | None
    expires: float


@dataclass
class AuthCode:
    aid: str
    redirect_uri: str
    nonce: str | None
    expires: float


@dataclass
class AccessToken:
    aid: str
    expires: float


_challenges: dict[str, PendingChallenge] = {}
_auth_codes: dict[str, AuthCode] = {}
_access_tokens: dict[str, AccessToken] = {}

# ---------------------------------------------------------------------------
# KERI / OOBI helpers
# ---------------------------------------------------------------------------

# KERI uses base64url-encoded keys with a 1-char prefix denoting the type.
# 'D' prefix = Ed25519 verification key (44 chars total: 1 prefix + 43 base64url)
# '1AAA' prefix = Ed25519 (88 chars total, qualified base64)

KERI_ED25519_PREFIX = "D"


def _extract_ed25519_key_from_keri(key_str: str) -> ed25519.Ed25519PublicKey:
    """Extract Ed25519 public key from a KERI key string.

    KERI uses a 1-character type code prefix followed by base64url-encoded key material.
    For Ed25519: prefix 'D', followed by 43 chars of base64url = 32 bytes.
    """
    if key_str.startswith(KERI_ED25519_PREFIX) and len(key_str) == 44:
        key_bytes = _b64url_decode(key_str[1:])
    elif key_str.startswith("1AAA") and len(key_str) == 48:
        # Qualified base64 format: 4-char prefix + 44 chars
        key_bytes = _b64url_decode(key_str[4:])
    else:
        raise ValueError(f"Unsupported KERI key format: {key_str[:4]}... (len={len(key_str)})")

    if len(key_bytes) != 32:
        raise ValueError(f"Invalid Ed25519 key length: {len(key_bytes)}")

    return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)


async def _resolve_oobi(aid: str, oobi_url: str | None = None) -> dict:
    """Resolve a KERI AID via OOBI to get the inception/key-state event.

    Tries the provided oobi_url first, then falls back to configured witnesses.
    Returns the parsed KERI event JSON containing the signing keys.
    """
    urls_to_try = []
    if oobi_url:
        urls_to_try.append(oobi_url.rstrip("/"))
    for w in WITNESSES:
        urls_to_try.append(f"{w.rstrip('/')}/oobi/{aid}")

    async with httpx.AsyncClient(timeout=10.0) as client:
        for url in urls_to_try:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return _parse_oobi_response(resp.text, aid)
            except httpx.RequestError as exc:
                log.warning("OOBI request to %s failed: %s", url, exc)
                continue

    raise ValueError(f"Could not resolve AID {aid} via any witness")


def _parse_oobi_response(body: str, aid: str) -> dict:
    """Parse OOBI response which may contain KERI JSON events with CESR attachments.

    The response body typically contains one or more JSON KERI events
    (possibly with CESR signature attachments appended). We look for
    the inception event (type 'icp') or the latest key-state event
    matching the requested AID.
    """
    events = _extract_keri_events(body)

    # Find the inception event for this AID, or fall back to any event with matching 'i' field
    for evt in reversed(events):
        if evt.get("i") == aid and evt.get("t") in ("icp", "rot", "dip", "drt"):
            return evt

    # If we got exactly one event and it looks like it has keys, use it
    if events and "k" in events[0]:
        return events[0]

    raise ValueError(f"No key event found for AID {aid} in OOBI response")


def _extract_keri_events(body: str) -> list[dict]:
    """Extract JSON KERI events from a response body.

    KERI responses may contain multiple JSON objects concatenated together,
    possibly interleaved with CESR attachment strings (starting with '-').
    """
    events = []
    i = 0
    while i < len(body):
        # Skip whitespace and CESR attachment lines
        if body[i] in (" ", "\n", "\r", "\t", "-"):
            i += 1
            continue

        if body[i] == "{":
            # Find matching closing brace (simple depth counter)
            depth = 0
            start = i
            while i < len(body):
                if body[i] == "{":
                    depth += 1
                elif body[i] == "}":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            try:
                events.append(json.loads(body[start:i]))
            except json.JSONDecodeError:
                pass
        else:
            i += 1

    return events


def _get_signing_keys(event: dict) -> list[str]:
    """Extract signing key list from a KERI event."""
    keys = event.get("k", [])
    if not keys:
        raise ValueError("KERI event has no signing keys ('k' field)")
    return keys


async def _verify_keri_signature(aid: str, oobi_url: str | None,
                                  challenge: str, signature_b64: str) -> bool:
    """Verify a KERI AID's Ed25519 signature over a challenge.

    1. Resolve the AID via OOBI to get the current signing key(s)
    2. Decode the base64url signature
    3. Verify against each signing key (threshold=1 for simplicity)
    """
    try:
        event = await _resolve_oobi(aid, oobi_url)
        keys = _get_signing_keys(event)

        sig_bytes = _b64url_decode(signature_b64.strip())
        challenge_bytes = challenge.encode()

        for key_str in keys:
            try:
                pub = _extract_ed25519_key_from_keri(key_str)
                pub.verify(sig_bytes, challenge_bytes)
                return True
            except Exception:
                continue

        return False
    except Exception as exc:
        log.error("KERI signature verification failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# OIDC Endpoints
# ---------------------------------------------------------------------------


@app.get("/.well-known/openid-configuration")
def openid_configuration():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported": ["sub", "name", "email", "email_verified", "preferred_username"],
    }


@app.get("/jwks")
def jwks():
    n_bytes = _rsa_public_numbers.n.to_bytes(256, "big")
    e_bytes = _rsa_public_numbers.e.to_bytes(3, "big")
    return {
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": _kid,
                "n": _b64url(n_bytes),
                "e": _b64url(e_bytes),
            }
        ]
    }


@app.get("/authorize", response_class=HTMLResponse)
def authorize(request: Request, client_id: str, redirect_uri: str, response_type: str,
              scope: str = "openid", state: str = "", nonce: str | None = None):
    if client_id != CONFIG["client_id"]:
        raise HTTPException(403, "Unknown client_id")
    if response_type != "code":
        raise HTTPException(400, "Only response_type=code is supported")

    challenge = secrets.token_hex(32)
    _challenges[state] = PendingChallenge(
        challenge=challenge,
        redirect_uri=redirect_uri,
        client_id=client_id,
        scope=scope,
        nonce=nonce,
        expires=time.time() + CONFIG["auth_code_ttl"],
    )
    return templates.TemplateResponse("authorize.html", {
        "request": request,
        "challenge": challenge,
        "state": state,
        "witnesses": WITNESSES,
    })


@app.post("/authorize/callback")
async def authorize_callback(
    state: str = Form(...),
    aid: str = Form(...),
    oobi_url: str = Form(""),
    signature: str = Form(...),
):
    pending = _challenges.pop(state, None)
    if not pending or time.time() > pending.expires:
        raise HTTPException(400, "Invalid or expired challenge")

    if not await _verify_keri_signature(aid, oobi_url or None, pending.challenge, signature.strip()):
        raise HTTPException(401, "KERI signature verification failed")

    code = secrets.token_urlsafe(32)
    _auth_codes[code] = AuthCode(
        aid=aid,
        redirect_uri=pending.redirect_uri,
        nonce=pending.nonce,
        expires=time.time() + CONFIG["auth_code_ttl"],
    )

    params = urlencode({"code": code, "state": state})
    return RedirectResponse(f"{pending.redirect_uri}?{params}", status_code=302)


def _authenticate_client(request_client_id: str | None, request_client_secret: str | None,
                          authorization: str | None) -> bool:
    """Verify client credentials via post body or Basic auth."""
    cid, csec = request_client_id, request_client_secret

    if authorization and authorization.startswith("Basic "):
        decoded = base64.b64decode(authorization[6:]).decode()
        cid, csec = decoded.split(":", 1)

    return cid == CONFIG["client_id"] and csec == CONFIG["client_secret"]


@app.post("/token")
async def token(request: Request):
    form = await request.form()
    grant_type = form.get("grant_type")
    code = form.get("code")
    redirect_uri = form.get("redirect_uri")
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    auth_header = request.headers.get("authorization")

    if grant_type != "authorization_code":
        raise HTTPException(400, "Unsupported grant_type")

    if not _authenticate_client(client_id, client_secret, auth_header):
        raise HTTPException(401, "Invalid client credentials")

    entry = _auth_codes.pop(code, None)
    if not entry or time.time() > entry.expires:
        raise HTTPException(400, "Invalid or expired authorization code")

    if redirect_uri and entry.redirect_uri != redirect_uri:
        raise HTTPException(400, "redirect_uri mismatch")

    now = int(time.time())
    aid_short = entry.aid[:12]

    id_token_claims = {
        "iss": ISSUER,
        "sub": entry.aid,
        "aud": CONFIG["client_id"],
        "exp": now + CONFIG["id_token_ttl"],
        "iat": now,
        "name": entry.aid,
        "preferred_username": entry.aid,
        "email": f"{aid_short}@dkms.bridge",
        "email_verified": True,
    }
    if entry.nonce:
        id_token_claims["nonce"] = entry.nonce

    id_token = jwt.encode(id_token_claims, _rsa_private_key, algorithm="RS256", headers={"kid": _kid})

    access_tok = secrets.token_urlsafe(32)
    _access_tokens[access_tok] = AccessToken(aid=entry.aid, expires=now + CONFIG["id_token_ttl"])

    return JSONResponse({
        "access_token": access_tok,
        "token_type": "Bearer",
        "expires_in": CONFIG["id_token_ttl"],
        "id_token": id_token,
    })


@app.get("/userinfo")
def userinfo(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")

    tok = authorization[7:]
    entry = _access_tokens.get(tok)
    if not entry or time.time() > entry.expires:
        raise HTTPException(401, "Invalid or expired access token")

    aid_short = entry.aid[:12]
    return {
        "sub": entry.aid,
        "name": entry.aid,
        "preferred_username": entry.aid,
        "email": f"{aid_short}@dkms.bridge",
        "email_verified": True,
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run("bridge:app", host=CONFIG["host"], port=CONFIG["port"], reload=True)
