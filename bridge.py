"""
DKMS-DEX Bridge: Minimal OIDC Provider for DID-based authentication.

Acts as an upstream OIDC identity provider that DEX connects to via its
built-in OIDC connector. Users authenticate by signing a challenge nonce
with their DID private key (Ed25519 did:key supported).
"""

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import jwt
import uvicorn
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_cfg_path = Path(__file__).parent / "config.yaml"
with open(_cfg_path) as f:
    CONFIG = yaml.safe_load(f)

ISSUER = CONFIG["issuer"]

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="DKMS-DEX Bridge", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

# ---------------------------------------------------------------------------
# RSA signing key (for ID tokens)
# ---------------------------------------------------------------------------

_rsa_private_key: rsa.RSAPrivateKey
_rsa_public_numbers: rsa.RSAPublicNumbers
_kid: str


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _init_rsa():
    global _rsa_private_key, _rsa_public_numbers, _kid

    key_path = CONFIG.get("rsa_key_path")
    if key_path:
        pem = Path(key_path).read_bytes()
        _rsa_private_key = serialization.load_pem_private_key(pem, password=None)
    else:
        _rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    _rsa_public_numbers = _rsa_private_key.public_key().public_numbers()
    # kid = SHA-256 thumbprint of the public key DER
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
    did: str
    redirect_uri: str
    nonce: str | None
    expires: float


@dataclass
class AccessToken:
    did: str
    expires: float


_challenges: dict[str, PendingChallenge] = {}
_auth_codes: dict[str, AuthCode] = {}
_access_tokens: dict[str, AccessToken] = {}

# ---------------------------------------------------------------------------
# DID key helpers
# ---------------------------------------------------------------------------

# Base58-btc alphabet (Bitcoin)
_B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s: str) -> bytes:
    """Decode a base58-btc string."""
    n = 0
    for ch in s.encode():
        n = n * 58 + _B58.index(ch)
    result = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    # preserve leading zeros
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + result


def _resolve_did_key(did: str) -> ed25519.Ed25519PublicKey:
    """Extract Ed25519 public key from a did:key URI.

    Supports did:key:z6Mk... (multicodec 0xed01 = Ed25519 pub key).
    """
    if not did.startswith("did:key:z"):
        raise ValueError("Only did:key with base58-btc (z prefix) is supported")

    multibase_value = did.split(":")[-1]
    # strip 'z' (base58-btc identifier)
    raw = _b58decode(multibase_value[1:])

    # multicodec: 0xed 0x01 for Ed25519 public key
    if len(raw) < 2 or raw[0] != 0xED or raw[1] != 0x01:
        raise ValueError("Unsupported multicodec (expected Ed25519 0xed01)")

    pub_bytes = raw[2:]
    if len(pub_bytes) != 32:
        raise ValueError(f"Invalid Ed25519 public key length: {len(pub_bytes)}")

    return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)


def _verify_did_signature(did: str, challenge: str, signature_hex: str) -> bool:
    """Verify that signature_hex is a valid Ed25519 signature of challenge under did's key."""
    try:
        pub = _resolve_did_key(did)
        sig = bytes.fromhex(signature_hex)
        pub.verify(sig, challenge.encode())
        return True
    except Exception:
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
        "request": request, "challenge": challenge, "state": state,
    })


@app.post("/authorize/callback")
def authorize_callback(state: str = Form(...), did: str = Form(...), signature: str = Form(...)):
    pending = _challenges.pop(state, None)
    if not pending or time.time() > pending.expires:
        raise HTTPException(400, "Invalid or expired challenge")

    if not _verify_did_signature(did, pending.challenge, signature.strip()):
        raise HTTPException(401, "DID signature verification failed")

    code = secrets.token_urlsafe(32)
    _auth_codes[code] = AuthCode(
        did=did,
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
    # Support both form-encoded and handle Basic auth
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
    did_short = entry.did.split(":")[-1][:12]

    id_token_claims = {
        "iss": ISSUER,
        "sub": entry.did,
        "aud": CONFIG["client_id"],
        "exp": now + CONFIG["id_token_ttl"],
        "iat": now,
        "name": entry.did,
        "preferred_username": entry.did,
        "email": f"{did_short}@dkms.local",
        "email_verified": True,
    }
    if entry.nonce:
        id_token_claims["nonce"] = entry.nonce

    id_token = jwt.encode(id_token_claims, _rsa_private_key, algorithm="RS256", headers={"kid": _kid})

    access_tok = secrets.token_urlsafe(32)
    _access_tokens[access_tok] = AccessToken(did=entry.did, expires=now + CONFIG["id_token_ttl"])

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

    did_short = entry.did.split(":")[-1][:12]
    return {
        "sub": entry.did,
        "name": entry.did,
        "preferred_username": entry.did,
        "email": f"{did_short}@dkms.local",
        "email_verified": True,
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run("bridge:app", host=CONFIG["host"], port=CONFIG["port"], reload=True)
