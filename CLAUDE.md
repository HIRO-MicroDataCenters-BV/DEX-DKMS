# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DKMS-DEX Bridge: A minimal OIDC Provider (FastAPI) that bridges [THCLab's KERI-based DKMS](https://github.com/THCLab/dkms-demo) to DEX. DEX connects to this bridge via its built-in OIDC connector. Users authenticate by proving control of a KERI AID — the bridge resolves the AID via OOBI on witnesses and verifies an Ed25519 signature of a challenge nonce.

## Setup & Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python bridge.py              # starts on port 8900
```

Requires running DKMS infrastructure (witnesses on ports 3232-3234, watcher on 3235).

## Architecture

Single-module design (`bridge.py`) acting as an OIDC Provider:

**Auth flow:** DEX → `/authorize` (renders challenge nonce) → user provides AID + signature → `POST /authorize/callback` (resolves AID via OOBI on witnesses, extracts Ed25519 key from KERI event, verifies signature, issues auth code) → DEX calls `/token` (exchanges code for JWT ID token) → DEX calls `/userinfo`

**OIDC endpoints:** `/.well-known/openid-configuration`, `/jwks`, `/authorize`, `/authorize/callback`, `/token`, `/userinfo`

**KERI integration:**
- AID resolution via OOBI: `GET {witness}/oobi/{AID}` returns KERI events (inception/rotation)
- Signing keys extracted from KERI event `k` field (Ed25519, prefix `D` = 44-char base64url)
- KERI event JSON parsed from OOBI response body (may contain concatenated events + CESR attachments)
- Signature format: base64url-encoded Ed25519 signature

**Key decisions:**
- OIDC ID tokens signed with RS256 (ephemeral RSA key by default, or load PEM via `config.yaml`)
- Only Ed25519 KERI keys supported (prefix `D` or `1AAA`)
- In-memory stores for auth codes, access tokens, and challenges (not production-ready)
- Synthesized email: `{aid_short}@dkms.bridge` since DEX expects an email claim

**Config:** `config.yaml` — issuer URL, client credentials, witness URLs, token TTLs
**DEX example:** `dex-config.yaml` — sample DEX config wiring its OIDC connector to this bridge
