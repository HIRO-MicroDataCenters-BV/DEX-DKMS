# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DKMS-DEX Bridge: A minimal OIDC Provider (FastAPI) that bridges Decentralized Key Management (DID-based identity) to DEX. DEX connects to this bridge via its built-in OIDC connector. Users authenticate by signing a challenge nonce with their DID private key (Ed25519 `did:key` method).

## Setup & Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python bridge.py              # starts on port 8900
# or
uvicorn bridge:app --port 8900 --reload
```

## Architecture

Single-module design (`bridge.py`) acting as an OIDC Provider:

**Auth flow:** DEX → `/authorize` (renders DID challenge) → user signs nonce → `POST /authorize/callback` (verifies Ed25519 signature, issues auth code) → DEX calls `/token` (exchanges code for JWT ID token) → DEX calls `/userinfo`

**OIDC endpoints:** `/.well-known/openid-configuration`, `/jwks`, `/authorize`, `/authorize/callback`, `/token`, `/userinfo`

**Key decisions:**
- ID tokens signed with RSA256 (ephemeral key by default, or load PEM via `config.yaml`)
- DID verification supports only `did:key` with Ed25519 (multicodec `0xed01`)
- In-memory stores for auth codes, access tokens, and challenges (not production-ready)
- Base58-btc decoding is inlined (no external dependency)
- Synthesized email: `{did_short}@dkms.local` since DEX expects an email claim

**Config:** `config.yaml` — issuer URL, client credentials, key path, token TTLs
**DEX example:** `dex-config.yaml` — sample DEX config wiring its OIDC connector to this bridge
