# DEX-DKMS Bridge

A minimal OIDC Provider that bridges Decentralized Key Management (DID-based identity) to [DEX](https://dexidp.io/). DEX connects to this bridge via its built-in OIDC connector.

## How It Works

1. DEX redirects user to the bridge's `/authorize` endpoint
2. Bridge presents a challenge nonce for DID-based authentication
3. User signs the nonce with their Ed25519 DID key (`did:key` method)
4. Bridge verifies the signature, issues an authorization code
5. DEX exchanges the code for a JWT ID token with DID claims

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python bridge.py
```

The bridge starts at `http://localhost:8900`.

## DEX Configuration

See `dex-config.yaml` for a sample DEX configuration that wires the OIDC connector to this bridge.

## Supported DID Methods

- `did:key` with Ed25519 (multicodec `0xed01`)
