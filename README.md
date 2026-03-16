# DEX-DKMS Bridge

A minimal OIDC Provider that bridges [THCLab's KERI-based DKMS](https://github.com/THCLab/dkms-demo) to [DEX](https://dexidp.io/). DEX connects to this bridge via its built-in OIDC connector.

## Architecture

### Auth Flow

```mermaid
sequenceDiagram
    actor User
    participant DEX as DEX<br/>:5556
    participant Bridge as DKMS-DEX Bridge<br/>:8900
    participant Witness as KERI Witnesses<br/>:3232-3234

    User->>DEX: 1. Login request
    DEX->>User: 2. Redirect to /authorize
    User->>Bridge: 3. GET /authorize
    Bridge->>User: 4. Challenge nonce page

    Note over User: Sign nonce with<br/>KERI Ed25519 key

    User->>Bridge: 5. POST /authorize/callback<br/>(AID + signature)

    Bridge->>Witness: 6. GET /oobi/{AID}
    Witness-->>Bridge: 7. KERI event (icp/rot)<br/>with signing keys

    Note over Bridge: Extract Ed25519 key<br/>from "k" field<br/>Verify signature

    Bridge->>User: 8. Redirect with auth code
    User->>DEX: 9. Callback with code

    DEX->>Bridge: 10. POST /token (exchange code)
    Bridge-->>DEX: 11. JWT ID token (sub = AID)

    DEX->>Bridge: 12. GET /userinfo
    Bridge-->>DEX: 13. User claims

    DEX->>User: 14. Authenticated (AID identity)
```

### Component Overview

```mermaid
graph TB
    subgraph OIDC["OIDC Layer (RS256 JWT)"]
        App["Client App"]
        DEX["DEX (IdP Hub)<br/>:5556"]
    end

    subgraph BridgeLayer["DKMS-DEX Bridge :8900"]
        Bridge["FastAPI OIDC Provider"]
        Store[("In-Memory Store<br/>Auth Codes | Tokens | Challenges")]
        Bridge --- Store
    end

    subgraph KERI["KERI Layer (Ed25519 / CESR)"]
        W1["Witness 1<br/>:3232"]
        W2["Witness 2<br/>:3233"]
        W3["Witness 3<br/>:3234"]
        Watcher["Watcher<br/>:3235"]
    end

    App <-->|"OAuth2 / OIDC"| DEX
    DEX <-->|"/.well-known<br/>/token  /userinfo"| Bridge
    Bridge <-->|"OOBI<br/>GET /oobi/{AID}"| W1
    Bridge <-->|"OOBI"| W2
    Bridge <-->|"OOBI"| W3
    W1 --- Watcher
    W2 --- Watcher
    W3 --- Watcher

    style OIDC fill:#e8f0fe,stroke:#4285f4
    style BridgeLayer fill:#fef7e0,stroke:#f9ab00
    style KERI fill:#e6f4ea,stroke:#34a853
```

## How It Works

1. DEX redirects user to the bridge's `/authorize` endpoint
2. Bridge presents a challenge nonce for KERI-based authentication
3. User provides their AID (Autonomic Identifier) and signs the nonce with their current KERI signing key (Ed25519)
4. Bridge resolves the AID via OOBI on configured KERI witnesses, extracts the signing key from the KEL, and verifies the signature
5. DEX exchanges the authorization code for a JWT ID token with AID-based claims

## Prerequisites

- Running [DKMS infrastructure](https://github.com/THCLab/dkms-demo) (witnesses, watcher, mesagkesto)
- A KERI AID created via `dkms-bin` or another KERI agent

## Quick Start

```bash
# Start DKMS infrastructure
cd /path/to/dkms-demo && docker-compose up -d

# Start the bridge
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python bridge.py
```

The bridge starts at `http://localhost:8900`. Configure witness URLs in `config.yaml`.

## DEX Configuration

See `dex-config.yaml` for a sample DEX configuration that wires the OIDC connector to this bridge.

## OIDC Claims Mapping

| OIDC Claim | Value |
|---|---|
| `sub` | KERI AID prefix |
| `name` | KERI AID prefix |
| `preferred_username` | KERI AID prefix |
| `email` | `{aid_short}@dkms.bridge` (synthesized) |
