# RedirectorOfFun

[![CI](https://github.com/i-vt/RedirectorOfFun/actions/workflows/ci.yml/badge.svg)](https://github.com/i-vt/RedirectorOfFun/actions/workflows/ci.yml)

**RedirectorOfFun is an nginx C2 redirector with a full operator control plane.**
It serves payloads, keys, and lure sites behind gates that you control.
Visitors that you do not expect get a decoy page. Operators get a panel, an
API, a mobile UI, and Telegram approvals.


---

## How it works

The redirector sits between the target and your C2. The target only ever
sees the redirector. The panel makes all release decisions.

```mermaid
flowchart LR
    subgraph Target side
        A[Agent / dropper]
        T[Target browser]
    end
    subgraph Redirector host
        N[nginx edge<br/>TLS · rate limits · blocklists]
        P[Control plane<br/>Django panel + Postgres]
        D[(Decoy pages)]
        L[(Lure sites)]
    end
    subgraph Backend
        C[C2 server]
    end
    A -->|beacon /a/token| N
    T -->|link /g/... or lure /l/...| N
    N -->|gate paths| P
    N -->|agent routes| C
    P -->|ban list + agent routes| N
    N -->|unknown / denied| D
    P -->|hosts| L
```

Every public request walks the same decision chain. Visitors that match your
rules get content. Everyone else gets the decoy.

```mermaid
flowchart TD
    R[Incoming request] --> B{IP banned?}
    B -->|yes| D1[Decoy page]
    B -->|no| C{Canary URL?}
    C -->|yes| D2[Decoy + alert]
    C -->|no| L{Known link path?}
    L -->|yes| G[Gate evaluation]
    L -->|no| A{Agent channel?}
    A -->|yes| C2[Proxy to C2]
    A -->|no| LU{Active lure site?}
    LU -->|yes| S[Serve lure file]
    LU -->|no| D3[Decoy page + 404 logged]
    G --> SERVED[Content released]
    G --> HELD[Held view: blank / decoy / redirect]
```

The gate itself checks in a fixed order. A failure at any step looks the same
to the visitor as a wrong token.

```mermaid
flowchart TD
    IN[Request on a link path] --> P1{Blocking rules<br/>IP · UA · ASN · country}
    P1 --> P2{IP / UA allow-list}
    P2 --> P3{Header contract}
    P3 --> P4{Credential<br/>none · token · TOTP · submission}
    P4 --> P5{JA3 / JA4 fingerprint}
    P5 --> P6{Replay dedupe}
    P6 --> P7{Approval status}
    P7 --> P8{Serve ratio N of M}
    P8 --> OUT[Release content]
    P1 & P2 & P3 & P4 & P5 & P6 -.->|fail| HOLD[Held view]
    P7 -.->|pending / denied| HOLD
    P8 -.->|rolled out| HOLD
```

## Quick start

1. Copy `.env.example` to `.env`.
2. Run `./start.sh`. The script makes the secrets, builds the images, and
   starts the stack.
3. Open the setup URL from the script output. Claim the administrator account.
4. Go to **Delivery Links**. Use **Quick drop** to serve a file at once, or
   **New link** for full control.

To update later, run `./update.sh`. To wipe and reinstall, run
`./update.sh --reset`.

## Daily use at a glance

```mermaid
sequenceDiagram
    participant Op as Operator
    participant Panel as Control plane
    participant Ag as Agent
    Op->>Panel: Quick drop a payload
    Panel-->>Op: Live URL (QR on the page)
    Ag->>Panel: POST encrypted submission
    Panel-->>Op: Notification (panel / push / Telegram)
    Op->>Panel: Approve (panel, mobile, or Telegram)
    Ag->>Panel: GET the link
    Panel-->>Ag: Payload released
```

## What you can do with it

| You want to | Do this |
|---|---|
| Serve a file now | Quick drop on the Delivery Links page |
| Approve before release | Set the gate to `submission` |
| Serve only to one network | Set the gate to `IP / User-Agent only` and fill the network profile |
| Make a fake site | Create a lure site, or import a bundle from the payload library |
| Hide a payload in a filename | Set **serve as** on the link |
| Watch what targets send | Open **Gate Intel** for decoded screenshots |
| Keep scanners out | Enable presets on the Blocking Rules page |
| Burn an op | Use the burn notice on the link |

## Documentation

| Page | Tells you |
|---|---|
| [docs/deploy.md](docs/deploy.md) | How to install and wire the edge |
| [docs/operations.md](docs/operations.md) | Daily operation and incident response |
| [docs/dsl.md](docs/dsl.md) | Ciphers, auto-rules, gate types, templates |
| [docs/api.md](docs/api.md) | The REST API and API keys |
| [docs/examples.md](docs/examples.md) | Ready-made blocking chains and feeds |
| [docs/openresty-ja3.md](docs/openresty-ja3.md) | JA3/JA4 front layer and JARM notes |
| [SETUP.md](SETUP.md) | Full testlab walkthrough (step by step) |

## Screenshots

![Panel overview](docs/assets/default-overview.png)

![Architecture](docs/assets/rof-architecture.png)

Every diagram in the docs is a mermaid block (renders on GitHub). Pre-rendered
SVG copies live in [docs/assets/diagrams/](docs/assets/diagrams/) for offline
reading.

## Themes

The panel has three themes: default, Cozy Clown, and Obnoxious Clown.
Pick yours under Settings.

![Themes](docs/assets/jester-brand-themes-v2.png)

## Safety notes

> [!WARNING]
> This is dual-use software for authorized security testing. Use it only on
> systems you own or have written permission to test.

> [!CAUTION]
> The one-time setup URL gives administrator access to anyone who opens it.
> Claim it immediately after install.

> [!NOTE]
> Every push runs the full test suite and shellcheck in CI.
