# RedirectorOfFun

> Modified from [coffeegist/now-you-see-me](https://github.com/coffeegist/now-you-see-me).  
> Automated nginx C2 redirector with SSL, blocklisting, UA filtering, and more.

<img width="543" height="498" alt="image" src="https://github.com/user-attachments/assets/b413caaf-9a91-49e4-942b-fec431dc7356" />


---

## Features

| Feature | Description |
|---|---|
| Auto SSL | Let's Encrypt via Certbot, renewed by cron |
| HTTP → HTTPS redirect | Activated automatically post-cert |
| C2 failover | Upstream backup server support |
| IP blocklisting | Firehol + Ipsum threat intel, updated on deploy |
| User-agent filtering | Allow only expected beacon UA patterns |
| Rate limiting | 10 req/s per IP, bursts to 20; dedicated 30 req/s zone for `/g/` gate traffic |
| Header stripping | Removes `Server`, `Via`, `X-Powered-By` |
| Decoy pages | Convincing landing page + maintenance 502/503 page |
| TLS hardening | TLSv1.2/1.3 only, modern cipher list |
| Profiles | Save/load domain+C2 configurations |
| Teardown | Clean removal of all artefacts including certs and logs |
| Log scrub | Zero out nginx access/error logs on demand |
| Webhook alerts | Slack/Teams/Discord notifications on deploy and teardown |
| Status dashboard | Processes, ports, connections, cert expiry, log sizes |
| Dry-run mode | Preview all changes before applying |
| Verbose mode | Print each command before execution |
| Docker support | Containerised deployment via compose |
| Release gates | Operator-approved downloads: held links return blank/placeholder/decoy until approved |
| Verification templates | base64 / XOR / AES-256-CBC decryption of submitted JSON (images extracted automatically) |
| Key distribution | One-time and time-limited URLs that plainly display a key |
| pwndrop proxying | Server-side fetch so the pwndrop location is never exposed |
| Operator IP bans | Manual bans plus auto-ban on suspicious-activity threshold; banned IPs get the decoy |
| Blocking rules | Regex rules over IP / user agent / ASN / ISP / country / city with AND / OR / NONE logic, presets (VirusTotal, AWS/GCP/Azure ASNs, scanner UAs), dry-run testing, optional auto-ban |
| Per-agent C2 URLs | Unique `/a/<token>` beacon paths with per-agent UA validation, rotation, hit tracking |
| Notifications | Panel toast + bing, browser notifications, Telegram for downloads, approvals, suspicious events |
| Telegram approvals | Reply `approve <id>` / `deny <id>` to the bot to decide submissions from your phone |
| Auto-decision rules | Per-link JSON rules that auto-approve/deny submissions by field regexes, forbidden patterns, and image presence |
| Operator 2FA | TOTP second factor (RFC 6238, no extra dependencies) with single-use backup codes and admin recovery |
| Mobile UI | Separate touch-first interface at `/m/` for approvals, links, and events |
| Keyboard review | `j/k` navigate, `a` approve, `d` deny, `u` undo on the approval queue |
| Undo | Approve/deny reversible within `DECISION_UNDO_SECONDS`, until content is released |
| Submission notes | Shared operator notes on every submission (panel, mobile, API) |
| Web Push | VAPID push notifications that work when the panel is closed |
| Burn notice | One-click link burn: deactivate, deny all, ban every visitor IP except the approved target |
| Watermarking | Optional unique per-release marker; the exact value is logged so leaks trace to a link + use |
| Decoy canaries | Per-visitor tracking pixel in decoy pages; re-hits and forgeries both raise suspicious events (on by default) |
| JA3/JA4 gating | Per-link TLS fingerprint enforcement via an OpenResty front layer (fails closed) |
| Domain reassignment | Pin links to any configured `REDIRECTOR_DOMAINS` entry; move a burned domain without touching payloads |
| Deployment templates | Built-in fill-in-the-blank presets for dropper check-ins, key drops, loader stages, file drops |
| Surface telemetry | Every hit/expiry/denial/404 tracked with hashed IPs |
| Self-testing | Blocking startup checks (DB, crypto templates, storage) plus non-blocking config checks |

---

## Operator Control Plane

The repository now includes a Django control plane alongside the original nginx/shell deployment. The original redirector scripts remain intact; the panel is a separate service and does not put application logic into nginx.

### Included

- Atomic one-time administrator bootstrap through a high-entropy capability URL
- Browser form and JSON automation using the same claim operation
- Named operators, Administrator/Operator/Auditor roles, single-use invitations, revocation, and session invalidation
- Append-only administrative audit events with request IDs
- Asynchronous nginx JSON 404 ingestion with idempotent checkpoints and retention
- Overview dashboard, filters, aggregated statistics, and cursor-paginated APIs
- Panel, browser, and optional Telegram notifications through a transactional outbox
- Liveness/readiness endpoints, startup checks, Docker deployment, and regression tests
- Release gates: operator-controlled URLs under `/g/` that distribute keys, gate payload downloads behind verification, and proxy pwndrop content without exposing its location
- Verification templates (base64 / XOR / AES-256-CBC) for decrypting dropper/loader submissions, with automatic screenshot extraction and an approve/deny queue
- One-time and time-limited links, custom operator-chosen paths, per-agent link tagging
- Operator IP banning with auto-ban on repeated suspicious activity
- Per-agent C2 beacon URLs under `/a/` with independent UA validation and token rotation
- Surface telemetry for hits, releases, holds, denials, expired links, bans, and suspicious events
- Startup self-test suite (`manage.py selftest --strict` gates container boot)
- Auto-decision rules: per-link JSON DSL; the first matching rule approves/denies a submission by regex-matching decoded fields, forbidding patterns, and requiring extracted images - no match stays manual
- Telegram approvals: reply `approve <id>` / `deny <id>` / `pending` / `help` to the bot (only `TELEGRAM_CHAT_ID` is honored); the `telegram-worker` compose service runs the poller
- Operator TOTP 2FA with single-use backup codes, a security enrollment page, and an administrator reset for lockouts; disabling 2FA invalidates sessions

These capabilities are built for authorized red-team engagements: every release decision stays with a human operator, and all telemetry stores hashed client addresses rather than raw IPs. Use only on infrastructure you are explicitly authorized to test.

### Local development

Python 3.12 is recommended. SQLite is used automatically when `DATABASE_URL` is unset.

```bash
python3 -m pip install -r requirements.txt
python3 manage.py migrate
python3 manage.py ensure_bootstrap
python3 manage.py runserver 0.0.0.0:3000
```

`ensure_bootstrap` prints the initial setup URL only when no administrator exists. The raw token is not stored in the database. Anyone with the unclaimed URL can claim the instance; protect provisioning output accordingly.

A JSON client can claim the same URL:

```bash
curl -X POST "http://localhost/setup/REPLACE_WITH_TOKEN/" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"REPLACE_WITH_A_STRONG_PASSWORD"}'
```

A successful claim returns HTTP 201. Subsequent GET or POST requests to that setup URL return HTTP 410.

### Production with Docker Compose

```bash
cp .env.example .env
# Replace every placeholder secret and set your hostnames/origins.
docker compose up -d --build
docker compose logs panel
```

The stack starts PostgreSQL, the panel, the 404 collector, and the notification worker. The collector has read-only access to the shared nginx log volume. To include the original redirector edge service, configure `DOMAIN_NAME` and `C2_SERVER`, then use:

```bash
docker compose --profile edge up -d --build
```

The panel is served on the standard ports through the web tier: **http://localhost** and **https://localhost** (the latter uses an auto-generated self-signed certificate on first start; mount real certificates into `docker/certs` to replace it). Port 3000 is internal to the compose network.

Out of the box the panel accepts **any** host and any client IP: `ALLOWED_HOSTS=*`, no `CSRF_TRUSTED_ORIGINS` entries (normal same-origin form posts pass CSRF checks), no `allow`/`deny` rules, and cookies not marked Secure (so plain-http browsing works from anywhere). Verified behavior: same-origin posts from arbitrary hosts/IPs succeed; cross-origin posts are still refused. Locking down is an explicit operator choice: list hostnames/IPs in `ALLOWED_HOSTS` in `.env`, uncomment the `allow`/`deny` rules in `docker/panel-web.conf`, or bind the published ports to a specific interface in `docker-compose.yml` — each has commented examples. When serving proper https, set `SESSION_COOKIE_SECURE=true` and `CSRF_COOKIE_SECURE=true`.

**Operator paths live under a secret prefix.** `start.sh` generates a random UUID (`OPERATOR_PREFIX` in `.env`) and mounts everything operator-facing behind it: `/panel/…`, `/api/v1/…`, `/m/…`, `/login/`, `/setup/…`, `/invite/…`, django-admin. There is nothing at `/panel/` or `/api` — anyone probing the plain paths (or any unknown URL outside the prefix, authenticated or not) gets the decoy page; only *inside* the prefix do signed-in operators see the panel's own 404. Public gate paths (`/g/…`, `/a/…`), `/health/`, and `/static/` stay at the root; URL reversal (`reverse`, `{% url %}`, login redirects) carries the prefix automatically. `start.sh` prints the full prefixed URLs for every interface address. Set `OPERATOR_PREFIX=` (empty) only for local development.

Unmatched paths behave like the edge: anonymous visitors to any unknown URL (including `/`) get the operator-selected default decoy page with its canary pixel and a tracked `not_found` event; signed-in operators get the real panel 404 page, and `/` takes them straight to the dashboard. Decoy pages are managed under **Decoy Pages** in the panel (and `/api/v1/decoys/`): pick any page shipped with the repo (Update Service, NYSM landing, maintenance, Crestfield example), upload your own HTML, or set a redirect URL; the default applies to 404s, gate denials, and banned visitors alike. Built-in pages are seeded automatically on first start.

With `--edge`, the redirector owns 80/443 instead; reach the panel via the commented `127.0.0.1:3000:3000` bind in `docker-compose.yml` or an SSH tunnel. Run migrations as a release step; the provided panel entrypoint does this before starting web workers.

### nginx 404 integration

`default.conf` and the panel web tier (`docker/panel-web.conf`) emit only 404 responses to `/var/log/nginx/access.json` using the same structured JSON (time, method, path, status, remote address, user agent); both share the `nginx-logs` volume the collector reads asynchronously. In the default deployment the web tier is the nginx answering 80/443, so every unmatched URL a visitor hits lands in 404 Events. The event stream stores the raw client IP and user agent alongside the hash: the client column shows the hash by default (REVEAL IDENTIFIERS toggle switches it to raw IPs), each row has an INFO button for the full identifier block, and the filters accept user-agent substrings, raw IPs, or hashes.

Run one ingestion pass manually with:

```bash
python3 manage.py ingest_404_logs --path /path/to/access.json --once
```

Run retention maintenance with:

```bash
python3 manage.py prune_events
```

### Panel routes

| Route | Purpose |
|---|---|
| `/panel/` | Overview, 14-day event telemetry, gate summary |
| `/panel/events/` | Filterable 404 event stream |
| `/panel/links/` | Delivery links: keys, gated files, pwndrop proxies |
| `/panel/submissions/` | Verification-gate approval queue with decoded JSON + images |
| `/panel/bans/` | Manual IP bans (banned visitors get the decoy page) |
| `/panel/agents/` | Per-agent C2 beacon URLs with rotation |
| `/panel/gate-events/` | Gate surface telemetry: hits, releases, holds, denials, expired, banned, suspicious |
| `/panel/operators/` | Invitations, roles, and access revocation |
| `/panel/audit/` | Administrative audit trail |
| `/panel/settings/` | Notification preferences (gates / suspicious included) |
| `/panel/security/` | TOTP 2FA enrollment, backup codes, disable |
| `/panel/health/` | Service and collector health |
| `/panel/selftest/` | Run the self-test suite on demand |

### Documentation

- `docs/operations.md` - daily loops, approvals, burn notices, canaries, notification channels
- `docs/deploy.md` - topology, multi-domain, JA3 front layer, backups
- `docs/dsl.md` - cipher templates, auto-rules, gate types, link templates
- `docs/api.md` - REST reference
- `docs/openresty-ja3.md` - TLS fingerprint front layer

### Release gates

Public gate URLs live under `GATE_BASE_PATH` (default `/g/`); nginx proxies that prefix to the panel. Any path an operator creates under `/g/` works without touching nginx - the control plane's 404 handler dispatches it. Agent beacon URLs live under `AGENT_BASE_PATH` (default `/a/`) and are generated per channel.

**Delivery link kinds**

- `key` - plainly displays `key_text` (one-time and time limits supported)
- `file` - serves an uploaded payload after the gate is satisfied
- `proxy` - fetches `pwndrop_url` server-side and streams it to the client; the pwndrop location is never exposed

**Gate types**

- `none` - path secrecy only
- `token` - static shared token via `?t=` or `X-Gate-Token`
- `totp` - time-based code, `HMAC(secret, time_window)` truncated to 8 hex chars, current and previous window accepted
- `submission` - POST body is decoded/decrypted per the cipher template and must parse to a JSON object containing the expected fields

**Cipher templates** (submission bodies are base64-wrapped after encryption)

| Template | Parameters |
|---|---|
| `base64` | - |
| `xor` | `cipher_key` |
| `aes256` | `cipher_key` (32-byte hex or passphrase → SHA-256), `cipher_iv` (16-byte hex) |

String fields in the decoded JSON that look like base64 images (PNG/JPEG/GIF/BMP magic bytes) are extracted and shown inline in the approval queue.

**Verification gate flow**

1. Dropper POSTs its encrypted package → decrypted, validated, stored as a pending submission, operator notified (panel bing / browser / Telegram).
2. Until a decision, the link returns the configured hold response (blank 204, placeholder page, or decoy).
3. Operator approves → next GET releases the content (download starts automatically; `Content-Disposition: attachment`).
4. Operator denies → the link serves the deny response (404, decoy, or a benevolent payload/message you configure).

One-time links deactivate after their first release; `max_uses` and `expires_at` provide count/time limits. Key retrieval, downloads, holds, approvals, denials, expired hits, banned hits, and suspicious events are all recorded as HitEvents with hashed client IPs.

**Auto-decision rules**

`auto_rules` is a JSON list on the link; the first rule whose `when` clause matches decides the submission (recorded with `via: auto-rule#N` and the matched reasons). No match leaves it pending for a human.

```json
[
  {"action": "approve",
   "when": {"fields_match": {"hostname": "^corp-laptop-\\d+$"},
            "forbid": ["vmware|virtualbox|vbox", "sandbox"],
            "require_images": true}},
  {"action": "deny",
   "when": {"fields_match": {"hostname": "^sandbox"}}}
]
```

- `fields_match`: every listed field's value must match its regex
- `forbid`: if any decoded value matches any of these regexes, the rule does **not** fire (safety net - a forbidden signal can never auto-approve)
- `require_images`: at least one image must have been extracted from the submission

Rules are validated on save (panel form and API both reject malformed DSL). Approve-by-rule flows still emit notifications and audit events with `via: auto-rule#…`.

**Telegram approvals**

With `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` set, run the poller (`manage.py poll_telegram`, or the `telegram-worker` compose service). Replying to the bot decides submissions without opening the panel - only the configured chat ID is honored, decisions are idempotent (a decided submission replies "already decided"), and `pending` lists the queue. The awaiting-approval notification includes the exact reply syntax.

**Two-factor authentication**

Each operator can enable TOTP under `/panel/security/` (enrollment shows the secret + `otpauth://` URI; confirming a generated code activates it and reveals eight single-use backup codes, stored only as SHA-256 hashes). Login becomes two-step: password, then code. Backup codes burn on use. Administrators can reset another operator's 2FA from the operators page (lockout recovery), which also invalidates that operator's sessions. Verified against RFC 6238 test vectors.

**Auto-ban**: an IP that triggers `AUTO_BAN_THRESHOLD` (default 5) suspicious events within an hour is banned automatically and the nginx deny include is rewritten. Set `NGINX_BAN_INCLUDE` and `NGINX_AGENT_ROUTES_INCLUDE` to enable file sync; then reload nginx (`manage.py sync_nginx` reminds you). Banned IPs receive the default decoy page.

**Blocking rules** (Blocking Rules in the panel, `/api/v1/block-rules/`): a firewall-style chain. Rules are regex conditions over `ip`, `cidr`, `ua`, `asn`, `isp`, `country`, `city`, combined with ALL / ANY / NONE logic and per-condition `negate`. The chain is evaluated **top to bottom, first match wins**: an **ALLOW** action stops the chain and lets the visitor through (place allow rules for trusted operators first to override later blocks), a **BLOCK** action serves the decoy, records a `blocked` Gate Event, and can auto-ban the IP. Rules live in **rulesets** — one "everything" chain by default, plus sets scoped to **404s only** or a **specific delivery link**; sets and rules are ordered by drag-and-drop in the panel (or `POST /api/v1/block-rules/reorder/`). Rulesets and rules **export/import as JSON** (panel buttons or `/api/v1/block-rules/export|import/`); imports always land disabled, name collisions get an "(imported)" suffix, and link-scoped sets re-attach by link path. ASN/ISP/geo come from best-effort enrichment (ip-api.com, cached per address; `IP_INTEL_ENABLED=false` keeps the panel offline) — missing intel makes intel conditions indeterminate and the rule will not fire. Eleven presets seed disabled on first start, including the three templates (block an IP/CIDR, block a region, allow a trusted operator). Use the Test page (or `POST /api/v1/block-rules/test/`) to dry-run an IP + UA against every rule before enabling — operators are not exempt from enabled rules.

**Agent channels**: each channel gets a unique `/a/<token>` path with its own UA regex. The panel writes exact-match nginx location blocks (proxied to `c2_backend`, non-matching UA → bare 404). Rotate a token to burn a deployed agent; unknown tokens get a bare 404.

### API and health

The session-authenticated API is under `/api/v1/` and includes `404-events/`, `404-stats/`, `audit-events/`, `operators/`, `notification-preferences/`, `notifications/recent/`, plus the gate surface:

| Endpoint | Purpose |
|---|---|
| `links/`, `links/<id>/` | List/create/update/delete delivery links |
| `submissions/`, `submissions/<id>/<approve|deny>/` | Approval queue and decisions |
| `bans/`, `bans/<id>/` | List/create/update bans |
| `agents/`, `agents/<id>/`, `agents/<id>/rotate/` | Per-agent channels and rotation |
| `hit-events/`, `gate-stats/` | Surface telemetry and 24h aggregates |

Event and audit list endpoints use cursor pagination. Operator administration requires the Administrator role.

- `GET /health/live/` checks the process without dependency-heavy work.
- `GET /health/ready/` checks the database and reports pending migrations.
- `python manage.py selftest` runs the startup check suite; `--strict` fails on blocking checks and the container entrypoint uses it.

### One-command Docker startup

```bash
./start.sh
```

The script creates `.env` with unique secrets on first run, builds and starts PostgreSQL, the panel, collector, and notification worker, waits for readiness, and prints the initial setup URL. Existing `.env` values are never replaced. To include the original redirector edge service after configuring its variables, run `./start.sh --edge`. If your filesystem does not preserve executable bits, use `bash start.sh` instead.

To wipe everything and start clean — containers, volumes (database, certificates, logs), the generated `.env`, and local runtime directories — run `./start.sh --reset`. It asks for confirmation first; pass `--yes` to skip the prompt. Use this instead of manual cleanup: deleting `.env` while the Postgres volume survives leaves the old database holding the old password, and the panel will fail its healthcheck with authentication errors.

### Full test suite

```bash
./test.sh --all
```

The complete suite runs three isolated stages:

1. **Unit tests:** 49 tests for token handling, state rules, parsing, serializers, models, roles, notification primitives, crypto templates (base64/XOR/AES-256 round-trips, tamper rejection, TOTP windows), image extraction, auto-rule validation/evaluation, RFC 6238 TOTP vectors, backup-code semantics, and the self-test suite.
2. **Functional tests:** 119 tests for Django views, workflows, management commands, permissions, retention, log rotation, every API endpoint, and the full gate surface (dispatch, one-time/expiry semantics, token and TOTP gates, submission approval and denial flows, auto-rule end-to-end, Telegram text commands and inline callbacks, Web Push delivery and pruning, undo/burn semantics, watermarks, decoy canaries, JA3/JA4 gating, mobile UI, deployment templates, domain pinning, pwndrop proxying, bans, auto-ban, agent rotation, two-factor login, security enrollment, notifications).
3. **End-to-end tests:** 9 real-browser tests covering bootstrap, login/logout, navigation, charts, filtering, pagination, XSS safety, invitations, acceptance, revocation, notifications, all API operations, health checks, custom 404s, and mobile layouts.

The test script builds `docker-compose.test.yml`, starts a disposable stack on port 3100, generates time-current nginx fixtures, and destroys the test database and containers afterward. It does not use the development or production database. The browser stage runs in its own container — Playwright, Chromium, and all of their system libraries live inside `docker/Dockerfile.browser`, so the host OS needs only Docker and curl. Nothing is pip-installed on the host. Set `KEEP_TEST_ENV=1` to retain the isolated stack for debugging.

Individual stages are available as `./test.sh --unit`, `./test.sh --functional`, and `./test.sh --e2e`. If your filesystem does not preserve executable bits, use `bash test.sh --all` (or the corresponding stage flag).

### Direct backend checks

```bash
python3 manage.py check
python3 manage.py test --tag unit
python3 manage.py test --tag functional
python3 manage.py collectstatic --noinput
```

Back up PostgreSQL with `pg_dump`, and test restoration into a separate database before relying on the backup. Keep the database, provisioning logs, Telegram token, and analytics hash salt outside source control. If bootstrap is unclaimed and the URL is lost, an SSH operator can replace it with `python3 manage.py reset_bootstrap`; this command refuses to reopen a claimed instance.

---

## File Structure

```
nysm/
├── automate.sh          # Main script (setup, teardown, status, etc.)
├── default.conf         # Nginx config template
├── nysm-cron            # Certbot renewal + expiry alert cron
├── blocklist-update.sh  # Fetches threat-intel IPs → nginx deny rules
├── .gitignore
├── README.md
├── decoy/
│   ├── index.html       # Decoy landing page served to non-beacon traffic
│   └── maintenance.html # Served when C2 backend is unreachable (502/503)
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── entrypoint.sh    # Substitutes env vars into config at container start
│   └── .env.example
└── profiles/
    └── example.conf     # Template for saving domain/C2 pairs
```

---

## Quick Start

### Bare-metal / VM

```bash
# Clone and enter the directory
git clone <repo> nysm && cd nysm
chmod +x automate.sh blocklist-update.sh

# Interactive menu
sudo ./automate.sh

# Non-interactive (domain + C2 as args)
sudo ./automate.sh updates.example.com 10.0.0.1:443

# With options
sudo ./automate.sh -v -d updates.example.com 10.0.0.1:443   # dry-run verbose
sudo ./automate.sh -w https://hooks.slack.com/... domain c2  # with webhook
```

### Docker

```bash
cd docker
cp .env.example .env
# Edit .env with your DOMAIN_NAME and C2_SERVER

docker compose up -d --build

# First-time cert (run once; cron handles renewals after)
docker compose exec redirector \
  certbot --nginx --register-unsafely-without-email --agree-tos -d "$DOMAIN_NAME"
```

---

## Menu Options

```
1) Setup Nginx Redirector   - install + configure (prompts for domain, C2, UA, HTTPS)
2) Load Profile             - re-deploy from a saved profile
3) Update Blocklist         - re-fetch threat-intel IPs and reload nginx
4) Check Status             - processes, ports, connections, certs, logs
5) Scrub Logs               - zero out nginx access and error logs
6) Teardown Redirector      - revoke certs, remove configs, purge packages
7) Quit
```

---

## Configuration

### User-agent filtering

When prompted, supply a regex matching expected beacon UA strings, e.g.:

```
Mozilla/5\.0.*Windows NT
```

Requests not matching are silently redirected to `https://www.microsoft.com`.  
Leave blank to allow all UA strings through.

### C2 failover

Edit `default.conf` and uncomment the backup line in the upstream block:

```nginx
upstream c2_backend {
    server 10.0.0.1:443;
    server 10.0.0.2:443 backup;   # ← uncomment
    keepalive 32;
}
```

### Decoy content

Replace `decoy/index.html` with a convincing clone of a parked domain, corporate
portal, or software update page. The `decoy/maintenance.html` is served on 502/503/504
when the C2 backend is unreachable.

### Webhook notifications

Pass `-w <url>` on the command line. Supports any service that accepts a JSON
`{"text": "..."}` POST (Slack, Teams, Discord webhooks).

---

## Cron Jobs

| Schedule | Job |
|---|---|
| 06:00 & 18:00 daily | Certificate renewal (random sleep up to 1hr to stagger) |
| 08:00 daily | Cert expiry check - logs warning to syslog if < 14 days remain |

---

## Blocklist Sources

| Source | Description |
|---|---|
| [Firehol Level-1](https://github.com/firehol/blocklist-ipsets) | Highest-confidence malicious IPs and CIDRs |
| [Ipsum](https://github.com/stamparm/ipsum) | Aggregated threat intelligence (score ≥ 3) |

Run `sudo bash blocklist-update.sh` at any time to refresh, or use menu option 3.

---

## Teardown

The teardown option:

1. Revokes and deletes the Let's Encrypt certificate
2. Removes the nginx config and blocklist
3. Removes the cron job
4. Stops nginx (optionally purges packages)
5. Removes the `/etc/hosts` entry
6. Zeroes nginx access and error logs

---

## Requirements

- Ubuntu 20.04 / 22.04 (or compatible Debian-based OS)
- Root access
- Public DNS A record pointing the domain to this host
- Ports 80 and 443 open inbound
