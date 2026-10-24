# Deployment Guide

## Topology

```
dropper / loader / agent
        │
        ▼
   nginx (edge: TLS, rate limits, blocklists, banlist, agent routes)
        │  /g/  → panel (Django, release gates)
        │  /a/  → per-agent routes → C2 backend
        │  else → decoy / C2 per classic NYSM rules
        ▼
   panel (Django + Postgres): links, approvals, telemetry, notifications
```

The edge stays dumb: all release decisions live in the panel. nginx proxies
`/g/` to the panel upstream (`PANEL_UPSTREAM`, default `127.0.0.1:3000`) and
includes two panel-managed files:

- `/etc/nginx/banlist.conf` - `deny` lines for banned IPs (`NGINX_BAN_INCLUDE`)
- `/etc/nginx/agent_routes.conf` - exact-match agent beacon locations
  (`NGINX_AGENT_ROUTES_INCLUDE`)

After any ban/agent change, reload nginx (`manage.py sync_nginx` prints the
reminder). `automate.sh` creates both files empty at setup.

## Install

Docker Compose (panel + Postgres + collector + notification worker +
telegram worker):

```bash
cp .env.example .env   # fill in secrets + TELEGRAM_* + VAPID_*
docker compose up -d --build
```

Bare metal: see README quick start. Python 3.12, then
`pip install -r requirements.txt && python manage.py migrate`.

Startup self-tests (`manage.py selftest --strict`) gate the container boot;
set `SELFTEST_SKIP=true` only to recover a broken deploy.

## Multiple domains per redirector

Point several DNS names at the same host, list them in `REDIRECTOR_DOMAINS`,
and add them to the nginx `server_name` (comma-separated). The panel then lets
you pin any link to a specific domain - and **reassign a link to another
domain without touching the payload**, which is the whole point: when a domain
gets reported or burned, you move links, not implants.

```bash
REDIRECTOR_DOMAINS=updates.example.com,cdn.example.net
```

```nginx
server_name updates.example.com cdn.example.net;
```

## JA3/JA4 fingerprint gating

Stock nginx terminates TLS without exposing a ClientHello fingerprint, so
fingerprint enforcement requires a front layer that computes JA3/JA4 and
injects it as a request header. See `openresty-ja3.md` for a working
OpenResty setup. Once the front layer sends `X-JA3-Fingerprint` /
`X-JA4-Fingerprint`, set the expected values on the link. Links with
fingerprints configured refuse to serve when the header is missing or
mismatched - including when the front layer is absent, so a fingerprint-gated
link cannot silently downgrade.

The front layer must *overwrite* these headers on every request (the OpenResty
snippet in `openresty-ja3.md` does); if a client-supplied value ever reaches
the panel, the fingerprint gate becomes spoofable.

## Client addresses

`TRUSTED_PROXIES` (default `127.0.0.1,::1`) lists the only peers whose
`X-Forwarded-For` header is believed. Every other client is identified by its
direct address, which stops XFF spoofing from evading bans or framing third
parties. Keep this list limited to your actual edge proxies.

## Threat-intel blocklist

`blocklist-update.sh` (Firehol L1 + Ipsum ≥ 3) writes
`/etc/nginx/blocklist.conf`. This is independent of operator bans
(banlist.conf) and auto-bans: three layers, three sources.

## Backups

`pg_dump` the panel database and copy `var/media` (payloads, extracted
screenshots). Test restores. The database holds link configurations, keys,
and submission contents - treat it like a loot repository.
