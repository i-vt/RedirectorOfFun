# NYSM — Now You See Me (Enhanced)

> Modified from [coffeegist/now-you-see-me](https://github.com/coffeegist/now-you-see-me).  
> Automated nginx C2 redirector with SSL, blocklisting, UA filtering, and more.

---

## Features

| Feature | Description |
|---|---|
| Auto SSL | Let's Encrypt via Certbot, renewed by cron |
| HTTP → HTTPS redirect | Activated automatically post-cert |
| C2 failover | Upstream backup server support |
| IP blocklisting | Firehol + Ipsum threat intel, updated on deploy |
| User-agent filtering | Allow only expected beacon UA patterns |
| Rate limiting | 10 req/s per IP, bursts to 20 |
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
1) Setup Nginx Redirector   — install + configure (prompts for domain, C2, UA, HTTPS)
2) Load Profile             — re-deploy from a saved profile
3) Update Blocklist         — re-fetch threat-intel IPs and reload nginx
4) Check Status             — processes, ports, connections, certs, logs
5) Scrub Logs               — zero out nginx access and error logs
6) Teardown Redirector      — revoke certs, remove configs, purge packages
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
| 08:00 daily | Cert expiry check — logs warning to syslog if < 14 days remain |

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
