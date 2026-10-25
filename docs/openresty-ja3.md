# OpenResty front layer for JA3/JA4 fingerprinting

Stock nginx cannot compute TLS ClientHello fingerprints. This setup places an
OpenResty instance (or a lua-capable stream layer) in front - or on the same
box as the edge - that computes JA3/JA4 and injects them as headers before
proxying to the panel and C2 paths.

## Option A: OpenResty with lua-resty-openssl (recommended)

Install OpenResty and `lua-resty-openssl`. The TLS ClientHello is available in
the `ssl_client_hello_by_lua_block` phase; compute JA4 (and JA3 if legacy
tooling requires it) and stash it in a per-session variable.

```nginx
# /etc/openresty/conf.d/fingerprint.conf
server {
    listen 443 ssl;
    server_name updates.example.com;

    ssl_certificate     /etc/letsencrypt/live/updates.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/updates.example.com/privkey.pem;

    ssl_client_hello_by_lua_block {
        local ssl = require "ngx.ssl"
        local ja4 = require "ja4"           -- e.g. lua-ja4 / your own module
        local chain = ssl.get_client_hello()
        if chain then
            local fp = ja4.compute(chain)
            ngx.var.ja4_fp = fp
        end
    }

    # proxy everything to the stock nginx edge (or directly to panel/C2)
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-JA4-Fingerprint $ja4_fp;
        proxy_set_header X-JA3-Fingerprint $ja3_fp;   -- if your module also emits JA3
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

JA4 (Cloudflare/Salesforce, 2023) is preferred over JA3: it is sortable,
includes TLS version and ALPN, and degrades gracefully across extensions.
Reference: <https://github.com/FoxIO-LLC/ja4>.

## Option B: HAProxy with fingerprint ACLs

HAProxy 2.8+ can match ClientHello fingerprints natively in the TLS
handshake (`ssl_fc_ja4_hash`, `ssl_fc_ja3_hash` with the right build), which
makes it the cheapest path if you prefer not to run Lua:

```
frontend edge
    bind :443 ssl crt /etc/haproxy/updates.pem
    http-request set-header X-JA4-Fingerprint %[ssl_fc_ja4_hash]
    http-request set-header X-JA3-Fingerprint %[ssl_fc_ja3_hash]
    default_backend nginx_edge
```

## Panel side

Once the headers arrive, set `ja3_fingerprint` / `ja4_fingerprint` on a link.
The gate requires an exact match; a missing header fails closed, so removing
the front layer (or an attacker bypassing it) silently denies rather than
downgrading. Confirm the header path works with:

```bash
curl -sI -H "X-JA4-Fingerprint: <expected>" https://updates.example.com/g/<path>
```

## Notes

- Fingerprints change when the beacon's TLS stack changes (library upgrades,
  different transport profiles in RCM). Treat them like UAs: verify per build,
  expect rotation.
- Rate-limit the fingerprint endpoint like any other gate path; a scanner that
  spoofs headers still hits the normal gate logic.
- Keep the front layer's existence non-obvious: it presents the same decoy
  behavior as the edge for non-gate paths.

## JARM randomization (edge layer)

JA3/JA4 gates validate the *client*; the redirector's own TLS fingerprint
(JARM) is fixed per OpenResty/nginx build and config, which makes a deployment
scannable across engagements. RedGuard-style rotation belongs at the edge -
nothing in the Django layer can influence it. Practical options:

- Rebuild or reconfigure the TLS stack per deployment (different cipher list,
  TLS version floor, ALPN order) so the JARM changes every time.
- Put a rotating TLS terminator in front (a small pool of OpenResty builds or
  a CDN front) and fail2ban-style switch on a schedule.
- Track your current JARM (`jarm scan <domain>`) in pre-flight checks; if it
  lands on a public blocklist, rotate before the op starts.

Treat JARM like the randomized gate/agent bases: per-deployment, never shared.
