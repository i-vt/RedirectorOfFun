#!/bin/sh
# TLS for the web tier.
# PANEL_DOMAIN set: request a real Let's Encrypt certificate via webroot
# (nginx serves the ACME challenge from /var/www/acme), persist it in
# /etc/letsencrypt (host-mounted), link it into /etc/nginx/certs, and renew
# in a background loop. Missing domain or a failed request falls back to a
# self-signed certificate generated on the spot, with a loud warning.
# Set TLS_REQUIRE_REAL=1 to fail the container instead of falling back.
set -eu

CONF="/etc/nginx/conf.d/default.conf"

# HSTS is opt-in: set HSTS_MAX_AGE (e.g. 31536000) to emit
# Strict-Transport-Security on the TLS listener; unset means none.
if [ -n "${HSTS_MAX_AGE:-}" ]; then
  sed -i "s|#hsts# ||g" "$CONF"
  sed -i "s|<HSTS_MAX_AGE>|${HSTS_MAX_AGE}|g" "$CONF"
else
  sed -i "/#hsts#/d" "$CONF"
fi

mkdir -p /etc/nginx/certs /var/www/acme

# TRACK_ALL_REQUESTS=1 stores every request in the analytics stream, not just
# 404s (the panel's events page gains 2xx/3xx/5xx visibility).
if [ "${TRACK_ALL_REQUESTS:-0}" = "1" ]; then
  sed -i 's/    default 0;/    default 1;/' "$CONF"
fi

if [ -n "${PANEL_DOMAIN:-}" ]; then
  LIVE="/etc/letsencrypt/live/${PANEL_DOMAIN}"
  if [ ! -f "$LIVE/fullchain.pem" ]; then
    echo "[entrypoint] Requesting a real certificate for ${PANEL_DOMAIN}..."
    # nginx must already be answering the ACME challenge on port 80.
    nginx
    if [ -n "${LETSENCRYPT_EMAIL:-}" ]; then
      certbot certonly --webroot -w /var/www/acme -d "$PANEL_DOMAIN" \
        --email "$LETSENCRYPT_EMAIL" --agree-tos --non-interactive || true
    else
      certbot certonly --webroot -w /var/www/acme -d "$PANEL_DOMAIN" \
        --register-unsafely-without-email --agree-tos --non-interactive || true
    fi
    nginx -s quit || true
    sleep 1
  fi
  if [ -f "$LIVE/fullchain.pem" ]; then
    ln -sf "$LIVE/fullchain.pem" /etc/nginx/certs/fullchain.pem
    ln -sf "$LIVE/privkey.pem" /etc/nginx/certs/privkey.pem
    echo "[entrypoint] Using the real certificate for ${PANEL_DOMAIN}."
  elif [ "${TLS_REQUIRE_REAL:-0}" = "1" ]; then
    echo "[entrypoint] ERROR: certificate request for ${PANEL_DOMAIN} failed and TLS_REQUIRE_REAL=1." >&2
    exit 1
  else
    echo "[entrypoint] WARNING: real certificate request failed; falling back to self-signed." >&2
  fi
fi

if [ ! -f /etc/nginx/certs/fullchain.pem ] || [ ! -f /etc/nginx/certs/privkey.pem ]; then
  echo "Generating self-signed certificate for the control plane..."
  # A fixed common name would fingerprint every deployment; randomize it.
  random_cn=$(head -c 200 /dev/urandom | tr -dc 'a-z0-9' | head -c 8)
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /etc/nginx/certs/privkey.pem \
    -out /etc/nginx/certs/fullchain.pem \
    -days 3650 \
    -subj "/CN=svc-${random_cn}" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
fi

if [ -n "${PANEL_DOMAIN:-}" ]; then
  ( while :; do
      sleep 43200
      certbot renew --webroot -w /var/www/acme --quiet && nginx -s reload
    done ) &
fi

exec nginx -g "daemon off;"
