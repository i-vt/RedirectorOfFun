#!/bin/sh
# Generate a self-signed certificate on first start so https:// works
# immediately. Mount real certificates over /etc/nginx/certs to replace it.
set -eu

# HSTS is opt-in: set HSTS_MAX_AGE (e.g. 31536000) to emit
# Strict-Transport-Security on the TLS listener; unset means none.
if [ -n "${HSTS_MAX_AGE:-}" ]; then
  sed -i "s|#hsts# ||g" /etc/nginx/conf.d/default.conf
  sed -i "s|<HSTS_MAX_AGE>|${HSTS_MAX_AGE}|g" /etc/nginx/conf.d/default.conf
else
  sed -i "/#hsts#/d" /etc/nginx/conf.d/default.conf
fi

if [ ! -f /etc/nginx/certs/fullchain.pem ] || [ ! -f /etc/nginx/certs/privkey.pem ]; then
  mkdir -p /etc/nginx/certs
  echo "Generating self-signed certificate for the control plane…"
  # A fixed common name would fingerprint every deployment; randomize it.
  random_cn=$(head -c 200 /dev/urandom | tr -dc 'a-z0-9' | head -c 8)
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /etc/nginx/certs/privkey.pem \
    -out /etc/nginx/certs/fullchain.pem \
    -days 3650 \
    -subj "/CN=svc-${random_cn}" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
fi

exec nginx -g "daemon off;"
