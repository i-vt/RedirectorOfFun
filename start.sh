#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

RESET=0
ASSUME_YES=0
EDGE=0
NO_CACHE=0
for arg in "$@"; do
  case "$arg" in
    --reset) RESET=1 ;;
    --edge) EDGE=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --no-cache) NO_CACHE=1 ;;
    *)
      echo "Usage: ./start.sh [--edge] [--reset] [--yes] [--no-cache]" >&2
      exit 2
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker is required. Install Docker with the Compose plugin." >&2
  exit 1
fi
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "Error: Docker Compose is required." >&2
  exit 1
fi

if [[ $RESET -eq 1 ]]; then
  echo "Reset removes the compose stack, its volumes (database, certificates,"
  echo "logs), the generated .env, and local runtime directories."
  if [[ $ASSUME_YES -eq 0 ]]; then
    read -r -p "This destroys all control-plane data. Continue? [y/N] " answer
    [[ "$answer" =~ ^[yY] ]] || { echo "Aborted."; exit 1; }
  fi
  "${COMPOSE[@]}" down -v --remove-orphans || true
  rm -f .env
  rm -rf var staticfiles .test-runtime
  echo "Reset complete."
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required to generate initial secrets." >&2
  exit 1
fi

ENV_FRESH=0
if [[ ! -f .env ]]; then
  echo "Creating .env with generated secrets…"
  ENV_FRESH=1
  DJANGO_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
  ANALYTICS_SALT=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
  POSTGRES_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(36))')
  export DJANGO_SECRET ANALYTICS_SALT POSTGRES_SECRET
  python3 - <<'PY'
import os
from pathlib import Path
text = Path(".env.example").read_text()
text = text.replace("replace-with-a-long-random-secret", os.environ["DJANGO_SECRET"])
text = text.replace("replace-with-a-different-long-random-secret", os.environ["ANALYTICS_SALT"])
text = text.replace("replace-with-a-database-password", os.environ["POSTGRES_SECRET"])
Path(".env").write_text(text)
PY
  chmod 600 .env 2>/dev/null || true
else
  echo "Using existing .env; no secrets were replaced."
  if [[ $RESET -eq 0 ]]; then
    echo "Hint: if you rebuilt .env from scratch, old database volumes hold the"
    echo "old password. Use ./start.sh --reset to wipe them, or docker compose"
    echo "down -v before restarting."
  fi
fi

# Catch port conflicts with other stacks before compose reports a cryptic
# daemon error. Compose projects are named after the directory, so a reset
# in one checkout never sees another checkout's running containers.
STACK_DIR_NAME=$(basename "$PWD" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9_-' '_')
if [[ $RESET -eq 0 ]]; then
  for port in 80 443; do
    occupants=$(docker ps --filter "publish=$port" --format '{{.Names}}' 2>/dev/null || true)
    foreign=$(grep -v "^${STACK_DIR_NAME}-" <<<"$occupants" || true)
    if [[ -n "$foreign" ]]; then
      echo "Error: port $port is already published by another container: $foreign" >&2
      echo "Stop that stack first, e.g.:  docker compose -p <its-directory> down -v" >&2
      exit 1
    fi
  done
fi

# Catch the classic footgun before compose reports a cryptic "unhealthy":
# POSTGRES_PASSWORD only applies on first init, so a regenerated .env against
# a surviving database volume means the panel can never authenticate.
if [[ $RESET -eq 0 && -f .env ]]; then
  if "${COMPOSE[@]}" ps -q --status running db 2>/dev/null | grep -q .; then
    DB_USER=$(grep -E '^POSTGRES_USER=' .env | tail -1 | cut -d= -f2-)
    DB_NAME=$(grep -E '^POSTGRES_DB=' .env | tail -1 | cut -d= -f2-)
    DB_PASS=$(grep -E '^POSTGRES_PASSWORD=' .env | tail -1 | cut -d= -f2-)
    auth_result=$(PGPASSWORD="$DB_PASS" timeout 10 "${COMPOSE[@]}" exec -T db \
      psql -U "${DB_USER:-redirector}" -d "${DB_NAME:-redirector_panel}" -c 'SELECT 1' 2>&1) || true
    if grep -qi "password authentication failed" <<<"$auth_result"; then
      echo "Error: the running database rejects the password from .env." >&2
      echo "The database volume outlived a regenerated .env. Run ./start.sh --reset" >&2
      echo "to wipe the volume, or restore the previous .env." >&2
      exit 1
    fi
  else
    if [[ $ENV_FRESH -eq 1 ]] && docker volume ls --format '{{.Name}}' 2>/dev/null \
        | grep -qi "^${STACK_DIR_NAME}_postgres-data$"; then
      echo "Error: a database volume from a previous run exists, but .env was just regenerated." >&2
      echo "The old database keeps the old password; the panel would fail to authenticate." >&2
      echo "Run ./start.sh --reset to start clean, or restore the previous .env." >&2
      exit 1
    fi
  fi
fi

PROFILE_ARGS=(--profile panelweb)
if [[ $EDGE -eq 1 ]]; then
  PROFILE_ARGS=(--profile edge)
  echo "Starting the control plane and redirector edge (the edge owns ports 80/443;"
  echo "reach the panel via the uncommented localhost:3000 bind or an SSH tunnel)…"
else
  echo "Starting the control plane, PostgreSQL, collector, notification worker, and web tier…"
fi

# A reset means fresh data against fresh code; cached layers from older
# checkouts would silently carry stale code, so reset builds without cache.
if [[ $RESET -eq 1 || $NO_CACHE -eq 1 ]]; then
  "${COMPOSE[@]}" "${PROFILE_ARGS[@]}" build --no-cache
fi
"${COMPOSE[@]}" "${PROFILE_ARGS[@]}" up -d --build

echo "Waiting for the panel to become ready…"
for attempt in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T panel python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3000/health/ready/')" >/dev/null 2>&1; then
    break
  fi
  if [[ $attempt -eq 60 ]]; then
    echo "Panel did not become ready. Recent logs:" >&2
    "${COMPOSE[@]}" logs --tail=80 panel >&2
    exit 1
  fi
  sleep 2
done

"${COMPOSE[@]}" ps
printf '\nControl plane: http://localhost (https://localhost works too, self-signed)\n'
printf 'Initial setup URL (printed only for an unclaimed instance):\n'
"${COMPOSE[@]}" logs panel 2>&1 | grep -E 'Initial administrator setup|/setup/' || true
printf '\nUseful commands:\n'
printf '  Logs:      docker compose logs -f panel collector notification-worker\n'
printf '  Stop:      docker compose down\n'
printf '  Reset all: ./start.sh --reset\n'
printf '  Full test: ./test.sh --all\n'
