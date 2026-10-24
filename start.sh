#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ $# -gt 1 ]] || [[ $# -eq 1 && "${1:-}" != "--edge" ]]; then
  echo "Usage: ./start.sh [--edge]" >&2
  exit 2
fi

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
if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required to generate initial secrets." >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  echo "Creating .env with generated secrets…"
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
fi

PROFILE_ARGS=()
if [[ "${1:-}" == "--edge" ]]; then
  PROFILE_ARGS=(--profile edge)
  echo "Starting the control plane and redirector edge…"
else
  echo "Starting the control plane, PostgreSQL, collector, and notification worker…"
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
printf '\nControl plane: http://localhost:3000\n'
printf 'Initial setup URL (printed only for an unclaimed instance):\n'
"${COMPOSE[@]}" logs panel 2>&1 | grep -E 'Initial administrator setup|/setup/' || true
printf '\nUseful commands:\n'
printf '  Logs:      docker compose logs -f panel collector notification-worker\n'
printf '  Stop:      docker compose down\n'
printf '  Full test: ./test.sh --all\n'
