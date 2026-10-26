#!/usr/bin/env bash
# Update the panel: pull the repo, rebuild images, restart the stack.
#   ./update.sh           pull + rebuild + restart, then prune stale image/build cache
#   ./update.sh --reset   pull, then a full clean install (start.sh --reset)
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

RESET=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --reset) RESET=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    *)
      echo "Usage: ./update.sh [--reset] [--yes]" >&2
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

echo "==> Pulling the latest code"
if ! git pull --ff-only; then
  cat >&2 <<'EOF'
Error: fast-forward pull failed - the local tree has diverged.
If you applied patches without committing, reconcile first:
  git stash && ./update.sh && git stash pop     (keep local edits)
  git reset --hard origin/main && ./update.sh   (discard local edits)
EOF
  exit 1
fi

if [[ $RESET -eq 1 ]]; then
  # Full clean install: start.sh owns the dangerous path (confirmation,
  # this project's volume teardown, fresh secrets).
  if [[ $ASSUME_YES -eq 1 ]]; then
    ./start.sh --reset --yes
  else
    ./start.sh --reset
  fi
  echo "==> Pruning stale Docker cache (dangling images + build cache)"
  docker image prune -f >/dev/null
  docker builder prune -f >/dev/null
  echo "==> Clean install complete."
  exit 0
fi

echo "==> Rebuilding images"
"${COMPOSE[@]}" down --remove-orphans
"${COMPOSE[@]}" build
"${COMPOSE[@]}" up -d

echo "==> Pruning stale Docker cache (dangling images + build cache)"
docker image prune -f >/dev/null
docker builder prune -f >/dev/null

echo "==> Done. Current revision: $(git rev-parse --short HEAD)"
"${COMPOSE[@]}" ps
