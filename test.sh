#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
MODE="${1:---all}"
if [[ $# -gt 1 ]] || [[ ! "$MODE" =~ ^(--all|--unit|--functional|--e2e)$ ]]; then
  echo "Usage: ./test.sh [--all|--unit|--functional|--e2e]" >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker is required for the isolated test stack." >&2
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
if ! command -v curl >/dev/null 2>&1; then
  echo "Error: curl is required for readiness checks." >&2
  exit 1
fi

PROJECT="redirector-control-plane-test"
TEST_COMPOSE=("${COMPOSE[@]}" -p "$PROJECT" -f docker-compose.test.yml)
RUNTIME_DIR="$PWD/.test-runtime"
mkdir -p "$RUNTIME_DIR"

cleanup() {
  local status=$?
  if [[ "${KEEP_TEST_ENV:-0}" == "1" ]]; then
    echo "Keeping test stack at http://localhost:3100 (KEEP_TEST_ENV=1)."
  else
    "${TEST_COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$RUNTIME_DIR" || true
  fi
  exit $status
}
trap cleanup EXIT INT TERM

build_image() {
  echo "Building isolated test image…"
  "${TEST_COMPOSE[@]}" build test-panel
}

run_backend_suite() {
  local tag=$1
  echo "\n=== ${tag^^} TESTS ==="
  "${TEST_COMPOSE[@]}" run --rm --no-deps \
    -e DJANGO_SETTINGS_MODULE=config.settings \
    test-panel python manage.py test --tag "$tag" --verbosity 1
}

seed_nginx_log() {
  echo "Seeding dynamic nginx JSON fixture…"
  "${TEST_COMPOSE[@]}" run --rm --no-deps -T \
    test-panel python - <<'PY'
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
now = datetime.now(timezone.utc)
path = Path("/test-runtime/nginx-access.json")
with path.open("w") as handle:
    for index in range(55):
        requested_path = "/download" if index % 2 == 0 else f"/missing/{index % 5}"
        if index == 54:
            requested_path = "/<script>alert(1)</script>"
        record = {
            "time": (now - timedelta(hours=index % 24)).isoformat(),
            "request_id": f"e2e-{index:04d}",
            "method": "POST" if index % 3 == 0 else "GET",
            "path": requested_path,
            "status": 404,
            "remote_addr": f"203.0.113.{index % 20 + 1}",
        }
        handle.write(json.dumps(record) + "\n")
    handle.write(json.dumps({
        "time": now.isoformat(), "request_id": "e2e-ignore-200", "method": "GET",
        "path": "/", "status": 200, "remote_addr": "127.0.0.1",
    }) + "\n")
PY
}

build_browser_runner() {
  echo "Building isolated browser runner (Playwright + Chromium inside Docker; nothing touches the host OS)…"
  "${TEST_COMPOSE[@]}" build test-browser
}

run_e2e_suite() {
  echo "\n=== END-TO-END FULL SUITE ==="
  "${TEST_COMPOSE[@]}" up -d test-panel
  echo "Waiting for isolated stack at http://localhost:3100…"
  for attempt in $(seq 1 60); do
    if curl -fsS http://localhost:3100/health/ready/ >/dev/null 2>&1; then
      break
    fi
    if [[ $attempt -eq 60 ]]; then
      "${TEST_COMPOSE[@]}" logs --tail=100 test-panel >&2
      echo "Isolated test stack failed to become ready." >&2
      exit 1
    fi
    sleep 2
  done
  seed_nginx_log
  "${TEST_COMPOSE[@]}" exec -T test-panel python manage.py ingest_404_logs --path /test-runtime/nginx-access.json --once
  "${TEST_COMPOSE[@]}" exec -T test-panel python manage.py deliver_notifications --once
  BOOTSTRAP_URL=$("${TEST_COMPOSE[@]}" logs test-panel 2>&1 | sed -nE 's#.*(http://[^/[:space:]]+/setup/[^/[:space:]]+/).*#\1#p' | tail -1)
  if [[ -z "$BOOTSTRAP_URL" ]]; then
    echo "Could not obtain the one-time setup URL from test-panel logs." >&2
    exit 1
  fi
  build_browser_runner
  "${TEST_COMPOSE[@]}" run --rm --no-deps \
    -e E2E_BASE_URL="http://test-panel:3100" \
    -e E2E_BOOTSTRAP_URL="$BOOTSTRAP_URL" \
    -e E2E_EXPECTED_EVENTS=55 \
    -e E2E_EXPECTED_DOWNLOADS=27 \
    -e E2E_EXPECTED_DOWNLOAD_POSTS=9 \
    -v "$PWD/tests:/suite/tests:ro" \
    test-browser tests/e2e/full_suite.py
}

case "$MODE" in
  --all)
    build_image
    run_backend_suite unit
    run_backend_suite functional
    run_e2e_suite
    ;;
  --unit)
    build_image
    run_backend_suite unit
    ;;
  --functional)
    build_image
    run_backend_suite functional
    ;;
  --e2e)
    build_image
    run_e2e_suite
    ;;
esac

echo "\nAll requested test stages passed."
