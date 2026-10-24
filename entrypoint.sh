#!/bin/sh
set -eu

python manage.py check
python manage.py migrate --noinput
python manage.py selftest --strict || { echo "SELF-TEST FAILED - refusing to start (set SELFTEST_SKIP=true to override)"; [ "${SELFTEST_SKIP:-false}" = "true" ] || exit 1; }
python manage.py ensure_bootstrap

if [ "${RUN_COLLECTOR:-false}" = "true" ]; then
  python manage.py ingest_404_logs &
fi
if [ "${RUN_NOTIFICATION_WORKER:-false}" = "true" ]; then
  python manage.py deliver_notifications &
fi

exec gunicorn config.wsgi:application \
  --bind "0.0.0.0:${PORT:-3000}" \
  --workers "${GUNICORN_WORKERS:-2}" \
  --threads "${GUNICORN_THREADS:-4}" \
  --access-logfile - \
  --error-logfile -
