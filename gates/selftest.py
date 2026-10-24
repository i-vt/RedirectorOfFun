"""Startup self-tests for the gate control plane.

Failures are split into two classes:
  - blocking : database, migrations, crypto round-trip, storage - the panel
               must not start if any of these fail.
  - warning  : reachability/configuration checks (pwndrop, telegram, nginx
               include paths) - reported but non-fatal.
"""
import socket
import urllib.request
from urllib.parse import urlparse

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from .crypto_utils import GateCryptoError, aes256_decrypt, b64_decode, decrypt_blob, xor_apply
from .models import DeliveryLink


def _check_database():
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        cursor.fetchone()
    executor = MigrationExecutor(connection)
    pending = executor.migration_plan(executor.loader.graph.leaf_nodes())
    if pending:
        return "fail", f"{len(pending)} migration(s) pending - run manage.py migrate"
    return "pass", "database reachable, migrations applied"


def _check_crypto():
    sample = b'{"hostname":"dc01","note":"self-test"}'
    if b64_decode(__import__("base64").b64encode(sample).decode()) != sample:
        return "fail", "base64 round-trip mismatch"
    if xor_apply(xor_apply(sample, "k3y"), "k3y") != sample:
        return "fail", "xor round-trip mismatch"
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import hashlib, os
    key = hashlib.sha256(b"selftest-pass").digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(sample) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    blob = enc.update(padded) + enc.finalize()
    if aes256_decrypt(blob, key.hex(), iv.hex()) != sample:
        return "fail", "aes256 round-trip mismatch"
    try:
        decrypt_blob("aes256", __import__("base64").b64encode(b"junk").decode(), key.hex(), iv.hex())
        return "fail", "aes256 accepted invalid ciphertext"
    except GateCryptoError:
        pass
    return "pass", "base64/xor/aes256 templates round-trip; tamper rejected"


def _check_storage():
    probe = default_storage.save("selftest/probe.txt", ContentFile(b"ok"))
    try:
        with default_storage.open(probe, "rb") as handle:
            if handle.read() != b"ok":
                return "fail", "storage read-back mismatch"
    finally:
        default_storage.delete(probe)
    return "pass", "media storage read/write OK"


def _check_pwndrop():
    urls = DeliveryLink.objects.filter(kind="proxy", active=True).exclude(pwndrop_url="")[:3]
    if not urls:
        return "skip", "no active proxy links configured"
    problems = []
    for link in urls:
        parsed = urlparse(link.pwndrop_url)
        try:
            with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=3):
                pass
        except OSError as exc:
            problems.append(f"{link.path}: {exc}")
    if problems:
        return "warn", "; ".join(problems)
    return "pass", f"{urls.count()} pwndrop source(s) reachable"


def _check_telegram():
    token = getattr(settings, "TELEGRAM_BOT_TOKEN", "")
    chat = getattr(settings, "TELEGRAM_CHAT_ID", "")
    if not token and not chat:
        return "skip", "telegram not configured"
    if token and ":" not in token:
        return "warn", "TELEGRAM_BOT_TOKEN does not look like a bot token"
    if not chat:
        return "warn", "telegram token set but TELEGRAM_CHAT_ID empty"
    return "pass", "telegram configuration present"


def _check_nginx_sync_paths():
    paths = [getattr(settings, "NGINX_BAN_INCLUDE", ""), getattr(settings, "NGINX_AGENT_ROUTES_INCLUDE", "")]
    paths = [p for p in paths if p]
    if not paths:
        return "skip", "no nginx include paths configured (sync disabled)"
    import os
    missing = [p for p in paths if not os.path.isdir(os.path.dirname(p))]
    if missing:
        return "warn", f"include target directories missing: {missing}"
    return "pass", f"{len(paths)} nginx include path(s) writable targets exist"


def _check_secrets():
    if settings.SECRET_KEY.startswith("development-only"):
        return "warn", "DJANGO_SECRET_KEY is the development default"
    return "pass", "secret key configured"


CHECKS = [
    ("database", _check_database, True),
    ("crypto_templates", _check_crypto, True),
    ("media_storage", _check_storage, True),
    ("pwndrop_reachability", _check_pwndrop, False),
    ("telegram_config", _check_telegram, False),
    ("nginx_sync_paths", _check_nginx_sync_paths, False),
    ("secrets", _check_secrets, False),
]


def run_selftest():
    results = []
    for name, check, blocking in CHECKS:
        try:
            status, message = check()
        except Exception as exc:  # a self-test must never crash startup
            status, message = "fail", f"unexpected error: {exc}"
        results.append({"name": name, "status": status, "blocking": blocking, "message": message})
    return results


def is_healthy(results):
    return not any(r["status"] == "fail" and r["blocking"] for r in results)
