"""Dependency-free TOTP (RFC 6238) and one-time backup codes for panel operators."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def generate_secret() -> str:
    """Base32-encoded 160-bit secret for authenticator apps (no padding)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int, digits: int = 6) -> str:
    padding = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode((secret + padding).upper())
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(secret: str, for_time=None, step: int = 30, digits: int = 6) -> str:
    counter = int((for_time if for_time is not None else time.time()) // step)
    return _hotp(secret, counter, digits)


def verify(secret: str, code: str, window: int = 1, step: int = 30, digits: int = 6) -> bool:
    """Accept codes from the previous, current, and next window."""
    if not secret or not code:
        return False
    candidate = code.strip().replace(" ", "")
    if not candidate.isdigit():
        return False
    now_counter = int(time.time() // step)
    for delta in range(-window, window + 1):
        if delta < 0 and now_counter + delta < 0:
            continue
        if hmac.compare_digest(_hotp(secret, now_counter + delta, digits), candidate):
            return True
    return False


def provisioning_uri(secret: str, username: str, issuer: str = "RDR-OPS") -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}&issuer={quote(issuer)}&digits=6&period=30"


def generate_backup_codes(count: int = 8) -> list:
    """Return raw backup codes; store only their hashes."""
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(count)]


def hash_backup_code(code: str) -> str:
    normalized = code.strip().lower().replace(" ", "")
    return hashlib.sha256(normalized.encode()).hexdigest()


def consume_backup_code(user, code: str) -> bool:
    """Burn a backup code; returns True once."""
    normalized_hash = hash_backup_code(code)
    hashes = list(user.backup_code_hashes or [])
    if normalized_hash not in hashes:
        return False
    hashes.remove(normalized_hash)
    user.backup_code_hashes = hashes
    user.save(update_fields=["backup_code_hashes"])
    return True
