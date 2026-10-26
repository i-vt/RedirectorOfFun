"""Decode/decrypt helpers for the verification gate.

Templates supported for submissions and rule evaluation:
  - base64 : standard base64 blob
  - xor    : single-pass XOR with the configured key (bytes of cipher_key)
  - aes256 : AES-256-CBC with PKCS7 padding, key (32 bytes from hex or
             derived by SHA-256 of the passphrase) and IV from hex
"""
import base64
import binascii
import hashlib
import hmac
import json

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class GateCryptoError(ValueError):
    """Raised when a blob cannot be decoded/decrypted or parsed."""


def sanitize_text(value, limit=1000):
    """Strip control characters and cap length for any untrusted text we store.

    Templates autoescape on render; this guards the other consumers: logs,
    terminals, Telegram messages, exports."""
    import re
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", str(value))[:limit]


def sanitize_json_text(value, key_limit=60, value_limit=300):
    """Recursively sanitize keys/strings in untrusted JSON-ish data."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in list(value.items())[:80]:
            cleaned[sanitize_text(key, key_limit)] = sanitize_json_text(item, key_limit, value_limit)
        return cleaned
    if isinstance(value, list):
        return [sanitize_json_text(item, key_limit, value_limit) for item in value[:80]]
    if isinstance(value, str):
        return sanitize_text(value, value_limit)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return sanitize_text(value, value_limit)


def b64_decode(blob: str) -> bytes:
    try:
        return base64.b64decode(blob.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise GateCryptoError(f"invalid base64: {exc}") from exc


def xor_apply(data: bytes, key: str) -> bytes:
    if not key:
        raise GateCryptoError("XOR template requires a key.")
    key_bytes = key.encode()
    return bytes(data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data)))


def _aes_key_bytes(cipher_key: str) -> bytes:
    raw = cipher_key.strip()
    if not raw:
        raise GateCryptoError("AES-256 template requires a key.")
    try:
        key = bytes.fromhex(raw)
        if len(key) == 32:
            return key
    except ValueError:
        pass
    return hashlib.sha256(raw.encode()).digest()


def aes256_decrypt(blob: bytes, cipher_key: str, cipher_iv: str) -> bytes:
    if not cipher_iv:
        raise GateCryptoError("AES-256 template requires an IV.")
    try:
        iv = bytes.fromhex(cipher_iv.strip())
    except ValueError as exc:
        raise GateCryptoError(f"IV must be hex: {exc}") from exc
    if len(iv) != 16:
        raise GateCryptoError("IV must be 16 bytes (32 hex chars).")
    unpadder = padding.PKCS7(128).unpadder()
    try:
        decryptor = Cipher(algorithms.AES(_aes_key_bytes(cipher_key)), modes.CBC(iv)).decryptor()
        padded = decryptor.update(blob) + decryptor.finalize()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise GateCryptoError(f"AES-256 decrypt failed: {exc}") from exc


def decrypt_blob(cipher: str, blob: str, cipher_key: str = "", cipher_iv: str = "") -> bytes:
    """Decode/decrypt a submitted blob according to the operator-selected template."""
    if cipher == "none":
        return blob.encode()
    if cipher == "base64":
        return b64_decode(blob)
    if cipher == "xor":
        return xor_apply(b64_decode(blob), cipher_key)
    if cipher == "aes256":
        return aes256_decrypt(b64_decode(blob), cipher_key, cipher_iv)
    raise GateCryptoError(f"unknown cipher template '{cipher}'.")


def parse_submission_json(data: bytes) -> dict:
    try:
        parsed = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateCryptoError(f"payload is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise GateCryptoError("payload JSON must be an object.")
    return parsed


_IMAGE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"BM", "image/bmp"),
)


def looks_like_image(value: str):
    """Return (content_type, raw_bytes) if the string smells like a base64 image."""
    if not isinstance(value, str) or len(value) < 64:
        return None
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    for signature, content_type in _IMAGE_SIGNATURES:
        if raw[:len(signature)] == signature:
            return content_type, raw
    return None


def extract_images(decoded: dict):
    """Pull image-like fields out of a decoded submission JSON."""
    found = []
    for field, value in decoded.items():
        match = looks_like_image(value)
        if match:
            content_type, raw = match
            found.append({"field": str(field)[:120], "content_type": content_type, "raw": raw})
    return found


def validate_expected_fields(decoded: dict, expected_fields) -> list:
    """Return the list of missing expected fields (empty when valid)."""
    missing = []
    for field in expected_fields or []:
        if field not in decoded:
            missing.append(str(field))
    return missing


def totp_code(secret: str, window_index: int, length: int = 8) -> str:
    """Time-based code. Style comes from the panel-wide GateConfig: truncated
    HMAC hex by default, or a 6-digit decimal code that looks like a standard
    TOTP token."""
    from .models import GateConfig
    style = GateConfig.get_solo().totp_style
    if style == "digits6":
        import struct
        key_bytes = secret.encode()
        digest = hmac.new(key_bytes, struct.pack(">Q", window_index), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        return str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)
    digest = hmac.new(secret.encode(), str(window_index).encode(), hashlib.sha256).hexdigest()
    return digest[:length]


def verify_totp(secret: str, presented: str, window_seconds: int = 30, skew: int = 1) -> bool:
    """Accept the current and previous windows to tolerate network delay."""
    if not secret or not presented:
        return False
    now_window = int(__import__("time").time()) // max(int(window_seconds), 1)
    for index in range(now_window - skew, now_window + 1):
        if hmac.compare_digest(totp_code(secret, index), presented.strip()):
            return True
    return False


def client_presented_token(request):
    """Token from query string or header; headers win."""
    return request.headers.get("X-Gate-Token") or request.GET.get("t", "")
