"""DRF authentication for operator API keys.

Usage:  Authorization: ApiKey rofk_<secret>
The key authenticates as its owning operator with the operator's roles;
it is a credential of its own (like a password) and does not interact
with TOTP 2FA.
"""
import hashlib
import hmac

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import APIKey


class APIKeyAuthentication(BaseAuthentication):
    keyword = "ApiKey"

    def authenticate(self, request):
        header = request.headers.get("Authorization", "")
        if not header.startswith(self.keyword + " "):
            return None
        raw = header[len(self.keyword) + 1:].strip()
        if not raw:
            return None
        api_key = (APIKey.objects.select_related("operator")
                   .filter(prefix=raw[:16], is_active=True).first())
        candidate = hashlib.sha256(raw.encode()).hexdigest()
        if api_key is None or not hmac.compare_digest(api_key.key_hash, candidate):
            raise AuthenticationFailed("Invalid API key.")
        if api_key.expired:
            raise AuthenticationFailed("API key expired.")
        if not api_key.operator.is_active:
            raise AuthenticationFailed("Operator is deactivated.")
        api_key.touch(request)
        return (api_key.operator, api_key)

    def authenticate_header(self, request):
        return self.keyword
