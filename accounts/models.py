from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class Operator(AbstractUser):
    THEME_CHOICES = [("default", "Default"), ("cozy", "Cozy Clown"), ("obnoxious", "Obnoxious Clown")]

    session_version = models.PositiveIntegerField(default=1)
    totp_secret = models.CharField(max_length=64, blank=True)
    totp_enabled = models.BooleanField(default=False)
    backup_code_hashes = models.JSONField(default=list, blank=True)
    theme = models.CharField(max_length=16, choices=THEME_CHOICES, default="default")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["username"]


def generate_api_key_raw():
    import secrets
    return "rofk_" + secrets.token_urlsafe(32)


class APIKey(models.Model):
    """Programmatic credential for an operator. The full key is shown once
    at creation; only its SHA-256 and a lookup prefix are stored."""

    name = models.CharField(max_length=120)
    operator = models.ForeignKey(Operator, on_delete=models.CASCADE, related_name="api_keys")
    prefix = models.CharField(max_length=20, unique=True)
    key_hash = models.CharField(max_length=64, unique=True)
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(Operator, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="api_keys_created")
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_used_ip = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.prefix})"

    @property
    def expired(self):
        return bool(self.expires_at and timezone.now() >= self.expires_at)

    @classmethod
    def create(cls, *, operator, name, created_by=None, expires_at=None):
        import hashlib
        raw = generate_api_key_raw()
        return cls.objects.create(
            operator=operator, name=name[:120], created_by=created_by, expires_at=expires_at,
            prefix=raw[:16], key_hash=hashlib.sha256(raw.encode()).hexdigest()), raw

    def touch(self, request):
        """Record use at most once a minute to avoid write amplification."""
        from datetime import timedelta
        if self.last_used_at and timezone.now() - self.last_used_at < timedelta(minutes=1):
            return
        ip = request.META.get("REMOTE_ADDR", "")[:64] if request else ""
        APIKey.objects.filter(pk=self.pk).update(last_used_at=timezone.now(), last_used_ip=ip)


class BootstrapState(models.Model):
    slot = models.PositiveSmallIntegerField(default=1, unique=True)
    token_digest = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    claimed_at = models.DateTimeField(null=True, blank=True)
    claimed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="bootstrap_claims",
    )
    disabled = models.BooleanField(default=False)

    @property
    def expired(self):
        ttl = settings.BOOTSTRAP_TOKEN_TTL_MINUTES
        return bool(ttl and not self.claimed_at and timezone.now() > self.created_at + timezone.timedelta(minutes=ttl))


class Invitation(models.Model):
    ROLE_CHOICES = [("Operator", "Operator"), ("Auditor", "Auditor"), ("Administrator", "Administrator")]
    username = models.CharField(max_length=150)
    email = models.EmailField(blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="Operator")
    token_digest = models.CharField(max_length=64, unique=True)
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="invitations_sent")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    @property
    def available(self):
        return not self.consumed_at and not self.revoked_at and self.expires_at > timezone.now()
