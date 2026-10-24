from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class Operator(AbstractUser):
    session_version = models.PositiveIntegerField(default=1)
    totp_secret = models.CharField(max_length=64, blank=True)
    totp_enabled = models.BooleanField(default=False)
    backup_code_hashes = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["username"]


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
