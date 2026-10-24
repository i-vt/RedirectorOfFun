from django.conf import settings
from django.db import models
from django.utils import timezone


class NotificationPreference(models.Model):
    EVENT_CHOICES = [
        ("security", "Security and authentication"),
        ("operators", "Operator administration"),
        ("system", "System health"),
        ("analytics", "404 analytics"),
        ("gates", "Gates and deliveries"),
        ("suspicious", "Suspicious activity"),
    ]
    CHANNEL_CHOICES = [("panel", "Panel"), ("browser", "Browser"), ("telegram", "Telegram"), ("webpush", "Web Push")]
    operator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notification_preferences")
    event_type = models.CharField(max_length=20, choices=EVENT_CHOICES)
    channel = models.CharField(max_length=20, choices=CHANNEL_CHOICES)
    enabled = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["operator", "event_type", "channel"], name="unique_notification_preference")]


class PushSubscription(models.Model):
    """Browser push subscription (VAPID) tied to an operator's device."""

    operator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="push_subscriptions")
    endpoint = models.URLField(max_length=1000, unique=True)
    keys = models.JSONField(default=dict)
    user_agent = models.CharField(max_length=300, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"push subscription #{self.pk} for {self.operator}"


class NotificationOutbox(models.Model):
    STATUS_CHOICES = [("pending", "Pending"), ("sent", "Sent"), ("failed", "Failed")]
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=20)
    channel = models.CharField(max_length=20)
    payload = models.JSONField(default=dict)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending", db_index=True)
    attempts = models.PositiveIntegerField(default=0)
    available_at = models.DateTimeField(default=timezone.now, db_index=True)
    last_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
