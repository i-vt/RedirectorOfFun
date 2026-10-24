from .models import NotificationOutbox, NotificationPreference

DEFAULT_EVENTS = ("security", "operators", "system")


def ensure_default_preferences(operator):
    for event_type in DEFAULT_EVENTS:
        NotificationPreference.objects.get_or_create(
            operator=operator, event_type=event_type, channel="panel", defaults={"enabled": True}
        )


def notify(event_type, payload, recipients=None):
    """Queue notifications; external delivery never blocks the originating action."""
    preferences = NotificationPreference.objects.filter(event_type=event_type, enabled=True).select_related("operator")
    if recipients is not None:
        preferences = preferences.filter(operator__in=recipients)
    entries = [NotificationOutbox(
        recipient=pref.operator, event_type=event_type, channel=pref.channel, payload=payload,
    ) for pref in preferences if pref.operator.is_active]
    return NotificationOutbox.objects.bulk_create(entries)
