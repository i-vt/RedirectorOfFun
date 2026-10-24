"""Web Push (VAPID) delivery for the notification outbox."""
import json
import logging

from django.conf import settings

logger = logging.getLogger(__name__)


def deliver(entry):
    """Push one outbox entry to every subscription of its recipient.

    Expired endpoints (404/410) are pruned; the entry fails only when no
    subscription accepted the push.
    """
    from pywebpush import WebPushException, webpush

    from notifications.models import PushSubscription

    if entry.recipient is None:
        raise RuntimeError("webpush entries require a recipient.")
    if not settings.VAPID_PRIVATE_KEY:
        raise RuntimeError("VAPID_PRIVATE_KEY is not configured.")
    subscriptions = PushSubscription.objects.filter(operator=entry.recipient)
    if not subscriptions.exists():
        raise RuntimeError(f"no push subscriptions for {entry.recipient}.")
    payload = json.dumps({
        "title": entry.payload.get("title", "Control plane notification"),
        "body": entry.payload.get("detail", ""),
        "url": entry.payload.get("url", "/panel/submissions/"),
    })
    errors = []
    delivered = 0
    for subscription in subscriptions:
        info = {"endpoint": subscription.endpoint, "keys": subscription.keys}
        try:
            webpush(
                subscription_info=info,
                data=payload,
                vapid_private_key=settings.VAPID_PRIVATE_KEY,
                vapid_claims={"sub": settings.VAPID_ADMIN_EMAIL},
                ttl=300,
            )
            delivered += 1
        except WebPushException as exc:
            status = getattr(exc.response, "status_code", None) if getattr(exc, "response", None) else None
            if status in (404, 410):
                subscription.delete()
                logger.info("pruned dead push subscription %s", subscription.pk)
            else:
                errors.append(str(exc)[:200])
    if delivered == 0:
        raise RuntimeError("; ".join(errors) or "all push deliveries failed")
