import json
import time
import urllib.request
from datetime import timedelta
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from notifications.models import NotificationOutbox


class Command(BaseCommand):
    help = "Deliver queued panel, browser, and Telegram notifications with bounded retries."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--sleep", type=float, default=3.0)

    def handle(self, *args, **options):
        while True:
            delivered = self.deliver_batch()
            if delivered:
                self.stdout.write(f"Delivered {delivered} notifications.")
            if options["once"]:
                return
            time.sleep(max(options["sleep"], 0.5))

    def deliver_batch(self):
        entries = NotificationOutbox.objects.filter(
            status__in=["pending", "failed"], attempts__lt=5, available_at__lte=timezone.now(),
        ).order_by("created_at")[:100]
        delivered = 0
        for entry in entries:
            try:
                if entry.channel == "telegram":
                    self.send_telegram(entry)
                elif entry.channel == "webpush":
                    self.send_webpush(entry)
                with transaction.atomic():
                    entry.status = "sent"
                    entry.sent_at = timezone.now()
                    entry.attempts += 1
                    entry.last_error = ""
                    entry.save(update_fields=["status", "sent_at", "attempts", "last_error"])
                delivered += 1
            except Exception as exc:
                entry.attempts += 1
                entry.status = "failed"
                entry.last_error = str(exc)[:1000]
                entry.available_at = timezone.now() + timedelta(seconds=min(2 ** entry.attempts * 15, 900))
                entry.save(update_fields=["attempts", "status", "last_error", "available_at"])
        return delivered

    @staticmethod
    def send_telegram(entry):
        if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
            raise RuntimeError("Telegram channel is not configured.")
        from gates.telegram import decision_keyboard
        payload = entry.payload
        message = {
            "chat_id": settings.TELEGRAM_CHAT_ID,
            "text": f"{payload.get('title', 'Control plane notification')}\n{payload.get('detail', '')}",
        }
        if payload.get("decision") and payload.get("submission_id"):
            message["reply_markup"] = decision_keyboard(int(payload["submission_id"]))
        body = json.dumps(message).encode()
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage",
            data=body, headers={"Content-Type": "application/json",
                                "User-Agent": settings.OUTBOUND_USER_AGENT}, method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status != 200:
                raise RuntimeError(f"Telegram returned HTTP {response.status}.")

    @staticmethod
    def send_webpush(entry):
        from gates.webpush import deliver as deliver_webpush
        deliver_webpush(entry)
