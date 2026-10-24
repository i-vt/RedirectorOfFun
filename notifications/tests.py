from django.core.management import call_command
from django.test import TestCase, tag
from accounts.models import Operator
from .models import NotificationOutbox, NotificationPreference
from .services import ensure_default_preferences, notify


@tag("functional")
class NotificationTests(TestCase):
    def setUp(self):
        self.user = Operator.objects.create_user(username="notify", password="Notification-Test-Password-91!")
        ensure_default_preferences(self.user)

    def test_security_event_creates_panel_outbox(self):
        notify("security", {"title": "Test", "detail": "Safe delivery"})
        entry = NotificationOutbox.objects.get()
        self.assertEqual(entry.channel, "panel")
        self.assertEqual(entry.status, "pending")
        self.assertEqual(entry.recipient, self.user)

    def test_panel_delivery_does_not_need_external_provider(self):
        notify("security", {"title": "Test", "detail": "Safe delivery"})
        call_command("deliver_notifications", "--once")
        entry = NotificationOutbox.objects.get()
        self.assertEqual(entry.status, "sent")
        self.assertIsNotNone(entry.sent_at)

    def test_telegram_failure_is_recorded_without_secret_leak(self):
        NotificationPreference.objects.create(operator=self.user, event_type="security", channel="telegram", enabled=True)
        notify("security", {"title": "Test", "detail": "Safe delivery"})
        call_command("deliver_notifications", "--once")
        entry = NotificationOutbox.objects.get(channel="telegram")
        self.assertEqual(entry.status, "failed")
        self.assertEqual(entry.attempts, 1)
        self.assertIn("not configured", entry.last_error)

    def test_preference_update_is_scoped_to_operator(self):
        other = Operator.objects.create_user(username="other", password="Other-Test-Password-91!")
        preference = NotificationPreference.objects.create(operator=other, event_type="security", channel="panel")
        self.client.force_login(self.user)
        response = self.client.patch(f"/api/v1/notification-preferences/{preference.pk}/", data='{"enabled":false}', content_type="application/json")
        self.assertEqual(response.status_code, 404)
