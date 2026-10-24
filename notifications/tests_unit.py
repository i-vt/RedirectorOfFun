from django.db import IntegrityError
from django.test import TestCase, tag
from accounts.models import Operator
from .models import NotificationOutbox, NotificationPreference
from .services import ensure_default_preferences, notify


@tag("unit")
class NotificationModelUnitTests(TestCase):
    def setUp(self):
        self.user = Operator.objects.create_user(username="unit-notify", password="Unit-Test-Password-91!")

    def test_outbox_defaults_are_retry_safe(self):
        entry = NotificationOutbox.objects.create(recipient=self.user, event_type="system", channel="panel", payload={})
        self.assertEqual(entry.status, "pending")
        self.assertEqual(entry.attempts, 0)
        self.assertIsNotNone(entry.available_at)

    def test_preference_uniqueness(self):
        NotificationPreference.objects.create(operator=self.user, event_type="system", channel="panel")
        with self.assertRaises(IntegrityError):
            NotificationPreference.objects.create(operator=self.user, event_type="system", channel="panel")

    def test_default_preferences_are_idempotent(self):
        ensure_default_preferences(self.user)
        ensure_default_preferences(self.user)
        self.assertEqual(NotificationPreference.objects.filter(operator=self.user, channel="panel").count(), 3)

    def test_disabled_preference_does_not_enqueue(self):
        NotificationPreference.objects.create(operator=self.user, event_type="system", channel="panel", enabled=False)
        notify("system", {"title": "Disabled"})
        self.assertEqual(NotificationOutbox.objects.count(), 0)

    def test_recipient_filter_is_enforced(self):
        other = Operator.objects.create_user(username="other-notify", password="Unit-Test-Password-91!")
        ensure_default_preferences(self.user)
        ensure_default_preferences(other)
        notify("system", {"title": "Scoped"}, recipients=[self.user])
        self.assertEqual(NotificationOutbox.objects.count(), 1)
        self.assertEqual(NotificationOutbox.objects.get().recipient, self.user)
