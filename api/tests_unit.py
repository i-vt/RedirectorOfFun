from django.test import TestCase, tag
from accounts.models import Operator
from analytics.models import NotFoundEvent
from django.utils import timezone
from .pagination import EventCursorPagination
from .serializers import NotFoundEventSerializer, NotificationPreferenceSerializer, OperatorSerializer


@tag("unit")
class SerializerAndPaginationUnitTests(TestCase):
    def test_operator_serializer_never_exposes_credentials(self):
        operator = Operator.objects.create_user(username="serialize", password="Unit-Test-Password-91!")
        data = OperatorSerializer(operator).data
        self.assertNotIn("password", data)
        self.assertNotIn("session_version", data)
        self.assertIn("roles", data)

    def test_event_serializer_contains_hash_not_raw_ip_field(self):
        event = NotFoundEvent.objects.create(request_id="serialize", occurred_at=timezone.now(), method="GET", path="/", source_ip_hash="a" * 64)
        data = NotFoundEventSerializer(event).data
        self.assertEqual(data["source_ip_hash"], "a" * 64)
        self.assertNotIn("remote_addr", data)
        self.assertNotIn("source_ip", data)

    def test_notification_preference_identity_fields_are_read_only(self):
        serializer = NotificationPreferenceSerializer()
        self.assertIn("event_type", serializer.Meta.read_only_fields)
        self.assertIn("channel", serializer.Meta.read_only_fields)
        self.assertIn("enabled", serializer.Meta.fields)

    def test_event_cursor_uses_stable_tiebreaker(self):
        self.assertEqual(EventCursorPagination.ordering, ("-occurred_at", "-id"))
        self.assertEqual(EventCursorPagination.page_size, 50)
