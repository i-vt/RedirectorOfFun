from django.test import TestCase, tag
from django.utils import timezone
from .services import dashboard_statistics, event_from_record, hash_address


@tag("unit")
class AnalyticsParsingUnitTests(TestCase):
    def test_address_hash_is_stable_and_input_specific(self):
        first = hash_address("203.0.113.10")
        self.assertEqual(first, hash_address("203.0.113.10"))
        self.assertNotEqual(first, hash_address("203.0.113.11"))
        self.assertEqual(hash_address(""), "")

    def test_non_404_records_are_ignored(self):
        self.assertIsNone(event_from_record({"status": 200, "request_id": "ok"}))

    def test_record_fields_are_normalized(self):
        event = event_from_record({
            "time": timezone.now().isoformat(), "request_id": "abc", "status": 404,
            "method": "post", "path": "/missing", "remote_addr": "203.0.113.10",
            "country_code": "us", "city": "Testville",
        })
        self.assertEqual(event.method, "POST")
        self.assertEqual(event.country_code, "US")
        self.assertEqual(event.status, 404)
        self.assertTrue(timezone.is_aware(event.occurred_at))

    def test_missing_request_id_has_idempotent_fallback(self):
        line = '{"status":404,"method":"GET","path":"/same"}'
        first = event_from_record({"status": 404, "method": "GET", "path": "/same"}, line)
        second = event_from_record({"status": 404, "method": "GET", "path": "/same"}, line)
        self.assertEqual(first.request_id, second.request_id)
        self.assertEqual(len(first.request_id), 64)

    def test_empty_statistics_have_complete_shape(self):
        stats = dashboard_statistics(14)
        self.assertEqual(stats["total"], 0)
        self.assertEqual(stats["unique_paths"], 0)
        self.assertEqual(len(stats["series"]), 14)
        self.assertEqual(stats["top_paths"], [])
        self.assertTrue(all(item["count"] == 0 for item in stats["series"]))
