import json
import os
from datetime import timedelta
from django.core.management import call_command
from django.test import TestCase, tag
from django.urls import reverse
from django.utils import timezone
from accounts.models import Operator
from .models import CollectorState, NotFoundEvent
from .services import dashboard_statistics, event_from_record


@tag("functional")
class AnalyticsTests(TestCase):
    def setUp(self):
        self.user = Operator.objects.create_user(username="analyst", password="Analytics-Test-Password-91!")

    def write_log(self, path):
        records = [
            {"time": timezone.now().isoformat(), "request_id": "one", "method": "GET", "path": "/missing", "status": 404, "remote_addr": "203.0.113.1"},
            {"time": timezone.now().isoformat(), "request_id": "two", "method": "GET", "path": "/<script>alert(1)</script>", "status": 404, "remote_addr": "203.0.113.2"},
            {"time": timezone.now().isoformat(), "request_id": "ignored", "method": "GET", "path": "/", "status": 200, "remote_addr": "127.0.0.1"},
        ]
        with open(path, "w") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")
            handle.write("not-valid-json\n")

    def test_ingestion_is_idempotent_and_ignores_non_404(self):
        path = "/tmp/test-nginx-access.json"
        self.write_log(path)
        call_command("ingest_404_logs", "--path", path, "--once")
        call_command("ingest_404_logs", "--path", path, "--once")
        self.assertEqual(NotFoundEvent.objects.count(), 2)
        self.assertEqual(CollectorState.objects.count(), 1)

    def test_log_rotation_restarts_checkpoint_and_ingests_new_file(self):
        path = "/tmp/test-nginx-rotation.json"
        replacement = "/tmp/test-nginx-rotation.new"
        self.write_log(path)
        call_command("ingest_404_logs", "--path", path, "--once")
        with open(replacement, "w") as handle:
            handle.write(json.dumps({"time": timezone.now().isoformat(), "request_id": "rotated", "method": "GET", "path": "/rotated", "status": 404}) + "\n")
        os.replace(replacement, path)
        call_command("ingest_404_logs", "--path", path, "--once")
        self.assertEqual(NotFoundEvent.objects.count(), 3)
        self.assertTrue(NotFoundEvent.objects.filter(request_id="rotated").exists())

    def test_event_does_not_store_raw_ip(self):
        event = event_from_record({"request_id": "x", "status": 404, "method": "GET", "path": "/", "remote_addr": "203.0.113.9"})
        self.assertNotIn("203.0.113.9", event.source_ip_hash)
        self.assertEqual(len(event.source_ip_hash), 64)

    def test_dashboard_escapes_untrusted_path(self):
        NotFoundEvent.objects.create(request_id="xss", occurred_at=timezone.now(), method="GET", path="/<script>alert(1)</script>")
        self.client.force_login(self.user)
        response = self.client.get(reverse("overview"))
        self.assertNotContains(response, "/<script>alert(1)</script>")
        self.assertContains(response, "&lt;script&gt;")

    def test_stats_and_filters(self):
        NotFoundEvent.objects.create(request_id="one", occurred_at=timezone.now(), method="GET", path="/alpha")
        NotFoundEvent.objects.create(request_id="two", occurred_at=timezone.now(), method="POST", path="/beta")
        stats = dashboard_statistics(14)
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["unique_paths"], 2)
        self.client.force_login(self.user)
        response = self.client.get(reverse("events"), {"method": "POST"})
        self.assertContains(response, "/beta")
        self.assertNotContains(response, "/alpha")

    def test_retention(self):
        NotFoundEvent.objects.create(request_id="old", occurred_at=timezone.now() - timedelta(days=60), method="GET", path="/old")
        call_command("prune_events", "--days", "30")
        self.assertFalse(NotFoundEvent.objects.filter(request_id="old").exists())

    def test_api_requires_authentication(self):
        response = self.client.get(reverse("api-404-stats"))
        self.assertIn(response.status_code, (401, 403))
