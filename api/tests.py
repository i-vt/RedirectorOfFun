import json
from datetime import timedelta
from django.contrib.auth.models import Group
from django.test import TestCase, tag
from django.urls import reverse
from django.utils import timezone
from accounts.models import Operator
from accounts.services import ensure_role_groups
from analytics.models import NotFoundEvent
from audit.models import AuditEvent
from notifications.models import NotificationOutbox, NotificationPreference

ADMIN_PASSWORD = "API-Admin-Password-91!"
USER_PASSWORD = "API-User-Password-91!"


@tag("functional")
class APITests(TestCase):
    def setUp(self):
        ensure_role_groups()
        self.admin = Operator.objects.create_user(username="admin", password=ADMIN_PASSWORD, is_superuser=True, is_staff=True)
        self.admin.groups.add(Group.objects.get(name="Administrator"))
        self.user = Operator.objects.create_user(username="user", password=USER_PASSWORD)
        self.old_event = NotFoundEvent.objects.create(
            request_id="old", occurred_at=timezone.now() - timedelta(days=45), method="GET", path="/old", source_ip_hash="b" * 64,
        )
        self.event = NotFoundEvent.objects.create(
            request_id="recent", occurred_at=timezone.now(), method="POST", path="/download", source_ip_hash="a" * 64,
        )
        self.audit = AuditEvent.objects.create(actor=self.admin, action="test.started", target_type="Operator", target_id=str(self.user.pk), request_id="request-1")
        self.preference = NotificationPreference.objects.create(operator=self.user, event_type="security", channel="panel", enabled=True)
        self.notification = NotificationOutbox.objects.create(recipient=self.user, event_type="security", channel="panel", payload={"title": "Test", "detail": "Scoped"})

    def login_admin(self):
        self.client.force_login(self.admin)

    def login_user(self):
        self.client.force_login(self.user)

    def test_every_private_api_requires_authentication(self):
        urls = [
            "/api/v1/404-events/", "/api/v1/404-stats/", "/api/v1/audit-events/",
            "/api/v1/operators/", "/api/v1/notification-preferences/", "/api/v1/notifications/recent/",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertIn(self.client.get(url).status_code, (401, 403))

    def test_operator_list_requires_admin_and_uses_pagination_envelope(self):
        self.login_user()
        self.assertEqual(self.client.get("/api/v1/operators/").status_code, 403)
        self.login_admin()
        response = self.client.get("/api/v1/operators/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 2)
        usernames = {item["username"] for item in payload["results"]}
        self.assertEqual(usernames, {"admin", "user"})
        self.assertNotIn("password", payload["results"][0])

    def test_api_revoke_writes_audit_and_deactivates(self):
        self.login_admin()
        response = self.client.post(f"/api/v1/operators/{self.user.pk}/revoke/")
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertTrue(AuditEvent.objects.filter(action="operator.deactivated").exists())

    def test_api_revoke_rejects_non_admin_and_self_deactivation(self):
        self.login_user()
        self.assertEqual(self.client.post(f"/api/v1/operators/{self.user.pk}/revoke/").status_code, 403)
        self.login_admin()
        response = self.client.post(f"/api/v1/operators/{self.admin.pk}/revoke/")
        self.assertEqual(response.status_code, 400)
        self.assertIn("own account", response.json()["detail"])

    def test_event_list_contains_expected_fields_but_no_raw_address(self):
        self.login_user()
        response = self.client.get("/api/v1/404-events/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["results"]), 1)
        serialized = json.dumps(payload)
        self.assertIn("source_ip_hash", serialized)
        self.assertNotIn("remote_addr", serialized)

    def test_event_cursor_pagination_follows_next_link(self):
        for index in range(53):
            NotFoundEvent.objects.create(request_id=f"bulk-{index}", occurred_at=timezone.now(), method="GET", path=f"/bulk/{index}")
        self.login_user()
        first = self.client.get("/api/v1/404-events/")
        payload = first.json()
        self.assertEqual(len(payload["results"]), 50)
        self.assertIsNotNone(payload["next"])
        second = self.client.get(payload["next"])
        self.assertEqual(second.status_code, 200)
        self.assertEqual(len(second.json()["results"]), 4)

    def test_event_filters_cover_path_method_and_time(self):
        self.login_user()
        response = self.client.get("/api/v1/404-events/", {"path": "download", "method": "POST", "days": 30})
        self.assertEqual(len(response.json()["results"]), 1)
        self.assertEqual(response.json()["results"][0]["request_id"], "recent")
        response = self.client.get("/api/v1/404-events/", {"method": "GET", "days": 365})
        self.assertEqual(len(response.json()["results"]), 1)
        self.assertEqual(response.json()["results"][0]["request_id"], "old")

    def test_stats_success_and_invalid_days(self):
        self.login_user()
        response = self.client.get("/api/v1/404-stats/", {"days": 14})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 2)
        self.assertEqual(response.json()["period"], 1)
        self.assertEqual(len(response.json()["series"]), 14)
        self.assertEqual(self.client.get("/api/v1/404-stats/", {"days": "invalid"}).status_code, 400)

    def test_audit_list_returns_actor_action_and_request_id(self):
        self.login_user()
        response = self.client.get("/api/v1/audit-events/")
        self.assertEqual(response.status_code, 200)
        result = response.json()["results"][0]
        self.assertEqual(result["action"], "test.started")
        self.assertEqual(result["actor"], "admin")
        self.assertEqual(result["request_id"], "request-1")

    def test_notification_preferences_are_scoped_and_patchable(self):
        other = Operator.objects.create_user(username="other", password=USER_PASSWORD)
        NotificationPreference.objects.create(operator=other, event_type="system", channel="telegram")
        self.login_user()
        response = self.client.get("/api/v1/notification-preferences/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 1)
        detail = self.client.get(f"/api/v1/notification-preferences/{self.preference.pk}/")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["event_type"], "security")
        response = self.client.patch(
            f"/api/v1/notification-preferences/{self.preference.pk}/",
            data=json.dumps({"enabled": False, "event_type": "analytics", "channel": "telegram"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.preference.refresh_from_db()
        self.assertFalse(self.preference.enabled)
        self.assertEqual(self.preference.event_type, "security")
        self.assertEqual(self.preference.channel, "panel")

    def test_notification_preference_cannot_patch_another_operator(self):
        other = Operator.objects.create_user(username="other", password=USER_PASSWORD)
        preference = NotificationPreference.objects.create(operator=other, event_type="security", channel="panel")
        self.login_user()
        response = self.client.patch(f"/api/v1/notification-preferences/{preference.pk}/", data='{"enabled":false}', content_type="application/json")
        self.assertEqual(response.status_code, 404)

    def test_recent_notifications_are_scoped_and_support_after_cursor(self):
        later = NotificationOutbox.objects.create(recipient=self.user, event_type="system", channel="panel", payload={"title": "Later"})
        NotificationOutbox.objects.create(recipient=self.admin, event_type="system", channel="panel", payload={"title": "Other"})
        self.login_user()
        response = self.client.get("/api/v1/notifications/recent/")
        self.assertEqual(len(response.json()), 2)
        response = self.client.get("/api/v1/notifications/recent/", {"after": self.notification.pk})
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.json()[0]["id"], later.pk)

    def test_read_only_endpoints_reject_writes(self):
        self.login_admin()
        self.assertEqual(self.client.post("/api/v1/404-events/").status_code, 405)
        self.assertEqual(self.client.post("/api/v1/404-stats/").status_code, 405)
        self.assertEqual(self.client.post("/api/v1/audit-events/").status_code, 405)

    def test_health_endpoints_are_public_and_separate(self):
        live = self.client.get("/health/live/")
        ready = self.client.get("/health/ready/")
        self.assertEqual(live.status_code, 200)
        self.assertEqual(ready.status_code, 200)
        self.assertEqual(live.json()["status"], "ok")
        self.assertEqual(ready.json()["pending_migrations"], 0)


@tag("functional")
class PanelFunctionalityTests(TestCase):
    def setUp(self):
        self.user = Operator.objects.create_user(username="panel", password=USER_PASSWORD, is_superuser=True, is_staff=True)
        self.client.force_login(self.user)
        NotFoundEvent.objects.create(request_id="panel-event", occurred_at=timezone.now(), method="GET", path="/panel-missing")

    def test_overview_and_health_pages(self):
        self.assertContains(self.client.get(reverse("overview")), "Surface volume / 14 days")
        self.assertContains(self.client.get(reverse("panel-health")), "Service health")

    def test_htmx_filter_returns_only_table_partial(self):
        response = self.client.get(reverse("events"), {"path": "panel"}, headers={"HX-Request": "true"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/panel-missing")
        self.assertNotContains(response, "<html")

    def test_notification_preferences_update_writes_audit(self):
        response = self.client.post(reverse("settings"), {"pref-security-panel": "on"})
        self.assertRedirects(response, reverse("settings"))
        self.assertTrue(NotificationPreference.objects.filter(operator=self.user, event_type="security", channel="panel", enabled=True).exists())
        self.assertFalse(NotificationPreference.objects.get(operator=self.user, event_type="operators", channel="panel").enabled)
        self.assertTrue(AuditEvent.objects.filter(action="notification.preferences_updated").exists())

    def test_notification_dismiss_is_scoped(self):
        entry = NotificationOutbox.objects.create(recipient=self.user, event_type="system", channel="panel", payload={})
        response = self.client.post(reverse("notification-dismiss", args=[entry.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertFalse(NotificationOutbox.objects.filter(pk=entry.pk).exists())

    def test_custom_404_and_logout(self):
        self.assertContains(self.client.get("/definitely-not-a-route/"), "Nothing lives at this address", status_code=404)
        response = self.client.post(reverse("logout"))
        self.assertEqual(response.status_code, 302)
        protected = self.client.get(reverse("overview"))
        self.assertRedirects(protected, reverse("login") + "?next=" + reverse("overview"))
