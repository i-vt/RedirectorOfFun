"""Real-browser end-to-end suite for the isolated Docker test stack.

Required environment:
  E2E_BASE_URL=http://localhost:3100
  E2E_BOOTSTRAP_URL=http://localhost:3100/setup/<one-time-token>/
Optional:
  CHROMIUM_BIN=/path/to/chromium
"""
import json
import os
import unittest
from playwright.sync_api import sync_playwright

BASE_URL = os.getenv("E2E_BASE_URL", "http://localhost:3100").rstrip("/")
BOOTSTRAP_URL = os.getenv("E2E_BOOTSTRAP_URL", "")
ADMIN_PASSWORD = "E2E-Administrator-Password-91!"
OPERATOR_PASSWORD = "E2E-Operator-Password-91!"
EXPECTED_EVENTS = int(os.getenv("E2E_EXPECTED_EVENTS", "55"))
EXPECTED_DOWNLOADS = int(os.getenv("E2E_EXPECTED_DOWNLOADS", "27"))
EXPECTED_DOWNLOAD_POSTS = int(os.getenv("E2E_EXPECTED_DOWNLOAD_POSTS", "9"))


class FullControlPlaneSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BOOTSTRAP_URL:
            raise RuntimeError("E2E_BOOTSTRAP_URL is required; run through ./test.sh --all")
        cls.console_errors = []
        cls.asset_failures = []
        cls.playwright = sync_playwright().start()
        launch_options = {"headless": True, "args": ["--no-sandbox"]}
        if os.getenv("CHROMIUM_BIN"):
            launch_options["executable_path"] = os.environ["CHROMIUM_BIN"]
        cls.browser = cls.playwright.chromium.launch(**launch_options)
        cls.public_request = cls.playwright.request.new_context(base_url=BASE_URL)
        response = cls.public_request.post(
            BOOTSTRAP_URL,
            data=json.dumps({"username": "admin", "password": ADMIN_PASSWORD}),
            headers={"Content-Type": "application/json"},
        )
        if response.status != 201:
            raise RuntimeError(f"Bootstrap failed with {response.status}: {response.text()}")
        replay = cls.public_request.get(BOOTSTRAP_URL)
        if replay.status != 410:
            raise RuntimeError(f"Claimed bootstrap returned {replay.status}, expected 410")

    @classmethod
    def tearDownClass(cls):
        cls.public_request.dispose()
        cls.browser.close()
        cls.playwright.stop()

    def new_session(self, mobile=False):
        viewport = {"width": 375, "height": 812} if mobile else {"width": 1440, "height": 1000}
        context = self.browser.new_context(base_url=BASE_URL, viewport=viewport)
        context.grant_permissions(["clipboard-read", "clipboard-write"], origin=BASE_URL)
        page = context.new_page()
        page.set_default_timeout(12000)
        page.on("console", lambda message: self.console_errors.append(message.text) if message.type == "error" and not message.text.startswith("Failed to load resource:") else None)
        page.on("pageerror", lambda error: self.console_errors.append(str(error)))
        page.on("response", lambda response: self.asset_failures.append(f"{response.status} {response.url}") if response.status >= 400 and "/static/" in response.url else None)
        self.addCleanup(context.close)
        return context, page

    def login(self, page, username="admin", password=ADMIN_PASSWORD):
        page.goto("/login/", wait_until="networkidle")
        page.locator("#id_username").fill(username)
        page.locator("#id_password").fill(password)
        page.get_by_role("button", name="Sign in to control plane").click()
        page.wait_for_url("**/panel/")
        page.wait_for_load_state("networkidle")

    def admin_session(self, mobile=False):
        context, page = self.new_session(mobile)
        self.login(page)
        return context, page

    @staticmethod
    def csrf_headers(context):
        cookies = context.cookies(BASE_URL)
        token = next((cookie["value"] for cookie in cookies if cookie["name"] == "csrftoken"), "")
        return {"X-CSRFToken": token, "Referer": BASE_URL + "/panel/"}

    def invite(self, page, username, role="Operator"):
        page.goto("/panel/operators/", wait_until="networkidle")
        page.locator("#id_username").fill(username)
        page.locator("#id_email").fill(f"{username}@example.test")
        page.locator("#id_role").select_option(role)
        page.get_by_role("button", name="Generate invitation").click()
        page.wait_for_load_state("networkidle")
        return page.locator("#invitation-url").input_value()

    def test_01_bootstrap_login_failure_success_and_logout(self):
        context, page = self.new_session()
        page.goto("/login/", wait_until="networkidle")
        page.locator("#id_username").fill("admin")
        page.locator("#id_password").fill("definitely-wrong-password")
        page.get_by_role("button", name="Sign in to control plane").click()
        page.wait_for_load_state("networkidle")
        self.assertIn("Please enter a correct username and password", page.locator("body").inner_text())
        self.login(page)
        self.assertEqual(page.locator("h1").inner_text(), "Overview")
        page.get_by_role("button", name="[ SIGN OUT ]").click()
        page.wait_for_load_state("networkidle")
        self.assertIn("/login/", page.url)
        page.goto("/panel/")
        self.assertIn("/login/", page.url)
        self.assertEqual(self.public_request.get(BOOTSTRAP_URL).status, 410)

    def test_02_dashboard_navigation_and_health(self):
        context, page = self.admin_session()
        self.assertEqual(page.locator(".metric strong").first.inner_text(), str(EXPECTED_EVENTS))
        self.assertTrue(page.locator("#events-chart").is_visible())
        destinations = [
            ("/panel/events/", "404 Events"),
            ("/panel/operators/", "Operators"),
            ("/panel/audit/", "Audit Log"),
            ("/panel/settings/", "Settings"),
            ("/panel/health/", "Service health"),
            ("/panel/", "Overview"),
        ]
        for path, heading in destinations:
            page.goto(path, wait_until="networkidle")
            self.assertEqual(page.locator("h1").inner_text(), heading)
        live = context.request.get("/health/live/")
        ready = context.request.get("/health/ready/")
        self.assertEqual(live.status, 200)
        self.assertEqual(live.json()["status"], "ok")
        self.assertEqual(ready.status, 200)
        self.assertEqual(ready.json()["pending_migrations"], 0)

    def test_03_events_filters_pagination_and_xss_safety(self):
        context, page = self.admin_session()
        page.goto("/panel/events/", wait_until="networkidle")
        self.assertEqual(page.locator("#events-table tbody tr").count(), 40)
        page.get_by_role("link", name="Next →").click()
        page.wait_for_load_state("networkidle")
        self.assertEqual(page.locator("#events-table tbody tr").count(), EXPECTED_EVENTS - 40)
        page.goto("/panel/events/", wait_until="networkidle")
        dialogs = []
        page.on("dialog", lambda dialog: dialogs.append(dialog.message))
        self.assertGreater(page.locator("td.path-cell", has_text="<script>").count(), 0)
        self.assertEqual(dialogs, [])
        page.locator("#filter-path").fill("/download")
        page.get_by_role("button", name="Apply filters").click()
        page.wait_for_load_state("networkidle")
        self.assertEqual(page.locator("#events-table tbody tr").count(), EXPECTED_DOWNLOADS)
        page.locator("#filter-method").select_option("POST")
        page.get_by_role("button", name="Apply filters").click()
        page.wait_for_load_state("networkidle")
        self.assertEqual(page.locator("#events-table tbody tr").count(), EXPECTED_DOWNLOAD_POSTS)
        rows = page.locator("#events-table tbody tr")
        for index in range(rows.count()):
            self.assertIn("/download", rows.nth(index).inner_text())
            self.assertIn("POST", rows.nth(index).inner_text())

    def test_04_operator_invitation_acceptance_revocation_and_permissions(self):
        admin_context, admin_page = self.admin_session()
        revoked_url = self.invite(admin_page, "revoked.invite", "Auditor")
        copy_button = admin_page.get_by_role("button", name="Copy")
        copy_button.click()
        self.assertEqual(admin_page.evaluate("navigator.clipboard.readText()"), revoked_url)
        invite_row = admin_page.locator(".invite-row", has_text="revoked.invite")
        invite_row.locator("xpath=following-sibling::form[1]/button").click()
        admin_page.wait_for_load_state("networkidle")
        self.assertEqual(self.public_request.get(revoked_url).status, 410)

        accepted_url = self.invite(admin_page, "e2e.operator", "Operator")
        operator_context, operator_page = self.new_session()
        operator_page.goto(accepted_url, wait_until="networkidle")
        operator_page.locator("#id_password").fill(OPERATOR_PASSWORD)
        operator_page.locator("#id_password_confirm").fill(OPERATOR_PASSWORD)
        operator_page.get_by_role("button", name="Activate operator account").click()
        operator_page.wait_for_load_state("networkidle")
        self.login(operator_page, "e2e.operator", OPERATOR_PASSWORD)
        self.assertEqual(operator_page.locator(".primary-nav a[href='/panel/operators/']").count(), 0)
        response = operator_page.goto("/panel/operators/")
        self.assertEqual(response.status, 403)
        self.assertEqual(operator_context.request.get("/api/v1/operators/").status, 403)

        operators = admin_context.request.get("/api/v1/operators/").json()["results"]
        operator_id = next(item["id"] for item in operators if item["username"] == "e2e.operator")
        revoke = admin_context.request.post(f"/api/v1/operators/{operator_id}/revoke/", headers=self.csrf_headers(admin_context))
        self.assertEqual(revoke.status, 200)
        self.assertFalse(revoke.json()["is_active"])
        operator_page.goto("/panel/")
        self.assertIn("/login/", operator_page.url)
        admin_page.goto("/panel/audit/", wait_until="networkidle")
        self.assertIn("operator.deactivated", admin_page.locator("body").inner_text())

    def test_05_notification_settings_browser_permission_dismiss_and_api(self):
        context, page = self.admin_session()
        page.goto("/panel/settings/", wait_until="networkidle")
        page.locator("input[name='pref-analytics-panel']").check()
        page.locator("input[name='pref-security-browser']").check()
        page.get_by_role("button", name="Save notification preferences").click()
        page.wait_for_load_state("networkidle")
        self.assertTrue(page.locator("input[name='pref-analytics-panel']").is_checked())
        page.get_by_role("button", name="Enable browser notifications").click()
        self.assertIn("Browser permission:", page.locator("#browser-permission-state").inner_text())
        before = page.locator(".notification-item").count()
        if before:
            page.locator(".notification-item form button").first.click()
            page.wait_for_load_state("networkidle")
            self.assertEqual(page.locator(".notification-item").count(), before - 1)

        preferences = context.request.get("/api/v1/notification-preferences/").json()
        analytics = next(item for item in preferences if item["event_type"] == "analytics" and item["channel"] == "panel")
        self.assertTrue(analytics["enabled"])
        security = next(item for item in preferences if item["event_type"] == "security" and item["channel"] == "panel")
        response = context.request.patch(
            f"/api/v1/notification-preferences/{security['id']}/",
            data=json.dumps({"enabled": False, "channel": "telegram"}),
            headers={**self.csrf_headers(context), "Content-Type": "application/json"},
        )
        self.assertEqual(response.status, 200)
        self.assertFalse(response.json()["enabled"])
        self.assertEqual(response.json()["channel"], "panel")
        recent = context.request.get("/api/v1/notifications/recent/?after=0")
        self.assertEqual(recent.status, 200)
        self.assertIsInstance(recent.json(), list)
        audit = context.request.get("/api/v1/audit-events/").json()["results"]
        self.assertTrue(any(item["action"] == "notification.preferences_updated" for item in audit))

    def test_06_complete_api_surface(self):
        context, page = self.admin_session()
        first = context.request.get("/api/v1/404-events/")
        self.assertEqual(first.status, 200)
        payload = first.json()
        self.assertEqual(len(payload["results"]), 50)
        self.assertIsNotNone(payload["next"])
        second = context.request.get(payload["next"])
        self.assertEqual(second.status, 200)
        self.assertEqual(len(second.json()["results"]), EXPECTED_EVENTS - 50)
        filtered = context.request.get("/api/v1/404-events/?path=download&method=POST&days=30")
        self.assertEqual(len(filtered.json()["results"]), EXPECTED_DOWNLOAD_POSTS)
        stats = context.request.get("/api/v1/404-stats/?days=14")
        self.assertEqual(stats.status, 200)
        self.assertEqual(stats.json()["total"], EXPECTED_EVENTS)
        self.assertEqual(len(stats.json()["series"]), 14)
        self.assertEqual(context.request.get("/api/v1/404-stats/?days=invalid").status, 400)
        audit = context.request.get("/api/v1/audit-events/")
        self.assertEqual(audit.status, 200)
        self.assertTrue(any(item["action"] == "bootstrap.completed" for item in audit.json()["results"]))
        operators = context.request.get("/api/v1/operators/")
        self.assertEqual(operators.status, 200)
        self.assertIn("results", operators.json())
        self.assertTrue(any(item["username"] == "admin" for item in operators.json()["results"]))
        self.assertEqual(context.request.get("/api/v1/notification-preferences/").status, 200)
        self.assertEqual(context.request.get("/api/v1/notifications/recent/").status, 200)
        for path in ("/api/v1/404-events/", "/api/v1/404-stats/", "/api/v1/audit-events/", "/api/v1/operators/", "/api/v1/notification-preferences/", "/api/v1/notifications/recent/"):
            self.assertIn(self.public_request.get(path).status, (401, 403))

    def test_07_public_health_and_custom_404(self):
        self.assertEqual(self.public_request.get("/health/live/").status, 200)
        self.assertEqual(self.public_request.get("/health/ready/").status, 200)
        context, page = self.admin_session()
        response = page.goto("/definitely-not-a-route/")
        self.assertEqual(response.status, 404)
        self.assertIn("Nothing lives at this address", page.locator("body").inner_text())
        page.get_by_role("link", name="Return to control plane").click()
        page.wait_for_load_state("networkidle")
        self.assertEqual(page.locator("h1").inner_text(), "Overview")

    def test_08_mobile_layout_has_no_page_overflow(self):
        context, page = self.admin_session(mobile=True)
        for path in ("/panel/", "/panel/events/", "/panel/operators/", "/panel/settings/", "/panel/health/"):
            page.goto(path, wait_until="networkidle")
            overflow = page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
            self.assertFalse(overflow, f"Horizontal page overflow at {path}")

    def test_09_no_browser_console_or_asset_errors(self):
        self.assertEqual(self.console_errors, [])
        self.assertEqual(self.asset_failures, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
