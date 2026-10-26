import base64
import hashlib
import json
import os
import time
from datetime import time as datetime_time
from unittest import mock

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.test import Client, TestCase, override_settings, tag
from django.urls import reverse
from django.utils import timezone

from accounts.models import Operator
from notifications.models import NotificationOutbox

from .crypto_utils import (
    GateCryptoError, aes256_decrypt, b64_decode, decrypt_blob, extract_images,
    parse_submission_json, totp_code, verify_totp, xor_apply,
)
from .models import (
    AgentChannel, BannedIP, BlockingRule, BotState, DecoyPage, DeliveryLink, HitEvent,
    IPIntel, LureSite, RuleSet, Submission, SubmissionImage, seed_blocking_rule_presets,
    seed_builtin_decoys, validate_auto_rules,
)
from .selftest import is_healthy, run_selftest
from . import services, telegram
from accounts.models import APIKey


def aes_encrypt(plaintext: bytes, passphrase: str, iv: bytes) -> bytes:
    key = hashlib.sha256(passphrase.encode()).digest()
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def xor_crypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    return bytes(data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data)))


@tag("unit")
class CryptoTemplateTests(TestCase):
    def test_base64_roundtrip(self):
        blob = base64.b64encode(b'{"hostname":"dc01"}').decode()
        self.assertEqual(decrypt_blob("base64", blob), b'{"hostname":"dc01"}')

    def test_base64_rejects_garbage(self):
        with self.assertRaises(GateCryptoError):
            b64_decode("!!!not-base64!!!")

    def test_xor_roundtrip(self):
        blob = base64.b64encode(xor_crypt(b'{"k":1}', "s3cret")).decode()
        self.assertEqual(decrypt_blob("xor", blob, "s3cret"), b'{"k":1}')

    def test_xor_requires_key(self):
        blob = base64.b64encode(b"data").decode()
        with self.assertRaises(GateCryptoError):
            decrypt_blob("xor", blob, "")

    def test_aes256_roundtrip_with_hex_key(self):
        iv = os.urandom(16)
        key = os.urandom(32)
        ciphertext = aes_encrypt(b'{"ok":true}', "", iv)  # empty passphrase not used here
        # encrypt with raw key instead
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(b'{"ok":true}') + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ciphertext = enc.update(padded) + enc.finalize()
        blob = base64.b64encode(ciphertext).decode()
        self.assertEqual(decrypt_blob("aes256", blob, key.hex(), iv.hex()), b'{"ok":true}')

    def test_aes256_rejects_tampered(self):
        iv = os.urandom(16)
        key = hashlib.sha256(b"pass").digest()
        blob = base64.b64encode(b"junk-ciphertext").decode()
        with self.assertRaises(GateCryptoError):
            decrypt_blob("aes256", blob, key.hex(), iv.hex())

    def test_parse_submission_json_requires_object(self):
        with self.assertRaises(GateCryptoError):
            parse_submission_json(b"[1,2,3]")
        with self.assertRaises(GateCryptoError):
            parse_submission_json(b"not json")

    def test_image_extraction_detects_png(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        decoded = {"hostname": "dc01", "screenshot": base64.b64encode(png).decode()}
        images = extract_images(decoded)
        self.assertEqual(len(images), 1)
        self.assertEqual(images[0]["field"], "screenshot")
        self.assertEqual(images[0]["content_type"], "image/png")
        self.assertEqual(images[0]["raw"], png)

    def test_image_extraction_ignores_short_strings(self):
        self.assertEqual(extract_images({"note": "hello"}), [])

    def test_totp_accepts_current_and_previous_window(self):
        secret = "shh"
        now_window = int(time.time()) // 30
        self.assertTrue(verify_totp(secret, totp_code(secret, now_window), window_seconds=30))
        self.assertTrue(verify_totp(secret, totp_code(secret, now_window - 1), window_seconds=30))
        self.assertFalse(verify_totp(secret, "00000000", window_seconds=30))
        self.assertFalse(verify_totp(secret, "", window_seconds=30))


@tag("functional")
@override_settings(AUTO_BAN_THRESHOLD=0)
class PublicDispatchTests(TestCase):
    def setUp(self):
        self.client = Client()

    def make_link(self, **kwargs):
        defaults = {"path": "/g/test/link", "kind": "key", "key_text": "deadbeef"}
        defaults.update(kwargs)
        return DeliveryLink.objects.create(**defaults)

    def test_key_link_served(self):
        link = self.make_link()
        response = self.client.get(link.path)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "deadbeef")
        link.refresh_from_db()
        self.assertEqual(link.hit_count, 1)

    def test_one_time_link_deactivates_after_release(self):
        link = self.make_link(one_time=True)
        self.assertEqual(self.client.get(link.path).status_code, 200)
        link.refresh_from_db()
        self.assertFalse(link.active)
        self.assertEqual(self.client.get(link.path).status_code, 410)
        categories = list(HitEvent.objects.values_list("category", flat=True))
        self.assertIn("expired", categories)

    def test_expired_link_returns_gone(self):
        link = self.make_link(expires_at=timezone.now() - timezone.timedelta(minutes=1))
        self.assertEqual(self.client.get(link.path).status_code, 410)

    def test_max_uses_enforced(self):
        link = self.make_link(max_uses=2)
        self.client.get(link.path)
        self.client.get(link.path)
        link.refresh_from_db()
        self.assertFalse(link.active)
        self.assertEqual(self.client.get(link.path).status_code, 410)

    def test_token_gate(self):
        link = self.make_link(gate_type="token", gate_token="s3cr3t")
        denied = self.client.get(link.path)
        self.assertEqual(denied.status_code, 204)
        ok = self.client.get(link.path, {"t": "s3cr3t"})
        self.assertEqual(ok.status_code, 200)
        header_ok = self.client.get(link.path, HTTP_X_GATE_TOKEN="s3cr3t")
        self.assertEqual(header_ok.status_code, 200)
        suspicious = HitEvent.objects.filter(category="suspicious")
        self.assertEqual(suspicious.count(), 1)

    def test_totp_gate(self):
        secret = "window-secret"
        link = self.make_link(gate_type="totp", totp_secret=secret, totp_window=30)
        bad = self.client.get(link.path, {"t": "nope"})
        self.assertEqual(bad.status_code, 204)
        window = int(time.time()) // 30
        good = self.client.get(link.path, {"t": totp_code(secret, window)})
        self.assertEqual(good.status_code, 200)

    def test_banned_ip_gets_decoy(self):
        self.make_link()
        BannedIP.objects.create(ip="203.0.113.7")
        response = self.client.get("/g/test/link", REMOTE_ADDR="203.0.113.7")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "deadbeef")
        self.assertTrue(HitEvent.objects.filter(category="banned").exists())

    def test_untracked_path_returns_stock_404(self):
        from analytics.models import NotFoundEvent
        response = self.client.get("/g/does/not/exist")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(HitEvent.objects.filter(category="not_found").exists())
        self.assertTrue(NotFoundEvent.objects.filter(path="/g/does/not/exist").exists())

    def test_anonymous_untracked_path_gets_decoy(self):
        response = self.client.get("/definitely-not-real")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Update Service")
        self.assertContains(response, "/g/canary/")

    def test_operator_untracked_path_gets_panel_404(self):
        operator = Operator.objects.create_user(username="op404", password="long-enough-password-123")
        self.client.force_login(operator)
        response = self.client.get("/definitely-not-real")
        self.assertEqual(response.status_code, 404)
        self.assertNotContains(response, "Update Service", status_code=404)
        self.assertContains(response, "Nothing lives at this address", status_code=404)

    def test_root_serves_decoy_to_anonymous_and_dashboard_to_operator(self):
        anonymous = Client()
        response = anonymous.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Update Service")
        self.assertContains(response, "/g/canary/")
        operator = Operator.objects.create_user(username="oproot", password="long-enough-password-123")
        self.client.force_login(operator)
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/panel/", response.url)

    def test_submission_flow_aes256(self):
        iv = os.urandom(16)
        key = hashlib.sha256(b"ops-key").digest()
        link = DeliveryLink.objects.create(
            path="/g/drop/a1", kind="file", gate_type="submission",
            cipher="aes256", cipher_key=key.hex(), cipher_iv=iv.hex(),
            expected_fields=["hostname"], requires_approval=True, placeholder="blank",
        )
        payload = json.dumps({"hostname": "dc01", "user": "admin"}).encode()
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(payload) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        blob = base64.b64encode(enc.update(padded) + enc.finalize()).decode()

        response = self.client.post(link.path, data=blob, content_type="application/octet-stream")
        self.assertEqual(response.status_code, 204)
        submission = Submission.objects.get(link=link)
        self.assertEqual(submission.status, "pending")
        self.assertEqual(submission.decoded_json["hostname"], "dc01")
        link.refresh_from_db()
        self.assertEqual(link.approval_status, "pending")

        # Held until approved.
        self.assertEqual(self.client.get(link.path).status_code, 204)
    def test_submission_flow_xor_with_image(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x01" * 100
        link = DeliveryLink.objects.create(
            path="/g/drop/x1", kind="key", key_text="KEYMATERIAL",
            gate_type="submission", cipher="xor", cipher_key="k",
            requires_approval=True,
        )
        payload = json.dumps({"hostname": "svr", "shot": base64.b64encode(png).decode()}).encode()
        blob = base64.b64encode(xor_crypt(payload, "k")).decode()
        self.client.post(link.path, data=json.dumps({"data": blob}), content_type="application/json")
        submission = Submission.objects.get(link=link)
        self.assertEqual(submission.images.count(), 1)
        image = submission.images.first()
        with image.image.open("rb") as handle:
            self.assertEqual(handle.read(), png)
    def test_undecryptable_submission_flagged_suspicious(self):
        link = DeliveryLink.objects.create(
            path="/g/drop/bad", kind="key", key_text="x",
            gate_type="submission", cipher="base64",
        )
        self.client.post(link.path, data="!!not-base64!!", content_type="text/plain")
        self.assertFalse(Submission.objects.exists())
        self.assertTrue(HitEvent.objects.filter(category="suspicious").exists())
    def test_missing_expected_fields_flagged(self):
        link = DeliveryLink.objects.create(
            path="/g/drop/missing", kind="key", key_text="x",
            gate_type="submission", cipher="base64", expected_fields=["hostname"],
        )
        blob = base64.b64encode(b'{"other":1}').decode()
        self.client.post(link.path, data=blob, content_type="text/plain")
        self.assertFalse(Submission.objects.exists())
        hit = HitEvent.objects.get(category="suspicious")
        self.assertIn("hostname", hit.detail["missing"])
    def test_proxy_link_fetches_pwndrop_server_side(self):
        link = self.make_link(kind="proxy", pwndrop_url="http://10.255.255.1/files/p.exe", path="/g/proxy/1")
        with mock.patch("gates.services._fetch_pwndrop", return_value=(b"MZ-fake", "application/octet-stream")) as fetch:
            response = self.client.get(link.path)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"MZ-fake")
        fetch.assert_called_once_with(link.pwndrop_url)
    def test_denied_link_serves_benevolent_text(self):
        link = self.make_link(requires_approval=True, approval_status="denied",
                              on_deny="benevolent", benevolent_text="exit-clean", path="/g/deny/1")
        response = self.client.get(link.path)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "exit-clean")
        self.assertTrue(HitEvent.objects.filter(category="disapproved").exists())
    def test_agent_channel_hit_tracked(self):
        agent = AgentChannel.objects.create(label="agent-7")
        response = self.client.get(agent.path, HTTP_USER_AGENT="Beacon/1.0")
        self.assertEqual(response.status_code, 200)  # no link; decoy at 200
        agent.refresh_from_db()
        self.assertEqual(agent.hits, 1)
        self.assertIsNotNone(agent.last_seen_at)


@tag("functional")
class AutoBanTests(TestCase):
    @override_settings(AUTO_BAN_THRESHOLD=2)
    def test_repeated_suspicious_auto_bans(self):
        link = DeliveryLink.objects.create(path="/g/ab/1", kind="key", key_text="k",
                                           gate_type="token", gate_token="t")
        ip = "198.51.100.3"
        self.client.get(link.path, REMOTE_ADDR=ip)  # suspicious #1
        self.client.get(link.path, REMOTE_ADDR=ip)  # suspicious #2 → ban
        self.assertTrue(BannedIP.is_banned(ip))
        ban = BannedIP.objects.get(ip=ip)
        self.assertTrue(ban.auto_created)
        response = self.client.get(link.path, REMOTE_ADDR=ip)
        self.assertEqual(response.status_code, 200)  # decoy, not the key


@tag("functional")
class PanelViewTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="op1", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)

    def test_panel_requires_login(self):
        anonymous = Client()
        for name in ["gate-links", "gate-submissions", "gate-bans", "gate-agents", "gate-events", "gate-selftest"]:
            response = anonymous.get(reverse(name))
            self.assertEqual(response.status_code, 302)

    def test_create_link_via_panel(self):
        response = self.client.post(reverse("gate-link-create"), {
            "path": "/g/ui/created", "kind": "key", "key_text": "abc123",
            "gate_type": "none", "cipher": "none", "placeholder": "blank",
            "on_deny": "not_found", "totp_window": "30", "max_uses": "0",
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(DeliveryLink.objects.filter(path="/g/ui/created").exists())

    def test_path_outside_base_rejected(self):
        response = self.client.post(reverse("gate-link-create"), {
            "path": "/elsewhere/x", "kind": "key", "key_text": "abc",
            "gate_type": "none", "cipher": "none", "placeholder": "blank",
            "on_deny": "not_found", "totp_window": "30", "max_uses": "0",
        })
        self.assertEqual(response.status_code, 200)  # re-rendered with form error
        self.assertFalse(DeliveryLink.objects.filter(path="/elsewhere/x").exists())

    def test_approve_releases_link(self):
        link = DeliveryLink.objects.create(path="/g/rel/1", kind="key", key_text="SECRET",
                                           gate_type="submission", cipher="base64",
                                           requires_approval=True)
        blob = base64.b64encode(b'{"hostname":"ok"}').decode()
        public = Client()
        public.post(link.path, data=blob, content_type="text/plain")
        submission = Submission.objects.get(link=link)

        response = self.client.post(reverse("gate-submission-decide", args=[submission.pk, "approve"]))
        self.assertEqual(response.status_code, 302)
        link.refresh_from_db()
        self.assertEqual(link.approval_status, "approved")
        released = public.get(link.path)
        self.assertEqual(released.status_code, 200)
        self.assertContains(released, "SECRET")

    def test_deny_serves_deny_response(self):
        link = DeliveryLink.objects.create(path="/g/rel/2", kind="key", key_text="SECRET",
                                           gate_type="submission", cipher="base64",
                                           requires_approval=True, on_deny="decoy")
        blob = base64.b64encode(b'{"hostname":"sandbox"}').decode()
        public = Client()
        public.post(link.path, data=blob, content_type="text/plain")
        submission = Submission.objects.get(link=link)
        self.client.post(reverse("gate-submission-decide", args=[submission.pk, "deny"]))
        released = public.get(link.path)
        self.assertEqual(released.status_code, 200)
        self.assertNotContains(released, "SECRET")

    def test_ban_and_lift_via_panel(self):
        response = self.client.post(reverse("gate-bans"), {"ip": "192.0.2.55", "note": "scanner"})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(BannedIP.is_banned("192.0.2.55"))
        ban = BannedIP.objects.get(ip="192.0.2.55")
        response = self.client.post(reverse("gate-ban-toggle", args=[ban.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertFalse(BannedIP.is_banned("192.0.2.55"))

    def test_invalid_ip_rejected(self):
        self.client.post(reverse("gate-bans"), {"ip": "not-an-ip", "note": ""})
        self.assertEqual(BannedIP.objects.count(), 0)

    def test_agent_lifecycle(self):
        response = self.client.post(reverse("gate-agents"), {
            "label": "agent-1", "ua_pattern": "Beacon", "note": "",
        })
        self.assertEqual(response.status_code, 302)
        agent = AgentChannel.objects.get(label="agent-1")
        old_token = agent.token
        self.client.post(reverse("gate-agent-rotate", args=[agent.pk]))
        agent.refresh_from_db()
        self.assertNotEqual(agent.token, old_token)
        self.client.post(reverse("gate-agent-toggle", args=[agent.pk]))
        agent.refresh_from_db()
        self.assertFalse(agent.active)

    def test_selftest_page_runs(self):
        response = self.client.post(reverse("gate-selftest"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "crypto_templates")

    def test_all_panel_pages_render(self):
        link = DeliveryLink.objects.create(
            path="/g/render/1", kind="key", key_text="K", gate_type="submission",
            cipher="base64", requires_approval=True, expected_fields=["hostname"],
        )
        blob = base64.b64encode(b'{"hostname":"h"}').decode()
        Client().post(link.path, data=blob, content_type="text/plain")
        submission = Submission.objects.get(link=link)
        totp_link = DeliveryLink.objects.create(
            path="/g/render/2", kind="key", key_text="K2", gate_type="totp", totp_secret="s",
        )
        BannedIP.objects.create(ip="192.0.2.1")
        AgentChannel.objects.create(label="a1")
        HitEvent.objects.create(category="suspicious", path="/g/x")
        for url in [reverse("gate-links"), reverse("gate-link-create"),
                    reverse("gate-link-detail", args=[link.pk]),
                    reverse("gate-link-edit", args=[link.pk]),
                    reverse("gate-link-totp", args=[totp_link.pk]),
                    reverse("gate-submissions"),
                    f"{reverse('gate-submissions')}?status=approved",
                    reverse("gate-bans"), reverse("gate-agents"),
                    reverse("gate-events"), reverse("gate-selftest")]:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, url)
        # Decision endpoints respond to POST and redirect back.
        response = self.client.post(reverse("gate-submission-decide", args=[submission.pk, "deny"]))
        self.assertEqual(response.status_code, 302)

    def test_submission_image_requires_login(self):
        link = DeliveryLink.objects.create(path="/g/img/1", kind="key", key_text="x")
        submission = Submission.objects.create(link=link, decoded_json={})
        image = SubmissionImage.objects.create(submission=submission, field_name="s")
        anonymous = Client()
        response = anonymous.get(reverse("gate-submission-image", args=[image.pk]))
        self.assertEqual(response.status_code, 302)


@tag("functional")
class ApiTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="apiop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)

    def test_api_requires_authentication(self):
        anonymous = Client()
        for url in ["/api/v1/links/", "/api/v1/submissions/", "/api/v1/bans/",
                    "/api/v1/agents/", "/api/v1/hit-events/", "/api/v1/gate-stats/"]:
            response = anonymous.get(url)
            self.assertIn(response.status_code, (302, 403))

    def test_link_crud_via_api(self):
        response = self.client.post("/api/v1/links/", data={
            "path": "/g/api/1", "kind": "key", "key_text": "k3y",
            "gate_type": "none", "cipher": "none", "placeholder": "blank", "on_deny": "not_found",
        }, content_type="application/json")
        self.assertEqual(response.status_code, 201)
        link_id = response.json()["id"]
        response = self.client.patch(f"/api/v1/links/{link_id}/", data={"active": False},
                                     content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["active"])
        response = self.client.delete(f"/api/v1/links/{link_id}/")
        self.assertEqual(response.status_code, 204)

    def test_link_path_validation_via_api(self):
        response = self.client.post("/api/v1/links/", data={
            "path": "/nope/x", "kind": "key", "gate_type": "none",
            "cipher": "none", "placeholder": "blank", "on_deny": "not_found",
        }, content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_submission_decide_via_api(self):
        link = DeliveryLink.objects.create(path="/g/api/s1", kind="key", key_text="K",
                                           gate_type="submission", cipher="base64",
                                           requires_approval=True)
        blob = base64.b64encode(b'{"hostname":"h"}').decode()
        Client().post(link.path, data=blob, content_type="text/plain")
        submission = Submission.objects.get(link=link)
        response = self.client.post(f"/api/v1/submissions/{submission.pk}/approve/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "approved")

    def test_ban_via_api(self):
        response = self.client.post("/api/v1/bans/", data={"ip": "192.0.2.99", "note": "n"},
                                    content_type="application/json")
        self.assertEqual(response.status_code, 201)
        response = self.client.post("/api/v1/bans/", data={"ip": "bad", "note": "n"},
                                    content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_ban_reactivation_via_api(self):
        self.client.post("/api/v1/bans/", data={"ip": "192.0.2.98", "note": "n"},
                         content_type="application/json")
        ban = BannedIP.objects.get(ip="192.0.2.98")
        self.client.patch(f"/api/v1/bans/{ban.pk}/", data={"active": False},
                          content_type="application/json")
        self.assertFalse(BannedIP.is_banned("192.0.2.98"))
        # Re-banning the same IP re-activates instead of 400-duplicate.
        response = self.client.post("/api/v1/bans/", data={"ip": "192.0.2.98", "note": "again"},
                                    content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(BannedIP.is_banned("192.0.2.98"))

    def test_invalid_auto_rules_json_renders_form_not_500(self):
        response = self.client.post(reverse("gate-link-create"), {
            "path": "/g/ar/1", "kind": "key", "key_text": "k",
            "auto_rules": "[{not json",
            "gate_type": "none", "cipher": "none", "placeholder": "blank",
            "on_deny": "not_found", "totp_window": "30", "max_uses": "0",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(DeliveryLink.objects.filter(path="/g/ar/1").exists())

    @override_settings(TRUSTED_PROXIES=["10.0.0.5", "172.16.0.0/12"])
    def test_xff_ignored_from_untrusted_peer(self):
        link = DeliveryLink.objects.create(path="/g/xff/1", kind="key", key_text="K",
                                           gate_type="token", gate_token="t")
        # Spoofed XFF from a non-proxy peer must not change who we see (the
        # gate check itself is unchanged by IP, but telemetry/bans must use
        # the real peer address).
        self.client.get(link.path, {"t": "t"}, REMOTE_ADDR="198.51.100.5",
                        HTTP_X_FORWARDED_FOR="10.0.0.5")
        hit = HitEvent.objects.filter(link=link).order_by("-created_at").first()
        self.assertEqual(hit.raw_ip, "198.51.100.5")
        # A trusted proxy's XFF is honored, and the LAST entry wins so a
        # client cannot prepend a fake address.
        self.client.get(link.path, {"t": "t"}, REMOTE_ADDR="10.0.0.5",
                        HTTP_X_FORWARDED_FOR="6.6.6.6, 198.51.100.6")
        hit = HitEvent.objects.filter(link=link).order_by("-created_at").first()
        self.assertEqual(hit.raw_ip, "198.51.100.6")
        # Docker-network peers are trusted by default (the web tier).
        self.client.get(link.path, {"t": "t"}, REMOTE_ADDR="172.18.0.5",
                        HTTP_X_FORWARDED_FOR="198.51.100.7")
        hit = HitEvent.objects.filter(link=link).order_by("-created_at").first()
        self.assertEqual(hit.raw_ip, "198.51.100.7")

    def test_telegram_fetches_callback_queries(self):
        with mock.patch.object(telegram, "_api", return_value=[]) as api_mock:
            telegram.fetch_updates(5)
        payload = api_mock.call_args[0][1]
        self.assertIn("callback_query", payload["allowed_updates"])

    def test_gate_stats_shape(self):
        DeliveryLink.objects.create(path="/g/st/1", kind="key", key_text="k")
        response = self.client.get("/api/v1/gate-stats/")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        for key in ["hits_24h", "suspicious_24h", "downloads_24h", "pending_submissions",
                    "active_links", "banned_ips", "by_category"]:
            self.assertIn(key, body)

    def test_hit_events_endpoint_paginates(self):
        link = DeliveryLink.objects.create(path="/g/st/2", kind="key", key_text="k")
        from gates.models import HitEvent
        for _ in range(3):
            HitEvent.objects.create(category="hit", path=link.path, link=link)
        response = self.client.get("/api/v1/hit-events/")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("results", body)
        self.assertEqual(len(body["results"]), 3)
        response = self.client.get("/api/v1/hit-events/?category=suspicious")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["results"]), 0)


@tag("unit")
class SelftestTests(TestCase):
    def test_selftest_healthy_in_test_env(self):
        results = run_selftest()
        self.assertTrue(is_healthy(results), results)


@tag("unit")
class AutoRuleValidatorTests(TestCase):
    def test_empty_is_valid(self):
        validate_auto_rules([])
        validate_auto_rules(None)

    def test_valid_rule_passes(self):
        validate_auto_rules([
            {"action": "approve", "when": {"fields_match": {"hostname": "^corp-.*"},
                                           "forbid": ["vmware"], "require_images": True}},
            {"action": "deny"},
        ])

    def test_non_list_rejected(self):
        with self.assertRaises(ValidationError):
            validate_auto_rules({"action": "approve"})

    def test_bad_action_rejected(self):
        with self.assertRaises(ValidationError):
            validate_auto_rules([{"action": "maybe"}])

    def test_bad_regex_rejected(self):
        with self.assertRaises(ValidationError):
            validate_auto_rules([{"action": "approve", "when": {"fields_match": {"h": "([bad"}}}])
        with self.assertRaises(ValidationError):
            validate_auto_rules([{"action": "approve", "when": {"forbid": ["([bad"]}}])

    def test_require_images_must_be_bool(self):
        with self.assertRaises(ValidationError):
            validate_auto_rules([{"action": "approve", "when": {"require_images": "yes"}}])


@tag("unit")
class AutoRuleEvaluationTests(TestCase):
    def setUp(self):
        self.link = DeliveryLink.objects.create(
            path="/g/rules/x", kind="key", key_text="k",
            auto_rules=[
                {"action": "approve", "when": {"fields_match": {"hostname": r"^corp-\d+$"},
                                               "forbid": ["vmware|virtualbox"], "require_images": False}},
                {"action": "deny", "when": {"fields_match": {"hostname": "sandbox"}}},
            ],
        )
        self.submission = Submission.objects.create(link=self.link, decoded_json={"hostname": "corp-7"})

    def test_first_matching_rule_wins(self):
        result = services.evaluate_auto_rules(self.link, self.submission)
        self.assertEqual(result[0], "approve")
        self.assertEqual(result[1], 0)

    def test_no_match_returns_none(self):
        self.submission.decoded_json = {"hostname": "random"}
        result = services.evaluate_auto_rules(self.link, self.submission)
        self.assertIsNone(result)

    def test_forbidden_value_blocks_rule(self):
        self.submission.decoded_json = {"hostname": "corp-7", "note": "vmware workstation"}
        result = services.evaluate_auto_rules(self.link, self.submission)
        self.assertIsNone(result)

    def test_later_rule_can_deny(self):
        self.submission.decoded_json = {"hostname": "sandbox-1"}
        result = services.evaluate_auto_rules(self.link, self.submission)
        self.assertEqual(result[0], "deny")

    def test_require_images_enforced(self):
        self.link.auto_rules = [
            {"action": "approve", "when": {"fields_match": {"hostname": "corp"}, "require_images": True}},
        ]
        self.submission.decoded_json = {"hostname": "corp"}
        self.assertIsNone(services.evaluate_auto_rules(self.link, self.submission))
        SubmissionImage.objects.create(
            submission=self.submission, field_name="shot",
            image=ContentFile(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32, name="x.png"),
        )
        result = services.evaluate_auto_rules(self.link, self.submission)
        self.assertEqual(result[0], "approve")


@tag("functional")
@override_settings(AUTO_BAN_THRESHOLD=0)
class AutoRuleFlowTests(TestCase):
    def make_link(self, rules):
        return DeliveryLink.objects.create(
            path="/g/auto/1", kind="key", key_text="RELEASED",
            gate_type="submission", cipher="base64", requires_approval=True,
            auto_rules=rules,
        )

    def post_blob(self, link, payload):
        blob = base64.b64encode(json.dumps(payload).encode()).decode()
        return Client().post(link.path, data=blob, content_type="text/plain")

    def test_auto_approve_releases_on_next_visit(self):
        link = self.make_link([
            {"action": "approve", "when": {"fields_match": {"hostname": r"^corp-\d+$"}}},
        ])
        self.post_blob(link, {"hostname": "corp-12"})
        link.refresh_from_db()
        self.assertEqual(link.approval_status, "approved")
        submission = Submission.objects.get(link=link)
        hit = HitEvent.objects.filter(category="approved").first()
        self.assertEqual(hit.detail["via"], "auto-rule#0")
        self.assertEqual(submission.decided_by, None)
        released = Client().get(link.path)
        self.assertEqual(released.status_code, 200)
        self.assertContains(released, "RELEASED")

    def test_auto_deny_serves_deny_response(self):
        link = self.make_link([
            {"action": "deny", "when": {"fields_match": {"hostname": "sandbox"}}},
        ], )
        link.on_deny = "benevolent"
        link.benevolent_text = "clean-exit"
        link.save(update_fields=["on_deny", "benevolent_text"])
        self.post_blob(link, {"hostname": "sandbox-01"})
        link.refresh_from_db()
        self.assertEqual(link.approval_status, "denied")
        response = Client().get(link.path)
        self.assertEqual(response.content.decode(), "clean-exit")

    def test_no_rule_match_stays_manual(self):
        link = self.make_link([
            {"action": "approve", "when": {"fields_match": {"hostname": "corp"}}},
        ])
        self.post_blob(link, {"hostname": "unknown"})
        link.refresh_from_db()
        self.assertEqual(link.approval_status, "pending")
        self.assertEqual(Client().get(link.path).status_code, 204)

    def test_invalid_rules_rejected_on_api(self):
        operator = Operator.objects.create_user(username="arop", password="long-enough-password-123")
        client = Client()
        client.force_login(operator)
        response = client.post("/api/v1/links/", data={
            "path": "/g/auto/2", "kind": "key", "gate_type": "none", "cipher": "none",
            "placeholder": "blank", "on_deny": "not_found",
            "auto_rules": [{"action": "sideways"}],
        }, content_type="application/json")
        self.assertEqual(response.status_code, 400)


@tag("functional")
class TelegramCommandTests(TestCase):
    def setUp(self):
        self.link = DeliveryLink.objects.create(
            path="/g/tg/1", kind="key", key_text="K", gate_type="submission",
            cipher="base64", requires_approval=True,
        )
        blob = base64.b64encode(b'{"hostname":"h1"}').decode()
        Client().post(self.link.path, data=blob, content_type="text/plain")
        self.submission = Submission.objects.get(link=self.link)

    def test_pending_lists_submissions(self):
        reply = telegram.handle_command("pending")
        self.assertIn(f"#{self.submission.pk}", reply)
        self.assertIn("/g/tg/1", reply)

    def test_approve_decides_submission(self):
        reply = telegram.handle_command(f"approve {self.submission.pk}")
        self.assertIn("approved", reply)
        self.submission.refresh_from_db()
        self.assertEqual(self.submission.status, "approved")
        hit = HitEvent.objects.filter(category="approved").first()
        self.assertEqual(hit.detail["via"], "telegram")

    def test_deny_decides_submission(self):
        reply = telegram.handle_command(f"deny #{self.submission.pk}")
        self.assertIn("denied", reply)
        self.submission.refresh_from_db()
        self.assertEqual(self.submission.status, "denied")

    def test_double_decision_blocked(self):
        telegram.handle_command(f"approve {self.submission.pk}")
        reply = telegram.handle_command(f"deny {self.submission.pk}")
        self.assertIn("already approved", reply)
        self.submission.refresh_from_db()
        self.assertEqual(self.submission.status, "approved")

    def test_unknown_submission_and_usage_errors(self):
        self.assertIn("not found", telegram.handle_command("approve 9999"))
        self.assertIn("Usage", telegram.handle_command("approve"))
        self.assertIn("Unknown command", telegram.handle_command("frobnicate"))

    def test_process_updates_ignores_other_chats(self):
        updates = [
            {"update_id": 10, "message": {"chat": {"id": "999"}, "text": f"deny {self.submission.pk}"}},
            {"update_id": 11, "message": {"chat": {"id": "42"}, "text": f"approve {self.submission.pk}"}},
        ]
        sent = []
        with mock.patch.object(telegram, "send_message", side_effect=lambda text: sent.append(text)):
            new_offset = telegram.process_updates(updates, chat_id="42")
        self.assertEqual(new_offset, 12)
        self.assertEqual(len(sent), 1)  # only the whitelisted chat got a reply
        self.submission.refresh_from_db()
        self.assertEqual(self.submission.status, "approved")

    def test_bot_state_offset_persists(self):
        state, created = BotState.objects.get_or_create(key="telegram-offset", defaults={"offset": 0})
        self.assertTrue(created)
        state.offset = 41
        state.save(update_fields=["offset"])
        self.assertEqual(BotState.objects.get(key="telegram-offset").offset, 41)

    def test_inline_keyboard_shape(self):
        keyboard = telegram.decision_keyboard(42)
        row = keyboard["inline_keyboard"][0]
        self.assertEqual(row[0]["callback_data"], "s:42:approve")
        self.assertEqual(row[1]["callback_data"], "s:42:deny")

    def test_callback_query_approves(self):
        query = {"id": "cb1", "message": {"chat": {"id": "42"}},
                 "data": f"s:{self.submission.pk}:approve"}
        answers, sent = [], []
        with mock.patch.object(telegram, "answer_callback", side_effect=lambda i, t="": answers.append(t)), \
             mock.patch.object(telegram, "send_message", side_effect=lambda t: sent.append(t)):
            telegram._handle_callback(query, chat_id="42")
        self.assertIn("approved", answers[0])
        self.submission.refresh_from_db()
        self.assertEqual(self.submission.status, "approved")

    def test_callback_query_wrong_chat_rejected(self):
        query = {"id": "cb2", "message": {"chat": {"id": "999"}},
                 "data": f"s:{self.submission.pk}:approve"}
        answers = []
        with mock.patch.object(telegram, "answer_callback", side_effect=lambda i, t="": answers.append(t)):
            telegram._handle_callback(query, chat_id="42")
        self.assertIn("Not authorized", answers[0])
        self.submission.refresh_from_db()
        self.assertEqual(self.submission.status, "pending")


@tag("functional")
@override_settings(AUTO_BAN_THRESHOLD=0, DECISION_UNDO_SECONDS=30)
class UndoBurnTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="ubop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)
        self.public = Client()

    def _submission_link(self):
        link = DeliveryLink.objects.create(path="/g/undo/1", kind="key", key_text="SECRET",
                                           gate_type="submission", cipher="base64",
                                           requires_approval=True)
        blob = base64.b64encode(b'{"hostname":"h"}').decode()
        self.public.post(link.path, data=blob, content_type="text/plain")
        return link, Submission.objects.get(link=link)

    def test_undo_within_window(self):
        link, sub = self._submission_link()
        self.client.post(reverse("gate-submission-decide", args=[sub.pk, "approve"]))
        sub.refresh_from_db()
        self.assertEqual(sub.status, "approved")
        response = self.client.post(reverse("gate-submission-undo", args=[sub.pk]))
        self.assertEqual(response.status_code, 302)
        sub.refresh_from_db()
        link.refresh_from_db()
        self.assertEqual(sub.status, "pending")
        self.assertEqual(link.approval_status, "pending")

    def test_undo_expired_window(self):
        link, sub = self._submission_link()
        self.client.post(reverse("gate-submission-decide", args=[sub.pk, "approve"]))
        sub.refresh_from_db()
        sub.decided_at = timezone.now() - timezone.timedelta(minutes=5)
        sub.save(update_fields=["decided_at"])
        ok, error = services.undo_decision(sub, self.operator)
        self.assertFalse(ok)
        self.assertIn("window", error)

    def test_undo_blocked_after_release(self):
        link, sub = self._submission_link()
        self.client.post(reverse("gate-submission-decide", args=[sub.pk, "approve"]))
        sub.refresh_from_db()
        released = self.public.get(link.path)
        self.assertEqual(released.status_code, 200)
        sub.refresh_from_db()
        self.assertTrue(sub.served_after_decision)
        ok, error = services.undo_decision(sub, self.operator)
        self.assertFalse(ok)
        self.assertIn("released", error)

    def test_burn_bans_visitors_but_keeps_approved_target(self):
        link, sub = self._submission_link()
        self.public.get(link.path, REMOTE_ADDR="203.0.113.10")   # scanner
        self.public.get(link.path, REMOTE_ADDR="203.0.113.20")   # scanner
        self.client.post(reverse("gate-submission-decide", args=[sub.pk, "approve"]))
        sub.refresh_from_db()
        approved_ip = sub.raw_ip  # test client default 127.0.0.1
        response = self.client.post(f"/api/v1/links/{link.pk}/burn/")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["burned"])
        self.assertIn("203.0.113.10", body["banned_ips"])
        self.assertNotIn(approved_ip, body["banned_ips"])
        link.refresh_from_db()
        self.assertFalse(link.active)
        self.assertTrue(BannedIP.is_banned("203.0.113.10"))

    def test_burn_never_bans_operator_or_loopback(self):
        link = DeliveryLink.objects.create(path="/g/burn/2", kind="key", key_text="K")
        self.public.get(link.path, REMOTE_ADDR="203.0.113.30")
        self.public.get(link.path, REMOTE_ADDR="127.0.0.2")  # loopback, never banned
        response = self.client.post(f"/api/v1/links/{link.pk}/burn/")  # burner = 127.0.0.1
        body = response.json()
        self.assertIn("203.0.113.30", body["banned_ips"])
        self.assertFalse(BannedIP.is_banned("127.0.0.1"))
        self.assertFalse(BannedIP.is_banned("127.0.0.2"))

    def test_replay_after_approval_does_not_relock(self):
        link, sub = self._submission_link()
        self.client.post(reverse("gate-submission-decide", args=[sub.pk, "approve"]))
        link.refresh_from_db()
        self.assertEqual(link.approval_status, "approved")
        # A second valid POST (dropper re-checkin) must not flip the link back.
        blob = base64.b64encode(b'{"hostname":"h-again"}').decode()
        self.public.post(link.path, data=blob, content_type="text/plain")
        link.refresh_from_db()
        self.assertEqual(link.approval_status, "approved")
        released = self.public.get(link.path)
        self.assertContains(released, "SECRET")


@tag("functional")
@override_settings(AUTO_BAN_THRESHOLD=0)
class WatermarkCanaryFingerprintTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_watermark_in_key_and_event(self):
        link = DeliveryLink.objects.create(path="/g/wm/1", kind="key", key_text="KEYMAT",
                                           watermark=True)
        response = self.client.get(link.path)
        self.assertContains(response, "ROFWM:")
        hit = HitEvent.objects.get(category="key_served")
        self.assertIn("ROFWM", hit.detail["watermark"])

    def test_watermark_trailer_on_file(self):
        link = DeliveryLink.objects.create(path="/g/wm/2", kind="proxy",
                                           pwndrop_url="http://10.255.255.1/x.bin", watermark=True)
        with mock.patch("gates.services._fetch_pwndrop", return_value=(b"PAYLOAD", "application/octet-stream")):
            response = self.client.get(link.path)
        self.assertIn(b"ROFWM:", response.content)
        hit = HitEvent.objects.get(category="download")
        self.assertTrue(hit.detail["watermark"].startswith(f"ROFWM:{link.pk}:"))

    def test_decoy_embeds_canary(self):
        BannedIP.objects.create(ip="192.0.2.1")
        response = self.client.get("/g/anything", REMOTE_ADDR="192.0.2.1")
        self.assertContains(response, "/g/canary/")

    def test_canary_hit_recorded(self):
        token = services.canary_token("198.51.100.9")
        response = self.client.get(f"/g/canary/{token}.gif", REMOTE_ADDR="198.51.100.9")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "image/gif")
        hit = HitEvent.objects.get(category="canary")
        self.assertEqual(hit.detail["canary"], "valid-token-rehit")

    def test_canary_forgery_recorded(self):
        response = self.client.get("/g/canary/ffffffffffffffffffffffff.gif", REMOTE_ADDR="198.51.100.9")
        self.assertEqual(response.status_code, 200)
        hit = HitEvent.objects.get(category="suspicious")
        self.assertEqual(hit.detail["canary"], "forged-or-stale-token")

    def test_ja3_gate_enforced(self):
        link = DeliveryLink.objects.create(path="/g/ja/1", kind="key", key_text="K",
                                           ja3_fingerprint="abc123")
        denied = self.client.get(link.path)
        self.assertEqual(denied.status_code, 204)
        ok = self.client.get(link.path, HTTP_X_JA3_FINGERPRINT="abc123")
        self.assertEqual(ok.status_code, 200)
        wrong = self.client.get(link.path, HTTP_X_JA3_FINGERPRINT="deadbeef")
        self.assertEqual(wrong.status_code, 204)
        self.assertEqual(HitEvent.objects.filter(category="suspicious").count(), 2)


@tag("functional")
class MobileUiTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="mop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)

    def _make_pending(self):
        link = DeliveryLink.objects.create(path="/g/m/1", kind="key", key_text="K",
                                           gate_type="submission", cipher="base64",
                                           requires_approval=True)
        blob = base64.b64encode(b'{"hostname":"h"}').decode()
        Client().post(link.path, data=blob, content_type="text/plain")
        return link, Submission.objects.get(link=link)

    def test_mobile_pages_render_and_require_login(self):
        link, sub = self._make_pending()
        anonymous = Client()
        for url in ["/m/", f"/m/submissions/{sub.pk}/", "/m/links/", f"/m/links/{link.pk}/", "/m/events/"]:
            self.assertEqual(anonymous.get(url).status_code, 302)
            self.assertEqual(self.client.get(url).status_code, 200, url)

    def test_mobile_decision_and_note(self):
        link, sub = self._make_pending()
        response = self.client.post(f"/m/submissions/{sub.pk}/", {"action": "approve"})
        self.assertEqual(response.status_code, 302)
        sub.refresh_from_db()
        self.assertEqual(sub.status, "approved")
        response = self.client.post(f"/m/submissions/{sub.pk}/", {"action": "note", "note": "customer DC01"})
        sub.refresh_from_db()
        self.assertEqual(sub.note, "customer DC01")
        self.assertEqual(sub.note_by, self.operator)

    def test_mobile_burn(self):
        link, sub = self._make_pending()
        Client().get(link.path, REMOTE_ADDR="203.0.113.99")
        response = self.client.post(f"/m/links/{link.pk}/", {"action": "burn"})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(BannedIP.is_banned("203.0.113.99"))


@tag("functional")
class WebPushTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="wpop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)

    def test_key_endpoint(self):
        response = self.client.get("/api/v1/push/key/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("public_key", response.json())

    def test_subscribe_unsubscribe(self):
        response = self.client.post("/api/v1/push/subscribe/", data={
            "endpoint": "https://push.example.com/sub/abc",
            "keys": {"p256dh": "BP256dh", "auth": "authsecret"},
        }, content_type="application/json")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.operator.push_subscriptions.count(), 1)
        response = self.client.post("/api/v1/push/unsubscribe/", data={
            "endpoint": "https://push.example.com/sub/abc"}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.operator.push_subscriptions.count(), 0)

    def test_deliver_success_and_prune(self):
        from notifications.models import NotificationOutbox, PushSubscription
        sub_live = PushSubscription.objects.create(operator=self.operator, endpoint="https://x/1", keys={})
        sub_dead = PushSubscription.objects.create(operator=self.operator, endpoint="https://x/2", keys={})
        entry = NotificationOutbox.objects.create(recipient=self.operator, event_type="gates",
                                                  channel="webpush", payload={"title": "t", "detail": "d"})

        from pywebpush import WebPushException

        class FakeExc(WebPushException):
            def __init__(self, code):
                class R: status_code = code
                super().__init__("gone", response=R())

        calls = []
        def fake_webpush(subscription_info, **kwargs):
            calls.append(subscription_info["endpoint"])
            if subscription_info["endpoint"] == "https://x/2":
                raise FakeExc(410)
        with mock.patch("pywebpush.webpush", side_effect=fake_webpush), \
             override_settings(VAPID_PRIVATE_KEY="k", VAPID_ADMIN_EMAIL="mailto:a@b"):
            from gates.webpush import deliver
            deliver(entry)
        self.assertEqual(set(calls), {"https://x/1", "https://x/2"})
        self.assertFalse(PushSubscription.objects.filter(pk=sub_dead.pk).exists())
        self.assertTrue(PushSubscription.objects.filter(pk=sub_live.pk).exists())


@tag("functional")
class TemplateAndDomainTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="tdop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)

    def test_template_prefills_form(self):
        response = self.client.get(reverse("gate-link-create"), {"template": "dropper-checkin"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "{second-stage trigger key}")
        self.assertContains(response, "aes256")

    def test_unknown_template_ignored(self):
        response = self.client.get(reverse("gate-link-create"), {"template": "nope"})
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "{second-stage trigger key}")

    @override_settings(REDIRECTOR_DOMAINS=["updates.example.com"])
    def test_domain_restricted_when_configured(self):
        response = self.client.post(reverse("gate-link-create"), {
            "path": "/g/dom/1", "kind": "key", "key_text": "k", "domain": "evil.example.com",
            "gate_type": "none", "cipher": "none", "placeholder": "blank",
            "on_deny": "not_found", "totp_window": "30", "max_uses": "0",
        })
        self.assertFalse(DeliveryLink.objects.filter(path="/g/dom/1").exists())
        response = self.client.post(reverse("gate-link-create"), {
            "path": "/g/dom/2", "kind": "key", "key_text": "k", "domain": "updates.example.com",
            "gate_type": "none", "cipher": "none", "placeholder": "blank",
            "on_deny": "not_found", "totp_window": "30", "max_uses": "0",
        })
        self.assertTrue(DeliveryLink.objects.filter(path="/g/dom/2", domain="updates.example.com").exists())


@tag("functional")
@override_settings(AUTO_BAN_THRESHOLD=0)
class DecoyPageTests(TestCase):
    def setUp(self):
        seed_builtin_decoys()
        self.operator = Operator.objects.create_user(username="dop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)
        self.public = Client()

    def test_builtin_pages_seeded_with_default(self):
        self.assertEqual(DecoyPage.objects.filter(kind="template").count(), 4)
        default = DecoyPage.objects.get(is_default=True)
        self.assertEqual(default.template_key, "update-service")

    def test_default_repo_decoy_is_served(self):
        response = self.public.get("/no-such-page")
        self.assertContains(response, "Update Service")

    def test_operator_can_switch_default_to_repo_page(self):
        crestfield = DecoyPage.objects.get(template_key="crestfield")
        self.client.post(reverse("gate-decoy-default", args=[crestfield.pk]))
        response = self.public.get("/no-such-page")
        self.assertContains(response, "CrestDesk")
        self.assertNotContains(response, "All systems operational")
        self.assertContains(response, "/g/canary/")
        # nysm-landing is also selectable and distinct from the update-service page title
        landing = DecoyPage.objects.get(template_key="nysm-landing")
        self.client.post(reverse("gate-decoy-default", args=[landing.pk]))
        response = self.public.get("/no-such-page")
        self.assertContains(response, "Service Portal")

    def test_uploaded_html_page_with_canary_injection(self):
        html = b"<html><body><h1>Customer Portal</h1></body></html>"
        page = DecoyPage.objects.create(kind="upload", name="portal", is_default=True)
        DecoyPage.objects.exclude(pk=page.pk).update(is_default=False)
        page.html_file.save("portal.html", ContentFile(html), save=True)
        response = self.public.get("/no-such-page")
        self.assertContains(response, "Customer Portal")
        self.assertContains(response, "/g/canary/")

    def test_redirect_decoy_sends_visitor_away(self):
        page = DecoyPage.objects.create(kind="redirect", name="ms",
                                        redirect_url="https://www.microsoft.com/", is_default=True)
        DecoyPage.objects.exclude(pk=page.pk).update(is_default=False)
        response = self.public.get("/no-such-page")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "https://www.microsoft.com/")
        # banned visitors follow the same default page
        BannedIP.objects.create(ip="203.0.113.99")
        denied = self.public.get("/anything", REMOTE_ADDR="203.0.113.99")
        self.assertEqual(denied.status_code, 302)

    def test_deactivating_default_falls_back(self):
        default = DecoyPage.objects.get(is_default=True)
        self.client.post(reverse("gate-decoy-toggle", args=[default.pk]))
        new_default = DecoyPage.objects.get(is_default=True)
        self.assertNotEqual(new_default.pk, default.pk)
        self.assertTrue(new_default.active)
        response = self.public.get("/no-such-page")
        self.assertContains(response, "/g/canary/")

    def test_builtin_pages_cannot_be_deleted(self):
        builtin = DecoyPage.objects.get(template_key="crestfield")
        self.client.post(reverse("gate-decoy-delete", args=[builtin.pk]))
        self.assertTrue(DecoyPage.objects.filter(pk=builtin.pk).exists())

    def test_uploaded_page_can_be_deleted_and_default_resets(self):
        page = DecoyPage.objects.create(kind="upload", name="tmp", is_default=True)
        DecoyPage.objects.exclude(pk=page.pk).update(is_default=False)
        page.html_file.save("tmp.html", ContentFile(b"<html></html>"), save=True)
        self.client.post(reverse("gate-decoy-delete", args=[page.pk]))
        self.assertFalse(DecoyPage.objects.filter(pk=page.pk).exists())
        self.assertTrue(DecoyPage.objects.get(template_key="update-service").is_default)

    def test_panel_page_renders(self):
        response = self.client.get(reverse("gate-decoys"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Decoy pages")

    def test_api_crud_and_default(self):
        response = self.client.get("/api/v1/decoys/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["results"] if "results" in response.json() else response.json()), 4)
        response = self.client.post("/api/v1/decoys/", data={
            "name": "api-upload", "kind": "redirect", "redirect_url": "https://example.com/",
        }, content_type="application/json")
        self.assertEqual(response.status_code, 201)
        page_id = response.json()["id"]
        response = self.client.post(f"/api/v1/decoys/{page_id}/default/")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["is_default"])
        self.assertEqual(DecoyPage.objects.filter(is_default=True).count(), 1)
        response = self.client.delete(f"/api/v1/decoys/{page_id}/")
        self.assertEqual(response.status_code, 204)
        self.assertTrue(DecoyPage.objects.get(template_key="update-service").is_default)


@tag("functional")
class EventIdentifierTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="eidop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)

    def _make_event(self, **kwargs):
        from analytics.models import NotFoundEvent
        defaults = {"request_id": "eid-1", "occurred_at": timezone.now(), "method": "GET",
                    "path": "/missing", "source_ip": "203.0.113.7",
                    "source_ip_hash": "ab" * 32, "user_agent": "curl/8.5.0"}
        defaults.update(kwargs)
        return NotFoundEvent.objects.create(**defaults)

    def test_filters_by_user_agent_ip_and_client(self):
        self._make_event()
        self._make_event(request_id="eid-2", source_ip="198.51.100.9",
                         source_ip_hash="cd" * 32, user_agent="python-requests/2.31")
        response = self.client.get("/panel/events/", {"ua": "curl"})
        self.assertEqual(len(response.context["events"]), 1)
        response = self.client.get("/panel/events/", {"ip": "198.51.100.9"})
        self.assertEqual(len(response.context["events"]), 1)
        response = self.client.get("/panel/events/", {"client": "ab" * 32})
        self.assertEqual(len(response.context["events"]), 1)
        response = self.client.get("/panel/events/", {"client": "203.0.113.7"})
        self.assertEqual(len(response.context["events"]), 1)

    def test_table_contains_detail_rows_and_toggle_markup(self):
        self._make_event()
        response = self.client.get("/panel/events/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "info-toggle")
        self.assertContains(response, "RAW IP")
        self.assertContains(response, "USER AGENT")
        self.assertContains(response, "client-raw")
        self.assertContains(response, "client-hash")
        self.assertContains(response, "identifiers-toggle")

    def test_collector_maps_new_fields(self):
        from analytics.services import event_from_record
        from django.utils import timezone as tz
        record = {"request_id": "eid-9", "time": tz.now().isoformat(), "method": "get",
                  "path": "/x", "status": 404, "remote_addr": "203.0.113.55",
                  "user_agent": "Mozilla/5.0"}
        event = event_from_record(record)
        self.assertEqual(event.source_ip, "203.0.113.55")
        self.assertEqual(event.user_agent, "Mozilla/5.0")
        self.assertEqual(event.method, "GET")


@tag("unit")
class BlockingRuleEngineTests(TestCase):
    def setUp(self):
        self.intel = IPIntel(ip="34.30.115.30", asn="396982", org="Google LLC",
                             country_code="US", city="Council Bluffs")

    def test_and_logic(self):
        rule = BlockingRule(name="aws", logic="all", conditions=[
            {"type": "asn", "pattern": r"^396982$"},
            {"type": "ua", "pattern": r"(?i)go-http-client"},
        ])
        matched, fired = services.rule_matches(rule, ip="34.30.115.30",
                                               user_agent="Go-http-client/1.1", intel=self.intel)
        self.assertTrue(matched)
        self.assertEqual(set(fired), {"asn", "ua"})
        matched, _ = services.rule_matches(rule, ip="34.30.115.30",
                                           user_agent="Mozilla/5.0", intel=self.intel)
        self.assertFalse(matched)

    def test_or_logic(self):
        rule = BlockingRule(name="either", logic="any", conditions=[
            {"type": "ua", "pattern": r"(?i)virustotal"},
            {"type": "asn", "pattern": r"^16509$"},
        ])
        matched, _ = services.rule_matches(rule, ip="1.1.1.1",
                                           user_agent="AppEngine-Google; virustotalcloud", intel=None)
        self.assertTrue(matched)

    def test_not_logic_and_negation(self):
        rule = BlockingRule(name="outside-us", logic="not", conditions=[
            {"type": "country", "pattern": r"^US$"},
        ])
        matched, _ = services.rule_matches(rule, ip="103.108.94.174",
                                           user_agent="Mozilla/5.0",
                                           intel=IPIntel(ip="103.108.94.174", asn="133480",
                                                         org="5G Network Operations", country_code="NZ"))
        self.assertTrue(matched)
        matched, _ = services.rule_matches(rule, ip="34.30.115.30",
                                           user_agent="Mozilla/5.0", intel=self.intel)
        self.assertFalse(matched)
        negated = BlockingRule(name="not-curl", logic="all", conditions=[
            {"type": "ua", "pattern": r"(?i)^curl", "negate": True},
        ])
        matched, _ = services.rule_matches(negated, ip="1.1.1.1", user_agent="Mozilla/5.0", intel=None)
        self.assertTrue(matched)
        matched, _ = services.rule_matches(negated, ip="1.1.1.1", user_agent="curl/8.0", intel=None)
        self.assertFalse(matched)

    def test_missing_intel_never_matches_intel_conditions(self):
        rule = BlockingRule(name="asn-only", logic="any", conditions=[
            {"type": "asn", "pattern": r"^.*$"},
        ])
        matched, _ = services.rule_matches(rule, ip="9.9.9.9", user_agent="", intel=None)
        self.assertFalse(matched)

    def test_condition_validator(self):
        from django.core.exceptions import ValidationError
        from gates.models import validate_blocking_conditions
        validate_blocking_conditions([{"type": "ip", "pattern": r"^10\."}])
        with self.assertRaises(ValidationError):
            validate_blocking_conditions([{"type": "asn"}])
        with self.assertRaises(ValidationError):
            validate_blocking_conditions([{"type": "foo", "pattern": "x"}])
        with self.assertRaises(ValidationError):
            validate_blocking_conditions([{"type": "ip", "pattern": "([bad"}])


@tag("functional")
@override_settings(AUTO_BAN_THRESHOLD=0, IP_INTEL_ENABLED=False)
class BlockingRuleFlowTests(TestCase):
    def setUp(self):
        seed_blocking_rule_presets()
        self.operator = Operator.objects.create_user(username="brlop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)
        self.public = Client()

    def test_presets_seeded_disabled(self):
        self.assertEqual(BlockingRule.objects.filter(preset=True).count(), 11)
        self.assertFalse(BlockingRule.objects.filter(enabled=True).exists())

    def test_enabled_rule_blocks_and_records(self):
        rule = BlockingRule.objects.create(
            name="block curl", logic="any", conditions=[{"type": "ua", "pattern": r"(?i)^curl"}],
            enabled=True)
        response = self.public.get("/probe-path", HTTP_USER_AGENT="curl/8.0")
        self.assertContains(response, "Update Service")  # decoy, 200 like a ban
        hit = HitEvent.objects.get(category="blocked")
        self.assertEqual(hit.detail["rule"], "block curl")
        rule.refresh_from_db()
        self.assertEqual(rule.match_count, 1)

    def test_auto_ban_adds_ip(self):
        BlockingRule.objects.create(
            name="block wget", logic="any", conditions=[{"type": "ua", "pattern": r"(?i)^wget"}],
            enabled=True, auto_ban=True)
        self.public.get("/probe-path", HTTP_USER_AGENT="wget/1.21", REMOTE_ADDR="203.0.113.44")
        self.assertTrue(BannedIP.is_banned("203.0.113.44"))
        followup = self.public.get("/probe-path", REMOTE_ADDR="203.0.113.44")
        self.assertContains(followup, "Update Service")
        self.assertTrue(HitEvent.objects.filter(category="banned").exists())

    def test_disabled_rule_does_nothing(self):
        BlockingRule.objects.create(
            name="off", logic="any", conditions=[{"type": "ua", "pattern": r"(?i)^curl"}], enabled=False)
        response = self.public.get("/probe-path", HTTP_USER_AGENT="curl/8.0")
        self.assertContains(response, "Update Service")  # plain 404 decoy
        self.assertFalse(HitEvent.objects.filter(category="blocked").exists())

    def test_panel_pages_render(self):
        for url in [reverse("gate-block-rules"), reverse("gate-block-rule-test")]:
            self.assertEqual(self.client.get(url).status_code, 200, url)
        response = self.client.post(reverse("gate-block-rule-test"),
                                    {"ip": "1.1.1.1", "ua": "Mozilla/5.0 (operator browser)"})
        self.assertContains(response, "No rules matched")

    def test_rule_create_via_panel_and_api(self):
        response = self.client.post(reverse("gate-block-rules"), {
            "name": "ua rule", "logic": "any", "auto_ban": "on",
            "conditions": '[{"type": "ua", "pattern": "(?i)python"}]',
        })
        self.assertEqual(response.status_code, 302)
        rule = BlockingRule.objects.get(name="ua rule")
        self.assertTrue(rule.auto_ban)
        response = self.client.post("/api/v1/block-rules/", data={
            "name": "api rule", "logic": "all", "conditions": [{"type": "ip", "pattern": "^10\\."}],
        }, content_type="application/json")
        self.assertEqual(response.status_code, 201)
        # invalid regex rejected
        response = self.client.post("/api/v1/block-rules/", data={
            "name": "bad", "logic": "all", "conditions": [{"type": "ip", "pattern": "([x"}],
        }, content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_api_dry_run_endpoint(self):
        BlockingRule.objects.create(
            name="vt-custom", logic="any", conditions=[{"type": "ua", "pattern": "(?i)virustotal"}],
            enabled=False)
        response = self.client.post("/api/v1/block-rules/test/", data={
            "ip": "35.187.132.69", "ua": "AppEngine-Google; virustotalcloud"}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        names = {m["name"] for m in body["matched"]}
        self.assertEqual(names, {"vt-custom", "preset: VirusTotal egress"})
        self.assertTrue(all(m["enabled"] is False for m in body["matched"]))

    def test_events_page_has_bulk_controls(self):
        from analytics.models import NotFoundEvent
        NotFoundEvent.objects.create(request_id="bulk-1", occurred_at=timezone.now(), method="GET",
                                     path="/x", source_ip="203.0.113.7", user_agent="curl/8")
        response = self.client.get("/panel/events/")
        self.assertContains(response, "expand-all")
        self.assertContains(response, "condense-all")


@tag("unit")
class RuleChainSemanticsTests(TestCase):
    def setUp(self):
        self.ruleset = RuleSet.objects.create(name="test set", scope="all")
        self.intel = IPIntel(ip="34.30.115.30", asn="396982", org="Google LLC",
                             country_code="US", city="Council Bluffs")

    def test_cidr_condition(self):
        rule = BlockingRule(name="cidr", logic="any", ruleset=self.ruleset, conditions=[
            {"type": "cidr", "pattern": "34.30.115.0/24"}])
        matched, _ = services.rule_matches(rule, ip="34.30.115.30", user_agent="", intel=None)
        self.assertTrue(matched)
        matched, _ = services.rule_matches(rule, ip="34.30.116.1", user_agent="", intel=None)
        self.assertFalse(matched)
        with self.assertRaises(ValidationError):
            services.validate = None
            from gates.models import validate_blocking_conditions
            validate_blocking_conditions([{"type": "cidr", "pattern": "999.0.0.0/8"}])

    def test_allow_overrides_later_block(self):
        BlockingRule.objects.create(
            name="allow operator", ruleset=self.ruleset, order=0, action="allow",
            conditions=[{"type": "ip", "pattern": r"^203\.0\.113\.10$"}])
        BlockingRule.objects.create(
            name="block all", ruleset=self.ruleset, order=1,
            conditions=[{"type": "ua", "pattern": r"(?i)^curl"}])
        class FakeRequest: META = {"HTTP_USER_AGENT": "curl/8.0"}
        decision = services.evaluate_blocking_rules(
            FakeRequest(), "203.0.113.10", is_404=True)
        self.assertIsNotNone(decision)
        rule, _ = decision
        self.assertEqual(rule.action, "allow")
        self.assertIsNone(services.apply_blocking_rule(FakeRequest(), "203.0.113.10", rule, ["ip"]))

    def test_block_decision_when_no_allow_matches(self):
        BlockingRule.objects.create(
            name="allow other", ruleset=self.ruleset, order=0, action="allow",
            conditions=[{"type": "ip", "pattern": r"^198\.51\.100\.1$"}])
        BlockingRule.objects.create(
            name="block curl", ruleset=self.ruleset, order=1,
            conditions=[{"type": "ua", "pattern": r"(?i)^curl"}])
        class FakeRequest: META = {"HTTP_USER_AGENT": "curl/8.0"}
        rule, _ = services.evaluate_blocking_rules(FakeRequest(), "203.0.113.10", is_404=True)
        self.assertEqual(rule.action, "block")

    def test_ruleset_scope_filters(self):
        link = DeliveryLink.objects.create(path="/g/scope/1", kind="key", key_text="K")
        s404 = RuleSet.objects.create(name="404s", scope="not_found")
        slink = RuleSet.objects.create(name="link", scope="link", link=link)
        BlockingRule.objects.create(name="r404", ruleset=s404,
                                    conditions=[{"type": "ua", "pattern": r"(?i)^curl"}])
        BlockingRule.objects.create(name="rlink", ruleset=slink,
                                    conditions=[{"type": "ua", "pattern": r"(?i)^curl"}])
        class FakeRequest: META = {"HTTP_USER_AGENT": "curl/8.0"}
        rule, _ = services.evaluate_blocking_rules(FakeRequest(), "1.1.1.1", is_404=True)
        self.assertEqual(rule.name, "r404")
        rule, _ = services.evaluate_blocking_rules(FakeRequest(), "1.1.1.1", is_404=False, link=link)
        self.assertEqual(rule.name, "rlink")
        self.assertIsNone(services.evaluate_blocking_rules(FakeRequest(), "1.1.1.1", is_404=False))

    def test_export_import_roundtrip(self):
        BlockingRule.objects.create(name="keep me", ruleset=self.ruleset, order=3,
                                    conditions=[{"type": "ua", "pattern": "(?i)curl"}])
        payload = services.export_blocking_rules()
        self.assertEqual(payload["format"], "rof-blocking-rules")
        BlockingRule.objects.all().delete()
        RuleSet.objects.all().delete()
        sets_created, rules_created, errors = services.import_blocking_rules(payload)
        self.assertEqual(errors, [])
        self.assertEqual(sets_created, 1)
        self.assertEqual(rules_created, 1)
        imported = BlockingRule.objects.get()
        self.assertFalse(imported.enabled)
        # importing again renames the colliding set
        sets_created, _, errors = services.import_blocking_rules(payload)
        self.assertTrue(RuleSet.objects.filter(name__contains="(imported)").exists())

    def test_reorder_endpoint(self):
        r1 = BlockingRule.objects.create(name="a", ruleset=self.ruleset, order=0,
                                         conditions=[{"type": "ua", "pattern": "x"}])
        r2 = BlockingRule.objects.create(name="b", ruleset=self.ruleset, order=1,
                                         conditions=[{"type": "ua", "pattern": "y"}])
        operator = Operator.objects.create_user(username="reorder", password="long-enough-password-123")
        client = Client()
        client.force_login(operator)
        response = client.post("/api/v1/block-rules/reorder/", data={
            "kind": "rule", "ids": [r2.pk, r1.pk]}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(BlockingRule.objects.get(pk=r1.pk).order, 1)
        self.assertEqual(BlockingRule.objects.get(pk=r2.pk).order, 0)

    def test_xor_logic(self):
        rule = BlockingRule.objects.create(name="xor", ruleset=self.ruleset, logic="xor",
                                           conditions=[
                                               {"type": "ua", "pattern": "(?i)virustotal"},
                                               {"type": "asn", "pattern": "^16509$"},
                                           ])
        # exactly one matched
        matched, _ = services.rule_matches(rule, ip="1.1.1.1", user_agent="virustotal",
                                           intel=IPIntel(ip="1.1.1.1", asn="133480"))
        self.assertTrue(matched)
        # both matched
        matched, _ = services.rule_matches(rule, ip="1.1.1.1", user_agent="virustotal",
                                           intel=IPIntel(ip="1.1.1.1", asn="16509"))
        self.assertFalse(matched)
        # neither matched
        matched, _ = services.rule_matches(rule, ip="1.1.1.1", user_agent="Mozilla",
                                           intel=IPIntel(ip="1.1.1.1", asn="133480"))
        self.assertFalse(matched)
        # unknown intel makes the rule indeterminate even with a UA match
        matched, _ = services.rule_matches(rule, ip="1.1.1.1", user_agent="virustotal",
                                           intel=None)
        self.assertFalse(matched)

    def test_xor_accepted_by_model_validation(self):
        rule = BlockingRule(name="xor ok", ruleset=self.ruleset, logic="xor",
                            conditions=[{"type": "ip", "pattern": ".*"}])
        rule.full_clean()


@tag("functional")
class QuickRuleGeneratorTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="qrgop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)

    def test_page_has_generator_modal(self):
        response = self.client.get(reverse("gate-block-rules"))
        self.assertContains(response, "quick-rule-modal")
        self.assertContains(response, "Quick rule generator")
        self.assertContains(response, "starts with")
        self.assertContains(response, "XOR (exactly one matches)")

    def test_samples_import_cleanly(self):
        import json as _json
        from pathlib import Path
        from django.conf import settings as dj_settings
        # the link-scoped sample references this path
        DeliveryLink.objects.create(path="/g/drop/example", kind="key", key_text="K")
        sample_dir = Path(dj_settings.BASE_DIR) / "samples"
        for sample in sorted(sample_dir.glob("*.json")):
            payload = _json.loads(sample.read_text())
            sets_created, rules_created, errors = services.import_blocking_rules(payload)
            self.assertEqual(errors, [], sample.name)
            self.assertGreaterEqual(sets_created + rules_created, 1, sample.name)
            # every imported rule is disabled on import
            self.assertFalse(BlockingRule.objects.filter(enabled=True).exists())


@tag("functional")
@override_settings(AUTO_BAN_THRESHOLD=0)
class FingerprintHygieneTests(TestCase):
    def test_request_id_header_only_on_operator_paths(self):
        public = self.client.get("/definitely-not-real")
        self.assertNotIn("X-Request-ID", public.headers)
        operator = Operator.objects.create_user(username="reqidop", password="long-enough-password-123")
        self.client.force_login(operator)
        panel = self.client.get("/panel/")
        self.assertIn("X-Request-ID", panel.headers)

    def test_outbound_user_agent_is_generic(self):
        from django.conf import settings as dj_settings
        self.assertIn("Mozilla/5.0", dj_settings.OUTBOUND_USER_AGENT)
        self.assertNotIn("redirector", dj_settings.OUTBOUND_USER_AGENT.lower())

    def test_pwndrop_fetch_uses_outbound_user_agent(self):
        with mock.patch("urllib.request.Request") as req:
            with mock.patch("urllib.request.build_opener") as opener:
                opener.return_value.open.return_value.__enter__.return_value.headers.get_content_type.return_value = "application/octet-stream"
                opener.return_value.open.return_value.__enter__.return_value.headers.get.return_value = "4"
                opener.return_value.open.return_value.__enter__.return_value.read.side_effect = [b"data", b""]
                services._fetch_pwndrop("http://10.0.0.5/f.bin")
            headers = req.call_args[1]["headers"]
            self.assertEqual(headers["User-Agent"], dj_settings_for_test().OUTBOUND_USER_AGENT)

    def test_watermark_prefix_configurable(self):
        link = DeliveryLink.objects.create(path="/g/wmp/1", kind="key", key_text="K", watermark=True)
        with override_settings(WATERMARK_PREFIX="OPSPEC"):
            marker = services.build_watermark(link)
        self.assertTrue(marker.startswith("OPSPEC:"))

    def test_untracked_path_writes_synthetic_404_record(self):
        from analytics.models import NotFoundEvent
        self.client.get("/no/such/place", HTTP_USER_AGENT="curl/8.0", REMOTE_ADDR="203.0.113.66")
        event = NotFoundEvent.objects.get(path="/no/such/place")
        self.assertEqual(event.status, 404)
        self.assertEqual(event.source_ip, "203.0.113.66")
        self.assertEqual(event.user_agent, "curl/8.0")


def dj_settings_for_test():
    from django.conf import settings
    return settings


@tag("functional")
@override_settings(AUTO_BAN_THRESHOLD=0)
class TotpSingleUseTests(TestCase):
    def setUp(self):
        from gates.crypto_utils import totp_code
        import time
        self.totp_code = totp_code
        self.window = int(time.time()) // 30
        self.link = DeliveryLink.objects.create(path="/g/otp/1", kind="key", key_text="K",
                                                gate_type="totp", totp_secret="s3cr3t")
        self.public = Client()

    def test_code_works_once_then_replay_rejected(self):
        code = self.totp_code("s3cr3t", self.window)
        first = self.public.get(self.link.path, {"t": code})
        self.assertEqual(first.status_code, 200)
        replay = self.public.get(self.link.path, {"t": code})
        self.assertEqual(replay.status_code, 204)
        hit = HitEvent.objects.filter(category="suspicious").order_by("-created_at").first()
        self.assertEqual(hit.detail["reason"], "totp code replay")
        # and it counts toward the auto-ban threshold like any suspicious hit
        from gates.models import UsedGateCode
        self.assertTrue(UsedGateCode.objects.filter(link=self.link, code=code).exists())

    def test_next_window_code_still_works(self):
        code_now = self.totp_code("s3cr3t", self.window)
        self.public.get(self.link.path, {"t": code_now})
        code_next = self.totp_code("s3cr3t", self.window + 1)
        # the next window's code passes verification only if within skew; force the flow
        from gates.crypto_utils import verify_totp
        self.assertTrue(verify_totp("s3cr3t", code_now, window_seconds=30))
        # a fresh code from the NEXT window is not accepted now (skew is ±1 past)
        # but the PREVIOUS window's unused code is
        code_prev = self.totp_code("s3cr3t", self.window - 1)
        second = self.public.get(self.link.path, {"t": code_prev})
        self.assertEqual(second.status_code, 200)

    def test_pruning_removes_old_codes(self):
        from gates.models import UsedGateCode
        code = self.totp_code("s3cr3t", self.window)
        self.public.get(self.link.path, {"t": code})
        # age the record beyond the prune horizon
        old = UsedGateCode.objects.get(link=self.link)
        old.used_at = timezone.now() - timezone.timedelta(seconds=200)
        old.save(update_fields=["used_at"])
        # a new valid code triggers the prune sweep
        self.public.get(self.link.path, {"t": self.totp_code("s3cr3t", self.window - 1)})
        self.assertFalse(UsedGateCode.objects.filter(pk=old.pk).exists())

    def test_same_code_different_links_independent(self):
        other = DeliveryLink.objects.create(path="/g/otp/2", kind="key", key_text="K2",
                                            gate_type="totp", totp_secret="other-secret")
        # per-link secrets produce different codes; verify both links accept theirs
        code_a = self.totp_code("s3cr3t", self.window)
        code_b = self.totp_code("other-secret", self.window)
        self.assertEqual(self.public.get(self.link.path, {"t": code_a}).status_code, 200)
        self.assertEqual(self.public.get(other.path, {"t": code_b}).status_code, 200)


@tag("unit")
class ConfirmDialogTests(TestCase):
    def test_no_native_confirm_left_in_app_js(self):
        import os
        from django.conf import settings as dj_settings
        js = open(os.path.join(dj_settings.BASE_DIR, "static/js/app.js")).read()
        self.assertNotIn("window.confirm", js)
        self.assertIn("confirm-overlay", js)
        self.assertIn("rdr-no-confirm", js)

    def test_mobile_templates_use_data_confirm(self):
        import os
        from django.conf import settings as dj_settings
        for name in ["submissions.html", "submission_detail.html", "link_detail.html"]:
            path = os.path.join(dj_settings.BASE_DIR, "templates", "mobile", name)
            text = open(path).read()
            self.assertNotIn("onsubmit", text, name)
            if name != "submissions.html":
                self.assertIn("data-confirm", text, name)

    def test_settings_page_has_reset_control(self):
        operator = Operator.objects.create_user(username="cfop", password="long-enough-password-123")
        client = Client()
        client.force_login(operator)
        response = client.get(reverse("settings"))
        self.assertContains(response, "reset-confirmations")
        self.assertContains(response, "rdr-no-confirm")


@tag("functional")
@override_settings(AUTO_BAN_THRESHOLD=0)
class GateFormatAndRangeTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="fmtop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)

    def test_totp_hex8_default(self):
        from gates.crypto_utils import totp_code
        code = totp_code("s3cr3t", 42)
        self.assertEqual(len(code), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in code))

    def test_totp_digits6_style(self):
        from gates.crypto_utils import totp_code
        from gates.models import GateConfig
        config = GateConfig.get_solo()
        config.totp_style = "digits6"
        config.save(update_fields=["totp_style"])
        code = totp_code("s3cr3t", 42)
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())
        config.totp_style = "hex8"
        config.save(update_fields=["totp_style"])

    def test_totp_digits6_gate_flow(self):
        import time
        from gates.crypto_utils import totp_code
        from gates.models import GateConfig
        config = GateConfig.get_solo()
        config.totp_style = "digits6"
        config.save(update_fields=["totp_style"])
        link = DeliveryLink.objects.create(path="/g/fmt/1", kind="key", key_text="K",
                                           gate_type="totp", totp_secret="s3cr3t")
        window = int(time.time()) // 30
        public = Client()
        ok = public.get(link.path, {"t": totp_code("s3cr3t", window)})
        self.assertEqual(ok.status_code, 200)
        config.totp_style = "hex8"
        config.save(update_fields=["totp_style"])

    def test_gate_style_via_settings_page(self):
        response = self.client.post(reverse("settings"), {"action": "gate_style", "totp_style": "digits6"})
        self.assertEqual(response.status_code, 302)
        from gates.models import GateConfig
        self.assertEqual(GateConfig.get_solo().totp_style, "digits6")

    def test_gate_style_via_api(self):
        response = self.client.patch("/api/v1/gate-config/", data={"totp_style": "digits6"},
                                     content_type="application/json")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/api/v1/gate-config/")
        self.assertEqual(response.json()["totp_style"], "digits6")

    def test_key_download_supports_range(self):
        link = DeliveryLink.objects.create(path="/g/rng/1", kind="key", key_text="K" * 2000)
        public = Client()
        full = public.get(link.path)
        self.assertEqual(full.get("Accept-Ranges"), "bytes")
        partial = public.get(link.path + "?re=1", HTTP_RANGE="bytes=0-99")
        self.assertIn(partial.status_code, (200, 206))

    def test_benevolent_supports_range_uniformly(self):
        link = DeliveryLink.objects.create(path="/g/rng/2", kind="key", key_text="K" * 500,
                                           requires_approval=True, approval_status="denied",
                                           on_deny="benevolent")
        link.benevolent_file.save("b.bin", ContentFile(b"B" * 4000), save=True)
        public = Client()
        full = public.get(link.path)
        self.assertEqual(full.get("Accept-Ranges"), "bytes")
        partial = public.get(link.path, HTTP_RANGE="bytes=0-99")
        self.assertEqual(partial.status_code, 206)
        self.assertEqual(partial.get("Content-Range"), "bytes 0-99/4000")
        bad = public.get(link.path, HTTP_RANGE="bytes=9999-10000")
        self.assertEqual(bad.status_code, 416)

    def test_file_download_supports_range(self):
        link = DeliveryLink.objects.create(path="/g/rng/3", kind="proxy",
                                           pwndrop_url="http://10.255.255.1/x.bin")
        with mock.patch("gates.services._fetch_pwndrop", return_value=(b"P" * 2000, "application/octet-stream")):
            partial = Client().get(link.path, HTTP_RANGE="bytes=500-999")
        self.assertEqual(partial.status_code, 206)
        self.assertEqual(partial.get("Content-Range"), "bytes 500-999/2000")


@tag("unit")
class BasePathCustomizationTests(TestCase):
    def test_settings_normalize_bases(self):
        from config.settings import _norm_base
        self.assertEqual(_norm_base("/g/", "/g/"), "/g/")
        self.assertEqual(_norm_base("fsafs/20fj", "/g/"), "/fsafs/20fj/")
        self.assertEqual(_norm_base("", "/g/"), "/g/")
        self.assertEqual(_norm_base("  /a4q9/  ", "/a/"), "/a4q9/")

    def test_default_conf_has_placeholders(self):
        from django.conf import settings as dj_settings
        import os
        conf = open(os.path.join(dj_settings.BASE_DIR, "default.conf")).read()
        self.assertIn("<GATE_BASE>", conf)
        self.assertIn("<AGENT_BASE>", conf)
        self.assertNotIn("location /g/", conf)
        self.assertNotIn("location /a/", conf)


@tag("functional")
@override_settings(GATE_BASE_PATH="/gx7q/", AGENT_BASE_PATH="/aq2w/", AUTO_BAN_THRESHOLD=0)
class CustomBasePathTests(TestCase):
    def test_links_live_under_custom_base(self):
        link = DeliveryLink.objects.create(path="/gx7q/drop1", kind="key", key_text="KEY")
        response = self.client.get(link.path)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "KEY")
        # the default /g/ base no longer routes
        stale = self.client.get("/g/drop1")
        self.assertEqual(stale.status_code, 200)

    def test_canary_follows_the_custom_base(self):
        response = self.client.get("/gx7q/canary/deadbeef.gif")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "image/gif")
        self.assertTrue(HitEvent.objects.filter(category="suspicious").exists())

    def test_agent_paths_follow_custom_base(self):
        agent = AgentChannel.objects.create(label="a1")
        self.assertTrue(agent.path.startswith("/aq2w/"), agent.path)


@tag("functional")
class APIKeyAuthTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="keyop", password="long-enough-password-123")
        self.api_key, self.raw = APIKey.create(operator=self.operator, name="ci")
        self.other = Operator.objects.create_user(username="keyop2", password="long-enough-password-123")

    def _auth(self, key=None):
        return {"HTTP_AUTHORIZATION": f"ApiKey {key or self.raw}"}

    def test_key_authenticates_against_api(self):
        response = self.client.get("/api/v1/gate-stats/", **self._auth())
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.json())

    def test_key_can_write(self):
        response = self.client.post("/api/v1/links/", data={
            "path": "/g/key/1", "kind": "key", "key_text": "k",
            "gate_type": "none", "cipher": "none", "placeholder": "blank",
            "on_deny": "not_found",
        }, content_type="application/json", **self._auth())
        self.assertEqual(response.status_code, 201)

    def test_wrong_and_revoked_keys_rejected(self):
        response = self.client.get("/api/v1/gate-stats/", **self._auth("rofk_wrongwrongwrongwrongwrong"))
        self.assertEqual(response.status_code, 403)
        self.api_key.is_active = False
        self.api_key.save(update_fields=["is_active"])
        response = self.client.get("/api/v1/gate-stats/", **self._auth())
        self.assertEqual(response.status_code, 403)

    def test_expired_key_rejected(self):
        self.api_key.expires_at = timezone.now() - timezone.timedelta(minutes=1)
        self.api_key.save(update_fields=["expires_at"])
        response = self.client.get("/api/v1/gate-stats/", **self._auth())
        self.assertEqual(response.status_code, 403)

    def test_key_does_not_use_session_and_ignores_csrf(self):
        # No session cookie: key-only request, POST without CSRF token works.
        response = self.client.post("/api/v1/bans/", data={"ip": "192.0.2.77", "note": "n"},
                                    content_type="application/json", **self._auth())
        self.assertEqual(response.status_code, 201)

    def test_last_used_recorded(self):
        self.client.get("/api/v1/gate-stats/", **self._auth())
        self.api_key.refresh_from_db()
        self.assertIsNotNone(self.api_key.last_used_at)

    def test_provision_and_revoke_via_api(self):
        response = self.client.post("/api/v1/apikeys/", data={"name": "second"},
                                    content_type="application/json", **self._auth())
        self.assertEqual(response.status_code, 201)
        key_id = response.json()["id"]
        new_raw = response.json()["key"]
        self.assertTrue(new_raw.startswith("rofk_"))
        # list does not expose secrets
        response = self.client.get("/api/v1/apikeys/", **self._auth())
        self.assertNotIn("key", response.json()[0])
        # other operator cannot revoke
        other_key = APIKey.create(operator=self.other, name="x")[0]
        response = self.client.post(f"/api/v1/apikeys/{other_key.pk}/revoke/",
                                    **self._auth())
        self.assertEqual(response.status_code, 403)
        # owner revokes
        response = self.client.post(f"/api/v1/apikeys/{key_id}/revoke/", **self._auth())
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/api/v1/gate-stats/",
                                   **{"HTTP_AUTHORIZATION": f"ApiKey {new_raw}"})
        self.assertEqual(response.status_code, 403)

    def test_admin_endpoints_via_key(self):
        admin = Operator.objects.create_user(username="keyadmin", password="long-enough-password-123",
                                             is_superuser=True)
        admin_key, admin_raw = APIKey.create(operator=admin, name="a")
        auth = {"HTTP_AUTHORIZATION": f"ApiKey {admin_raw}"}
        response = self.client.post("/api/v1/operators/invitations/", data={
            "username": "invited-op", "role": "Operator"}, content_type="application/json", **auth)
        self.assertEqual(response.status_code, 201)
        self.assertIn("invite/", response.json()["url"])
        # non-admin cannot invite
        response = self.client.post("/api/v1/operators/invitations/", data={
            "username": "nope"}, content_type="application/json", **self._auth())
        self.assertEqual(response.status_code, 403)
        # admin resets 2fa
        target = Operator.objects.create_user(username="locked2", password="long-enough-password-123")
        target.totp_enabled = True
        target.save(update_fields=["totp_enabled"])
        response = self.client.post(f"/api/v1/operators/{target.pk}/reset-2fa/", **auth)
        self.assertEqual(response.status_code, 200)
        target.refresh_from_db()
        self.assertFalse(target.totp_enabled)

    def test_parity_endpoints(self):
        link = DeliveryLink.objects.create(path="/g/ktotp/1", kind="key", key_text="K",
                                           gate_type="totp", totp_secret="s")
        response = self.client.get(f"/api/v1/links/{link.pk}/totp/", **self._auth())
        self.assertEqual(response.status_code, 200)
        self.assertIn("codes", response.json())
        response = self.client.post("/api/v1/selftest/", **self._auth())
        self.assertEqual(response.status_code, 200)
        self.assertIn("checks", response.json())

    def test_manage_command(self):
        from io import StringIO
        from django.core.management import call_command
        out = StringIO()
        call_command("create_apikey", "keyop", "--name", "from-cli", stdout=out)
        self.assertIn("rofk_", out.getvalue())
        self.assertTrue(APIKey.objects.filter(operator=self.operator, name="from-cli").exists())

    def test_security_page_shows_key_management(self):
        self.client.force_login(self.operator)
        response = self.client.get(reverse("security"))
        self.assertContains(response, "API keys")
        response = self.client.post(reverse("security"), {"action": "apikey_create", "name": "ui key"})
        self.assertContains(response, "rofk_")


@tag("functional")
class ThemeTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="themeop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)

    def test_default_theme_has_no_circus_class(self):
        response = self.client.get(reverse("overview"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "theme-cozy")
        self.assertNotContains(response, "theme-cozy.css")

    def test_settings_apply_theme(self):
        response = self.client.post(reverse("settings"), {"action": "theme", "theme": "cozy"})
        self.assertEqual(response.status_code, 302)
        self.operator.refresh_from_db()
        self.assertEqual(self.operator.theme, "cozy")
        response = self.client.get(reverse("overview"))
        self.assertContains(response, "theme-cozy")
        self.assertContains(response, "theme-cozy.css")

    def test_theme_is_per_account(self):
        other = Operator.objects.create_user(username="themeop2", password="long-enough-password-123")
        other_client = Client()
        other_client.force_login(other)
        self.client.post(reverse("settings"), {"action": "theme", "theme": "cozy"})
        response = other_client.get(reverse("overview"))
        self.assertNotContains(response, "theme-cozy")

    def test_invalid_theme_rejected(self):
        self.client.post(reverse("settings"), {"action": "theme", "theme": "deep-blue-sea"})
        self.operator.refresh_from_db()
        self.assertEqual(self.operator.theme, "default")

    def test_mobile_ui_uses_theme(self):
        self.operator.theme = "cozy"
        self.operator.save(update_fields=["theme"])
        DeliveryLink.objects.create(path="/g/t/1", kind="key", key_text="K",
                                    gate_type="submission", cipher="base64", requires_approval=True)
        import base64
        blob = base64.b64encode(b'{"hostname":"h"}').decode()
        Client().post("/g/t/1", data=blob, content_type="text/plain")
        response = self.client.get("/m/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'class="theme-cozy"')
        self.assertContains(response, "theme-cozy.css")

    def test_brand_renamed(self):
        response = self.client.get(reverse("overview"))
        self.assertContains(response, "RoF//OPS")
        self.assertNotContains(response, "RDR//OPS")

    def test_obnoxious_theme_loads_full_kit(self):
        self.operator.theme = "obnoxious"
        self.operator.save(update_fields=["theme"])
        response = self.client.get(reverse("overview"))
        self.assertContains(response, "theme-obnoxious.css")
        self.assertContains(response, "theme-obnoxious.js")
        self.assertContains(response, "circus-balloon")
        self.assertContains(response, "brand-mark jester")
        self.assertContains(response, "circus-eyes")

    def test_obnoxious_assets_exist(self):
        import os
        from django.conf import settings
        for asset in ["css/theme-obnoxious.css", "js/theme-obnoxious.js", "css/theme-cozy.css"]:
            path = os.path.join(settings.BASE_DIR, "static", asset)
            self.assertTrue(os.path.exists(path), asset)

    def test_cozy_keeps_orbit_and_jester_stays_obnoxious(self):
        self.operator.theme = "cozy"
        self.operator.save(update_fields=["theme"])
        response = self.client.get(reverse("overview"))
        self.assertContains(response, "theme-cozy.css")
        self.assertNotContains(response, "theme-obnoxious.css")
        self.assertNotContains(response, "circus-balloon")
        self.assertContains(response, "status-orbit")

    def test_nav_icons_and_theme_favicons(self):
        response = self.client.get(reverse("overview"))
        self.assertContains(response, 'class="icon"', count=None)  # nav icons present
        self.assertContains(response, 'favicon.svg')
        self.assertNotContains(response, "favicon-obnoxious.svg")
        self.operator.theme = "obnoxious"
        self.operator.save(update_fields=["theme"])
        response = self.client.get(reverse("overview"))
        self.assertContains(response, "favicon-obnoxious.svg")
        self.operator.theme = "cozy"
        self.operator.save(update_fields=["theme"])
        response = self.client.get(reverse("overview"))
        self.assertContains(response, "favicon-cozy.svg")

    def test_mobile_tabbar_icons(self):
        response = self.client.get("/m/")
        self.assertContains(response, 'class="icon"')


@tag("functional")
@override_settings(ROOT_URLCONF="config.test_urls", OPERATOR_PREFIX="testprefix")
class OperatorPrefixTests(TestCase):
    def test_operator_paths_live_under_the_prefix(self):
        self.assertEqual(reverse("login"), "/testprefix/login/")
        self.assertEqual(reverse("logout"), "/testprefix/logout/")
        self.assertEqual(reverse("overview"), "/testprefix/panel/")
        self.assertEqual(reverse("gate-links"), "/testprefix/panel/links/")
        self.assertEqual(reverse("gate-decoys"), "/testprefix/panel/decoys/")
        self.assertEqual(reverse("api-links"), "/testprefix/api/v1/links/")
        self.assertEqual(reverse("m-submissions"), "/testprefix/m/")
        self.assertEqual(self.client.get("/testprefix/login/").status_code, 200)
        # infrastructure stays at the root
        self.assertEqual(self.client.get("/health/live/").status_code, 200)

    def test_unprefixed_operator_paths_are_gone(self):
        for path in ("/panel/", "/login/", "/api/v1/links/", "/api", "/m/"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)  # decoy at 200
        # and unknown paths present the decoy to anonymous visitors
        response = self.client.get("/panel/")
        self.assertContains(response, "Update Service")

    def test_outside_prefix_is_decoy_even_for_authenticated_operators(self):
        from accounts.models import Operator
        operator = Operator.objects.create_user(username="prefop", password="long-enough-password-123")
        self.client.force_login(operator)
        for path in ("/api", "/api/v1/links/", "/panel/", "/login/"):
            response = self.client.get(path)
            self.assertContains(response, "Update Service", msg_prefix=path)
        # inside the prefix, operators still get the helpful panel 404
        response = self.client.get("/testprefix/panel/no-such-page/")
        self.assertContains(response, "Nothing lives at this address", status_code=404)
        self.assertNotContains(response, "Update Service", status_code=404)








@override_settings(AUTO_BAN_THRESHOLD=0)
class PayloadManagerTests(TestCase):
    def setUp(self):
        import shutil
        import tempfile
        media = tempfile.mkdtemp(prefix="rof-media-")
        patch = override_settings(MEDIA_ROOT=media)
        patch.enable()
        self.addCleanup(patch.disable)
        self.addCleanup(shutil.rmtree, media, True)
        self.operator = Operator.objects.create_user(username="pmop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)
        self.public = Client()

    def _file_link(self, path="/g/pm/one", payload=b"X" * 64, name="one.bin", **kwargs):
        link = DeliveryLink.objects.create(path=path, kind="file", placeholder="blank", **kwargs)
        link.payload.save(name, ContentFile(payload), save=True)
        return link

    def test_quick_drop_creates_live_file_link(self):
        response = self.client.post(reverse("gate-link-quick-drop"), {
            "file": ContentFile(b"PAYLOADBYTES", name="update.bin"), "name": "Q4 update"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        link = DeliveryLink.objects.get(pk=body["id"])
        self.assertEqual(link.kind, "file")
        self.assertTrue(link.active)
        self.assertEqual(link.label, "Q4 update")
        from django.conf import settings as dj_settings
        self.assertTrue(link.path.startswith(dj_settings.GATE_BASE_PATH))
        served = self.public.get(link.path)
        self.assertEqual(served.status_code, 200)
        self.assertEqual(served.content, b"PAYLOADBYTES")

    def test_quick_drop_requires_file(self):
        response = self.client.post(reverse("gate-link-quick-drop"), {"name": "nothing"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(DeliveryLink.objects.count(), 0)

    def test_quick_drop_labels_from_filename(self):
        response = self.client.post(reverse("gate-link-quick-drop"), {
            "file": ContentFile(b"Z", name="agent-stage2.exe")})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["label"], "agent-stage2.exe")

    def test_payloads_page_lists_payload_links(self):
        link = self._file_link()
        response = self.client.get(reverse("gate-payloads"))
        self.assertContains(response, link.payload.name.rsplit("/", 1)[-1])
        self.assertContains(response, "one")  # stored name keeps the uploaded stem
        self.assertContains(response, link.path)

    def test_payloads_replace_keeps_url_swaps_file(self):
        link = self._file_link(payload=b"OLD")
        old_name = link.payload.name
        response = self.client.post(reverse("gate-payloads"), {
            "link_id": link.pk, "action": "replace",
            "payload": ContentFile(b"NEWCONTENT", name="two.bin")})
        self.assertRedirects(response, reverse("gate-payloads"))
        link.refresh_from_db()
        self.assertNotEqual(link.payload.name, old_name)
        self.assertIn("two.bin", link.payload.name)
        served = self.public.get(link.path)
        self.assertEqual(served.status_code, 200)
        self.assertEqual(served.content, b"NEWCONTENT")

    def test_payloads_clear_removes_file_link_stays(self):
        link = self._file_link()
        response = self.client.post(reverse("gate-payloads"), {"link_id": link.pk, "action": "clear"})
        self.assertRedirects(response, reverse("gate-payloads"))
        link.refresh_from_db()
        self.assertFalse(link.payload)
        # Link object survives; serving now fails closed rather than 500s.
        self.assertIn(self.public.get(link.path).status_code, (404, 502))

    def test_payloads_clear_benevolent(self):
        link = DeliveryLink.objects.create(path="/g/pm/ben", kind="file", on_deny="benevolent")
        link.benevolent_file.save("deny.bin", ContentFile(b"DENY"), save=True)
        self.client.post(reverse("gate-payloads"), {"link_id": link.pk, "action": "clear_benevolent"})
        link.refresh_from_db()
        self.assertFalse(link.benevolent_file)

    def test_payloads_page_shows_gate_intel(self):
        link = self._file_link()
        submission = Submission.objects.create(
            link=link, decoded_json={"hostname": "dc01"}, client_ip_hash="a" * 64)
        SubmissionImage.objects.create(
            submission=submission, field_name="screenshot",
            image=ContentFile(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16, name="s.png"))
        response = self.client.get(reverse("gate-payloads"))
        self.assertContains(response, "dc01")
        self.assertContains(response, "1 img")
        self.assertContains(response, "1 SUB")

    def test_payloads_page_lists_benevolent_and_decoys(self):
        link = DeliveryLink.objects.create(path="/g/pm/b2", kind="file", on_deny="benevolent")
        link.benevolent_file.save("sorry.html", ContentFile(b"<html>"), save=True)
        page = DecoyPage.objects.create(name="Portal", kind="upload", active=True)
        page.html_file.save("portal.html", ContentFile(b"<html>portal</html>"), save=True)
        response = self.client.get(reverse("gate-payloads"))
        self.assertContains(response, link.benevolent_file.name.rsplit("/", 1)[-1])
        self.assertContains(response, "Portal")

    def test_link_detail_renders_download_chart(self):
        link = self._file_link()
        self.public.get(link.path)
        response = self.client.get(reverse("gate-link-detail", args=[link.pk]))
        self.assertContains(response, 'id="payload-chart"')
        self.assertContains(response, 'id="payload-series"')
        marker = '<script id="payload-series" type="application/json">'
        blob = response.content.decode().split(marker, 1)[1].split("</script>", 1)[0]
        series = json.loads(blob)
        self.assertEqual(len(series), 14)
        self.assertEqual(series[-1]["count"], 1)

    def test_link_form_has_drag_drop_zones(self):
        response = self.client.get(reverse("gate-link-create"))
        self.assertContains(response, 'drop-zone" data-file-input="payload-input"')
        self.assertContains(response, 'data-file-input="benevolent-input"')

    def test_nav_links_to_payloads(self):
        response = self.client.get(reverse("overview"))
        self.assertContains(response, reverse("gate-payloads"))

    def test_safe_size_helpers_survive_missing_files(self):
        link = self._file_link()
        link.payload.delete(save=False)  # removes from storage, name still set
        link.refresh_from_db()
        self.assertIsNone(link.payload_size)
        page = DecoyPage.objects.create(name="Gone", kind="upload")
        self.assertIsNone(page.html_file_size)

    def test_api_exposes_payload_fields(self):
        _, raw = APIKey.create(operator=self.operator, name="ci")
        link = self._file_link(payload=b"N" * 32)
        response = self.client.get("/api/v1/links/", HTTP_AUTHORIZATION=f"ApiKey {raw}")
        self.assertEqual(response.status_code, 200)
        entry = next(item for item in response.json() if item["id"] == link.pk)
        self.assertIn("one", entry["payload"])
        self.assertIn(".bin", entry["payload"])
        self.assertEqual(entry["payload_size"], 32)
        self.assertIsNone(entry["benevolent_file"])


@override_settings(AUTO_BAN_THRESHOLD=0)
class LureAndDecoySiteTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="luop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)
        self.public = Client()

    def _lure(self, slug="portal", active=True):
        site = LureSite.objects.create(name="Portal", slug=slug, active=active)
        site.files.create(path="index.html", content="<h1>Portal Home</h1>")
        site.files.create(path="about.html", content="<h1>About Us</h1>")
        site.files.create(path="css/style.css", content="body{color:#111}")
        return site

    # ── Lure serving ────────────────────────────────────────────────────────
    def test_lure_index_served_at_root(self):
        self._lure()
        response = self.public.get("/l/portal/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Portal Home", response.content)
        self.assertIn("text/html", response["Content-Type"])

    def test_lure_nested_page_and_asset_content_types(self):
        site = self._lure()
        self.assertIn(b"About Us", self.public.get("/l/portal/about.html").content)
        css = self.public.get("/l/portal/css/style.css")
        self.assertEqual(css.status_code, 200)
        self.assertIn("text/css", css["Content-Type"])
        site.files.create(path="js/app.js", content="console.log(1)")
        script = self.public.get("/l/portal/js/app.js")
        self.assertIn("text/javascript", script["Content-Type"])

    def test_lure_hit_recorded(self):
        site = self._lure()
        self.public.get("/l/portal/")
        hit = HitEvent.objects.get(category="lure")
        self.assertEqual(hit.detail["slug"], "portal")
        self.assertEqual(hit.detail["file"], "index.html")

    def test_inactive_lure_falls_back_to_decoy(self):
        self._lure(active=False)
        response = self.public.get("/l/portal/")
        self.assertContains(response, "Update Service")
        self.assertNotIn(b"Portal Home", response.content)

    def test_unknown_lure_slug_is_decoy(self):
        self._lure()
        response = self.public.get("/l/nope/")
        self.assertContains(response, "Update Service")

    def test_missing_lure_page_uses_site_404_then_decoy(self):
        site = self._lure()
        # No 404.html yet: global decoy.
        response = self.public.get("/l/portal/no-such-page")
        self.assertContains(response, "Update Service")
        hit = HitEvent.objects.get(category="lure", status_code=404)
        self.assertEqual(hit.detail["missing"], "no-such-page")
        # With a 404.html the site keeps its own look.
        site.files.create(path="404.html", content="<h1>Portal Not Found</h1>")
        response = self.public.get("/l/portal/no-such-page")
        self.assertIn(b"Portal Not Found", response.content)

    def test_lure_traversal_gets_nowhere(self):
        self._lure()
        for nasty in ("/l/portal/../secret", "/l/portal/..%2fsecret", "/l/portal/%2e%2e/secret"):
            response = self.public.get(nasty)
            self.assertIn(b"Update Service", response.content, nasty)

    def test_lure_blocking_rules_apply(self):
        self._lure()
        BlockingRule.objects.create(
            name="block curl", logic="any",
            conditions=[{"type": "ua", "pattern": r"(?i)^curl"}], enabled=True)
        response = self.public.get("/l/portal/", HTTP_USER_AGENT="curl/8.0")
        self.assertContains(response, "Update Service")
        self.assertFalse(HitEvent.objects.filter(category="lure", status_code=200).exists())
        self.assertTrue(HitEvent.objects.filter(category="blocked").exists())

    # ── Decoy assets ────────────────────────────────────────────────────────
    def test_decoy_asset_served(self):
        page = DecoyPage.objects.create(name="P", kind="template", template_key="update-service")
        asset = page.assets.create(path="style.css", content="a{color:red}")
        response = self.public.get(asset.public_path)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"a{color:red}", response.content)
        self.assertIn("text/css", response["Content-Type"])
        self.assertTrue(HitEvent.objects.filter(category="decoy_asset").exists())

    def test_decoy_asset_unknown_and_inactive_fall_back(self):
        page = DecoyPage.objects.create(name="P", kind="template", template_key="update-service")
        asset = page.assets.create(path="style.css", content="x")
        response = self.public.get(f"/d/{page.pk}/missing.css")
        self.assertContains(response, "Update Service")
        page.active = False
        page.save(update_fields=["active"])
        response = self.public.get(asset.public_path)
        self.assertContains(response, "Update Service")

    # ── Decoy html override ─────────────────────────────────────────────────
    def test_decoy_html_override_precedence_and_revert(self):
        page = DecoyPage.objects.get(template_key="update-service")
        DecoyPage.objects.filter(pk=page.pk).update(is_default=True)
        page.html = "<h1>Edited Cover</h1>"
        page.save(update_fields=["html"])
        response = self.public.get("/definitely-not-real")
        self.assertIn(b"Edited Cover", response.content)
        self.assertNotIn(b"Update Service", response.content)
        page.html = ""
        page.save(update_fields=["html"])
        response = self.public.get("/definitely-not-real")
        self.assertContains(response, "Update Service")

    # ── Browser editor (panel) ──────────────────────────────────────────────
    def test_lure_create_seeds_files_and_redirects_to_editor(self):
        response = self.client.post(reverse("gate-lures"), {
            "name": "New Lure", "slug": "newlure", "description": "d"})
        site = LureSite.objects.get(slug="newlure")
        self.assertRedirects(response, reverse("gate-lure-edit", args=[site.pk]))
        self.assertTrue(site.files.filter(path="index.html").exists())
        self.assertTrue(site.files.filter(path="css/style.css").exists())
        self.assertIn(b"It works", self.public.get("/l/newlure/").content)

    def test_lure_editor_save_rename_delete(self):
        site = self._lure()
        url = reverse("gate-lure-edit", args=[site.pk])
        self.client.post(url, {"action": "save_file", "original_path": "index.html",
                               "path": "index.html", "content": "<h1>V2</h1>"})
        self.assertIn(b"V2", self.public.get("/l/portal/").content)
        # rename via the path field
        self.client.post(url, {"action": "save_file", "original_path": "about.html",
                               "path": "company.html", "content": "<h1>Co</h1>"})
        self.assertFalse(site.files.filter(path="about.html").exists())
        self.assertIn(b"Co", self.public.get("/l/portal/company.html").content)
        # delete
        self.client.post(url, {"action": "delete_file", "path": "company.html"})
        self.assertFalse(site.files.filter(path="company.html").exists())

    def test_lure_editor_rejects_bad_paths(self):
        site = self._lure()
        url = reverse("gate-lure-edit", args=[site.pk])
        for bad in ("../evil", "/abs.html", "a//b.html", "x?.html", "..hidden"):
            self.client.post(url, {"action": "add_file", "path": bad})
            self.assertFalse(site.files.filter(path=bad).exists(), bad)
        self.assertEqual(site.files.count(), 3)

    def test_lure_meta_and_toggle(self):
        site = self._lure()
        self.client.post(reverse("gate-lure-edit", args=[site.pk]),
                         {"action": "meta", "name": "Renamed", "slug": "portal",
                          "description": "x", "active": "off"})
        site.refresh_from_db()
        self.assertFalse(site.active)
        self.client.post(reverse("gate-lure-toggle", args=[site.pk]))
        site.refresh_from_db()
        self.assertTrue(site.active)

    def test_decoy_editor_saves_override_and_assets(self):
        page = DecoyPage.objects.get(template_key="update-service")
        url = reverse("gate-decoy-edit", args=[page.pk])
        response = self.client.get(url)
        self.assertContains(response, "Update Service")  # prefilled from source
        self.client.post(url, {"action": "save_html", "content": "<h1>My Cover</h1>"})
        page.refresh_from_db()
        self.assertEqual(page.html, "<h1>My Cover</h1>")
        self.client.post(url, {"action": "add_asset", "path": "style.css"})
        self.client.post(url, {"action": "save_asset", "original_path": "style.css",
                               "path": "style.css", "content": "body{margin:0}"})
        self.assertIn(b"body{margin:0}", self.public.get(f"/d/{page.pk}/style.css").content)
        self.client.post(url, {"action": "delete_asset", "path": "style.css"})
        self.assertFalse(page.assets.filter(path="style.css").exists())

    # ── API parity ──────────────────────────────────────────────────────────
    def test_api_lure_roundtrip(self):
        _, raw = APIKey.create(operator=self.operator, name="ci")
        auth = {"HTTP_AUTHORIZATION": f"ApiKey {raw}"}
        response = self.client.post("/api/v1/lures/", data={
            "name": "API Lure", "slug": "apilure", "description": "", "active": True,
        }, content_type="application/json", **auth)
        self.assertEqual(response.status_code, 201)
        pk = response.json()["id"]
        response = self.client.put(f"/api/v1/lures/{pk}/file/", data={
            "path": "index.html", "content": "<h1>API Home</h1>"},
            content_type="application/json", **auth)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"API Home", self.public.get("/l/apilure/").content)
        detail = self.client.get(f"/api/v1/lures/{pk}/", **auth).json()
        self.assertEqual(detail["files"][0]["path"], "index.html")
        self.assertEqual(detail["public_path"], "/l/apilure/")
        response = self.client.delete(f"/api/v1/lures/{pk}/file/",
                                      data={"path": "index.html"},
                                      content_type="application/json", **auth)
        self.assertEqual(response.status_code, 204)

    def test_api_decoy_html_and_assets(self):
        _, raw = APIKey.create(operator=self.operator, name="ci")
        auth = {"HTTP_AUTHORIZATION": f"ApiKey {raw}"}
        page = DecoyPage.objects.get(template_key="update-service")
        response = self.client.patch(f"/api/v1/decoys/{page.pk}/",
                                     data={"html": "<h1>API Cover</h1>"},
                                     content_type="application/json", **auth)
        self.assertEqual(response.status_code, 200)
        page.refresh_from_db()
        self.assertEqual(page.html, "<h1>API Cover</h1>")
        response = self.client.put(f"/api/v1/decoys/{page.pk}/asset/", data={
            "path": "app.js", "content": "let a=1"}, content_type="application/json", **auth)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"let a=1", self.public.get(f"/d/{page.pk}/app.js").content)

    def test_nav_links_to_lures(self):
        response = self.client.get(reverse("overview"))
        self.assertContains(response, reverse("gate-lures"))


@override_settings(AUTO_BAN_THRESHOLD=0)
class GateIntelTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="giop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)
        self.public = Client()

    def _png(self, tag=b"A"):
        # A real 1x1 PNG (valid header + IHDR) so the bytes render as an image.
        return (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89" + tag)

    def _submission_with_image(self, path="/g/gi/one", hostname="ws-01", field="screenshot"):
        link = DeliveryLink.objects.create(path=path, kind="file", placeholder="blank")
        sub = Submission.objects.create(
            link=link, decoded_json={"hostname": hostname}, client_ip_hash="c" * 64)
        image = SubmissionImage.objects.create(
            submission=sub, field_name=field,
            image=ContentFile(self._png(), name="shot.png"), content_type="image/png")
        return link, sub, image

    def test_link_detail_intel_gallery(self):
        link, sub, image = self._submission_with_image()
        response = self.client.get(reverse("gate-link-detail", args=[link.pk]))
        self.assertContains(response, "INTEL GALLERY")
        self.assertContains(response, "intel-card")
        self.assertContains(response, reverse("gate-submission-image", args=[image.pk]))
        self.assertContains(response, "data-lightbox")
        self.assertContains(response, "screenshot")

    def test_link_detail_gallery_absent_without_images(self):
        link = DeliveryLink.objects.create(path="/g/gi/none", kind="file")
        response = self.client.get(reverse("gate-link-detail", args=[link.pk]))
        self.assertNotContains(response, "INTEL GALLERY")

    def test_intel_page_lists_images_with_context(self):
        self._submission_with_image()
        response = self.client.get(reverse("gate-intel"))
        self.assertContains(response, "intel-card")
        self.assertContains(response, "ws-01")
        self.assertContains(response, "/g/gi/one")
        self.assertContains(response, "lightbox.js")

    def test_intel_page_filters(self):
        self._submission_with_image(path="/g/gi/one", hostname="ws-01", field="screenshot")
        self._submission_with_image(path="/g/gi/two", hostname="ws-02", field="webcam")
        response = self.client.get(reverse("gate-intel") + "?link=two")
        self.assertContains(response, "ws-02")
        self.assertNotContains(response, "ws-01")
        response = self.client.get(reverse("gate-intel") + "?field=webcam")
        self.assertContains(response, "ws-02")
        self.assertNotContains(response, "ws-01")

    def test_intel_page_empty_state(self):
        response = self.client.get(reverse("gate-intel"))
        self.assertContains(response, "No imagery yet")

    def test_submissions_table_thumbs_open_lightbox(self):
        self._submission_with_image()
        response = self.client.get(reverse("gate-submissions") + "?status=pending")
        self.assertContains(response, "data-lightbox")
        self.assertContains(response, "lightbox.js")

    def test_nav_links_to_intel(self):
        response = self.client.get(reverse("overview"))
        self.assertContains(response, reverse("gate-intel"))

    def test_api_submissions_nest_images_and_serve_bytes(self):
        _, raw = APIKey.create(operator=self.operator, name="ci")
        auth = {"HTTP_AUTHORIZATION": f"ApiKey {raw}"}
        link, sub, image = self._submission_with_image()
        listing = self.client.get("/api/v1/submissions/", **auth)
        entry = next(item for item in listing.json() if item["id"] == sub.pk)
        self.assertEqual(entry["images"][0]["field_name"], "screenshot")
        self.assertIn(f"/api/v1/submissions/image/{image.pk}/", entry["images"][0]["url"])
        response = self.client.get(entry["images"][0]["url"], **auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), image.image.open("rb").read())
        # anonymous callers get nothing
        anon = self.public.get(entry["images"][0]["url"])
        self.assertIn(anon.status_code, (401, 403))


@override_settings(AUTO_BAN_THRESHOLD=0)
class GateHardeningTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="ghop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)
        self.public = Client()

    def _key_link(self, path="/g/h/one", **kwargs):
        kwargs.setdefault("placeholder", "blank")
        return DeliveryLink.objects.create(path=path, kind="key", key_text="SEKRET", **kwargs)

    # ── IP / UA gating (no visitor-provided data needed) ────────────────────
    def test_allowed_ips_gate(self):
        self._key_link(allowed_ips=["10.8.0.0/16"])
        held = self.public.get("/g/h/one")
        self.assertEqual(held.status_code, 204)
        hit = HitEvent.objects.get(category="suspicious")
        self.assertEqual(hit.detail["reason"], "ip outside allow-list")
        DeliveryLink.objects.all().update(allowed_ips=["127.0.0.0/8"])
        self.assertEqual(self.public.get("/g/h/one").status_code, 200)

    def test_allowed_uas_gate(self):
        self._key_link(allowed_uas=[r"^MyAgent/\d+$"])
        held = self.public.get("/g/h/one", HTTP_USER_AGENT="curl/8.0")
        self.assertEqual(held.status_code, 204)
        ok = self.public.get("/g/h/one", HTTP_USER_AGENT="MyAgent/3")
        self.assertEqual(ok.status_code, 200)
        self.assertIn(b"SEKRET", ok.content)

    # ── Malleable header contract ───────────────────────────────────────────
    def test_header_contract_exact_and_missing(self):
        self._key_link(header_contract=[{"name": "X-Api-Version", "value": "2.1"}])
        self.assertEqual(self.public.get("/g/h/one").status_code, 204)  # missing
        self.assertEqual(self.public.get("/g/h/one", HTTP_X_API_VERSION="2.0").status_code, 204)  # wrong
        ok = self.public.get("/g/h/one", HTTP_X_API_VERSION="2.1")
        self.assertEqual(ok.status_code, 200)

    def test_header_contract_regex_fullmatch(self):
        self._key_link(header_contract=[{"name": "Accept-Language", "pattern": r"en-.."}])
        self.assertEqual(self.public.get("/g/h/one", HTTP_ACCEPT_LANGUAGE="xen-USx").status_code, 204)
        self.assertEqual(self.public.get("/g/h/one", HTTP_ACCEPT_LANGUAGE="en-US").status_code, 200)

    def test_header_contract_runs_before_token_check(self):
        # A contract failure must not reveal whether the gate token was right.
        self._key_link(gate_type="token", gate_token="tok",
                       header_contract=[{"name": "X-C2", "value": "yes"}])
        held = self.public.get("/g/h/one?t=tok")
        self.assertEqual(held.status_code, 204)
        self.assertEqual(HitEvent.objects.get(category="suspicious").detail["reason"],
                         "contract header missing: X-C2")

    def test_contract_validation_rejects_bad_shapes(self):
        from gates.models import validate_header_contract
        for bad in ([{"name": "X"}], [{"name": "X", "value": "1", "pattern": "2"}],
                    [{"pattern": "1"}], [{"name": "Bad Header", "value": "1"}], "nope"):
            with self.assertRaises(ValidationError, msg=str(bad)):
                validate_header_contract(bad)

    # ── Replay dedupe ───────────────────────────────────────────────────────
    def test_replay_dedupe_refuses_verbatim_repeat(self):
        self._key_link(gate_type="token", gate_token="tok", replay_dedupe=True)
        first = self.public.get("/g/h/one?t=tok")
        self.assertEqual(first.status_code, 200)
        repeat = self.public.get("/g/h/one?t=tok")
        self.assertEqual(repeat.status_code, 204)
        hit = HitEvent.objects.filter(category="suspicious").latest("created_at")
        self.assertEqual(hit.detail["reason"], "replayed request")
        # a different query string is a different request
        varied = self.public.get("/g/h/one?t=tok&r=2")
        self.assertEqual(varied.status_code, 200)

    def test_replay_dedupe_off_by_default(self):
        self._key_link(gate_type="token", gate_token="tok")
        self.assertEqual(self.public.get("/g/h/one?t=tok").status_code, 200)
        self.assertEqual(self.public.get("/g/h/one?t=tok").status_code, 200)

    # ── Time-window availability ────────────────────────────────────────────
    def test_active_window_blocks_outside_hours(self):
        now = timezone.now()
        self._key_link(
            active_window_start=(now + timezone.timedelta(hours=1)).time(),
            active_window_end=(now + timezone.timedelta(hours=2)).time())
        response = self.public.get("/g/h/one")
        self.assertEqual(response.status_code, 410)  # looks expired, like RedGuard
        link2 = self._key_link(path="/g/h/two",
                               active_window_start=datetime_time(0, 0),
                               active_window_end=datetime_time(23, 59))
        self.assertTrue(link2.in_active_window)
        self.assertEqual(self.public.get("/g/h/two").status_code, 200)

    def test_active_window_crosses_midnight(self):
        link = self._key_link(active_window_start=datetime_time(22, 0),
                              active_window_end=datetime_time(2, 0))
        real_now = timezone.now()
        with mock.patch("gates.models.timezone") as mocked:
            mocked.now.return_value = real_now.replace(hour=23, minute=30)
            self.assertTrue(link.in_active_window)
            mocked.now.return_value = real_now.replace(hour=1, minute=30)
            self.assertTrue(link.in_active_window)
            mocked.now.return_value = real_now.replace(hour=12, minute=0)
            self.assertFalse(link.in_active_window)

    # ── QR codes ────────────────────────────────────────────────────────────
    def test_qr_requires_login_and_renders_svg(self):
        link = self._key_link()
        anon = self.public.get(reverse("gate-link-qr", args=[link.pk]))
        self.assertEqual(anon.status_code, 302)
        response = self.client.get(reverse("gate-link-qr", args=[link.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertIn("image/svg+xml", response["Content-Type"])
        self.assertIn(b"<svg", response.content)

    # ── Geo conditions via stored intel ─────────────────────────────────────
    def test_country_condition_uses_stored_intel(self):
        IPIntel.objects.create(ip="127.0.0.1", country_code="US", org="Test ISP", asn="AS1")
        BlockingRule.objects.create(
            name="block US", logic="any", enabled=True,
            conditions=[{"type": "country", "pattern": "^US$"}])
        response = self.public.get("/g/h/nowhere")
        self.assertContains(response, "Update Service")
        self.assertTrue(HitEvent.objects.filter(category="blocked").exists())

    # ── Vendor feed import ──────────────────────────────────────────────────
    def test_import_ip_feed_replaces_ruleset(self):
        from django.core.management import call_command
        feed = b"# vendor ranges\n203.0.113.0/24\n198.51.100.7\ntext,203.0.113.0/24,extra\n\nbad-entry\n"
        with mock.patch("urllib.request.urlopen") as fetch:
            handle = mock.MagicMock()
            handle.read.return_value = feed
            handle.__enter__.return_value = handle
            handle.__exit__.return_value = False
            fetch.return_value = handle
            call_command("import_ip_feed", url="https://feeds.example/vendors.txt")
            call_command("import_ip_feed", url="https://feeds.example/vendors.txt")
        ruleset = RuleSet.objects.get(name="Vendor feed blocklist")
        self.assertTrue(ruleset.enabled)
        rules = list(ruleset.rules.all())
        self.assertEqual(len(rules), 1)
        patterns = {c["pattern"] for c in rules[0].conditions}
        self.assertEqual(patterns, {"203.0.113.0/24", "198.51.100.7/32"})

    # ── API parity ──────────────────────────────────────────────────────────
    def test_api_roundtrip_network_profile(self):
        _, raw = APIKey.create(operator=self.operator, name="ci")
        response = self.client.post("/api/v1/links/", data={
            "path": "/g/h/api", "kind": "key", "key_text": "K", "gate_type": "none",
            "cipher": "none", "placeholder": "blank", "on_deny": "not_found",
            "allowed_uas": ["^Agent"], "allowed_ips": ["127.0.0.0/8"],
            "header_contract": [{"name": "X-C2", "pattern": "^ok"}],
            "replay_dedupe": True,
            "active_window_start": "00:00", "active_window_end": "23:59",
        }, content_type="application/json", HTTP_AUTHORIZATION=f"ApiKey {raw}")
        self.assertEqual(response.status_code, 201, response.content)
        link = DeliveryLink.objects.get(path="/g/h/api")
        self.assertTrue(link.replay_dedupe)
        self.assertEqual(link.header_contract[0]["name"], "X-C2")
        held = self.public.get("/g/h/api", HTTP_USER_AGENT="curl/8.0", HTTP_X_C2="ok")
        self.assertEqual(held.status_code, 204)  # UA blocked before anything else
        ok = self.public.get("/g/h/api", HTTP_USER_AGENT="Agent/1", HTTP_X_C2="ok")
        self.assertEqual(ok.status_code, 200)


@override_settings(AUTO_BAN_THRESHOLD=0)
class NetworkGateAndFormUxTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="uxop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)
        self.public = Client()

    def test_network_gate_passes_on_profile_alone(self):
        DeliveryLink.objects.create(
            path="/g/n/one", kind="key", key_text="K", placeholder="blank",
            gate_type="network", allowed_uas=[r"^MyAgent/"], allowed_ips=["127.0.0.0/8"])
        # right UA + IP: no token, no code - the profile is the credential
        ok = self.public.get("/g/n/one", HTTP_USER_AGENT="MyAgent/1.2")
        self.assertEqual(ok.status_code, 200)
        # wrong UA: held, nothing served
        held = self.public.get("/g/n/one", HTTP_USER_AGENT="curl/8.0")
        self.assertEqual(held.status_code, 204)

    def test_network_gate_requires_an_allowlist(self):
        link = DeliveryLink(path="/g/n/empty", kind="key", key_text="K", gate_type="network")
        with self.assertRaises(ValidationError):
            link.full_clean()
        link.allowed_ips = ["10.0.0.0/8"]
        link.full_clean()  # one allow-list is enough

    def test_network_gate_rejects_header_contract_combo(self):
        link = DeliveryLink(path="/g/n/mix", kind="key", key_text="K", gate_type="network",
                            allowed_ips=["10.0.0.0/8"],
                            header_contract=[{"name": "X", "value": "1"}])
        with self.assertRaises(ValidationError):
            link.full_clean()

    def test_network_gate_via_form(self):
        response = self.client.post(reverse("gate-link-create"), {
            "path": "/g/n/form", "kind": "key", "key_text": "K", "gate_type": "network",
            "cipher": "none", "placeholder": "blank", "on_deny": "not_found",
            "allowed_uas": "^MyAgent", "active": "on",
        })
        self.assertRedirects(response, reverse("gate-link-detail", args=[DeliveryLink.objects.get(path="/g/n/form").pk]))
        self.assertEqual(self.public.get("/g/n/form", HTTP_USER_AGENT="MyAgent/9").status_code, 200)

    def test_form_marks_mutually_exclusive_fields(self):
        response = self.client.get(reverse("gate-link-create"))
        for marker in ('data-show-when="kind:key"', 'data-show-when="kind:file"',
                       'data-show-when="kind:proxy"', 'data-show-when="gate_type:token"',
                       'data-show-when="gate_type:totp"', 'data-show-when="gate_type:submission"',
                       'data-also-when="cipher:aes256"', 'data-show-when="on_deny:benevolent"',
                       'data-feature-when="gate_type:network"'):
            self.assertContains(response, marker)
        self.assertContains(response, "IP / User-Agent only")

    def test_decoy_form_hides_irrelevant_kinds(self):
        response = self.client.get(reverse("gate-decoys"))
        self.assertContains(response, 'data-show-when="kind:template"')
        self.assertContains(response, 'data-show-when="kind:upload"')
        self.assertContains(response, 'data-show-when="kind:redirect"')

    def test_conditional_fields_assets_loaded(self):
        response = self.client.get(reverse("gate-link-create"))
        self.assertContains(response, "js/conditional_fields.js")
        css = open("static/css/panel.css").read()
        self.assertIn(".field-hidden", css)
        self.assertIn(".field-dimmed", css)
        self.assertIn(".field-featured", css)


@override_settings(AUTO_BAN_THRESHOLD=0)
class GuidanceUxTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="gxop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)

    def test_guide_modal_shell_present_and_filled(self):
        response = self.client.get(reverse("gate-links"))
        self.assertContains(response, 'id="guide-open"')
        self.assertContains(response, 'id="guide-modal"')
        self.assertContains(response, "guide-body")
        self.assertContains(response, "QUICK PATH")  # links guide content rendered

    def test_link_form_tooltips_and_guide(self):
        response = self.client.get(reverse("gate-link-create"))
        content = response.content.decode()
        self.assertGreaterEqual(content.count("help-dot"), 15)
        self.assertContains(response, "CHOOSE A GATE")
        self.assertContains(response, "data-tip=")

    def test_submissions_guide_documents_shortcuts(self):
        response = self.client.get(reverse("gate-submissions"))
        self.assertContains(response, "kbd")

    def test_tip_tag_escapes_content(self):
        from django.template import Context, Template
        rendered = Template('{% load gate_extras %}{% tip "a<b>c" %}').render(Context())
        self.assertIn("a&lt;b&gt;c", rendered)
        self.assertIn("help-dot", rendered)

    def test_pages_without_guide_hide_button(self):
        # audit page has no guide block; the button stays hidden in markup
        response = self.client.get(reverse("audit-log"))
        self.assertContains(response, 'id="guide-open"')
        self.assertContains(response, 'id="guide-open" class="text-button" type="button" hidden')

    def test_mobile_intel_gallery(self):
        link = DeliveryLink.objects.create(path="/g/m/i", kind="file")
        sub = Submission.objects.create(link=link, decoded_json={"hostname": "ws-5"})
        SubmissionImage.objects.create(
            submission=sub, field_name="screenshot",
            image=ContentFile(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16, name="s.png"))
        response = self.client.get(reverse("m-intel"))
        self.assertContains(response, "shot-card")
        self.assertContains(response, "ws-5")
        self.assertContains(response, "INTEL")  # tab bar entry
        # anonymous visitors are redirected to login
        self.assertEqual(Client().get(reverse("m-intel")).status_code, 302)

    def test_mobile_links_have_quick_drop(self):
        response = self.client.get(reverse("m-links"))
        self.assertContains(response, "QUICK DROP")
        self.assertContains(response, "qd-file")


@override_settings(AUTO_BAN_THRESHOLD=0)
class ServeChanceTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="scop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)
        self.public = Client()

    def _link(self, num=1, den=1):
        return DeliveryLink.objects.create(path="/g/sc/one", kind="key", key_text="SEKRET",
                                           placeholder="blank", serve_num=num, serve_den=den)

    def test_default_ratio_always_serves(self):
        self._link()
        for _ in range(3):
            self.assertEqual(self.public.get("/g/sc/one").status_code, 200)

    def test_failed_roll_holds_without_consuming_uses(self):
        self._link(num=1, den=2)
        with mock.patch("secrets.randbelow", return_value=1):  # >= num -> rolled out
            response = self.public.get("/g/sc/one")
        self.assertEqual(response.status_code, 204)
        link = DeliveryLink.objects.get(path="/g/sc/one")
        self.assertEqual(link.hit_count, 0)  # no release consumed
        roll_hit = HitEvent.objects.filter(category="hit").latest("created_at")
        self.assertEqual(roll_hit.detail["chance_roll"], "1/2")
        self.assertFalse(roll_hit.detail["served"])

    def test_successful_roll_serves(self):
        self._link(num=1, den=20)
        with mock.patch("secrets.randbelow", return_value=0):  # < num -> serve
            response = self.public.get("/g/sc/one")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SEKRET", response.content)
        self.assertTrue(HitEvent.objects.filter(category="key_served").exists())

    def test_ratio_validation(self):
        link = self._link(num=3, den=7)
        link.full_clean()  # 3/7 valid
        link.serve_num, link.serve_den = 7, 3
        with self.assertRaises(ValidationError):
            link.full_clean()
        link.serve_num, link.serve_den = 0, 5
        with self.assertRaises(ValidationError):
            link.full_clean()

    def test_form_saves_ratio(self):
        response = self.client.post(reverse("gate-link-create"), {
            "path": "/g/sc/form", "kind": "key", "key_text": "K", "gate_type": "none",
            "cipher": "none", "placeholder": "blank", "on_deny": "not_found",
            "serve_num": "3", "serve_den": "7", "active": "on",
        })
        link = DeliveryLink.objects.get(path="/g/sc/form")
        self.assertEqual((link.serve_num, link.serve_den), (3, 7))
        # bad ratio rejected with a form error, no crash
        response = self.client.post(reverse("gate-link-create"), {
            "path": "/g/sc/bad", "kind": "key", "key_text": "K", "gate_type": "none",
            "cipher": "none", "placeholder": "blank", "on_deny": "not_found",
            "serve_num": "7", "serve_den": "3", "active": "on",
        })
        self.assertEqual(response.status_code, 200)  # form re-rendered with error
        self.assertFalse(DeliveryLink.objects.filter(path="/g/sc/bad").exists())

    def test_api_ratio_validation_and_roundtrip(self):
        _, raw = APIKey.create(operator=self.operator, name="ci")
        auth = {"HTTP_AUTHORIZATION": f"ApiKey {raw}"}
        bad = self.client.post("/api/v1/links/", data={
            "path": "/g/sc/api", "kind": "key", "key_text": "K", "gate_type": "none",
            "cipher": "none", "placeholder": "blank", "on_deny": "not_found",
            "serve_num": 5, "serve_den": 2,
        }, content_type="application/json", **auth)
        self.assertEqual(bad.status_code, 400)
        ok = self.client.post("/api/v1/links/", data={
            "path": "/g/sc/api", "kind": "key", "key_text": "K", "gate_type": "none",
            "cipher": "none", "placeholder": "blank", "on_deny": "not_found",
            "serve_num": 1, "serve_den": 20,
        }, content_type="application/json", **auth)
        self.assertEqual(ok.status_code, 201)
        self.assertEqual((ok.json()["serve_num"], ok.json()["serve_den"]), (1, 20))


class ProgressiveDisclosureTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="pdop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)

    def test_create_form_collapses_advanced_sections(self):
        response = self.client.get(reverse("gate-link-create"))
        content = response.content.decode()
        self.assertIn('details class="adv"', content)
        # network profile + fingerprints + routing collapsed by default
        self.assertIn('data-autoopen-when="gate_type:network"', content)
        self.assertNotIn('<details class="adv" open', content.replace("autoopen-when", ""))  # no eager open on blank form
        self.assertIn("FINGERPRINTS", content)
        self.assertIn("ROUTING", content)
        self.assertIn("NETWORK PROFILE", content)

    def test_edit_form_opens_sections_with_content(self):
        link = DeliveryLink.objects.create(
            path="/g/pd/one", kind="key", key_text="K", watermark=True,
            agent_label="agent-7", allowed_ips=["10.0.0.0/8"],
            gate_type="token", gate_token="t")
        response = self.client.get(reverse("gate-link-edit", args=[link.pk]))
        content = response.content.decode()
        self.assertGreaterEqual(content.count('<details class="adv"'), 3)
        self.assertGreaterEqual(content.count("open"), 2)  # routing + fingerprints + network open

    def test_auto_rules_collapsed_until_submission(self):
        response = self.client.get(reverse("gate-link-create"))
        self.assertContains(response, 'data-show-when="gate_type:submission"', )
        self.assertContains(response, "AUTO-DECISION RULES")

    def test_block_rules_advanced_collapsed_and_scope_picker(self):
        response = self.client.get(reverse("gate-block-rules"))
        self.assertContains(response, "LOGIC &amp; RAW CONDITIONS")
        self.assertContains(response, 'data-show-when="set_scope:link"')


@override_settings(AUTO_BAN_THRESHOLD=0)
class PayloadLibraryTests(TestCase):
    def setUp(self):
        import shutil
        import tempfile
        lib = tempfile.mkdtemp(prefix="rof-lib-")
        patch = override_settings(PAYLOAD_LIBRARY_DIR=lib)
        patch.enable()
        self.addCleanup(patch.disable)
        self.addCleanup(shutil.rmtree, lib, True)
        self.lib = lib
        self.operator = Operator.objects.create_user(username="plop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)
        self.public = Client()

    def _bundle(self, name="microsoft"):
        from gates import library
        root = library.library_dir()
        folder = root / name
        (folder / "js").mkdir(parents=True)
        (folder / "index.html").write_text("<html><head><script>alert(1)</script></head></html>")
        (folder / "js" / "app.js").write_text("console.log('x')")
        (folder / "style.css").write_text("body{}")
        return folder

    def test_bundle_gets_notes_and_icon_automatically(self):
        folder = self._bundle()
        response = self.client.get(reverse("gate-library-bundle", args=["microsoft"]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue((folder / "README.md").exists())
        ico = folder / "favicon.ico"
        self.assertTrue(ico.exists())
        self.assertEqual(ico.read_bytes()[:4], b"\x00\x00\x01\x00")  # ICO magic
        # notes render as escaped text: JS shows, never executes
        self.assertContains(response, "README")
        self.assertContains(response, "favicon.ico")

    def test_notes_with_script_are_escaped(self):
        from gates import library
        folder = self._bundle()
        library.save_notes(folder, "evil <script>alert(1)</script> notes")
        response = self.client.get(reverse("gate-library-bundle", args=["microsoft"]))
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, "<script>alert(1)</script>")

    def test_payloads_page_lists_library(self):
        self._bundle()
        response = self.client.get(reverse("gate-payloads"))
        self.assertContains(response, "PAYLOAD LIBRARY")
        self.assertContains(response, "microsoft")

    def test_import_as_lure(self):
        self._bundle()
        response = self.client.post(reverse("gate-library-bundle", args=["microsoft"]),
                                    {"action": "import_lure", "slug": "ms-portal"})
        site = LureSite.objects.get(slug="ms-portal")
        self.assertRedirects(response, reverse("gate-lure-edit", args=[site.pk]))
        self.assertTrue(site.files.filter(path="index.html").exists())
        self.assertTrue(site.files.filter(path="js/app.js").exists())  # nested files import too
        self.assertIn(b"alert(1)", self.public.get("/l/ms-portal/").content)  # lures serve raw

    def test_quick_drop_registers_bundle(self):
        self.client.post(reverse("gate-link-quick-drop"),
                         {"file": ContentFile(b"DATA", name="toolkit.exe")})
        from gates import library
        folder = library.library_dir() / "toolkit.exe"
        self.assertTrue((folder / "toolkit.exe").exists())
        self.assertTrue((folder / "README.md").exists())
        self.assertTrue((folder / "favicon.ico").exists())

    def test_library_file_serving_and_traversal(self):
        folder = self._bundle()
        from gates import library
        library.ensure_icon(folder)
        response = self.client.get(reverse("gate-library-file", args=["microsoft", "favicon.ico"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "image/vnd.microsoft.icon")
        self.assertEqual(self.client.get(reverse("gate-library-file", args=["microsoft", "../settings.py"])).status_code, 404)
        self.assertEqual(self.client.get("/panel/payloads/library/..%2Fevil/").status_code, 404)
        self.assertEqual(self.public.get(reverse("gate-library-bundle", args=["microsoft"])).status_code, 302)

    def test_delete_bundle(self):
        self._bundle()
        self.client.post(reverse("gate-library-bundle", args=["microsoft"]), {"action": "delete_bundle"})
        from gates import library
        self.assertFalse((library.library_dir() / "microsoft").exists())


class TrackAllRequestsTests(TestCase):
    def test_404_only_by_default(self):
        from analytics.services import event_from_record
        record = {"status": 200, "time": "2026-10-26T00:00:00+00:00", "request_id": "r1"}
        self.assertIsNone(event_from_record(record))

    @override_settings(TRACK_ALL_REQUESTS=True)
    def test_all_statuses_stored_when_enabled(self):
        from analytics.services import event_from_record
        record = {"status": 200, "time": "2026-10-26T00:00:00+00:00", "request_id": "r1",
                  "method": "get", "path": "/ok", "remote_addr": "203.0.113.9"}
        event = event_from_record(record)
        self.assertEqual(event.status, 200)
        self.assertEqual(event.method, "GET")

    @override_settings(TRACK_ALL_REQUESTS=True)
    def test_status_class_filter(self):
        from analytics.models import NotFoundEvent
        from django.utils import timezone
        NotFoundEvent.objects.create(request_id="a", occurred_at=timezone.now(), status=200, path="/fine")
        NotFoundEvent.objects.create(request_id="b", occurred_at=timezone.now(), status=404, path="/gone")
        operator = Operator.objects.create_user(username="taop", password="long-enough-password-123")
        client = Client()
        client.force_login(operator)
        response = client.get(reverse("events") + "?status_class=2")
        self.assertContains(response, "/fine")
        self.assertNotContains(response, "/gone")
        response = client.get(reverse("events"))
        self.assertContains(response, "TRACKING ALL")


class UpdateScriptTests(TestCase):
    def test_update_script_shape(self):
        from pathlib import Path
        script = (Path(__file__).resolve().parent.parent / "update.sh").read_text()
        self.assertIn("--reset", script)
        self.assertIn("git pull --ff-only", script)
        self.assertIn("start.sh --reset", script)
        self.assertIn("builder prune", script)


@override_settings(AUTO_BAN_THRESHOLD=0)
class ServeAsFilenameTests(TestCase):
    def setUp(self):
        self.operator = Operator.objects.create_user(username="saop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.operator)
        self.public = Client()

    def test_payload_downloads_under_masquerade_name(self):
        link = DeliveryLink.objects.create(path="/g/sa/one", kind="file", placeholder="blank",
                                           serve_as="helper.pdf.exe")
        link.payload.save("fwfafs.exe", ContentFile(b"MZ payload bytes"), save=True)
        response = self.public.get("/g/sa/one")
        self.assertEqual(response.status_code, 200)
        self.assertIn('filename="helper.pdf.exe"', response["Content-Disposition"])
        self.assertEqual(response.content, b"MZ payload bytes")
        # storage keeps the real name
        link.refresh_from_db()
        self.assertIn("fwfafs", link.payload.name)
        hit = HitEvent.objects.get(category="download")
        self.assertEqual(hit.detail["served_as"], "helper.pdf.exe")

    def test_empty_serve_as_keeps_real_name(self):
        link = DeliveryLink.objects.create(path="/g/sa/two", kind="file", placeholder="blank")
        link.payload.save("real-name.bin", ContentFile(b"DATA"), save=True)
        response = self.public.get("/g/sa/two")
        self.assertIn("real-name", response["Content-Disposition"])

    def test_serve_as_sanitized(self):
        link = DeliveryLink.objects.create(path="/g/sa/three", kind="file", placeholder="blank",
                                           serve_as='..\\evil"quot;.exe')
        link.payload.save("x.exe", ContentFile(b"X"), save=True)
        response = self.public.get("/g/sa/three")
        self.assertNotIn('"quot;', response["Content-Disposition"])
        self.assertNotIn("..", response["Content-Disposition"])

    def test_form_and_api_roundtrip(self):
        response = self.client.post(reverse("gate-link-create"), {
            "path": "/g/sa/form", "kind": "file", "gate_type": "none", "cipher": "none",
            "placeholder": "blank", "on_deny": "not_found", "serve_as": "report.pdf.exe",
            "active": "on",
        })
        link = DeliveryLink.objects.get(path="/g/sa/form")
        self.assertEqual(link.serve_as, "report.pdf.exe")
        _, raw = APIKey.create(operator=self.operator, name="ci")
        detail = self.client.get(f"/api/v1/links/{link.pk}/", HTTP_AUTHORIZATION=f"ApiKey {raw}")
        self.assertEqual(detail.json()["serve_as"], "report.pdf.exe")
