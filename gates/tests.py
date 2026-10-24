import base64
import hashlib
import json
import os
import time
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
    IPIntel, RuleSet, Submission, SubmissionImage, seed_blocking_rule_presets,
    seed_builtin_decoys, validate_auto_rules,
)
from .selftest import is_healthy, run_selftest
from . import services, telegram


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
        response = self.client.get("/g/does/not/exist")
        self.assertEqual(response.status_code, 404)
        self.assertTrue(HitEvent.objects.filter(category="not_found").exists())

    def test_anonymous_untracked_path_gets_decoy(self):
        response = self.client.get("/definitely-not-real")
        self.assertEqual(response.status_code, 404)
        self.assertContains(response, "Update Service", status_code=404)
        self.assertContains(response, "/g/canary/", status_code=404)

    def test_operator_untracked_path_gets_panel_404(self):
        operator = Operator.objects.create_user(username="op404", password="long-enough-password-123")
        self.client.force_login(operator)
        response = self.client.get("/definitely-not-real")
        self.assertEqual(response.status_code, 404)
        self.assertNotContains(response, "Update Service", status_code=404)
        self.assertContains(response, "RDR", status_code=404)

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
        self.assertEqual(response.status_code, 404)  # no link; falls to stock 404
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
        self.assertContains(response, "Update Service", status_code=404)

    def test_operator_can_switch_default_to_repo_page(self):
        crestfield = DecoyPage.objects.get(template_key="crestfield")
        self.client.post(reverse("gate-decoy-default", args=[crestfield.pk]))
        response = self.public.get("/no-such-page")
        self.assertContains(response, "CrestDesk", status_code=404)
        self.assertNotContains(response, "All systems operational", status_code=404)
        self.assertContains(response, "/g/canary/", status_code=404)
        # nysm-landing is also selectable and distinct from the update-service page title
        landing = DecoyPage.objects.get(template_key="nysm-landing")
        self.client.post(reverse("gate-decoy-default", args=[landing.pk]))
        response = self.public.get("/no-such-page")
        self.assertContains(response, "Service Portal", status_code=404)

    def test_uploaded_html_page_with_canary_injection(self):
        html = b"<html><body><h1>Customer Portal</h1></body></html>"
        page = DecoyPage.objects.create(kind="upload", name="portal", is_default=True)
        DecoyPage.objects.exclude(pk=page.pk).update(is_default=False)
        page.html_file.save("portal.html", ContentFile(html), save=True)
        response = self.public.get("/no-such-page")
        self.assertContains(response, "Customer Portal", status_code=404)
        self.assertContains(response, "/g/canary/", status_code=404)

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
        self.assertContains(response, "/g/canary/", status_code=404)

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
        self.assertContains(response, "Update Service", status_code=404)  # plain 404 decoy
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
            self.assertEqual(response.status_code, 404, path)
        # and unknown paths present the decoy to anonymous visitors
        response = self.client.get("/panel/")
        self.assertContains(response, "Update Service", status_code=404)

    def test_outside_prefix_is_decoy_even_for_authenticated_operators(self):
        from accounts.models import Operator
        operator = Operator.objects.create_user(username="prefop", password="long-enough-password-123")
        self.client.force_login(operator)
        for path in ("/api", "/api/v1/links/", "/panel/", "/login/"):
            response = self.client.get(path)
            self.assertContains(response, "Update Service", status_code=404, msg_prefix=path)
        # inside the prefix, operators still get the helpful panel 404
        response = self.client.get("/testprefix/panel/no-such-page/")
        self.assertContains(response, "Nothing lives at this address", status_code=404)
        self.assertNotContains(response, "Update Service", status_code=404)







