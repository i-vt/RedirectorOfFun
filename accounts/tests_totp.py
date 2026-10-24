from django.test import Client, TestCase, tag
from django.urls import reverse

from .models import Operator
from .totp import (
    consume_backup_code, generate_backup_codes, generate_secret, hash_backup_code,
    provisioning_uri, totp, verify,
)

# RFC 6238 test key: ASCII "12345678901234567890"
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


@tag("unit")
class TotpUnitTests(TestCase):
    def test_rfc6238_vector_time_59(self):
        # RFC 6238 Appendix B: T(59) → 94287082 (8 digits); 6-digit tail is 287082
        self.assertEqual(totp(RFC_SECRET, for_time=59, digits=8), "94287082")

    def test_rfc6238_vector_time_1111111109(self):
        self.assertEqual(totp(RFC_SECRET, for_time=1111111109, digits=8), "07081804")

    def test_verify_accepts_generated_code(self):
        secret = generate_secret()
        self.assertTrue(verify(secret, totp(secret)))

    def test_verify_rejects_wrong_and_malformed(self):
        secret = generate_secret()
        self.assertFalse(verify(secret, "000000"))
        self.assertFalse(verify(secret, "abc123"))
        self.assertFalse(verify("", "123456"))
        self.assertFalse(verify(secret, ""))

    def test_provisioning_uri_format(self):
        uri = provisioning_uri(RFC_SECRET, "operator1")
        self.assertTrue(uri.startswith("otpauth://totp/RDR-OPS:operator1?secret="))
        self.assertIn("issuer=RDR-OPS", uri)

    def test_backup_codes_single_use(self):
        operator = Operator.objects.create_user(username="bk", password="long-enough-password-123")
        raw = generate_backup_codes()
        self.assertEqual(len(raw), 8)
        self.assertTrue(all(len(code) == 9 and code[4] == "-" for code in raw))
        operator.backup_code_hashes = [hash_backup_code(c) for c in raw]
        operator.save(update_fields=["backup_code_hashes"])
        code = raw[0]
        self.assertTrue(consume_backup_code(operator, code))
        operator.refresh_from_db()
        self.assertFalse(consume_backup_code(operator, code))
        self.assertFalse(consume_backup_code(operator, "ffff-ffff"))
        self.assertEqual(len(operator.backup_code_hashes), 7)


@tag("functional")
class TwoFactorLoginTests(TestCase):
    def setUp(self):
        self.user = Operator.objects.create_user(username="2faop", password="long-enough-password-123")
        self.user.totp_secret = generate_secret()
        self.user.totp_enabled = True
        raw = generate_backup_codes()
        self.backup_code = raw[0]
        self.user.backup_code_hashes = [hash_backup_code(c) for c in raw]
        self.user.save()
        self.client = Client()

    def login_password_step(self):
        return self.client.post(reverse("login"), {"username": "2faop", "password": "long-enough-password-123"})

    def test_password_step_redirects_to_totp(self):
        response = self.login_password_step()
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login-totp"), response.url)
        self.assertNotIn("session_key", self.client.session)
        self.assertFalse("_auth_user_id" in self.client.session)

    def test_full_login_with_totp_code(self):
        self.login_password_step()
        response = self.client.post(reverse("login-totp"), {"code": totp(self.user.totp_secret)})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))
        overview = self.client.get(reverse("overview"))
        self.assertEqual(overview.status_code, 200)

    def test_wrong_code_rejected(self):
        self.login_password_step()
        response = self.client.post(reverse("login-totp"), {"code": "000000"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse("_auth_user_id" in self.client.session)

    def test_backup_code_works_once(self):
        self.login_password_step()
        response = self.client.post(reverse("login-totp"), {"code": self.backup_code})
        self.assertEqual(response.status_code, 302)
        self.client.post(reverse("logout"))
        # second use of the same backup code must fail
        self.login_password_step()
        response = self.client.post(reverse("login-totp"), {"code": self.backup_code})
        self.assertEqual(response.status_code, 200)
        self.assertFalse("_auth_user_id" in self.client.session)

    def test_totp_page_requires_pending_session(self):
        response = self.client.get(reverse("login-totp"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_user_without_2fa_logs_in_directly(self):
        plain = Operator.objects.create_user(username="plainop", password="long-enough-password-123")
        client = Client()
        response = client.post(reverse("login"), {"username": "plainop", "password": "long-enough-password-123"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(client.session["_auth_user_id"], str(plain.pk))


@tag("functional")
class SecurityViewTests(TestCase):
    def setUp(self):
        self.user = Operator.objects.create_user(username="secop", password="long-enough-password-123")
        self.client = Client()
        self.client.force_login(self.user)

    def test_enroll_confirm_flow(self):
        self.client.post(reverse("security"), {"action": "enroll"})
        pending = self.client.session.get("pending_totp_secret")
        self.assertTrue(pending)
        page = self.client.get(reverse("security"))
        self.assertContains(page, pending)
        response = self.client.post(reverse("security"), {"action": "confirm", "code": totp(pending)})
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.totp_enabled)
        self.assertContains(response, "Save these now")  # backup codes rendered once
        self.assertEqual(len(self.user.backup_code_hashes), 8)

    def test_confirm_with_wrong_code_fails(self):
        self.client.post(reverse("security"), {"action": "enroll"})
        self.client.post(reverse("security"), {"action": "confirm", "code": "000000"})
        self.user.refresh_from_db()
        self.assertFalse(self.user.totp_enabled)

    def test_disable_requires_valid_code(self):
        secret = generate_secret()
        self.user.totp_secret = secret
        self.user.totp_enabled = True
        self.user.save()
        self.client.post(reverse("security"), {"action": "disable", "code": "999999"})
        self.user.refresh_from_db()
        self.assertTrue(self.user.totp_enabled)
        self.client.post(reverse("security"), {"action": "disable", "code": totp(secret)})
        self.user.refresh_from_db()
        self.assertFalse(self.user.totp_enabled)
        self.assertEqual(self.user.totp_secret, "")

    def test_admin_can_reset_2fa(self):
        from accounts.permissions import is_administrator
        admin_group = self.user.groups.create(name="Administrator")
        other = Operator.objects.create_user(username="locked", password="long-enough-password-123")
        other.totp_enabled = True
        other.totp_secret = generate_secret()
        other.save()
        self.assertTrue(is_administrator(self.user))
        response = self.client.post(reverse("operator-reset-2fa", args=[other.pk]))
        self.assertEqual(response.status_code, 302)
        other.refresh_from_db()
        self.assertFalse(other.totp_enabled)
        self.assertEqual(other.totp_secret, "")
