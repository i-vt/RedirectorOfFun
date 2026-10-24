import json
import secrets
from io import StringIO
from django.contrib.auth.models import Group
from django.core.management import call_command, CommandError
from django.test import TestCase, tag, override_settings
from django.urls import reverse
from django.utils import timezone
from audit.models import AuditEvent
from .models import BootstrapState, Invitation, Operator
from .services import (
    accept_invitation, claim_bootstrap, create_invitation, deactivate_operator,
    digest_token, ensure_bootstrap, ensure_role_groups,
)

PASSWORD = "Correct-Horse-Red-Planet-91!"


@tag("functional")
class BootstrapTests(TestCase):
    def setUp(self):
        ensure_role_groups()
        self.token = ensure_bootstrap()
        self.url = reverse("bootstrap", args=[self.token])

    def test_get_does_not_claim_bootstrap(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Operator.objects.count(), 0)
        self.assertIsNone(BootstrapState.objects.get(slot=1).claimed_at)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["Referrer-Policy"], "no-referrer")

    def test_json_claim_creates_one_admin_and_retires_url(self):
        response = self.client.post(self.url, data=json.dumps({
            "username": "admin", "password": PASSWORD, "password_confirm": PASSWORD,
        }), content_type="application/json")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Operator.objects.filter(is_superuser=True).count(), 1)
        self.assertTrue(AuditEvent.objects.filter(action="bootstrap.completed").exists())
        replay = self.client.get(self.url)
        self.assertEqual(replay.status_code, 410)
        second = self.client.post(self.url, data=json.dumps({
            "username": "other", "password": PASSWORD,
        }), content_type="application/json")
        self.assertEqual(second.status_code, 410)
        self.assertEqual(Operator.objects.count(), 1)

    def test_password_is_validated(self):
        response = self.client.post(self.url, data=json.dumps({
            "username": "admin", "password": "short", "password_confirm": "short",
        }), content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Operator.objects.count(), 0)
        self.assertIsNone(BootstrapState.objects.get(slot=1).claimed_at)

    @override_settings(BOOTSTRAP_TOKEN_TTL_MINUTES=1)
    def test_expired_token_cannot_claim(self):
        state = BootstrapState.objects.get(slot=1)
        state.created_at = timezone.now() - timezone.timedelta(minutes=2)
        state.save(update_fields=["created_at"])
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 410)
        self.assertEqual(Operator.objects.count(), 0)

    def test_reset_replaces_only_unclaimed_bootstrap(self):
        output = StringIO()
        call_command("reset_bootstrap", stdout=output)
        replacement = output.getvalue().strip().split("/setup/")[1].strip("/")
        self.assertNotEqual(replacement, self.token)
        self.assertEqual(self.client.get(self.url).status_code, 410)
        self.assertEqual(self.client.get(reverse("bootstrap", args=[replacement])).status_code, 200)

    def test_invalid_token_cannot_claim(self):
        response = self.client.post(reverse("bootstrap", args=["invalid"]), data=json.dumps({
            "username": "admin", "password": PASSWORD,
        }), content_type="application/json")
        self.assertEqual(response.status_code, 410)
        self.assertEqual(Operator.objects.count(), 0)


@tag("functional")
class OperatorLifecycleTests(TestCase):
    def setUp(self):
        ensure_role_groups()
        self.admin = Operator.objects.create_user(username="admin", password=PASSWORD, is_superuser=True, is_staff=True)
        self.admin.groups.add(Group.objects.get(name="Administrator"))
        self.client.force_login(self.admin)
        self.client.session["operator_session_version"] = self.admin.session_version

    def test_invitation_is_single_use_and_never_superuser(self):
        invitation, token = create_invitation(
            invited_by=self.admin, username="operator", email="", role="Operator",
        )
        self.assertNotEqual(invitation.token_digest, token)
        operator = accept_invitation(token, PASSWORD)
        self.assertFalse(operator.is_superuser)
        self.assertTrue(operator.groups.filter(name="Operator").exists())
        with self.assertRaisesMessage(Exception, "invalid, expired, revoked, or already used"):
            accept_invitation(token, PASSWORD)

    def test_browser_invitation_flow(self):
        _, token = create_invitation(invited_by=self.admin, username="browserop", email="", role="Auditor")
        self.client.logout()
        response = self.client.get(reverse("invitation-accept", args=[token]))
        self.assertContains(response, "Activate browserop")
        response = self.client.post(reverse("invitation-accept", args=[token]), {
            "username": "browserop", "password": PASSWORD, "password_confirm": PASSWORD,
        })
        self.assertRedirects(response, reverse("login"))
        self.assertTrue(Operator.objects.filter(username="browserop").exists())

    def test_deactivation_revokes_existing_session(self):
        operator = Operator.objects.create_user(username="revoked", password=PASSWORD)
        other = self.client.session
        deactivate_operator(actor=self.admin, target=operator)
        operator.refresh_from_db()
        self.assertFalse(operator.is_active)
        self.assertEqual(operator.session_version, 2)
        self.assertTrue(AuditEvent.objects.filter(action="operator.deactivated").exists())

    def test_session_version_mismatch_logs_out(self):
        operator = Operator.objects.create_user(username="sessiontest", password=PASSWORD)
        operator.groups.add(Group.objects.get(name="Operator"))
        session = self.client.session
        session["operator_session_version"] = operator.session_version
        session.save()
        self.client.force_login(operator)
        session = self.client.session
        session["operator_session_version"] = operator.session_version
        session.save()
        operator.session_version += 1
        operator.save()
        response = self.client.get(reverse("overview"))
        self.assertRedirects(response, reverse("login"))

    def test_cannot_deactivate_last_admin_or_self(self):
        with self.assertRaisesMessage(ValueError, "your own account"):
            deactivate_operator(actor=self.admin, target=self.admin)
        with self.assertRaises(CommandError):
            call_command("reset_bootstrap")

    def test_revoked_invitation_cannot_be_accepted(self):
        from .services import revoke_invitation
        invitation, token = create_invitation(invited_by=self.admin, username="revokedinvite", email="", role="Operator")
        response = self.client.post(reverse("invitation-revoke", args=[invitation.pk]))
        self.assertRedirects(response, reverse("operators"))
        invitation.refresh_from_db()
        self.assertIsNotNone(invitation.revoked_at)
        with self.assertRaisesMessage(Exception, "invalid, expired, revoked, or already used"):
            accept_invitation(token, PASSWORD)

    def test_non_admin_cannot_open_operator_administration(self):
        operator = Operator.objects.create_user(username="ordinary", password=PASSWORD)
        self.client.force_login(operator)
        response = self.client.get(reverse("operators"))
        self.assertEqual(response.status_code, 403)
