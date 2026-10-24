from datetime import timedelta
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings, tag
from django.utils import timezone
from .models import BootstrapState, Invitation, Operator
from .permissions import is_administrator, is_auditor
from .services import digest_token, ensure_bootstrap, ensure_role_groups


@tag("unit")
class TokenAndStateUnitTests(TestCase):
    def test_token_digest_is_deterministic_and_never_raw(self):
        token = "a-high-entropy-capability"
        digest = digest_token(token)
        self.assertEqual(digest, digest_token(token))
        self.assertEqual(len(digest), 64)
        self.assertNotIn(token, digest)
        self.assertNotEqual(digest, digest_token(token + "x"))

    @override_settings(BOOTSTRAP_TOKEN_TTL_MINUTES=10)
    def test_bootstrap_expiration_boundary(self):
        state = BootstrapState(token_digest="a" * 64)
        state.created_at = timezone.now() - timedelta(minutes=11)
        self.assertTrue(state.expired)
        state.created_at = timezone.now() - timedelta(minutes=9)
        self.assertFalse(state.expired)
        state.claimed_at = timezone.now()
        self.assertFalse(state.expired)

    def test_invitation_availability_covers_every_terminal_state(self):
        invitation = Invitation(username="operator", token_digest="a" * 64, expires_at=timezone.now() + timedelta(hours=1))
        self.assertTrue(invitation.available)
        invitation.expires_at = timezone.now() - timedelta(seconds=1)
        self.assertFalse(invitation.available)
        invitation.expires_at = timezone.now() + timedelta(hours=1)
        invitation.revoked_at = timezone.now()
        self.assertFalse(invitation.available)
        invitation.revoked_at = None
        invitation.consumed_at = timezone.now()
        self.assertFalse(invitation.available)


@tag("unit")
class RoleAndBootstrapUnitTests(TestCase):
    def test_role_group_creation_is_idempotent(self):
        ensure_role_groups()
        ensure_role_groups()
        self.assertEqual(Group.objects.filter(name__in=["Administrator", "Operator", "Auditor"]).count(), 3)

    def test_role_checks_accept_only_expected_groups(self):
        ensure_role_groups()
        user = Operator.objects.create_user(username="ordinary", password="Unit-Test-Password-91!")
        self.assertFalse(is_administrator(user))
        self.assertFalse(is_auditor(user))
        user.groups.add(Group.objects.get(name="Auditor"))
        self.assertFalse(is_administrator(user))
        self.assertTrue(is_auditor(user))
        user.groups.add(Group.objects.get(name="Administrator"))
        self.assertTrue(is_administrator(user))

    def test_superuser_is_administrator(self):
        user = Operator.objects.create_user(username="root", password="Unit-Test-Password-91!", is_superuser=True)
        self.assertTrue(is_administrator(user))
        self.assertTrue(is_auditor(user))

    def test_bootstrap_token_is_returned_only_on_creation(self):
        token = ensure_bootstrap()
        self.assertIsNotNone(token)
        self.assertGreaterEqual(len(token), 40)
        self.assertIsNone(ensure_bootstrap())
        self.assertEqual(BootstrapState.objects.count(), 1)
