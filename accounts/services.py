import hashlib
import secrets
from datetime import timedelta
from django.conf import settings
from django.contrib.auth.models import Group
from django.db import transaction
from django.utils import timezone
from audit.services import record_event
from notifications.services import ensure_default_preferences, notify
from .models import BootstrapState, Invitation, Operator

ROLE_NAMES = ("Administrator", "Operator", "Auditor")


def digest_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ensure_role_groups():
    return [Group.objects.get_or_create(name=name)[0] for name in ROLE_NAMES]


def ensure_bootstrap():
    """Return a raw token only when a new bootstrap capability is generated."""
    ensure_role_groups()
    state = BootstrapState.objects.filter(slot=1).first()
    if state or Operator.objects.filter(is_superuser=True, is_active=True).exists():
        return None
    raw_token = secrets.token_urlsafe(32)
    BootstrapState.objects.create(slot=1, token_digest=digest_token(raw_token))
    return raw_token


class BootstrapError(Exception):
    pass


@transaction.atomic
def claim_bootstrap(raw_token, username, password, request=None):
    state = BootstrapState.objects.select_for_update().filter(
        slot=1, token_digest=digest_token(raw_token), claimed_at__isnull=True, disabled=False,
    ).first()
    if not state or state.expired or Operator.objects.filter(is_superuser=True, is_active=True).exists():
        raise BootstrapError("This setup link is invalid or has already been claimed.")
    operator = Operator.objects.create_user(
        username=username, password=password, is_staff=True, is_superuser=True,
    )
    operator.groups.add(Group.objects.get(name="Administrator"))
    state.claimed_at = timezone.now()
    state.claimed_by = operator
    state.save(update_fields=["claimed_at", "claimed_by"])
    ensure_default_preferences(operator)
    record_event(action="bootstrap.completed", actor=operator, target=operator, request=request)
    notify("security", {"title": "Initial administrator created", "detail": f"Bootstrap completed for {operator.username}."})
    return operator


@transaction.atomic
def create_invitation(*, invited_by, username, email, role, request=None):
    ensure_role_groups()
    raw_token = secrets.token_urlsafe(32)
    invitation = Invitation.objects.create(
        username=username, email=email, role=role,
        token_digest=digest_token(raw_token), invited_by=invited_by,
        expires_at=timezone.now() + timedelta(hours=settings.INVITATION_TTL_HOURS),
    )
    record_event(action="operator.invited", actor=invited_by, target=invitation,
                 metadata={"username": username, "role": role}, request=request)
    notify("operators", {"title": "Operator invited", "detail": f"{username} was invited as {role}."})
    return invitation, raw_token


@transaction.atomic
def accept_invitation(raw_token, password, request=None):
    invitation = Invitation.objects.select_for_update().filter(token_digest=digest_token(raw_token)).first()
    if not invitation or not invitation.available:
        raise BootstrapError("This invitation is invalid, expired, revoked, or already used.")
    if Operator.objects.filter(username__iexact=invitation.username).exists():
        raise BootstrapError("An operator with this username already exists.")
    operator = Operator.objects.create_user(
        username=invitation.username, email=invitation.email, password=password,
        is_staff=invitation.role == "Administrator",
        is_superuser=False,
    )
    operator.groups.add(Group.objects.get(name=invitation.role))
    invitation.consumed_at = timezone.now()
    invitation.save(update_fields=["consumed_at"])
    ensure_default_preferences(operator)
    record_event(action="operator.invitation_accepted", actor=operator, target=operator,
                 metadata={"role": invitation.role}, request=request)
    notify("security", {"title": "Invitation accepted", "detail": f"{operator.username} joined the control plane."})
    return operator


@transaction.atomic
def revoke_invitation(*, actor, invitation, request=None):
    invitation = Invitation.objects.select_for_update().get(pk=invitation.pk)
    if invitation.consumed_at or invitation.revoked_at or invitation.expires_at <= timezone.now():
        raise ValueError("This invitation is no longer active.")
    invitation.revoked_at = timezone.now()
    invitation.save(update_fields=["revoked_at"])
    record_event(action="operator.invitation_revoked", actor=actor, target=invitation,
                 metadata={"username": invitation.username}, request=request)
    notify("operators", {"title": "Invitation revoked", "detail": f"Invitation for {invitation.username} was revoked."})
    return invitation


@transaction.atomic
def reset_operator_2fa(*, actor, target, request=None):
    """Administrator lockout recovery: clear another operator's 2FA."""
    target.totp_enabled = False
    target.totp_secret = ""
    target.backup_code_hashes = []
    target.session_version += 1
    target.save(update_fields=["totp_enabled", "totp_secret", "backup_code_hashes", "session_version"])
    record_event(action="operator.2fa_reset", actor=actor, target=target, request=request)
    return target


@transaction.atomic
def deactivate_operator(*, actor, target, request=None):
    target = Operator.objects.select_for_update().get(pk=target.pk)
    if actor.pk == target.pk:
        raise ValueError("You cannot deactivate your own account.")
    if target.is_superuser and Operator.objects.filter(is_superuser=True, is_active=True).count() <= 1:
        raise ValueError("The last active administrator cannot be deactivated.")
    if not target.is_active:
        raise ValueError("This operator is already deactivated.")
    target.is_active = False
    target.session_version += 1
    target.save(update_fields=["is_active", "session_version"])
    record_event(action="operator.deactivated", actor=actor, target=target,
                 metadata={"username": target.username}, request=request)
    notify("operators", {"title": "Operator deactivated", "detail": f"Access revoked for {target.username}."})
    return target
