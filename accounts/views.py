import json
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import password_validation
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from .decorators import rate_limit
from .forms import ClaimForm, InvitationAcceptForm, InvitationForm, OperatorAuthenticationForm
from .models import APIKey, BootstrapState, Invitation, Operator
from .permissions import AdministratorRequiredMixin, is_administrator
from .services import BootstrapError, accept_invitation, claim_bootstrap, create_invitation, deactivate_operator, digest_token, revoke_invitation
from .totp import (
    consume_backup_code, generate_backup_codes, generate_secret, hash_backup_code,
    provisioning_uri, verify as totp_verify,
)
from django.contrib.auth import login as auth_login
from django.utils.decorators import method_decorator
from django.views import View


@method_decorator(rate_limit("login", limit=15, window=300), name="dispatch")
class OperatorLoginView(LoginView):
    template_name = "registration/login.html"
    authentication_form = OperatorAuthenticationForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        user = form.get_user()
        if user.totp_enabled:
            # Password accepted; hold the session at the second factor.
            self.request.session.flush()
            self.request.session["pending_totp_user"] = user.pk
            self.request.session["pending_totp_next"] = self.get_redirect_url() or settings.LOGIN_REDIRECT_URL
            return redirect("login-totp")
        response = super().form_valid(form)
        self.request.session["operator_session_version"] = self.request.user.session_version
        return response


@never_cache
@rate_limit("totp", limit=10, window=300)
def totp_login_view(request):
    """Second factor step for operators with TOTP enabled."""
    user_id = request.session.get("pending_totp_user")
    if not user_id:
        return redirect("login")
    user = Operator.objects.filter(pk=user_id, is_active=True, totp_enabled=True).first()
    if user is None:
        request.session.flush()
        return redirect("login")
    error = ""
    if request.method == "POST":
        code = request.POST.get("code", "")
        if totp_verify(user.totp_secret, code) or consume_backup_code(user, code):
            next_url = request.session.get("pending_totp_next") or settings.LOGIN_REDIRECT_URL
            request.session.flush()
            user.backend = "django.contrib.auth.backends.ModelBackend"
            auth_login(request, user)
            request.session["operator_session_version"] = user.session_version
            return redirect(next_url)
        error = "Invalid code. Try again."
    return render(request, "registration/totp.html", {"error": error, "next": request.session.get("pending_totp_next", "")})


@login_required
@never_cache
@rate_limit("security", limit=30, window=300)
def security_view(request):
    """Enroll, confirm, or disable TOTP second-factor authentication."""
    user = request.user
    if request.method == "POST":
        action = request.POST.get("action", "")
        if action == "apikey_create":
            from audit.services import record_event
            api_key, raw = APIKey.create(
                operator=user, name=request.POST.get("name", "").strip()[:120] or "api key",
                created_by=user)
            record_event(action="apikey.created", actor=user, target=api_key, request=request)
            pending = request.session.get("pending_totp_secret", "")
            return render(request, "panel/security.html", {
                "title": "Security", "enabled": user.totp_enabled, "new_key": raw,
                "api_keys": user.api_keys.all(),
                "all_api_keys": APIKey.objects.select_related("operator")[:20] if is_administrator(user) else [],
                "pending_secret": pending,
                "pending_uri": provisioning_uri(pending, user.username) if pending else "",
                "backup_code_count": len(user.backup_code_hashes or []),
            })
        if action == "apikey_revoke":
            from audit.services import record_event
            api_key = get_object_or_404(APIKey, pk=request.POST.get("key_id", ""))
            if api_key.operator != user and not is_administrator(user):
                messages.error(request, "Not allowed.")
                return redirect("security")
            api_key.is_active = False
            api_key.save(update_fields=["is_active"])
            record_event(action="apikey.revoked", actor=user, target=api_key, request=request)
            messages.success(request, f"API key '{api_key.name}' revoked.")
            return redirect("security")
        if action == "enroll":
            secret = generate_secret()
            request.session["pending_totp_secret"] = secret
        elif action == "confirm":
            secret = request.session.get("pending_totp_secret", "")
            code = request.POST.get("code", "")
            if secret and totp_verify(secret, code):
                user.totp_secret = secret
                user.totp_enabled = True
                raw_codes = generate_backup_codes()
                user.backup_code_hashes = [hash_backup_code(c) for c in raw_codes]
                user.save(update_fields=["totp_secret", "totp_enabled", "backup_code_hashes"])
                request.session.pop("pending_totp_secret", None)
                messages.success(request, "Two-factor authentication enabled.")
                return render(request, "panel/security.html", {
                    "title": "Security", "enabled": True, "just_enabled": True,
                    "backup_codes": raw_codes, "recovery_note": True,
                })
            messages.error(request, "Code did not match. Enrollment not activated.")
        elif action == "disable":
            code = request.POST.get("code", "")
            if totp_verify(user.totp_secret, code) or consume_backup_code(user, code):
                user.totp_enabled = False
                user.totp_secret = ""
                user.backup_code_hashes = []
                user.save(update_fields=["totp_enabled", "totp_secret", "backup_code_hashes"])
                user.session_version += 1
                user.save(update_fields=["session_version"])
                messages.success(request, "Two-factor authentication disabled. Existing sessions were invalidated.")
            else:
                messages.error(request, "A valid current code or backup code is required to disable 2FA.")
        return redirect("security")
    pending_secret = request.session.get("pending_totp_secret", "")
    return render(request, "panel/security.html", {
        "title": "Security", "enabled": user.totp_enabled,
        "pending_secret": pending_secret,
        "pending_uri": provisioning_uri(pending_secret, user.username) if pending_secret else "",
        "backup_code_count": len(user.backup_code_hashes or []),
        "api_keys": user.api_keys.all(),
        "all_api_keys": APIKey.objects.select_related("operator")[:20] if is_administrator(user) else [],
    })


@login_required
@never_cache
def reset_operator_2fa(request, pk):
    """Administrator lockout recovery: clear another operator's 2FA."""
    if not is_administrator(request.user):
        return render(request, "403.html", status=403)
    target = get_object_or_404(Operator, pk=pk)
    if request.method == "POST":
        from .services import reset_operator_2fa as reset_2fa_service
        reset_2fa_service(actor=request.user, target=target, request=request)
        messages.success(request, f"2FA reset for {target.username}; their sessions were invalidated.")
    return redirect("operators")


def _no_store(response):
    response["Cache-Control"] = "no-store"
    response["Referrer-Policy"] = "no-referrer"
    return response


@never_cache
@csrf_exempt
@rate_limit("bootstrap", limit=20, window=300)
def bootstrap_view(request, token):
    """One-time, session-independent capability claim for browsers and automation."""
    valid_state = BootstrapState.objects.filter(
        slot=1, token_digest=digest_token(token), claimed_at__isnull=True, disabled=False,
    ).first()
    if not valid_state or valid_state.expired or Operator.objects.filter(is_superuser=True, is_active=True).exists():
        return _no_store(render(request, "accounts/bootstrap_closed.html", status=410))

    if request.method == "GET":
        return _no_store(render(request, "accounts/bootstrap.html", {"form": ClaimForm(), "token": token}))

    if request.content_type == "application/json":
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _no_store(JsonResponse({"detail": "Invalid JSON body."}, status=400))
        form = ClaimForm({
            "username": payload.get("username", "admin"),
            "password": payload.get("password", ""),
            "password_confirm": payload.get("password_confirm", payload.get("password", "")),
        })
    else:
        form = ClaimForm(request.POST)
    if not form.is_valid():
        if request.content_type == "application/json":
            return _no_store(JsonResponse({"errors": form.errors.get_json_data()}, status=400))
        return _no_store(render(request, "accounts/bootstrap.html", {"form": form, "token": token}, status=400))
    try:
        operator = claim_bootstrap(token, form.cleaned_data["username"], form.cleaned_data["password"], request)
    except BootstrapError as exc:
        if request.content_type == "application/json":
            return _no_store(JsonResponse({"detail": str(exc)}, status=410))
        return _no_store(render(request, "accounts/bootstrap_closed.html", {"message": str(exc)}, status=410))
    if request.content_type == "application/json":
        return _no_store(JsonResponse({"detail": "Administrator created. Bootstrap is now closed.", "username": operator.username}, status=201))
    messages.success(request, "Administrator created. Sign in to continue.")
    return _no_store(redirect("login"))


@login_required
def operators_view(request):
    if not is_administrator(request.user):
        return render(request, "403.html", status=403)
    form = InvitationForm(request.POST or None)
    invitation_url = None
    if request.method == "POST" and form.is_valid():
        invitation, raw_token = create_invitation(
            invited_by=request.user, request=request, **form.cleaned_data,
        )
        invitation_url = settings.BOOTSTRAP_BASE_URL + reverse("invitation-accept", args=[raw_token])
        form = InvitationForm()
    operators = Operator.objects.prefetch_related("groups").all()
    invitations = Invitation.objects.filter(consumed_at__isnull=True, revoked_at__isnull=True).order_by("-created_at")[:10]
    return render(request, "panel/operators.html", {
        "title": "Operators", "form": form, "operators": operators,
        "invitations": invitations, "invitation_url": invitation_url,
        "roles": [r for r, _ in Invitation.ROLE_CHOICES],
    })


@login_required
def operator_role_view(request, pk):
    """Change an operator's role (admin only)."""
    if not is_administrator(request.user):
        return render(request, "403.html", status=403)
    target = get_object_or_404(Operator, pk=pk)
    if request.method == "POST":
        role = request.POST.get("role", "")
        from accounts.models import Invitation
        valid = dict(Invitation.ROLE_CHOICES)
        if role in valid and target.pk != request.user.pk:
            from django.contrib.auth.models import Group
            from .services import ensure_role_groups
            ensure_role_groups()
            target.groups.set([Group.objects.get(name=role)])
            from audit.services import record_event
            record_event(action="operator.role_changed", actor=request.user, target=target,
                         metadata={"role": role}, request=request)
            from django.contrib import messages
            messages.success(request, f"{target.username} is now {role}.")
    return redirect("operators")


@login_required
def revoke_operator_view(request, pk):
    if not is_administrator(request.user):
        return render(request, "403.html", status=403)
    target = get_object_or_404(Operator, pk=pk)
    if request.method == "POST":
        try:
            deactivate_operator(actor=request.user, target=target, request=request)
            messages.success(request, f"{target.username} was deactivated.")
        except ValueError as exc:
            messages.error(request, str(exc))
    return redirect("operators")


@login_required
def revoke_invitation_view(request, pk):
    if not is_administrator(request.user):
        return render(request, "403.html", status=403)
    invitation = get_object_or_404(Invitation, pk=pk)
    if request.method == "POST":
        try:
            revoke_invitation(actor=request.user, invitation=invitation, request=request)
            messages.success(request, f"Invitation for {invitation.username} was revoked.")
        except ValueError as exc:
            messages.error(request, str(exc))
    return redirect("operators")


@never_cache
def invitation_accept_view(request, token):
    invitation = Invitation.objects.filter(token_digest=digest_token(token)).first()
    if not invitation or not invitation.available:
        return _no_store(render(request, "accounts/bootstrap_closed.html", {
            "title": "Invitation unavailable", "message": "This invitation is invalid, expired, revoked, or already used.",
        }, status=410))
    form = InvitationAcceptForm(request.POST or None, initial={"username": invitation.username})
    if request.method == "POST" and form.is_valid():
        try:
            accept_invitation(token, form.cleaned_data["password"], request)
        except (BootstrapError, ValidationError) as exc:
            form.add_error(None, str(exc))
        else:
            messages.success(request, "Your operator account is ready. Sign in to continue.")
            return redirect("login")
    return _no_store(render(request, "accounts/invitation.html", {"form": form, "invitation": invitation, "token": token}))
