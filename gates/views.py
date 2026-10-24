import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.http import FileResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from accounts.permissions import is_administrator
from audit.services import record_event
from notifications.services import notify

from .models import (
    AgentChannel, BannedIP, BUILTIN_DECOYS, DecoyPage, DeliveryLink, HitEvent,
    Submission, SubmissionImage, validate_auto_rules,
)
from .link_templates import LINK_TEMPLATES
from . import services


@login_required
def links_view(request):
    links = DeliveryLink.objects.all()
    label = request.GET.get("label", "").strip()
    kind = request.GET.get("kind", "").strip()
    if label:
        links = links.filter(label__icontains=label[:120])
    if kind in {"key", "file", "proxy"}:
        links = links.filter(kind=kind)
    paginator = Paginator(links, 30)
    page = paginator.get_page(request.GET.get("page"))
    template = "panel/_links_table.html" if request.headers.get("HX-Request") else "panel/links.html"
    return render(request, template, {
        "title": "Delivery Links", "page": page, "links": page.object_list,
        "pending_count": DeliveryLink.objects.filter(requires_approval=True, approval_status="pending").count(),
    })


@login_required
@transaction.atomic
def link_create(request):
    if request.method == "POST":
        link = DeliveryLink(created_by=request.user)
        try:
            _link_from_post(request, link)
            link.full_clean()
        except ValidationError as exc:
            messages.error(request, "; ".join(
                f"{field}: {', '.join(errors)}" for field, errors in exc.message_dict.items()))
            return _render_link_form(request, link, "New Delivery Link")
        link.save()
        record_event(action="gate.link_created", actor=request.user, target=link, request=request)
        messages.success(request, f"Link {link.path} created.")
        return redirect("gate-link-detail", pk=link.pk)
    link = DeliveryLink()
    template_name = request.GET.get("template", "").strip()
    template = LINK_TEMPLATES.get(template_name)
    if template:
        for field, value in template["defaults"].items():
            setattr(link, field, value)
        messages.info(request, f"Template '{template['label']}' loaded - replace the {{placeholder}} values.")
    return _render_link_form(request, link, "New Delivery Link")


def _render_link_form(request, link, title):
    from django.conf import settings
    return render(request, "panel/link_form.html", {
        "title": title, "link": link, "kinds": DeliveryLink.KIND_CHOICES,
        "gates": DeliveryLink.GATE_CHOICES, "ciphers": DeliveryLink.CIPHER_CHOICES,
        "placeholders": DeliveryLink.PLACEHOLDER_CHOICES, "denies": DeliveryLink.DENY_CHOICES,
        "base_path": _base_path(),
        "expected_fields_csv": ", ".join(link.expected_fields or []),
        "domains": getattr(settings, "REDIRECTOR_DOMAINS", []),
        "templates": LINK_TEMPLATES,
    })


def _base_path():
    from django.conf import settings
    return getattr(settings, "GATE_BASE_PATH", "/g/")


def _split_csv(value):
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _link_from_post(request, link):
    link.path = request.POST.get("path", "").strip()
    link.kind = request.POST.get("kind", "key")
    link.label = request.POST.get("label", "").strip()[:120]
    link.agent_label = request.POST.get("agent_label", "").strip()[:120]
    link.key_text = request.POST.get("key_text", "")
    link.pwndrop_url = request.POST.get("pwndrop_url", "").strip()
    if request.FILES.get("payload"):
        link.payload = request.FILES["payload"]
    if request.FILES.get("benevolent_file"):
        link.benevolent_file = request.FILES["benevolent_file"]
    link.benevolent_text = request.POST.get("benevolent_text", "")
    link.gate_type = request.POST.get("gate_type", "none")
    link.gate_token = request.POST.get("gate_token", "").strip()
    link.totp_secret = request.POST.get("totp_secret", "").strip()
    window = request.POST.get("totp_window", "30").strip()
    link.totp_window = int(window) if window.isdigit() else 30
    link.cipher = request.POST.get("cipher", "none")
    link.cipher_key = request.POST.get("cipher_key", "").strip()
    link.cipher_iv = request.POST.get("cipher_iv", "").strip()
    link.expected_fields = _split_csv(request.POST.get("expected_fields", ""))
    raw_rules = request.POST.get("auto_rules", "").strip()
    if raw_rules:
        try:
            link.auto_rules = json.loads(raw_rules)
        except json.JSONDecodeError as exc:
            raise ValidationError({"auto_rules": [f"invalid JSON: {exc}"]})
        try:
            validate_auto_rules(link.auto_rules)
        except ValidationError as exc:
            raise ValidationError({"auto_rules": exc.messages})
    link.placeholder = request.POST.get("placeholder", "blank")
    link.on_deny = request.POST.get("on_deny", "not_found")
    link.requires_approval = request.POST.get("requires_approval") == "on"
    link.domain = request.POST.get("domain", "").strip()[:253]
    link.ja3_fingerprint = request.POST.get("ja3_fingerprint", "").strip()[:64]
    link.ja4_fingerprint = request.POST.get("ja4_fingerprint", "").strip()[:64]
    link.watermark = request.POST.get("watermark") == "on"
    link.one_time = request.POST.get("one_time") == "on"
    max_uses = request.POST.get("max_uses", "0").strip()
    link.max_uses = int(max_uses) if max_uses.isdigit() else 0
    expires = request.POST.get("expires_at", "").strip()
    link.expires_at = None
    if expires:
        from django.utils.dateparse import parse_datetime
        parsed = parse_datetime(expires)
        link.expires_at = parsed if parsed else None
    link.active = request.POST.get("active", "on") == "on"
    return link


@login_required
def link_detail(request, pk):
    link = get_object_or_404(DeliveryLink, pk=pk)
    submissions = link.submissions.select_related("decided_by")[:20]
    return render(request, "panel/link_detail.html", {
        "title": f"Link {link.path}", "link": link, "submissions": submissions,
        "hits": link.hit_events.all()[:30], "is_administrator": is_administrator(request.user),
        "undo_seconds": services_undo_window(),
    })


@login_required
@transaction.atomic
def link_update(request, pk):
    link = get_object_or_404(DeliveryLink, pk=pk)
    if request.method == "POST":
        try:
            _link_from_post(request, link)
            link.full_clean()
        except ValidationError as exc:
            messages.error(request, "; ".join(
                f"{field}: {', '.join(errors)}" for field, errors in exc.message_dict.items()))
            return _render_link_form(request, link, f"Edit {link.path}")
        link.save()
        record_event(action="gate.link_updated", actor=request.user, target=link, request=request)
        messages.success(request, f"Link {link.path} updated.")
        return redirect("gate-link-detail", pk=link.pk)
    return _render_link_form(request, link, f"Edit {link.path}")


@login_required
@transaction.atomic
def link_toggle(request, pk):
    link = get_object_or_404(DeliveryLink, pk=pk)
    if request.method == "POST":
        link.active = not link.active
        link.save(update_fields=["active"])
        record_event(action="gate.link_toggled", actor=request.user, target=link,
                     metadata={"active": link.active}, request=request)
    return redirect("gate-link-detail", pk=link.pk)


@login_required
@transaction.atomic
def link_burn(request, pk):
    link = get_object_or_404(DeliveryLink, pk=pk)
    if request.method == "POST":
        banned, _ = services.burn_link(link, actor=request.user, request=request)
        messages.warning(request, f"Link burned. {banned} visitor IP(s) banned.")
    return redirect("gate-link-detail", pk=link.pk)


@login_required
@transaction.atomic
def submission_decide(request, pk, verdict):
    if request.method != "POST" or verdict not in {"approve", "deny"}:
        return redirect("gate-submissions")
    submission = get_object_or_404(Submission.objects.select_related("link"), pk=pk)
    decided = services.decide_submission(submission, verdict, actor=request.user,
                                         via="panel", request=request)
    if decided is None:
        messages.info(request, f"Submission #{submission.pk} was already decided.")
    return redirect(request.META.get("HTTP_REFERER", "gate-submissions"))


@login_required
def submissions_view(request):
    status = request.GET.get("status", "pending").strip()
    submissions = Submission.objects.select_related("link", "decided_by")
    if status in {"pending", "approved", "denied"}:
        submissions = submissions.filter(status=status)
    paginator = Paginator(submissions, 25)
    page = paginator.get_page(request.GET.get("page"))
    template = "panel/_submissions_table.html" if request.headers.get("HX-Request") else "panel/submissions.html"
    return render(request, template, {
        "title": "Approval Queue", "page": page, "submissions": page.object_list,
        "status": status,
        "pending_count": Submission.objects.filter(status="pending").count(),
        "undo_seconds": services_undo_window(),
    })


def services_undo_window():
    from django.conf import settings
    return getattr(settings, "DECISION_UNDO_SECONDS", 10)


@login_required
@transaction.atomic
def submission_note(request, pk):
    submission = get_object_or_404(Submission, pk=pk)
    if request.method == "POST":
        note = request.POST.get("note", "")[:4000]
        submission.note = note
        submission.note_by = request.user if note else None
        submission.note_at = timezone.now() if note else None
        submission.save(update_fields=["note", "note_by", "note_at"])
        record_event(action="gate.submission_noted", actor=request.user, target=submission, request=request)
        messages.success(request, f"Note saved on submission #{submission.pk}.")
    return redirect(request.META.get("HTTP_REFERER", "gate-submissions"))


@login_required
@transaction.atomic
def submission_undo(request, pk):
    submission = get_object_or_404(Submission.objects.select_related("link"), pk=pk)
    if request.method == "POST":
        ok, error = services.undo_decision(submission, request.user)
        if ok:
            record_event(action="gate.submission_undone", actor=request.user, target=submission, request=request)
            messages.success(request, f"Decision on submission #{submission.pk} undone.")
        else:
            messages.error(request, error)
    return redirect(request.META.get("HTTP_REFERER", "gate-submissions"))


@login_required
def submission_image(request, pk):
    image = get_object_or_404(SubmissionImage.objects.select_related("submission__link"), pk=pk)
    if not image.image:
        return HttpResponseForbidden("Image not stored.")
    return FileResponse(image.image.open("rb"), content_type=image.content_type)


@login_required
@transaction.atomic
def bans_view(request):
    if request.method == "POST":
        ip = request.POST.get("ip", "").strip()
        note = request.POST.get("note", "").strip()[:240]
        if services.valid_ip(ip):
            ban, created = BannedIP.objects.get_or_create(
                ip=ip, defaults={"note": note, "created_by": request.user})
            if not created:
                ban.active, ban.note = True, note or ban.note
                ban.save(update_fields=["active", "note"])
            services.sync_nginx_files()
            record_event(action="gate.ip_banned", actor=request.user, target=ban, request=request)
            notify("suspicious", {"title": "IP banned", "detail": f"{ip}: {note or 'no note'}"})
            messages.success(request, f"{ip} banned.")
        else:
            messages.error(request, f"'{ip}' is not a valid IP address.")
        return redirect("gate-bans")
    bans = BannedIP.objects.all()
    paginator = Paginator(bans, 30)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "panel/bans.html", {"title": "Banned IPs", "page": page, "bans": page.object_list})


@login_required
@transaction.atomic
def ban_toggle(request, pk):
    ban = get_object_or_404(BannedIP, pk=pk)
    if request.method == "POST":
        ban.active = not ban.active
        ban.save(update_fields=["active"])
        services.sync_nginx_files()
        record_event(action="gate.ip_ban_toggled", actor=request.user, target=ban,
                     metadata={"active": ban.active}, request=request)
    return redirect("gate-bans")


@login_required
@transaction.atomic
def agents_view(request):
    if request.method == "POST":
        agent = AgentChannel.objects.create(
            label=request.POST.get("label", "").strip()[:120] or "unnamed agent",
            ua_pattern=request.POST.get("ua_pattern", "").strip()[:240],
            note=request.POST.get("note", "").strip()[:240],
            created_by=request.user,
        )
        written = services.sync_nginx_files()
        record_event(action="gate.agent_created", actor=request.user, target=agent, request=request)
        messages.success(request, f"Agent URL {agent.path} created. nginx sync: {len(written)} file(s) written.")
        return redirect("gate-agents")
    return render(request, "panel/agents.html", {
        "title": "Agent Channels", "agents": AgentChannel.objects.all(),
        "base_path": _agent_base(),
    })


def _agent_base():
    from django.conf import settings
    return getattr(settings, "AGENT_BASE_PATH", "/a/")


@login_required
@transaction.atomic
def agent_toggle(request, pk):
    agent = get_object_or_404(AgentChannel, pk=pk)
    if request.method == "POST":
        agent.active = not agent.active
        agent.save(update_fields=["active"])
        written = services.sync_nginx_files()
        record_event(action="gate.agent_toggled", actor=request.user, target=agent,
                     metadata={"active": agent.active, "nginx_synced": list(written)}, request=request)
    return redirect("gate-agents")


@login_required
@transaction.atomic
def agent_rotate(request, pk):
    agent = get_object_or_404(AgentChannel, pk=pk)
    if request.method == "POST":
        from .models import agent_token
        old = agent.path
        agent.token = agent_token()
        agent.save(update_fields=["token"])
        written = services.sync_nginx_files()
        record_event(action="gate.agent_rotated", actor=request.user, target=agent,
                     metadata={"old_path": old}, request=request)
        messages.success(request, f"Rotated {old} → {agent.path}. Redeploy the agent.")
    return redirect("gate-agents")


@login_required
def gate_events_view(request):
    events = HitEvent.objects.select_related("link", "agent_channel")
    category = request.GET.get("category", "").strip()
    days = request.GET.get("days", "7").strip()
    if category in dict(HitEvent.CATEGORY_CHOICES):
        events = events.filter(category=category)
    if days.isdigit() and 1 <= int(days) <= 365:
        events = events.filter(created_at__gte=timezone.now() - timezone.timedelta(days=int(days)))
    paginator = Paginator(events, 40)
    page = paginator.get_page(request.GET.get("page"))
    template = "panel/_gate_events_table.html" if request.headers.get("HX-Request") else "panel/gate_events.html"
    return render(request, template, {
        "title": "Gate Events", "page": page, "events": page.object_list,
        "categories": HitEvent.CATEGORY_CHOICES, "category": category,
        "suspicious_today": HitEvent.objects.filter(category="suspicious", created_at__date=timezone.now().date()).count(),
    })


@login_required
def selftest_view(request):
    from .selftest import run_selftest
    results = None
    if request.method == "POST" or request.GET.get("run") == "1":
        results = run_selftest()
    return render(request, "panel/selftest.html", {"title": "Self-Test", "results": results})


@login_required
def decoys_view(request):
    if request.method == "POST":
        kind = request.POST.get("kind", "template")
        page = DecoyPage(kind=kind, created_by=request.user)
        page.name = request.POST.get("name", "").strip()[:120] or "unnamed decoy"
        if kind == "template":
            page.template_key = request.POST.get("template_key", "").strip()
            meta = BUILTIN_DECOYS.get(page.template_key)
            if meta:
                page.name = request.POST.get("name", "").strip()[:120] or meta["label"]
        elif kind == "upload":
            if request.FILES.get("html_file"):
                page.html_file = request.FILES["html_file"]
        elif kind == "redirect":
            page.redirect_url = request.POST.get("redirect_url", "").strip()
        try:
            page.full_clean()
        except ValidationError as exc:
            messages.error(request, "; ".join(
                f"{field}: {', '.join(errors)}" for field, errors in exc.message_dict.items()))
            return redirect("gate-decoys")
        page.save()
        record_event(action="gate.decoy_created", actor=request.user, target=page, request=request)
        messages.success(request, f"Decoy page '{page.name}' created.")
        return redirect("gate-decoys")
    pages = DecoyPage.objects.all()
    return render(request, "panel/decoys.html", {
        "title": "Decoy Pages", "pages": pages,
        "builtin": BUILTIN_DECOYS, "kinds": DecoyPage.KIND_CHOICES,
        "current_default": services.get_default_decoy(),
    })


@login_required
@transaction.atomic
def decoy_set_default(request, pk):
    page = get_object_or_404(DecoyPage, pk=pk)
    if request.method == "POST":
        if not page.active:
            messages.error(request, "Activate the page before making it the default.")
            return redirect("gate-decoys")
        DecoyPage.objects.exclude(pk=page.pk).update(is_default=False)
        DecoyPage.objects.filter(pk=page.pk).update(is_default=True)
        record_event(action="gate.decoy_defaulted", actor=request.user, target=page, request=request)
        messages.success(request, f"'{page.name}' is now the default decoy.")
    return redirect("gate-decoys")


def _promote_fallback_decoy(exclude_pk=None):
    """Pick a new default: the update-service page, else any active page."""
    queryset = DecoyPage.objects.filter(active=True)
    if exclude_pk is not None:
        queryset = queryset.exclude(pk=exclude_pk)
    fallback = queryset.filter(kind="template", template_key="update-service").first() \
        or queryset.first()
    if fallback is not None:
        DecoyPage.objects.filter(pk=fallback.pk).update(is_default=True)
        return fallback
    return None


@login_required
@transaction.atomic
def decoy_toggle(request, pk):
    page = get_object_or_404(DecoyPage, pk=pk)
    if request.method == "POST":
        page.active = not page.active
        if not page.active and page.is_default:
            page.is_default = False
            page.save(update_fields=["active", "is_default"])
            _promote_fallback_decoy(exclude_pk=page.pk)
        else:
            page.save(update_fields=["active"])
        record_event(action="gate.decoy_toggled", actor=request.user, target=page,
                     metadata={"active": page.active}, request=request)
    return redirect("gate-decoys")


@login_required
@transaction.atomic
def decoy_delete(request, pk):
    page = get_object_or_404(DecoyPage, pk=pk)
    if request.method == "POST":
        if page.kind == "template":
            messages.error(request, "Built-in pages cannot be deleted, only deactivated.")
            return redirect("gate-decoys")
        was_default = page.is_default
        name = page.name
        page.delete()
        if was_default:
            _promote_fallback_decoy()
        record_event(action="gate.decoy_deleted", actor=request.user,
                     metadata={"name": name}, request=request)
        messages.success(request, f"Decoy page '{name}' deleted.")
    return redirect("gate-decoys")


@login_required
def link_totp_preview(request, pk):
    """Show the operator the current TOTP code(s) for a gate."""
    import time
    from .crypto_utils import totp_code
    link = get_object_or_404(DeliveryLink, pk=pk, gate_type="totp")
    now_window = int(time.time()) // max(link.totp_window, 1)
    codes = {str(w): totp_code(link.totp_secret, w) for w in (now_window - 1, now_window)}
    return render(request, "panel/_totp_codes.html", {"link": link, "codes": codes})
