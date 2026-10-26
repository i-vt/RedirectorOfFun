import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.http import FileResponse, HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from accounts.permissions import is_administrator
from audit.services import record_event
from notifications.services import notify

from .models import (
    AgentChannel, BannedIP, BlockingRule, BUILTIN_DECOYS, DecoyPage, DeliveryLink,
    HitEvent, LureSite, RuleSet, seed_blocking_rule_presets, Submission,
    SubmissionImage, validate_auto_rules, validate_header_contract,
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
        "allowed_uas_csv": ", ".join(link.allowed_uas or []),
        "allowed_ips_csv": ", ".join(link.allowed_ips or []),
        "domains": getattr(settings, "REDIRECTOR_DOMAINS", []),
        "templates": LINK_TEMPLATES,
    })


def _base_path():
    from django.conf import settings
    return getattr(settings, "GATE_BASE_PATH", "/g/")


def _base_path_setting(name, default):
    from django.conf import settings
    return getattr(settings, name, default)


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
    link.allowed_uas = _split_csv(request.POST.get("allowed_uas", ""))
    link.allowed_ips = _split_csv(request.POST.get("allowed_ips", ""))
    raw_contract = request.POST.get("header_contract", "").strip()
    if raw_contract:
        try:
            link.header_contract = json.loads(raw_contract)
        except json.JSONDecodeError as exc:
            raise ValidationError({"header_contract": [f"invalid JSON: {exc}"]})
        try:
            validate_header_contract(link.header_contract)
        except ValidationError as exc:
            raise ValidationError({"header_contract": exc.messages})
    else:
        link.header_contract = []
    link.replay_dedupe = request.POST.get("replay_dedupe") == "on"
    from django.utils.dateparse import parse_time
    link.active_window_start = parse_time(request.POST.get("active_window_start", "").strip() or "") \
        if request.POST.get("active_window_start", "").strip() else None
    link.active_window_end = parse_time(request.POST.get("active_window_end", "").strip() or "") \
        if request.POST.get("active_window_end", "").strip() else None
    link.one_time = request.POST.get("one_time") == "on"
    max_uses = request.POST.get("max_uses", "0").strip()
    link.max_uses = int(max_uses) if max_uses.isdigit() else 0
    for field in ("serve_num", "serve_den"):
        raw = request.POST.get(field, "1").strip()
        setattr(link, field, int(raw) if raw.isdigit() and int(raw) >= 1 else 1)
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
    from datetime import timedelta
    link = get_object_or_404(DeliveryLink, pk=pk)
    submissions = link.submissions.select_related("decided_by")[:20]
    # 14-day release series for the payload chart (downloads + key serves only,
    # not the generic per-visit "hit" records)
    since = timezone.now() - timedelta(days=14)
    hits = link.hit_events.filter(created_at__gte=since, category__in=["download", "key_served"])
    from django.db.models import Count
    from django.db.models.functions import TruncDate
    daily = {str(item["day"]): item["count"] for item in
             hits.annotate(day=TruncDate("created_at")).values("day").annotate(count=Count("id"))}
    series = []
    now = timezone.now()
    for offset in range(13, -1, -1):
        day = (now - timedelta(days=offset)).date().isoformat()
        series.append({"day": day, "count": daily.get(day, 0)})
    intel_qs = SubmissionImage.objects.filter(
        submission__link=link).select_related("submission").order_by("-created_at")
    return render(request, "panel/link_detail.html", {
        "title": f"Link {link.path}", "link": link, "submissions": submissions,
        "hits": link.hit_events.all()[:30], "is_administrator": is_administrator(request.user),
        "undo_seconds": services_undo_window(), "series_json": series,
        "intel_images": intel_qs[:24], "intel_total": intel_qs.count(),
        "public_url": request.build_absolute_uri(link.path),
    })


@login_required
def link_qr(request, pk):
    """QR code (SVG) for a link's public URL - scan-to-visit from a phone."""
    link = get_object_or_404(DeliveryLink, pk=pk)
    return _qr_svg_response(request.build_absolute_uri(link.path))


@login_required
def lure_qr(request, pk):
    site = get_object_or_404(LureSite, pk=pk)
    return _qr_svg_response(request.build_absolute_uri(site.public_path))


def _qr_svg_response(text):
    import qrcode
    import qrcode.image.svg
    image = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=8)
    return HttpResponse(image.to_string(), content_type="image/svg+xml")


@login_required
def intel_gallery(request):
    """Every image the gates received, as a filterable visual gallery."""
    images = SubmissionImage.objects.select_related("submission__link").order_by("-created_at")
    link_q = request.GET.get("link", "").strip()
    field_q = request.GET.get("field", "").strip()
    if link_q:
        images = images.filter(submission__link__path__icontains=link_q[:200])
    if field_q:
        images = images.filter(field_name__icontains=field_q[:120])
    from datetime import timedelta
    day_ago = timezone.now() - timedelta(hours=24)
    stats = {
        "total": SubmissionImage.objects.count(),
        "last_24h": SubmissionImage.objects.filter(created_at__gte=day_ago).count(),
        "links": SubmissionImage.objects.values("submission__link").distinct().count(),
    }
    paginator = Paginator(images, 48)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "panel/intel.html", {
        "title": "Gate Intel", "page": page, "images": page.object_list,
        "stats": stats, "link_q": link_q, "field_q": field_q,
    })


@login_required
@transaction.atomic
def link_quick_drop(request):
    """One-step file drop: name + file -> a live download link with an
    auto-generated path under the gate base. Returns JSON for the modal."""
    import secrets
    if request.method != "POST":
        return JsonResponse({"detail": "POST only."}, status=405)
    file = request.FILES.get("file")
    if not file:
        return JsonResponse({"detail": "Attach a file."}, status=400)
    base = _base_path()
    path = f"{base}{secrets.token_urlsafe(6)}"
    link = DeliveryLink.objects.create(
        path=path, kind="file", label=request.POST.get("name", "").strip()[:120] or file.name[:120],
        placeholder="blank", on_deny="not_found", payload=file, created_by=request.user,
    )
    record_event(action="gate.link_quick_dropped", actor=request.user, target=link,
                 metadata={"size": file.size}, request=request)
    return JsonResponse({"path": link.path, "label": link.label, "id": link.pk})


@login_required
def payloads_view(request):
    """File manager: every payload, benevolent file, and decoy page, with the
    gate intel (submissions) attached to each link."""
    if request.method == "POST":
        action = request.POST.get("action", "")
        link = get_object_or_404(DeliveryLink, pk=request.POST.get("link_id", ""))
        if action == "replace" and request.FILES.get("payload"):
            old_name = link.payload.name if link.payload else ""
            link.payload = request.FILES["payload"]
            link.save(update_fields=["payload"])
            record_event(action="gate.payload_rotated", actor=request.user, target=link,
                         metadata={"old": old_name}, request=request)
            messages.success(request, f"Payload on {link.path} replaced; the URL is unchanged.")
        elif action == "clear":
            if link.payload:
                link.payload.delete(save=False)
                link.payload = None
                link.save(update_fields=["payload"])
                record_event(action="gate.payload_cleared", actor=request.user, target=link,
                             request=request)
                messages.success(request, f"Payload cleared from {link.path}.")
        elif action == "clear_benevolent":
            if link.benevolent_file:
                link.benevolent_file.delete(save=False)
                link.benevolent_file = None
                link.save(update_fields=["benevolent_file"])
                messages.success(request, f"Benevolent file cleared from {link.path}.")
        return redirect("gate-payloads")
    file_links = DeliveryLink.objects.filter(payload__isnull=False).exclude(payload="")
    benevolent_links = DeliveryLink.objects.filter(benevolent_file__isnull=False).exclude(benevolent_file="")
    decoys = DecoyPage.objects.filter(kind="upload", html_file__isnull=False).exclude(html_file="")
    intel = {}
    for link in list(file_links) + list(benevolent_links):
        submissions = link.submissions.all()
        if submissions.exists():
            latest = submissions.first()
            intel[link.pk] = {
                "count": submissions.count(),
                "hostname": (latest.decoded_json or {}).get("hostname", ""),
                "ip_hash": latest.client_ip_hash[:12],
                "images": latest.images.count(),
                "at": latest.created_at,
            }
    return render(request, "panel/payloads.html", {
        "title": "Payloads",
        "file_links": file_links,
        "benevolent_links": benevolent_links,
        "decoys": decoys,
        "intel": intel,
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


DEFAULT_LURE_INDEX = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Welcome</title>
  <link rel="stylesheet" href="css/style.css">
</head>
<body>
  <main class="wrap">
    <h1>It works.</h1>
    <p>Edit this page from the panel. Add more pages and assets on the left.</p>
  </main>
</body>
</html>
"""

DEFAULT_LURE_CSS = """body { font-family: system-ui, sans-serif; margin: 0; color: #1c2733; }
.wrap { max-width: 640px; margin: 12vh auto; padding: 0 20px; }
"""


@login_required
def lures_view(request):
    """Hosted multi-page lure sites, served publicly under LURE_BASE_PATH."""
    if request.method == "POST":
        site = LureSite(
            name=request.POST.get("name", "").strip()[:120] or "unnamed lure",
            slug=request.POST.get("slug", "").strip().lower()[:60],
            description=request.POST.get("description", "").strip()[:240],
            created_by=request.user,
        )
        try:
            site.full_clean()
        except ValidationError as exc:
            messages.error(request, "; ".join(
                f"{field}: {', '.join(errors)}" for field, errors in exc.message_dict.items()))
            return redirect("gate-lures")
        site.save()
        site.files.create(path="index.html", content=DEFAULT_LURE_INDEX)
        site.files.create(path="css/style.css", content=DEFAULT_LURE_CSS)
        record_event(action="gate.lure_created", actor=request.user, target=site, request=request)
        messages.success(request, f"Lure '{site.name}' is live at {site.public_path}")
        return redirect("gate-lure-edit", pk=site.pk)
    from django.db.models import Count
    sites = LureSite.objects.annotate(file_count=Count("files"))
    return render(request, "panel/lures.html", {
        "title": "Lures", "sites": sites,
        "lure_base": _base_path_setting("LURE_BASE_PATH", "/l/"),
    })


def _file_form_error(request, exc):
    message_dict = getattr(exc, "message_dict", None)
    if message_dict:
        messages.error(request, "; ".join(
            f"{field}: {', '.join(errors)}" for field, errors in message_dict.items()))
    else:
        messages.error(request, str(exc) or "Save failed.")


def _upsert_site_file(files, fk_name, owner, original, path, content):
    """Create or rename+save a text file row under `owner`. Returns (file, error)."""
    file = files.filter(path=original).first() if original else None
    if file is None:
        file = files.model(**{fk_name: owner})
    file.path = path.strip()
    file.content = content
    try:
        file.full_clean()
        file.save()
    except Exception as exc:  # noqa: BLE001 - ValidationError or raced IntegrityError
        return None, exc
    return file, None


@login_required
@transaction.atomic
def lure_edit(request, pk):
    """Multi-file browser editor for one lure site."""
    from django.urls import reverse
    from urllib.parse import quote
    site = get_object_or_404(LureSite, pk=pk)

    def back(file_path=""):
        url = reverse("gate-lure-edit", args=[site.pk])
        return redirect(f"{url}?file={quote(file_path)}" if file_path else url)

    if request.method == "POST":
        action = request.POST.get("action", "")
        if action == "meta":
            site.name = request.POST.get("name", "").strip()[:120] or site.name
            site.slug = request.POST.get("slug", "").strip().lower()[:60] or site.slug
            site.description = request.POST.get("description", "").strip()[:240]
            site.active = request.POST.get("active", "off") == "on"
            try:
                site.full_clean()
                site.save()
                record_event(action="gate.lure_updated", actor=request.user, target=site,
                             request=request)
                messages.success(request, "Lure settings saved.")
            except ValidationError as exc:
                _file_form_error(request, exc)
            return back()
        if action == "save_file":
            original = request.POST.get("original_path", "")
            file, error = _upsert_site_file(site.files, "site", site, original,
                                            request.POST.get("path", ""),
                                            request.POST.get("content", ""))
            if error is not None:
                _file_form_error(request, error)
                return back(original)
            record_event(action="gate.lure_file_saved", actor=request.user, target=site,
                         metadata={"path": file.path}, request=request)
            messages.success(request, f"Saved {file.path}.")
            return back(file.path)
        if action == "add_file":
            path = request.POST.get("path", "").strip()
            if site.files.filter(path=path).exists():
                messages.error(request, f"{path} already exists.")
                return back(path)
            file, error = _upsert_site_file(site.files, "site", site, "", path, "")
            if error is not None:
                _file_form_error(request, error)
                return back()
            messages.success(request, f"Created {file.path}.")
            return back(file.path)
        if action == "delete_file":
            path = request.POST.get("path", "")
            site.files.filter(path=path).delete()
            record_event(action="gate.lure_file_deleted", actor=request.user, target=site,
                         metadata={"path": path}, request=request)
            messages.success(request, f"Deleted {path}.")
            return back()
        if action == "delete_site":
            name = site.name
            site.delete()
            record_event(action="gate.lure_deleted", actor=request.user,
                         metadata={"name": name}, request=request)
            messages.success(request, f"Lure '{name}' deleted.")
            return redirect("gate-lures")
        return back()

    files = site.files.all()
    selected = request.GET.get("file", "")
    current = files.filter(path=selected).first() \
        or files.filter(path="index.html").first() or files.first()
    return render(request, "panel/lure_edit.html", {
        "title": f"Lure {site.slug}", "site": site, "files": files, "current": current,
    })


@login_required
@transaction.atomic
def lure_toggle(request, pk):
    site = get_object_or_404(LureSite, pk=pk)
    if request.method == "POST":
        site.active = not site.active
        site.save(update_fields=["active"])
        record_event(action="gate.lure_toggled", actor=request.user, target=site,
                     metadata={"active": site.active}, request=request)
    return redirect("gate-lures")


@login_required
@transaction.atomic
def decoy_edit(request, pk):
    """Browser editor for a decoy page: HTML override plus tied assets."""
    from django.urls import reverse
    from urllib.parse import quote
    page = get_object_or_404(DecoyPage, pk=pk)

    def back(asset_path=""):
        url = reverse("gate-decoy-edit", args=[page.pk])
        return redirect(f"{url}?asset={quote(asset_path)}" if asset_path else url)

    if request.method == "POST":
        action = request.POST.get("action", "")
        if action == "meta":
            page.name = request.POST.get("name", "").strip()[:120] or page.name
            if page.kind == "redirect":
                page.redirect_url = request.POST.get("redirect_url", "").strip()
            try:
                page.full_clean()
                page.save()
                record_event(action="gate.decoy_updated", actor=request.user, target=page,
                             request=request)
                messages.success(request, "Decoy settings saved.")
            except ValidationError as exc:
                _file_form_error(request, exc)
            return back()
        if action == "save_html":
            page.html = request.POST.get("content", "")
            page.save(update_fields=["html"])
            record_event(action="gate.decoy_updated", actor=request.user, target=page,
                         metadata={"html_override": bool(page.html)}, request=request)
            messages.success(request, "HTML saved."
                             if page.html else "Override cleared - back to the source content.")
            return back()
        if action == "save_asset":
            original = request.POST.get("original_path", "")
            asset, error = _upsert_site_file(page.assets, "page", page, original,
                                             request.POST.get("path", ""),
                                             request.POST.get("content", ""))
            if error is not None:
                _file_form_error(request, error)
                return back(original)
            record_event(action="gate.decoy_asset_saved", actor=request.user, target=page,
                         metadata={"path": asset.path}, request=request)
            messages.success(request, f"Saved {asset.path} - served at {asset.public_path}")
            return back(asset.path)
        if action == "add_asset":
            path = request.POST.get("path", "").strip()
            if page.assets.filter(path=path).exists():
                messages.error(request, f"{path} already exists.")
                return back(path)
            asset, error = _upsert_site_file(page.assets, "page", page, "", path, "")
            if error is not None:
                _file_form_error(request, error)
                return back()
            messages.success(request, f"Created {asset.path} - served at {asset.public_path}")
            return back(asset.path)
        if action == "delete_asset":
            path = request.POST.get("path", "")
            page.assets.filter(path=path).delete()
            record_event(action="gate.decoy_asset_deleted", actor=request.user, target=page,
                         metadata={"path": path}, request=request)
            messages.success(request, f"Deleted {path}.")
            return back()
        return back()

    # Editor source: the saved override, else the source content so the operator
    # can start editing immediately (saving creates the override).
    override_active = bool(page.html)
    if override_active:
        editor_html = page.html
    elif page.kind == "upload" and page.html_file:
        editor_html = page.html_file.read().decode("utf-8", errors="replace")
    elif page.kind == "template":
        meta = BUILTIN_DECOYS.get(page.template_key, {})
        if meta.get("django_template"):
            from django.template.loader import render_to_string
            editor_html = render_to_string(meta["template_name"], {})
        else:
            try:
                from django.conf import settings as dj_settings
                editor_html = (dj_settings.BASE_DIR / meta["path"]).read_text(
                    encoding="utf-8", errors="replace")
            except (OSError, KeyError):
                editor_html = ""
    else:
        editor_html = ""
    assets = page.assets.all()
    selected = request.GET.get("asset", "")
    current_asset = assets.filter(path=selected).first() or assets.first()
    return render(request, "panel/decoy_edit.html", {
        "title": f"Decoy {page.name}", "page": page, "editor_html": editor_html,
        "override_active": override_active, "assets": assets, "current_asset": current_asset,
    })


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
def block_rules_view(request):
    if request.method == "POST":
        action = request.POST.get("action", "")
        if action == "seed_presets":
            seed_blocking_rule_presets()
            messages.info(request, "Preset rules ensured (new ones are created disabled).")
            return redirect("gate-block-rules")
        if action == "create_set":
            ruleset = RuleSet(
                name=request.POST.get("set_name", "").strip()[:120] or "unnamed set",
                scope=request.POST.get("set_scope", "all"),
            )
            link_id = request.POST.get("set_link", "").strip()
            if ruleset.scope == "link" and link_id:
                ruleset.link = get_object_or_404(DeliveryLink, pk=link_id)
            try:
                ruleset.full_clean()
                ruleset.save()
            except ValidationError as exc:
                messages.error(request, "; ".join(
                    f"{field}: {', '.join(errors)}" for field, errors in exc.message_dict.items()))
                return redirect("gate-block-rules")
            record_event(action="gate.rule_set_created", actor=request.user, target=ruleset, request=request)
            messages.success(request, f"Ruleset '{ruleset.name}' created.")
            return redirect("gate-block-rules")
        if action == "import":
            raw = request.POST.get("import_payload", "")
            if request.FILES.get("import_file"):
                raw = request.FILES["import_file"].read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                messages.error(request, f"Invalid JSON: {exc}")
                return redirect("gate-block-rules")
            sets_created, rules_created, errors = services.import_blocking_rules(payload, actor=request.user)
            for error in errors[:5]:
                messages.warning(request, error)
            messages.success(request, f"Imported {sets_created} ruleset(s), {rules_created} rule(s) (disabled on import).")
            return redirect("gate-block-rules")
        # create rule
        ruleset = None
        ruleset_id = request.POST.get("ruleset", "").strip()
        if ruleset_id:
            ruleset = get_object_or_404(RuleSet, pk=ruleset_id)
        rule = BlockingRule(
            ruleset=ruleset,
            name=request.POST.get("name", "").strip()[:120] or "unnamed rule",
            logic=request.POST.get("logic", "all"),
            action=request.POST.get("action", "block"),
            auto_ban=request.POST.get("auto_ban") == "on",
            created_by=request.user,
        )
        try:
            rule.conditions = json.loads(request.POST.get("conditions", "[]"))
        except json.JSONDecodeError as exc:
            messages.error(request, f"Conditions must be valid JSON: {exc}")
            return redirect("gate-block-rules")
        try:
            rule.full_clean()
        except ValidationError as exc:
            messages.error(request, "; ".join(
                f"{field}: {', '.join(errors)}" for field, errors in exc.message_dict.items()))
            return redirect("gate-block-rules")
        if rule.ruleset is not None:
            last = rule.ruleset.rules.order_by("-order").first()
            rule.order = (last.order + 1) if last else 0
        rule.save()
        record_event(action="gate.block_rule_created", actor=request.user, target=rule, request=request)
        messages.success(request, f"Rule '{rule.name}' created.")
        return redirect("gate-block-rules")
    sets = list(RuleSet.objects.prefetch_related("rules"))
    loose_rules = list(BlockingRule.objects.filter(ruleset__isnull=True))
    return render(request, "panel/block_rules.html", {
        "title": "Blocking Rules",
        "rule_sets": sets, "loose_rules": loose_rules,
        "links": DeliveryLink.objects.filter(active=True)[:50],
        "logics": BlockingRule.LOGIC_CHOICES,
        "actions": BlockingRule.ACTION_CHOICES,
        "condition_types": ["ip", "cidr", "ua", "asn", "isp", "country", "city"],
    })


@login_required
@transaction.atomic
def rule_set_toggle(request, pk):
    ruleset = get_object_or_404(RuleSet, pk=pk)
    if request.method == "POST":
        ruleset.enabled = not ruleset.enabled
        ruleset.save(update_fields=["enabled"])
        record_event(action="gate.rule_set_toggled", actor=request.user, target=ruleset,
                     metadata={"enabled": ruleset.enabled}, request=request)
    return redirect("gate-block-rules")


@login_required
@transaction.atomic
def rule_set_delete(request, pk):
    ruleset = get_object_or_404(RuleSet, pk=pk)
    if request.method == "POST":
        name = ruleset.name
        rules = list(ruleset.rules.all())
        ruleset.delete()  # cascades rules
        for rule in rules:
            rule.ruleset = None
            rule.save(update_fields=["ruleset"])  # orphan back into the loose chain
        record_event(action="gate.rule_set_deleted", actor=request.user,
                     metadata={"name": name}, request=request)
        messages.success(request, f"Ruleset '{name}' deleted; its rules moved to the ungrouped chain.")
    return redirect("gate-block-rules")


@login_required
@transaction.atomic
def block_rules_reorder(request):
    if request.method != "POST":
        return redirect("gate-block-rules")
    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        payload = request.POST
    kind = payload.get("kind")
    ids = payload.get("ids", [])
    if kind == "rule":
        for index, rule_id in enumerate(ids):
            BlockingRule.objects.filter(pk=rule_id).update(order=index)
        record_event(action="gate.block_rules_reordered", actor=request.user,
                     metadata={"rules": len(ids)}, request=request)
    elif kind == "set":
        for index, set_id in enumerate(ids):
            RuleSet.objects.filter(pk=set_id).update(order=index)
        record_event(action="gate.rule_sets_reordered", actor=request.user,
                     metadata={"sets": len(ids)}, request=request)
    if request.headers.get("HX-Request") or request.content_type == "application/json":
        return JsonResponse({"ok": True})
    return redirect("gate-block-rules")


@login_required
def block_rules_export(request):
    payload = services.export_blocking_rules()
    record_event(action="gate.block_rules_exported", actor=request.user, request=request)
    response = JsonResponse(payload)
    response["Content-Disposition"] = 'attachment; filename="rof-blocking-rules.json"'
    return response


@login_required
@transaction.atomic
def block_rule_toggle(request, pk):
    rule = get_object_or_404(BlockingRule, pk=pk)
    if request.method == "POST":
        rule.enabled = not rule.enabled
        rule.save(update_fields=["enabled"])
        record_event(action="gate.block_rule_toggled", actor=request.user, target=rule,
                     metadata={"enabled": rule.enabled}, request=request)
    return redirect("gate-block-rules")


@login_required
@transaction.atomic
def block_rule_delete(request, pk):
    rule = get_object_or_404(BlockingRule, pk=pk)
    if request.method == "POST":
        if rule.preset:
            messages.error(request, "Preset rules cannot be deleted, only disabled.")
            return redirect("gate-block-rules")
        name = rule.name
        rule.delete()
        record_event(action="gate.block_rule_deleted", actor=request.user,
                     metadata={"name": name}, request=request)
        messages.success(request, f"Rule '{name}' deleted.")
    return redirect("gate-block-rules")


@login_required
def block_rule_test(request):
    result = None
    if request.method == "POST":
        ip = request.POST.get("ip", "").strip()[:64]
        ua = request.POST.get("ua", "").strip()[:1000]
        intel = services.get_ip_intel(ip)
        matched = []
        for rule in BlockingRule.objects.all():
            hit, fired = services.rule_matches(rule, ip=ip, user_agent=ua, intel=intel)
            if hit:
                matched.append({"name": rule.name, "enabled": rule.enabled, "fired": fired})
        result = {"ip": ip, "ua": ua, "intel": str(intel) if intel else None, "matched": matched}
    return render(request, "panel/block_rule_test.html", {
        "title": "Test Blocking Rules", "result": result,
    })


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
