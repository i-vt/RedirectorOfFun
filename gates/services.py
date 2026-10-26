"""Core logic for the release-gate system: evaluation, serving, banning, sync."""
import functools
import hashlib
import ipaddress
import json
import logging
import re
import urllib.request

from django.conf import settings
from django.core.files.base import ContentFile
from django.db.models import F
from django.http import FileResponse, HttpResponse
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.utils import timezone

from analytics.services import hash_address
from audit.services import record_event
from notifications.services import notify
from .crypto_utils import (
    GateCryptoError, client_presented_token, decrypt_blob, extract_images,
    parse_submission_json, validate_expected_fields, verify_totp,
)
from .models import (
    AgentChannel, BannedIP, BlockingRule, BUILTIN_DECOYS, DecoyPage, DeliveryLink,
    HitEvent, IPIntel, LureSite, SeenRequest, Submission, SubmissionImage,
)

logger = logging.getLogger(__name__)

SUSPICIOUS_AUTO_BAN_REASON = "auto-banned after repeated suspicious activity"


def _remote_is_trusted(remote):
    if not remote:
        return False
    try:
        address = ipaddress.ip_address(remote)
    except ValueError:
        return False
    for entry in getattr(settings, "TRUSTED_PROXIES", ("127.0.0.1", "::1")):
        try:
            if "/" in entry:
                if address in ipaddress.ip_network(entry, strict=False):
                    return True
            elif address == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def client_ip(request):
    # X-Forwarded-For is only honored when the immediate peer is a configured
    # proxy; otherwise a client can forge it to evade bans or frame third
    # parties. The single trusted hop appends the observed address, so the
    # LAST entry is the real client; earlier entries may be client-supplied
    # garbage.
    remote = request.META.get("REMOTE_ADDR", "")
    if _remote_is_trusted(remote):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            return forwarded.split(",")[-1].strip()
    return remote


def record_hit(category, *, request=None, path="", link=None, agent_channel=None,
               status_code=200, detail=None, ip_override=""):
    ip = ip_override or (client_ip(request) if request is not None else "")
    event = HitEvent(
        category=category,
        path=path[:8192],
        link=link,
        agent_channel=agent_channel,
        ip_hash=hash_address(ip),
        raw_ip=ip or None,
        user_agent=(request.META.get("HTTP_USER_AGENT", "")[:1000] if request is not None else ""),
        status_code=status_code,
        detail=detail or {},
    )
    event.save()
    if category == "suspicious" and ip:
        maybe_auto_ban(ip)
    return event


def suspicious_count(ip_hash):
    from datetime import timedelta
    since = timezone.now() - timedelta(hours=1)
    return HitEvent.objects.filter(category="suspicious", ip_hash=ip_hash, created_at__gte=since).count()


def _is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def maybe_auto_ban(ip):
    threshold = getattr(settings, "AUTO_BAN_THRESHOLD", 0)
    if not threshold or _is_loopback(ip):
        return None
    ip_hash = hash_address(ip)
    if suspicious_count(ip_hash) < threshold:
        return None
    if BannedIP.is_banned(ip):
        return None
    ban, _ = BannedIP.objects.get_or_create(
        ip=ip, defaults={"note": SUSPICIOUS_AUTO_BAN_REASON, "auto_created": True})
    try:
        sync_nginx_files()
    except OSError as exc:
        # A broken include path must not take down the public surface.
        logger.warning("nginx ban sync failed after auto-ban of %s: %s", ip, exc)
    notify("suspicious", {
        "title": "IP auto-banned",
        "detail": f"{ip} hit {threshold}+ suspicious events within an hour and was banned.",
    })
    logger.info("auto-banned %s after suspicious activity threshold", ip)
    return ban


def _blank():
    return HttpResponse(status=204)


def _placeholder(link=None):
    return range_aware_response(request, render_to_string("gates/placeholder.html", {"link": link}), content_type="text/html")


def _canary_url(request):
    if request is not None and getattr(settings, "DECOY_CANARIES", True):
        return f"{getattr(settings, 'GATE_BASE_PATH', '/g/')}canary/{canary_token(client_ip(request))}.gif"
    return ""


def _inject_canary(html, request):
    url = _canary_url(request)
    if not url:
        return html
    tag = f'<img src="{url}" width="1" height="1" alt="" aria-hidden="true" style="position:absolute;left:-9999px">'
    index = html.lower().rfind("</body>")
    if index != -1:
        return html[:index] + tag + html[index:]
    return html + tag


def get_default_decoy():
    """The operator-selected decoy page, falling back to the historical default."""
    page = DecoyPage.objects.filter(active=True, is_default=True).first()
    if page is None:
        page = DecoyPage.objects.filter(
            active=True, kind="template", template_key="update-service").first()
    return page


def render_decoy(page, request):
    """HTML for the decoy page, or None when the page is an external redirect."""
    if page is None or page.kind == "redirect":
        return None
    if page.html:
        # Operator-edited override beats both the upload and the built-in.
        return _inject_canary(page.html, request)
    if page.kind == "upload":
        if not page.html_file:
            return None
        return _inject_canary(page.html_file.read().decode("utf-8", errors="replace"), request)
    meta = BUILTIN_DECOYS.get(page.template_key)
    if meta is None:
        return None
    if meta.get("django_template"):
        context = {}
        url = _canary_url(request)
        if url:
            context["canary"] = url
        return render_to_string(meta["template_name"], context)
    path = settings.BASE_DIR / meta["path"]
    try:
        html = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return _inject_canary(html, request)


def decoy_response(request=None, status=200):
    """Serve (or redirect to) the operator-selected default decoy page."""
    page = get_default_decoy()
    if page is not None and page.kind == "redirect" and page.redirect_url:
        return redirect(page.redirect_url)
    html = render_decoy(page, request)
    if html is None:
        # Fallback keeps the public surface alive even if the default row
        # was deleted or its template file went missing.
        context = {}
        url = _canary_url(request)
        if url:
            context["canary"] = url
        html = render_to_string("gates/decoy.html", context)
    if request is not None:
        return range_aware_response(request, html, content_type="text/html")
    return HttpResponse(html, status=status)


def _decoy(request=None, status=200):
    return decoy_response(request, status=status)


# ─── Hosted sites (lures) and decoy asset bundles ──────────────────────────

def serve_lure(request, rest):
    """Serve a hosted lure site file. `rest` is '<slug>/<path>' after the lure
    base prefix. Returns None when no active site owns the slug (caller then
    treats the request as a normal not-found)."""
    slug, _, rel = rest.partition("/")
    site = LureSite.objects.filter(slug=slug[:60], active=True).first()
    if site is None:
        return None
    ip = client_ip(request)
    decision = evaluate_blocking_rules(request, ip, is_404=False)
    if decision is not None:
        rule, fired = decision
        response = apply_blocking_rule(request, ip, rule, fired)
        if response is not None:
            return response
    rel = rel.strip("/") or "index.html"
    file = site.files.filter(path=rel).first()
    if file is None:
        record_hit("lure", request=request, path=request.path, status_code=404,
                   detail={"slug": site.slug, "missing": rel[:200]})
        missing = site.files.filter(path="404.html").first()
        if missing is not None:
            return range_aware_response(request, missing.content, content_type="text/html")
        return _decoy(request)
    record_hit("lure", request=request, path=request.path, status_code=200,
               detail={"slug": site.slug, "file": rel})
    return range_aware_response(request, file.content,
                                content_type=file.content_type or "text/plain")


def serve_decoy_asset(request, rest):
    """Serve one tied asset of a decoy page. `rest` is '<page id>/<path>'.
    Returns None when the page or asset does not exist."""
    pk_part, _, rel = rest.partition("/")
    if not pk_part.isdigit():
        return None
    page = DecoyPage.objects.filter(pk=int(pk_part), active=True).first()
    if page is None:
        return None
    asset = page.assets.filter(path=rel.strip("/")).first()
    if asset is None:
        return None
    ip = client_ip(request)
    decision = evaluate_blocking_rules(request, ip, is_404=False)
    if decision is not None:
        rule, fired = decision
        response = apply_blocking_rule(request, ip, rule, fired)
        if response is not None:
            return response
    record_hit("decoy_asset", request=request, path=request.path, status_code=200,
               detail={"page": page.pk, "file": asset.path})
    return range_aware_response(request, asset.content,
                                content_type=asset.content_type or "text/plain")


def gate_denied_response(link, request=None):
    record_for = {"not_found": ("disapproved", 404), "decoy": ("disapproved", 200), "benevolent": ("disapproved", 200)}
    category, status = record_for.get(link.on_deny, ("disapproved", 404))
    record_hit(category, request=request, link=link, status_code=status, detail={"on_deny": link.on_deny})
    if link.on_deny == "decoy":
        return _decoy(request, status=status)
    if link.on_deny == "benevolent":
        if link.benevolent_file:
            with link.benevolent_file.open("rb") as handle:
                return range_aware_response(request, handle.read(),
                                            filename=link.benevolent_file.name.rsplit("/", 1)[-1])
        return range_aware_response(request, link.benevolent_text or "",
                                    content_type="text/plain")
    return HttpResponse(status=404)


def hold_response(link, request=None):
    """What a not-yet-approved link returns until an operator releases it."""
    if link.placeholder == "placeholder":
        return _placeholder(link)
    if link.placeholder == "decoy":
        return _decoy(request)
    return _blank()


def _extract_blob(request):
    body = request.body.decode("utf-8", errors="replace").strip()
    if not body:
        raise GateCryptoError("empty submission body.")
    try:
        wrapper = json.loads(body)
        if isinstance(wrapper, dict) and "data" in wrapper:
            return str(wrapper["data"])
    except json.JSONDecodeError:
        pass
    return body


def handle_submission(link, request):
    """Decrypt/validate an incoming package and queue it for the operator."""
    max_bytes = getattr(settings, "SUBMISSION_MAX_BYTES", 4 * 1024 * 1024)
    try:
        declared = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        declared = 0
    if declared > max_bytes:
        record_hit("suspicious", request=request, path=link.path, link=link,
                   status_code=413, detail={"reason": "submission body too large"})
        return hold_response(link, request)
    try:
        blob = _extract_blob(request)
        decoded_bytes = decrypt_blob(link.cipher, blob, link.cipher_key, link.cipher_iv)
        decoded = parse_submission_json(decoded_bytes)
    except GateCryptoError as exc:
        record_hit("suspicious", request=request, path=link.path, link=link,
                   status_code=400, detail={"reason": "undecryptable submission", "error": str(exc)[:200]})
        return hold_response(link, request)

    missing = validate_expected_fields(decoded, link.expected_fields)
    if missing:
        record_hit("suspicious", request=request, path=link.path, link=link,
                   status_code=400, detail={"reason": "missing expected fields", "missing": missing})
        return hold_response(link, request)

    submission = Submission.objects.create(
        link=link,
        raw_blob=blob[:65536],
        decoded_json=decoded,
        client_ip_hash=hash_address(client_ip(request)),
        raw_ip=client_ip(request) or None,
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
    )
    for image in extract_images(decoded):
        SubmissionImage.objects.create(
            submission=submission,
            field_name=image["field"],
            content_type=image["content_type"],
            image=ContentFile(image["raw"], name=f"sub_{submission.pk}_{image['field'][:40]}"),
        )

    # A replayed or repeat check-in must not re-lock a link that was already
    # approved; only move the link back to pending when nothing was decided yet.
    if link.approval_status != "approved":
        link.approval_status = "pending"
        link.save(update_fields=["approval_status"])
    record_hit("awaiting_approval", request=request, path=link.path, link=link,
               detail={"submission": submission.pk})
    notify("gates", {
        "title": "Submission awaiting approval",
        "detail": (f"{link.path} received a decrypted package (submission #{submission.pk}). "
                   f"Reply 'approve {submission.pk}' or 'deny {submission.pk}' via Telegram, "
                   f"or decide in the panel."),
        "submission_id": submission.pk,
        "decision": True,
    })

    auto = evaluate_auto_rules(link, submission)
    if auto is not None:
        verdict, rule_index, reasons = auto
        decide_submission(submission, verdict, via=f"auto-rule#{rule_index}",
                          extra_detail={"reasons": reasons})
        logger.info("auto-rule #%s %s submission #%s (%s)", rule_index, verdict,
                    submission.pk, "; ".join(reasons))
    return hold_response(link, request)


def _request_digest(request, path):
    """Stable digest of a request for replay dedupe: method, path, query, UA,
    and a body hash (bodies can be large, so the body joins as its digest)."""
    body = b""
    try:
        if request.method in {"POST", "PUT", "PATCH"}:
            body = request.body or b""
    except Exception:  # noqa: BLE001 - unreadable body hashes as empty
        body = b""
    material = "|".join([
        request.method, path,
        request.META.get("QUERY_STRING", ""),
        request.META.get("HTTP_USER_AGENT", "")[:300],
    ]).encode() + b"|" + hashlib.sha256(body).digest()
    return hashlib.sha256(material).hexdigest()


def gate_passed(link, request) -> tuple:
    """Returns (passed, reason). Reason explains a failure when there is one.

    Network-profile checks (IP allow-list, UA pinning, header contract) run
    before any credential check: they need nothing from the visitor beyond
    the request itself, and a mismatch must not reveal which gate failed."""
    if link.allowed_ips:
        ip = client_ip(request)
        if not ip or not any(_cidr_matches(entry, ip) for entry in link.allowed_ips):
            return False, "ip outside allow-list"
    if link.allowed_uas:
        ua = request.META.get("HTTP_USER_AGENT", "")
        matched_any = False
        for pattern in link.allowed_uas:
            try:
                if _compiled_pattern(pattern).search(ua[:1000]):
                    matched_any = True
                    break
            except re.error:
                continue
        if not matched_any:
            return False, "user-agent outside allow-list"
    for rule in link.header_contract or []:
        presented = request.headers.get(str(rule.get("name", "")), "")
        if not presented:
            return False, f"contract header missing: {rule.get('name')}"
        if "value" in rule and presented != str(rule["value"]):
            return False, f"contract header mismatch: {rule.get('name')}"
        if "pattern" in rule:
            try:
                if not _compiled_pattern(str(rule["pattern"])).fullmatch(presented[:1000]):
                    return False, f"contract header mismatch: {rule.get('name')}"
            except re.error:
                return False, f"contract header invalid: {rule.get('name')}"
    if link.gate_type in ("none", "network"):
        # Network gate: the profile checks above (IP / UA allow-lists) ARE the
        # gate; nothing further is requested from the visitor.
        return True, None
    presented = client_presented_token(request)
    if link.gate_type == "token":
        ok = bool(link.gate_token) and presented == link.gate_token
        return ok, None if ok else "token mismatch"
    if link.gate_type == "totp":
        if not verify_totp(link.totp_secret, presented, window_seconds=link.totp_window):
            return False, "code mismatch"
        # A gate code is single-use per link: the first claim wins, replays
        # are rejected and flagged as suspicious. The inner savepoint keeps a
        # rejected insert from poisoning the surrounding transaction.
        from django.db import IntegrityError, transaction
        from .models import UsedGateCode
        horizon = timezone.now() - timezone.timedelta(seconds=max(link.totp_window, 1) * 3)
        UsedGateCode.objects.filter(link=link, used_at__lt=horizon).delete()
        try:
            with transaction.atomic():
                UsedGateCode.objects.create(link=link, code=presented)
        except IntegrityError:
            return False, "totp code replay"
        return True, None
    if link.gate_type == "submission":
        # POST bodies are the submission itself (validated during handling);
        # GETs pass through to the operator-approval check below.
        return True, None
    return False, "unknown gate"


def evaluate_auto_rules(link, submission):
    """Evaluate the link's auto-decision rules against a decoded submission.

    Returns (verdict, rule_index, reasons) for the first matching rule, or
    None when no rule matches (the submission stays pending for a human).
    """
    rules = link.auto_rules or []
    if not rules:
        return None
    decoded = submission.decoded_json or {}
    image_count = submission.images.count()
    # Truncate long values before running operator-configured regexes so a
    # pathological pattern cannot be combined with a huge candidate string.
    values = [str(v)[:1000] for v in decoded.values() if isinstance(v, (str, int, float, bool))]

    for index, rule in enumerate(rules):
        when = rule.get("when", {})
        reasons, matched = [], True
        for field, pattern in when.get("fields_match", {}).items():
            candidate = decoded.get(field)
            if candidate is None or not re.search(pattern, str(candidate)):
                matched, reasons = False, reasons + [f"field '{field}' does not match {pattern!r}"]
                break
            reasons.append(f"field '{field}' matches {pattern!r}")
        if not matched:
            continue
        forbidden_hits = [p for p in when.get("forbid", []) if any(re.search(p, v) for v in values)]
        if forbidden_hits:
            continue  # a forbidden pattern fired - this rule must not decide
        if when.get("require_images") and image_count < 1:
            continue
        if when.get("require_images"):
            reasons.append(f"{image_count} image(s) attached")
        return ("approve" if rule.get("action") == "approve" else "deny"), index, reasons
    return None


def learn_from_decision(link, submission, verdict):
    """Append an auto-decision rule learned from a human decision.

    The rule matches the decided submission exactly (every short scalar field
    anchored with ^...$, images required when present). Idempotent: an
    identical learned rule is never duplicated. Returns True when added."""
    decoded = submission.decoded_json or {}
    fields = {}
    for key, value in decoded.items():
        if isinstance(value, str) and 0 < len(value) <= 120 and "\n" not in value:
            # anchor exact, escaping only real regex specials (keep - readable)
            fields[str(key)[:60]] = "^" + re.sub(r"([.^$*+?{}\[\]\\|()])", r"\\\1", value) + "$"
    if not fields:
        return False
    when = {"fields_match": fields}
    if submission.images.exists():
        when["require_images"] = True
    rules = list(link.auto_rules or [])
    for existing in rules:
        if (existing.get("action") == verdict
                and existing.get("when", {}).get("fields_match") == fields):
            return False
    rules.append({"action": verdict, "learned": True, "when": when})
    link.auto_rules = rules
    link.save(update_fields=["auto_rules"])
    return True


def decide_submission(submission, verdict, *, actor=None, via="panel", request=None,
                      extra_detail=None, remember=False):
    """Shared approve/deny path for the panel, the API, Telegram, and auto rules.

    Returns the refreshed submission, or None if it was already decided.
    The pending-to-decided transition is atomic so concurrent deciders
    (panel + telegram + API) cannot both win. With remember=True the decision
    is learned as an auto-rule for future submissions on the same link.
    """
    if verdict not in {"approve", "deny"}:
        raise ValueError("verdict must be 'approve' or 'deny'")
    now = timezone.now()
    status = "approved" if verdict == "approve" else "denied"
    won = Submission.objects.filter(pk=submission.pk, status="pending").update(
        status=status, decided_by=actor, decided_at=now)
    if not won:
        return None
    submission.refresh_from_db()
    link = submission.link
    link.approval_status = status
    link.decided_by = actor
    link.decided_at = now
    link.save(update_fields=["approval_status", "decided_by", "decided_at"])
    detail = {"submission": submission.pk, "via": via}
    if extra_detail:
        detail.update(extra_detail)
    record_hit("approved" if verdict == "approve" else "disapproved",
               request=request, path=link.path, link=link, detail=detail)
    actor_name = actor.username if actor is not None else via
    notify("gates", {
        "title": f"Submission {status}",
        "detail": f"{link.path}: submission #{submission.pk} {status} by {actor_name}.",
    })
    record_event(action=f"gate.submission_{status}", actor=actor, target=submission,
                 metadata={"link": link.path, "via": via}, request=request)
    if remember:
        if learn_from_decision(link, submission, verdict):
            notify("gates", {
                "title": "Decision learned",
                "detail": f"{link.path}: future matching submissions will be auto-{status}.",
            })
            record_event(action="gate.decision_learned", actor=actor, target=link,
                         metadata={"submission": submission.pk, "verdict": verdict},
                         request=request)
    return submission


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("pwndrop source attempted to redirect; refusing to follow.")


def _fetch_pwndrop(url, timeout=None):
    """Server-side fetch; the pwndrop location is never visible to the client."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("pwndrop source must be an http(s) URL.")
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": settings.OUTBOUND_USER_AGENT})
    with opener.open(request, timeout=timeout or getattr(settings, "PWNDROP_TIMEOUT", 10)) as response:
        length = response.headers.get("Content-Length")
        max_bytes = getattr(settings, "PWNDROP_MAX_BYTES", 512 * 1024 * 1024)
        if length and int(length) > max_bytes:
            raise RuntimeError("pwndrop object exceeds the configured size cap.")
        chunks, read = [], 0
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            read += len(chunk)
            if read > max_bytes:
                raise RuntimeError("pwndrop object exceeds the configured size cap.")
            chunks.append(chunk)
    return b"".join(chunks), response.headers.get_content_type()


def build_watermark(link):
    """Unique per-release marker; the exact value lands in the download HitEvent."""
    import secrets
    return f"{getattr(settings, 'WATERMARK_PREFIX', 'ROFWM')}:{link.pk}:{link.hit_count + 1}:{secrets.token_hex(8)}"


def _mark_served(link):
    """Block undo once content has been released after a decision."""
    latest = link.submissions.exclude(decided_at__isnull=True).order_by("-decided_at").first()
    if latest is not None and not latest.served_after_decision:
        latest.served_after_decision = True
        latest.save(update_fields=["served_after_decision"])


def _safe_filename(name):
    import re
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120]
    cleaned = cleaned.lstrip(".").replace("..", "__")
    return cleaned or "download.bin"


def range_aware_response(request, content, *, filename=None, content_type="application/octet-stream"):
    """Uniform HTTP Range support for everything the gate serves.

    nginx answers ranges on its static decoy pages, so the gated content must
    too; the asymmetry between response types is itself a fingerprint.
    """
    if isinstance(content, str):
        content = content.encode()
    total = len(content)
    range_header = request.headers.get("Range", "")
    if range_header.startswith("bytes="):
        try:
            start_s, _, end_s = range_header[6:].partition("-")
            start = int(start_s) if start_s else 0
            end = int(end_s) if end_s else total - 1
            if start > end or start >= total or start < 0:
                raise ValueError("bad range")
            end = min(end, total - 1)
        except ValueError:
            response = HttpResponse(status=416)
            response["Content-Range"] = f"bytes */{total}"
            return response
        response = HttpResponse(content[start:end + 1], status=206, content_type=content_type)
        response["Content-Range"] = f"bytes {start}-{end}/{total}"
    else:
        response = HttpResponse(content, content_type=content_type)
    response["Accept-Ranges"] = "bytes"
    if filename:
        response["Content-Disposition"] = f'attachment; filename="{_safe_filename(filename)}"'
        response["X-Content-Type-Options"] = "nosniff"
    return response


def serve_link(link, request):
    """Release content for an approved/ungated link."""
    marker = build_watermark(link) if link.watermark else ""
    if link.kind == "key":
        if not link.register_release():
            record_hit("expired", request=request, path=link.path, link=link, status_code=410)
            return HttpResponse(status=410)
        _mark_served(link)
        record_hit("key_served", request=request, path=link.path, link=link,
                   detail={"watermark": marker} if marker else {})
        notify("gates", {"title": "Key retrieved", "detail": f"{link.path} served its key ({link.hit_count} use(s))."})
        key_text = link.key_text + (f"\n{marker}\n" if marker else "")
        return range_aware_response(
            request,
            render_to_string("gates/key.html", {"link": link, "key_text": key_text}),
            content_type="text/html",
        )

    try:
        content, filename, content_type = _link_content(link)
    except (RuntimeError, OSError):
        logger.exception("failed to serve %s", link.path)
        record_hit("suspicious", request=request, path=link.path, link=link,
                   status_code=502, detail={"reason": "serve failed"})
        return HttpResponse(status=502)
    if link.serve_as:
        # Masquerade: the stored/uploaded name stays internal; the visitor
        # gets the operator-chosen filename (e.g. fwfafs.exe -> helper.pdf.exe).
        filename = link.serve_as
        detail_masquerade = {"served_as": _safe_filename(filename)}
    else:
        detail_masquerade = {}
    if not link.register_release():
        record_hit("expired", request=request, path=link.path, link=link, status_code=410)
        return HttpResponse(status=410)
    _mark_served(link)
    filename = _safe_filename(filename)
    if marker:
        content = content + b"\n" + marker.encode() + b"\n"
    detail = {"bytes": len(content), "filename": filename}
    detail.update(detail_masquerade)
    if marker:
        detail["watermark"] = marker
    record_hit("download", request=request, path=link.path, link=link, detail=detail)
    notify("gates", {
        "title": "Gated download released",
        "detail": f"{link.path} released '{filename}' ({len(content)} bytes, use {link.hit_count}).",
    })
    return range_aware_response(request, content, filename=filename,
                                content_type=content_type or "application/octet-stream")


def _link_content(link):
    if link.kind == "proxy":
        if not link.pwndrop_url:
            raise RuntimeError("proxy link is missing its source URL.")
        data, content_type = _fetch_pwndrop(link.pwndrop_url)
        filename = link.pwndrop_url.rstrip("/").rsplit("/", 1)[-1] or "download.bin"
        return data, filename[:120], content_type
    if link.payload:
        with link.payload.open("rb") as handle:
            return handle.read(), link.payload.name.rsplit("/", 1)[-1], "application/octet-stream"
    raise RuntimeError("file link has no payload attached.")


def dispatch(request, path):
    """Public entry point called from the 404 handler for untracked paths.

    Returns an HttpResponse for paths the gate system owns, or None to fall
    through to the stock 404 page.
    """
    ip = client_ip(request)
    if ip and BannedIP.is_banned(ip):
        record_hit("banned", request=request, path=path, status_code=200)
        return _decoy(request)

    normalized = path if path.startswith("/") else f"/{path}"
    canary_base = f"{getattr(settings, 'GATE_BASE_PATH', '/g/')}canary/"
    if normalized.startswith(canary_base):
        token = normalized[len(canary_base):].split(".")[0]
        return canary_response(request, token)

    link = DeliveryLink.objects.filter(path=normalized).first()
    if link is None:
        agent = AgentChannel.objects.filter(token=normalized.rsplit("/", 1)[-1], active=True).first()
        if agent is not None and normalized == agent.path:
            agent.hits += 1
            agent.last_seen_at = timezone.now()
            agent.save(update_fields=["hits", "last_seen_at"])
            record_hit("hit", request=request, path=normalized, agent_channel=agent,
                       detail={"label": agent.label})
        # Hosted content: lure sites and decoy asset bundles. Unknown slugs and
        # missing assets fall through to the normal not-found handling below.
        lure_base = getattr(settings, "LURE_BASE_PATH", "/l/")
        if normalized.startswith(lure_base):
            response = serve_lure(request, normalized[len(lure_base):])
            if response is not None:
                return response
        if normalized.startswith("/d/"):
            response = serve_decoy_asset(request, normalized[len("/d/"):])
            if response is not None:
                return response
        decision = evaluate_blocking_rules(request, ip, is_404=True)
        if decision is not None:
            rule, fired = decision
            response = apply_blocking_rule(request, ip, rule, fired)
            if response is not None:
                return response
        record_hit("not_found", request=request, path=path, status_code=404)
        # Public responses are 200 decoys; the 404 semantics live in the
        # analytics record, not in what the visitor sees.
        try:
            from analytics.models import NotFoundEvent
            NotFoundEvent.objects.get_or_create(
                request_id=getattr(request, "request_id", "")[:64] or "nofid-" + hashlib.sha256(path.encode()).hexdigest()[:56],
                defaults={
                    "occurred_at": timezone.now(),
                    "method": request.method[:10].upper(),
                    "path": path[:8192],
                    "status": 404,
                    "source_ip": ip or None,
                    "source_ip_hash": hash_address(ip),
                    "user_agent": request.META.get("HTTP_USER_AGENT", "")[:1000],
                })
        except Exception:
            logger.exception("failed to write synthetic 404 record")
        return None

    decision = evaluate_blocking_rules(request, ip, is_404=False, link=link)
    if decision is not None:
        rule, fired = decision
        response = apply_blocking_rule(request, ip, rule, fired)
        if response is not None:
            return response

    if not link.available:
        record_hit("expired", request=request, path=normalized, link=link, status_code=410)
        return HttpResponse(status=410)

    record_hit("hit", request=request, path=normalized, link=link)

    passed, gate_reason = gate_passed(link, request)
    if not passed:
        record_hit("suspicious", request=request, path=normalized, link=link, status_code=403,
                   detail={"reason": gate_reason or f"gate '{link.gate_type}' not satisfied"})
        return hold_response(link, request)

    if (link.ja3_fingerprint or link.ja4_fingerprint) and not fingerprint_passed(link, request):
        record_hit("suspicious", request=request, path=normalized, link=link, status_code=403,
                   detail={"reason": "JA3/JA4 fingerprint mismatch"})
        return hold_response(link, request)

    if link.replay_dedupe:
        digest = _request_digest(request, normalized)
        horizon = timezone.now() - timezone.timedelta(days=7)
        SeenRequest.objects.filter(link=link, created_at__lt=horizon).delete()
        from django.db import IntegrityError, transaction
        try:
            with transaction.atomic():
                SeenRequest.objects.create(link=link, digest=digest)
        except IntegrityError:
            record_hit("suspicious", request=request, path=normalized, link=link,
                       status_code=403, detail={"reason": "replayed request"})
            return hold_response(link, request)

    if link.gate_type == "submission" and request.method == "POST":
        return handle_submission(link, request)

    if link.requires_approval:
        if link.approval_status == "denied":
            return gate_denied_response(link, request)
        if link.approval_status != "approved":
            return hold_response(link, request)

    if link.serve_den > 1:
        # Probabilistic serving: N of every M passing requests get the payload,
        # the rest see the held view. Failed rolls never consume uses.
        import secrets
        if secrets.randbelow(link.serve_den) >= link.serve_num:
            record_hit("hit", request=request, path=normalized, link=link,
                       detail={"chance_roll": f"{link.serve_num}/{link.serve_den}", "served": False})
            return hold_response(link, request)

    try:
        return serve_link(link, request)
    except (RuntimeError, OSError) as exc:
        logger.exception("failed to serve %s", link.path)
        record_hit("suspicious", request=request, path=normalized, link=link,
                   status_code=502, detail={"reason": "serve failed", "error": str(exc)[:200]})
        return HttpResponse(status=502)


def undo_decision(submission, actor):
    """Revert an approve/deny within the undo window, before any release.

    Returns (ok, error_message).
    """
    if submission.status == "pending":
        return False, "Submission has no decision to undo."
    window = getattr(settings, "DECISION_UNDO_SECONDS", 10)
    age = (timezone.now() - submission.decided_at).total_seconds() if submission.decided_at else None
    if age is None or age > window:
        return False, f"Undo window ({window}s) has expired."
    if submission.served_after_decision:
        return False, "Content was already released; the decision is final."
    if submission.decided_by_id and actor is not None and submission.decided_by_id != actor.pk:
        from accounts.permissions import is_administrator
        if not is_administrator(actor):
            return False, "Only the deciding operator or an administrator can undo."
    link = submission.link
    submission.status = "pending"
    submission.decided_by = None
    submission.decided_at = None
    submission.save(update_fields=["status", "decided_by", "decided_at"])
    # Recompute the link state from the remaining decisions instead of
    # assuming this submission was the one driving it.
    latest = link.submissions.exclude(decided_at__isnull=True).order_by("-decided_at").first()
    link.approval_status = latest.status if latest is not None else "pending"
    link.decided_by = latest.decided_by if latest is not None else None
    link.decided_at = latest.decided_at if latest is not None else None
    link.save(update_fields=["approval_status", "decided_by", "decided_at"])
    record_hit("hit", path=link.path, link=link, detail={"undo": submission.pk})
    return True, ""


def burn_link(link, *, actor, request=None):
    """Burn a link: stop serving content, deny all, ban every visitor IP except
    the approved target's. Returns (bans_created, banned_ips)."""
    link.active = False
    if link.requires_approval:
        link.approval_status = "denied"
    link.save(update_fields=["active", "approval_status"])

    keep = None
    decided = link.submissions.filter(status="approved", raw_ip__isnull=False).order_by("-decided_at").first()
    if decided is not None:
        keep = decided.raw_ip

    burner = client_ip(request) if request is not None else ""
    ips, seen = [], set()
    for ip in link.hit_events.exclude(raw_ip__isnull=True).values_list("raw_ip", flat=True).distinct():
        if ip and ip != keep and ip != burner and not _is_loopback(ip) and ip not in seen and not BannedIP.is_banned(ip):
            seen.add(ip)
            ips.append(ip)
    created = [BannedIP.objects.get_or_create(
        ip=ip, defaults={"note": f"burn notice for {link.path}", "auto_created": True,
                         "created_by": actor})[0] for ip in ips]
    try:
        sync_nginx_files()
    except OSError as exc:
        logger.warning("nginx ban sync failed after burn of %s: %s", link.path, exc)
    record_hit("suspicious", path=link.path, link=link, status_code=200,
               detail={"burn_notice": True, "banned": len(created), "kept": keep})
    notify("suspicious", {
        "title": "Link burned",
        "detail": f"{link.path} was burned by {actor.username if actor else 'system'}: "
                  f"{len(created)} IP(s) banned, approved target preserved." if keep else
                  f"{link.path} was burned by {actor.username if actor else 'system'}: {len(created)} IP(s) banned.",
    })
    record_event(action="gate.link_burned", actor=actor, target=link,
                 metadata={"banned": len(created), "kept": keep}, request=request)
    return len(created), ips


def fingerprint_passed(link, request) -> bool:
    """JA3/JA4 enforcement. The hashes must arrive as headers from an OpenResty
    fingerprint front layer; when the front layer is absent the headers are
    empty and fingerprint-gated links refuse to serve."""
    ok = True
    if link.ja3_fingerprint:
        ok = request.headers.get("X-JA3-Fingerprint", "") == link.ja3_fingerprint
    if ok and link.ja4_fingerprint:
        ok = request.headers.get("X-JA4-Fingerprint", "") == link.ja4_fingerprint
    return ok


# ─── Blocking rules ───────────────────────────────────────────────────────────

_intel_cache = {}


def get_ip_intel(ip):
    """Cached ASN/ISP/geo lookup for an address (best-effort).

    Successful responses are stored in the database; failures are not, so a
    later request retries. Rules with intel conditions only fire when data
    exists - treat them as opportunistic.
    """
    if not ip:
        return None
    if ip in _intel_cache:
        return _intel_cache[ip]
    intel = IPIntel.objects.filter(ip=ip).first()
    if intel is None and getattr(settings, "IP_INTEL_ENABLED", True):
        intel = _fetch_ip_intel(ip)
    _intel_cache[ip] = intel
    return intel


def _fetch_ip_intel(ip):
    fields = "status,message,countryCode,city,isp,org,as,query"
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": settings.OUTBOUND_USER_AGENT})
        with urllib.request.urlopen(request, timeout=getattr(settings, "IP_INTEL_TIMEOUT", 2.5)) as response:
            payload = json.loads(response.read().decode())
    except (OSError, ValueError):
        return None
    if payload.get("status") != "success" or payload.get("query") != ip:
        return None
    asn, _, org = str(payload.get("as", "")).partition(" ")
    return IPIntel.objects.create(
        ip=ip,
        asn=asn.upper().removeprefix("AS").strip(),
        org=(org or payload.get("isp", ""))[:200],
        country_code=str(payload.get("countryCode", ""))[:2].upper(),
        city=str(payload.get("city", ""))[:120],
        source="ip-api.com",
    )


@functools.lru_cache(maxsize=256)
def _compiled_pattern(pattern):
    return re.compile(pattern)


def _condition_value(condition_type, ip, user_agent, intel):
    if condition_type == "ip":
        return ip
    if condition_type == "ua":
        return user_agent
    if intel is None:
        return None
    return {
        "asn": intel.asn,
        "isp": intel.org,
        "country": intel.country_code.upper(),
        "city": intel.city,
    }.get(condition_type)


def _cidr_matches(pattern, ip):
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False


def rule_matches(rule, *, ip, user_agent, intel):
    """Evaluate one rule. Returns (matched, fired_conditions).

    A condition whose value is unavailable (missing intel enrichment) makes
    the whole rule indeterminate: it never fires under ANY logic, because
    "NOT unknown" must not mean "match everything".
    """
    results, fired, undetermined = [], [], False
    for condition in rule.conditions or []:
        if condition.get("type") == "cidr":
            matched = _cidr_matches(condition.get("pattern", ""), ip)
        else:
            value = _condition_value(condition.get("type"), ip, user_agent, intel)
            if value is None or value == "":
                undetermined = True
                continue
            try:
                matched = _compiled_pattern(condition["pattern"]).search(str(value)[:1000]) is not None
            except re.error:
                matched = False
        if condition.get("negate"):
            matched = not matched
        results.append(matched)
        if matched:
            fired.append(condition.get("type"))
    if not results:
        return False, fired
    if rule.logic == "any":
        # A determined match decides the rule; unknowns cannot confirm a
        # non-match.
        return any(results), fired
    # all / not / xor need every condition evaluable: "all matched", "none
    # matched", and "exactly one matched" are all unprovable while any input
    # is unknown.
    if undetermined:
        return False, fired
    if rule.logic == "all":
        return all(results), fired
    if rule.logic == "xor":
        return sum(1 for m in results if m) == 1, fired
    return not any(results), fired


def evaluate_blocking_rules(request, ip, *, is_404=False, link=None):
    """Walk the ruleset chain for this request context; first match wins.

    Returns (rule, fired) or None. Sets are ordered; within a set rules are
    ordered. Set scopes: everything / 404s only / a specific delivery link.
    An ALLOW match stops the chain and lets the request through.
    """
    from .models import RuleSet
    sets = list(RuleSet.objects.filter(enabled=True).prefetch_related("rules"))
    loose_rules = list(BlockingRule.objects.filter(enabled=True, ruleset__isnull=True))
    if not sets and not loose_rules:
        return None
    user_agent = request.META.get("HTTP_USER_AGENT", "")[:1000]
    candidate_rules = [r for s in sets for r in s.rules.all() if r.enabled] + loose_rules
    needs_intel = any({c.get("type") for c in r.conditions} & {"asn", "isp", "country", "city"}
                      for r in candidate_rules)
    intel = get_ip_intel(ip) if (needs_intel and ip) else _intel_cache.get(ip)
    for ruleset in sets:
        if ruleset.scope == "not_found" and not is_404:
            continue
        if ruleset.scope == "link" and (link is None or ruleset.link_id != link.pk):
            continue
        for rule in [r for r in ruleset.rules.all() if r.enabled]:
            matched, fired = rule_matches(rule, ip=ip, user_agent=user_agent, intel=intel)
            if matched:
                return rule, fired
    for rule in loose_rules:
        matched, fired = rule_matches(rule, ip=ip, user_agent=user_agent, intel=intel)
        if matched:
            return rule, fired
    return None


def apply_blocking_rule(request, ip, rule, fired):
    BlockingRule.objects.filter(pk=rule.pk).update(match_count=F("match_count") + 1)
    detail = {"rule": rule.name, "action": rule.action, "fired": fired, "auto_ban": rule.auto_ban}
    if rule.action == "allow":
        logger.info("rule '%s' allowed %s (%s)", rule.name, ip, ", ".join(fired))
        return None
    if rule.auto_ban and ip and not _is_loopback(ip):
        ban, created = BannedIP.objects.get_or_create(
            ip=ip, defaults={"note": f"auto-ban by rule '{rule.name}'", "auto_created": True})
        detail["banned"] = created or ban.active
        try:
            sync_nginx_files()
        except OSError as exc:
            logger.warning("nginx ban sync failed after rule auto-ban of %s: %s", ip, exc)
    record_hit("blocked", request=request, path=request.path, status_code=200, detail=detail)
    logger.info("blocked %s by rule '%s' (%s)", ip, rule.name, ", ".join(fired))
    return _decoy(request)


# ─── Rule export / import ──────────────────────────────────────────────────

def export_blocking_rules():
    from .models import RuleSet
    sets = []
    for ruleset in RuleSet.objects.prefetch_related("rules"):
        sets.append({
            "name": ruleset.name, "scope": ruleset.scope,
            "link_path": ruleset.link.path if ruleset.link else None,
            "enabled": ruleset.enabled, "order": ruleset.order,
            "rules": [{
                "name": r.name, "action": r.action, "logic": r.logic,
                "conditions": r.conditions, "enabled": r.enabled,
                "auto_ban": r.auto_ban, "order": r.order, "preset": r.preset,
            } for r in ruleset.rules.all()],
        })
    loose = BlockingRule.objects.filter(ruleset__isnull=True)
    return {
        "format": "rof-blocking-rules", "version": 1,
        "sets": sets,
        "loose_rules": [{
            "name": r.name, "action": r.action, "logic": r.logic,
            "conditions": r.conditions, "enabled": r.enabled,
            "auto_ban": r.auto_ban, "order": r.order, "preset": r.preset,
        } for r in loose],
    }


def import_blocking_rules(payload, *, actor=None):
    """Import an export payload. Returns (sets_created, rules_created, errors).

    Name collisions get an "(imported)" suffix; link-scoped sets match links
    by path. Imported rules are created DISABLED unless the payload says
    otherwise; presets are skipped (already present).
    """
    from .models import RuleSet
    errors, sets_created, rules_created = [], 0, 0
    if not isinstance(payload, dict) or payload.get("format") != "rof-blocking-rules":
        return 0, 0, ["not a rof-blocking-rules export"]
    for entry in payload.get("sets", []):
        name = str(entry.get("name", "imported set"))[:120]
        if RuleSet.objects.filter(name=name).exists():
            name = f"{name} (imported)"
        link = None
        if entry.get("scope") == "link" and entry.get("link_path"):
            link = DeliveryLink.objects.filter(path=entry["link_path"]).first()
            if link is None:
                errors.append(f"set '{name}': link {entry['link_path']} not found; set skipped")
                continue
        try:
            ruleset = RuleSet.objects.create(
                name=name, scope=entry.get("scope", "all"), link=link,
                enabled=bool(entry.get("enabled", True)), order=int(entry.get("order", 0)))
        except Exception as exc:
            errors.append(f"set '{name}': {exc}")
            continue
        sets_created += 1
        for rule_entry in entry.get("rules", []):
            if rule_entry.get("preset"):
                continue
            try:
                BlockingRule.objects.create(
                    ruleset=ruleset, name=str(rule_entry.get("name", "imported rule"))[:120],
                    action=rule_entry.get("action", "block"), logic=rule_entry.get("logic", "all"),
                    conditions=rule_entry.get("conditions", []),
                    enabled=False,  # imports always land disabled; review before enabling
                    auto_ban=bool(rule_entry.get("auto_ban", False)),
                    order=int(rule_entry.get("order", 0)), created_by=actor)
                rules_created += 1
            except Exception as exc:
                errors.append(f"rule '{rule_entry.get('name')}': {exc}")
    for rule_entry in payload.get("loose_rules", []):
        if rule_entry.get("preset"):
            continue
        name = str(rule_entry.get("name", "imported rule"))[:120]
        if BlockingRule.objects.filter(name=name, ruleset__isnull=True).exists():
            name = f"{name} (imported)"
        try:
            BlockingRule.objects.create(
                ruleset=None, name=name, action=rule_entry.get("action", "block"),
                logic=rule_entry.get("logic", "all"), conditions=rule_entry.get("conditions", []),
                enabled=False,  # imports always land disabled; review before enabling
                auto_ban=bool(rule_entry.get("auto_ban", False)),
                order=int(rule_entry.get("order", 0)), created_by=actor)
            rules_created += 1
        except Exception as exc:
            errors.append(f"rule '{rule_entry.get('name')}': {exc}")
    return sets_created, rules_created, errors


# Decoy canaries.
import base64 as _b64
import hmac as _hmac
import time as _time

CANARY_GIF = _b64.b64decode(
    "R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=="
)


def canary_token(ip, day=None):
    """HMAC-derived per-visitor token; verifiable for ~72h without server state."""
    day = day if day is not None else int(_time.time() // 86400)
    digest = _hmac.new(settings.SECRET_KEY.encode(), f"canary:{ip}:{day}".encode(),
                       hashlib.sha256).hexdigest()
    return digest[:24]


def verify_canary_token(request, token):
    """A canary is valid when recomputing the token for this visitor's address
    across the last three days matches. Both valid hits (someone re-fetched the
    pixel path later) and forgeries are suspicious; the event detail tells them
    apart. A 1x1 GIF is always returned so the response is not an oracle."""
    ip = client_ip(request)
    today = int(_time.time() // 86400)
    if not token or len(token) > 64:
        return False
    return any(_hmac.compare_digest(canary_token(ip, day), token)
               for day in range(today - 2, today + 1))


def canary_response(request, token):
    known = verify_canary_token(request, token)
    # A valid re-hit is expected decoy traffic, not an attack; only forged or
    # stale tokens count toward suspicious activity (and auto-ban).
    record_hit("canary" if known else "suspicious", request=request,
               path=f"canary:{token[:16]}", status_code=200,
               detail={"canary": "valid-token-rehit" if known else "forged-or-stale-token"})
    return HttpResponse(CANARY_GIF, content_type="image/gif")


def sync_nginx_files():
    """Write nginx include files for bans and agent routes when paths are configured.

    Banned IPs get the default page from the app via the 404 handler anyway;
    the nginx-level deny is a performance belt-and-suspenders layer.
    """
    written = {}
    ban_path = getattr(settings, "NGINX_BAN_INCLUDE", "")
    if ban_path:
        lines = ["# generated by gates.services.sync_nginx_files - do not edit"]
        for ban in BannedIP.objects.filter(active=True):
            lines.append(f"deny {ban.ip};")
        written[ban_path] = _write_atomic(ban_path, "\n".join(lines) + "\n")
    agent_path = getattr(settings, "NGINX_AGENT_ROUTES_INCLUDE", "")
    if agent_path:
        lines = ["# generated by gates.services.sync_nginx_files - do not edit"]
        for agent in AgentChannel.objects.filter(active=True):
            lines.append(f"location = {agent.path} {{")
            if agent.ua_pattern:
                lines.append(f"    if ($http_user_agent !~* \"{agent.ua_pattern}\") {{ return 404; }}")
            lines.append("    limit_req zone=beacon burst=20 nodelay;")
            lines.append("    proxy_pass http://c2_backend;")
            lines.append("    proxy_redirect off;")
            lines.append("    proxy_set_header Host $host;")
            lines.append("    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
            lines.append("    proxy_set_header X-Real-IP $remote_addr;")
            lines.append("    proxy_hide_header X-Powered-By;")
            lines.append("    proxy_hide_header Server;")
            lines.append("    proxy_hide_header Via;")
            lines.append("}")
        written[agent_path] = _write_atomic(agent_path, "\n".join(lines) + "\n")
    return written


def _write_atomic(target, content):
    import os
    import tempfile
    directory = os.path.dirname(target)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".sync_", suffix=".conf")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
        os.replace(tmp, target)
        return True
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
