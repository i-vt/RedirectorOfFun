import json
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render
from django.utils import timezone
from audit.models import AuditEvent
from notifications.models import NotificationOutbox
from .models import CollectorState, NotFoundEvent
from .services import dashboard_statistics


@login_required
def overview(request):
    from gates.models import BannedIP, DeliveryLink, HitEvent, Submission
    stats = dashboard_statistics(14)
    return render(request, "panel/overview.html", {
        "title": "Overview", "stats": stats, "stats_json": stats["series"],
        "recent_events": NotFoundEvent.objects.all()[:6],
        "recent_audit": AuditEvent.objects.select_related("actor")[:5],
        "notifications": NotificationOutbox.objects.filter(recipient=request.user)[:5],
        "collector_state": CollectorState.objects.order_by("-updated_at").first(),
        "now": timezone.now(),
        "gate_summary": {
            "active_links": DeliveryLink.objects.filter(active=True).count(),
            "pending_approvals": Submission.objects.filter(status="pending").count(),
            "releases_24h": HitEvent.objects.filter(
                category__in=["download", "key_served"],
                created_at__gte=timezone.now() - timezone.timedelta(hours=24)).count(),
            "suspicious_24h": HitEvent.objects.filter(
                category="suspicious",
                created_at__gte=timezone.now() - timezone.timedelta(hours=24)).count(),
            "banned_ips": BannedIP.objects.filter(active=True).count(),
        },
    })


def filtered_events(request):
    from django.db.models import Q
    events = NotFoundEvent.objects.all()
    path = request.GET.get("path", "").strip()
    method = request.GET.get("method", "").strip().upper()
    days = request.GET.get("days", "30")
    ua = request.GET.get("ua", "").strip()
    ip = request.GET.get("ip", "").strip()
    client = request.GET.get("client", "").strip()
    if path:
        events = events.filter(path__icontains=path[:200])
    if method in {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"}:
        events = events.filter(method=method)
    if ua:
        events = events.filter(user_agent__icontains=ua[:200])
    if ip:
        events = events.filter(Q(source_ip=ip) | Q(source_ip_hash=ip))
    if client:
        events = events.filter(Q(source_ip=client) | Q(source_ip_hash=client))
    if days.isdigit() and 1 <= int(days) <= 365:
        events = events.filter(occurred_at__gte=timezone.now() - timezone.timedelta(days=int(days)))
    status_class = request.GET.get("status_class", "").strip()
    if status_class in {"2", "3", "4", "5"}:
        low = int(status_class) * 100
        events = events.filter(status__gte=low, status__lte=low + 99)
    return events


@login_required
def events_view(request):
    paginator = Paginator(filtered_events(request), 40)
    page = paginator.get_page(request.GET.get("page"))
    intel = {}
    ips = [e.source_ip for e in page.object_list if e.source_ip]
    if ips:
        from gates.models import IPIntel
        intel = {i.ip: i for i in IPIntel.objects.filter(ip__in=ips)}
    template = "panel/_events_table.html" if request.headers.get("HX-Request") else "panel/events.html"
    return render(request, template, {
        "title": "404 Events", "page": page, "events": page.object_list,
        "intel": intel,
        "show_identifiers": request.GET.get("identifiers") == "1",
        "track_all": getattr(settings, "TRACK_ALL_REQUESTS", False),
    })


@login_required
def health_view(request):
    collector = CollectorState.objects.order_by("-updated_at").first()
    return render(request, "panel/health.html", {
        "title": "Service health", "collector": collector,
        "database_ready": True, "event_count": NotFoundEvent.objects.count(),
    })
