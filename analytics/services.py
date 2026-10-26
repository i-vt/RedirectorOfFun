import hashlib
import json
from datetime import timedelta
from django.conf import settings
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from .models import NotFoundEvent


def hash_address(address):
    if not address:
        return ""
    return hashlib.sha256(f"{settings.ANALYTICS_IP_HASH_SALT}:{address}".encode()).hexdigest()


def event_from_record(record, raw_line="", track_all=None):
    from gates.crypto_utils import sanitize_text
    status = int(record.get("status", 0) or 0)
    if track_all is None:
        track_all = getattr(settings, "TRACK_ALL_REQUESTS", False)
    if not track_all and status != 404:
        return None
    request_id = str(record.get("request_id") or hashlib.sha256(raw_line.encode()).hexdigest())[:64]
    occurred_at = parse_datetime(str(record.get("time", ""))) or timezone.now()
    if timezone.is_naive(occurred_at):
        occurred_at = timezone.make_aware(occurred_at, timezone.utc)
    remote_addr = str(record.get("remote_addr", ""))[:64]
    return NotFoundEvent(
        request_id=request_id,
        occurred_at=occurred_at,
        method=str(record.get("method", "GET"))[:10].upper(),
        path=sanitize_text(str(record.get("path", record.get("uri", "/"))), 8192),
        status=status,
        source_ip=remote_addr or None,
        source_ip_hash=hash_address(remote_addr),
        user_agent=sanitize_text(str(record.get("user_agent", ""))),
        country_code=str(record.get("country_code", ""))[:2].upper(),
        city=str(record.get("city", ""))[:100],
    )


def dashboard_statistics(days=14):
    now = timezone.now()
    since = now - timedelta(days=days)
    queryset = NotFoundEvent.objects.all()
    recent = queryset.filter(occurred_at__gte=since)
    daily = list(recent.annotate(day=TruncDate("occurred_at")).values("day").annotate(count=Count("id")).order_by("day"))
    counts = {item["day"].isoformat(): item["count"] for item in daily}
    series = []
    for offset in range(days - 1, -1, -1):
        day = (now - timedelta(days=offset)).date()
        series.append({"day": day.isoformat(), "label": day.strftime("%d %b"), "count": counts.get(day.isoformat(), 0)})
    return {
        "total": queryset.count(),
        "today": queryset.filter(occurred_at__date=now.date()).count(),
        "period": recent.count(),
        "unique_paths": recent.values("path").distinct().count(),
        "top_paths": list(recent.values("path").annotate(count=Count("id")).order_by("-count")[:6]),
        "series": series,
    }
