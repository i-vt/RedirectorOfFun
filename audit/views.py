from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render
from .models import AuditEvent


@login_required
def audit_log(request):
    events = AuditEvent.objects.select_related("actor").all()
    action = request.GET.get("action", "").strip()
    if action:
        events = events.filter(action__icontains=action[:100])
    page = Paginator(events, 50).get_page(request.GET.get("page"))
    return render(request, "panel/audit.html", {"title": "Audit Log", "page": page, "events": page.object_list})
