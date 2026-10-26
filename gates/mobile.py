"""Touch-first mobile operator interface under /m/."""
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from audit.services import record_event

from . import services
from .models import DeliveryLink, HitEvent, Submission, SubmissionImage


@login_required
def submissions(request):
    queryset = Submission.objects.select_related("link", "decided_by").filter(status="pending")
    paginator = Paginator(queryset, 10)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "mobile/submissions.html", {
        "title": "Approvals", "page": page, "submissions": page.object_list,
        "undo_seconds": getattr(settings, "DECISION_UNDO_SECONDS", 10),
    })


@login_required
def submission_detail(request, pk):
    submission = get_object_or_404(
        Submission.objects.select_related("link", "decided_by", "note_by"), pk=pk)
    if request.method == "POST":
        action = request.POST.get("action", "")
        if action in {"approve", "deny"}:
            services.decide_submission(submission, action, actor=request.user, via="mobile", request=request)
            return redirect("m-submissions")
        if action == "undo":
            services.undo_decision(submission, request.user)
            return redirect("m-submission", pk=pk)
        if action == "note":
            note = request.POST.get("note", "")[:4000]
            submission.note = note
            submission.note_by = request.user if note else None
            submission.note_at = timezone.now() if note else None
            submission.save(update_fields=["note", "note_by", "note_at"])
            record_event(action="gate.submission_noted", actor=request.user, target=submission, request=request)
            return redirect("m-submission", pk=pk)
    decided = Submission.objects.filter(link=submission.link).exclude(pk=submission.pk)[:5]
    return render(request, "mobile/submission_detail.html", {
        "title": f"#{submission.pk}", "s": submission, "images": submission.images.all(),
        "siblings": decided,
    })


@login_required
def links(request):
    paginator = Paginator(DeliveryLink.objects.all(), 15)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "mobile/links.html", {"title": "Links", "page": page, "links": page.object_list})


@login_required
@transaction.atomic
def link_detail(request, pk):
    link = get_object_or_404(DeliveryLink, pk=pk)
    if request.method == "POST":
        action = request.POST.get("action", "")
        if action == "burn":
            services.burn_link(link, actor=request.user, request=request)
            return redirect("m-link", pk=pk)
        if action == "toggle":
            link.active = not link.active
            link.save(update_fields=["active"])
            return redirect("m-link", pk=pk)
    return render(request, "mobile/link_detail.html", {
        "title": link.path, "link": link,
        "hits": link.hit_events.all()[:15],
        "submissions": link.submissions.select_related("decided_by")[:8],
    })


@login_required
def events(request):
    paginator = Paginator(HitEvent.objects.select_related("link", "agent_channel"), 25)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "mobile/events.html", {"title": "Events", "page": page, "events": page.object_list})


@login_required
def intel(request):
    """Gate imagery as a touch-friendly gallery."""
    images = SubmissionImage.objects.select_related("submission__link").order_by("-created_at")
    paginator = Paginator(images, 20)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "mobile/intel.html", {
        "title": "Intel", "page": page, "images": page.object_list,
    })
