from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.db import transaction
from audit.services import record_event
from .models import NotificationOutbox, NotificationPreference


@login_required
@transaction.atomic
def settings_view(request):
    preferences = { (p.event_type, p.channel): p for p in NotificationPreference.objects.filter(operator=request.user) }
    if request.method == "POST":
        if request.POST.get("action") == "theme":
            theme = request.POST.get("theme", "default")
            if theme in dict(request.user.THEME_CHOICES):
                request.user.theme = theme
                request.user.save(update_fields=["theme"])
                record_event(action="operator.theme_changed", actor=request.user, target=request.user,
                             metadata={"theme": theme}, request=request)
                messages.success(request, "Interface theme updated.")
            return redirect("settings")
        for event_type, _ in NotificationPreference.EVENT_CHOICES:
            for channel, _ in NotificationPreference.CHANNEL_CHOICES:
                key = f"pref-{event_type}-{channel}"
                preference, _ = NotificationPreference.objects.get_or_create(
                    operator=request.user, event_type=event_type, channel=channel,
                )
                preference.enabled = key in request.POST
                preference.save(update_fields=["enabled"])
        record_event(action="notification.preferences_updated", actor=request.user, target=request.user, request=request)
        return redirect("settings")
    preference_matrix = []
    for event_type, label in NotificationPreference.EVENT_CHOICES:
        channels = []
        for channel, channel_label in NotificationPreference.CHANNEL_CHOICES:
            preference = preferences.get((event_type, channel))
            channels.append({"channel": channel, "label": channel_label, "enabled": preference.enabled if preference else channel == "panel" and event_type != "analytics"})
        preference_matrix.append({"event_type": event_type, "label": label, "channels": channels})
    return render(request, "panel/settings.html", {
        "title": "Settings",
        "event_choices": NotificationPreference.EVENT_CHOICES,
        "channel_choices": NotificationPreference.CHANNEL_CHOICES,
        "preference_matrix": preference_matrix,
        "recent_notifications": NotificationOutbox.objects.filter(recipient=request.user)[:8],
        "theme": request.user.theme,
        "theme_choices": request.user.THEME_CHOICES,
    })


@login_required
def dismiss_notification(request, pk):
    if request.method == "POST":
        NotificationOutbox.objects.filter(pk=pk, recipient=request.user).delete()
    return redirect(request.META.get("HTTP_REFERER", "overview"))
