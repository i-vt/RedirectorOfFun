from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.db import transaction
from audit.services import record_event
from gates.models import GateConfig
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
        if request.POST.get("action") == "gate_style":
            style = request.POST.get("totp_style", "hex8")
            if style in dict(GateConfig.TOTP_STYLE_CHOICES):
                config = GateConfig.get_solo()
                config.totp_style = style
                config.save(update_fields=["totp_style"])
                record_event(action="gate.totp_style_changed", actor=request.user, target=config,
                             metadata={"totp_style": style}, request=request)
                messages.success(request, "Gate code format updated; reissue in-flight links.")
            return redirect("settings")
        if request.POST.get("action") == "identifiers":
            config = GateConfig.get_solo()
            config.reveal_identifiers = request.POST.get("reveal_identifiers") == "on"
            config.save(update_fields=["reveal_identifiers"])
            record_event(action="gate.identifiers_toggled", actor=request.user, target=config,
                         metadata={"reveal": config.reveal_identifiers}, request=request)
            messages.success(request, "Identifier display preference saved.")
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
        "totp_style": GateConfig.get_solo().totp_style,
        "totp_style_choices": GateConfig.TOTP_STYLE_CHOICES,
        "reveal_identifiers": GateConfig.get_solo().reveal_identifiers,
    })


@login_required
def dismiss_notification(request, pk):
    if request.method == "POST":
        NotificationOutbox.objects.filter(pk=pk, recipient=request.user).delete()
    return redirect(request.META.get("HTTP_REFERER", "overview"))
