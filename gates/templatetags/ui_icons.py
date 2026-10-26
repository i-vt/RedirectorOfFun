"""Inline SVG icons for the panel: {% icon "name" %} renders a stroke-only
16-viewBox icon in currentColor so every theme tints it."""
from django import template
from django.utils.safestring import mark_safe

register = template.Library()

_ICONS = {
    # Nav icons
    "overview": '<circle cx="8" cy="8" r="6"/><path d="M8 8l3.2-3.4M8 4.6v.9M3.6 8h.9"/>',
    "events": '<path d="M3 13V7M3 13h12M3 7h12M7 7v6M11 7v6M15 7v6M15 3v10M3 3h12"/>',
    "links": '<path d="M6 9.5a3.5 3.5 0 0 1 0-2L8 5a3 3 0 0 1 4.2 0l.8.8a3 3 0 0 1 0 4.2L11 12a3 3 0 0 1-4.2 0"/><path d="M8 6.5a3.5 3.5 0 0 1 0 2L6 11a3 3 0 0 1-4.2 0"/>',
    "payloads": '<path d="M8 2.2l5.2 2.6v6.4L8 13.8l-5.2-2.6V4.8z"/><path d="M2.8 4.8L8 7.4l5.2-2.6M8 7.4v6.4M5.4 3.5l5.2 2.6"/>',
    "lures": '<circle cx="8" cy="8" r="6.2"/><path d="M1.8 8h12.4M8 1.8c-3.6 3.8-3.6 8.6 0 12.4M8 1.8c3.6 3.8 3.6 8.6 0 12.4"/>',
    "intel": '<rect x="1.8" y="2.8" width="12.4" height="10.4" rx="1"/><path d="M1.8 10.6l3.6-3.6 3 3 2.4-2.4 3.4 3.4"/><circle cx="5.6" cy="6" r="1.1"/>',
    "approvals": '<circle cx="8" cy="8" r="6.5"/><path d="M5.2 8.4l2 2 3.6-4"/>',
    "operators": '<circle cx="8" cy="5.4" r="2.6"/><path d="M2.8 13.4c.6-2.4 2.6-3.6 5.2-3.6s4.6 1.2 5.2 3.6"/>',
    "bans": '<circle cx="8" cy="8" r="6.4"/><path d="M3.6 3.6l8.8 8.8"/>',
    "rules": '<path d="M2.5 3.5h11l-4.2 4.8v4.2l-2.6-1.4V8.3z"/>',
    "agents": '<path d="M8 13.5v-3"/><circle cx="8" cy="8.2" r="1.4"/><path d="M5 5.4a4.4 4.4 0 0 0 0 5.6M11 5.4a4.4 4.4 0 0 1 0 5.6M3.2 3.4a7 7 0 0 0 0 9.6M12.8 3.4a7 7 0 0 1 0 9.6"/>',
    "gate-events": '<path d="M2 8h2.4l1.6-4 2 8 1.6-4H14"/>',
    "decoys": '<path d="M3 5.2c1.2-.6 2.6-.9 5-.9s3.8.3 5 .9v3.4c0 3.6-2.6 5.9-5 6.6-2.4-.7-5-3-5-6.6z"/><path d="M6 8c.7-.4 1.4-.4 2 0M11 8c-.6-.4-1.3-.4-2 0M6.8 11.4c.8.6 1.6.6 2.4 0"/>',
    "audit": '<path d="M4 3h8v10H4z"/><path d="M6 6h4M6 8.4h4M6 10.8h3"/>',
    "settings": '<circle cx="8" cy="8" r="2.2"/><path d="M8 1.6v1.8M8 12.6v1.8M1.6 8h1.8M12.6 8h1.8M3.5 3.5l1.3 1.3M11.2 11.2l1.3 1.3M3.5 12.5l1.3-1.3M11.2 4.8l1.3-1.3"/>',
    "security": '<rect x="3.4" y="7" width="9.2" height="6.4" rx="1"/><path d="M5.6 7V5a2.4 2.4 0 0 1 4.8 0v2"/>',
    "selftest": '<path d="M8 1.8l5.4 2v4.4c0 3.4-2.2 5.5-5.4 6.6-3.2-1.1-5.4-3.2-5.4-6.6V3.8z"/><path d="M5.6 8.2l1.8 1.8 3-3.4"/>',
    "health": '<path d="M8 14s-5.4-3.4-5.4-7.2c0-2 1.4-3.4 3-3.4 1 0 1.8.5 2.4 1.4.6-.9 1.4-1.4 2.4-1.4 1.6 0 3 1.4 3 3.4C13.4 10.6 8 14 8 14z"/>',
    "mobile": '<rect x="4.6" y="2" width="6.8" height="12" rx="1.2"/><path d="M7 11.6h2"/>',
    "signout": '<path d="M6 2.6h6M6 13.4h6M12 2.6v10.8"/><path d="M2.6 8h5.8M6.4 5.8L8.6 8l-2.2 2.2"/>',
    # Action icons
    "plus": '<path d="M8 3v10M3 8h10"/>',
    "check": '<path d="M3.4 8.6l3 3 6.2-7.2"/>',
    "x": '<path d="M4 4l8 8M12 4l-8 8"/>',
    "flame": '<path d="M8 1.8c.8 2.2 3.4 4 3.4 7a3.4 3.4 0 0 1-6.8 0c0-1.4.8-2.6 1.6-3.6.2 1 .8 1.6 1.4 2 .4-1.4 0-3.2.4-5.4z"/>',
    "flask": '<path d="M6 2h4M7 2v4.2L3.4 12c-.5.8.2 2 1.2 2h6.8c1 0 1.7-1.2 1.2-2L9 6.2V2"/><path d="M5 10.4h6"/>',
    "download": '<path d="M8 2v8M4.6 6.8L8 10l3.4-3.2M3 12.6h10"/>',
    "upload": '<path d="M8 10.6V2.6M4.6 5.8 8 2.4l3.4 3.4M3 13.4h10"/>',
    "star": '<path d="M8 2l1.8 3.6 4 .5-2.9 2.8.7 4L8 11l-3.6 1.9.7-4L2.2 6.1l4-.5z"/>',
    "cycle": '<path d="M12.4 6A4.6 4.6 0 1 1 12 9.4"/><path d="M12.4 2.6v3.6H8.8"/>',
    "trash": '<path d="M2.8 4.4h10.4M6 4.2V2.8h4v1.4M4.4 4.6l.6 8.8h6l.6-8.8"/>',
    "eye": '<path d="M2 8s2.4-4 6-4 6 4 6 4-2.4 4-6 4-6-4-6-4z"/><circle cx="8" cy="8" r="1.8"/>',
    "broadcast": '<circle cx="8" cy="8" r="1.6"/><path d="M8 9.6v3M5.2 4.6a5.2 5.2 0 0 0 0 6.8M10.8 4.6a5.2 5.2 0 0 1 0 6.8M3.6 2.8a8 8 0 0 0 0 10.4M12.4 2.8a8 8 0 0 1 0 10.4"/>',
}


@register.simple_tag
def icon(name, cls="icon"):
    body = _ICONS.get(name)
    if body is None:
        return ""
    return mark_safe(
        f'<svg class="{cls}" viewBox="0 0 16 16" fill="none" stroke="currentColor" '
        f'stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round" '
        f'aria-hidden="true">{body}</svg>'
    )


@register.simple_tag(takes_context=True)
def palette_destinations(context):
    """Navigation targets for the Ctrl+K command palette, as a JSON script."""
    import json
    from django.urls import reverse
    from accounts.permissions import is_administrator
    request = context.get("request")
    items = [
        {"group": "NAVIGATE", "label": "Overview", "url": reverse("overview"), "hint": "dashboard"},
        {"group": "NAVIGATE", "label": "404 Events", "url": reverse("events"), "hint": "edge telemetry"},
        {"group": "NAVIGATE", "label": "Delivery Links", "url": reverse("gate-links"), "hint": "gates"},
        {"group": "NAVIGATE", "label": "Payloads", "url": reverse("gate-payloads"), "hint": "files + library"},
        {"group": "NAVIGATE", "label": "Lures", "url": reverse("gate-lures"), "hint": "hosted sites"},
        {"group": "NAVIGATE", "label": "Approvals", "url": reverse("gate-submissions"), "hint": "queue + admissions"},
        {"group": "NAVIGATE", "label": "Gate Intel", "url": reverse("gate-intel"), "hint": "imagery"},
        {"group": "ADMINISTER", "label": "Banned IPs", "url": reverse("gate-bans"), "hint": ""},
        {"group": "ADMINISTER", "label": "Blocking Rules", "url": reverse("gate-block-rules"), "hint": ""},
        {"group": "ADMINISTER", "label": "Agent Channels", "url": reverse("gate-agents"), "hint": ""},
        {"group": "ADMINISTER", "label": "Gate Events", "url": reverse("gate-events"), "hint": ""},
        {"group": "ADMINISTER", "label": "Decoy Pages", "url": reverse("gate-decoys"), "hint": ""},
        {"group": "ADMINISTER", "label": "Audit Log", "url": reverse("audit-log"), "hint": ""},
        {"group": "ADMINISTER", "label": "Settings", "url": reverse("settings"), "hint": ""},
        {"group": "ADMINISTER", "label": "Security", "url": reverse("security"), "hint": "2FA + keys"},
        {"group": "ADMINISTER", "label": "Service Health", "url": reverse("panel-health"), "hint": ""},
        {"group": "ADMINISTER", "label": "Self-Test", "url": reverse("gate-selftest"), "hint": ""},
        {"group": "CREATE", "label": "New delivery link", "url": reverse("gate-link-create"), "hint": "full form"},
        {"group": "CREATE", "label": "New lure site", "url": reverse("gate-lures"), "hint": "create at top"},
        {"group": "CREATE", "label": "Add decoy page", "url": reverse("gate-decoys"), "hint": "form at top"},
        {"group": "CREATE", "label": "Mobile UI", "url": reverse("m-submissions"), "hint": "touch view"},
    ]
    if request is not None and is_administrator(request.user):
        items.append({"group": "ADMINISTER", "label": "Operators", "url": reverse("operators"), "hint": "accounts"})
    return mark_safe(
        '<script id="palette-data" type="application/json">'
        + json.dumps(items).replace("</", "<\\/") + "</script>")
