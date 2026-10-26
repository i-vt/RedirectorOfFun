import json

from django import template
from django.utils.html import escape, format_html

register = template.Library()


@register.simple_tag
def tip(text, cls=""):
    """Inline help dot with a tooltip: {% tip "explainer" %}. Hover or tap."""
    return format_html('<i class="help-dot{}" data-tip="{}" role="button" tabindex="0" '
                       'aria-label="help">?</i>', f" {cls}" if cls else "", escape(str(text)))


@register.filter
def pretty_json(value):
    try:
        return json.dumps(value, indent=2, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


@register.filter
def as_json(value):
    """Render a JSONField value back into an editable textarea; empty stays empty."""
    if value in (None, "", [], {}):
        return ""
    try:
        return json.dumps(value, indent=2)
    except (TypeError, ValueError):
        return ""


@register.filter
def get_item(mapping, key):
    try:
        return mapping.get(key)
    except AttributeError:
        return None


@register.filter
def basename(value):
    """File name without the storage directory ('payloads/x.bin' -> 'x.bin')."""
    try:
        return str(value).rsplit("/", 1)[-1]
    except (AttributeError, IndexError):
        return value


@register.filter
def json_compact(value):
    """One-line JSON for table cells."""
    try:
        return json.dumps(value, separators=(", ", ": "))
    except (TypeError, ValueError):
        return str(value)
