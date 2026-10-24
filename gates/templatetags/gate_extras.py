import json

from django import template

register = template.Library()


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
