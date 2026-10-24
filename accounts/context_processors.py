from .permissions import is_administrator


def panel_context(request):
    user = request.user
    theme = getattr(user, "theme", "default") if user.is_authenticated else "default"
    return {
        "is_administrator": is_administrator(user),
        "panel_name": "RoF//OPS",
        "theme": theme,
    }
