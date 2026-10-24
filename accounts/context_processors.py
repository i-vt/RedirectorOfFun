from .permissions import is_administrator


def panel_context(request):
    return {
        "is_administrator": is_administrator(request.user),
        "panel_name": "RDR//OPS",
    }
