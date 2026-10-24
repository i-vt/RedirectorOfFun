"""Hook between Django's 404 handler and the gate dispatcher."""
from django.views.decorators.csrf import csrf_exempt

from . import services


@csrf_exempt
def dispatch_public_request(request, exception=None):
    """Called from config.views.not_found; returns a response for gate-owned paths."""
    return services.dispatch(request, request.path)
