from django.conf import settings
from django.shortcuts import redirect, render

from gates.public import dispatch_public_request
from gates.services import decoy_response


def not_found(request, exception):
    """404 handler that first offers the request to the gate dispatcher.

    Anything outside the operator prefix is decoy for everyone - a session
    must never turn a wrong URL into panel branding. Inside the prefix,
    authenticated operators get the real panel 404 page to help navigation;
    everyone else gets the decoy.
    """
    response = dispatch_public_request(request, exception)
    if response is not None:
        return response
    prefix = getattr(settings, "OPERATOR_PREFIX", "")
    if prefix and not request.path.startswith(f"/{prefix}/"):
        return decoy_response(request, status=404)
    if request.user.is_authenticated:
        return render(request, "404.html", status=404)
    return decoy_response(request, status=404)


def root(request):
    """Operators get the dashboard; everyone else sees the decoy."""
    if request.user.is_authenticated:
        return redirect("overview")
    return decoy_response(request)
