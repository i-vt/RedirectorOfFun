from django.shortcuts import redirect, render

from gates.public import dispatch_public_request
from gates.services import decoy_response


def not_found(request, exception):
    """404 handler that first offers the request to the gate dispatcher.

    Anonymous visitors get the public decoy (same as they would from the
    edge); authenticated operators get the real panel 404 page.
    """
    response = dispatch_public_request(request, exception)
    if response is not None:
        return response
    if request.user.is_authenticated:
        return render(request, "404.html", status=404)
    return decoy_response(request, status=404)


def root(request):
    """Operators get the dashboard; everyone else sees the decoy."""
    if request.user.is_authenticated:
        return redirect("overview")
    return decoy_response(request)
