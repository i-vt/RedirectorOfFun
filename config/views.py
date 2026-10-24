from django.shortcuts import render

from gates.public import dispatch_public_request


def not_found(request, exception):
    """404 handler that first offers the request to the gate dispatcher."""
    response = dispatch_public_request(request, exception)
    if response is not None:
        return response
    return render(request, "404.html", status=404)
