import uuid

from django.conf import settings


class RequestIDMiddleware:
    """Attach a request identifier used by logs and audit records.

    The header only goes out on operator paths; on the public surface a
    per-request UUID header is a fingerprint, so it stays internal there.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    OPERATOR_PATHS = ("/panel/", "/api/", "/m/")

    def __call__(self, request):
        request.request_id = uuid.uuid4().hex
        response = self.get_response(request)
        prefix = getattr(settings, "OPERATOR_PREFIX", "")
        if prefix:
            expose = request.path.startswith(f"/{prefix}/")
        else:
            expose = request.path.startswith(self.OPERATOR_PATHS)
        if expose:
            response["X-Request-ID"] = request.request_id
        return response
