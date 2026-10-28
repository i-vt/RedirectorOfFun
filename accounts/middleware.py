from django.contrib.auth import logout
from django.shortcuts import redirect


class OperatorSessionMiddleware:
    """Invalidate existing sessions after an operator's session version changes."""

    SESSION_KEY = "operator_session_version"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            version = request.session.get(self.SESSION_KEY)
            if version is None:
                request.session[self.SESSION_KEY] = request.user.session_version
            elif version != request.user.session_version:
                logout(request)
                return redirect("login")
        return self.get_response(request)


class ReadOnlyAuditorMiddleware:
    """Auditors are read-only: safe methods pass, everything else is 403.

    Covers the panel AND the API (DRF runs under the same stack), so an
    auditor's API key is read-only too. Logout stays allowed.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from .permissions import is_read_only
        if (request.method not in ("GET", "HEAD", "OPTIONS")
                and request.user.is_authenticated
                and is_read_only(request.user)
                and not request.path.rstrip("/").endswith("/logout")):
            from django.shortcuts import render
            return render(request, "403.html", status=403)
        return self.get_response(request)
