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
