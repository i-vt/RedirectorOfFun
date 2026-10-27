from functools import wraps
from django.core.cache import cache
from django.http import JsonResponse


def rate_limit(prefix, limit=20, window=300):
    def decorator(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if request.method == "POST":
                from gates.services import client_ip
                address = client_ip(request) or "unknown"
                # login-ish endpoints also key on the username so one fumbling
                # operator cannot lock out everyone behind a shared proxy
                username = request.POST.get("username", "")[:80]
                key = f"rate:{prefix}:{address}:{username}"
                added = cache.add(key, 1, window)
                count = 1 if added else cache.incr(key)
                if count > limit:
                    return JsonResponse({"detail": "Too many attempts. Try again later."}, status=429)
            return view(request, *args, **kwargs)
        return wrapped
    return decorator
