from functools import wraps
from django.core.cache import cache
from django.http import JsonResponse


def rate_limit(prefix, limit=20, window=300):
    def decorator(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if request.method == "POST":
                address = request.META.get("REMOTE_ADDR", "unknown")
                key = f"rate:{prefix}:{address}"
                added = cache.add(key, 1, window)
                count = 1 if added else cache.incr(key)
                if count > limit:
                    return JsonResponse({"detail": "Too many attempts. Try again later."}, status=429)
            return view(request, *args, **kwargs)
        return wrapped
    return decorator
