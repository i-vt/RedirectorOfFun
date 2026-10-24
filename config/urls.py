from django.contrib import admin
from django.urls import include, path

from . import views

urlpatterns = [
    path("django-admin/", admin.site.urls),
    path("", include("accounts.urls")),
    path("panel/", include("analytics.urls")),
    path("panel/", include("audit.urls")),
    path("panel/", include("notifications.urls")),
    path("panel/", include("gates.urls")),
    path("m/", include("gates.murls")),
    path("api/v1/", include("api.urls")),
    path("health/", include("config.health_urls")),
    path("", views.root, name="root"),
]

# The 404 handler doubles as the public entry point for operator-controlled
# paths (/g/…, /a/…): gates.public.dispatch_public_request serves matching
# links and falls back to the stock 404 page for everything else.
handler404 = "config.views.not_found"
