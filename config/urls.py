from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from . import views


def build_urlpatterns(prefix):
    """Mount every operator path under the secret prefix.

    Public surface (/g/, /a/) and infrastructure (/health/, /static/) stay
    at the root; with an empty prefix the layout is unchanged.
    """
    op = f"{prefix}/" if prefix else ""
    return [
        path(f"{op}django-admin/", admin.site.urls),
        path(op, include("accounts.urls")),
        path(f"{op}panel/", include("analytics.urls")),
        path(f"{op}panel/", include("audit.urls")),
        path(f"{op}panel/", include("notifications.urls")),
        path(f"{op}panel/", include("gates.urls")),
        path(f"{op}m/", include("gates.murls")),
        path(f"{op}api/v1/", include("api.urls")),
        path("health/", include("config.health_urls")),
        path("", views.root, name="root"),
    ]


urlpatterns = build_urlpatterns(settings.OPERATOR_PREFIX)

handler404 = "config.views.not_found"
