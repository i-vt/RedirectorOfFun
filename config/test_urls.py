"""Alternate URLconf with a fixed operator prefix, for tests only."""

from django.conf import settings

from .urls import build_urlpatterns

urlpatterns = build_urlpatterns("testprefix")

handler404 = "config.views.not_found"
