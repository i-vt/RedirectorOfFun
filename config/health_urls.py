from django.urls import path
from . import health

urlpatterns = [
    path("live/", health.liveness, name="health-live"),
    path("ready/", health.readiness, name="health-ready"),
]
