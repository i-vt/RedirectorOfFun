from django.urls import path
from . import views

urlpatterns = [
    path("", views.overview, name="overview"),
    path("events/", views.events_view, name="events"),
    path("health/", views.health_view, name="panel-health"),
]
