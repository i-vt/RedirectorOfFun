from django.urls import path
from . import views

urlpatterns = [
    path("settings/", views.settings_view, name="settings"),
    path("notifications/<int:pk>/dismiss/", views.dismiss_notification, name="notification-dismiss"),
]
