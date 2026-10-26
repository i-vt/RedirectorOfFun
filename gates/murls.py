from django.urls import path

from . import mobile

urlpatterns = [
    path("", mobile.submissions, name="m-submissions"),
    path("submissions/<int:pk>/", mobile.submission_detail, name="m-submission"),
    path("links/", mobile.links, name="m-links"),
    path("links/<int:pk>/", mobile.link_detail, name="m-link"),
    path("intel/", mobile.intel, name="m-intel"),
    path("events/", mobile.events, name="m-events"),
]
