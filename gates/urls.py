from django.urls import path

from . import views

urlpatterns = [
    path("links/", views.links_view, name="gate-links"),
    path("links/new/", views.link_create, name="gate-link-create"),
    path("links/<int:pk>/", views.link_detail, name="gate-link-detail"),
    path("links/<int:pk>/edit/", views.link_update, name="gate-link-edit"),
    path("links/<int:pk>/toggle/", views.link_toggle, name="gate-link-toggle"),
    path("links/<int:pk>/burn/", views.link_burn, name="gate-link-burn"),
    path("links/<int:pk>/totp/", views.link_totp_preview, name="gate-link-totp"),
    path("submissions/", views.submissions_view, name="gate-submissions"),
    path("submissions/<int:pk>/note/", views.submission_note, name="gate-submission-note"),
    path("submissions/<int:pk>/undo/", views.submission_undo, name="gate-submission-undo"),
    path("submissions/<int:pk>/<str:verdict>/", views.submission_decide, name="gate-submission-decide"),
    path("submissions/image/<int:pk>/", views.submission_image, name="gate-submission-image"),
    path("bans/", views.bans_view, name="gate-bans"),
    path("bans/<int:pk>/toggle/", views.ban_toggle, name="gate-ban-toggle"),
    path("agents/", views.agents_view, name="gate-agents"),
    path("agents/<int:pk>/toggle/", views.agent_toggle, name="gate-agent-toggle"),
    path("agents/<int:pk>/rotate/", views.agent_rotate, name="gate-agent-rotate"),
    path("gate-events/", views.gate_events_view, name="gate-events"),
    path("selftest/", views.selftest_view, name="gate-selftest"),
    path("decoys/", views.decoys_view, name="gate-decoys"),
    path("decoys/<int:pk>/default/", views.decoy_set_default, name="gate-decoy-default"),
    path("decoys/<int:pk>/toggle/", views.decoy_toggle, name="gate-decoy-toggle"),
    path("decoys/<int:pk>/delete/", views.decoy_delete, name="gate-decoy-delete"),
]
