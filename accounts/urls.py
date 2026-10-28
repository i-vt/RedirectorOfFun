from django.contrib.auth.views import LogoutView
from django.urls import path
from . import views

urlpatterns = [
    path("login/", views.OperatorLoginView.as_view(), name="login"),
    path("login/totp/", views.totp_login_view, name="login-totp"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("setup/<str:token>/", views.bootstrap_view, name="bootstrap"),
    path("invite/<str:token>/", views.invitation_accept_view, name="invitation-accept"),
    path("panel/operators/", views.operators_view, name="operators"),
    path("panel/operators/<int:pk>/revoke/", views.revoke_operator_view, name="operator-revoke"),
    path("panel/operators/<int:pk>/role/", views.operator_role_view, name="operator-role"),
    path("panel/operators/<int:pk>/reset-2fa/", views.reset_operator_2fa, name="operator-reset-2fa"),
    path("panel/security/", views.security_view, name="security"),
    path("panel/invitations/<int:pk>/revoke/", views.revoke_invitation_view, name="invitation-revoke"),
]
