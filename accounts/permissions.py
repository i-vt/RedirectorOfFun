from django.contrib.auth.mixins import UserPassesTestMixin
from django.core.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission


def is_administrator(user):
    return bool(user.is_authenticated and user.is_active and (user.is_superuser or user.groups.filter(name="Administrator").exists()))


def is_auditor(user):
    return bool(user.is_authenticated and user.is_active and (
        is_administrator(user) or user.groups.filter(name__in=["Auditor", "Operator"]).exists()
    ))


class AdministratorRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        return is_administrator(self.request.user)

    def handle_no_permission(self):
        if self.request.user.is_authenticated:
            raise PermissionDenied
        return super().handle_no_permission()


class IsAdministrator(BasePermission):
    def has_permission(self, request, view):
        return is_administrator(request.user)


def is_read_only(user):
    """Auditors watch everything and change nothing. Administrators always write."""
    return bool(user.is_authenticated and user.is_active
                and user.groups.filter(name="Auditor").exists()
                and not is_administrator(user))
