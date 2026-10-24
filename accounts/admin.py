from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Invitation, Operator


@admin.register(Operator)
class OperatorAdmin(UserAdmin):
    list_display = ("username", "email", "is_active", "is_staff", "created_at")
    fieldsets = UserAdmin.fieldsets + (("Session control", {"fields": ("session_version", "created_at")}),)
    readonly_fields = ("created_at",)


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ("username", "role", "invited_by", "expires_at", "consumed_at", "revoked_at")
    readonly_fields = ("token_digest", "created_at", "consumed_at")
