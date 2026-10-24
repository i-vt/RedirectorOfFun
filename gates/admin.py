from django.contrib import admin

from .models import AgentChannel, BannedIP, DeliveryLink, HitEvent, Submission, SubmissionImage


@admin.register(DeliveryLink)
class DeliveryLinkAdmin(admin.ModelAdmin):
    list_display = ["path", "kind", "gate_type", "requires_approval", "approval_status", "active", "hit_count", "expires_at"]
    list_filter = ["kind", "gate_type", "active", "requires_approval"]
    search_fields = ["path", "label", "agent_label"]


@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    list_display = ["id", "link", "status", "client_ip_hash", "created_at"]
    list_filter = ["status"]


admin.site.register([SubmissionImage, BannedIP, AgentChannel, HitEvent])
