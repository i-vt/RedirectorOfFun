from rest_framework import serializers
from accounts.models import APIKey, Operator
from analytics.models import NotFoundEvent
from audit.models import AuditEvent
from gates.models import (
    AgentChannel, BannedIP, BlockingRule, DecoyAsset, DecoyPage, DeliveryLink, HitEvent,
    LureFile, LureSite, RuleSet, Submission, SubmissionImage,
)
from notifications.models import NotificationOutbox, NotificationPreference, PushSubscription


class NotFoundEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotFoundEvent
        fields = ["id", "request_id", "occurred_at", "method", "path", "status",
                  "source_ip", "source_ip_hash", "user_agent", "country_code", "city"]


class AuditEventSerializer(serializers.ModelSerializer):
    actor = serializers.StringRelatedField()

    class Meta:
        model = AuditEvent
        fields = ["id", "actor", "action", "target_type", "target_id", "request_id", "metadata", "created_at"]


class OperatorSerializer(serializers.ModelSerializer):
    roles = serializers.SlugRelatedField(many=True, read_only=True, slug_field="name", source="groups")

    class Meta:
        model = Operator
        fields = ["id", "username", "email", "is_active", "is_staff", "last_login", "created_at", "roles"]


class NotificationPreferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationPreference
        fields = ["id", "event_type", "channel", "enabled"]
        read_only_fields = ["event_type", "channel"]


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationOutbox
        fields = ["id", "event_type", "channel", "payload", "status", "created_at"]


class DeliveryLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeliveryLink
        fields = ["id", "path", "kind", "label", "agent_label", "pwndrop_url", "gate_type",
                  "gate_token", "totp_secret", "totp_window", "cipher", "cipher_key", "cipher_iv",
                  "expected_fields", "auto_rules", "placeholder", "on_deny", "requires_approval",
                  "manual_admission",
                  "approval_status", "one_time", "max_uses", "expires_at", "active", "hit_count",
                  "domain", "ja3_fingerprint", "ja4_fingerprint", "watermark",
                  "allowed_uas", "allowed_ips", "header_contract", "replay_dedupe",
                  "active_window_start", "active_window_end", "serve_num", "serve_den",
                  "payload", "payload_size", "benevolent_file", "serve_as",
                  "post_download_redirect", "post_download_url", "benevolent_target",
                  "loading_page", "fingerprint_page",
                  "created_at", "updated_at"]
        read_only_fields = ["approval_status", "hit_count", "payload_size", "benevolent_target", "created_at", "updated_at"]
        extra_kwargs = {"payload": {"required": False}, "benevolent_file": {"required": False}}

    payload_size = serializers.SerializerMethodField()

    def get_payload_size(self, obj):
        try:
            return obj.payload.size if obj.payload else None
        except (OSError, ValueError):
            return None

    def validate_path(self, value):
        from django.core.exceptions import ValidationError as DjangoValidationError
        from gates.models import validate_gate_path
        try:
            validate_gate_path(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return value

    def validate_auto_rules(self, value):
        from django.core.exceptions import ValidationError as DjangoValidationError
        from gates.models import validate_auto_rules
        try:
            validate_auto_rules(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return value

    def validate_header_contract(self, value):
        from django.core.exceptions import ValidationError as DjangoValidationError
        from gates.models import validate_header_contract
        try:
            validate_header_contract(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return value

    def validate_allowed_uas(self, value):
        from django.core.exceptions import ValidationError as DjangoValidationError
        from gates.models import validate_regex_list
        try:
            validate_regex_list(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return value

    def validate_allowed_ips(self, value):
        from django.core.exceptions import ValidationError as DjangoValidationError
        from gates.models import validate_cidr_list
        try:
            validate_cidr_list(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return value

    def validate(self, attrs):
        num = attrs.get("serve_num", getattr(self.instance, "serve_num", 1))
        den = attrs.get("serve_den", getattr(self.instance, "serve_den", 1))
        if num < 1 or den < 1 or num > den:
            raise serializers.ValidationError(
                {"serve_num": "serve ratio must be N/M with 1 <= N <= M (1/1 serves always)."})
        return attrs


class SubmissionImageSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = SubmissionImage
        fields = ["id", "field_name", "content_type", "url", "created_at"]

    def get_url(self, obj):
        from django.urls import reverse
        return reverse("api-submission-image", args=[obj.pk])


class SubmissionSerializer(serializers.ModelSerializer):
    images = SubmissionImageSerializer(many=True, read_only=True)
    note = serializers.CharField(max_length=4000, required=False, allow_blank=True)

    class Meta:
        model = Submission
        fields = ["id", "link", "decoded_json", "status", "decided_by", "decided_at",
                  "client_ip_hash", "user_agent", "created_at", "images", "note"]
        read_only_fields = ["decoded_json", "status", "decided_by", "decided_at", "client_ip_hash", "user_agent", "created_at"]


class BannedIPSerializer(serializers.ModelSerializer):
    class Meta:
        model = BannedIP
        fields = ["id", "ip", "note", "active", "auto_created", "created_at"]
        read_only_fields = ["auto_created", "created_at"]
        # Uniqueness is handled by get_or_create in the view so an existing
        # ban can be re-activated instead of rejected as a duplicate.
        extra_kwargs = {"ip": {"validators": []}}


class AgentChannelSerializer(serializers.ModelSerializer):
    path = serializers.ReadOnlyField()

    class Meta:
        model = AgentChannel
        fields = ["id", "label", "token", "path", "ua_pattern", "note", "active", "hits", "last_seen_at", "created_at"]
        read_only_fields = ["token", "hits", "last_seen_at", "created_at"]


class HitEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = HitEvent
        fields = ["id", "category", "path", "link", "agent_channel", "ip_hash", "user_agent",
                  "status_code", "detail", "created_at"]


class PushSubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = PushSubscription
        fields = ["endpoint", "keys"]
        extra_kwargs = {"endpoint": {"validators": []}}


class DecoyAssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = DecoyAsset
        fields = ["path", "content", "content_type", "public_path", "updated_at"]
        read_only_fields = ["content_type", "public_path", "updated_at"]


class DecoyPageSerializer(serializers.ModelSerializer):
    assets = DecoyAssetSerializer(many=True, read_only=True)

    class Meta:
        model = DecoyPage
        fields = ["id", "name", "kind", "template_key", "redirect_url", "html", "active",
                  "is_default", "assets", "created_at"]
        read_only_fields = ["is_default", "created_at"]


class LureFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = LureFile
        fields = ["path", "content", "content_type", "updated_at"]
        read_only_fields = ["content_type", "updated_at"]


class LureSiteSerializer(serializers.ModelSerializer):
    files = LureFileSerializer(many=True, read_only=True)
    public_path = serializers.ReadOnlyField()

    class Meta:
        model = LureSite
        fields = ["id", "name", "slug", "description", "active", "public_path",
                  "files", "created_at", "updated_at"]
        read_only_fields = ["created_at", "updated_at"]


class APIKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = APIKey
        fields = ["id", "name", "prefix", "is_active", "expires_at", "last_used_at",
                  "last_used_ip", "created_at"]
        read_only_fields = fields


class RuleSetSerializer(serializers.ModelSerializer):
    link_path = serializers.SlugRelatedField(source="link", slug_field="path",
                                             queryset=DeliveryLink.objects.all(),
                                             required=False, allow_null=True)

    class Meta:
        model = RuleSet
        fields = ["id", "name", "scope", "link", "link_path", "enabled", "order", "created_at"]
        read_only_fields = ["created_at"]


class BlockingRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockingRule
        fields = ["id", "name", "ruleset", "order", "action", "logic", "conditions",
                  "enabled", "auto_ban", "preset", "match_count", "created_at"]
        read_only_fields = ["preset", "match_count", "created_at"]
