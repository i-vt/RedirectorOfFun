from rest_framework import serializers
from accounts.models import Operator
from analytics.models import NotFoundEvent
from audit.models import AuditEvent
from gates.models import AgentChannel, BannedIP, DecoyPage, DeliveryLink, HitEvent, Submission
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
                  "approval_status", "one_time", "max_uses", "expires_at", "active", "hit_count",
                  "domain", "ja3_fingerprint", "ja4_fingerprint", "watermark",
                  "created_at", "updated_at"]
        read_only_fields = ["approval_status", "hit_count", "created_at", "updated_at"]

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


class SubmissionSerializer(serializers.ModelSerializer):
    images = serializers.StringRelatedField(many=True, read_only=True)
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


class DecoyPageSerializer(serializers.ModelSerializer):
    class Meta:
        model = DecoyPage
        fields = ["id", "name", "kind", "template_key", "redirect_url", "active",
                  "is_default", "created_at"]
        read_only_fields = ["is_default", "created_at"]
