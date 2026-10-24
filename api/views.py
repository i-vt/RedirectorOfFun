from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.models import Operator
from accounts.permissions import IsAdministrator
from accounts.services import deactivate_operator
from analytics.models import NotFoundEvent
from analytics.services import dashboard_statistics
from analytics.views import filtered_events
from audit.models import AuditEvent
from audit.services import record_event
from gates import services as gate_services
from gates.models import (
    AgentChannel, BannedIP, BlockingRule, DecoyPage, DeliveryLink, HitEvent, RuleSet, Submission,
)
from notifications.models import NotificationOutbox, NotificationPreference, PushSubscription
from .pagination import AuditCursorPagination, EventCursorPagination, HitCursorPagination, OperatorPagination
from .serializers import (
    AgentChannelSerializer, AuditEventSerializer, BannedIPSerializer, BlockingRuleSerializer,
    DecoyPageSerializer, DeliveryLinkSerializer, HitEventSerializer, NotFoundEventSerializer,
    NotificationPreferenceSerializer, NotificationSerializer, OperatorSerializer,
    PushSubscriptionSerializer, RuleSetSerializer, SubmissionSerializer,
)


class NotFoundEventList(generics.ListAPIView):
    serializer_class = NotFoundEventSerializer
    pagination_class = EventCursorPagination

    def get_queryset(self):
        return filtered_events(self.request)


class NotFoundStats(APIView):
    def get(self, request):
        try:
            days = min(max(int(request.query_params.get("days", 14)), 1), 90)
        except (TypeError, ValueError):
            return Response({"detail": "days must be an integer."}, status=400)
        return Response(dashboard_statistics(days))


class AuditEventList(generics.ListAPIView):
    serializer_class = AuditEventSerializer
    pagination_class = AuditCursorPagination
    queryset = AuditEvent.objects.select_related("actor").all()


class OperatorList(generics.ListAPIView):
    permission_classes = [IsAdministrator]
    serializer_class = OperatorSerializer
    pagination_class = OperatorPagination
    queryset = Operator.objects.prefetch_related("groups").all()


class OperatorRevoke(APIView):
    permission_classes = [IsAdministrator]

    def post(self, request, pk):
        target = get_object_or_404(Operator, pk=pk)
        try:
            operator = deactivate_operator(actor=request.user, target=target, request=request)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(OperatorSerializer(operator).data)


class NotificationPreferenceList(generics.ListAPIView):
    serializer_class = NotificationPreferenceSerializer

    def get_queryset(self):
        return NotificationPreference.objects.filter(operator=self.request.user)


class NotificationPreferenceDetail(generics.RetrieveUpdateAPIView):
    serializer_class = NotificationPreferenceSerializer

    def get_queryset(self):
        return NotificationPreference.objects.filter(operator=self.request.user)


class RecentNotifications(generics.ListAPIView):
    serializer_class = NotificationSerializer

    def get_queryset(self):
        after = self.request.query_params.get("after")
        queryset = NotificationOutbox.objects.filter(recipient=self.request.user)
        if after and after.isdigit():
            return queryset.filter(pk__gt=int(after)).order_by("created_at")[:20]
        return queryset.order_by("-created_at")[:20]


class DeliveryLinkList(generics.ListCreateAPIView):
    serializer_class = DeliveryLinkSerializer

    def get_queryset(self):
        return DeliveryLink.objects.all()

    def perform_create(self, serializer):
        link = serializer.save(created_by=self.request.user)
        record_event(action="gate.link_created", actor=self.request.user, target=link, request=self.request)


class DeliveryLinkDetail(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DeliveryLinkSerializer
    queryset = DeliveryLink.objects.all()

    def perform_update(self, serializer):
        link = serializer.save()
        record_event(action="gate.link_updated", actor=self.request.user, target=link, request=self.request)


class SubmissionList(generics.ListAPIView):
    serializer_class = SubmissionSerializer

    def get_queryset(self):
        queryset = Submission.objects.select_related("link", "decided_by")
        status_filter = self.request.query_params.get("status")
        if status_filter in {"pending", "approved", "denied"}:
            queryset = queryset.filter(status=status_filter)
        return queryset


class SubmissionDecide(APIView):
    def post(self, request, pk, verdict):
        if verdict not in {"approve", "deny"}:
            return Response({"detail": "verdict must be 'approve' or 'deny'."}, status=status.HTTP_400_BAD_REQUEST)
        submission = get_object_or_404(Submission.objects.select_related("link"), pk=pk)
        decided = gate_services.decide_submission(submission, verdict, actor=request.user,
                                                  via="api", request=request)
        if decided is None:
            return Response({"detail": f"Submission #{submission.pk} was already decided."},
                            status=status.HTTP_409_CONFLICT)
        return Response(SubmissionSerializer(submission).data)


class BannedIPList(generics.ListCreateAPIView):
    serializer_class = BannedIPSerializer

    def get_queryset(self):
        return BannedIP.objects.all()

    def create(self, request, *args, **kwargs):
        ip = str(request.data.get("ip", "")).strip()
        if not gate_services.valid_ip(ip):
            return Response({"detail": f"'{ip}' is not a valid IP address."}, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ban, created = BannedIP.objects.get_or_create(
            ip=ip, defaults={**serializer.validated_data, "created_by": request.user})
        if not created:
            for field, value in serializer.validated_data.items():
                setattr(ban, field, value)
            ban.active = True
            ban.save()
        gate_services.sync_nginx_files()
        record_event(action="gate.ip_banned", actor=request.user, target=ban, request=request)
        return Response(BannedIPSerializer(ban).data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


class BannedIPDetail(generics.RetrieveUpdateAPIView):
    serializer_class = BannedIPSerializer
    queryset = BannedIP.objects.all()

    def perform_update(self, serializer):
        ban = serializer.save()
        gate_services.sync_nginx_files()
        record_event(action="gate.ip_ban_toggled", actor=self.request.user, target=ban,
                     metadata={"active": ban.active}, request=self.request)


class AgentChannelList(generics.ListCreateAPIView):
    serializer_class = AgentChannelSerializer

    def get_queryset(self):
        return AgentChannel.objects.all()

    def perform_create(self, serializer):
        agent = serializer.save(created_by=self.request.user)
        gate_services.sync_nginx_files()
        record_event(action="gate.agent_created", actor=self.request.user, target=agent, request=self.request)


class AgentChannelDetail(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = AgentChannelSerializer
    queryset = AgentChannel.objects.all()

    def perform_update(self, serializer):
        agent = serializer.save()
        gate_services.sync_nginx_files()
        record_event(action="gate.agent_toggled", actor=self.request.user, target=agent,
                     metadata={"active": agent.active}, request=self.request)


class AgentChannelRotate(APIView):
    def post(self, request, pk):
        agent = get_object_or_404(AgentChannel, pk=pk)
        from gates.models import agent_token
        old = agent.path
        agent.token = agent_token()
        agent.save(update_fields=["token"])
        gate_services.sync_nginx_files()
        record_event(action="gate.agent_rotated", actor=request.user, target=agent,
                     metadata={"old_path": old, "via": "api"}, request=request)
        return Response(AgentChannelSerializer(agent).data)


class HitEventList(generics.ListAPIView):
    serializer_class = HitEventSerializer
    pagination_class = HitCursorPagination

    def get_queryset(self):
        queryset = HitEvent.objects.select_related("link", "agent_channel")
        category = self.request.query_params.get("category")
        if category in dict(HitEvent.CATEGORY_CHOICES):
            queryset = queryset.filter(category=category)
        return queryset


class GateStats(APIView):
    def get(self, request):
        from django.db.models import Count
        from datetime import timedelta
        since = timezone.now() - timedelta(days=1)
        recent = HitEvent.objects.filter(created_at__gte=since)
        return Response({
            "hits_24h": recent.count(),
            "suspicious_24h": recent.filter(category="suspicious").count(),
            "downloads_24h": recent.filter(category="download").count(),
            "pending_submissions": Submission.objects.filter(status="pending").count(),
            "active_links": DeliveryLink.objects.filter(active=True).count(),
            "banned_ips": BannedIP.objects.filter(active=True).count(),
            "by_category": list(HitEvent.objects.values("category").annotate(count=Count("id")).order_by("-count")),
        })


class SubmissionNote(APIView):
    def post(self, request, pk):
        submission = get_object_or_404(Submission, pk=pk)
        note = str(request.data.get("note", ""))[:4000]
        submission.note = note
        submission.note_by = request.user if note else None
        submission.note_at = timezone.now() if note else None
        submission.save(update_fields=["note", "note_by", "note_at"])
        record_event(action="gate.submission_noted", actor=request.user, target=submission, request=request)
        return Response(SubmissionSerializer(submission).data)


class SubmissionUndo(APIView):
    def post(self, request, pk):
        submission = get_object_or_404(Submission.objects.select_related("link"), pk=pk)
        ok, error = gate_services.undo_decision(submission, request.user)
        if not ok:
            return Response({"detail": error}, status=status.HTTP_409_CONFLICT)
        record_event(action="gate.submission_undone", actor=request.user, target=submission, request=request)
        return Response(SubmissionSerializer(submission).data)


class LinkBurn(APIView):
    def post(self, request, pk):
        link = get_object_or_404(DeliveryLink, pk=pk)
        banned_count, ips = gate_services.burn_link(link, actor=request.user, request=request)
        return Response({"burned": True, "banned": banned_count, "banned_ips": ips})


class PushKey(APIView):
    def get(self, request):
        from django.conf import settings as dj_settings
        return Response({"public_key": dj_settings.VAPID_PUBLIC_KEY,
                         "configured": bool(dj_settings.VAPID_PRIVATE_KEY)})


class DecoyPageList(generics.ListCreateAPIView):
    serializer_class = DecoyPageSerializer

    def get_queryset(self):
        return DecoyPage.objects.all()

    def perform_create(self, serializer):
        page = serializer.save(created_by=self.request.user)
        record_event(action="gate.decoy_created", actor=self.request.user, target=page,
                     metadata={"via": "api"}, request=self.request)


class DecoyPageDetail(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DecoyPageSerializer
    queryset = DecoyPage.objects.all()

    def perform_update(self, serializer):
        page = serializer.save()
        if not page.active and page.is_default:
            DecoyPage.objects.filter(pk=page.pk).update(is_default=False)
        record_event(action="gate.decoy_updated", actor=self.request.user, target=page,
                     request=self.request)

    def perform_destroy(self, instance):
        if instance.kind == "template":
            from rest_framework.exceptions import ValidationError as DRFValidationError
            raise DRFValidationError("Built-in pages cannot be deleted, only deactivated.")
        was_default = instance.is_default
        instance.delete()
        if was_default:
            fallback = DecoyPage.objects.filter(active=True, kind="template",
                                                template_key="update-service").first()
            if fallback is not None:
                DecoyPage.objects.filter(pk=fallback.pk).update(is_default=True)


class BlockingRuleList(generics.ListCreateAPIView):
    serializer_class = BlockingRuleSerializer

    def get_queryset(self):
        return BlockingRule.objects.all()

    def perform_create(self, serializer):
        rule = serializer.save(created_by=self.request.user)
        record_event(action="gate.block_rule_created", actor=self.request.user, target=rule,
                     metadata={"via": "api"}, request=self.request)


class BlockingRuleDetail(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = BlockingRuleSerializer
    queryset = BlockingRule.objects.all()

    def perform_update(self, serializer):
        rule = serializer.save()
        record_event(action="gate.block_rule_updated", actor=self.request.user, target=rule,
                     request=self.request)

    def perform_destroy(self, instance):
        if instance.preset:
            from rest_framework.exceptions import ValidationError as DRFValidationError
            raise DRFValidationError("Preset rules cannot be deleted, only disabled.")
        name = instance.name
        instance.delete()
        record_event(action="gate.block_rule_deleted", actor=self.request.user,
                     metadata={"name": name, "via": "api"}, request=self.request)


class RuleSetList(generics.ListCreateAPIView):
    serializer_class = RuleSetSerializer
    queryset = RuleSet.objects.all()

    def perform_create(self, serializer):
        ruleset = serializer.save()
        record_event(action="gate.rule_set_created", actor=self.request.user, target=ruleset,
                     metadata={"via": "api"}, request=self.request)


class RuleSetDetail(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = RuleSetSerializer
    queryset = RuleSet.objects.all()

    def perform_destroy(self, instance):
        name = instance.name
        rules = list(instance.rules.all())
        instance.delete()
        for rule in rules:
            rule.ruleset = None
            rule.save(update_fields=["ruleset"])


class BlockingRuleReorder(APIView):
    def post(self, request):
        kind = request.data.get("kind")
        ids = request.data.get("ids", [])
        if kind == "rule":
            for index, rule_id in enumerate(ids):
                BlockingRule.objects.filter(pk=rule_id).update(order=index)
        elif kind == "set":
            for index, set_id in enumerate(ids):
                RuleSet.objects.filter(pk=set_id).update(order=index)
        else:
            return Response({"detail": "kind must be 'rule' or 'set'."}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"ok": True})


class BlockingRuleExport(APIView):
    def get(self, request):
        payload = gate_services.export_blocking_rules()
        response = Response(payload)
        response["Content-Disposition"] = 'attachment; filename="rof-blocking-rules.json"'
        return response


class BlockingRuleImport(APIView):
    def post(self, request):
        sets_created, rules_created, errors = gate_services.import_blocking_rules(
            request.data, actor=request.user)
        status_code = status.HTTP_201_CREATED if (sets_created or rules_created) else status.HTTP_200_OK
        return Response({"sets": sets_created, "rules": rules_created, "errors": errors},
                        status=status_code)


class BlockingRuleTest(APIView):
    def post(self, request):
        ip = str(request.data.get("ip", "")).strip()[:64]
        ua = str(request.data.get("ua", "")).strip()[:1000]
        intel = gate_services.get_ip_intel(ip)
        matched = []
        for rule in BlockingRule.objects.all():
            hit, fired = gate_services.rule_matches(rule, ip=ip, user_agent=ua, intel=intel)
            if hit:
                matched.append({"name": rule.name, "enabled": rule.enabled, "fired": fired})
        return Response({
            "ip": ip, "user_agent": ua,
            "intel": {"asn": intel.asn, "org": intel.org, "country_code": intel.country_code,
                      "city": intel.city} if intel else None,
            "matched": matched,
        })


class DecoyPageSetDefault(APIView):
    def post(self, request, pk):
        page = get_object_or_404(DecoyPage, pk=pk)
        if not page.active:
            return Response({"detail": "Activate the page before making it the default."},
                            status=status.HTTP_409_CONFLICT)
        DecoyPage.objects.exclude(pk=page.pk).update(is_default=False)
        DecoyPage.objects.filter(pk=page.pk).update(is_default=True)
        page.refresh_from_db()
        record_event(action="gate.decoy_defaulted", actor=request.user, target=page,
                     metadata={"via": "api"}, request=request)
        return Response(DecoyPageSerializer(page).data)


class PushSubscribe(APIView):
    def post(self, request):
        serializer = PushSubscriptionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        subscription, _ = PushSubscription.objects.update_or_create(
            endpoint=serializer.validated_data["endpoint"],
            defaults={
                "operator": request.user,
                "keys": serializer.validated_data.get("keys", {}),
                "user_agent": request.META.get("HTTP_USER_AGENT", "")[:300],
            },
        )
        return Response({"subscribed": True, "id": subscription.pk}, status=status.HTTP_201_CREATED)


class PushUnsubscribe(APIView):
    def post(self, request):
        endpoint = str(request.data.get("endpoint", ""))
        PushSubscription.objects.filter(operator=request.user, endpoint=endpoint).delete()
        return Response({"unsubscribed": True})
