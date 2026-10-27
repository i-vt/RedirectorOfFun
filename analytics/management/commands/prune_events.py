from datetime import timedelta
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone
from analytics.models import NotFoundEvent


class Command(BaseCommand):
    help = ("Delete 404 events older than the configured retention window, plus "
            "stale gate telemetry and admissions so the tables stay bounded.")

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, default=settings.ANALYTICS_RETENTION_DAYS)

    def handle(self, *args, **options):
        days = max(options["days"], 1)
        cutoff = timezone.now() - timedelta(days=days)
        deleted, _ = NotFoundEvent.objects.filter(occurred_at__lt=cutoff).delete()
        self.stdout.write(f"Deleted {deleted} expired event records.")
        from gates.models import GateAdmission, HitEvent
        gate_deleted, _ = HitEvent.objects.filter(created_at__lt=cutoff).delete()
        pending_cutoff = timezone.now() - timedelta(days=7)
        denied_cutoff = timezone.now() - timedelta(days=30)
        adm_deleted, _ = GateAdmission.objects.filter(
            status="pending", last_seen_at__lt=pending_cutoff).delete()
        denied_deleted, _ = GateAdmission.objects.filter(
            status="denied", last_seen_at__lt=denied_cutoff).delete()
        self.stdout.write(
            f"Deleted {gate_deleted} gate telemetry records and "
            f"{adm_deleted + denied_deleted} stale admissions.")
