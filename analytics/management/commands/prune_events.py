from datetime import timedelta
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone
from analytics.models import NotFoundEvent


class Command(BaseCommand):
    help = "Delete 404 events older than the configured retention window."

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, default=settings.ANALYTICS_RETENTION_DAYS)

    def handle(self, *args, **options):
        days = max(options["days"], 1)
        deleted, _ = NotFoundEvent.objects.filter(occurred_at__lt=timezone.now() - timedelta(days=days)).delete()
        self.stdout.write(f"Deleted {deleted} expired event records.")
