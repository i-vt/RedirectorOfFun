import json
import os
import time
from pathlib import Path
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from analytics.models import CollectorState, NotFoundEvent
from analytics.services import event_from_record
from notifications.services import notify


class Command(BaseCommand):
    help = "Incrementally ingest nginx JSON access logs without joining the request path."

    def add_arguments(self, parser):
        parser.add_argument("--path", default=settings.NGINX_JSON_LOG_PATH)
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--sleep", type=float, default=2.0)
        parser.add_argument("--batch-size", type=int, default=500)

    def handle(self, *args, **options):
        while True:
            try:
                count = self.ingest(options["path"], options["batch_size"])
                if count:
                    self.stdout.write(f"{timezone.now().isoformat()} ingested={count}")
                    if count >= settings.ANALYTICS_ALERT_THRESHOLD:
                        notify("analytics", {"title": "Elevated 404 volume", "detail": f"The collector ingested {count} events in one batch."})
            except FileNotFoundError:
                if options["once"]:
                    self.stdout.write("Log file does not exist yet; nothing to ingest.")
            if options["once"]:
                return
            time.sleep(max(options["sleep"], 0.2))

    def ingest(self, path, batch_size):
        file_path = Path(path)
        stat = file_path.stat()
        state, _ = CollectorState.objects.get_or_create(key=str(file_path.resolve()))
        offset = state.offset if state.inode == stat.st_ino and state.offset <= stat.st_size else 0
        inserted = 0
        with file_path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            batch = []
            while True:
                line = handle.readline(65536)
                if not line:
                    break
                try:
                    event = event_from_record(json.loads(line), line)
                except (json.JSONDecodeError, TypeError, ValueError):
                    event = None
                if event:
                    batch.append(event)
                if len(batch) >= batch_size:
                    NotFoundEvent.objects.bulk_create(batch, ignore_conflicts=True)
                    inserted += len(batch)
                    batch = []
            if batch:
                NotFoundEvent.objects.bulk_create(batch, ignore_conflicts=True)
                inserted += len(batch)
            new_offset = handle.tell()
        state.inode = stat.st_ino
        state.offset = new_offset
        state.save(update_fields=["inode", "offset", "updated_at"])
        return inserted
