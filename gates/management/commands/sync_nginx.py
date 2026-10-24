from django.core.management.base import BaseCommand

from gates import services


class Command(BaseCommand):
    help = "Write nginx include files (banned IPs, agent routes) from the database."

    def handle(self, *args, **options):
        written = services.sync_nginx_files()
        if not written:
            self.stdout.write("No nginx include paths configured; nothing written.")
            return
        for path, ok in written.items():
            self.stdout.write(f"{'wrote' if ok else 'FAILED'} {path}")
        self.stdout.write("Reload nginx to apply: nginx -s reload")
