from django.conf import settings
from django.core.management.base import BaseCommand
from accounts.services import ensure_bootstrap


class Command(BaseCommand):
    help = "Create and print the initial one-time administrator setup URL when required."

    def handle(self, *args, **options):
        token = ensure_bootstrap()
        if token:
            self.stdout.write("\nInitial administrator setup (anyone with this URL can claim it):")
            self.stdout.write(f"{settings.BOOTSTRAP_BASE_URL}/setup/{token}/\n")
        else:
            self.stdout.write("Administrator bootstrap is already configured or claimed.")
