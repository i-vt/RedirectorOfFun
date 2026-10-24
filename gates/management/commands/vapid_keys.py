import base64

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Generate a VAPID key pair for Web Push; put the values into your .env."

    def handle(self, *args, **options):
        from py_vapid import Vapid

        vapid = Vapid()
        vapid.generate_keys()
        private_key = base64.urlsafe_b64encode(vapid.private_key.to_pem()).decode() if hasattr(vapid.private_key, "to_pem") else vapid.private_key
        self.stdout.write("VAPID_PRIVATE_KEY=" + private_key.replace("\n", "\\n"))
        self.stdout.write("VAPID_PUBLIC_KEY=" + vapid.public_key_urlsafe_base64)
        self.stdout.write("VAPID_ADMIN_EMAIL=mailto:operators@example.com  # adjust")
