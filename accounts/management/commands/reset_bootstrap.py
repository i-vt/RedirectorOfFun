import secrets
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from accounts.models import BootstrapState, Operator
from accounts.services import digest_token


class Command(BaseCommand):
    help = "SSH-only recovery: replace an unclaimed bootstrap URL. Never reopens a claimed instance."

    def handle(self, *args, **options):
        if Operator.objects.filter(is_superuser=True, is_active=True).exists():
            raise CommandError("An active administrator exists; bootstrap cannot be reopened.")
        state = BootstrapState.objects.filter(slot=1).first()
        if state and state.claimed_at:
            raise CommandError("Bootstrap was already claimed; use administrator recovery instead.")
        token = secrets.token_urlsafe(32)
        if state:
            state.token_digest = digest_token(token)
            state.disabled = False
            state.save(update_fields=["token_digest", "disabled"])
        else:
            BootstrapState.objects.create(slot=1, token_digest=digest_token(token))
        self.stdout.write(f"{settings.BOOTSTRAP_BASE_URL}/setup/{token}/")
