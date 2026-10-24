from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from accounts.models import APIKey, Operator


class Command(BaseCommand):
    help = "Provision an API key for an operator; prints the full key exactly once."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("--name", default="cli provisioned")
        parser.add_argument("--days", type=int, default=0,
                            help="Expire after N days (0 = never)")

    def handle(self, *args, **options):
        operator = Operator.objects.filter(username=options["username"]).first()
        if operator is None:
            raise CommandError(f"operator '{options['username']}' not found")
        expires = None
        if options["days"]:
            expires = timezone.now() + timedelta(days=options["days"])
        api_key, raw = APIKey.create(operator=operator, name=options["name"], expires_at=expires)
        self.stdout.write(f"operator: {operator.username}")
        self.stdout.write(f"name:     {api_key.name}")
        self.stdout.write(f"prefix:   {api_key.prefix}")
        self.stdout.write("key:      " + raw)
        self.stdout.write(self.style.WARNING("Store it now; it will never be shown again."))
