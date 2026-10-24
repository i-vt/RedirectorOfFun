from django.conf import settings
from django.core.management.base import BaseCommand

from gates import telegram


class Command(BaseCommand):
    help = "Poll Telegram for approval commands (reply 'approve <id>' / 'deny <id>')."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Process one batch and exit.")

    def handle(self, *args, **options):
        if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
            self.stdout.write("Telegram is not configured (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID); nothing to do.")
            return
        telegram.run_forever(once=options["once"])
        self.stdout.write("Telegram polling stopped.")
