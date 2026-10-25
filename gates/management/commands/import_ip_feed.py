import ipaddress
import json
import urllib.request

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from audit.services import record_event
from gates.models import BlockingRule, RuleSet
from gates import services

CHUNK = 500  # conditions per rule; keeps the JSON conditions lists manageable


class Command(BaseCommand):
    help = ("Import an IP/CIDR feed as a blocking ruleset - e.g. a curated list of "
            "security-vendor and sandbox ranges. Text feeds (one entry per line, "
            "'#' comments, CSV first column) replace the ruleset's rules; a "
            "rof-blocking-rules JSON export is imported via the normal importer.")

    def add_arguments(self, parser):
        parser.add_argument("--url", default=getattr(settings, "VENDOR_FEED_URL", ""),
                            help="Feed URL (or set VENDOR_FEED_URL).")
        parser.add_argument("--name", default="Vendor feed blocklist",
                            help="Ruleset name; existing rules in it are replaced.")
        parser.add_argument("--action", choices=["block", "allow"], default="block")
        parser.add_argument("--disabled", action="store_true",
                            help="Import the ruleset disabled (review before enabling).")

    def handle(self, *args, **options):
        url = options["url"]
        if not url:
            raise CommandError("Pass --url or set VENDOR_FEED_URL.")
        request = urllib.request.Request(url, headers={"User-Agent": settings.OUTBOUND_USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read(8 * 1024 * 1024)
        except OSError as exc:
            raise CommandError(f"fetch failed: {exc}")
        text = body.decode("utf-8", errors="replace")

        if text.lstrip().startswith("{"):
            payload = json.loads(text)
            sets_created, rules_created, errors = services.import_blocking_rules(payload)
            for error in errors:
                self.stderr.write(f"  ! {error}")
            self.stdout.write(f"Imported JSON export: {sets_created} set(s), {rules_created} rule(s).")
            return

        networks = self._parse_lines(text)
        if not networks:
            raise CommandError("no usable IP/CIDR entries found in the feed")

        ruleset, _ = RuleSet.objects.get_or_create(
            name=options["name"],
            defaults={"scope": "all", "enabled": not options["disabled"], "order": 0})
        ruleset.enabled = not options["disabled"]
        ruleset.save(update_fields=["enabled"])
        replaced = ruleset.rules.filter(preset=False).delete()[0]

        created = 0
        for index in range(0, len(networks), CHUNK):
            chunk = networks[index:index + CHUNK]
            BlockingRule.objects.create(
                name=f"{options['name']} #{index // CHUNK + 1}",
                ruleset=ruleset, order=index // CHUNK, action=options["action"],
                logic="any", enabled=True,
                conditions=[{"type": "cidr", "pattern": net} for net in chunk])
            created += 1
        record_event(action="gate.feed_imported", actor=None,
                     metadata={"ruleset": ruleset.name, "networks": len(networks),
                               "rules": created, "replaced_rules": replaced, "url": url[:200]})
        self.stdout.write(
            f"{ruleset.name}: {len(networks)} networks in {created} rule(s) "
            f"(replaced {replaced}), action={options['action']}, "
            f"{'enabled' if ruleset.enabled else 'DISABLED'}.")

    def _parse_lines(self, text):
        networks, seen = [], set()
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            token = line.replace(",", " ").split()[0].strip().strip('"')
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            key = str(network)
            if key not in seen:
                seen.add(key)
                networks.append(key)
        return networks
