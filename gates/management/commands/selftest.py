import json

from django.core.management.base import BaseCommand

from gates.selftest import is_healthy, run_selftest


class Command(BaseCommand):
    help = "Run control-plane self-tests (blocking checks gate startup with --strict)."

    def add_arguments(self, parser):
        parser.add_argument("--strict", action="store_true",
                            help="Exit non-zero if any blocking check fails.")
        parser.add_argument("--json", action="store_true", help="Emit results as JSON.")

    def handle(self, *args, **options):
        results = run_selftest()
        if options["json"]:
            self.stdout.write(json.dumps({"healthy": is_healthy(results), "checks": results}, indent=2))
        else:
            for result in results:
                marker = {"pass": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]", "skip": "[SKIP]"}[result["status"]]
                suffix = " (blocking)" if result["blocking"] else ""
                self.stdout.write(f"{marker} {result['name']}{suffix}: {result['message']}")
            self.stdout.write(f"healthy={is_healthy(results)}")
        if options["strict"] and not is_healthy(results):
            raise SystemExit(1)
