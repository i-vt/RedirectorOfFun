from django.apps import AppConfig


class GatesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "gates"
    verbose_name = "Release gates and deliveries"

    def ready(self):
        from django.db.models.signals import post_migrate

        def _seed(sender, **kwargs):
            from .models import seed_builtin_decoys, seed_blocking_rule_presets
            seed_builtin_decoys()
            seed_blocking_rule_presets()

        post_migrate.connect(_seed, sender=self)
