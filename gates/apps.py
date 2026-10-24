from django.apps import AppConfig


class GatesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "gates"
    verbose_name = "Release gates and deliveries"
