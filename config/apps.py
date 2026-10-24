from django.apps import AppConfig


class ControlPlaneConfig(AppConfig):
    name = "config"

    def ready(self):
        from . import checks  # noqa: F401
