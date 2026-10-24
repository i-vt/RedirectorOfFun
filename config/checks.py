from django.conf import settings
from django.core.checks import Warning, register


@register()
def production_configuration_check(app_configs, **kwargs):
    messages = []
    if not settings.DEBUG:
        if settings.SECRET_KEY == "development-only-change-me":
            messages.append(Warning("DJANGO_SECRET_KEY must be set in production.", id="config.W001"))
        if settings.ANALYTICS_IP_HASH_SALT == "development-only-analytics-salt":
            messages.append(Warning("ANALYTICS_IP_HASH_SALT must be set in production.", id="config.W002"))
    return messages
