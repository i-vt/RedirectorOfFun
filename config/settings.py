"""Django settings for the RedirectorOfFun control plane."""
from pathlib import Path
import os
import sys
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name, default=False):
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


DEBUG = env_bool("DEBUG", True)
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "development-only-change-me")
ALLOWED_HOSTS = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "*").split(",") if h.strip()]
CSRF_TRUSTED_ORIGINS = [o.strip() for o in os.getenv("CSRF_TRUSTED_ORIGINS", "").split(",") if o.strip()]

INSTALLED_APPS = [
    "config.apps.ControlPlaneConfig",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "accounts",
    "audit",
    "analytics",
    "notifications",
    "gates",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "accounts.middleware.OperatorSessionMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "config.middleware.RequestIDMiddleware",
]

ROOT_URLCONF = "config.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [BASE_DIR / "templates"],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
        "accounts.context_processors.panel_context",
    ]},
}]
WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {"default": dj_database_url.config(
    default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
    conn_max_age=60,
    conn_health_checks=True,
)}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.Operator"
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "config.storage.StaticFilesStorage"},
}
if "test" in sys.argv:
    STORAGES["staticfiles"] = {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"}

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "overview"
LOGOUT_REDIRECT_URL = "login"
SESSION_COOKIE_AGE = 8 * 60 * 60
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", not DEBUG)
CSRF_COOKIE_SECURE = env_bool("CSRF_COOKIE_SECURE", not DEBUG)
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {"anon": "20/min", "user": "240/min"},
}

BOOTSTRAP_BASE_URL = os.getenv("BOOTSTRAP_BASE_URL", "http://localhost:3000").rstrip("/")
BOOTSTRAP_TOKEN_TTL_MINUTES = int(os.getenv("BOOTSTRAP_TOKEN_TTL_MINUTES", "0"))
INVITATION_TTL_HOURS = int(os.getenv("INVITATION_TTL_HOURS", "48"))
ANALYTICS_RETENTION_DAYS = int(os.getenv("ANALYTICS_RETENTION_DAYS", "30"))
ANALYTICS_ALERT_THRESHOLD = int(os.getenv("ANALYTICS_ALERT_THRESHOLD", "1000"))
ANALYTICS_IP_HASH_SALT = os.getenv("ANALYTICS_IP_HASH_SALT", "development-only-analytics-salt")
NGINX_JSON_LOG_PATH = os.getenv("NGINX_JSON_LOG_PATH", "/var/log/nginx/access.json")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Release gates / delivery links.
GATE_BASE_PATH = os.getenv("GATE_BASE_PATH", "/g/")
AGENT_BASE_PATH = os.getenv("AGENT_BASE_PATH", "/a/")
AUTO_BAN_THRESHOLD = int(os.getenv("AUTO_BAN_THRESHOLD", "5"))
NGINX_BAN_INCLUDE = os.getenv("NGINX_BAN_INCLUDE", "")
NGINX_AGENT_ROUTES_INCLUDE = os.getenv("NGINX_AGENT_ROUTES_INCLUDE", "")
PWNDROP_TIMEOUT = int(os.getenv("PWNDROP_TIMEOUT", "10"))
PWNDROP_MAX_BYTES = int(os.getenv("PWNDROP_MAX_BYTES", str(512 * 1024 * 1024)))
DECISION_UNDO_SECONDS = int(os.getenv("DECISION_UNDO_SECONDS", "10"))
DECOY_CANARIES = env_bool("DECOY_CANARIES", True)
REDIRECTOR_DOMAINS = [d.strip() for d in os.getenv("REDIRECTOR_DOMAINS", "").split(",") if d.strip()]
# Peers allowed to supply X-Forwarded-For; any other client has its own
# header ignored so it cannot spoof addresses for bans or telemetry.
TRUSTED_PROXIES = tuple(p.strip() for p in os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1").split(",") if p.strip())
SUBMISSION_MAX_BYTES = int(os.getenv("SUBMISSION_MAX_BYTES", str(4 * 1024 * 1024)))
VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_ADMIN_EMAIL = os.getenv("VAPID_ADMIN_EMAIL", "mailto:operators@example.com")
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "var" / "media"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": os.getenv("LOG_LEVEL", "INFO")},
}
