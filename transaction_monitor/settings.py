import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# ========================
# 🔐 SECURITY
# ========================

SECRET_KEY = os.environ.get("SECRET_KEY")

# Safer DEBUG handling
DEBUG = os.environ.get("DEBUG", "False") == "True"

# ========================
# 🌐 ALLOWED HOSTS
# ========================

RENDER_HOST = os.environ.get("RENDER_EXTERNAL_HOSTNAME")

ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
]

if RENDER_HOST:
    ALLOWED_HOSTS.append(RENDER_HOST)

# fallback (prevents 502 during misconfig)
if not ALLOWED_HOSTS:
    ALLOWED_HOSTS = ["*"]

# ========================
# 🛡️ CSRF
# ========================

CSRF_TRUSTED_ORIGINS = []

if RENDER_HOST:
    CSRF_TRUSTED_ORIGINS.append(f"https://{RENDER_HOST}")

# ========================
# ⚡ PERFORMANCE CACHE
# ========================

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
        "LOCATION": BASE_DIR / "cache",
        "TIMEOUT": 60 * 30,  # reduced memory pressure
    }
}

# ========================
#  APPS
# ========================

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "api",
]

# ========================
# 🔄 MIDDLEWARE
# ========================

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "api.middleware.EnsureAmlDatasetMiddleware",
]

# ========================
# 🌍 URLS / WSGI
# ========================

ROOT_URLCONF = "transaction_monitor.urls"
WSGI_APPLICATION = "transaction_monitor.wsgi.application"

# ========================
#  TEMPLATES
# ========================

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "api.context_processors.fing_flags",
            ],
        },
    },
]

# ========================
# DATABASE
# ========================

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

if DATABASE_URL:
    import dj_database_url

    DATABASES = {
        "default": dj_database_url.config(
            default=DATABASE_URL,
            conn_max_age=300,  # reduce memory
            ssl_require=True,
        )
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

# ========================
# AUTH
# ========================

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/monitoring/"
LOGOUT_REDIRECT_URL = "/login/"

# ========================
# INTERNATIONALIZATION
# ========================

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ========================
#  STATIC FILES
# ========================

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# ========================
# ⚙️ DJANGO REST
# ========================

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "20/hour",
        "user": "200/hour",
    },
}


# ========================
# 🤖 ML CONFIG (CRITICAL OPTIMIZATION)
# ========================

ML_MODEL_PATH = BASE_DIR / "ml_artifacts" / "finguard_best_model.pkl"
ML_PREPROCESSOR_PATH = BASE_DIR / "ml_artifacts" / "finguard_preprocessor.pkl"
ML_THRESHOLD_PATH = BASE_DIR / "ml_artifacts" / "threshold.json"

ML_OPTIMAL_THRESHOLD = 0.603939

# 🚨 Reduce memory footprint
ML_MAX_ALERT_ROWS = 500   # was 2000
ML_CACHE_TIMEOUT_SECONDS = 60 * 15

AML_MAX_CASE_PERSIST_ROWS = int(os.environ.get("AML_MAX_CASE_PERSIST_ROWS", "100000"))
AML_ANALYTICS_DB_MAX_ROWS = int(os.environ.get("AML_ANALYTICS_DB_MAX_ROWS", "100000"))

AML_DATASET_CSV = BASE_DIR / "transactions_dataset.csv"

# ⚠️ VERY IMPORTANT (prevents startup crash)
AML_AUTO_SYNC_DATASET = False

# ========================
# 🤖 OPENAI
# ========================

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")

OPENAI_CHAT_MAX_TOKENS = int(os.environ.get("OPENAI_CHAT_MAX_TOKENS", "500"))
OPENAI_CHAT_TEMPERATURE = float(os.environ.get("OPENAI_CHAT_TEMPERATURE", "0.2"))

# ========================
# 🔐 PROXY / HTTPS
# ========================

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Optional but recommended
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG