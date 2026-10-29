
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Перемикач між захищеною версією і ні 
SECURE  = os.environ.get("SECURE", "0") == "1"

TEST_MODE = os.environ.get("TEST_MODE", "0") == "1"


SECRET_KEY = os.environ.get("SECRET_KEY", "dev") if SECURE else "dev"


DEBUG = False

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "django-p"] if SECURE else ["*"]


# Application definition

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'core'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    "core.middleware.csp_middleware", 
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'OPTIONS': {},
    }
]

WSGI_APPLICATION = 'config.wsgi.application'


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Cookie

SESSION_COOKIE_HTTPONLY = SECURE
SESSION_COOKIE_SAMESITE = "Lax" if SECURE else "None"
SESSION_COOKIE_SECURE = not SECURE
