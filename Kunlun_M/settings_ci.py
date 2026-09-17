import os
import platform as platform_pack

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = 'ci'
DEBUG = False
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'web.index',
    'web.dashboard',
    'web.backend',
    'web.api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'Kunlun_M.middleware.SDataMiddleware',
]

ROOT_URLCONF = 'Kunlun_M.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'Kunlun_M.wsgi.application'

TIME_ZONE = 'Asia/Shanghai'
LANGUAGE_CODE = 'en-us'
USE_I18N = True
USE_L10N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static")
]

TITLE = 'KunLun-M 控制台'
DESCRIPTION = 'KunLun-Mirror 专注于白帽子的静态代码审计工具'
SUPER_ADMIN = []
IS_OPEN_REGISTER = True

PROJECT_DIRECTORY = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

TMP_PATH = os.path.join(PROJECT_DIRECTORY, 'tmp', 'ci')
if os.path.isdir(TMP_PATH) is not True:
    os.makedirs(TMP_PATH, exist_ok=True)

RUNNING_PATH = os.path.join(TMP_PATH, 'running')
if os.path.isdir(RUNNING_PATH) is not True:
    os.makedirs(RUNNING_PATH, exist_ok=True)

PACKAGE_PATH = os.path.join(TMP_PATH, 'package')
if os.path.isdir(PACKAGE_PATH) is not True:
    os.makedirs(PACKAGE_PATH, exist_ok=True)

SOURCE_PATH = os.path.join(TMP_PATH, 'git')
if os.path.isdir(SOURCE_PATH) is not True:
    os.makedirs(SOURCE_PATH, exist_ok=True)

ISSUE_PATH = os.path.join(TMP_PATH, 'issue')
if os.path.isdir(ISSUE_PATH) is not True:
    os.makedirs(ISSUE_PATH, exist_ok=True)

EXPORT_PATH = os.path.join(TMP_PATH, 'export')
if not os.path.exists(EXPORT_PATH):
    os.makedirs(EXPORT_PATH, exist_ok=True)

RESULT_PATH = os.path.join(TMP_PATH, 'result')
if os.path.isdir(RESULT_PATH) is not True:
    os.makedirs(RESULT_PATH, exist_ok=True)
DEFAULT_RESULT_PATH = RESULT_PATH

HTML_TEMPLATE_PATH = ''

KUNLUN_MAIN = os.path.join(PROJECT_DIRECTORY, 'kunlun.py')
CORE_PATH = os.path.join(PROJECT_DIRECTORY, 'core')
TESTS_PATH = os.path.join(PROJECT_DIRECTORY, 'tests')
EXAMPLES_PATH = os.path.join(TESTS_PATH, 'examples')
RULES_PATH = os.path.join(PROJECT_DIRECTORY, 'rules')
CONFIG_PATH = os.path.join(PROJECT_DIRECTORY, 'config')
LOGS_PATH = os.path.join(PROJECT_DIRECTORY, 'logs')
PLUGIN_PATH = os.path.join(PROJECT_DIRECTORY, 'core', 'plugins')
IGNORE_PATH = os.path.join(PROJECT_DIRECTORY, 'Kunlun_M', '.kunlunmignore')

HISTORY_FILE_PATH = os.path.join(TMP_PATH, '.history')
MAX_HISTORY_LENGTH = 1000

PLATFORM = "Linux"
if "Windows" in platform_pack.system():
    PLATFORM = "windows"
elif "Linux" in platform_pack.system():
    PLATFORM = "linux"
elif "Darwin" in platform_pack.system():
    PLATFORM = "mac"

API_TOKEN = "ci"

IS_OPEN_REMOTE_SERVER = False
REMOTE_URL = "http://127.0.0.1:9999"
REMOTE_URL_APITOKEN = "ci"

WITH_VENDOR = False
ACTIVE_SCA_SYSTEM = ['osv', 'depsdev', 'ossindex']
MURPHYSEC_TOKEN = ""

db_dir = os.path.join(TMP_PATH, 'db')
if os.path.isdir(db_dir) is not True:
    os.makedirs(db_dir, exist_ok=True)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(db_dir, 'kunlun_ci.db'),
    }
}

