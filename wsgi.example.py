"""
Образец WSGI-файла для PythonAnywhere.

Где использовать: вкладка Web -> секция Code -> файл
  /var/www/USERNAME_pythonanywhere_com_wsgi.py
Скопируйте содержимое ниже, заменив USERNAME на ваш логин и задав свой
SECRET_KEY (сгенерировать: python -c "import secrets; print(secrets.token_hex(32))").

Важно: переменные окружения задаются здесь, ДО импорта приложения, потому
что export в bash-консоли не сохраняется между перезагрузками приложения.
"""
import os
import sys

PROJECT_DIR = "/home/USERNAME/vpn-aggregator"
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

# Виртуальное окружение обычно привязывается во вкладке Web (поле Virtualenv).
# Если по какой-то причине это не сделано — раскомментируйте две строки ниже:
# VENV_SITE = "/home/USERNAME/.virtualenvs/vpn-env/lib/python3.10/site-packages"
# sys.path.insert(0, VENV_SITE)

# --- ОБЯЗАТЕЛЬНО: секрет для подписи сессий и CSRF -------------------------
os.environ.setdefault(
    "SECRET_KEY",
    "<ВСТАВЬТЕ_СЮДА_ЗНАЧЕНИЕ_python_-c_import_secrets_print_secrets.token_hex(32)>",
)

# --- ОДНОРАЗОВО: создание первого администратора при первом запуске --------
# Раскомментируйте, нажмите Reload, убедитесь, что вход работает, затем
# закомментируйте обратно (пароль не должен постоянно лежать в WSGI-файле).
# os.environ["ADMIN_USERNAME"] = "admin"
# os.environ["ADMIN_PASSWORD"] = "<пароль_минимум_8_символов>"

# --- ОПЦИОНАЛЬНО: домен закрыт реверс-прокси (DDoS-Guard / Cloudflare) -----
# Раскомментируйте, только если ваш домен (не *.pythonanywhere.com) работает
# через прокси, который ВСЕГДА ставит X-Forwarded-For: тогда в журнале
# записывается реальный IP клиента, а не IP прокси.
# os.environ["TRUST_PROXY"] = "1"

from app import app as application  # noqa: E402  (импорт после настройки env)
