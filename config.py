"""
Конфигурация приложения.

Все секреты читаются из переменных окружения. Если SECRET_KEY не задан,
он генерируется один раз и сохраняется в файл .secret_key рядом с проектом:
это безопаснее, чем статический ключ в коде (файл создаётся с правами 0600),
и надёжнее, чем генерация при каждом старте (ключ остаётся стабильным между
перезапусками и одинаковым для всех воркеров PythonAnywhere).
"""
import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SECRET_KEY_FILE = BASE_DIR / ".secret_key"


def _load_or_create_secret_key() -> str:
    """SECRET_KEY из окружения, иначе — из файла .secret_key (создаётся сам)."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    try:
        return SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        pass
    new_key = secrets.token_hex(32)
    try:
        # O_CREAT | O_EXCL защищает от гонки, если несколько воркеров
        # PythonAnywhere стартуют одновременно.
        fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_key)
    except FileExistsError:
        pass  # другой воркер уже создал файл — просто перечитаем
    return SECRET_KEY_FILE.read_text(encoding="utf-8").strip()


class Config:
    """Базовая конфигурация Flask."""

    SECRET_KEY = _load_or_create_secret_key()

    # SQLite-файл лежит рядом с проектом. Путь абсолютный, поэтому одинаково
    # работает и локально, и в WSGI-окружении PythonAnywhere.
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{BASE_DIR / 'vpn_aggregator.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Ждём блокировку записи до 15 секунд (SQLite + несколько воркеров PA).
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"timeout": 15}}

    # --- Безопасность сессий ---
    SESSION_COOKIE_HTTPONLY = True   # JavaScript не может читать cookie сессии
    SESSION_COOKIE_SAMESITE = "Lax"  # базовая защита от CSRF при переходах извне
    # Secure-флаг требует HTTPS. На PythonAnywhere он есть всегда; для локальной
    # разработки по http://127.0.0.1:5000 запустите с INSECURE_COOKIES=1.
    SESSION_COOKIE_SECURE = os.environ.get("INSECURE_COOKIES") != "1"

    # --- Доверие к реверс-прокси ---
    # Включайте (TRUST_PROXY=1) ТОЛЬКО если домен закрыт прокси, который ВСЕГДА
    # ставит X-Forwarded-For (DDoS-Guard/Cloudflare перед приложением): тогда
    # IP клиента в журнале и rate limit входа считаются по реальному IP.
    # По умолчанию выключено: на PythonAnywhere remote_addr — уже реальный IP,
    # а слепое доверие к XFF позволило бы обходить rate limit подменой заголовка.
    TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY") == "1"

    # Сессия «протухает» через 12 часов неактивности
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)

    # --- Rate limiting страницы входа ---
    # Счётчик хранится в БД, поэтому лимит общий для всех воркеров PA
    # (in-memory лимиты при нескольких процессах не работают).
    LOGIN_MAX_ATTEMPTS = 5       # сколько неудачных попыток подряд
    LOGIN_WINDOW_MINUTES = 15    # за какой интервал

    # --- Ограничения загрузки источников (используются в utils/parser.py) ---
    FETCH_TIMEOUT = (5, 10)               # (connect, read), секунды
    MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # максимум 5 МБ на один источник
    MAX_SOURCES_PER_REQUEST = 50          # защита от слишком долгих запросов
