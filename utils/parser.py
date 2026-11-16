"""
Загрузка и парсинг VPN-подписок (ядро агрегатора, без зависимости от Flask/БД).

Логика on-demand запроса /sub/<token>:
  1) безопасная загрузка источника: SSRF-защита, таймауты, лимиты размера;
     запрос маскируется под клиент Happ (см. HAPP_HEADERS), куки анти-DDoS
     (DDoS-Guard, Cloudflare) копятся через requests.Session, статусы
     403/429/503 повторяются с новым x-hwid;
  2) декодирование тела: sing-box/Happ/Xray JSON (outbounds -> URI) либо
     Base64 (стандартный/url-safe) -> plain text;
  3) извлечение строк vless://, vmess://, trojan://, ss:// и других;
  4) дедупликация по ПОЛНОЙ ссылке, включая название сервера;
  5) сборка единого списка + итоговый Base64 + subscription-userinfo.

Модуль не зависит от Flask и SQLAlchemy — его легко тестировать отдельно.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import logging
import random
import re
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Iterable

import requests

log = logging.getLogger(__name__)

# --- Значения по умолчанию (приложение передаёт свои из config.py) ----------
DEFAULT_TIMEOUT = (5, 10)                # (соединение, чтение), секунды
DEFAULT_MAX_BYTES = 5 * 1024 * 1024      # максимум 5 МБ на один источник
MAX_REDIRECTS = 5                        # редиректы идут через ручную проверку
FETCH_WORKERS = 8                        # параллельных потоков загрузки

# --- Обход анти-бот защиты источников (спуфинг клиента Happ) ------------------
# Сайты-источники (allvsub.cc и подобные) стоят за анти-DDoS (DDoS-Guard,
# Cloudflare) и отдают 403 любому запросу, который не похож на VPN-клиент:
# UA «python-requests/2.x» или браузерный Chrome отсекаются сразу.
#
# Решение: исходящий запрос маскируется под РЕАЛЬНЫЙ клиент Happ. Ниже —
# заголовки, перехваченные mitmproxy при загрузке подписки приложением Happ
# (HTTP/2 -> имена заголовков в нижнем регистре, как и шлёт сам Happ).

# Идентификатор устройства Happ. Сделан КОНСТАНТОЙ: источники, привязанные
# к устройству, должны видеть один и тот же «телефон» при каждом запросе
# агрегатора. Если к /sub/<token> обращается реальный клиент Happ, его
# НАСТОЯЩИЙ x-hwid перекрывает эту константу (см. _build_source_headers).
HAPP_HWID = "kjlol2w78avsdcxd"

# brotli («br» в accept-encoding) requests декодирует ТОЛЬКО при установленном
# пакете brotli/brotlicffi. Если пакета нет — просим gzip/deflate: иначе
# источник пришлёт brotli-байты, которые мы не сможем расшифровать.
try:
    import brotli  # noqa: F401
    _HAS_BROTLI = True
except ImportError:
    try:
        import brotlicffi  # noqa: F401
        _HAS_BROTLI = True
    except ImportError:
        _HAS_BROTLI = False

ACCEPT_ENCODING = "gzip, deflate, br" if _HAS_BROTLI else "gzip, deflate"

# Точный набор заголовков Happ (перехваченный mitmproxy запрос GET /s/...).
HAPP_HEADERS = {
    "user-agent": "Happ/4.13.0/macos catalyst/2606241216657",
    "accept": "*/*",                       # Happ готов принять любой формат
    "accept-encoding": ACCEPT_ENCODING,    # только сжатие, которое умеем читать
    "accept-language": "ru",               # язык интерфейса клиента
    "priority": "u=3",                     # HTTP/2-приоритет Happ, серверам безразличен
    "x-device-os": "macOS",                # ОС «устройства»
    "x-hwid": HAPP_HWID,                   # привязка подписки к устройству
    "x-app-version": "4.13.0",             # версия приложения
    "x-device-model": "Mac",               # модель устройства
    "x-ver-os": "26.6.2",                  # версия ОС
    "x-device-locale": "ru",               # локаль устройства
}

# Статусы, после которых нужна повторная попытка: анти-DDoS при первом визите
# отдаёт 403/429/503 ВМЕСТЕ с cookie (__ddg1_ / cf_clearance), и второй запрос
# с этой cookie обычно проходит. Куки копит requests.Session (см. safe_fetch).
ANTIBOT_STATUSES = frozenset({403, 429, 503})

MAX_RETRIES = 2                            # до 2 повторов после первой попытки
RETRY_DELAYS = ((0.5, 1.0), (1.0, 2.0))    # пауза между попытками, сек (random)

_HWID_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def generate_hwid() -> str:
    """
    Случайный HWID в формате Happ: 16 строчных букв и цифр
    (как реальный «kjlol2w78avsdcxd»). Используется при повторных попытках
    после 403: часть анти-бот систем привязывает выданную cookie к
    «устройству», и свежий HWID заставляет выдать новую cookie вместо отказа.
    """
    return "".join(random.choices(_HWID_ALPHABET, k=16))

# Заголовки КЛИЕНТА, которые разрешено пересылать источникам при загрузке
# подписки. Happ шлёт x-hwid (идентификатор устройства) — многие
# «персональные» источники без него отдают вместо ключей заглушку
# «Включите отправку HWID в настройках приложения». Всё, что вне списка
# (Cookie, Authorization и т.п.), наружу НЕ уходит.
FORWARDABLE_HEADERS = (
    "x-hwid", "user-agent", "x-device-os", "x-device-locale",
    "x-app-version", "x-device-model", "x-ver-os", "accept-language",
)

# --- Что извлекаем из подписок ----------------------------------------------
SUPPORTED_PREFIXES = (
    "vless://", "vmess://", "trojan://", "ss://", "ssr://",
    "hysteria://", "hysteria2://", "hy2://", "tuic://", "juicity://",
    "socks://", "socks4://", "socks5://", "anytls://",
)

# Имена хостов, которые запрещено открывать всегда (SSRF)
BLOCKED_HOSTNAMES = {
    "localhost", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "instance-data",
}
# «Внутренние» суффиксы (mDNS, зарезервированные TLD)
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan",
                    ".home", ".home.arpa", ".localdomain", ".invalid")


class FetchError(Exception):
    """Любая ошибка загрузки источника: сеть, SSRF, лимиты, HTTP-статус."""


@dataclass
class SourceResult:
    """Результат обработки одного источника."""
    source_id: int
    ok: bool
    count: int = 0                                  # уникальных ключей
    links: list[str] = field(default_factory=list)  # все извлечённые ссылки
    userinfo: dict = field(default_factory=dict)    # из заголовка subscription-userinfo
    error: str = ""
    stubs_removed: int = 0                          # сколько заглушек отсеяно


# =============================================================================
# 1. SSRF-защита
# =============================================================================
def _ip_is_forbidden(ip_str: str) -> bool:
    """True, если IP запрещён: приватный, loopback, link-local, reserved, multicast."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # нераспознанный формат — по умолчанию запрещаем
    # IPv4, «спрятанный» в IPv6 (::ffff:10.0.0.1) — проверяем настоящий адрес
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return (addr.is_unspecified or addr.is_loopback or addr.is_link_local
            or addr.is_private or addr.is_reserved or addr.is_multicast)


def _hostname_is_forbidden(hostname: str) -> bool:
    """True для localhost-подобных имён и IP-литералов из запрещённых диапазонов."""
    host = (hostname or "").lower().rstrip(".")
    if not host:
        return True
    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES):
        return True
    try:
        ipaddress.ip_address(host)   # это IP-литерал?
    except ValueError:
        return False                 # обычный домен — его проверит DNS-резолв
    return _ip_is_forbidden(host)


def resolve_hostname(hostname: str) -> set[str]:
    """Резолвит имя во все IPv4/IPv6. Ошибка DNS -> FetchError."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise FetchError(f"DNS: не удалось разрешить «{hostname}» ({exc})") from exc
    return {info[4][0] for info in infos}


def validate_url(url: str) -> None:
    """
    Полная проверка URL. Бросает FetchError, если:
      * схема не http/https;
      * хост — localhost/.local/.internal-подобное имя;
      * хост — IP-литерал из запрещённых диапазонов
        (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1, ...);
      * хост резолвится хотя бы в один запрещённый IP.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise FetchError(f"Некорректный URL: {exc}") from exc

    if parsed.scheme.lower() not in ("http", "https"):
        raise FetchError(
            f"Разрешены только схемы http/https (получено «{parsed.scheme or '—'}»)")
    if not parsed.hostname:
        raise FetchError("В URL нет имени хоста")
    if len(url) > 2048:
        raise FetchError("Слишком длинный URL")

    if _hostname_is_forbidden(parsed.hostname):
        raise FetchError(
            f"Хост «{parsed.hostname}» запрещён (localhost/приватный IP)")

    for ip in resolve_hostname(parsed.hostname):
        if _ip_is_forbidden(ip):
            raise FetchError(
                f"Хост «{parsed.hostname}» резолвится в запрещённый IP {ip} (SSRF)")


# =============================================================================
# 2. Безопасная загрузка
# =============================================================================
def _build_source_headers(extra_headers: dict | None) -> dict:
    """
    Собирает заголовки исходящего запроса к источнику.

    База — точный набор Happ (HAPP_HEADERS): маскировка нужна ЛЮБОМУ запросу,
    иначе анти-DDoS источника отвечает 403 на «python-requests» или браузер.

    Поверх базы ложатся разрешённые заголовки РЕАЛЬНОГО клиента
    (extra_headers, только имена из FORWARDABLE_HEADERS):
      * x-hwid и остальные x-device-* перекрывают константы — источник,
        привязанный к устройству, видит настоящий HWID клиента Happ;
      * user-agent пересылается ТОЛЬКО если это сам Happ. UA браузера
        (проверка источников из панели) или python-requests наружу не светим —
        именно такие UA и получают 403 от анти-бот защиты.
    Заголовки вне списка (Cookie, Authorization и т.п.) игнорируются.
    """
    headers = dict(HAPP_HEADERS)
    for name, value in (extra_headers or {}).items():
        lname = str(name).lower()
        if lname not in FORWARDABLE_HEADERS or not value:
            continue
        value = str(value)[:256]
        if lname == "user-agent" and not value.lower().startswith("happ/"):
            continue                    # браузер/curl/requests — подменяем на Happ
        headers[lname] = value
    return headers


def _read_limited(resp, max_bytes: int):
    """Читает тело ответа потоково, не держа в памяти больше max_bytes.
    Возвращает (bytes, headers); ответ закрывает сама."""
    declared = resp.headers.get("Content-Length", "")
    if declared.isdigit() and int(declared) > max_bytes:
        resp.close()
        raise FetchError(f"Ответ слишком большой: {int(declared)} байт (лимит {max_bytes})")
    chunks: list[bytes] = []
    received = 0
    try:
        for chunk in resp.iter_content(chunk_size=16384):
            received += len(chunk)
            chunks.append(chunk)
    finally:
        resp.close()
    return b"".join(chunks), resp.headers


def safe_fetch(url: str, timeout=DEFAULT_TIMEOUT,
               max_bytes: int = DEFAULT_MAX_BYTES,
               extra_headers: dict | None = None):
    """
    Загрузка источника с маскировкой под Happ и защитой от SSRF.
    В своём коде можно импортировать эту же функцию по имени fetch_subscription.

    Как обходится анти-бот защита (allvsub.cc, DDoS-Guard, Cloudflare):
      1) запрос идёт с точным набором заголовков Happ (см. HAPP_HEADERS);
      2) используется requests.Session(): куки анти-DDoS (например, __ddg1_),
         выданные источником в ответе 403/302, сохраняются в сессии и
         отправляются с повторным запросом и при редиректе. Без Session каждая
         попытка выглядела бы «новым устройством» и блокировалась бы заново;
      3) редиректы РАЗРЕШЕНЫ, но прослеживаются вручную: requests при
         allow_redirects=True не даёт проверить промежуточные хосты, а
         «белый» домен, редиректящий на 169.254.169.254, — классический обход
         SSRF-фильтров. Каждый хоп проверяется validate_url и идёт с теми же
         заголовками и куками сессии;
      4) при 403/429/503 — до MAX_RETRIES повторов с паузой (time.sleep +
         случайный джиттер) и НОВЫМ x-hwid (generate_hwid);
      5) если после повторов источник всё же отвечает 403, бросается
         понятная ошибка «403 Forbidden (Анти-бот защита)».

    Таймауты и сетевые ошибки тоже получают повторные попытки, после чего
    превращаются в FetchError с понятным текстом.

    extra_headers — разрешённые заголовки клиента (x-hwid, User-Agent и др.)
    для источников, привязанных к устройству; см. _build_source_headers.

    Возвращает (bytes, headers). Бросает FetchError при любом нарушении.
    """
    session = requests.Session()
    # Сбрасываем дефолтные заголовки requests (python-requests/2.x, его
    # Accept-Encoding): сессия должна отправлять ТОЛЬКО наш набор Happ.
    session.headers.clear()
    session.headers.update(_build_source_headers(extra_headers))

    current_url = url
    redirects = 0
    retries = 0
    try:
        while True:
            # SSRF-проверка каждого адреса: первый URL, каждый хоп редиректа
            # и каждая повторная попытка (DNS мог «переехать» на приватный IP).
            validate_url(current_url)
            try:
                resp = session.get(current_url, timeout=timeout,
                                   allow_redirects=False, stream=True)
            except requests.Timeout as exc:
                if retries < MAX_RETRIES:
                    retries += 1
                    time.sleep(random.uniform(*RETRY_DELAYS[retries - 1]))
                    continue
                raise FetchError("Таймаут при загрузке источника "
                                 "(истекло время ожидания ответа)") from exc
            except requests.ConnectionError as exc:
                if retries < MAX_RETRIES:
                    retries += 1
                    time.sleep(random.uniform(*RETRY_DELAYS[retries - 1]))
                    continue
                raise FetchError("Ошибка соединения с источником "
                                 f"({exc.__class__.__name__})") from exc

            if 300 <= resp.status_code < 400:
                # Редирект обрабатываем сами (allow_redirects=False выше).
                location = resp.headers.get("Location", "")
                resp.close()
                if not location:
                    raise FetchError(f"HTTP {resp.status_code} без заголовка Location")
                redirects += 1
                if redirects > MAX_REDIRECTS:
                    raise FetchError(f"Слишком много редиректов (>{MAX_REDIRECTS})")
                current_url = urllib.parse.urljoin(current_url, location)
                continue

            if resp.status_code == 200:
                return _read_limited(resp, max_bytes)

            resp.close()
            if resp.status_code in ANTIBOT_STATUSES and retries < MAX_RETRIES:
                retries += 1
                # Пауза с джиттером: анти-боты вычисляют роботов по строгим
                # одинаковым интервалам между запросами.
                time.sleep(random.uniform(*RETRY_DELAYS[retries - 1]))
                # Новый HWID: часть анти-DDoS привязывает выданную cookie к
                # «устройству» — свежий x-hwid просит выдать cookie заново.
                session.headers["x-hwid"] = generate_hwid()
                continue
            if resp.status_code == 403:
                raise FetchError("403 Forbidden (Анти-бот защита)")
            raise FetchError(f"HTTP {resp.status_code} от источника")
    finally:
        session.close()


# Имя-синоним: в своём коде функцию удобно импортировать как fetch_subscription.
fetch_subscription = safe_fetch


# =============================================================================
# 3. Декодирование тела подписки и извлечение ссылок
# =============================================================================
def decode_subscription(text: str) -> str:
    """
    Приводит тело подписки к plain text со ссылками (с диагностикой в лог).

    Порядок распознавания (старые ветки полностью сохранены, новые добавлены
    только ДО них, поэтому прежние форматы ведут себя как раньше):
      0) BOM в начале тела просто срезается;
      1) JSON (объект ИЛИ массив): sing-box/Happ/Xray-конфиги -> outbounds
         конвертируются в URI-ссылки (parse_singbox_json). Если ссылок не
         вышло — пробуем JSON-массив/словарь СТРОК-ссылок (так отдают
         некоторые панели);
      2) plain-text список ссылок — возвращается как есть;
      3) Base64 (стандартный/url-safe, с паддингом или без) декодируется;
         если внутри снова JSON — тоже конвертируется.
    """
    stripped = (text or "").strip()
    if stripped.startswith("\ufeff"):        # BOM от некоторых источников
        stripped = stripped.lstrip("\ufeff").strip()
    if not stripped:
        log.info("[DECODE] Пустое тело")
        return ""

    log.info("[DECODE] Первый символ тела: %r", stripped[:1])

    # --- Ветка 1: JSON (объект или массив) -----------------------------------
    if stripped[:1] in ("{", "["):
        sb_links = parse_singbox_json(stripped)
        if sb_links:
            log.info("[DECODE] JSON дал %d ссылок", len(sb_links))
            return "\n".join(sb_links)
        # JSON есть, но outbounds не дал ссылок: некоторые панели отдают
        # JSON-массив СТРОК-ссылок (["vless://..."]) или словарь строк.
        try:
            jdata = json.loads(stripped)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            jdata = None
        if isinstance(jdata, list):
            strs = [s.strip() for s in jdata
                    if isinstance(s, str)
                    and s.strip().lower().startswith(SUPPORTED_PREFIXES)]
            if strs:
                log.info("[DECODE] JSON-массив строк: %d ссылок", len(strs))
                return "\n".join(strs)
        elif isinstance(jdata, dict):
            strs = [str(v).strip() for v in jdata.values()
                    if isinstance(v, str)
                    and str(v).strip().lower().startswith(SUPPORTED_PREFIXES)]
            if strs:
                log.info("[DECODE] JSON-словарь со ссылками: %d строк", len(strs))
                return "\n".join(strs)
        log.info("[DECODE] JSON не дал ссылок, продолжаем поиск")

    # --- Ветка 2: plain-text список ссылок -----------------------------------
    if any(line.strip().lower().startswith(SUPPORTED_PREFIXES)
           for line in stripped.splitlines()[:5]):
        log.info("[DECODE] Обычный текстовый список ссылок")
        return stripped

    # --- Ветка 3: Base64 ------------------------------------------------------
    log.info("[DECODE] Пробуем Base64")
    compact = "".join(stripped.split())
    if len(compact) % 4 == 1:
        log.info("[DECODE] Невозможная длина для Base64 (%d) — отдаём как есть",
                 len(compact))
        return stripped

    normalized = compact.replace("-", "+").replace("_", "/")
    padded = normalized + "=" * ((4 - len(normalized) % 4) % 4)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", padded):
        log.info("[DECODE] Не похоже на Base64 — отдаём как есть")
        return stripped

    try:
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
        log.info("[DECODE] Base64 декодирован: %d символов", len(decoded))
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        log.info("[DECODE] Ошибка декодирования Base64: %s", exc)
        return stripped

    # Иногда источник отдаёт Base64 от sing-box/Happ/Xray JSON — конвертируем
    if decoded.strip()[:1] in ("{", "["):
        sb_links = parse_singbox_json(decoded)
        if sb_links:
            log.info("[DECODE] Внутри Base64 найден JSON: %d ссылок", len(sb_links))
            return "\n".join(sb_links)

    # Считаем это base64-подпиской, только если внутри получились ссылки
    if "://" in decoded:
        return decoded
    log.info("[DECODE] В декодированном тексте нет ссылок — отдаём как есть")
    return stripped


# =============================================================================
# 3.1 sing-box / Happ JSON -> URI-ссылки
# =============================================================================
# Транспорт sing-box -> значение параметра type= в URI (v2rayN/Xray-соглашения)
_SINGBOX_TRANSPORT_URI = {
    "ws": "ws", "grpc": "grpc", "http": "http",
    "httpupgrade": "httpupgrade", "quic": "quic",
}
# Транспорт sing-box -> поле net= в vmess-JSON (h2 = HTTP/2-транспорт)
_SINGBOX_TRANSPORT_NET = {
    "ws": "ws", "grpc": "grpc", "http": "h2",
    "httpupgrade": "httpupgrade", "quic": "quic", "": "tcp",
}


def _sb_port(outbound: dict) -> int:
    """server_port -> int (в «кривых» конфигах бывает строкой); 0 = неверный."""
    try:
        return int(outbound.get("server_port") or 0)
    except (TypeError, ValueError):
        return 0


def _sb_format_host(server: str) -> str:
    """IPv6-литерал без скобок -> [ipv6]; домены/IPv4 не трогаем."""
    server = str(server).strip().strip("[]")
    return f"[{server}]" if ":" in server else server


def _sb_uri_join(scheme: str, authority: str, params: dict, tag: str) -> str:
    """Собирает URI вида scheme://authority?key=val&...#tag."""
    query_parts = []
    for k, v in params.items():
        if v in ("", None):
            continue
        # ALPN не должен кодировать слэши и запятые (h2,http/1.1)
        safe_chars = '/' if k == 'alpn' else ''
        query_parts.append(f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(v), safe=safe_chars)}")

    query = "&".join(query_parts)
    link = f"{scheme}://{authority}"
    if query:
        link += "?" + query
    if tag:
        link += "#" + urllib.parse.quote(str(tag), safe="")
    return link


def _sb_tls_params(outbound: dict) -> dict:
    """
    Блок tls sing-box -> параметры URI security/sni/fp/alpn/pbk/sid/allowInsecure.

      security=tls      — обычный TLS;
      security=reality  — REALITY: public_key (pbk) и short_id (sid) обязательны;
      fp                — отпечаток uTLS (chrome/firefox/...);
      allowInsecure=1   — если источник сам разрешил невалидные сертификаты.
    """
    params: dict = {}
    tls = outbound.get("tls")
    if not isinstance(tls, dict):
        return params
    reality = tls.get("reality") if isinstance(tls.get("reality"), dict) else {}
    if reality.get("enabled"):
        params["security"] = "reality"
        if reality.get("public_key"):
            params["pbk"] = str(reality["public_key"])
        if reality.get("short_id"):
            params["sid"] = str(reality["short_id"])
    elif tls.get("enabled"):
        params["security"] = "tls"
    else:
        return params                       # TLS выключен — параметров нет
    if tls.get("server_name"):
        params["sni"] = str(tls["server_name"])
    utls = tls.get("utls") if isinstance(tls.get("utls"), dict) else {}
    if utls.get("enabled") and utls.get("fingerprint"):
        params["fp"] = str(utls["fingerprint"])
    alpn = tls.get("alpn")
    if isinstance(alpn, list) and alpn:
        params["alpn"] = ",".join(str(a) for a in alpn)
    if tls.get("insecure"):
        params["allowInsecure"] = "1"
    return params


def _sb_transport_params(outbound: dict) -> dict:
    """
    Блок transport sing-box -> параметры URI type/path/host/serviceName/ed/eh.

      ws          -> type=ws&path=...&host=... (+ed/eh: WebSocket 0-RTT);
      grpc        -> type=grpc&serviceName=...;
      http        -> type=http&path=...&host=... (host может быть списком);
      httpupgrade -> type=httpupgrade&path=...&host=...
    """
    params: dict = {}
    tr = outbound.get("transport")
    if not isinstance(tr, dict):
        return params
    ttype = str(tr.get("type", "")).lower()
    uri_type = _SINGBOX_TRANSPORT_URI.get(ttype, ttype)
    if uri_type:
        params["type"] = uri_type
    if ttype == "ws":
        if tr.get("path"):
            params["path"] = str(tr["path"])
        headers = tr.get("headers") if isinstance(tr.get("headers"), dict) else {}
        # sing-box пишет «Host», но встречается и строчная запись
        host = headers.get("Host") or headers.get("host")
        if host:
            params["host"] = str(host)
        try:
            early = int(tr.get("max_early_data") or 0)
        except (TypeError, ValueError):
            early = 0
        if early > 0:                       # ws 0-RTT: v2rayN-соглашение ed/eh
            params["ed"] = str(early)
            if tr.get("early_data_header_name"):
                params["eh"] = str(tr["early_data_header_name"])
    elif ttype == "grpc":
        if tr.get("service_name"):
            params["serviceName"] = str(tr["service_name"])
    elif ttype in ("http", "httpupgrade"):
        host = tr.get("host")
        if isinstance(host, list):
            host = ",".join(str(h) for h in host if h)
        if host:
            params["host"] = str(host)
        if tr.get("path"):
            params["path"] = str(tr["path"])
    return params


def _sb_vless(outbound: dict) -> str:
    """vless://uuid@server:port?encryption=none&security=...&type=...#tag"""
    uuid = str(outbound.get("uuid") or "")
    server = str(outbound.get("server") or "")
    port = _sb_port(outbound)
    if not uuid or not server or port <= 0:
        return ""
    params = {"encryption": "none"}         # vless всегда шифрует внутри TLS
    params.update(_sb_tls_params(outbound))
    params.update(_sb_transport_params(outbound))
    if outbound.get("flow"):
        params["flow"] = str(outbound["flow"])
    authority = f"{uuid}@{_sb_format_host(server)}:{port}"
    return _sb_uri_join("vless", authority, params, outbound.get("tag") or "")


def _sb_vmess(outbound: dict) -> str:
    """
    vmess://<base64 JSON> (формат v2rayN) — так ссылку понимают все клиенты.

    Транспорт/TLS из sing-box маппятся в поля net/host/path/tls/sni/scy.
    """
    uuid = str(outbound.get("uuid") or "")
    server = str(outbound.get("server") or "")
    port = _sb_port(outbound)
    if not uuid or not server or port <= 0:
        return ""
    tr = outbound.get("transport") if isinstance(outbound.get("transport"), dict) else {}
    ttype = str(tr.get("type", "")).lower()
    tls = outbound.get("tls") if isinstance(outbound.get("tls"), dict) else {}
    utls = tls.get("utls") if isinstance(tls.get("utls"), dict) else {}
    alpn = tls.get("alpn")
    host = ""
    path = ""
    if ttype == "ws":
        headers = tr.get("headers") if isinstance(tr.get("headers"), dict) else {}
        host = str(headers.get("Host") or headers.get("host") or "")
        path = str(tr.get("path") or "")
    elif ttype == "grpc":
        path = str(tr.get("service_name") or "")   # у v2rayN serviceName живёт в path
    elif ttype in ("http", "httpupgrade"):
        h = tr.get("host")
        host = ",".join(str(x) for x in h) if isinstance(h, list) else str(h or "")
        path = str(tr.get("path") or "")
    payload = {
        "v": "2",                               # версия формата vmess-ссылки
        "ps": str(outbound.get("tag") or ""),
        "add": server,
        "port": str(port),
        "id": uuid,
        "aid": str(outbound.get("alter_id") or 0),
        "scy": str(outbound.get("security") or "auto"),   # шифрование vmess
        "net": _SINGBOX_TRANSPORT_NET.get(ttype, "tcp"),
        "type": "",                             # header type (kcp) — нет в sing-box
        "host": host,
        "path": path,
        "tls": "tls" if tls.get("enabled") else "",
        "sni": str(tls.get("server_name") or ""),
        "alpn": ",".join(str(a) for a in alpn) if isinstance(alpn, list) else "",
        "fp": str(utls.get("fingerprint") or "") if utls.get("enabled") else "",
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return "vmess://" + b64


def _sb_trojan(outbound: dict) -> str:
    """trojan://пароль@server:port?security=tls&sni=...&type=...#tag"""
    password = str(outbound.get("password") or "")
    server = str(outbound.get("server") or "")
    port = _sb_port(outbound)
    if not password or not server or port <= 0:
        return ""
    params: dict = {}
    tls_params = _sb_tls_params(outbound)
    # У trojan TLS подразумевается всегда: если в конфиге блок tls не задан,
    # всё равно проставим security=tls, чтобы клиент не решил иначе.
    params.update(tls_params if tls_params else {"security": "tls"})
    params.update(_sb_transport_params(outbound))
    authority = f"{urllib.parse.quote(password, safe='')}@{_sb_format_host(server)}:{port}"
    return _sb_uri_join("trojan", authority, params, outbound.get("tag") or "")


def _sb_shadowsocks(outbound: dict) -> str:
    """
    ss://<base64url(method:password)>@server:port[#tag] — SIP002.

    Плагин (obfs/v2ray-plugin), если есть, идёт параметром ?plugin=...
    """
    method = str(outbound.get("method") or "")
    password = str(outbound.get("password") or "")
    server = str(outbound.get("server") or "")
    port = _sb_port(outbound)
    if not method or not password or not server or port <= 0:
        return ""
    userinfo = base64.urlsafe_b64encode(
        f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
    link = f"ss://{userinfo}@{_sb_format_host(server)}:{port}"
    plugin = str(outbound.get("plugin") or "")
    if plugin:                              # например obfs-local;obfs=http;obfs-host=...
        opts = str(outbound.get("plugin_opts") or "")
        link += "?plugin=" + urllib.parse.quote(f"{plugin};{opts}".rstrip(";"), safe="")
    if outbound.get("tag"):
        link += "#" + urllib.parse.quote(str(outbound["tag"]), safe="")
    return link


_SINGBOX_BUILDERS = {
    "vless": _sb_vless,
    "vmess": _sb_vmess,
    "trojan": _sb_trojan,
    "shadowsocks": _sb_shadowsocks,
    "ss": _sb_shadowsocks,
}


# --- Формат Xray-core / Happ-экспорт (protocol/settings/streamSettings) ------

# «Настоящие» серверные outbound-ы: у Xray протокол лежит в «protocol»,
# у sing-box — в «type». DIRECT/BLOCK/freedom/blackhole/selector/urltest/dns
# в набор не входят и при сборке ссылок пропускаются.
_XRAY_PROTOCOLS = frozenset({"vless", "vmess", "trojan", "shadowsocks"})
_REAL_OUTBOUND_KINDS = _XRAY_PROTOCOLS | set(_SINGBOX_BUILDERS)

# Обобщённые теги-заглушки вида «proxy», «proxy-1», «proxy_2»: имя из них
# берётся, только если ничего содержательнее нет (см. parse_singbox_json).
_GENERIC_PROXY_TAGS = re.compile(r"^(proxy|proxy[-_ ]?\d+)$", re.IGNORECASE)


def _xray_tls_params(stream: dict) -> dict:
    """Блок streamSettings (security: tls/reality) -> параметры URI."""
    security = str(stream.get("security") or "none").lower()

    if security == "reality":
        rs = stream.get("realitySettings")
        rs = rs if isinstance(rs, dict) else {}
        params: dict = {"security": "reality"}

        # Поддержка serverName и serverNames (массив)
        sni = rs.get("serverName")
        if not sni and isinstance(rs.get("serverNames"), list) and rs["serverNames"]:
            sni = rs["serverNames"][0]
        if sni:
            params["sni"] = str(sni)

        # Поддержка shortId и shortIds (массив)
        sid = rs.get("shortId")
        if not sid and isinstance(rs.get("shortIds"), list) and rs["shortIds"]:
            sid = rs["shortIds"][0]
        if sid:
            params["sid"] = str(sid)

        if rs.get("fingerprint"):
            params["fp"] = str(rs["fingerprint"])

        # Если publicKey нет, а privateKey есть — это ошибка генератора конфигов,
        # но мы попытаемся использовать его как pbk.
        pbk = rs.get("publicKey")
        if not pbk:
            pbk = rs.get("privateKey")
        if pbk:
            params["pbk"] = str(pbk)

        if rs.get("spiderX"):
            params["spx"] = str(rs["spiderX"])
        return params

    if security == "tls":
        ts = stream.get("tlsSettings")
        ts = ts if isinstance(ts, dict) else {}
        params = {"security": "tls"}

        sni = ts.get("serverName")
        if not sni and isinstance(ts.get("serverNames"), list) and ts["serverNames"]:
            sni = ts["serverNames"][0]

        if sni:
            params["sni"] = str(sni)
            # Если домен заканчивается на .internal или .local,
            # это самоподписанный сертификат. Принудительно разрешаем.
            if ".internal" in str(sni) or ".local" in str(sni):
                params["allowInsecure"] = "1"

        if ts.get("fingerprint"):
            params["fp"] = str(ts["fingerprint"])

        alpn = ts.get("alpn")
        if isinstance(alpn, list) and alpn:
            params["alpn"] = ",".join(str(a) for a in alpn)
        elif isinstance(alpn, str) and alpn:
            params["alpn"] = alpn

        # Если в конфиге есть жесткая привязка сертификата,
        # Happ не сможет его проверить, нужен allowInsecure.
        if (ts.get("allowInsecure") or ts.get("insecure")
                or ts.get("pinnedPeerCertSha256") or ts.get("verifyPeerCertByName")):
            params["allowInsecure"] = "1"

        return params

    return {"security": "none"}


def _xray_transport_params(stream: dict) -> dict:
    """
    Блок streamSettings (network) -> параметры URI type/path/host/...

      ws -> type=ws&path=&host=; grpc -> type=grpc&serviceName=...;
      http/h2 -> type=http&path=&host=; httpupgrade/kcp/quic — аналогично;
      tcp с http-маскировкой -> headerType=http&path=&host=.
    """
    network = str(stream.get("network") or "tcp").lower()
    params: dict = {}
    if network not in ("", "tcp", "raw"):
        # «h2» в URI называется «http» (соглашение v2rayN/Xray)
        params["type"] = "http" if network in ("http", "h2") else network

    if network in ("tcp", "raw"):
        tcp = stream.get("tcpSettings")
        tcp = tcp if isinstance(tcp, dict) else {}
        header = tcp.get("header")
        header = header if isinstance(header, dict) else {}
        htype = str(header.get("type") or "")
        if htype and htype != "none":       # TCP с http-маскировкой
            params["headerType"] = htype
            request = header.get("request")
            request = request if isinstance(request, dict) else {}
            raw_path = request.get("path")
            if isinstance(raw_path, list) and raw_path:
                params["path"] = str(raw_path[0])
            elif raw_path:
                params["path"] = str(raw_path)
            req_headers = request.get("headers")
            req_headers = req_headers if isinstance(req_headers, dict) else {}
            raw_host = req_headers.get("Host") or req_headers.get("host")
            if raw_host:
                params["host"] = (",".join(str(x) for x in raw_host)
                                  if isinstance(raw_host, list) else str(raw_host))
    elif network == "ws":
        ws = stream.get("wsSettings")
        ws = ws if isinstance(ws, dict) else {}
        if ws.get("path"):
            params["path"] = str(ws["path"])
        headers = ws.get("headers")
        headers = headers if isinstance(headers, dict) else {}
        host = headers.get("Host") or headers.get("host") or ws.get("host")
        if host:
            params["host"] = str(host)
    elif network == "grpc":
        g = stream.get("grpcSettings")
        g = g if isinstance(g, dict) else {}
        if g.get("serviceName"):
            params["serviceName"] = str(g["serviceName"])
        if g.get("multiMode"):
            params["mode"] = "multi"
    elif network in ("http", "h2"):
        h = stream.get("httpSettings")
        h = h if isinstance(h, dict) else {}
        host = h.get("host")
        if isinstance(host, list):
            host = ",".join(str(x) for x in host if x)
        if host:
            params["host"] = str(host)
        if h.get("path"):
            params["path"] = str(h["path"])
    elif network == "httpupgrade":
        hu = stream.get("httpupgradeSettings")
        hu = hu if isinstance(hu, dict) else {}
        if hu.get("host"):
            params["host"] = str(hu["host"])
        if hu.get("path"):
            params["path"] = str(hu["path"])
    elif network == "kcp":
        k = stream.get("kcpSettings")
        k = k if isinstance(k, dict) else {}
        header = k.get("header")
        header = header if isinstance(header, dict) else {}
        htype = str(header.get("type") or "")
        if htype and htype != "none":
            params["headerType"] = htype
        if k.get("seed"):
            params["seed"] = str(k["seed"])
    elif network == "quic":
        q = stream.get("quicSettings")
        q = q if isinstance(q, dict) else {}
        if q.get("security"):
            params["quicSecurity"] = str(q["security"])
        if q.get("key"):
            params["key"] = str(q["key"])
        header = q.get("header")
        header = header if isinstance(header, dict) else {}
        htype = str(header.get("type") or "")
        if htype and htype != "none":
            params["headerType"] = htype
    return params

def _xray_vmess_link(user: dict, address: str, port: int,
                     stream: dict, name: str) -> str:
    """Xray-vmess -> vmess://<base64 JSON> (формат v2rayN)."""
    uuid = str(user.get("id") or "").strip()
    if not uuid:
        return ""
    network = str(stream.get("network") or "tcp").lower()
    security = str(stream.get("security") or "none").lower()

    ts = stream.get("tlsSettings")
    ts = ts if isinstance(ts, dict) else {}
    rs = stream.get("realitySettings")
    rs = rs if isinstance(rs, dict) else {}

    host = ""
    path = ""
    header_type = ""
    if network == "ws":
        ws = stream.get("wsSettings")
        ws = ws if isinstance(ws, dict) else {}
        headers = ws.get("headers")
        headers = headers if isinstance(headers, dict) else {}
        host = str(headers.get("Host") or headers.get("host") or ws.get("host") or "")
        path = str(ws.get("path") or "")
    elif network == "grpc":
        g = stream.get("grpcSettings")
        g = g if isinstance(g, dict) else {}
        path = str(g.get("serviceName") or "")
    elif network in ("http", "h2"):
        h = stream.get("httpSettings")
        h = h if isinstance(h, dict) else {}
        raw_host = h.get("host")
        host = (",".join(str(x) for x in raw_host)
                if isinstance(raw_host, list) else str(raw_host or ""))
        path = str(h.get("path") or "")
    elif network == "httpupgrade":
        hu = stream.get("httpupgradeSettings")
        hu = hu if isinstance(hu, dict) else {}
        host = str(hu.get("host") or "")
        path = str(hu.get("path") or "")
    elif network in ("tcp", "raw"):
        tcp = stream.get("tcpSettings")
        tcp = tcp if isinstance(tcp, dict) else {}
        header = tcp.get("header")
        header = header if isinstance(header, dict) else {}
        header_type = str(header.get("type") or "")
        if header_type and header_type != "none":
            request = header.get("request")
            request = request if isinstance(request, dict) else {}
            raw_path = request.get("path")
            path = (str(raw_path[0]) if isinstance(raw_path, list) and raw_path
                    else str(raw_path or ""))
            req_headers = request.get("headers")
            req_headers = req_headers if isinstance(req_headers, dict) else {}
            raw_host = req_headers.get("Host") or req_headers.get("host")
            host = (",".join(str(x) for x in raw_host)
                    if isinstance(raw_host, list) else str(raw_host or ""))
        else:
            header_type = ""

    # Исправление массивов serverNames для SNI
    sni = ts.get("serverName")
    if not sni and isinstance(ts.get("serverNames"), list) and ts["serverNames"]:
        sni = ts["serverNames"][0]
    if not sni:
        sni = rs.get("serverName")
    if not sni and isinstance(rs.get("serverNames"), list) and rs["serverNames"]:
        sni = rs["serverNames"][0]

    alpn = ts.get("alpn")
    if isinstance(alpn, list):
        alpn_str = ",".join(str(a) for a in alpn)
    else:
        alpn_str = str(alpn or "")

    payload = {
        "v": "2",
        "ps": name,
        "add": address,
        "port": str(port),
        "id": uuid,
        "aid": str(user.get("alterId") or 0),
        "scy": str(user.get("security") or "auto"),
        "net": "tcp" if network in ("", "raw", "tcp") else network,
        "type": header_type,
        "host": host,
        "path": path,
        "tls": "tls" if security in ("tls", "reality") else "",
        "sni": str(sni or ""),
        "alpn": alpn_str,
        "fp": str(ts.get("fingerprint") or rs.get("fingerprint") or ""),
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(raw.encode("utf-8")).decode("ascii")


def _parse_xray_outbound(ob: dict, remark_override: str = "") -> str:
    """
    Один outbound формата Xray-core (v2ray JSON) -> URI-ссылка.

    Структура: {"protocol": "vless", "settings": {"vnext": [...]},
                "streamSettings": {...}}.

    Имя сервера (по убыванию приоритета):
      * remark_override — «remarks» КОРНЕВОГО объекта конфига. В экспортах
        Happ/Xray красивое имя («🇬🇧 Paper VPN | Великобритания») лежит на
        уровень ВЫШЕ, а в поле tag обычно скучный «proxy»;
      * собственные remarks/remark/name outbound-а (встречается в кривых
        конфигах);
      * tag outbound-а.
    """
    proto = str(ob.get("protocol") or "").lower()
    if proto not in ("vless", "vmess", "trojan", "shadowsocks"):
        return ""

    name = str(remark_override or "").strip()
    if not name:
        name = str(ob.get("remarks") or ob.get("remark")
                   or ob.get("name") or ob.get("tag") or "").strip()

    settings = ob.get("settings")
    settings = settings if isinstance(settings, dict) else {}
    stream = ob.get("streamSettings")
    stream = stream if isinstance(stream, dict) else {}

    if proto in ("vless", "vmess"):
        vnext = settings.get("vnext")
        if (not isinstance(vnext, list) or not vnext
                or not isinstance(vnext[0], dict)):
            return ""
        node = vnext[0]
        address = str(node.get("address") or "").strip()
        try:
            port = int(node.get("port") or 0)
        except (TypeError, ValueError):
            return ""
        users = node.get("users")
        if (not address or port <= 0 or not isinstance(users, list)
                or not users or not isinstance(users[0], dict)):
            return ""
        user = users[0]

        if proto == "vmess":
            return _xray_vmess_link(user, address, port, stream, name)

        # --- vless -----------------------------------------------------------
        uuid = str(user.get("id") or "").strip()
        if not uuid:
            return ""
        params: dict = {}
        enc = str(user.get("encryption") or "none")
        # mlkem (post-quantum) в URI пока не переносят — отдаём «none»,
        # чтобы клиент вообще взял ключ
        params["encryption"] = "none" if "mlkem" in enc.lower() else enc
        params.update(_xray_tls_params(stream))
        params.update(_xray_transport_params(stream))
        # ВАЖНО: flow (xtls-rprx-vision) обязателен для REALITY/Vision —
        # без него сервер отклоняет соединение. Раньше поле извлекалось,
        # но в ссылку не попадало — часть серверов не подключалась.
        flow = str(user.get("flow") or "").strip()
        if flow:
            params["flow"] = flow
        authority = f"{uuid}@{_sb_format_host(address)}:{port}"
        return _sb_uri_join("vless", authority, params, name)

    # --- trojan / shadowsocks: данные в settings.servers ----------------------
    servers = settings.get("servers")
    if (not isinstance(servers, list) or not servers
            or not isinstance(servers[0], dict)):
        return ""
    node = servers[0]
    address = str(node.get("address") or "").strip()
    try:
        port = int(node.get("port") or 0)
    except (TypeError, ValueError):
        return ""
    if not address or port <= 0:
        return ""

    if proto == "trojan":
        password = str(node.get("password") or "")
        if not password:
            return ""
        params = _xray_tls_params(stream)
        if not params:
            # TLS у trojan подразумевается всегда, даже без блока streamSettings
            params = {"security": "tls"}
        params.update(_xray_transport_params(stream))
        authority = (f"{urllib.parse.quote(password, safe='')}"
                     f"@{_sb_format_host(address)}:{port}")
        return _sb_uri_join("trojan", authority, params, name)

    # shadowsocks (SIP002)
    method = str(node.get("method") or "")
    password = str(node.get("password") or "")
    if not method or not password:
        return ""
    userinfo = base64.urlsafe_b64encode(
        f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
    link = f"ss://{userinfo}@{_sb_format_host(address)}:{port}"
    if name:
        link += "#" + urllib.parse.quote(name, safe="")
    return link


def _apply_link_name(link: str, name: str) -> str:
    """
    Принудительно ставит имя в ГОТОВУЮ ссылку:
      * vless/trojan/ss/... — fragment после «#» (percent-кодируется);
      * vmess://base64(JSON) — название живёт ВНУТРИ payload (поле «ps»),
        fragment клиенты игнорируют, поэтому декодируем, меняем «ps»,
        кодируем обратно.
    """
    name = str(name or "").strip()
    if not name or not link:
        return link
    if link.lower().startswith("vmess://"):
        payload = link[len("vmess://"):].split("#", 1)[0].strip()
        try:
            padded = payload.replace("-", "+").replace("_", "/")
            padded += "=" * ((4 - len(padded) % 4) % 4)
            data = json.loads(base64.b64decode(padded).decode("utf-8"))
            if isinstance(data, dict):
                data["ps"] = name
                raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
                return "vmess://" + base64.b64encode(raw.encode("utf-8")).decode("ascii")
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            pass                    # нераспарсиваемый vmess — хотя бы fragment
    base = link.split("#", 1)[0]
    return f"{base}#{urllib.parse.quote(name, safe='')}"


def _build_any_outbound(ob: dict, remark_override: str = "") -> str:
    """Один outbound (Xray- или sing-box-формат) -> URI-ссылка."""
    proto = str(ob.get("protocol") or "").lower()
    if proto in _XRAY_PROTOCOLS:
        return _parse_xray_outbound(ob, remark_override)
    builder = _SINGBOX_BUILDERS.get(str(ob.get("type") or "").lower())
    if builder is None:
        return ""
    try:
        link = builder(ob)
    except Exception as exc:                # один битый узел не роняет остальные
        log.debug("JSON: outbound %r пропущен (%s: %s)",
                  ob.get("tag"), type(exc).__name__, exc)
        return ""
    if link and remark_override:
        link = _apply_link_name(link, remark_override)
    return link


def _collect_configs(data) -> list[dict]:
    """
    Извлекает из разобранного JSON все объекты-конфиги с блоком «outbounds».

    Понимаемые формы:
      * {"outbounds": [...]} — обычный sing-box/Happ конфиг;
      * [ {"outbounds": [...]}, ... ] — экспорт Happ/Xray: МАССИВ полных
        конфигов, у каждого своё имя в «remarks»;
      * [ {...}, {...} ] — «голый» массив outbound-ов без обёртки;
      * одиночный outbound-объект без обёртки.
    """
    configs: list[dict] = []
    if isinstance(data, dict):
        if isinstance(data.get("outbounds"), list):
            configs.append(data)
        else:
            # одиночный outbound: {"type": "vless", "server": ..., ...}
            kind = str(data.get("type") or data.get("protocol") or "").lower()
            if kind in _REAL_OUTBOUND_KINDS:
                configs.append({"outbounds": [data]})
    elif isinstance(data, list):
        wrapped = [item for item in data
                   if isinstance(item, dict) and isinstance(item.get("outbounds"), list)]
        if wrapped:
            configs.extend(wrapped)
        else:
            bare = [item for item in data if isinstance(item, dict)]
            if bare:
                configs.append({"outbounds": bare})
    return configs


def parse_singbox_json(json_text: str) -> list[str]:
    """
    JSON -> список URI-ссылок. Понимает форматы:

      * sing-box: {"outbounds": [{"type": "vless", ...}]} — имя из «tag»;
      * экспорт Happ/Xray: [ {"remarks": "🇬🇧 Paper VPN | Великобритания",
        "outbounds": [{"tag": "proxy", ...}]}, ... ] — имя из «remarks»
        КОРНЕВОГО объекта (в tag обычно скучный «proxy»);
      * «голый» массив outbound-ов и одиночный outbound-объект;
      * JSON внутри Base64 — decode_subscription разворачивает заранее.

    «remarks» ставится в имя, только когда серверных outbound-ов в конфиге
    РОВНО ОДИН: иначе всем серверам досталось бы ОДНО И ТО ЖЕ имя — это и
    была причина «дублирующихся» названий. При нескольких серверных
    outbound-ах берутся их собственные имена/теги (а если все теги —
    заглушки вида «proxy», имена берутся из remarks с номером).
    """
    try:
        data = json.loads(json_text)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        log.info("[JSON] Тело не является корректным JSON (%s) — пропущено",
                 type(exc).__name__)
        return []

    links: list[str] = []
    for config in _collect_configs(data):
        outbounds = config.get("outbounds")
        if not isinstance(outbounds, list):
            continue
        real = [ob for ob in outbounds
                if isinstance(ob, dict)
                and str(ob.get("protocol") or ob.get("type") or "").lower()
                in _REAL_OUTBOUND_KINDS]
        remark = str(config.get("remarks") or config.get("remark") or "").strip()
        # Все теги — заглушки «proxy(-N)»? Тогда при нескольких серверах имя
        # берём из remarks с номером вместо одинаковых «proxy-1», «proxy-2»...
        generic_tags = bool(real) and all(
            _GENERIC_PROXY_TAGS.match(str(ob.get("tag") or "").strip())
            for ob in real)
        for idx, ob in enumerate(real):
            name = ""
            if remark and len(real) == 1:
                name = remark                   # 1 сервер — имя из remarks
            elif remark and generic_tags:
                name = f"{remark} {idx + 1}"    # несколько «proxy» — нумеруем
            link = _build_any_outbound(ob, remark_override=name)
            if link:
                links.append(link)

    if not links:
        # Страховка для редких JSON, где ноды лежат «в глубине» структуры:
        # рекурсивно ищем объекты, похожие на VPN-ноды.
        for ob in _find_proxy_objects(data):
            link = _build_any_outbound(ob)
            if link:
                links.append(link)

    log.info("[JSON] Сконвертировано в URI: %d ссылок", len(links))
    return links


def _find_proxy_objects(data) -> list[dict]:
    """
    Рекурсивно обходит JSON и находит объекты, похожие на VPN-ноды
    (есть «type» + ключ хоста + ключ порта). Используется как ПОСЛЕДНИЙ
    шанс, когда обычный разбор не нашёл ни одной ссылки.
    """
    found: list[dict] = []
    if isinstance(data, dict):
        has_type = "type" in data
        has_host = any(k in data for k in ("server", "address", "add", "host"))
        has_port = any(k in data for k in ("port", "server_port"))
        if has_type and has_host and has_port:
            found.append(data)
        else:
            for value in data.values():
                found.extend(_find_proxy_objects(value))
    elif isinstance(data, list):
        for item in data:
            found.extend(_find_proxy_objects(item))
    return found


# Страховка: если построчный разбор ничего не нашёл (HTML-страница, текст,
# где ссылки идут «в потоке»), добираем ссылки регуляркой по всему телу.
# (?<![\w.+/:\-]) — не совпадать внутри слов/URL («pass://», «https://x/ss://»).
_LINK_RE = re.compile(
    r"(?<![\w.+/:\-])(?:vless|vmess|trojan|ss|ssr|hysteria2|hysteria|hy2|tuic"
    r"|juicity|anytls|socks5|socks4)://[^\s\"'<>\\]{8,}",
    re.IGNORECASE,
)


def extract_links(text: str) -> list[str]:
    """Построчно извлекает ссылки на поддерживаемые протоколы (с диагностикой)."""
    links: list[str] = []
    lines = text.splitlines()
    log.info("[EXTRACT] Всего строк в тексте: %d", len(lines))
    for i, line in enumerate(lines[:5]):
        log.info("[EXTRACT] Строка %d (первые 100 симв): %r", i, line[:100])

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if line.lower().startswith(SUPPORTED_PREFIXES):
            links.append(line)

    if not links:
        # Построчно ничего: ищем ссылки внутри текста (HTML, «в потоке»)
        for match in _LINK_RE.finditer(text):
            candidate = match.group(0).rstrip(".,;:!?)]}»\"'`")
            if candidate.lower().startswith(SUPPORTED_PREFIXES):
                links.append(candidate)
        if links:
            log.info("[EXTRACT] Регулярка добрала %d ссылок из текста", len(links))

    log.info("[EXTRACT] Итог: %d ссылок", len(links))
    return links


# =============================================================================
# 4. Дедупликация: ключ — ПОЛНАЯ ссылка, вместе с названием сервера
# =============================================================================
def dedup_key(link: str) -> str:
    """
    Ключ сравнения — ВСЯ ссылка целиком, включая название после «#»
    («вариант А»).

    Раньше название отрезалось, и дубликатами считались серверы с одинаковым
    IP/портом/ID — даже если у них разные sni/flow/fingerprint или просто
    разные имена. Из 361 сервера в подписке оставалось ~105. Теперь
    дубликатами считаются только АБСОЛЮТНО идентичные строки: одинаковый
    сервер под разными именами сохраняется (так задумано источником),
    полностью совпадающие строки убираются.

    Исключение — vmess://: сравнивается канонический payload-JSON СО ВСЕМИ
    полями (включая название «ps»), чтобы не зависеть от варианта base64
    (стандартный/url-safe, с паддингом или без).
    """
    link = (link or "").strip()
    if link.lower().startswith("vmess://"):
        payload = link[len("vmess://"):].split("#", 1)[0].strip()
        try:
            padded = payload.replace("-", "+").replace("_", "/")
            padded += "=" * ((4 - len(padded) % 4) % 4)
            data = json.loads(base64.b64decode(padded).decode("utf-8"))
            if isinstance(data, dict):
                return "vmess://" + json.dumps(data, sort_keys=True,
                                               ensure_ascii=False,
                                               separators=(",", ":"))
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            pass  # нераспарсиваемый vmess — сравниваем как обычную строку
    return link


def deduplicate(links: Iterable[str]) -> list[str]:
    """Убирает полностью идентичные ссылки, первое вхождение сохраняется."""
    seen: set[str] = set()
    unique: list[str] = []
    for link in links:
        key = dedup_key(link)
        if key and key not in seen:
            seen.add(key)
            unique.append(link)
    return unique


# =============================================================================
# 4.1 Ключи-заглушки («Включите отправку HWID…» и подобные)
# =============================================================================
STUB_HOSTS = {"0.0.0.0", "::", "::1", "127.0.0.1", "localhost"}
STUB_UUID = "00000000-0000-0000-0000-000000000000"


def parse_link_meta(uri: str) -> dict:
    """
    Рыхлый разбор URI ключа: протокол, хост, порт, название, «логин».

    Нужен только для фильтра заглушек и диагностики, поэтому ошибки парсинга
    не фатальны — возвращается то, что удалось извлечь.
    """
    meta = {"protocol": "", "host": "", "port": None, "remark": "", "user": ""}
    try:
        scheme, sep, rest = uri.partition("://")
        if not sep:
            return meta
        meta["protocol"] = scheme.lower()
        if "#" in rest:
            rest, fragment = rest.split("#", 1)
            meta["remark"] = urllib.parse.unquote(fragment).strip()
        if meta["protocol"] == "vmess":
            # название и адрес лежат внутри base64-JSON
            padded = rest.strip().replace("-", "+").replace("_", "/")
            padded += "=" * ((4 - len(padded) % 4) % 4)
            data = json.loads(base64.b64decode(padded).decode("utf-8", "replace"))
            if isinstance(data, dict):
                meta["host"] = str(data.get("add") or "")
                try:
                    meta["port"] = int(str(data.get("port")))
                except (TypeError, ValueError):
                    pass
                meta["user"] = str(data.get("id") or "")
                meta["remark"] = str(data.get("ps") or "") or meta["remark"]
            return meta
        rest = rest.split("?", 1)[0].rstrip("/")
        if "@" in rest:
            creds, _, hostport = rest.rpartition("@")
            meta["user"] = creds
        else:
            hostport = rest
        m = re.match(r"^\[(.+)\]:(\d+)$", hostport)
        if m:                                # [ipv6]:порт
            meta["host"], meta["port"] = m.group(1), int(m.group(2))
            return meta
        host, _, port = hostport.rpartition(":")
        meta["host"] = host or hostport
        if port.isdigit():
            meta["port"] = int(port)
    except Exception:
        pass
    return meta


def is_stub_link(uri: str) -> bool:
    """
    True для сервисных «ключей-заглушек», которые нельзя отдавать клиенту.

    Признаки: хост 0.0.0.0/127.0.0.1/localhost/::, нулевой UUID
    (vless/tuic/vmess) или название вида «Включите отправку HWID…».
    """
    meta = parse_link_meta(uri)
    host = (meta["host"] or "").lower().strip("[]").rstrip(".")
    if host in STUB_HOSTS:
        return True
    if meta["user"] and meta["user"].strip().lower() == STUB_UUID:
        return True
    remark_l = meta["remark"].lower()
    return ("hwid" in remark_l
            and ("включ" in remark_l or "enable" in remark_l
                 or "отправк" in remark_l))


def filter_stubs_from(links: Iterable[str]) -> tuple[list[str], int]:
    """(оставшиеся ссылки, число удалённых заглушек)."""
    kept, removed = [], 0
    for link in links:
        if is_stub_link(link):
            removed += 1
        else:
            kept.append(link)
    return kept, removed


# =============================================================================
# 5. subscription-userinfo
# =============================================================================
_USERINFO_KEYS = ("upload", "download", "total", "expire")


def parse_userinfo(header_value: str) -> dict:
    """'upload=1; download=2; total=3; expire=4' -> dict (только числовые поля)."""
    result: dict = {}
    for part in (header_value or "").split(";"):
        key, _, value = part.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key in _USERINFO_KEYS and value.isdigit():
            result[key] = int(value)
    return result


def merge_userinfo(userinfos: Iterable[dict]) -> dict:
    """Несколько источников: трафик суммируется, expire — минимальный ненулевой."""
    merged: dict = {}
    for info in userinfos:
        for key in ("upload", "download", "total"):
            merged[key] = merged.get(key, 0) + info.get(key, 0)
        expire = info.get("expire", 0)
        if expire:
            merged["expire"] = (min(merged["expire"], expire)
                                if merged.get("expire") else expire)
    return merged


def format_userinfo(info: dict) -> str | None:
    """Строка для заголовка subscription-userinfo или None, если данных нет."""
    if not info or not any(info.get(k) for k in _USERINFO_KEYS):
        return None
    return "; ".join(f"{k}={info[k]}" for k in _USERINFO_KEYS if info.get(k))


# =============================================================================
# 6. Загрузка одного источника и финальная агрегация
# =============================================================================
def fetch_one_source(source_id: int, url: str, timeout=DEFAULT_TIMEOUT,
                     max_bytes: int = DEFAULT_MAX_BYTES,
                     extra_headers: dict | None = None,
                     filter_stubs: bool = True) -> SourceResult:
    """
    Скачивает и парсит один источник с подробной диагностикой в лог;
    сетевые ошибки не прерывают агрегацию.

    extra_headers — разрешённые заголовки клиента (x-hwid и т.п.); запрос
    в любом случае маскируется под Happ (см. safe_fetch).
    filter_stubs — отсеивать ключи-заглушки из ответа источника.
    """
    try:
        raw, headers = safe_fetch(url, timeout=timeout, max_bytes=max_bytes,
                                  extra_headers=extra_headers)
        text = raw.decode("utf-8", errors="replace")
        log.info("[FETCH #%s] %s: получено %d байт, Content-Type=%s",
                 source_id, url, len(raw), headers.get("Content-Type", "N/A"))
        log.info("[FETCH #%s] Первые 150 символов тела: %r", source_id, text[:150])

        body = decode_subscription(text)
        links = extract_links(body)
        log.info("[FETCH #%s] Извлечено ссылок: %d", source_id, len(links))

        stubs_removed = 0
        if filter_stubs:
            links, stubs_removed = filter_stubs_from(links)
            if stubs_removed:
                log.info("[FETCH #%s] Удалено заглушек: %d", source_id, stubs_removed)

        # Дедуп внутри источника — по полной ссылке с именем (см. dedup_key)
        unique = deduplicate(links)
        log.info("[FETCH #%s] Уникальных ключей: %d", source_id, len(unique))

        ui_header = headers.get("subscription-userinfo")
        userinfo = parse_userinfo(ui_header) if ui_header else {}
        return SourceResult(
            source_id=source_id, ok=True,
            count=len(unique),
            links=links,
            userinfo=userinfo,
            stubs_removed=stubs_removed,
        )
    except FetchError as exc:
        log.error("[FETCH #%s] Ошибка: %s", source_id, exc)
        return SourceResult(source_id=source_id, ok=False, error=str(exc))
    except requests.RequestException as exc:
        log.error("[FETCH #%s] Сеть: %s", source_id, exc)
        return SourceResult(source_id=source_id, ok=False,
                            error=f"Сетевая ошибка: {exc.__class__.__name__}: {exc}")
    except Exception as exc:  # непредвиденное — не роняем обработку остальных
        log.exception("Неожиданная ошибка при загрузке источника #%s", source_id)
        return SourceResult(source_id=source_id, ok=False,
                            error=f"Внутренняя ошибка: {exc}")


def aggregate_sources(sources: Iterable, timeout=DEFAULT_TIMEOUT,
                      max_bytes: int = DEFAULT_MAX_BYTES,
                      workers: int = FETCH_WORKERS,
                      client_headers: dict | None = None):
    """
    Главная функция on-demand агрегации.

    Вход: активные источники (объекты с полями id и url; опционально —
    флаги forward_headers и filter_stubs).
    Выход: (base64-подписка, {source_id: SourceResult}, subscription-userinfo|None).

    client_headers — разрешённые заголовки клиента (x-hwid, User-Agent, ...):
    источник получает их, только если у него включён флаг forward_headers
    (по умолчанию включён). Даже с выключенным флагом (или без заголовков
    клиента — например, при проверке из панели) запрос к источнику маскируется
    под Happ с константным x-hwid: иначе анти-DDoS источников отвечает 403.
    Флаг filter_stubs источника (по умолчанию
    включён) управляет удалением заглушек из его ответа.

    Источники скачиваются ПАРАЛЛЕЛЬНО через ThreadPoolExecutor — это обычные
    потоки внутри запроса, а не фоновые задачи, поэтому PythonAnywhere их
    разрешает. Дедупликация глобальная — по ПОЛНОЙ ссылке, включая название
    (полностью идентичные строки убираются; одинаковый сервер под разными
    именами сохраняется, чтобы не терять ни один ключ источника).
    """
    sources = list(sources)
    results: dict[int, SourceResult] = {}
    if sources:
        workers = max(1, min(workers, len(sources)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="fetch") as pool:
            futures = {}
            for s in sources:
                headers = client_headers if getattr(s, "forward_headers", True) else None
                futures[pool.submit(
                    fetch_one_source, s.id, s.url, timeout, max_bytes,
                    headers, getattr(s, "filter_stubs", True))] = s.id
            for future in futures:  # все ошибки уже перехвачены внутри задач
                results[futures[future]] = future.result()

    all_links: list[str] = []
    userinfos: list[dict] = []
    for source in sources:                  # порядок источников сохраняем
        res = results[source.id]
        if res.ok:
            all_links.extend(res.links)
            if res.userinfo:
                userinfos.append(res.userinfo)

    unique_links = deduplicate(all_links)
    payload = "\n".join(unique_links)
    # Стандартный Base64 без паддинга «=» в конце — так отдают большинство
    # VPN-панелей; Happ/v2rayN/sing-box такое читают (проверено живым
    # запросом через ngrok).
    b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    userinfo_header = format_userinfo(merge_userinfo(userinfos)) if userinfos else None
    return b64, results, userinfo_header
