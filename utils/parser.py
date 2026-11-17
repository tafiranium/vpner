"""
Загрузка и парсинг VPN-подписок (ядро агрегатора, без зависимости от Flask/БД).
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import time
import hashlib
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Iterable

import requests

log = logging.getLogger(__name__)

# --- Значения по умолчанию --------------------------------------------------
DEFAULT_TIMEOUT = (5, 10)
# Увеличили лимит до 100 МБ, чтобы точно не резать большие конфиги
DEFAULT_MAX_BYTES = 100 * 1024 * 1024
MAX_REDIRECTS = 5
FETCH_WORKERS = 8

# --- Обход анти-бот защиты источников ----------------------------------------
HAPP_HWID = "kjlol2w78avsdcxd"

try:
    import brotli
    _HAS_BROTLI = True
except ImportError:
    try:
        import brotlicffi
        _HAS_BROTLI = True
    except ImportError:
        _HAS_BROTLI = False

ACCEPT_ENCODING = "gzip, deflate, br" if _HAS_BROTLI else "gzip, deflate"

HAPP_HEADERS = {
    "user-agent": "Happ/4.13.0/macos catalyst/2606241216657",
    "accept": "*/*",
    "accept-encoding": ACCEPT_ENCODING,
    "accept-language": "ru",
    "priority": "u=3",
    "x-device-os": "macOS",
    "x-hwid": HAPP_HWID,
    "x-app-version": "4.13.0",
    "x-device-model": "Mac",
    "x-ver-os": "26.6.2",
    "x-device-locale": "ru",
}

ANTIBOT_STATUSES = frozenset({403, 429, 503})
MAX_RETRIES = 2
RETRY_DELAYS = ((0.5, 1.0), (1.0, 2.0))
_HWID_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

# Кэш для хэшей сертификатов, чтобы не подключаться к серверам каждый раз
_CERT_HASH_CACHE = {}

def generate_hwid() -> str:
    return "".join(random.choices(_HWID_ALPHABET, k=16))

FORWARDABLE_HEADERS = (
    "x-hwid", "user-agent", "x-device-os", "x-device-locale",
    "x-app-version", "x-device-model", "x-ver-os", "accept-language",
)

SUPPORTED_PREFIXES = (
    "vless://", "vmess://", "trojan://", "ss://", "ssr://",
    "hysteria://", "hysteria2://", "hy2://", "tuic://", "juicity://",
    "socks://", "socks4://", "socks5://", "anytls://",
)

BLOCKED_HOSTNAMES = {
    "localhost", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "instance-data",
}
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan",
                    ".home", ".home.arpa", ".localdomain", ".invalid")

class FetchError(Exception):
    pass

@dataclass
class SourceResult:
    source_id: int
    ok: bool
    count: int = 0
    links: list[str] = field(default_factory=list)
    userinfo: dict = field(default_factory=dict)
    error: str = ""
    stubs_removed: int = 0

# =============================================================================
# 1. SSRF-защита
# =============================================================================
def _ip_is_forbidden(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return (addr.is_unspecified or addr.is_loopback or addr.is_link_local
            or addr.is_private or addr.is_reserved or addr.is_multicast)

def _hostname_is_forbidden(hostname: str) -> bool:
    host = (hostname or "").lower().rstrip(".")
    if not host:
        return True
    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES):
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return _ip_is_forbidden(host)

def resolve_hostname(hostname: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise FetchError(f"DNS: не удалось разрешить «{hostname}» ({exc})") from exc
    return {info[4][0] for info in infos}

def validate_url(url: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise FetchError(f"Некорректный URL: {exc}") from exc

    if parsed.scheme.lower() not in ("http", "https"):
        raise FetchError(f"Разрешены только схемы http/https (получено «{parsed.scheme or '—'}»)")
    if not parsed.hostname:
        raise FetchError("В URL нет имени хоста")
    if len(url) > 2048:
        raise FetchError("Слишком длинный URL")

    if _hostname_is_forbidden(parsed.hostname):
        raise FetchError(f"Хост «{parsed.hostname}» запрещён (localhost/приватный IP)")

    for ip in resolve_hostname(parsed.hostname):
        if _ip_is_forbidden(ip):
            raise FetchError(f"Хост «{parsed.hostname}» резолвится в запрещённый IP {ip} (SSRF)")

# =============================================================================
# 2. Безопасная загрузка
# =============================================================================
def _build_source_headers(extra_headers: dict | None) -> dict:
    headers = dict(HAPP_HEADERS)
    for name, value in (extra_headers or {}).items():
        lname = str(name).lower()
        if lname not in FORWARDABLE_HEADERS or not value:
            continue
        value = str(value)[:256]
        if lname == "user-agent" and not value.lower().startswith("happ/"):
            continue
        headers[lname] = value
    return headers

def _read_limited(resp, max_bytes: int):
    """Читает тело ответа потоково, БЕЗ ограничения размера."""
    chunks: list[bytes] = []
    try:
        for chunk in resp.iter_content(chunk_size=16384):
            chunks.append(chunk)
    finally:
        resp.close()
    return b"".join(chunks), resp.headers

def safe_fetch(url: str, timeout=DEFAULT_TIMEOUT,
               max_bytes: int = DEFAULT_MAX_BYTES,
               extra_headers: dict | None = None):
    session = requests.Session()
    session.headers.clear()
    session.headers.update(_build_source_headers(extra_headers))

    current_url = url
    redirects = 0
    retries = 0
    try:
        while True:
            validate_url(current_url)
            try:
                resp = session.get(current_url, timeout=timeout, allow_redirects=False, stream=True)
            except requests.Timeout as exc:
                if retries < MAX_RETRIES:
                    retries += 1
                    time.sleep(random.uniform(*RETRY_DELAYS[retries - 1]))
                    continue
                raise FetchError("Таймаут при загрузке источника (истекло время ожидания ответа)") from exc
            except requests.ConnectionError as exc:
                if retries < MAX_RETRIES:
                    retries += 1
                    time.sleep(random.uniform(*RETRY_DELAYS[retries - 1]))
                    continue
                raise FetchError("Ошибка соединения с источником "
                                 f"({exc.__class__.__name__})") from exc

            if 300 <= resp.status_code < 400:
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
                time.sleep(random.uniform(*RETRY_DELAYS[retries - 1]))
                session.headers["x-hwid"] = generate_hwid()
                continue
            if resp.status_code == 403:
                raise FetchError("403 Forbidden (Анти-бот защита)")
            raise FetchError(f"HTTP {resp.status_code} от источника")
    finally:
        session.close()

fetch_subscription = safe_fetch

# =============================================================================
# 3. Декодирование тела подписки и извлечение ссылок
# =============================================================================
def decode_subscription(text: str) -> str:
    stripped = (text or "").strip()
    if stripped.startswith("\ufeff"):
        stripped = stripped.lstrip("\ufeff").strip()
    if not stripped:
        return ""

    if stripped[:1] in ("{", "["):
        sb_links = parse_singbox_json(stripped)
        if sb_links:
            return "\n".join(sb_links)
        try:
            jdata = json.loads(stripped)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            jdata = None
        if isinstance(jdata, list):
            strs = [s.strip() for s in jdata
                    if isinstance(s, str) and s.strip().lower().startswith(SUPPORTED_PREFIXES)]
            if strs:
                return "\n".join(strs)
        elif isinstance(jdata, dict):
            strs = [str(v).strip() for v in jdata.values()
                    if isinstance(v, str) and str(v).strip().lower().startswith(SUPPORTED_PREFIXES)]
            if strs:
                return "\n".join(strs)

    if any(line.strip().lower().startswith(SUPPORTED_PREFIXES)
           for line in stripped.splitlines()[:5]):
        return stripped

    compact = "".join(stripped.split())
    if len(compact) % 4 == 1:
        return stripped

    normalized = compact.replace("-", "+").replace("_", "/")
    padded = normalized + "=" * ((4 - len(normalized) % 4) % 4)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", padded):
        return stripped

    try:
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return stripped

    if decoded.strip()[:1] in ("{", "["):
        sb_links = parse_singbox_json(decoded)
        if sb_links:
            return "\n".join(sb_links)

    if "://" in decoded:
        return decoded
    return stripped

# =============================================================================
# 3.1 sing-box / Happ JSON -> URI-ссылки
# =============================================================================
_SINGBOX_TRANSPORT_URI = {
    "ws": "ws", "grpc": "grpc", "http": "http",
    "httpupgrade": "httpupgrade", "quic": "quic",
}
_SINGBOX_TRANSPORT_NET = {
    "ws": "ws", "grpc": "grpc", "http": "h2",
    "httpupgrade": "httpupgrade", "quic": "quic", "": "tcp",
}

def _sb_port(outbound: dict) -> int:
    try:
        return int(outbound.get("server_port") or 0)
    except (TypeError, ValueError):
        return 0

def _sb_format_host(server: str) -> str:
    server = str(server).strip().strip("[]")
    return f"[{server}]" if ":" in server else server

def _sb_uri_join(scheme: str, authority: str, params: dict, tag: str) -> str:
    query_parts = []
    for k, v in params.items():
        if v in ("", None):
            continue
        safe_chars = '/' if k == 'alpn' else ''
        query_parts.append(f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(v), safe=safe_chars)}")

    query = "&".join(query_parts)
    link = f"{scheme}://{authority}"
    if query:
        link += "?" + query
    if tag:
        link += "#" + urllib.parse.quote(str(tag), safe="")
    return link

def _get_cert_sha256(host: str, port: int, sni: str) -> str:
    """Динамически подключается к серверу и получает хэш сертификата."""
    key = f"{host}:{port}:{sni}"
    if key in _CERT_HASH_CACHE:
        return _CERT_HASH_CACHE[key]

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    res = hashlib.sha256(der_cert).hexdigest().upper()
                    _CERT_HASH_CACHE[key] = res
                    return res
    except Exception:
        pass
    _CERT_HASH_CACHE[key] = ""
    return ""

def _sb_tls_params(outbound: dict, host: str = "", port: int = 0) -> dict:
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
        return params
    if tls.get("server_name"):
        params["sni"] = str(tls["server_name"])
    utls = tls.get("utls") if isinstance(tls.get("utls"), dict) else {}
    if utls.get("enabled") and utls.get("fingerprint"):
        params["fp"] = str(utls["fingerprint"])
    alpn = tls.get("alpn")
    if isinstance(alpn, list) and alpn:
        params["alpn"] = ",".join(str(a) for a in alpn)

    pinned = tls.get("pinned_peer_cert_sha256")
    if pinned:
        params["pinnedPeerCertSha256"] = str(pinned)
    elif tls.get("insecure"):
        dynamic_hash = _get_cert_sha256(host, port, params.get("sni", host))
        if dynamic_hash:
            params["pinnedPeerCertSha256"] = dynamic_hash
        else:
            return {"security": "invalid"}
    return params

def _sb_transport_params(outbound: dict) -> dict:
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
        host = headers.get("Host") or headers.get("host")
        if host:
            params["host"] = str(host)
        try:
            early = int(tr.get("max_early_data") or 0)
        except (TypeError, ValueError):
            early = 0
        if early > 0:
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
    uuid = str(outbound.get("uuid") or "")
    server = str(outbound.get("server") or "")
    port = _sb_port(outbound)
    if not uuid or not server or port <= 0:
        return ""
    params = {"encryption": "none"}
    tls_params = _sb_tls_params(outbound, server, port)
    if tls_params.get("security") == "invalid":
        return ""
    params.update(tls_params)
    params.update(_sb_transport_params(outbound))
    if outbound.get("flow"):
        params["flow"] = str(outbound["flow"])
    authority = f"{uuid}@{_sb_format_host(server)}:{port}"
    return _sb_uri_join("vless", authority, params, outbound.get("tag") or "")

def _sb_vmess(outbound: dict) -> str:
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
    host, path = "", ""
    if ttype == "ws":
        headers = tr.get("headers") if isinstance(tr.get("headers"), dict) else {}
        host = str(headers.get("Host") or headers.get("host") or "")
        path = str(tr.get("path") or "")
    elif ttype == "grpc":
        path = str(tr.get("service_name") or "")
    elif ttype in ("http", "httpupgrade"):
        h = tr.get("host")
        host = ",".join(str(x) for x in h) if isinstance(h, list) else str(h or "")
        path = str(tr.get("path") or "")
    payload = {
        "v": "2", "ps": str(outbound.get("tag") or ""), "add": server, "port": str(port),
        "id": uuid, "aid": str(outbound.get("alter_id") or 0),
        "scy": str(outbound.get("security") or "auto"),
        "net": _SINGBOX_TRANSPORT_NET.get(ttype, "tcp"), "type": "",
        "host": host, "path": path, "tls": "tls" if tls.get("enabled") else "",
        "sni": str(tls.get("server_name") or ""),
        "alpn": ",".join(str(a) for a in alpn) if isinstance(alpn, list) else "",
        "fp": str(utls.get("fingerprint") or "") if utls.get("enabled") else "",
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(raw.encode("utf-8")).decode("ascii")

def _sb_trojan(outbound: dict) -> str:
    password = str(outbound.get("password") or "")
    server = str(outbound.get("server") or "")
    port = _sb_port(outbound)
    if not password or not server or port <= 0:
        return ""
    params: dict = {}
    tls_params = _sb_tls_params(outbound, server, port)
    if tls_params.get("security") == "invalid":
        return ""
    params.update(tls_params if tls_params else {"security": "tls"})
    params.update(_sb_transport_params(outbound))
    authority = f"{urllib.parse.quote(password, safe='')}@{_sb_format_host(server)}:{port}"
    return _sb_uri_join("trojan", authority, params, outbound.get("tag") or "")

def _sb_shadowsocks(outbound: dict) -> str:
    method = str(outbound.get("method") or "")
    password = str(outbound.get("password") or "")
    server = str(outbound.get("server") or "")
    port = _sb_port(outbound)
    if not method or not password or not server or port <= 0:
        return ""
    userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
    link = f"ss://{userinfo}@{_sb_format_host(server)}:{port}"
    plugin = str(outbound.get("plugin") or "")
    if plugin:
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

_XRAY_PROTOCOLS = frozenset({"vless", "vmess", "trojan", "shadowsocks"})
_REAL_OUTBOUND_KINDS = _XRAY_PROTOCOLS | set(_SINGBOX_BUILDERS)
_GENERIC_PROXY_TAGS = re.compile(r"^(proxy|proxy[-_ ]?\d+)$", re.IGNORECASE)

def _xray_tls_params(stream: dict, host: str = "", port: int = 0) -> dict:
    security = str(stream.get("security") or "none").lower()

    if security == "reality":
        rs = stream.get("realitySettings")
        rs = rs if isinstance(rs, dict) else {}
        params: dict = {"security": "reality"}
        sni = rs.get("serverName")
        if not sni and isinstance(rs.get("serverNames"), list) and rs["serverNames"]:
            sni = rs["serverNames"][0]
        if sni: params["sni"] = str(sni)
        sid = rs.get("shortId")
        if not sid and isinstance(rs.get("shortIds"), list) and rs["shortIds"]:
            sid = rs["shortIds"][0]
        if sid: params["sid"] = str(sid)
        if rs.get("fingerprint"): params["fp"] = str(rs["fingerprint"])
        pbk = rs.get("publicKey")
        if pbk: params["pbk"] = str(pbk)
        if rs.get("spiderX"): params["spx"] = str(rs["spiderX"])
        return params

    if security == "tls":
        ts = stream.get("tlsSettings")
        ts = ts if isinstance(ts, dict) else {}
        params = {"security": "tls"}
        sni = ts.get("serverName")
        if not sni and isinstance(ts.get("serverNames"), list) and ts["serverNames"]:
            sni = ts["serverNames"][0]
        if sni: params["sni"] = str(sni)
        if ts.get("fingerprint"): params["fp"] = str(ts["fingerprint"])
        alpn = ts.get("alpn")
        if isinstance(alpn, list) and alpn:
            params["alpn"] = ",".join(str(a) for a in alpn)
        elif isinstance(alpn, str) and alpn:
            params["alpn"] = alpn

        pinned = ts.get("pinnedPeerCertSha256")
        if pinned:
            params["pinnedPeerCertSha256"] = str(pinned)
        else:
            needs_insecure = (
                ts.get("allowInsecure") or
                ts.get("insecure") or
                ts.get("verifyPeerCertByName") or
                (sni and (".internal" in str(sni).lower() or ".local" in str(sni).lower()))
            )
            if needs_insecure:
                dynamic_hash = _get_cert_sha256(host, port, sni or host)
                if dynamic_hash:
                    params["pinnedPeerCertSha256"] = dynamic_hash
                else:
                    return {"security": "invalid"}

        return params

    return {"security": "none"}

def _xray_transport_params(stream: dict) -> dict:
    network = str(stream.get("network") or "tcp").lower()
    params: dict = {}
    if network not in ("", "tcp", "raw"):
        params["type"] = "http" if network in ("http", "h2") else network

    if network in ("tcp", "raw"):
        tcp = stream.get("tcpSettings") if isinstance(stream.get("tcpSettings"), dict) else {}
        header = tcp.get("header") if isinstance(tcp.get("header"), dict) else {}
        htype = str(header.get("type") or "")
        if htype and htype != "none":
            params["headerType"] = htype
            request = header.get("request") if isinstance(header.get("request"), dict) else {}
            raw_path = request.get("path")
            if isinstance(raw_path, list) and raw_path:
                params["path"] = str(raw_path[0])
            elif raw_path:
                params["path"] = str(raw_path)
            req_headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
            raw_host = req_headers.get("Host") or req_headers.get("host")
            if raw_host:
                params["host"] = (",".join(str(x) for x in raw_host)
                                  if isinstance(raw_host, list) else str(raw_host))
    elif network == "ws":
        ws = stream.get("wsSettings") if isinstance(stream.get("wsSettings"), dict) else {}
        if ws.get("path"): params["path"] = str(ws["path"])
        headers = ws.get("headers") if isinstance(ws.get("headers"), dict) else {}
        host = headers.get("Host") or headers.get("host") or ws.get("host")
        if host: params["host"] = str(host)
    elif network == "grpc":
        g = stream.get("grpcSettings") if isinstance(stream.get("grpcSettings"), dict) else {}
        if g.get("serviceName"): params["serviceName"] = str(g["serviceName"])
        if g.get("multiMode"): params["mode"] = "multi"
    elif network in ("http", "h2"):
        h = stream.get("httpSettings") if isinstance(stream.get("httpSettings"), dict) else {}
        host = h.get("host")
        if isinstance(host, list): host = ",".join(str(x) for x in host if x)
        if host: params["host"] = str(host)
        if h.get("path"): params["path"] = str(h["path"])
    elif network == "httpupgrade":
        hu = stream.get("httpupgradeSettings") if isinstance(stream.get("httpupgradeSettings"), dict) else {}
        if hu.get("host"): params["host"] = str(hu["host"])
        if hu.get("path"): params["path"] = str(hu["path"])
    elif network == "kcp":
        k = stream.get("kcpSettings") if isinstance(stream.get("kcpSettings"), dict) else {}
        header = k.get("header") if isinstance(k.get("header"), dict) else {}
        htype = str(header.get("type") or "")
        if htype and htype != "none": params["headerType"] = htype
        if k.get("seed"): params["seed"] = str(k["seed"])
    elif network == "quic":
        q = stream.get("quicSettings") if isinstance(stream.get("quicSettings"), dict) else {}
        if q.get("security"): params["quicSecurity"] = str(q["security"])
        if q.get("key"): params["key"] = str(q["key"])
        header = q.get("header") if isinstance(q.get("header"), dict) else {}
        htype = str(header.get("type") or "")
        if htype and htype != "none": params["headerType"] = htype
    return params

def _xray_vmess_link(user: dict, address: str, port: int, stream: dict, name: str) -> str:
    uuid = str(user.get("id") or "").strip()
    if not uuid: return ""
    network = str(stream.get("network") or "tcp").lower()
    security = str(stream.get("security") or "none").lower()

    ts = stream.get("tlsSettings") if isinstance(stream.get("tlsSettings"), dict) else {}
    rs = stream.get("realitySettings") if isinstance(stream.get("realitySettings"), dict) else {}

    host, path, header_type = "", "", ""
    if network == "ws":
        ws = stream.get("wsSettings") if isinstance(stream.get("wsSettings"), dict) else {}
        headers = ws.get("headers") if isinstance(ws.get("headers"), dict) else {}
        host = str(headers.get("Host") or headers.get("host") or ws.get("host") or "")
        path = str(ws.get("path") or "")
    elif network == "grpc":
        g = stream.get("grpcSettings") if isinstance(stream.get("grpcSettings"), dict) else {}
        path = str(g.get("serviceName") or "")
    elif network in ("http", "h2"):
        h = stream.get("httpSettings") if isinstance(stream.get("httpSettings"), dict) else {}
        raw_host = h.get("host")
        host = (",".join(str(x) for x in raw_host) if isinstance(raw_host, list) else str(raw_host or ""))
        path = str(h.get("path") or "")
    elif network == "httpupgrade":
        hu = stream.get("httpupgradeSettings") if isinstance(stream.get("httpupgradeSettings"), dict) else {}
        host = str(hu.get("host") or "")
        path = str(hu.get("path") or "")
    elif network in ("tcp", "raw"):
        tcp = stream.get("tcpSettings") if isinstance(stream.get("tcpSettings"), dict) else {}
        header = tcp.get("header") if isinstance(tcp.get("header"), dict) else {}
        header_type = str(header.get("type") or "")
        if header_type and header_type != "none":
            request = header.get("request") if isinstance(header.get("request"), dict) else {}
            raw_path = request.get("path")
            path = (str(raw_path[0]) if isinstance(raw_path, list) and raw_path else str(raw_path or ""))
            req_headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
            raw_host = req_headers.get("Host") or req_headers.get("host")
            host = (",".join(str(x) for x in raw_host) if isinstance(raw_host, list) else str(raw_host or ""))
        else:
            header_type = ""

    sni = ts.get("serverName")
    if not sni and isinstance(ts.get("serverNames"), list) and ts["serverNames"]: sni = ts["serverNames"][0]
    if not sni: sni = rs.get("serverName")
    if not sni and isinstance(rs.get("serverNames"), list) and rs["serverNames"]: sni = rs["serverNames"][0]

    alpn = ts.get("alpn")
    alpn_str = ",".join(str(a) for a in alpn) if isinstance(alpn, list) else str(alpn or "")

    payload = {
        "v": "2", "ps": name, "add": address, "port": str(port), "id": uuid,
        "aid": str(user.get("alterId") or 0), "scy": str(user.get("security") or "auto"),
        "net": "tcp" if network in ("", "raw", "tcp") else network,
        "type": header_type, "host": host, "path": path,
        "tls": "tls" if security in ("tls", "reality") else "",
        "sni": str(sni or ""), "alpn": alpn_str,
        "fp": str(ts.get("fingerprint") or rs.get("fingerprint") or ""),
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(raw.encode("utf-8")).decode("ascii")

def _parse_xray_outbound(ob: dict, remark_override: str = "") -> str:
    proto = str(ob.get("protocol") or "").lower()
    if proto not in ("vless", "vmess", "trojan", "shadowsocks"):
        return ""

    name = str(remark_override or "").strip()
    if not name:
        name = str(ob.get("remarks") or ob.get("remark") or ob.get("name") or ob.get("tag") or "").strip()

    settings = ob.get("settings") if isinstance(ob.get("settings"), dict) else {}
    stream = ob.get("streamSettings") if isinstance(ob.get("streamSettings"), dict) else {}

    if proto in ("vless", "vmess"):
        vnext = settings.get("vnext")
        if not isinstance(vnext, list) or not vnext or not isinstance(vnext[0], dict): return ""
        node = vnext[0]
        address = str(node.get("address") or "").strip()
        try:
            port = int(node.get("port") or 0)
        except (TypeError, ValueError):
            return ""
        users = node.get("users")
        if not address or port <= 0 or not isinstance(users, list) or not users or not isinstance(users[0], dict): return ""
        user = users[0]

        if proto == "vmess":
            return _xray_vmess_link(user, address, port, stream, name)

        uuid = str(user.get("id") or "").strip()
        if not uuid: return ""
        params: dict = {}
        enc = str(user.get("encryption") or "none")
        params["encryption"] = "none" if "mlkem" in enc.lower() else enc

        tls_params = _xray_tls_params(stream, address, port)
        if tls_params.get("security") == "invalid":
            return ""

        params.update(tls_params)
        params.update(_xray_transport_params(stream))

        flow = str(user.get("flow") or "").strip()
        if flow: params["flow"] = flow
        authority = f"{uuid}@{_sb_format_host(address)}:{port}"
        return _sb_uri_join("vless", authority, params, name)

    servers = settings.get("servers")
    if not isinstance(servers, list) or not servers or not isinstance(servers[0], dict): return ""
    node = servers[0]
    address = str(node.get("address") or "").strip()
    try:
        port = int(node.get("port") or 0)
    except (TypeError, ValueError):
        return ""
    if not address or port <= 0: return ""

    if proto == "trojan":
        password = str(node.get("password") or "")
        if not password: return ""
        params = _xray_tls_params(stream, address, port)
        if params.get("security") == "invalid":
            return ""
        if not params: params = {"security": "tls"}
        params.update(_xray_transport_params(stream))
        authority = (f"{urllib.parse.quote(password, safe='')}@{_sb_format_host(address)}:{port}")
        return _sb_uri_join("trojan", authority, params, name)

    method = str(node.get("method") or "")
    password = str(node.get("password") or "")
    if not method or not password: return ""
    userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
    link = f"ss://{userinfo}@{_sb_format_host(address)}:{port}"
    if name: link += "#" + urllib.parse.quote(name, safe="")
    return link

def _apply_link_name(link: str, name: str) -> str:
    name = str(name or "").strip()
    if not name or not link: return link
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
            pass
    base = link.split("#", 1)[0]
    return f"{base}#{urllib.parse.quote(name, safe='')}"

def _build_any_outbound(ob: dict, remark_override: str = "") -> str:
    proto = str(ob.get("protocol") or "").lower()
    if proto in _XRAY_PROTOCOLS:
        return _parse_xray_outbound(ob, remark_override)
    builder = _SINGBOX_BUILDERS.get(str(ob.get("type") or "").lower())
    if builder is None: return ""
    try:
        link = builder(ob)
    except Exception as exc:
        log.debug("JSON: outbound %r пропущен (%s: %s)", ob.get("tag"), type(exc).__name__, exc)
        return ""
    if link and remark_override:
        link = _apply_link_name(link, remark_override)
    return link

def _collect_configs(data) -> list[dict]:
    configs: list[dict] = []
    if isinstance(data, dict):
        if isinstance(data.get("outbounds"), list):
            configs.append(data)
        else:
            kind = str(data.get("type") or data.get("protocol") or "").lower()
            if kind in _REAL_OUTBOUND_KINDS:
                configs.append({"outbounds": [data]})
    elif isinstance(data, list):
        wrapped = [item for item in data if isinstance(item, dict) and isinstance(item.get("outbounds"), list)]
        if wrapped:
            configs.extend(wrapped)
        else:
            bare = [item for item in data if isinstance(item, dict)]
            if bare: configs.append({"outbounds": bare})
    return configs

def parse_singbox_json(json_text: str) -> list[str]:
    try:
        data = json.loads(json_text)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        return []

    links: list[str] = []
    for config in _collect_configs(data):
        outbounds = config.get("outbounds")
        if not isinstance(outbounds, list): continue
        real = [ob for ob in outbounds if isinstance(ob, dict) and str(ob.get("protocol") or ob.get("type") or "").lower() in _REAL_OUTBOUND_KINDS]
        remark = str(config.get("remarks") or config.get("remark") or "").strip()
        generic_tags = bool(real) and all(_GENERIC_PROXY_TAGS.match(str(ob.get("tag") or "").strip()) for ob in real)
        for idx, ob in enumerate(real):
            name = ""
            if remark and len(real) == 1:
                name = remark
            elif remark and generic_tags:
                name = f"{remark} {idx + 1}"
            link = _build_any_outbound(ob, remark_override=name)
            if link:
                links.append(link)

    if not links:
        for ob in _find_proxy_objects(data):
            link = _build_any_outbound(ob)
            if link:
                links.append(link)

    return links

def _find_proxy_objects(data) -> list[dict]:
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

_LINK_RE = re.compile(
    r"(?<![\w.+/:\-])(?:vless|vmess|trojan|ss|ssr|hysteria2|hysteria|hy2|tuic"
    r"|juicity|anytls|socks5|socks4)://[^\s\"'<>\\]{8,}",
    re.IGNORECASE,
)

def extract_links(text: str) -> list[str]:
    links: list[str] = []
    lines = text.splitlines()

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if line.lower().startswith(SUPPORTED_PREFIXES):
            links.append(line)

    if not links:
        for match in _LINK_RE.finditer(text):
            candidate = match.group(0).rstrip(".,;:!?)]}»\"'`")
            if candidate.lower().startswith(SUPPORTED_PREFIXES):
                links.append(candidate)
        if links:
            log.info("[EXTRACT] Регулярка добрала %d ссылок из текста", len(links))

    return links

def dedup_key(link: str) -> str:
    link = (link or "").strip()
    if link.lower().startswith("vmess://"):
        payload = link[len("vmess://"):].split("#", 1)[0].strip()
        try:
            padded = payload.replace("-", "+").replace("_", "/")
            padded += "=" * ((4 - len(padded) % 4) % 4)
            data = json.loads(base64.b64decode(padded).decode("utf-8"))
            if isinstance(data, dict):
                return "vmess://" + json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            pass
    return link

def deduplicate(links: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for link in links:
        key = dedup_key(link)
        if key and key not in seen:
            seen.add(key)
            unique.append(link)
    return unique

STUB_HOSTS = {"0.0.0.0", "::", "::1", "127.0.0.1", "localhost"}
STUB_UUID = "00000000-0000-0000-0000-000000000000"

def parse_link_meta(uri: str) -> dict:
    meta = {"protocol": "", "host": "", "port": None, "remark": "", "user": ""}
    try:
        scheme, sep, rest = uri.partition("://")
        if not sep: return meta
        meta["protocol"] = scheme.lower()
        if "#" in rest:
            rest, fragment = rest.split("#", 1)
            meta["remark"] = urllib.parse.unquote(fragment).strip()
        if meta["protocol"] == "vmess":
            padded = rest.strip().replace("-", "+").replace("_", "/")
            padded += "=" * ((4 - len(padded) % 4) % 4)
            data = json.loads(base64.b64decode(padded).decode("utf-8", "replace"))
            if isinstance(data, dict):
                meta["host"] = str(data.get("add") or "")
                try: meta["port"] = int(str(data.get("port")))
                except (TypeError, ValueError): pass
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
        if m:
            meta["host"], meta["port"] = m.group(1), int(m.group(2))
            return meta
        host, _, port = hostport.rpartition(":")
        meta["host"] = host or hostport
        if port.isdigit(): meta["port"] = int(port)
    except Exception:
        pass
    return meta

def is_stub_link(uri: str) -> bool:
    meta = parse_link_meta(uri)
    host = (meta["host"] or "").lower().strip("[]").rstrip(".")
    if host in STUB_HOSTS: return True
    if meta["user"] and meta["user"].strip().lower() == STUB_UUID: return True
    remark_l = meta["remark"].lower()
    return ("hwid" in remark_l and ("включ" in remark_l or "enable" in remark_l or "отправк" in remark_l))

def filter_stubs_from(links: Iterable[str]) -> tuple[list[str], int]:
    kept, removed = [], 0
    for link in links:
        if is_stub_link(link): removed += 1
        else: kept.append(link)
    return kept, removed

_USERINFO_KEYS = ("upload", "download", "total", "expire")

def parse_userinfo(header_value: str) -> dict:
    result: dict = {}
    for part in (header_value or "").split(";"):
        key, _, value = part.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key in _USERINFO_KEYS and value.isdigit():
            result[key] = int(value)
    return result

def merge_userinfo(userinfos: Iterable[dict]) -> dict:
    merged: dict = {}
    for info in userinfos:
        for key in ("upload", "download", "total"):
            merged[key] = merged.get(key, 0) + info.get(key, 0)
        expire = info.get("expire", 0)
        if expire:
            merged["expire"] = (min(merged["expire"], expire) if merged.get("expire") else expire)
    return merged

def format_userinfo(info: dict) -> str | None:
    if not info or not any(info.get(k) for k in _USERINFO_KEYS): return None
    return "; ".join(f"{k}={info[k]}" for k in _USERINFO_KEYS if info.get(k))

def fetch_one_source(source_id: int, url: str, timeout=DEFAULT_TIMEOUT,
                     max_bytes: int = DEFAULT_MAX_BYTES,
                     extra_headers: dict | None = None,
                     filter_stubs: bool = True) -> SourceResult:
    try:
        raw, headers = safe_fetch(url, timeout=timeout, max_bytes=max_bytes,
                                  extra_headers=extra_headers)
        text = raw.decode("utf-8", errors="replace")

        # --- СОХРАНЕНИЕ СЫРОГО ОТВЕТА В ФАЙЛ ---
        try:
            os.makedirs("debug_raw", exist_ok=True)
            safe_url_name = "".join([c if c.isalnum() else "_" for c in url])[:50]
            filename = f"debug_raw/source_{source_id}_{safe_url_name}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"URL: {url}\n")
                f.write(f"Content-Type: {headers.get('Content-Type', 'N/A')}\n")
                f.write(f"Size: {len(raw)} bytes\n")
                f.write("-" * 40 + "\n")
                f.write(text)
            log.info("[FETCH #%s] Сырой ответ сохранен в %s", source_id, filename)
        except Exception as e:
            log.error("[FETCH #%s] Не удалось сохранить сырой ответ: %s", source_id, e)
        # ---------------------------------------

        body = decode_subscription(text)
        links = extract_links(body)

        stubs_removed = 0
        if filter_stubs:
            links, stubs_removed = filter_stubs_from(links)

        unique = deduplicate(links)
        ui_header = headers.get("subscription-userinfo")
        userinfo = parse_userinfo(ui_header) if ui_header else {}
        return SourceResult(source_id=source_id, ok=True, count=len(unique),
                            links=links, userinfo=userinfo, stubs_removed=stubs_removed)
    except FetchError as exc:
        return SourceResult(source_id=source_id, ok=False, error=str(exc))
    except requests.RequestException as exc:
        return SourceResult(source_id=source_id, ok=False, error=f"Сетевая ошибка: {exc.__class__.__name__}: {exc}")
    except Exception as exc:
        log.exception("Неожиданная ошибка при загрузке источника #%s", source_id)
        return SourceResult(source_id=source_id, ok=False, error=f"Внутренняя ошибка: {exc}")

def aggregate_sources(sources: Iterable, timeout=DEFAULT_TIMEOUT,
                      max_bytes: int = DEFAULT_MAX_BYTES,
                      workers: int = FETCH_WORKERS,
                      client_headers: dict | None = None):
    sources = list(sources)
    results: dict[int, SourceResult] = {}
    if sources:
        workers = max(1, min(workers, len(sources)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="fetch") as pool:
            futures = {}
            for s in sources:
                headers = client_headers if getattr(s, "forward_headers", True) else None
                futures[pool.submit(fetch_one_source, s.id, s.url, timeout, max_bytes,
                                    headers, getattr(s, "filter_stubs", True))] = s.id
            for future in futures:
                results[futures[future]] = future.result()

    all_links: list[str] = []
    userinfos: list[dict] = []
    for source in sources:
        res = results[source.id]
        if res.ok:
            all_links.extend(res.links)
            if res.userinfo:
                userinfos.append(res.userinfo)

    unique_links = deduplicate(all_links)
    payload = "\n".join(unique_links)
    b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    userinfo_header = format_userinfo(merge_userinfo(userinfos)) if userinfos else None
    return b64, results, userinfo_header