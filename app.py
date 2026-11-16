"""
VPN-подписки: панель администратора + on-demand API для VPN-клиентов (Happ).

Локальный запуск:      python app.py          -> http://127.0.0.1:5000
PythonAnywhere (WSGI): from app import app as application

Никаких фоновых задач (cron/APScheduler) нет: каждое обращение к
/sub/<token> выполняет полную агрегацию источников «на лету».
"""
import base64
import hmac
import json
import logging
import os
import secrets
from datetime import timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, redirect, render_template,
                   request, session, url_for)
from sqlalchemy import text

from config import Config
from models import (GeneratedKeys, LoginAttempt, RequestLog, Source, User,
                    db, utcnow)
from utils.parser import (FetchError, FORWARDABLE_HEADERS, aggregate_sources,
                          validate_url)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("vpn-aggregator")


def _b64_decode_payload(b64: str) -> str:
    """
    Декодирует агрегированную подписку обратно в текст (для журнала/«Ключей»).

    Терпим к варианту base64: стандартный или url-safe, С паддингом «=»
    или без (aggregate_sources отдаёт без паддинга, как большинство
    VPN-панелей). Прежняя строка с жёстким urlsafe_b64decode падала
    «Incorrect padding» на безпаддинговом выводе.
    """
    if not b64:
        return ""
    s = b64.strip()
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii")).decode("utf-8", "replace")


def create_app() -> Flask:
    """Фабрика приложения: конфигурация, БД, CSRF, маршруты."""
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    # -------------------------------------------------------------------
    # CSRF-защита всех POST-форм: токен хранится в сессии, сравнение — за
    # константное время (hmac.compare_digest).
    # -------------------------------------------------------------------
    def csrf_token() -> str:
        """Ленивая генерация CSRF-токена для шаблонов."""
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(32)
        return session["_csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            stored = session.get("_csrf_token")
            sent = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
            if not stored or not sent or not hmac.compare_digest(stored.encode(),
                                                                 sent.encode()):
                abort(400, description="Недействительный CSRF-токен. Обновите страницу.")

    # -------------------------------------------------------------------
    # Минимальный набор security-заголовков на каждый ответ.
    # -------------------------------------------------------------------
    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        return response

    # -------------------------------------------------------------------
    # Помощники.
    # -------------------------------------------------------------------
    def login_required(view):
        """Декоратор: страница доступна только вошедшему администратору."""
        @wraps(view)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapper

    def current_user() -> User | None:
        uid = session.get("user_id")
        return db.session.get(User, uid) if uid else None

    def client_ip() -> str:
        # На PythonAnywhere remote_addr — уже IP клиента. Доверять
        # X-Forwarded-For (TRUST_PROXY=1) стоит только если приложение закрыто
        # своим реверс-прокси (DDoS-Guard/Cloudflare), иначе подменой заголовка
        # можно обходить rate limit входа.
        if app.config.get("TRUST_PROXY_HEADERS"):
            xff = request.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()[:64]
        return (request.remote_addr or "unknown")[:64]

    def collect_client_headers() -> dict[str, str]:
        """
        Разрешённые заголовки клиента Happ для пересылки источникам:
        x-hwid, User-Agent, x-device-os и т.д. (только имена из
        FORWARDABLE_HEADERS — Cookie и Authorization наружу не уходят).
        """
        out: dict[str, str] = {}
        for name in FORWARDABLE_HEADERS:
            value = request.headers.get(name)
            if value:
                out[name] = value[:256]
        return out

    def _get_own_source(source_id: int) -> Source:
        """Источник текущего пользователя; 404 для чужих и несуществующих."""
        user = current_user()
        source = db.session.get(Source, source_id)
        if source is None or user is None or source.user_id != user.id:
            abort(404)
        return source

    def _validate_source_form(user: User, name: str, url: str,
                              exclude_id: int = 0) -> str | None:
        """Валидация формы источника; возвращает текст ошибки или None."""
        if not name or len(name) > 100:
            return "Название обязательно (1–100 символов)."
        if not url or len(url) > 2048:
            return "URL обязателен (до 2048 символов)."
        try:
            # Схема http/https + SSRF-проверка (включая DNS-резолв) прямо при
            # сохранении — опечатки и внутренние адреса отсекаются сразу.
            validate_url(url)
        except FetchError as exc:
            return f"URL не прошёл проверку: {exc}"
        duplicate = db.session.scalar(
            db.select(db.func.count())
            .select_from(Source)
            .where(Source.user_id == user.id, Source.url == url,
                   Source.id != exclude_id)
        )
        if duplicate:
            return "Этот URL уже добавлен."
        return None

    def _login_blocked(ip: str) -> bool:
        """
        Rate limiting страницы входа.

        Счётчик неудач хранится в БД, поэтому лимит общий для всех воркеров
        PythonAnywhere (in-memory лимиты при нескольких процессах не работают).
        Фоновых задач нет — старые записи подчищаем прямо здесь.
        """
        now = utcnow()
        window_start = now - timedelta(minutes=app.config["LOGIN_WINDOW_MINUTES"])
        db.session.execute(
            db.delete(LoginAttempt)
            .where(LoginAttempt.created_at < now - timedelta(days=1))
        )
        failed = db.session.scalar(
            db.select(db.func.count())
            .select_from(LoginAttempt)
            .where(LoginAttempt.ip_address == ip,
                   LoginAttempt.successful.is_(False),
                   LoginAttempt.created_at >= window_start)
        ) or 0
        db.session.commit()
        return failed >= app.config["LOGIN_MAX_ATTEMPTS"]

    # ===================================================================
    # Маршруты панели администратора
    # ===================================================================
    @app.route("/")
    def index():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = client_ip()
            if _login_blocked(ip):
                flash("Слишком много неудачных попыток. Попробуйте снова через 15 минут.",
                      "error")
                return render_template("login.html"), 429

            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            user = db.session.scalar(db.select(User).where(User.username == username))

            if user and user.check_password(password):
                # Успех: сбрасываем счётчик неудач этого IP и фиксируем вход
                db.session.execute(db.delete(LoginAttempt).where(
                    LoginAttempt.ip_address == ip,
                    LoginAttempt.successful.is_(False)))
                db.session.add(LoginAttempt(ip_address=ip, successful=True))
                db.session.commit()
                # Защита от фиксации сессии: полностью новая сессия
                session.clear()
                session["user_id"] = user.id
                session.permanent = True
                flash("Вы вошли в панель.", "success")
                next_url = request.args.get("next") or ""
                # Открытый redirect запрещён: только относительные пути сайта
                if next_url.startswith("/") and not next_url.startswith("//"):
                    return redirect(next_url)
                return redirect(url_for("dashboard"))

            db.session.add(LoginAttempt(ip_address=ip, successful=False))
            db.session.commit()
            flash("Неверный логин или пароль.", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = current_user()
        sources = user.sources.order_by(Source.created_at.desc()).all()
        # Схему берём с учётом прокси PythonAnywhere (X-Forwarded-Proto), чтобы
        # ссылка всегда была вида https://username.pythonanywhere.com/sub/<token>
        proto = request.headers.get("X-Forwarded-Proto", request.scheme)
        sub_url = f"{proto}://{request.host}/sub/{user.sub_token}"
        # Сокращённый алиас того же списка: оба адреса работают одинаково
        sub_url_short = f"{proto}://{request.host}/s/{user.sub_token}"
        return render_template("dashboard.html", user=user, sources=sources,
                               sub_url=sub_url, sub_url_short=sub_url_short)

    @app.route("/sources/new", methods=["GET", "POST"])
    @login_required
    def source_new():
        user = current_user()
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            url = (request.form.get("url") or "").strip()
            is_active = request.form.get("is_active") == "on"
            forward_headers = request.form.get("forward_headers") == "on"
            filter_stubs_flag = request.form.get("filter_stubs") == "on"
            error = _validate_source_form(user, name, url)
            if error:
                flash(error, "error")
                return render_template("source_form.html", source=None,
                                       form=request.form,
                                       action_url=url_for("source_new")), 400
            db.session.add(Source(user_id=user.id, name=name, url=url,
                                  is_active=is_active,
                                  forward_headers=forward_headers,
                                  filter_stubs=filter_stubs_flag))
            db.session.commit()
            flash(f"Источник «{name}» добавлен.", "success")
            return redirect(url_for("dashboard"))
        return render_template("source_form.html", source=None,
                               form={"name": "", "url": "", "is_active": True,
                                     "forward_headers": True, "filter_stubs": True},
                               action_url=url_for("source_new"))

    @app.route("/sources/<int:source_id>/edit", methods=["GET", "POST"])
    @login_required
    def source_edit(source_id: int):
        user = current_user()
        source = _get_own_source(source_id)
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            url = (request.form.get("url") or "").strip()
            is_active = request.form.get("is_active") == "on"
            error = _validate_source_form(user, name, url, exclude_id=source.id)
            if error:
                flash(error, "error")
                return render_template("source_form.html", source=source,
                                       form=request.form,
                                       action_url=url_for("source_edit",
                                                          source_id=source.id)), 400
            source.name, source.url, source.is_active = name, url, is_active
            source.forward_headers = request.form.get("forward_headers") == "on"
            source.filter_stubs = request.form.get("filter_stubs") == "on"
            db.session.commit()
            flash(f"Источник «{name}» сохранён.", "success")
            return redirect(url_for("dashboard"))
        return render_template("source_form.html", source=source,
                               form={"name": source.name, "url": source.url,
                                     "is_active": source.is_active,
                                     "forward_headers": source.forward_headers,
                                     "filter_stubs": source.filter_stubs},
                               action_url=url_for("source_edit", source_id=source.id))

    @app.post("/sources/<int:source_id>/toggle")
    @login_required
    def source_toggle(source_id: int):
        source = _get_own_source(source_id)
        source.is_active = not source.is_active
        db.session.commit()
        state = "включён" if source.is_active else "выключен"
        flash(f"Источник «{source.name}» {state}.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/sources/<int:source_id>/delete")
    @login_required
    def source_delete(source_id: int):
        source = _get_own_source(source_id)
        name = source.name
        db.session.delete(source)
        db.session.commit()
        flash(f"Источник «{name}» удалён.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/sources/check")
    @login_required
    def sources_check():
        """
        Кнопка «Проверить источники»: синхронно (без фоновых задач) скачивает
        активные источники и показывает, сколько ключей дал каждый.
        Результаты сохраняются в БД и видны в таблице дашборда.
        """
        user = current_user()
        active = user.sources.filter_by(is_active=True).order_by(Source.id).all()
        limit = app.config["MAX_SOURCES_PER_REQUEST"]
        sources, overflow = active[:limit], len(active) > limit
        if not sources:
            flash("Нет активных источников для проверки.", "error")
            return redirect(url_for("dashboard"))

        _, results, _ = aggregate_sources(
            sources,
            timeout=app.config["FETCH_TIMEOUT"],
            max_bytes=app.config["MAX_RESPONSE_BYTES"],
            client_headers=collect_client_headers(),
        )
        for source in sources:
            res = results[source.id]
            source.last_checked_at = utcnow()
            if res.ok:
                source.last_status = "ok"
                source.last_count = res.count
                source.last_error = ""
                flash(f"«{source.name}»: получено ключей — {res.count}.", "success")
                if res.stubs_removed:
                    source.last_error = f"заглушек удалено: {res.stubs_removed}"
                    flash(f"«{source.name}»: источник отдал заглушек — "
                          f"{res.stubs_removed} (удалены). Источник привязан к "
                          f"HWID устройства: убедитесь, что Happ отправляет "
                          f"заголовок x-hwid.", "warning")
            else:
                source.last_status = "error"
                source.last_count = 0
                source.last_error = res.error[:500]
                flash(f"«{source.name}»: ошибка — {res.error}", "error")
        if overflow:
            flash(f"Проверены первые {limit} источников (лимит на один запрос).",
                  "error")
        db.session.commit()
        return redirect(url_for("dashboard"))

    @app.post("/settings/regenerate-token")
    @login_required
    def regenerate_token():
        """Пересоздаёт токен персональной ссылки (старая ссылка отмирает)."""
        user = current_user()
        user.sub_token = secrets.token_urlsafe(32)
        db.session.commit()
        flash("Новый токен создан. Обновите ссылку в Happ — старая больше не действует.",
              "success")
        return redirect(url_for("dashboard"))

    # ===================================================================
    # Страницы «Ключи» и «Журнал запросов»
    # ===================================================================
    def _log_request(user_id, ip, ua, success, status_code, keys_count,
                     error_text, hwid=""):
        """
        Пишет запись в журнал запросов и подрезает историю до последних 200
        записей. Фоновых задач нет — чистка выполняется прямо при вставке.
        """
        db.session.add(RequestLog(user_id=user_id, ip_address=ip,
                                  user_agent=(ua or "")[:256], success=success,
                                  status_code=status_code, keys_count=keys_count,
                                  error_text=(error_text or "")[:500] or None,
                                  hwid=(hwid or "")[:128]))
        threshold = db.session.scalar(
            db.select(RequestLog.id)
            .order_by(RequestLog.id.desc()).offset(200).limit(1))
        if threshold:
            db.session.execute(db.delete(RequestLog).where(RequestLog.id < threshold))
        db.session.commit()

    def _save_generated_keys(user_id: int, payload_text: str, total: int,
                             summary: list[dict], overwrite: bool = True) -> None:
        """
        Сохраняет последний результат агрегации для страницы «Ключи».
        overwrite=False (полный провал всех источников) не затирает последний
        удачный список.
        """
        if not overwrite:
            return
        row = db.session.scalar(
            db.select(GeneratedKeys).where(GeneratedKeys.user_id == user_id))
        if row is None:
            row = GeneratedKeys(user_id=user_id)
            db.session.add(row)
        row.payload_text = payload_text
        row.total_count = total
        row.source_summary = json.dumps(summary, ensure_ascii=False)
        row.created_at = utcnow()
        try:
            db.session.commit()
        except Exception:
            # Параллельный запрос успел создать запись раньше — обновим её
            db.session.rollback()
            row = db.session.scalar(
                db.select(GeneratedKeys).where(GeneratedKeys.user_id == user_id))
            if row is not None:
                row.payload_text = payload_text
                row.total_count = total
                row.source_summary = json.dumps(summary, ensure_ascii=False)
                row.created_at = utcnow()
                db.session.commit()

    @app.route("/keys")
    @login_required
    def keys_page():
        """Просмотр последних сгенерированных ключей."""
        user = current_user()
        row = db.session.scalar(
            db.select(GeneratedKeys).where(GeneratedKeys.user_id == user.id))
        summary = []
        if row and row.source_summary:
            try:
                summary = json.loads(row.source_summary)
            except ValueError:
                summary = []
        return render_template("keys.html", row=row, summary=summary)

    @app.post("/keys/generate")
    @login_required
    def keys_generate():
        """
        Кнопка «Собрать сейчас»: генерирует список ключей без ожидания запроса
        клиента. Синхронно, без фоновых задач.
        """
        user = current_user()
        sources = (user.sources.filter_by(is_active=True).order_by(Source.id)
                   .all()[:app.config["MAX_SOURCES_PER_REQUEST"]])
        if not sources:
            flash("Нет активных источников — добавьте их на дашборде.", "error")
            return redirect(url_for("keys_page"))

        b64, results, _ = aggregate_sources(
            sources,
            timeout=app.config["FETCH_TIMEOUT"],
            max_bytes=app.config["MAX_RESPONSE_BYTES"],
            client_headers=collect_client_headers(),
        )
        payload_text = _b64_decode_payload(b64)
        keys_count = len(payload_text.splitlines()) if payload_text else 0
        ok_count = sum(1 for r in results.values() if r.ok)

        for s in sources:
            res = results[s.id]
            if res.ok:
                flash(f"«{s.name}»: получено ключей — {res.count}.", "success")
            else:
                flash(f"«{s.name}»: ошибка — {res.error}", "error")

        if ok_count:
            _save_generated_keys(
                user.id, payload_text, keys_count,
                [{"name": s.name, "count": results[s.id].count}
                 for s in sources if results[s.id].ok])
            flash(f"Список собран: {keys_count} уникальных ключей.", "success")
        else:
            flash("Все источники вернули ошибки — последний удачный список "
                  "сохранён без изменений.", "error")
        return redirect(url_for("keys_page"))

    @app.route("/requests")
    @login_required
    def requests_log():
        """
        Журнал последних 10 запросов клиентов к /sub/<token>: успешные,
        частичные и неудачные (с текстом ошибки). Записи с неизвестным
        токеном (user_id NULL) видны всем администраторам — они касаются
        попыток подбора ссылок подписки.
        """
        user = current_user()
        entries = db.session.scalars(
            db.select(RequestLog)
            .where(db.or_(RequestLog.user_id == user.id,
                          RequestLog.user_id.is_(None)))
            .order_by(RequestLog.created_at.desc(), RequestLog.id.desc())
            .limit(10)
        ).all()
        return render_template("requests.html", entries=entries)

    # ===================================================================
    # On-demand API для VPN-клиентов (Happ)
    # ===================================================================
    @app.get("/sub/<token>")
    @app.get("/s/<token>")
    def subscription(token: str):
        """
        GET /sub/<token> (алиас /s/<token>) — точка входа клиента Happ.

        Каждый запрос выполняет полную агрегацию «на лету»:
        скачивание источников -> парсинг -> дедупликация -> Base64.
        Кэша нет: ответ всегда собирается заново.

        Заголовки клиента (x-hwid, User-Agent, x-device-os, ...) пересылаются
        источникам — без этого источники, привязанные к устройству, отдают
        заглушку «Включите отправку HWID...» вместо ключей, а отсеянные
        заглушки не попадают в ответ даже если источник их вернул.

        Каждый запрос логируется в request_logs (журнал в панели, с HWID), а
        последний удачный результат сохраняется в generated_keys (страница
        «Ключи»).
        """
        ip = client_ip()
        ua = request.headers.get("User-Agent") or ""
        hwid = (request.headers.get("x-hwid") or "")[:128]
        client_headers = collect_client_headers()

        user = db.session.scalar(db.select(User).where(User.sub_token == token))
        if user is None:
            # Одинаковое «Not Found» независимо от причины — не раскрываем,
            # существует ли токен вообще. Попытка попадает в журнал (с HWID).
            _log_request(user_id=None, ip=ip, ua=ua, success=False,
                         status_code=404, keys_count=None,
                         error_text="Неизвестный токен", hwid=hwid)
            return Response("Not Found\n", status=404, mimetype="text/plain")

        try:
            sources = (user.sources.filter_by(is_active=True).order_by(Source.id)
                       .all()[:app.config["MAX_SOURCES_PER_REQUEST"]])

            b64, results, userinfo = aggregate_sources(
                sources,
                timeout=app.config["FETCH_TIMEOUT"],
                max_bytes=app.config["MAX_RESPONSE_BYTES"],
                client_headers=client_headers,
            )
            payload_text = _b64_decode_payload(b64)
            keys_count = len(payload_text.splitlines()) if payload_text else 0
            ok_count = sum(1 for r in results.values() if r.ok)

            # Ошибки источников + информация об отсеянных заглушках — всё это
            # попадает в журнал (колонка «Ошибка»)
            problems = [f"«{s.name}»: {results[s.id].error}"
                        for s in sources if not results[s.id].ok]
            problems += [f"«{s.name}»: удалено заглушек — {results[s.id].stubs_removed}"
                         for s in sources
                         if results[s.id].ok and results[s.id].stubs_removed]
            if not sources:
                error_text = "Нет активных источников"
            elif problems:
                error_text = "; ".join(problems)
            else:
                error_text = None

            _save_generated_keys(
                user.id, payload_text, keys_count,
                [{"name": s.name, "count": results[s.id].count}
                 for s in sources if results[s.id].ok],
                overwrite=ok_count > 0)
            _log_request(user_id=user.id, ip=ip, ua=ua, success=ok_count > 0,
                         status_code=200, keys_count=keys_count,
                         error_text=error_text, hwid=hwid)

            headers = {
                "Content-Type": "text/plain; charset=utf-8",
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                # Интервал автообновления подписки в часах. Клиент может опрашивать
                # хоть каждую минуту — агрегация всегда выполняется заново.
                "profile-update-interval": "1",
            }
            if userinfo:
                headers["subscription-userinfo"] = userinfo
            return Response(b64, status=200, headers=headers)
        except Exception as exc:
            # Непредвиденная ошибка агрегации — фиксируем в журнале, отдаём 500
            db.session.rollback()
            log.exception("Ошибка агрегации при запросе /sub")
            _log_request(user_id=user.id, ip=ip, ua=ua, success=False,
                         status_code=500, keys_count=None,
                         error_text=f"Внутренняя ошибка: {exc}", hwid=hwid)
            return Response("Internal Server Error\n", status=500,
                            mimetype="text/plain")

    # -------------------------------------------------------------------
    # Инициализация БД (создаётся автоматически при первом запуске/импорте).
    # -------------------------------------------------------------------
    with app.app_context():
        db.create_all()
        _ensure_schema()
        _bootstrap_admin()

    return app


def _ensure_schema() -> None:
    """
    Мини-миграция для БД, созданной предыдущей версией приложения:
    db.create_all() не добавляет колонки в уже существующие таблицы, поэтому
    недостающие добавляются через ALTER TABLE (SQLite). Выполняется при каждом
    старте, но реальный ALTER происходит только один раз. Новые таблицы
    создаются сразу со всеми колонками (create_all).
    """
    plan = (
        ("sources", "forward_headers",
         "ALTER TABLE sources ADD COLUMN forward_headers BOOLEAN NOT NULL DEFAULT 1"),
        ("sources", "filter_stubs",
         "ALTER TABLE sources ADD COLUMN filter_stubs BOOLEAN NOT NULL DEFAULT 1"),
        ("request_logs", "hwid",
         "ALTER TABLE request_logs ADD COLUMN hwid VARCHAR(128) NOT NULL DEFAULT ''"),
    )
    for table, column, ddl in plan:
        columns = {row[1] for row in db.session.execute(
            text(f"PRAGMA table_info({table})"))}
        if column in columns:
            continue
        try:
            db.session.execute(text(ddl))
            db.session.commit()
            log.info("Схема обновлена: добавлена колонка %s.%s", table, column)
        except Exception:
            # Второй воркер добавил колонку одновременно с нами — не критично
            db.session.rollback()


def _bootstrap_admin() -> None:
    """
    Создаёт первого администратора из переменных окружения при самом первом
    запуске, если БД пуста: ADMIN_USERNAME и ADMIN_PASSWORD (пароль от 8
    символов). Иначе — используйте скрипт create_admin.py.
    """
    users_total = db.session.scalar(
        db.select(db.func.count()).select_from(User)) or 0
    if users_total:
        return
    username = (os.environ.get("ADMIN_USERNAME") or "").strip()
    password = os.environ.get("ADMIN_PASSWORD") or ""
    if username and len(password) >= 8:
        try:
            admin = User(username=username)
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()
            log.warning("Создан первый администратор «%s» (из переменных окружения).",
                        username)
        except Exception:
            # Параллельный воркер создал админа раньше — это норма
            db.session.rollback()
            log.info("Администратор уже создан другим воркером.")
    else:
        log.warning("В БД нет пользователей. Создайте админа: python create_admin.py "
                    "(или задайте ADMIN_USERNAME и ADMIN_PASSWORD при первом запуске).")


# WSGI-точка входа: на PythonAnywhere импортируется `from app import app`
app = create_app()

if __name__ == "__main__":
    # Локальная разработка. debug=True — ТОЛЬКО локально, не на PythonAnywhere.
    app.run(host="127.0.0.1", port=5000, debug=True)
