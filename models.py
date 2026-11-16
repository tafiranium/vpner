"""
Модели SQLAlchemy: администраторы, источники подписок, журнал попыток входа.
"""
import secrets
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


def utcnow() -> datetime:
    """Текущее время UTC (наивное, как принято для SQLite)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def generate_sub_token() -> str:
    """Криптостойкий токен персональной ссылки подписки (подбор невозможен)."""
    return secrets.token_urlsafe(32)


class User(db.Model):
    """Администратор панели + владелец ссылки подписки."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    # Пароль хранится ТОЛЬКО в виде хеша (werkzeug, scrypt по умолчанию)
    password_hash = db.Column(db.String(256), nullable=False)
    sub_token = db.Column(db.String(64), unique=True, nullable=False, index=True,
                          default=generate_sub_token)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    sources = db.relationship("Source", back_populates="user",
                              cascade="all, delete-orphan", lazy="dynamic")

    def set_password(self, password: str) -> None:
        """Хеширует пароль и сохраняет (сам пароль нигде не хранится)."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Постоянная проверка пароля против хеша."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Source(db.Model):
    """Ссылка на подписку, добавленная администратором."""

    __tablename__ = "sources"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"),
                        nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(2048), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # Пересылать источнику заголовки клиента (x-hwid, User-Agent, x-device-os…).
    # Нужно «персональным» источникам, привязанным к устройству Happ: без
    # x-hwid они отдают заглушку «Включите отправку HWID…» вместо ключей.
    forward_headers = db.Column(db.Boolean, nullable=False, default=True)
    # Удалять из ответа источника ключи-заглушки («Включите отправку HWID…»,
    # хост 0.0.0.0 и т.п.), чтобы клиент их никогда не видел.
    filter_stubs = db.Column(db.Boolean, nullable=False, default=True)

    # Результаты последней проверки кнопкой «Проверить источники»
    last_checked_at = db.Column(db.DateTime)
    last_status = db.Column(db.String(10))    # 'ok' | 'error' | NULL (ещё не проверялся)
    last_count = db.Column(db.Integer)        # сколько уникальных ключей получено
    last_error = db.Column(db.String(500))    # текст последней ошибки

    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow,
                           onupdate=utcnow)

    user = db.relationship("User", back_populates="sources")

    def __repr__(self) -> str:
        return f"<Source {self.name}>"


class LoginAttempt(db.Model):
    """Журнал попыток входа — основа rate limiting страницы /login."""

    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    successful = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)


class GeneratedKeys(db.Model):
    """
    Последний результат агрегации пользователя (страница «Ключи»).

    Одна запись на пользователя (user_id уникален): обновляется при каждом
    успешном запросе клиента к /sub/<token> и по кнопке «Собрать сейчас».
    Полностью неудачная генерация последний удачный список НЕ затирает.
    """

    __tablename__ = "generated_keys"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"),
                        nullable=False, unique=True, index=True)
    payload_text = db.Column(db.Text, nullable=False, default="")   # список ключей
    total_count = db.Column(db.Integer, nullable=False, default=0)
    # JSON: [{"name": "...", "count": N}] — сколько уникальных ключей дал каждый источник
    source_summary = db.Column(db.Text, nullable=False, default="[]")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class RequestLog(db.Model):
    """
    Журнал запросов клиентов к /sub/<token>: успешные и неудачные.

    При каждой вставке история подрезается до последних 200 записей
    (без фоновых задач), в панели отображаются последние 10.
    """

    __tablename__ = "request_logs"

    id = db.Column(db.Integer, primary_key=True)
    # NULL = запрос с неизвестным токеном (404); такие записи видны всем админам
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"),
                        nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False)
    user_agent = db.Column(db.String(256), nullable=False, default="")
    # x-hwid клиента Happ (если передан) — помогает диагностировать источники,
    # привязанные к устройству
    hwid = db.Column(db.String(128), nullable=False, default="")
    success = db.Column(db.Boolean, nullable=False, default=False)
    status_code = db.Column(db.Integer, nullable=False, default=200)
    keys_count = db.Column(db.Integer)          # сколько ключей отдано (при 200)
    error_text = db.Column(db.String(500))      # текст ошибки, если была
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
