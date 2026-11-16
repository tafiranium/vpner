"""
Создание первого администратора (или сброс пароля существующего).

Локально:                             python create_admin.py
На PythonAnywhere (в Bash-консоли):   workon vpn-env && cd ~/vpn-aggregator && python create_admin.py

Логин/пароль можно передать переменными окружения:
    ADMIN_USERNAME=admin ADMIN_PASSWORD=... python create_admin.py

Скрипт заодно создаёт БД (таблицы), если её ещё нет.
"""
import getpass
import os
import sys

from app import app
from models import User, db


def main() -> int:
    username = (os.environ.get("ADMIN_USERNAME") or input("Логин администратора: ")).strip()
    password = os.environ.get("ADMIN_PASSWORD") or getpass.getpass(
        "Пароль (минимум 8 символов): ")

    if len(username) < 3:
        print("Ошибка: логин должен быть не короче 3 символов.")
        return 1
    if len(password) < 8:
        print("Ошибка: пароль должен быть не короче 8 символов.")
        return 1

    with app.app_context():
        user = db.session.scalar(db.select(User).where(User.username == username))
        if user:
            user.set_password(password)          # сброс пароля существующего админа
            action = "Пароль обновлён"
        else:
            user = User(username=username)       # sub_token сгенерируется сам
            user.set_password(password)
            db.session.add(user)
            action = "Администратор создан"
        db.session.commit()

        print(f"{action}: {username}")
        print(f"Токен подписки (вставьте в ссылку https://<ваш-домен>/sub/<токен>):")
        print(f"  {user.sub_token}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
