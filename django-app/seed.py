
import os

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from django.contrib.auth.models import User
from core.models import Note

if not User.objects.exists():
    users = {}
    for name, pw in [("alice", "alice123"), ("bob", "bob123"), ("admin", "admin123")]:
        users[name] = User.objects.create_user(name, f"{name}@example.com", pw)
    for owner, text in [
        ("alice", "Alice: список покупок"),
        ("alice", "Alice: пароль від Wi-Fi 12345"),
        ("bob", "Bob: секретний план проєкту"),
        ("admin", "Admin: ключі від сервера"),
    ]:
        Note.objects.create(owner=users[owner], text=text)