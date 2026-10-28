
TARGETS = [
    {"framework": "flask",   "mode": "vulnerable", "base_url": "http://localhost:5001", "table": "users",      "pwd_col": "password_hash"},
    {"framework": "flask",   "mode": "secure",     "base_url": "http://localhost:5101", "table": "users",      "pwd_col": "password_hash"},
    {"framework": "django",  "mode": "vulnerable", "base_url": "http://localhost:5002", "table": "auth_user",  "pwd_col": "password"},
    {"framework": "django",  "mode": "secure",     "base_url": "http://localhost:5102", "table": "auth_user",  "pwd_col": "password"},
    {"framework": "fastapi", "mode": "vulnerable", "base_url": "http://localhost:5003", "table": "users",      "pwd_col": "password_hash"},
    {"framework": "fastapi", "mode": "secure",     "base_url": "http://localhost:5103", "table": "users",      "pwd_col": "password_hash"},
]
CSRF_FIELD = {"flask": "csrf_token", "fastapi": "csrf_token", "django": "csrfmiddlewaretoken"}

LOGIN_USER = {"username": "alice", "password": "alice123"}
