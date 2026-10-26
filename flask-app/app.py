import hmac
import os
import secrets
import sqlite3

from flask import Flask, g, jsonify, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

SECURE = os.environ.get("SECURE", "0") == "1"
DB_PATH = os.environ.get("DB_PATH", "app.db")

app = Flask(__name__)
app.config.update(
    # V: слабкий ключ підпису сесії. P: ключ береться із середовища
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev") if SECURE else "dev",
    # V: JavaScript на сторінці може прочитати cookie(document.cookie)
    # P: HttpOnly забороняє це, тож XSS не вкраде сесію
    SESSION_COOKIE_HTTPONLY=SECURE,
    # V: браузер шле coookie і з чужих сайтів. P: Lax блокує частину міжсайтових POST
    SESSION_COOKIE_SAMESITE="Lax" if SECURE else None,
)


# База даних
def get_db():
    """Одне з'єднання на запит, зберігаємо в g."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row # доступ до колонок за іменем
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Створює таблиці й текстові дані. Безпечно викликати повторно."""
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS comments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            text TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            text TEXT NOT NULL
        );
        """
    )
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        for name, pw, email in[
            ("alice", "alice123", "alice@examle.com"),
            ("bob", "bob123", "bob@example.com"),
            ("admin", "admin123", "admin@example.com"),
        ]:
            db.execute(
                "INSERT INTO users(username, password_hash, email) VALUES (?,?,?)",
                (name, generate_password_hash(pw), email),
            )
        for owner, text in [
            (1, "Alice: список покупок"),
            (1, "Alice: пароль від Wi-Fi 12345"),
            (2, "Bob: секретний план проєкту"),
            (3, "Admin: ключі від сервера"),   
        ]:
            db.execute("INSERT INTO notes(owner_id, text) VALUES (?,?)", (owner, text))
    db.commit()
    db.close()

#Заголовки безпеки (тільки в режимі P)
@app.after_request
def add_security_headers(resp):
    if SECURE:
        # CSP: дозволяє тільки ресурси з нашого домену, забороняє inline-скрипти
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none' frame-ancestors 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


#Шаблони 
# 'raw' = True у режимі V: фільтр |safe вимикає екранування.

SEARCH_HTML = """
<h1>Результати дня: {{ (q|safe) if raw else q }}</h1>
<ul>
{% for r in rows %}<li>{{ r['id'] }} | {{ r['username'] }} | {{ r['email'] }}</li>
{% endfor %}
</ul>
"""

COMMENTS_HTML = """
<h1>Коментарі</h1>
{% for r in rows %}
<p><b>{{ r['author' ]}}</b>: {{ (r['text']|safe) if raw else r['text'] }}</p>
{% endfor %}
"""

#Ендпоінти 
@app.get("/")
def index():
    return jsonify(app="flask", mode="secure" if SECURE else "vulnerable")


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # Тут запит параметризований в обох режимах: SQLi досліджуємо на /search
    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify(error="invalid credentials"), 401
    session.clear()
    session["user_id"] = row["id"]
    session["csrf_token"] = secrets.token_hex(16)
    return jsonify(message="ok", user=row["username"])


@app.get("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    try:
        if SECURE:
            # P: ? це плейсхолдер. Драйвер передає q як ДАНІ, не як частину SQL
            rows = db.execute(
                "SELECT id, username, email FROM users WHERE username LIKE ?",
                (f"%{q}%",),
            ).fetchall()
        else:
            # V: q вклеюється прямо в текст запиту
            rows = db.execute(
                f"SELECT id, username, email FROM users WHERE username LIKE '%{q}%'"
            ).fetchall()
    except sqlite3.Error as e:
        if SECURE:
            return "search error", 400
        return f"SQL error: {e}", 500  # V: витік внутрішніх деталей
    return render_template_string(SEARCH_HTML, q=q, rows=rows, raw=not SECURE)


@app.post("/comments")
def add_comment():
    author = request.form.get("author", "anon")
    text = request.form.get("text", "")
    db = get_db()
    # Зберігаємо ТЕКСТ як є в обох режимах. Екранувати треба при ВИВОДІ
    db.execute("INSERT INTO comments(author, text) VALUES (?, ?)", (author, text))
    db.commit()
    return jsonify(message="saved"), 201


@app.get("/comments")
def list_comments():
    rows = get_db().execute("SELECT author, text FROM comments").fetchall()
    return render_template_string(COMMENTS_HTML, rows=rows, raw=not SECURE)


@app.get("/csrf-token")
def csrf_token():
    if "user_id" not in session:
        return jsonify(error="login required"), 401
    return jsonify(csrf_token=session["csrf_token"])


@app.post("/profile/email")
def change_email():
    uid = session.get("user_id")
    if uid is None:
        return jsonify(error="login required"), 401
    if SECURE:
        sent = request.form.get("csrf_token", "")
        # compare_digest: порівняння за сталий час (проти timing-атак)
        if not hmac.compare_digest(sent, session.get("csrf_token", "")):
            return jsonify(error="bad csrf token"), 403
    email = request.form.get("email", "")
    db = get_db()
    db.execute("UPDATE users SET email = ? WHERE id = ?", (email, uid))
    db.commit()
    return jsonify(message="email updated", email=email)


@app.get("/notes/<int:note_id>")
def get_note(note_id):
    uid = session.get("user_id")
    if uid is None:
        return jsonify(error="login required"), 401
    row = get_db().execute(
        "SELECT id, owner_id, text FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    # P: перевірка, що нотатка належить поточному користувачу
    if SECURE and row["owner_id"] != uid:
        return jsonify(error="forbidden"), 403
    return jsonify(id=row["id"], owner_id=row["owner_id"], text=row["text"])


@app.get("/profile")
def profile():
    uid = session.get("user_id")
    if uid is None:
        return jsonify(error="login required"), 401
    row = get_db().execute(
        "SELECT username, email FROM users WHERE id = ?", (uid,)
    ).fetchone()
    return jsonify(username=row["username"], email=row["email"])


if os.environ.get("TEST_MODE") == "1":
    @app.post("/__reset")
    def reset_state():
        db = get_db()
        db.execute("DELETE FROM comments")
        db.execute("UPDATE users SET email = username || '@example.com'")
        db.commit()
        return jsonify(message="reset")