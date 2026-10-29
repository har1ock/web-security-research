import hashlib
import hmac
import os
import secrets

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from itsdangerous import BadSignature, URLSafeSerializer
from jinja2 import Environment
from markupsafe import Markup
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from sqlalchemy import String, Text, create_engine, delete, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

# Конфігурація
SECURE = os.environ.get("SECURE", "0") == "1"
DB_PATH = os.environ.get("DB_PATH", "app.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev") if SECURE else "dev"

# Спочатку створюємо додаток FastAPI
app = FastAPI(
    docs_url=None if SECURE else "/docs",
    redoc_url=None if SECURE else "/redoc",
    openapi_url=None if SECURE else "/openapi.json",
)

limiter = Limiter(key_func=get_remote_address, enabled=SECURE)
app.state.limiter = limiter

app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Модель даних
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True)
    password_hash: Mapped[str]
    email: Mapped[str]


class Comment(Base):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(primary_key=True)
    author: Mapped[str]
    text: Mapped[str] = mapped_column(Text)


class Note(Base):
    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int]
    text: Mapped[str] = mapped_column(Text)


def get_db():
    """Залежність: одна сесія БД на запит, закривається після відповіді."""
    with Session(engine) as db:
        yield db


# Паролі
def hash_password(pw: str) -> str:
    salt = secrets.token_hex(8)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000)
    return f"{salt}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    salt, digest = stored.split("$")
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000)
    return hmac.compare_digest(dk.hex(), digest)


def init_db():
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        if db.scalar(select(User.id).limit(1)) is None:
            for name, pw in [("alice", "alice123"), ("bob", "bob123"), ("admin", "admin123")]:
                db.add(User(username=name, password_hash=hash_password(pw), email=f"{name}@example.com"))
            db.flush()
            for owner, text in [
                (1, "Alice: список покупок"),
                (1, "Alice: пароль від Wi-Fi 12345"),
                (2, "Bob: секретний план проєкту"),
                (3, "Admin: ключі від сервера"),
            ]:
                db.add(Note(owner_id=owner, text=text))
            db.commit()


# Сесія: підписана cookie
serializer = URLSafeSerializer(SECRET_KEY, salt="session")


def read_session(request: Request) -> dict:
    raw = request.cookies.get("session")
    if not raw:
        return {}
    try:
        return serializer.loads(raw)
    except BadSignature:
        return {}


# Заголовки безпеки (лише в P)
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    if SECURE:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
    return response


# Шаблони
jenv = Environment(autoescape=True)

SEARCH_T = jenv.from_string(
    """
<h1>Результати для: {{ (q|safe) if raw else q }}</h1>
<ul>
{% for r in rows %}<li>{{ r['id'] }} | {{ r['username'] }} | {{ r['email'] }}</li>
{% endfor %}
</ul>
"""
)
COMMENTS_T = jenv.from_string(
    """
<h1>Коментарі</h1>
{% for r in rows %}
<p><b>{{ r['author'] }}</b>: {{ (r['text']|safe) if raw else r['text'] }}</p>
{% endfor %}
"""
)
GREET_T = jenv.from_string("<h1>Hello {{ n }}</h1>")


# Ендпоінти
@app.get("/")
def index():
    return {"app": "fastapi", "mode": "secure" if SECURE else "vulnerable"}


@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, username: str = Form(""), password: str = Form(""), db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == username))
    if user is None or not verify_password(password, user.password_hash):
        return JSONResponse({"error": "invalid credentials"}, status_code=401)
    resp = JSONResponse({"message": "ok", "user": user.username})
    token = serializer.dumps({"user_id": user.id, "csrf_token": secrets.token_hex(16)})
    resp.set_cookie(
        "session",
        token,
        httponly=SECURE,
        samesite="lax" if SECURE else None,
    )
    return resp


@app.get("/search")
def search(q: str = "", db: Session = Depends(get_db)):
    try:
        if SECURE:
            stmt = select(User.id, User.username, User.email).where(
                User.username.icontains(q, autoescape=True)
            )
            rows = [dict(r._mapping) for r in db.execute(stmt)]
        else:
            result = db.connection().exec_driver_sql(
                f"SELECT id, username, email FROM users WHERE username LIKE '%{q}%'"
            )
            rows = [dict(r._mapping) for r in result]
    except SQLAlchemyError as e:
        if SECURE:
            return HTMLResponse("search error", status_code=400)
        return HTMLResponse(f"SQL error: {e}", status_code=500)
    return HTMLResponse(SEARCH_T.render(q=q, rows=rows, raw=not SECURE))


@app.post("/comments", status_code=201)
def add_comment(author: str = Form("anon"), text: str = Form(""), db: Session = Depends(get_db)):
    db.add(Comment(author=author, text=text))
    db.commit()
    return {"message": "saved"}


@app.get("/comments")
def list_comments(db: Session = Depends(get_db)):
    rows = [{"author": c.author, "text": c.text} for c in db.scalars(select(Comment))]
    return HTMLResponse(COMMENTS_T.render(rows=rows, raw=not SECURE))


@app.get("/csrf-token")
def csrf_token(request: Request):
    sess = read_session(request)
    if "user_id" not in sess:
        return JSONResponse({"error": "login required"}, status_code=401)
    return {"csrf_token": sess["csrf_token"]}


@app.get("/profile")
def profile(request: Request, db: Session = Depends(get_db)):
    uid = read_session(request).get("user_id")
    if uid is None:
        return JSONResponse({"error": "login required"}, status_code=401)
    user = db.get(User, uid)
    return {"username": user.username, "email": user.email}


@app.post("/profile/email")
def change_email(
    request: Request,
    email: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    sess = read_session(request)
    uid = sess.get("user_id")
    if uid is None:
        return JSONResponse({"error": "login required"}, status_code=401)
    if SECURE:
        if not hmac.compare_digest(csrf_token.encode(), sess.get("csrf_token", "").encode()):
            return JSONResponse({"error": "bad csrf token"}, status_code=403)
    db.execute(update(User).where(User.id == uid).values(email=email))
    db.commit()
    return {"message": "email updated", "email": email}


@app.get("/notes/{note_id}")
def get_note(note_id: int, request: Request, db: Session = Depends(get_db)):
    uid = read_session(request).get("user_id")
    if uid is None:
        return JSONResponse({"error": "login required"}, status_code=401)
    note = db.get(Note, note_id)
    if note is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    if SECURE and note.owner_id != uid:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return {"id": note.id, "owner_id": note.owner_id, "text": note.text}


@app.get("/greet")
def greet(name: str = ""):
    return HTMLResponse(GREET_T.render(n=name if SECURE else Markup(name)))


if os.environ.get("TEST_MODE") == "1":
    @app.post("/__reset")
    def reset_state(db: Session = Depends(get_db)):
        db.execute(delete(Comment))
        for u in db.scalars(select(User)):
            u.email = f"{u.username}@example.com"
        db.commit()
        return {"message": "reset"}