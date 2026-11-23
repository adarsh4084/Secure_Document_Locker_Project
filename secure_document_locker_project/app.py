"""Secure Document Locker - an educational Flask application.

Files are encrypted at rest using AES-256-GCM. User vault keys are wrapped
with a password-derived key. The app uses a server-side session table so the
vault key is never placed inside Flask's browser cookie.
"""
from __future__ import annotations

import hashlib
import hmac
import mimetypes
import os
import re
import secrets
import sqlite3
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto_utils import (
    PASSWORD_KDF_ITERATIONS, derive_password_key, derive_pin_hash, encrypt_stream,
    decrypt_stream, wrap_file_key, unwrap_file_key, safe_unlink,
)
from flask import (
    Flask,
    current_app,
    abort,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_INSTANCE_DIR = BASE_DIR / "instance"
SESSION_HOURS = 8
PIN_MAX_FAILURES = 5
PIN_LOCK_MINUTES = 10
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_MINUTES = 10
PREVIEW_TEXT_LIMIT = 2 * 1024 * 1024
CATEGORIES = [
    "Personal", "Identity", "Education", "Finance", "Legal", "Medical",
    "Work", "Certificates", "Property", "Other",
]
TEXT_EXTENSIONS = {".txt", ".csv", ".md", ".log", ".json", ".xml"}
SAFE_IMAGE_MIMES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    kdf_salt BLOB NOT NULL,
    wrapped_key BLOB NOT NULL,
    pin_salt BLOB NOT NULL,
    pin_hash BLOB NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS registration_drafts (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    kdf_salt BLOB NOT NULL,
    wrapped_key BLOB NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_vault_key BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    doc_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    wrapped_file_key BLOB NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_documents_user_created ON documents(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_user_type ON documents(user_id, doc_type);
CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_id TEXT,
    file_name TEXT,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activity_user_created ON activity_log(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS pin_guard (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    failures INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
);
CREATE TABLE IF NOT EXISTS login_guard (
    attempt_key TEXT PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
);
"""


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def timestamp() -> str:
    return utc_now().isoformat()


def _load_or_create_secret(secret_path: Path) -> bytes:
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    if secret_path.exists():
        value = secret_path.read_bytes()
        if len(value) >= 32:
            return value
        raise RuntimeError(f"App secret at {secret_path} is invalid. Remove it and restart to create a new one.")
    value = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(secret_path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(value)
    return value


def _secret_bytes(app: Flask) -> bytes:
    secret = app.config["SECRET_KEY"]
    return secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(str(current_app.config["DATABASE"]), timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 30000")
    return g.db


def init_db(app: Flask) -> None:
    db_path = Path(app.config["DATABASE"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path), timeout=30)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(SCHEMA)
        connection.commit()
    finally:
        connection.close()



def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()



def storage_path(app: Flask, user_id: int, file_id: str) -> Path:
    # The filename is an internally generated UUID, never a user-supplied path.
    return Path(app.config["STORAGE_DIR"]) / f"user_{int(user_id)}" / f"{file_id}.sdl"


def new_temp_path(app: Flask, prefix: str = "plain-") -> Path:
    temp_dir = Path(app.config["TEMP_DIR"])
    temp_dir.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=str(temp_dir))
    os.close(fd)
    return Path(path)




def log_event(user_id: int, action: str, details: str, file_id: str | None = None,
              file_name: str | None = None) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO activity_log (user_id, file_id, file_name, action, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, file_id, file_name, action, details[:500], timestamp()),
    )
    db.commit()


def format_bytes(value: int | None) -> str:
    size = int(value or 0)
    units = ["B", "KB", "MB", "GB", "TB"]
    amount = float(size)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{int(amount)} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TB"


def get_document(user_id: int, file_id: str) -> sqlite3.Row | None:
    return get_db().execute(
        "SELECT * FROM documents WHERE id = ? AND user_id = ?", (file_id, user_id)
    ).fetchone()


def validate_password(password: str) -> list[str]:
    issues: list[str] = []
    if len(password) < 10:
        issues.append("Use at least 10 characters.")
    if not re.search(r"[a-z]", password):
        issues.append("Add a lowercase letter.")
    if not re.search(r"[A-Z]", password):
        issues.append("Add an uppercase letter.")
    if not re.search(r"[0-9]", password):
        issues.append("Add a number.")
    if not re.search(r"[^A-Za-z0-9]", password):
        issues.append("Add a symbol, such as ! or #.")
    return issues


def validate_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,24}", username))


def get_draft(token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    db = get_db()
    db.execute("DELETE FROM registration_drafts WHERE expires_at <= ?", (timestamp(),))
    db.commit()
    return db.execute(
        "SELECT * FROM registration_drafts WHERE token_hash = ? AND expires_at > ?",
        (hash_token(token), timestamp()),
    ).fetchone()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    instance_dir = Path(DEFAULT_INSTANCE_DIR)
    app.config.from_mapping(
        SECRET_KEY=None,
        INSTANCE_DIR=str(instance_dir),
        DATABASE=str(instance_dir / "vault.sqlite3"),
        STORAGE_DIR=str(instance_dir / "encrypted_files"),
        TEMP_DIR=str(instance_dir / "temp"),
        KDF_ITERATIONS=PASSWORD_KDF_ITERATIONS,
        SESSION_HOURS=SESSION_HOURS,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("SDL_HTTPS_ONLY", "0") == "1",
        MAX_CONTENT_LENGTH=None,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = _load_or_create_secret(Path(app.config["INSTANCE_DIR"]) / "app_secret.key")
    app.secret_key = app.config["SECRET_KEY"]
    Path(app.config["STORAGE_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["TEMP_DIR"]).mkdir(parents=True, exist_ok=True)
    init_db(app)

    # Remove plaintext temp files left behind by an interrupted older run.
    cutoff = datetime.fromtimestamp((utc_now() - timedelta(hours=24)).timestamp(), tz=timezone.utc).timestamp()
    for candidate in Path(app.config["TEMP_DIR"]).glob("*.tmp"):
        try:
            if candidate.stat().st_mtime < cutoff:
                candidate.unlink(missing_ok=True)
        except OSError:
            pass

    @app.before_request
    def load_request_context() -> None:
        g.current_user = None
        g.vault_key = None
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            supplied = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not supplied or not expected or not hmac.compare_digest(supplied, expected):
                abort(400, description="Your form session expired. Refresh the page and try again.")
        token = session.get("auth_token")
        if token:
            token_digest = hash_token(token)
            db = get_db()
            row = db.execute(
                "SELECT s.*, u.id AS uid, u.username, u.created_at AS user_created_at "
                "FROM user_sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
                (token_digest,),
            ).fetchone()
            if not row or row["expires_at"] <= timestamp():
                if row:
                    db.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_digest,))
                    db.commit()
                session.pop("auth_token", None)
            else:
                try:
                    wrapped = bytes(row["wrapped_vault_key"])
                    vault_key = AESGCM(_secret_bytes(app)).decrypt(
                        wrapped[:12], wrapped[12:], token_digest.encode("ascii")
                    )
                except Exception:
                    db.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_digest,))
                    db.commit()
                    session.pop("auth_token", None)
                else:
                    g.current_user = {
                        "id": row["uid"],
                        "username": row["username"],
                        "created_at": row["user_created_at"],
                    }
                    g.vault_key = vault_key

    @app.teardown_appcontext
    def close_db(_error: Exception | None = None) -> None:
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        response.headers.setdefault("Cache-Control", "no-store, max-age=0")
        if request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.context_processor
    def inject_template_context():
        return {
            "current_user": g.get("current_user"),
            "csrf_token": session.get("csrf_token", ""),
            "categories": CATEGORIES,
            "format_bytes": format_bytes,
            "year_now": utc_now().year,
        }

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.get("current_user") is None:
                flash("Please sign in to open your secure vault.", "info")
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    @app.route("/")
    def index():
        if g.get("current_user"):
            return redirect(url_for("dashboard"))
        return render_template("landing.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.get("current_user"):
            return redirect(url_for("dashboard"))
        if request.method == "GET":
            return render_template("register.html", step=1)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        issues: list[str] = []
        if not validate_username(username):
            issues.append("Username must be 3-24 characters and use only letters, numbers, dot, underscore, or hyphen.")
        if password != confirm:
            issues.append("The passwords do not match.")
        issues.extend(validate_password(password))
        db = get_db()
        # Expired registration drafts retain a unique username constraint, so remove
        # them before checking availability and inserting a fresh Step 1 draft.
        db.execute("DELETE FROM registration_drafts WHERE expires_at <= ?", (timestamp(),))
        db.commit()
        if username and db.execute("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone():
            issues.append("That username is already in use. Choose another one.")
        if username and db.execute(
            "SELECT 1 FROM registration_drafts WHERE username = ? COLLATE NOCASE AND expires_at > ?",
            (username, timestamp()),
        ).fetchone():
            issues.append("A registration for that username is already in progress. Continue it or wait 30 minutes.")
        if issues:
            for issue in issues:
                flash(issue, "error")
            return render_template("register.html", step=1, form_username=username), 400
        # The key is random. A key derived from the password wraps it so the app can
        # recover the vault key only after a successful password login.
        kdf_salt = secrets.token_bytes(16)
        derived_key = derive_password_key(password, kdf_salt, app.config["KDF_ITERATIONS"])
        vault_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        wrapped_key = nonce + AESGCM(derived_key).encrypt(
            nonce, vault_key, f"vault-key:{username.casefold()}".encode("utf-8")
        )
        password_hash = generate_password_hash(password, method="scrypt")
        draft_token = secrets.token_urlsafe(32)
        expires = (utc_now() + timedelta(minutes=30)).isoformat()
        db.execute(
            "INSERT INTO registration_drafts (token_hash, username, password_hash, kdf_salt, wrapped_key, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (hash_token(draft_token), username, password_hash, kdf_salt, wrapped_key, expires),
        )
        db.commit()
        session["draft_token"] = draft_token
        return redirect(url_for("register_pin"))

    @app.route("/register/pin", methods=["GET", "POST"])
    def register_pin():
        if g.get("current_user"):
            return redirect(url_for("dashboard"))
        draft_token = session.get("draft_token")
        draft = get_draft(draft_token)
        if not draft:
            session.pop("draft_token", None)
            flash("Your registration step expired. Please start again.", "info")
            return redirect(url_for("register"))
        if request.method == "GET":
            return render_template("register.html", step=2, draft_username=draft["username"])
        pin = request.form.get("pin", "")
        confirm_pin = request.form.get("confirm_pin", "")
        issues = []
        if not re.fullmatch(r"[0-9]{6}", pin):
            issues.append("Your security PIN must be exactly six digits.")
        if pin != confirm_pin:
            issues.append("The PIN entries do not match.")
        if issues:
            for issue in issues:
                flash(issue, "error")
            return render_template("register.html", step=2, draft_username=draft["username"]), 400
        pin_salt = secrets.token_bytes(16)
        pin_hash = derive_pin_hash(pin, pin_salt)
        db = get_db()
        try:
            cursor = db.execute(
                "INSERT INTO users (username, password_hash, kdf_salt, wrapped_key, pin_salt, pin_hash, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (draft["username"], draft["password_hash"], draft["kdf_salt"], draft["wrapped_key"],
                 pin_salt, pin_hash, timestamp()),
            )
            user_id = cursor.lastrowid
            db.execute("DELETE FROM registration_drafts WHERE token_hash = ?", (hash_token(draft_token),))
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            flash("That username was just registered. Please choose another one.", "error")
            return redirect(url_for("register"))
        session.pop("draft_token", None)
        log_event(user_id, "ACCOUNT_CREATED", "Account created and six-digit security PIN configured.")
        flash("Your vault is ready. Sign in to start protecting documents.", "success")
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.get("current_user"):
            return redirect(url_for("dashboard"))
        if request.method == "GET":
            return render_template("login.html")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        attempt_key = hashlib.sha256(username.casefold().encode("utf-8")).hexdigest()
        guard = db.execute("SELECT * FROM login_guard WHERE attempt_key = ?", (attempt_key,)).fetchone()
        now = utc_now()
        if guard and guard["locked_until"]:
            try:
                login_locked_until = datetime.fromisoformat(guard["locked_until"])
            except ValueError:
                login_locked_until = now
            if login_locked_until > now:
                flash(f"Too many sign-in attempts. Try again in about {max(1, int((login_locked_until - now).total_seconds() // 60) + 1)} minute(s).", "error")
                return render_template("login.html", form_username=username), 429
        user = db.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
        valid_user = bool(user and check_password_hash(user["password_hash"], password))
        if not valid_user:
            failures = (guard["failures"] if guard else 0) + 1
            lock_until = (now + timedelta(minutes=LOGIN_LOCK_MINUTES)).isoformat() if failures >= LOGIN_MAX_FAILURES else None
            db.execute(
                "INSERT INTO login_guard (attempt_key, failures, locked_until) VALUES (?, ?, ?) "
                "ON CONFLICT(attempt_key) DO UPDATE SET failures = excluded.failures, locked_until = excluded.locked_until",
                (attempt_key, 0 if lock_until else failures, lock_until),
            )
            db.commit()
            flash("Username or password was incorrect.", "error")
            return render_template("login.html", form_username=username), 401
        db.execute("DELETE FROM login_guard WHERE attempt_key = ?", (attempt_key,))
        db.commit()
        try:
            derived_key = derive_password_key(password, bytes(user["kdf_salt"]), app.config["KDF_ITERATIONS"])
            wrapped = bytes(user["wrapped_key"])
            vault_key = AESGCM(derived_key).decrypt(
                wrapped[:12], wrapped[12:], f"vault-key:{user['username'].casefold()}".encode("utf-8")
            )
        except Exception:
            flash("The vault key could not be unlocked. Check the account data and try again.", "error")
            return render_template("login.html", form_username=username), 401
        token = secrets.token_urlsafe(32)
        token_digest = hash_token(token)
        nonce = secrets.token_bytes(12)
        session_key = nonce + AESGCM(_secret_bytes(app)).encrypt(nonce, vault_key, token_digest.encode("ascii"))
        expiry = (utc_now() + timedelta(hours=app.config["SESSION_HOURS"])).isoformat()
        db.execute(
            "INSERT INTO user_sessions (token_hash, user_id, wrapped_vault_key, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (token_digest, user["id"], session_key, timestamp(), expiry),
        )
        db.commit()
        session.clear()
        session.permanent = True
        session["auth_token"] = token
        # CSRF token is created on the next request after session rotation.
        log_event(user["id"], "LOGIN", "Successful sign in.")
        flash(f"Welcome back, {user['username']}.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/logout", methods=["POST"])
    def logout():
        token = session.get("auth_token")
        user = g.get("current_user")
        if token:
            db = get_db()
            db.execute("DELETE FROM user_sessions WHERE token_hash = ?", (hash_token(token),))
            db.commit()
        if user:
            log_event(user["id"], "LOGOUT", "Signed out and ended the server-side session.")
        session.clear()
        response = make_response(redirect(url_for("index")))
        response.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"), path="/")
        return response

    @app.route("/dashboard")
    @login_required
    def dashboard():
        db = get_db()
        q = request.args.get("q", "").strip()[:100]
        doc_type = request.args.get("type", "")
        if doc_type not in CATEGORIES:
            doc_type = ""
        page = max(1, request.args.get("page", default=1, type=int) or 1)
        page_size = 12
        where = ["user_id = ?"]
        params: list[object] = [g.current_user["id"]]
        if q:
            where.append("(title LIKE ? OR original_filename LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        if doc_type:
            where.append("doc_type = ?")
            params.append(doc_type)
        where_sql = " AND ".join(where)
        total_docs = db.execute(f"SELECT COUNT(*) FROM documents WHERE {where_sql}", params).fetchone()[0]
        docs = db.execute(
            f"SELECT * FROM documents WHERE {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [*params, page_size, (page - 1) * page_size],
        ).fetchall()
        stats = db.execute(
            "SELECT COUNT(*) AS count, COALESCE(SUM(size_bytes),0) AS size FROM documents WHERE user_id = ?",
            (g.current_user["id"],),
        ).fetchone()
        views = db.execute(
            "SELECT COUNT(*) FROM activity_log WHERE user_id = ? AND action = 'FILE_VIEWED'",
            (g.current_user["id"],),
        ).fetchone()[0]
        downloads = db.execute(
            "SELECT COUNT(*) FROM activity_log WHERE user_id = ? AND action = 'FILE_DOWNLOADED'",
            (g.current_user["id"],),
        ).fetchone()[0]
        recent = db.execute(
            "SELECT * FROM activity_log WHERE user_id = ? ORDER BY id DESC LIMIT 6",
            (g.current_user["id"],),
        ).fetchall()
        return render_template(
            "dashboard.html", documents=docs, q=q, selected_type=doc_type,
            page=page, page_size=page_size, total_docs=total_docs,
            total_pages=max(1, (total_docs + page_size - 1) // page_size),
            total_size=stats["size"], total_document_count=stats["count"], view_count=views, download_count=downloads,
            recent_activity=recent,
        )

    @app.route("/upload", methods=["POST"])
    @login_required
    def upload():
        title = request.form.get("title", "").strip()[:100]
        doc_type = request.form.get("doc_type", "Other")
        uploaded = request.files.get("document")
        if not title:
            flash("Add a document title before uploading.", "error")
            return redirect(url_for("dashboard"))
        if doc_type not in CATEGORIES:
            flash("Choose a valid document category.", "error")
            return redirect(url_for("dashboard"))
        if uploaded is None or not uploaded.filename:
            flash("Choose a file to upload and encrypt.", "error")
            return redirect(url_for("dashboard"))
        filename = secure_filename(uploaded.filename)[:180]
        if not filename:
            filename = "document.bin"
        file_id = uuid.uuid4().hex
        data_key = secrets.token_bytes(32)
        path = storage_path(app, g.current_user["id"], file_id)
        try:
            size_bytes = encrypt_stream(uploaded.stream, path, data_key, file_id.encode("ascii"))
            wrapped_data_key = wrap_file_key(g.vault_key, data_key, file_id)
        except Exception:
            safe_unlink(path)
            app.logger.exception("File encryption failed for user_id=%s", g.current_user["id"])
            flash("The file could not be encrypted. Check storage space and try again.", "error")
            return redirect(url_for("dashboard"))
        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        db = get_db()
        db.execute(
            "INSERT INTO documents (id, user_id, title, original_filename, doc_type, size_bytes, mime_type, wrapped_file_key, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (file_id, g.current_user["id"], title, filename, doc_type, size_bytes,
             mime_type, wrapped_data_key, timestamp()),
        )
        log_event(
            g.current_user["id"], "UPLOAD_ENCRYPTED",
            f"Encrypted {format_bytes(size_bytes)} with AES-256-GCM; category: {doc_type}.", file_id, title,
        )
        flash(f"{title} was encrypted and added to your vault.", "success")
        return redirect(url_for("dashboard"))

    def pin_verification(user_id: int, pin: str) -> tuple[bool, str]:
        db = get_db()
        guard = db.execute("SELECT * FROM pin_guard WHERE user_id = ?", (user_id,)).fetchone()
        now = utc_now()
        if guard and guard["locked_until"]:
            try:
                locked_until = datetime.fromisoformat(guard["locked_until"])
            except ValueError:
                locked_until = now
            if locked_until > now:
                remaining = max(1, int((locked_until - now).total_seconds() // 60) + 1)
                return False, f"Too many incorrect PIN attempts. Try again in about {remaining} minute(s)."
        user = db.execute("SELECT pin_salt, pin_hash FROM users WHERE id = ?", (user_id,)).fetchone()
        matches = False
        if re.fullmatch(r"[0-9]{6}", pin or ""):
            supplied_hash = derive_pin_hash(pin, bytes(user["pin_salt"]))
            matches = hmac.compare_digest(supplied_hash, bytes(user["pin_hash"]))
        if matches:
            db.execute(
                "INSERT INTO pin_guard (user_id, failures, locked_until) VALUES (?, 0, NULL) "
                "ON CONFLICT(user_id) DO UPDATE SET failures = 0, locked_until = NULL",
                (user_id,),
            )
            db.commit()
            return True, ""
        failures = (guard["failures"] if guard else 0) + 1
        locked_until = (now + timedelta(minutes=PIN_LOCK_MINUTES)).isoformat() if failures >= PIN_MAX_FAILURES else None
        db.execute(
            "INSERT INTO pin_guard (user_id, failures, locked_until) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET failures = excluded.failures, locked_until = excluded.locked_until",
            (user_id, 0 if locked_until else failures, locked_until),
        )
        db.commit()
        if locked_until:
            return False, f"Too many incorrect PIN attempts. PIN access is paused for {PIN_LOCK_MINUTES} minutes."
        return False, f"That PIN did not match. {PIN_MAX_FAILURES - failures} attempt(s) remaining before a {PIN_LOCK_MINUTES}-minute lock."

    def get_plain_temp(doc: sqlite3.Row) -> Path:
        wrapped_key = bytes(doc["wrapped_file_key"])
        data_key = unwrap_file_key(g.vault_key, wrapped_key, doc["id"])
        encrypted_path = storage_path(app, g.current_user["id"], doc["id"])
        if not encrypted_path.exists():
            raise FileNotFoundError("Encrypted file is missing from storage.")
        plain_path = new_temp_path(app)
        decrypt_stream(encrypted_path, plain_path, data_key, doc["id"].encode("ascii"))
        return plain_path

    @app.route("/files/<file_id>/<action>", methods=["GET", "POST"])
    @login_required
    def file_action(file_id: str, action: str):
        if action not in {"view", "download", "delete"}:
            abort(404)
        doc = get_document(g.current_user["id"], file_id)
        if not doc:
            abort(404)
        if request.method == "GET":
            return render_template("pin.html", document=doc, action=action)
        pin = request.form.get("pin", "")
        ok, message = pin_verification(g.current_user["id"], pin)
        if not ok:
            log_event(g.current_user["id"], "PIN_FAILED", f"PIN verification failed for {action} action.", doc["id"], doc["title"])
            flash(message, "error")
            return render_template("pin.html", document=doc, action=action), 401

        if action == "delete":
            target = storage_path(app, g.current_user["id"], doc["id"])
            try:
                target.unlink(missing_ok=True)
            except OSError:
                flash("The encrypted file could not be removed. Check the storage folder permissions.", "error")
                return redirect(url_for("dashboard"))
            log_event(g.current_user["id"], "FILE_DELETED", "Encrypted file and metadata deleted after PIN verification; audit event retained.", doc["id"], doc["title"])
            db = get_db()
            db.execute("DELETE FROM documents WHERE id = ? AND user_id = ?", (doc["id"], g.current_user["id"]))
            db.commit()
            flash(f"{doc['title']} was deleted from the vault.", "success")
            return redirect(url_for("dashboard"))

        if action == "view":
            ext = Path(doc["original_filename"]).suffix.lower()
            mime = doc["mime_type"]
            if ext in TEXT_EXTENSIONS and doc["size_bytes"] > PREVIEW_TEXT_LIMIT:
                log_event(g.current_user["id"], "FILE_VIEWED", "PIN verified; text preview skipped because the file exceeds 2 MiB.", doc["id"], doc["title"])
                return render_template("view_unavailable.html", document=doc, reason="This text file is larger than the 2 MiB preview limit." )
            is_text = ext in TEXT_EXTENSIONS or (mime.startswith("text/") and ext not in {".html", ".htm", ".svg"})
            if mime == "application/pdf" or mime in SAFE_IMAGE_MIMES:
                try:
                    plain_path = get_plain_temp(doc)
                except (InvalidTag, ValueError, FileNotFoundError, OSError):
                    log_event(g.current_user["id"], "INTEGRITY_ERROR", "Unable to authenticate or read the encrypted file.", doc["id"], doc["title"])
                    flash("The file could not be authenticated. The encrypted copy may be damaged.", "error")
                    return redirect(url_for("dashboard"))
                log_event(g.current_user["id"], "FILE_VIEWED", "PIN verified; file opened in browser preview.", doc["id"], doc["title"])
                response = send_file(plain_path, mimetype=mime, as_attachment=False, download_name=doc["original_filename"], conditional=False)
                response.call_on_close(lambda p=plain_path: safe_unlink(p))
                response.headers["Cache-Control"] = "no-store, max-age=0"
                response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
                return response
            if is_text:
                try:
                    plain_path = get_plain_temp(doc)
                    with plain_path.open("rb") as handle:
                        raw_text = handle.read(PREVIEW_TEXT_LIMIT + 1)
                    if len(raw_text) > PREVIEW_TEXT_LIMIT:
                        raw_text = raw_text[:PREVIEW_TEXT_LIMIT]
                    text_preview = raw_text.decode("utf-8", errors="replace")
                except (InvalidTag, ValueError, FileNotFoundError, OSError):
                    log_event(g.current_user["id"], "INTEGRITY_ERROR", "Unable to authenticate or read the encrypted file.", doc["id"], doc["title"])
                    flash("The file could not be authenticated. The encrypted copy may be damaged.", "error")
                    return redirect(url_for("dashboard"))
                finally:
                    if "plain_path" in locals():
                        safe_unlink(plain_path)
                log_event(g.current_user["id"], "FILE_VIEWED", "PIN verified; text preview rendered safely as escaped text.", doc["id"], doc["title"])
                return render_template("text_preview.html", document=doc, text_preview=text_preview)
            log_event(g.current_user["id"], "FILE_VIEWED", "PIN verified; browser preview is not supported for this file type.", doc["id"], doc["title"])
            return render_template("view_unavailable.html", document=doc, reason="Your browser does not support a safe inline preview for this file type. Download it after PIN verification to open it in a suitable app.")

        # action == download
        try:
            plain_path = get_plain_temp(doc)
        except (InvalidTag, ValueError, FileNotFoundError, OSError):
            log_event(g.current_user["id"], "INTEGRITY_ERROR", "Unable to authenticate or read the encrypted file.", doc["id"], doc["title"])
            flash("The file could not be authenticated. The encrypted copy may be damaged.", "error")
            return redirect(url_for("dashboard"))
        log_event(g.current_user["id"], "FILE_DOWNLOADED", "PIN verified; decrypted download delivered.", doc["id"], doc["title"])
        response = send_file(plain_path, mimetype="application/octet-stream", as_attachment=True,
                             download_name=doc["original_filename"], conditional=False)
        response.call_on_close(lambda p=plain_path: safe_unlink(p))
        response.headers["Cache-Control"] = "no-store, max-age=0"
        return response

    @app.route("/history")
    @login_required
    def history():
        db = get_db()
        action_filter = request.args.get("action", "")
        allowed_actions = {
            "ACCOUNT_CREATED", "LOGIN", "LOGOUT", "UPLOAD_ENCRYPTED", "FILE_VIEWED",
            "FILE_DOWNLOADED", "FILE_DELETED", "PIN_FAILED", "INTEGRITY_ERROR",
        }
        if action_filter not in allowed_actions:
            action_filter = ""
        page = max(1, request.args.get("page", default=1, type=int) or 1)
        limit = 50
        if action_filter:
            events = db.execute(
                "SELECT * FROM activity_log WHERE user_id = ? AND action = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (g.current_user["id"], action_filter, limit, (page - 1) * limit),
            ).fetchall()
            count = db.execute("SELECT COUNT(*) FROM activity_log WHERE user_id = ? AND action = ?", (g.current_user["id"], action_filter)).fetchone()[0]
        else:
            events = db.execute(
                "SELECT * FROM activity_log WHERE user_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (g.current_user["id"], limit, (page - 1) * limit),
            ).fetchall()
            count = db.execute("SELECT COUNT(*) FROM activity_log WHERE user_id = ?", (g.current_user["id"],)).fetchone()[0]
        return render_template("history.html", events=events, selected_action=action_filter,
                               actions=sorted(allowed_actions), page=page,
                               total_pages=max(1, (count + limit - 1) // limit))

    @app.route("/security")
    @login_required
    def security():
        db = get_db()
        document_count = db.execute("SELECT COUNT(*) FROM documents WHERE user_id = ?", (g.current_user["id"],)).fetchone()[0]
        return render_template("security.html", document_count=document_count)

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "app": "Secure Document Locker"})

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message=getattr(error, "description", "The request could not be processed.")), 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="This page or document could not be found."), 404

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("error.html", code=413, message="The server rejected this upload because it exceeded a configured request-size limit."), 413

    @app.errorhandler(500)
    def internal_error(_error):
        return render_template("error.html", code=500, message="Something went wrong. Your encrypted files were not intentionally exposed."), 500

    app.jinja_env.filters["datetime_short"] = lambda value: (value or "").replace("T", " ").replace("+00:00", " UTC")[:19]
    app.jinja_env.filters["action_label"] = lambda value: {
        "ACCOUNT_CREATED": "Account created", "LOGIN": "Signed in", "LOGOUT": "Signed out",
        "UPLOAD_ENCRYPTED": "Uploaded & encrypted", "FILE_VIEWED": "Viewed file",
        "FILE_DOWNLOADED": "Downloaded file", "FILE_DELETED": "Deleted file",
        "PIN_FAILED": "PIN check failed", "INTEGRITY_ERROR": "Integrity check alert",
    }.get(value, value.replace("_", " ").title())
    app.jinja_env.filters["action_icon"] = lambda value: {
        "ACCOUNT_CREATED": "✦", "LOGIN": "↗", "LOGOUT": "↙", "UPLOAD_ENCRYPTED": "↑",
        "FILE_VIEWED": "◉", "FILE_DOWNLOADED": "↓", "FILE_DELETED": "×",
        "PIN_FAILED": "!", "INTEGRITY_ERROR": "盾",
    }.get(value, "•")
    return app


app = create_app()

if __name__ == "__main__":
    # Local development only. Use a production WSGI server and HTTPS for deployment.
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
