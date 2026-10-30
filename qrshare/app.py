"""
QRShare - secure, time-limited classroom file sharing via QR codes.

Stack (all free tiers):  Vercel (hosting)  +  Neon Postgres (database)
                         +  Cloudinary (private file storage)

Security highlights
  * No secrets in code - everything comes from environment variables.
  * Files are stored as *authenticated* (private) Cloudinary assets and handed out
    only through 60-second signed URLs, so a burned link cannot be re-used.
  * Browser uploads straight to Cloudinary with a server-signed request (Vercel
    rejects request bodies over 4.5 MB); the server then downloads the file and
    verifies its real content before it is ever shared.
  * Share tokens are 192-bit random values; only their SHA-256 hash is stored.
  * Single-use links are burned atomically in one SQL statement; the student
    download is a POST (never a GET) so link-preview crawlers cannot burn it.
  * Login throttling, CSRF protection, role-based admin, hardened cookies,
    CSP / security headers, and an access audit log.
"""

import hashlib
import io
import os
import secrets
import sqlite3
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import cloudinary
import cloudinary.api
import cloudinary.uploader
import cloudinary.utils
import qrcode
from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from PIL import Image
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IS_PROD = bool(os.environ.get("VERCEL")) or os.environ.get("QRSHARE_ENV") == "production"

# --------------------------------------------------------------------------
# Configuration (environment variables only - never hard-code secrets)
# --------------------------------------------------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    if IS_PROD:
        raise RuntimeError("SECRET_KEY environment variable is required in production.")
    SECRET_KEY = secrets.token_hex(32)  # local dev only: sessions reset on restart

DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))
if USE_PG:
    import psycopg
    from psycopg.rows import dict_row
elif IS_PROD:
    raise RuntimeError("DATABASE_URL (Neon Postgres) is required in production.")
SQLITE_PATH = os.environ.get("SQLITE_PATH", os.path.join(BASE_DIR, "local_dev.db"))

cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
    secure=True,
)

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "10"))  # Cloudinary free plan: 10 MB
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
REGISTRATION_CODE = os.environ.get("REGISTRATION_CODE", "")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

SESSION_MAX_AGE = timedelta(hours=8)
SIGNED_URL_TTL = 60          # seconds a Cloudinary download URL stays valid
MIN_PASSWORD_LEN = 10

app = Flask(__name__, static_folder="public/static", static_url_path="/static")  # on Vercel the CDN serves /public first
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,   # files never pass through Flask
    WTF_CSRF_TIME_LIMIT=None,
    SESSION_COOKIE_NAME="__Host-qrshare" if IS_PROD else "qrshare",
    SESSION_COOKIE_SECURE=IS_PROD,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    JSON_SORT_KEYS=False,
)
csrf = CSRFProtect(app)
confirm_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="qrshare-share-confirm")

DURATION_MAP = {"1": timedelta(hours=1), "2": timedelta(hours=2),
                "24": timedelta(hours=24), "never": None}

# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def now_iso():
    return iso(now_utc())


def parse_iso(value):
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def client_ip() -> str:
    return request.remote_addr or "0.0.0.0"   # ProxyFix has applied X-Forwarded-For


def ip_fingerprint() -> str:
    """Pseudonymous, salted source fingerprint (no raw IPs stored)."""
    return hashlib.sha256((SECRET_KEY + client_ip()).encode()).hexdigest()[:16]


def public_link(token: str) -> str:
    base = PUBLIC_BASE_URL or request.url_root.rstrip("/")
    return f"{base}/share/{token}"


def safe_back(default="/"):
    ref = request.referrer
    if ref:
        p = urlparse(ref)
        if p.netloc == request.host:
            return p.path + (f"?{p.query}" if p.query else "")
    return default


def make_qr_b64(link: str) -> str:
    img = qrcode.make(link, box_size=10, border=2,
                      error_correction=qrcode.constants.ERROR_CORRECT_M)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    import base64
    return base64.b64encode(buf.getvalue()).decode("ascii")


# --------------------------------------------------------------------------
# Database layer (Postgres on Vercel/Neon, SQLite for local development)
# --------------------------------------------------------------------------

class DB:
    def __init__(self):
        if USE_PG:
            # prepare_threshold=None: required for Neon's pooled (pgbouncer) endpoint
            self.conn = psycopg.connect(DATABASE_URL, row_factory=dict_row,
                                        prepare_threshold=None, connect_timeout=10)
        else:
            self.conn = sqlite3.connect(SQLITE_PATH)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")

    def execute(self, sql, params=()):
        if USE_PG:
            sql = sql.replace("?", "%s")
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def get_db() -> DB:
    if "db" not in g:
        g.db = DB()
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'instructor',
        created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS items (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('file','folder')),
        parent_id TEXT REFERENCES items(id) ON DELETE CASCADE,
        owner_id TEXT NOT NULL,
        size BIGINT NOT NULL DEFAULT 0,
        mime_type TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        deleted_at TEXT,
        is_starred INTEGER NOT NULL DEFAULT 0,
        file_path TEXT)""",
    """CREATE TABLE IF NOT EXISTS shares (
        id TEXT PRIMARY KEY,
        item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
        token_hash TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        uses_left INTEGER)""",
    """CREATE TABLE IF NOT EXISTS pending_uploads (
        id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL,
        parent_id TEXT NOT NULL,
        name TEXT NOT NULL,
        ext TEXT NOT NULL,
        public_id TEXT NOT NULL,
        duration TEXT NOT NULL,
        uses TEXT NOT NULL,
        created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS access_log (
        id TEXT PRIMARY KEY,
        ts TEXT NOT NULL,
        event TEXT NOT NULL,
        username TEXT,
        item_id TEXT,
        share_id TEXT,
        source TEXT,
        detail TEXT)""",
    """CREATE TABLE IF NOT EXISTS rate_limits (
        key TEXT NOT NULL,
        ts TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS idx_items_parent ON items(parent_id)",
    "CREATE INDEX IF NOT EXISTS idx_items_owner ON items(owner_id)",
    "CREATE INDEX IF NOT EXISTS idx_shares_item ON shares(item_id)",
    "CREATE INDEX IF NOT EXISTS idx_log_ts ON access_log(ts)",
    "CREATE INDEX IF NOT EXISTS idx_rate_key ON rate_limits(key, ts)",
]

_schema_ready = False


def ensure_schema():
    """Create tables once per server instance and bootstrap the admin account."""
    global _schema_ready
    if _schema_ready:
        return
    db = get_db()
    try:
        for stmt in SCHEMA:
            db.execute(stmt)
        db.commit()
    except Exception:          # another instance may be creating the tables at the same time
        db.conn.rollback()
    if ADMIN_USERNAME and ADMIN_PASSWORD:
        row = db.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
        if not row:
            db.execute(
                "INSERT INTO users (id, username, password, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
                (str(uuid.uuid4()), ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), now_iso()),
            )
            db.commit()
    _schema_ready = True


# --------------------------------------------------------------------------
# Rate limiting + audit log (stored in the database so it works across
# serverless instances - in-memory counters would not)
# --------------------------------------------------------------------------

def is_rate_limited(key: str, limit: int, window_s: int) -> bool:
    cutoff = iso(now_utc() - timedelta(seconds=window_s))
    row = get_db().execute("SELECT COUNT(*) AS n FROM rate_limits WHERE key = ? AND ts > ?",
                           (key, cutoff)).fetchone()
    return row["n"] >= limit


def rate_hit(key: str):
    db = get_db()
    db.execute("INSERT INTO rate_limits (key, ts) VALUES (?, ?)", (key, now_iso()))
    if secrets.randbelow(50) == 0:      # opportunistic cleanup
        db.execute("DELETE FROM rate_limits WHERE ts < ?", (iso(now_utc() - timedelta(days=1)),))
    db.commit()


def rate_clear(key: str):
    db = get_db()
    db.execute("DELETE FROM rate_limits WHERE key = ?", (key,))
    db.commit()


def log_event(event, username=None, item_id=None, share_id=None, detail=None):
    db = get_db()
    db.execute(
        "INSERT INTO access_log (id, ts, event, username, item_id, share_id, source, detail) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), now_iso(), event, username, item_id, share_id,
         ip_fingerprint(), (detail or "")[:200]),
    )
    db.commit()


# --------------------------------------------------------------------------
# Upload validation: whitelist + deep content verification
# --------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx",
                      "png", "jpg", "jpeg", "gif", "txt", "zip"}
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
OOXML_ROOT = {"docx": "word/", "xlsx": "xl/", "pptx": "ppt/"}
IMAGE_FORMAT = {"png": "PNG", "jpg": "JPEG", "jpeg": "JPEG", "gif": "GIF"}


def allowed_extension(filename: str):
    if "." not in filename:
        return None
    ext = filename.rsplit(".", 1)[1].lower()
    return ext if ext in ALLOWED_EXTENSIONS else None


def _check_zip(data: bytes, ext: str):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return False, "Corrupted or invalid ZIP structure."
    infos = zf.infolist()
    if len(infos) > 2000:
        return False, "Archive contains too many entries."
    total = sum(i.file_size for i in infos)
    if total > 100 * 1024 * 1024 or (len(data) and total / len(data) > 150):
        return False, "Archive expands suspiciously large (possible ZIP bomb)."
    names = [i.filename for i in infos]
    if any(n.startswith("/") or ".." in n.replace("\\", "/").split("/") for n in names):
        return False, "Archive contains unsafe file paths."
    if ext in OOXML_ROOT:
        if "[Content_Types].xml" not in names or not any(n.startswith(OOXML_ROOT[ext]) for n in names):
            return False, f"File is not a genuine .{ext} document."
        if any(n.lower().endswith("vbaproject.bin") for n in names):
            return False, "Documents containing macros are not allowed."
    return True, ""


def verify_file_content(ext: str, data: bytes):
    """Return (ok, reason). Inspects the real bytes, not the file name."""
    if not data:
        return False, "File is empty."
    head = data[:2048]
    if ext == "pdf":
        if b"%PDF-" not in head[:1024]:
            return False, "File content is not a PDF."
        lowered = data.lower()
        if b"/launch" in lowered or b"/javascript" in lowered or b"/js " in lowered:
            return False, "PDFs with embedded scripts or launch actions are not allowed."
        return True, ""
    if ext in IMAGE_FORMAT:
        try:
            with Image.open(io.BytesIO(data)) as im:
                if im.format != IMAGE_FORMAT[ext]:
                    return False, "Image format does not match its extension."
                im.verify()
        except Exception:
            return False, "File content is not a valid image."
        return True, ""
    if ext == "txt":
        if b"\x00" in data:
            return False, "Text file contains binary data."
        return True, ""
    if ext in ("zip", "docx", "xlsx", "pptx"):
        if not head.startswith(b"PK\x03\x04"):
            return False, f"File content is not a valid .{ext}."
        return _check_zip(data, ext)
    if ext in ("doc", "xls", "ppt"):
        if not head.startswith(OLE_MAGIC):
            return False, f"File content is not a valid legacy .{ext} document."
        return True, ""
    return False, "Unsupported file type."


# --------------------------------------------------------------------------
# Cloudinary helpers (private / authenticated storage, expiring signed URLs)
# --------------------------------------------------------------------------

def cloud_configured() -> bool:
    c = cloudinary.config()
    return bool(c.cloud_name and c.api_key and c.api_secret)


def signed_download_url(public_id: str, ext: str, ttl: int = SIGNED_URL_TTL) -> str:
    return cloudinary.utils.private_download_url(
        public_id, ext, resource_type="raw", type="authenticated",
        attachment=True, expires_at=int(time.time()) + ttl,
    )


def fetch_asset_bytes(public_id: str, ext: str, limit: int) -> bytes:
    req = Request(signed_download_url(public_id, ext, 90), headers={"User-Agent": "qrshare-verify"})
    with urlopen(req, timeout=25) as resp:
        return resp.read(limit + 1)


def purge_cloud_file(public_id):
    if not public_id:
        return
    try:
        cloudinary.uploader.destroy(public_id, resource_type="raw", type="authenticated", invalidate=True)
    except Exception:
        pass


# --------------------------------------------------------------------------
# Template helpers
# --------------------------------------------------------------------------

@app.template_filter("share_info")
def share_info_filter(item):
    keys = item.keys()
    share_id = item["share_id"] if "share_id" in keys else None
    if not share_id:
        return {"status": "none", "text": "Inactive"}
    uses_left = item["share_uses_left"] if "share_uses_left" in keys else None
    expires_at = item["share_expires_at"] if "share_expires_at" in keys else None
    if uses_left is not None and uses_left <= 0:
        return {"status": "burned", "text": "Burned"}
    time_str = "No expiry"
    if expires_at:
        try:
            exp = parse_iso(expires_at)
            diff = exp - now_utc()
            if diff.total_seconds() <= 0:
                return {"status": "expired", "text": "Expired"}
            hours = int(diff.total_seconds() // 3600)
            mins = int((diff.total_seconds() % 3600) // 60)
            time_str = f"{hours}h left" if hours > 0 else (f"{mins}m left" if mins > 0 else "<1m left")
        except ValueError:
            time_str = "Active"
    uses_str = "1 use" if uses_left == 1 else ("Unlimited" if uses_left is None else f"{uses_left} uses")
    return {"status": "active", "uses": uses_str, "time": time_str}


@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def inject_globals():
    return {"csp_nonce": g.get("csp_nonce", "")}


@app.after_request
def security_headers(resp):
    nonce = g.get("csp_nonce", "")
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "script-src-attr 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self'; "
        "connect-src 'self' https://api.cloudinary.com; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"     # share tokens live in URLs
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if IS_PROD:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if not request.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
    return resp


# --------------------------------------------------------------------------
# Authentication gate
# --------------------------------------------------------------------------

PUBLIC_ENDPOINTS = {"login", "register", "welcome", "share_item", "share_download",
                    "api_share_status", "static"}


@app.before_request
def gate():
    if request.endpoint == "static":
        return None
    ensure_schema()
    g.user = None
    username = session.get("user")
    if username:
        issued = session.get("iat", 0)
        if time.time() - issued > SESSION_MAX_AGE.total_seconds():
            session.clear()
        else:
            row = get_db().execute("SELECT username, role FROM users WHERE username = ?",
                                   (username,)).fetchone()
            if row:
                g.user = row
            else:
                session.clear()
    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        return None
    if g.user is None:
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Authentication required."}), 401
        return redirect("/welcome")
    return None


def current_username():
    return g.user["username"]


def require_admin():
    if g.user is None or g.user["role"] != "admin":
        abort(403)


# --------------------------------------------------------------------------
# Error handlers (no internal details leak to the browser)
# --------------------------------------------------------------------------

def _error_response(code, message):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": message}), code
    return (f"<!doctype html><meta charset='utf-8'><title>{code}</title>"
            f"<body style='font-family:sans-serif;padding:3rem;background:#0b1020;color:#e5e7eb'>"
            f"<h2>{code}</h2><p>{message}</p><p><a style='color:#818cf8' href='/'>Back to QRShare</a></p>"), code


@app.errorhandler(CSRFError)
def handle_csrf(_e):
    return _error_response(400, "Your session expired. Please refresh the page and try again.")


@app.errorhandler(400)
def handle_400(e):
    return _error_response(400, getattr(e, "description", "Bad request."))


@app.errorhandler(403)
def handle_403(_e):
    return _error_response(403, "You do not have permission to do that.")


@app.errorhandler(404)
def handle_404(_e):
    return _error_response(404, "Not found.")


@app.errorhandler(413)
def handle_413(_e):
    return _error_response(413, "Request too large.")


@app.errorhandler(500)
def handle_500(_e):
    return _error_response(500, "Something went wrong on our side.")


# --------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------

import re  # noqa: E402

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
DUMMY_HASH = generate_password_hash("qrshare-dummy-password")


@app.route("/welcome")
def welcome():
    if g.user:
        return redirect("/")
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_key, user_key = f"login:ip:{ip_fingerprint()}", f"login:user:{username.lower()}"
        if is_rate_limited(ip_key, 50, 900) or is_rate_limited(user_key, 5, 900):   # per-IP limit is generous: campuses share one IP
            log_event("login_blocked", username=username[:32])
            error = "Too many attempts. Please wait 15 minutes and try again."
            return render_template("login.html", error=error), 429
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        ok = check_password_hash(user["password"] if user else DUMMY_HASH, password)  # constant-ish time
        if user and ok:
            session.clear()                       # prevents session fixation
            session["user"] = user["username"]
            session["iat"] = int(time.time())
            rate_clear(user_key)
            log_event("login_ok", username=user["username"])
            return redirect("/")
        rate_hit(ip_key)
        rate_hit(user_key)
        log_event("login_fail", username=username[:32])
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    require_code = bool(REGISTRATION_CODE)
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        code = request.form.get("invite_code", "")
        reg_key = f"register:{ip_fingerprint()}"
        if is_rate_limited(reg_key, 20, 3600):
            return render_template("register.html", error="Too many attempts. Try again later.",
                                   require_code=require_code), 429
        rate_hit(reg_key)
        reserved = {"admin", "administrator", "root", "system", ADMIN_USERNAME.lower()}
        if not username or not password:
            error = "All fields are required"
        elif not USERNAME_RE.match(username):
            error = "Username must be 3-32 characters: letters, numbers, dot, dash or underscore"
        elif username.lower() in reserved:
            error = "That username is reserved"
        elif len(password) < MIN_PASSWORD_LEN or len(password) > 128:
            error = f"Password must be {MIN_PASSWORD_LEN}-128 characters"
        elif password.lower() == username.lower():
            error = "Password cannot be the same as your username"
        elif require_code and not secrets.compare_digest(code.encode(), REGISTRATION_CODE.encode()):
            error = "Invalid faculty invite code"
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (id, username, password, role, created_at) VALUES (?, ?, ?, 'instructor', ?)",
                    (str(uuid.uuid4()), username, generate_password_hash(password), now_iso()),
                )
                db.commit()
                log_event("register", username=username)
                return redirect("/login")
            except Exception:
                db.conn.rollback()
                error = "Username already exists"
    return render_template("register.html", error=error, require_code=require_code)


@app.route("/logout", methods=["POST"])
def logout():
    if g.user:
        log_event("logout", username=g.user["username"])
    session.clear()
    return redirect("/welcome")


# --------------------------------------------------------------------------
# Folder browsing
# --------------------------------------------------------------------------

SHARE_COLUMNS = """
    (SELECT s.id FROM shares s WHERE s.item_id = items.id ORDER BY s.created_at DESC LIMIT 1) AS share_id,
    (SELECT s.expires_at FROM shares s WHERE s.item_id = items.id ORDER BY s.created_at DESC LIMIT 1) AS share_expires_at,
    (SELECT s.uses_left FROM shares s WHERE s.item_id = items.id ORDER BY s.created_at DESC LIMIT 1) AS share_uses_left
"""


@app.route("/")
def root_redirect():
    username = current_username()
    db = get_db()
    row = db.execute(
        "SELECT id FROM items WHERE parent_id IS NULL AND type = 'folder' AND owner_id = ? "
        "AND deleted_at IS NULL LIMIT 1", (username,)).fetchone()
    if row:
        root_id = row["id"]
    else:
        root_id = str(uuid.uuid4())
        ts = now_iso()
        db.execute("INSERT INTO items (id, name, type, parent_id, owner_id, created_at, updated_at) "
                   "VALUES (?, 'My Files', 'folder', NULL, ?, ?, ?)", (root_id, username, ts, ts))
        db.commit()
    return redirect(f"/folder/{root_id}")


@app.route("/folder/<folder_id>")
def view_folder(folder_id):
    username = current_username()
    db = get_db()
    current_folder = db.execute(
        "SELECT * FROM items WHERE id = ? AND type = 'folder' AND owner_id = ?",
        (folder_id, username)).fetchone()
    if not current_folder:
        abort(403)

    sort_by = request.args.get("sort", "name")
    valid_sorts = {"name": "name", "size": "size", "type": "type", "date": "updated_at"}
    sort_col = valid_sorts.get(sort_by, "name")
    sort_ord = "DESC" if request.args.get("order", "ASC").upper() == "DESC" else "ASC"

    children = db.execute(
        f"SELECT items.*, {SHARE_COLUMNS} FROM items "
        f"WHERE parent_id = ? AND owner_id = ? AND deleted_at IS NULL "
        f"ORDER BY type DESC, {sort_col} {sort_ord}", (folder_id, username)).fetchall()

    breadcrumbs, curr = [], current_folder
    while curr and curr["parent_id"]:
        breadcrumbs.insert(0, {"id": curr["id"], "name": curr["name"]})
        curr = db.execute("SELECT * FROM items WHERE id = ? AND owner_id = ?",
                          (curr["parent_id"], username)).fetchone()
    if curr:
        breadcrumbs.insert(0, {"id": curr["id"], "name": curr["name"]})

    link = session.pop("ephemeral_link", None)          # Post/Redirect/Get: shown once
    qr_code = make_qr_b64(link) if link else None

    return render_template("room.html", current_folder=current_folder, children=children,
                           breadcrumbs=breadcrumbs, view_type="folder", current_sort=sort_by,
                           current_order=sort_ord, qr_code=qr_code, link=link)


@app.route("/virtual/<view_name>")
def view_virtual(view_name):
    username = current_username()
    db = get_db()
    if view_name == "recent":
        rows = db.execute(f"SELECT items.*, {SHARE_COLUMNS} FROM items WHERE owner_id = ? "
                          "AND deleted_at IS NULL ORDER BY updated_at DESC LIMIT 50", (username,))
    elif view_name == "starred":
        rows = db.execute(f"SELECT items.*, {SHARE_COLUMNS} FROM items WHERE owner_id = ? "
                          "AND is_starred = 1 AND deleted_at IS NULL ORDER BY name ASC", (username,))
    elif view_name == "trash":
        rows = db.execute("SELECT * FROM items WHERE owner_id = ? AND deleted_at IS NOT NULL "
                          "ORDER BY deleted_at DESC", (username,))
    else:
        abort(400, description="Invalid view")
    return render_template("room.html", children=rows.fetchall(), view_type=view_name,
                           breadcrumbs=[{"id": "", "name": view_name.capitalize()}],
                           current_folder={"id": ""}, current_sort="name", current_order="ASC",
                           qr_code=None, link=None)


@app.route("/item/create_folder", methods=["POST"])
def create_folder():
    username = current_username()
    parent_id = request.form.get("parent_id", "")
    name = "".join(ch for ch in request.form.get("name", "").strip() if ch.isprintable())[:100] or "New Folder"
    db = get_db()
    if not db.execute("SELECT id FROM items WHERE id = ? AND owner_id = ? AND type = 'folder'",
                      (parent_id, username)).fetchone():
        abort(403)
    ts = now_iso()
    db.execute("INSERT INTO items (id, name, type, parent_id, owner_id, created_at, updated_at) "
               "VALUES (?, ?, 'folder', ?, ?, ?, ?)", (str(uuid.uuid4()), name, parent_id, username, ts, ts))
    db.commit()
    log_event("folder_create", username=username, item_id=parent_id)
    return redirect(f"/folder/{parent_id}")


# --------------------------------------------------------------------------
# Share links
# --------------------------------------------------------------------------

def create_share(db, item_id: str, duration_key: str, uses_key: str) -> str:
    """Create a share row and return the PUBLIC link. Only the token hash is stored."""
    delta = DURATION_MAP.get(duration_key)
    expires_at = iso(now_utc() + delta) if delta else None
    uses_left = 1 if uses_key == "1" else None
    token = secrets.token_urlsafe(24)                     # 192 bits of entropy
    share_id = str(uuid.uuid4())
    db.execute("INSERT INTO shares (id, item_id, token_hash, created_at, expires_at, uses_left) "
               "VALUES (?, ?, ?, ?, ?, ?)",
               (share_id, item_id, hash_token(token), now_iso(), expires_at, uses_left))
    db.commit()
    return public_link(token), share_id


@app.route("/api/item/share/<file_id>", methods=["POST"])
def api_share_file(file_id):
    username = current_username()
    db = get_db()
    file_item = db.execute(
        "SELECT * FROM items WHERE id = ? AND type = 'file' AND owner_id = ? AND deleted_at IS NULL",
        (file_id, username)).fetchone()
    if not file_item:
        return jsonify({"success": False, "error": "File not found or unauthorized"}), 404
    if is_rate_limited(f"mkshare:{username}", 60, 3600):
        return jsonify({"success": False, "error": "Too many links created. Try again later."}), 429
    rate_hit(f"mkshare:{username}")
    duration = request.form.get("duration", "never")
    uses = request.form.get("uses", "1")
    link, share_id = create_share(db, file_id, duration if duration in DURATION_MAP else "never", uses)
    log_event("share_create", username=username, item_id=file_id, share_id=share_id)
    return jsonify({"success": True, "link": link, "qr_code": make_qr_b64(link),
                    "filename": file_item["name"]})


def lookup_share(token: str):
    """Return (share, item, state). state in: active | expired | burned | missing."""
    db = get_db()
    share = db.execute("SELECT * FROM shares WHERE token_hash = ?", (hash_token(token),)).fetchone()
    if not share:
        return None, None, "missing"
    item = db.execute("SELECT * FROM items WHERE id = ? AND deleted_at IS NULL AND type = 'file'",
                      (share["item_id"],)).fetchone()
    if not item or not item["file_path"]:
        return share, None, "missing"
    if share["uses_left"] is not None and share["uses_left"] <= 0:
        return share, item, "burned"
    if share["expires_at"] and parse_iso(share["expires_at"]) <= now_utc():
        return share, item, "expired"
    return share, item, "active"


@app.route("/share/<token>", methods=["GET"])
def share_item(token):
    """Landing page: shows details only. It never consumes a use (crawler safe)."""
    ip_key = f"share:{ip_fingerprint()}"
    if is_rate_limited(ip_key, 120, 60):
        return render_template("share.html", status="burned"), 429
    rate_hit(ip_key)
    share, item, state = lookup_share(token)
    if state == "missing":
        miss_key = f"sharemiss:{ip_fingerprint()}"
        rate_hit(miss_key)
        log_event("share_view_denied", detail="unknown token")
        return render_template("share.html", status="missing"), 404
    if state != "active":
        log_event("share_view_denied", share_id=share["id"], detail=state)
        return render_template("share.html", status=state), 410
    confirm = confirm_serializer.dumps(hash_token(token))
    log_event("share_view", item_id=item["id"], share_id=share["id"])
    return render_template("share.html", status="active", item=item, share=share,
                           download_link=url_for("share_download", token=token),
                           confirm_token=confirm)


@csrf.exempt   # public, cookie-less action; protected by a signed, expiring confirm token instead
@app.route("/share/<token>/download", methods=["POST"])
def share_download(token):
    """Burns a single-use token and redirects to a 60-second signed Cloudinary URL."""
    ip_key = f"share:{ip_fingerprint()}"
    if is_rate_limited(ip_key, 120, 60):
        abort(429)
    rate_hit(ip_key)
    try:
        confirmed = confirm_serializer.loads(request.form.get("confirm", ""), max_age=1800)
    except (BadSignature, SignatureExpired):
        return redirect(url_for("share_item", token=token))
    if not secrets.compare_digest(confirmed, hash_token(token)):
        return redirect(url_for("share_item", token=token))

    share, item, state = lookup_share(token)
    if state != "active":
        return redirect(url_for("share_item", token=token))

    # Build the (purely local) signed URL first, then burn atomically.
    ext = item["name"].rsplit(".", 1)[-1].lower() if "." in item["name"] else ""
    cloud_url = signed_download_url(item["file_path"], ext)

    db = get_db()
    now = now_iso()
    cur = db.execute(
        "UPDATE shares SET uses_left = CASE WHEN uses_left IS NULL THEN NULL ELSE uses_left - 1 END "
        "WHERE id = ? AND (uses_left IS NULL OR uses_left > 0) AND (expires_at IS NULL OR expires_at > ?)",
        (share["id"], now))
    db.commit()
    if cur.rowcount == 0:                      # lost the race, expired, or already burned
        log_event("share_download_denied", share_id=share["id"], detail="burned_or_expired")
        return redirect(url_for("share_item", token=token))
    log_event("share_download", item_id=item["id"], share_id=share["id"])
    return redirect(cloud_url, code=303)


@app.route("/api/share/status/<token>")
def api_share_status(token):
    ip_key = f"status:{ip_fingerprint()}"
    if is_rate_limited(ip_key, 120, 60):
        return jsonify({"active": False, "reason": "rate_limited"}), 429
    rate_hit(ip_key)
    share, _item, state = lookup_share(token)
    if state == "active":
        return jsonify({"active": True, "uses_left": share["uses_left"]})
    return jsonify({"active": False, "reason": state})


# --------------------------------------------------------------------------
# Upload: sign (server) -> upload directly to Cloudinary (browser) -> verify (server)
# --------------------------------------------------------------------------

@app.route("/api/upload/sign", methods=["POST"])
def api_upload_sign():
    username = current_username()
    data = request.get_json(silent=True) or {}
    if not cloud_configured():
        return jsonify({"success": False, "error": "Storage is not configured."}), 503
    parent_id = str(data.get("parent_id", ""))
    filename = secure_filename(str(data.get("filename", ""))) or "unnamed_file"
    try:
        size = int(data.get("size", 0))
    except (TypeError, ValueError):
        size = 0
    duration = str(data.get("duration", "never"))
    uses = str(data.get("uses", "1"))

    db = get_db()
    if not db.execute("SELECT id FROM items WHERE id = ? AND owner_id = ? AND type = 'folder'",
                      (parent_id, username)).fetchone():
        return jsonify({"success": False, "error": "Invalid target folder."}), 403
    ext = allowed_extension(filename)
    if ext is None:
        return jsonify({"success": False, "error": "File type not allowed."}), 400
    if size <= 0 or size > MAX_UPLOAD_BYTES:
        return jsonify({"success": False, "error": f"File must be between 1 byte and {MAX_UPLOAD_MB} MB."}), 400
    if duration not in DURATION_MAP:
        duration = "never"
    uses = "1" if uses == "1" else "unli"
    if is_rate_limited(f"upload:{username}", 30, 3600):
        return jsonify({"success": False, "error": "Upload limit reached. Try again later."}), 429
    rate_hit(f"upload:{username}")

    db.execute("DELETE FROM pending_uploads WHERE created_at < ?", (iso(now_utc() - timedelta(hours=1)),))
    upload_id = str(uuid.uuid4())
    public_id = f"qrshare_vault/{upload_id}/{filename}"
    db.execute("INSERT INTO pending_uploads (id, owner_id, parent_id, name, ext, public_id, duration, uses, created_at) "
               "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
               (upload_id, username, parent_id, filename, ext, public_id, duration, uses, now_iso()))
    db.commit()

    params = {"public_id": public_id, "timestamp": int(time.time()), "type": "authenticated"}
    signature = cloudinary.utils.api_sign_request(params, cloudinary.config().api_secret)
    cloud = cloudinary.config()
    return jsonify({
        "success": True,
        "upload_id": upload_id,
        "upload_url": f"https://api.cloudinary.com/v1_1/{cloud.cloud_name}/raw/upload",
        "fields": {**params, "api_key": cloud.api_key, "signature": signature},
    })


@app.route("/api/upload/finalize", methods=["POST"])
def api_upload_finalize():
    username = current_username()
    data = request.get_json(silent=True) or {}
    db = get_db()
    pend = db.execute("SELECT * FROM pending_uploads WHERE id = ? AND owner_id = ?",
                      (str(data.get("upload_id", "")), username)).fetchone()
    if not pend:
        return jsonify({"success": False, "error": "Upload session not found or expired."}), 404

    def reject(reason, status=400):
        purge_cloud_file(pend["public_id"])
        db.execute("DELETE FROM pending_uploads WHERE id = ?", (pend["id"],))
        db.commit()
        log_event("upload_rejected", username=username, detail=reason)
        return jsonify({"success": False, "error": reason}), status

    try:
        content = fetch_asset_bytes(pend["public_id"], pend["ext"], MAX_UPLOAD_BYTES)
    except Exception:
        return jsonify({"success": False, "error": "Could not read the uploaded file. Please try again."}), 502
    if len(content) > MAX_UPLOAD_BYTES:
        return reject(f"File exceeds the {MAX_UPLOAD_MB} MB limit.")
    ok, reason = verify_file_content(pend["ext"], content)
    if not ok:
        return reject(reason)

    ts = now_iso()
    file_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO items (id, name, type, parent_id, owner_id, size, mime_type, created_at, updated_at, file_path) "
        "VALUES (?, ?, 'file', ?, ?, ?, ?, ?, ?, ?)",
        (file_id, pend["name"], pend["parent_id"], username, len(content), pend["ext"], ts, ts, pend["public_id"]))
    db.execute("DELETE FROM pending_uploads WHERE id = ?", (pend["id"],))
    db.commit()
    link, share_id = create_share(db, file_id, pend["duration"], pend["uses"])
    log_event("upload_ok", username=username, item_id=file_id, share_id=share_id)
    session["ephemeral_link"] = link                    # shown once after the redirect (PRG)
    return jsonify({"success": True})


# --------------------------------------------------------------------------
# Owner downloads + live status APIs
# --------------------------------------------------------------------------

@app.route("/download/<file_id>")
def download_item(file_id):
    username = current_username()
    item = get_db().execute(
        "SELECT * FROM items WHERE id = ? AND type = 'file' AND owner_id = ? AND deleted_at IS NULL",
        (file_id, username)).fetchone()
    if not item or not item["file_path"]:
        abort(404)
    log_event("owner_download", username=username, item_id=file_id)
    ext = item["name"].rsplit(".", 1)[-1].lower() if "." in item["name"] else ""
    return redirect(signed_download_url(item["file_path"], ext), code=303)


@app.route("/api/item/exists/<file_id>")
def api_item_exists(file_id):
    row = get_db().execute(
        "SELECT id FROM items WHERE id = ? AND type = 'file' AND owner_id = ? AND deleted_at IS NULL",
        (file_id, current_username())).fetchone()
    return jsonify({"exists": row is not None})


@app.route("/api/folder/<folder_id>/contents")
def api_folder_contents(folder_id):
    rows = get_db().execute(
        "SELECT id, name, type, size, is_starred FROM items "
        "WHERE parent_id = ? AND owner_id = ? AND deleted_at IS NULL", (folder_id, current_username())).fetchall()
    return jsonify({"success": True, "items": [dict(r) for r in rows]})


# --------------------------------------------------------------------------
# Trash / restore / delete / star
# --------------------------------------------------------------------------

def _descendant_ids(db, root_id, owner_id):
    rows = db.execute(
        """WITH RECURSIVE subtree AS (
               SELECT id FROM items WHERE id = ? AND owner_id = ?
               UNION ALL
               SELECT i.id FROM items i JOIN subtree s ON i.parent_id = s.id WHERE i.owner_id = ?
           ) SELECT id FROM subtree""", (root_id, owner_id, owner_id)).fetchall()
    return [r["id"] for r in rows]


def _in_clause(ids):
    return ",".join("?" for _ in ids)


@app.route("/item/trash/<item_id>", methods=["POST"])
def move_to_trash(item_id):
    username, db = current_username(), get_db()
    ids = _descendant_ids(db, item_id, username)
    if ids:
        db.execute(f"UPDATE items SET deleted_at = ? WHERE id IN ({_in_clause(ids)}) AND owner_id = ?",
                   (now_iso(), *ids, username))
        db.commit()
        log_event("trash", username=username, item_id=item_id)
    return redirect(safe_back())


@app.route("/item/restore/<item_id>", methods=["POST"])
def restore_item(item_id):
    username, db = current_username(), get_db()
    ids = _descendant_ids(db, item_id, username)
    if ids:
        db.execute(f"UPDATE items SET deleted_at = NULL WHERE id IN ({_in_clause(ids)}) AND owner_id = ?",
                   (*ids, username))
        db.commit()
    return redirect("/virtual/trash")


@app.route("/item/delete_forever/<item_id>", methods=["POST"])
def delete_forever(item_id):
    username, db = current_username(), get_db()
    ids = _descendant_ids(db, item_id, username)
    if ids:
        marks = _in_clause(ids)
        for row in db.execute(f"SELECT file_path FROM items WHERE id IN ({marks}) AND owner_id = ? "
                              "AND type = 'file'", (*ids, username)).fetchall():
            purge_cloud_file(row["file_path"])
        db.execute(f"DELETE FROM items WHERE id IN ({marks}) AND owner_id = ?", (*ids, username))
        db.commit()
        log_event("delete_forever", username=username, item_id=item_id)
    return redirect("/virtual/trash")


@app.route("/item/star/<item_id>", methods=["POST"])
def toggle_star(item_id):
    db = get_db()
    db.execute("UPDATE items SET is_starred = 1 - is_starred WHERE id = ? AND owner_id = ?",
               (item_id, current_username()))
    db.commit()
    return redirect(safe_back())


# --------------------------------------------------------------------------
# Admin (role-based, not username-based)
# --------------------------------------------------------------------------

@app.route("/admin")
def admin_panel():
    require_admin()
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY username ASC").fetchall()
    files = db.execute("SELECT * FROM items WHERE type = 'file' ORDER BY created_at DESC").fetchall()
    total_bytes = db.execute("SELECT COALESCE(SUM(size), 0) AS total FROM items WHERE type = 'file'").fetchone()["total"]
    active_shares = db.execute(
        "SELECT COUNT(*) AS n FROM shares WHERE (uses_left IS NULL OR uses_left > 0) "
        "AND (expires_at IS NULL OR expires_at > ?)", (now_iso(),)).fetchone()["n"]
    logs = db.execute("SELECT * FROM access_log ORDER BY ts DESC LIMIT 100").fetchall()
    return render_template("admin.html", users=users, files=files, logs=logs,
                           total_storage_mb=round(total_bytes / (1024 * 1024), 2),
                           active_shares=active_shares)


@app.route("/admin/delete_user/<username>", methods=["POST"])
def admin_delete_user(username):
    require_admin()
    db = get_db()
    target = db.execute("SELECT role FROM users WHERE username = ?", (username,)).fetchone()
    if not target:
        abort(404)
    if target["role"] == "admin":
        abort(400, description="Administrator accounts cannot be deleted here.")
    for f in db.execute("SELECT file_path FROM items WHERE owner_id = ? AND type = 'file'", (username,)).fetchall():
        purge_cloud_file(f["file_path"])
    db.execute("DELETE FROM items WHERE owner_id = ?", (username,))
    db.execute("DELETE FROM users WHERE username = ?", (username,))
    db.commit()
    log_event("admin_delete_user", username=current_username(), detail=username)
    return redirect("/admin")


@app.route("/admin/delete_file/<file_id>", methods=["POST"])
def admin_delete_file(file_id):
    require_admin()
    db = get_db()
    row = db.execute("SELECT file_path FROM items WHERE id = ?", (file_id,)).fetchone()
    if row and row["file_path"]:
        purge_cloud_file(row["file_path"])
    db.execute("DELETE FROM items WHERE id = ?", (file_id,))
    db.commit()
    log_event("admin_delete_file", username=current_username(), item_id=file_id)
    return redirect("/admin")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
