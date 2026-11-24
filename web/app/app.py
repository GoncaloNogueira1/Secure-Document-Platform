import base64
import functools
import io
import pathlib
import json
import os
import logging
import secrets
from datetime import timedelta
import time
import uuid
import urllib.request
import urllib.error
from flask import app
import psycopg2
import flask
import dotenv
import pyotp
import qrcode
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from qrcode.constants import ERROR_CORRECT_M
from werkzeug.middleware.proxy_fix import ProxyFix
from . import db
from . import utils
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect, CSRFError

dotenv.load_dotenv()

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent


def _required_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}

POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "docdb")
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "10"))

# App DB users (defined in db/db_roles.sh)
APP_USER = os.getenv("APP_USER", "app_user")
APP_USER_PASSWORD = _required_env("APP_USER_PASSWORD")
APP_ADMIN = os.getenv("APP_ADMIN", "app_admin")
APP_ADMIN_PASSWORD = _required_env("APP_ADMIN_PASSWORD")
SECRET_KEY = _required_env("SECRET_KEY")

UPLOAD_FOLDER = "uploads"
DOC_VOLUME_ROOT = pathlib.Path(os.getenv("DOC_VOLUME_ROOT", "/data"))
STAGING_DIR = DOC_VOLUME_ROOT / "staging"
STORAGE_DIR = DOC_VOLUME_ROOT / "storage"
ANALYZER_URL = os.getenv("DOCUMENT_ANALYZER_URL", "http://document-analyzer:9000/analyze")
TOTP_ISSUER = os.getenv("TOTP_ISSUER", "SS_PROJ")
csrf = CSRFProtect()

def rate_limit_key():
    user_id = flask.session.get("user_id")
    if user_id:
        return f"user:{user_id}"
    return f"ip:{get_remote_address()}"


def make_qr_for_two_factor_setup(secret: str, username: str, issuer: str) -> str:
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    qr = qrcode.QRCode(
        version=1, error_correction=ERROR_CORRECT_M, box_size=8, border=2
    )
    qr.add_data(uri)
    qr.make(fit=True)
    buf = io.BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def two_factor_code_is_valid(secret: str, token: str) -> bool:
    digits = "".join(c for c in str(token or "") if c.isdigit())
    if len(digits) != 6:
        return False
    return bool(pyotp.TOTP(secret).verify(digits, valid_window=2))


def get_db(is_admin=False):
    """Get a new DB connection using the appropriate role (admin or user).
    
    Args:
        is_admin (bool): If True, connect as app_admin; otherwise as app_user.
        
    Returns:
        psycopg2 connection object.
    """
    user = APP_ADMIN if is_admin else APP_USER
    password = APP_ADMIN_PASSWORD if is_admin else APP_USER_PASSWORD
    
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=user,
        password=password,
    )

def create_app():
    app = flask.Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.secret_key = SECRET_KEY
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    app.config["PREFERRED_URL_SCHEME"] = "https"
    app.config["PREFERRED_URL_SCHEME"] = "https"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = _env_bool("SESSION_COOKIE_SECURE", False)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    csrf.init_app(app)

    # Initialize rate limiter
    limiter = Limiter(
        app=app,
        key_func=rate_limit_key,
        default_limits=["200 per day", "50 per hour"],
    )

    register_routes(app, limiter)

    return app

def get_documents_for_user(cur, owner_id):
    cur.execute(
        """
        SELECT id, title, filename, metadata, uploaded_at
        FROM documents
        WHERE owner_id = %s
        ORDER BY uploaded_at DESC
        """,
        (owner_id,),
    )
    return cur.fetchall()


def get_shared_documents_for_user(cur, user_id):
    query = """
        SELECT d.id, d.title, d.filename, d.metadata, d.uploaded_at, u.username
        FROM documents d
        INNER JOIN document_shares ds ON d.id = ds.document_id
        INNER JOIN users u ON d.owner_id = u.id
        WHERE ds.shared_with = %s
        ORDER BY d.uploaded_at DESC
    """
    cur.execute(query, (user_id,))
    return cur.fetchall()

def extract_metadata(filename):
    path = pathlib.Path(filename)
    try:
        stat_result = path.stat()
        return json.dumps(
            {
                "size": stat_result.st_size,
                "size_bytes": stat_result.st_size,
                "mode": stat_result.st_mode,
                "owner": stat_result.st_uid,
                "mtime": int(stat_result.st_mtime),
            }
        )
    except FileNotFoundError:
        return json.dumps({"error": "file not found"})
    except OSError as e:
        return json.dumps({"error": str(e)})


def call_document_analyzer(path: str) -> tuple[bool, dict]:
    payload = json.dumps({"path": path}).encode("utf-8")
    request_id = utils.get_request_id()
    req = urllib.request.Request(
        ANALYZER_URL, data=payload, headers={"Content-Type": "application/json", "X-Request-ID": request_id}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return bool(data.get("ok")), data
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
            return False, json.loads(body)
        except Exception:
            return False, {"ok": False, "reason": "analyzer_http_error", "status": e.code}
    except Exception as e:
        return False, {"ok": False, "reason": "analyzer_unreachable", "error": str(e)}


def _original_filename_from_metadata(metadata: object) -> str | None:
    """Best-effort extraction for legacy + JSON metadata values."""
    if not metadata:
        return None
    if not isinstance(metadata, str):
        return None
    try:
        obj = json.loads(metadata)
    except Exception:
        return None
    if isinstance(obj, dict) and obj.get("original_filename"):
        return str(obj["original_filename"])
    return None

def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in flask.session:

            utils.log_auth_unauthorized_access(
                reason="authentication_required"
            )

            flask.flash("Please log in first.", "error")
            return flask.redirect(flask.url_for("login"))
        return fn(*args, **kwargs)

    return wrapper

def is_admin(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        user_id = flask.session.get("user_id")
        if not user_id or not flask.session.get("is_admin"):
            utils.log_admin_access_denied(
                reason="admin_role_required"
            )
            return "Unauthorized", 403

        # Re-check current privilege/disabled state in DB to prevent stale-session admin access.
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT is_admin, is_disabled FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row or not row[0]:
            
            utils.log_admin_access_denied(
                reason="stale_admin_session"
            )
            
            flask.session.clear()
            return "Unauthorized", 403

        if row[1]:

            utils.log_admin_access_denied(
                reason="disabled_admin_account"
            )
            
            flask.session.clear()
            return "Your account is disabled. Please contact an administrator.", 403

        return fn(*args, **kwargs)

    return wrapper

def register_routes(app, limiter):

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if flask.request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.before_request
    def expire_session_if_needed():
        until = flask.session.get("two_factor_pending_until")
        if until and int(time.time()) > int(until):
            flask.session.pop("two_factor_pending_user_id", None)
            flask.session.pop("two_factor_pending_until", None)

        expires_at = flask.session.get("session_expires_at")
        if not expires_at:
            return

        if flask.request.endpoint in {
            "login",
            "register",
            "logout",
            "static",
            "two_factor_login",
        }:
            if int(time.time()) > expires_at:
                flask.session.clear()
            return

        if int(time.time()) > expires_at:
            expired_user_id = flask.session.get("user_id")
            expired_username = flask.session.get("username")

            utils.log_auth_session_expired(
                user_id=expired_user_id,
                username=expired_username,
                reason="session_timeout",
            )

            flask.session.clear()

            flask.flash("Your session has expired. Please log in again.", "error")
            return flask.redirect(flask.url_for("login"))

    @app.errorhandler(429)
    def ratelimit_handler(e):
        retry_after = getattr(e, "retry_after", None)

        try:
            retry_after = int(retry_after) if retry_after is not None else 60
        except Exception:
            retry_after = 60

        rate_limit = getattr(e, "description", None) or str(e)

        try:
            limit_key = rate_limit_key()
        except Exception:
            limit_key = "unknown"

        utils.log_security_rate_limit_exceeded(
            rate_limit=rate_limit,
            retry_after_seconds=retry_after,
            limit_key=limit_key,
        )

        response = flask.make_response(
            flask.render_template(
                "error.html",
                status_code=429,
                title="Too Many Requests",
                message="You've made too many requests. Please wait before trying again.",
                retry_after=retry_after,
            ),
            429,
        )

        response.headers["Retry-After"] = str(retry_after)
        return response

    @app.errorhandler(CSRFError)
    def csrf_error_handler(e):
        csrf_description = getattr(e, "description", None) or str(e)

        utils.log_security_csrf_failed(
            csrf_description=csrf_description,
            reason="csrf_token_invalid",
        )

        return flask.render_template(
            "error.html",
            status_code=400,
            title="Invalid CSRF Token",
            message="Your form session expired or is invalid. Please try again.",
        ), 400

    @app.route("/")
    def index():
        if flask.session.get("user_id"):
            if flask.session.get("is_admin"):
                return flask.redirect(flask.url_for("admin_users"))
            return flask.redirect(flask.url_for("documents_page"))
        return flask.redirect(flask.url_for("login"))



    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per hour")
    def register():
        if flask.request.method != "POST":
            return flask.render_template("register.html")

        username_raw = flask.request.form.get("username", "")
        password = flask.request.form.get("password", "")

        username = utils.sanitize_input(
            username_raw,
            allowed_chars="A-Za-z0-9._-",
            max_length=32,
        )

        if not username or not password:
            utils.log_admin_register_account(
                target_username=username or None,
                target_previous_status=None,
                target_new_status=None,
                status=302,
                outcome="denied",
                reason="missing_credentials",
                severity="medium",
            )

            flask.flash("Username and password are required.", "error")
            return flask.redirect(flask.url_for("register"))

        if not utils.validate_username(username):
            utils.log_admin_register_account(
                target_username=username or username_raw,
                target_previous_status=None,
                target_new_status=None,
                status=302,
                outcome="denied",
                reason="invalid_username",
                severity="medium",
            )

            flask.flash(
                "Invalid username. Use letters, numbers, dot, underscore or hyphen (3-32 chars).",
                "error",
            )
            return flask.redirect(flask.url_for("register"))

        if not utils.validate_password(password):
            utils.log_admin_register_account(
                target_username=username,
                target_previous_status=None,
                target_new_status=None,
                status=302,
                outcome="denied",
                reason="invalid_password_policy",
                severity="medium",
            )

            flask.flash("Password does not meet policy (min length 8, printable characters).", "error")
            return flask.redirect(flask.url_for("register"))

        conn = None
        cur = None
        created_user_id = None

        try:
            conn = get_db()
            cur = conn.cursor()

            existing_user = db.get_user_by_username(cur, username)

            if existing_user:
                utils.log_admin_register_account(
                    target_user_id=existing_user[0],
                    target_username=username,
                    target_previous_status="existing",
                    target_new_status="existing",
                    status=302,
                    outcome="denied",
                    reason="username_taken",
                    severity="medium",
                )

                cur.close()
                conn.close()

                flask.flash("Username already taken.", "error")
                return flask.redirect(flask.url_for("register"))

            totp_secret = pyotp.random_base32()

            db.create_user_with_totp(cur, username, password, totp_secret)

            cur.execute(
                """
                SELECT id
                FROM users
                WHERE username = %s
                """,
                (username,),
            )
            created_user = cur.fetchone()

            if created_user:
                created_user_id = created_user[0]

            conn.commit()

            cur.close()
            conn.close()

        except psycopg2.IntegrityError:
            if conn:
                conn.rollback()

            if cur:
                cur.close()
            if conn:
                conn.close()

            utils.log_admin_register_account(
                target_username=username,
                target_previous_status=None,
                target_new_status=None,
                status=302,
                outcome="denied",
                reason="username_taken",
                severity="medium",
            )

            flask.flash("Username already taken.", "error")
            return flask.redirect(flask.url_for("register"))

        except psycopg2.Error:
            if conn:
                conn.rollback()

            if cur:
                cur.close()
            if conn:
                conn.close()

            utils.log_admin_register_account(
                target_username=username,
                target_previous_status=None,
                target_new_status=None,
                status=500,
                outcome="failed",
                reason="database_insert_failed",
                severity="error",
            )

            flask.flash("Registration failed. Please try again.", "error")
            return flask.redirect(flask.url_for("register"))

        except Exception:
            if conn:
                conn.rollback()

            if cur:
                cur.close()
            if conn:
                conn.close()

            utils.log_admin_register_account(
                target_username=username,
                target_previous_status=None,
                target_new_status=None,
                status=500,
                outcome="failed",
                reason="unexpected_exception",
                severity="error",
            )

            flask.flash("Registration failed unexpectedly. Please try again.", "error")
            return flask.redirect(flask.url_for("register"))

        try:
            qr_data_url = make_qr_for_two_factor_setup(
                totp_secret,
                username,
                TOTP_ISSUER,
            )

        except Exception:
            utils.log_admin_register_account(
                target_user_id=created_user_id,
                target_username=username,
                target_previous_status=None,
                target_new_status="created_pending_2fa",
                status=500,
                outcome="failed",
                reason="two_factor_qr_generation_failed",
                severity="error",
            )

            flask.flash("Account created, but 2FA setup failed. Please contact an administrator.", "error")
            return flask.redirect(flask.url_for("login"))

        utils.log_admin_register_account(
            target_user_id=created_user_id,
            target_username=username,
            target_previous_status=None,
            target_new_status="created_pending_2fa",
            status=200,
            outcome="success",
            reason="",
            severity="info",
        )

        return flask.render_template(
            "register_2fa.html",
            qr_data_url=qr_data_url,
            username=username,
        )

    @app.route("/login", methods=["GET", "POST"])
    @csrf.exempt
    @limiter.limit("10 per 2 minutes")
    def login():

        if flask.request.method == "POST":
            username_raw = flask.request.form.get("username", "")
            password = flask.request.form.get("password", "")

            # sanitize username;
            username = utils.sanitize_input(username_raw, allowed_chars="A-Za-z0-9._-", max_length=32)

            conn = get_db()
            cur = conn.cursor()

            user = db.get_user_by_username(cur, username)

            cur.close()
            conn.close()

            password_matches = False
            if user and not user[3]:
                stored_password = user[2] or ""
                if stored_password.startswith("$argon2"):
                    password_matches = db.verify_password(stored_password, password)
                else:
                    password_matches = stored_password == password

            if user and password_matches and not user[3]:
                if user[6] and user[5]:
                    flask.session.clear()
                    flask.session["two_factor_pending_user_id"] = user[0]
                    flask.session["two_factor_pending_until"] = int(time.time()) + 300
                    return flask.redirect(flask.url_for("two_factor_login"))

                flask.session.clear()
                flask.session.permanent = True
                flask.session["user_id"] = user[0]
                flask.session["username"] = user[1]
                flask.session["is_admin"] = bool(user[4])
                flask.session["session_expires_at"] = int(time.time()) + (
                    SESSION_TIMEOUT_MINUTES * 60
                )

                # Log successful login
                utils.log_auth_login_success(user[0], user[1], flask.session.get("session_token"))

                if flask.session["is_admin"]:
                    return flask.redirect(flask.url_for("admin_users"))
                return flask.redirect(flask.url_for("documents_page"))

            # Log failed login
            reason = "account_disabled" if user and user[3] else "invalid_credentials"
            utils.log_auth_login_failed(username, reason)
            flask.flash("Invalid credentials.", "error")

        return flask.render_template("login.html")

    @app.route("/login/2fa", methods=["GET", "POST"])
    @limiter.limit("20 per 2 minutes")
    def two_factor_login():
        user_id_after_password = flask.session.get("two_factor_pending_user_id")
        deadline_unix = flask.session.get("two_factor_pending_until")
        if not user_id_after_password or not deadline_unix:
            flask.flash("Please sign in first.", "error")
            utils.log_auth_login_failed(username, reason= "Not signed in first.")
            return flask.redirect(flask.url_for("login"))
        if int(time.time()) > int(deadline_unix):
            flask.session.pop("two_factor_pending_user_id", None)
            flask.session.pop("two_factor_pending_until", None)
            flask.flash("Login step expired. Please sign in again.", "error")
            utils.log_auth_login_failed(username, reason= "Login step expired.")
            return flask.redirect(flask.url_for("login"))

        if flask.request.method == "POST":
            otp_raw = flask.request.form.get("otp", "")
            otp = utils.sanitize_input(otp_raw, allowed_chars=r"0-9", max_length=12)

            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT username, is_admin, is_disabled, two_factor_secret,
                    COALESCE(two_factor_enabled, FALSE)
                FROM users WHERE id = %s
                """,
                (user_id_after_password,),
            )
            row = cur.fetchone()
            cur.close()
            conn.close()

            if not row or row[2]:
                flask.session.pop("two_factor_pending_user_id", None)
                flask.session.pop("two_factor_pending_until", None)
                flask.flash("Account unavailable. Please sign in again.", "error")
                utils.log_auth_login_failed(username, reason= "Account unavailable.")
                return flask.redirect(flask.url_for("login"))

            secret = row[3]
            if not secret or not row[4]:
                flask.session.pop("two_factor_pending_user_id", None)
                flask.session.pop("two_factor_pending_until", None)
                flask.flash("Two-factor is not active for this account.", "error")
                utils.log_auth_login_failed(username, reason= "Two-factor is not active for this account.")
                return flask.redirect(flask.url_for("login"))

            if not two_factor_code_is_valid(secret, otp):
                flask.flash("Wrong code.", "error")
                utils.log_auth_login_failed(username, reason= "Wrong Two Factor Authentication Code.")
                return flask.render_template("two_factor_login.html")

            username, is_admin = row[0], bool(row[1])
            flask.session.clear()
            flask.session.permanent = True
            flask.session["user_id"] = user_id_after_password
            flask.session["username"] = username
            flask.session["is_admin"] = is_admin
            flask.session["session_expires_at"] = int(time.time()) + (
                SESSION_TIMEOUT_MINUTES * 60
            )
            flask.session.pop("two_factor_pending_user_id", None)
            flask.session.pop("two_factor_pending_until", None)
            if is_admin:
                utils.log_auth_login_success(user_id_after_password, username, flask.session.get("session_token"))
                return flask.redirect(flask.url_for("admin_users"))
            utils.log_auth_login_success(user_id_after_password, username, flask.session.get("session_token"))
            return flask.redirect(flask.url_for("documents_page"))

        return flask.render_template("two_factor_login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        user_id = flask.session.get("user_id")
        username = flask.session.get("username")
        if user_id:
            utils.log_auth_logout(user_id, username)
        flask.session.clear()
        return flask.redirect(flask.url_for("login"))

    @app.route("/documents/<int:document_id>")
    @login_required
    def document_details(document_id):
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT id, owner_id, title, filename, metadata
            FROM documents
            WHERE id = %s
            AND (
                owner_id = %s OR
                id IN (
                    SELECT document_id FROM document_shares WHERE shared_with = %s
                )
            )
        """, (document_id, flask.session.get("user_id"), flask.session.get("user_id")))

        
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return flask.render_template(
                "error.html",
                status_code=404,
                title="Document Not Found",
                message="The document you're looking for doesn't exist or you don't have access to it."
            ), 404

        document = {
            "id": row[0],
            "owner_id": row[1],
            "title": row[2],
            "filename": row[3],
            "metadata": row[4],
        }

        return flask.render_template("document_details.html", document=document)

    @app.route("/documents")
    @login_required
    def documents_page():
        if flask.session.get("is_admin"):
            return flask.redirect(flask.url_for("admin_users"))
        
    
        current_user_id = flask.session.get("user_id")

        owner_id = current_user_id

        conn = get_db()
        cur = conn.cursor()

        docs = get_documents_for_user(cur, owner_id)
        shared_documents = get_shared_documents_for_user(cur, current_user_id)
        
        cur.close()
        conn.close()

        documents = [
            {
                "id": d[0],
                "title": d[1],
                "filename": d[2],
                "original_filename": _original_filename_from_metadata(d[3]),
                "uploaded_at": d[4],
            }
            for d in docs
        ]

        shared_documents_data = [
            {
                "id": row[0],
                "title": row[1],
                "filename": row[2],
                "original_filename": _original_filename_from_metadata(row[3]),
                "uploaded_at": row[4],
                "owner_username": row[5],
            }
            for row in shared_documents
        ]

        
        return flask.render_template(
            "documents.html",
            documents=documents,
            shared_documents=shared_documents_data,
            requested_user_id=owner_id,
            current_user_id=current_user_id,
            username=flask.session.get("username"),
        )

    @app.route("/documents/<int:document_id>/download")
    @login_required
    @limiter.limit("30 per 1 hour", key_func=rate_limit_key)
    def download_document(document_id):
        current_user_id = flask.session.get("user_id")

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT documents.owner_id, documents.filename, documents.metadata
            FROM documents
            LEFT JOIN document_shares
                ON documents.id = document_shares.document_id
            WHERE documents.id = %s
            AND (
                documents.owner_id = %s
                OR document_shares.shared_with = %s
            )
            """,
            (document_id, current_user_id, current_user_id),
        )
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            utils.log_file_download_failed(
                document_id=document_id,
                status=404,
                reason="document_not_found_or_access_denied",
                access_type="unknown",
            )
            return "Document not found or access denied", 404

        owner_id, stored_filename, metadata_raw = row
        access_type = "owner" if owner_id == current_user_id else "shared"

        if not stored_filename:
            utils.log_file_download_failed(
                document_id=document_id,
                document_owner_id=owner_id,
                status=404,
                reason="filename_missing",
                access_type=access_type,
            )
            return "File not found", 404

        safe_name = pathlib.Path(stored_filename).name
        if safe_name != stored_filename:
            utils.log_file_download_failed(
                document_id=document_id,
                document_owner_id=owner_id,
                original_filename=stored_filename,
                status=400,
                reason="invalid_filename",
                access_type=access_type,
            )
            return "Invalid filename", 400

        storage_root = STORAGE_DIR.resolve()
        file_path = (storage_root / safe_name).resolve()

        try:
            file_path.relative_to(storage_root)
        except ValueError:
            utils.log_file_download_failed(
                document_id=document_id,
                document_owner_id=owner_id,
                original_filename=stored_filename,
                file_path=file_path,
                status=400,
                reason="invalid_file_path",
                access_type=access_type,
            )
            return "Invalid file path", 400

        if not file_path.exists():
            utils.log_file_download_failed(
                document_id=document_id,
                document_owner_id=owner_id,
                original_filename=stored_filename,
                file_path=file_path,
                status=404,
                reason="file_not_found_on_server",
                access_type=access_type,
            )
            return "File not found on server", 404

        metadata = {}
        if metadata_raw:
            try:
                metadata = json.loads(metadata_raw)
            except Exception:
                metadata = {}

        original_filename = metadata.get("original_filename") if isinstance(metadata, dict) else None
        download_name = original_filename or stored_filename

        try:
            utils.log_file_download_success(
                document_id=document_id,
                document_owner_id=owner_id,
                original_filename=download_name,
                file_path=file_path,
                access_type=access_type,
            )

            return flask.send_file(
                file_path,
                as_attachment=True,
                download_name=download_name,
            )

        except OSError:
            utils.log_file_download_failed(
                document_id=document_id,
                document_owner_id=owner_id,
                original_filename=download_name,
                file_path=file_path,
                status=500,
                reason="storage_read_failed",
                access_type=access_type,
            )
            return "File could not be read", 500

    @app.route("/documents/upload", methods=["POST"])
    @login_required
    @limiter.limit("10 per 1 hour", key_func=rate_limit_key)
    def upload_document():
        user_id = flask.session.get("user_id")

        title_raw = flask.request.form.get("title", "Untitled")
        title = utils.sanitize_input(
            title_raw,
            allowed_chars=r"A-Za-z0-9 \._\-,",
            max_length=200,
        ) or "Untitled"

        uploaded_file = flask.request.files.get("document")

        if not uploaded_file or uploaded_file.filename == "":
            utils.log_file_upload_failed(
                status=400,
                reason="missing_file",
                title=title,
                severity="medium",
                outcome="denied",
            )
            flask.flash("Please choose a file.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        original_filename = uploaded_file.filename or "document.pdf"
        filename = utils.sanitize_filename(original_filename)

        if not filename.lower().endswith(".pdf"):
            utils.log_file_upload_failed(
                status=400,
                reason="invalid_file_extension",
                title=title,
                original_filename=original_filename,
                severity="medium",
                outcome="denied",
            )
            flask.flash("Only PDF files are allowed.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        file_signature = uploaded_file.stream.read(5)
        uploaded_file.stream.seek(0)

        if file_signature != b"%PDF-":
            utils.log_file_upload_failed(
                status=400,
                reason="invalid_pdf_signature",
                title=title,
                original_filename=original_filename,
                severity="high",
                outcome="denied",
            )
            flask.flash("Only valid PDF files are allowed.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        STAGING_DIR.mkdir(parents=True, exist_ok=True)
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)

        staging_name = f"{uuid.uuid4().hex}.pdf"
        staging_path = (STAGING_DIR / staging_name).resolve()

        try:
            uploaded_file.save(staging_path)
        except Exception:
            utils.log_file_upload_failed(
                status=500,
                reason="staging_write_failed",
                title=title,
                original_filename=original_filename,
                file_path=staging_path,
                severity="error",
                outcome="failed",
            )
            flask.flash("Upload failed while saving temporary file.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        ok, analysis = call_document_analyzer(str(staging_path))

        if not ok:
            try:
                staging_path.unlink(missing_ok=True)
            except Exception:
                pass

            analyzer_reason = analysis.get("reason") if isinstance(analysis, dict) else None

            utils.log_file_upload_failed(
                status=400,
                reason=analyzer_reason or "document_analyzer_rejected",
                title=title,
                original_filename=original_filename,
                file_path=staging_path,
                analysis=analysis,
                severity="high",
                outcome="denied",
            )

            flask.flash(f"Upload rejected by analyzer ({analyzer_reason or 'unknown'}).", "error")
            return flask.redirect(flask.url_for("documents_page"))

        sha256 = (analysis.get("sha256") or "").strip() if isinstance(analysis, dict) else ""

        if not sha256:
            try:
                staging_path.unlink(missing_ok=True)
            except Exception:
                pass

            utils.log_file_upload_failed(
                status=400,
                reason="analyzer_missing_sha256",
                title=title,
                original_filename=original_filename,
                file_path=staging_path,
                analysis=analysis,
                severity="error",
                outcome="failed",
            )

            flask.flash("Upload rejected by analyzer (missing sha256).", "error")
            return flask.redirect(flask.url_for("documents_page"))

        final_name = f"{sha256}.pdf"
        final_path = (STORAGE_DIR / final_name).resolve()

        try:
            final_path.relative_to(STORAGE_DIR.resolve())
        except ValueError:
            try:
                staging_path.unlink(missing_ok=True)
            except Exception:
                pass

            utils.log_file_upload_failed(
                status=400,
                reason="invalid_storage_path",
                title=title,
                original_filename=original_filename,
                stored_filename=final_name,
                file_path=final_path,
                analysis=analysis,
                severity="error",
                outcome="failed",
            )

            flask.flash("Upload failed because the storage path is invalid.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        try:
            staging_path.replace(final_path)
        except Exception:
            try:
                staging_path.unlink(missing_ok=True)
            except Exception:
                pass

            utils.log_file_upload_failed(
                status=500,
                reason="storage_finalize_failed",
                title=title,
                original_filename=original_filename,
                stored_filename=final_name,
                file_path=final_path,
                analysis=analysis,
                severity="error",
                outcome="failed",
            )

            flask.flash("Upload failed while finalizing storage.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        metadata = {
            "original_filename": original_filename,
            "stored_filename": final_name,
            **(analysis if isinstance(analysis, dict) else {}),
        }

        conn = None
        cur = None

        try:
            conn = get_db()
            cur = conn.cursor()

            time_of_upload = time.strftime("%Y-%m-%d %H:%M:%S")

            cur.execute(
                """
                INSERT INTO documents (owner_id, title, filename, metadata, uploaded_at)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (user_id, title, final_name, json.dumps(metadata), time_of_upload),
            )

            document_id = cur.fetchone()[0]
            conn.commit()

            cur.close()
            conn.close()

            utils.log_file_upload_success(
                document_id=document_id,
                document_owner_id=user_id,
                title=title,
                original_filename=original_filename,
                stored_filename=final_name,
                file_path=final_path,
                analysis=analysis,
            )

            return flask.redirect(flask.url_for("documents_page", uploaded=title))

        except psycopg2.Error:
            if conn:
                conn.rollback()

            if cur:
                cur.close()
            if conn:
                conn.close()

            utils.log_file_upload_failed(
                status=500,
                reason="database_insert_failed",
                title=title,
                original_filename=original_filename,
                stored_filename=final_name,
                file_path=final_path,
                analysis=analysis,
                severity="error",
                outcome="failed",
            )

            flask.flash("Upload failed while saving document metadata.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        except Exception:
            if conn:
                conn.rollback()

            if cur:
                cur.close()
            if conn:
                conn.close()

            utils.log_file_upload_failed(
                status=500,
                reason="unexpected_exception",
                title=title,
                original_filename=original_filename,
                stored_filename=final_name,
                file_path=final_path,
                analysis=analysis,
                severity="error",
                outcome="failed",
            )

            flask.flash("Upload failed unexpectedly.", "error")
            return flask.redirect(flask.url_for("documents_page"))

    @app.route("/health")
    def health():
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
            conn.close()
            return {"status": "ok"}, 200
        except Exception as e:
            print(f"Health check error: {e}", flush=True)
            import traceback
            traceback.print_exc()
            return {"status": "error"}, 500

    @app.route("/admin/users")
    @login_required
    @is_admin
    def admin_users():
        conn = get_db(is_admin=True)
        cur = conn.cursor()
        cur.execute("SELECT id, username, is_disabled, is_admin FROM users ORDER BY id")
        users = cur.fetchall()
        cur.close()
        conn.close()
        return flask.render_template("admin_users.html", users=users)
    
    @app.route("/admin/users/<int:id>/enable", methods=["POST"])
    @login_required
    @is_admin
    def enable_user(id):
        actor_user_id = flask.session.get("user_id")

        conn = None
        cur = None
        target_user_id = id
        target_username = None
        target_previous_status = None

        try:
            conn = get_db(is_admin=True)
            cur = conn.cursor()

            cur.execute(
                """
                SELECT id, username, is_disabled
                FROM users
                WHERE id = %s
                """,
                (id,),
            )
            target = cur.fetchone()

            if not target:
                utils.log_admin_enable_account_failed(
                    target_user_id=id,
                    target_username=None,
                    target_previous_status=None,
                    target_new_status=None,
                    status=404,
                    outcome="not_found",
                    reason="target_user_not_found",
                    severity="medium",
                )

                cur.close()
                conn.close()

                return flask.render_template(
                    "error.html",
                    status_code=404,
                    title="User Not Found",
                    message="The target user does not exist.",
                ), 404

            target_user_id, target_username, is_disabled = target
            target_previous_status = "disabled" if is_disabled else "enabled"

            if actor_user_id == target_user_id:
                utils.log_admin_enable_account_denied(
                    target_user_id=target_user_id,
                    target_username=target_username,
                    target_previous_status=target_previous_status,
                    target_new_status=target_previous_status,
                    reason="self_account_change_blocked",
                    status=400,
                )

                cur.close()
                conn.close()

                return "You cannot enable your own account", 400

            if not is_disabled:
                utils.log_admin_enable_account_failed(
                    target_user_id=target_user_id,
                    target_username=target_username,
                    target_previous_status="enabled",
                    target_new_status="enabled",
                    status=302,
                    outcome="noop",
                    reason="already_enabled",
                    severity="info",
                )

                cur.close()
                conn.close()

                return flask.redirect(flask.url_for("admin_users"))

            cur.execute(
                """
                UPDATE users
                SET is_disabled = false
                WHERE id = %s
                """,
                (target_user_id,),
            )

            if cur.rowcount != 1:
                conn.rollback()

                utils.log_admin_enable_account_failed(
                    target_user_id=target_user_id,
                    target_username=target_username,
                    target_previous_status=target_previous_status,
                    target_new_status=target_previous_status,
                    status=500,
                    outcome="failed",
                    reason="database_update_failed",
                    severity="error",
                )

                cur.close()
                conn.close()

                return flask.render_template(
                    "error.html",
                    status_code=500,
                    title="Enable Failed",
                    message="The account could not be enabled.",
                ), 500

            conn.commit()

            utils.log_admin_enable_account_success(
                target_user_id=target_user_id,
                target_username=target_username,
                target_previous_status="disabled",
                target_new_status="enabled",
            )

            cur.close()
            conn.close()

            return flask.redirect(flask.url_for("admin_users"))

        except psycopg2.Error:
            if conn:
                conn.rollback()

            utils.log_admin_enable_account_failed(
                target_user_id=target_user_id,
                target_username=target_username,
                target_previous_status=target_previous_status,
                target_new_status=target_previous_status,
                status=500,
                outcome="failed",
                reason="database_update_failed",
                severity="error",
            )

            if cur:
                cur.close()
            if conn:
                conn.close()

            return flask.render_template(
                "error.html",
                status_code=500,
                title="Database Error",
                message="The account could not be enabled.",
            ), 500

        except Exception:
            if conn:
                conn.rollback()

            utils.log_admin_enable_account_failed(
                target_user_id=target_user_id,
                target_username=target_username,
                target_previous_status=target_previous_status,
                target_new_status=target_previous_status,
                status=500,
                outcome="failed",
                reason="unexpected_exception",
                severity="error",
            )

            if cur:
                cur.close()
            if conn:
                conn.close()

            return flask.render_template(
                "error.html",
                status_code=500,
                title="Unexpected Error",
                message="An unexpected error occurred while enabling the account.",
            ), 500
    

    @app.route("/admin/users/<int:id>/disable", methods=["POST"])
    @login_required
    @is_admin
    def disable_user(id):
        actor_user_id = flask.session.get("user_id")

        conn = None
        cur = None
        target_user_id = id
        target_username = None
        target_previous_status = None

        try:
            conn = get_db(is_admin=True)
            cur = conn.cursor()

            cur.execute(
                """
                SELECT id, username, is_disabled
                FROM users
                WHERE id = %s
                """,
                (id,),
            )
            target = cur.fetchone()

            if not target:
                utils.log_admin_disable_account_failed(
                    target_user_id=id,
                    target_username=None,
                    target_previous_status=None,
                    target_new_status=None,
                    status=404,
                    outcome="not_found",
                    reason="target_user_not_found",
                    severity="medium",
                )

                cur.close()
                conn.close()

                return flask.render_template(
                    "error.html",
                    status_code=404,
                    title="User Not Found",
                    message="The target user does not exist.",
                ), 404

            target_user_id, target_username, is_disabled = target
            target_previous_status = "disabled" if is_disabled else "enabled"

            if actor_user_id == target_user_id:
                utils.log_admin_disable_account_denied(
                    target_user_id=target_user_id,
                    target_username=target_username,
                    target_previous_status=target_previous_status,
                    target_new_status=target_previous_status,
                    reason="self_account_change_blocked",
                    status=400,
                )

                cur.close()
                conn.close()

                return "You cannot disable your own account", 400

            if is_disabled:
                utils.log_admin_disable_account_failed(
                    target_user_id=target_user_id,
                    target_username=target_username,
                    target_previous_status="disabled",
                    target_new_status="disabled",
                    status=302,
                    outcome="noop",
                    reason="already_disabled",
                    severity="info",
                )

                cur.close()
                conn.close()

                return flask.redirect(flask.url_for("admin_users"))

            cur.execute(
                """
                UPDATE users
                SET is_disabled = true
                WHERE id = %s
                """,
                (target_user_id,),
            )

            if cur.rowcount != 1:
                conn.rollback()

                utils.log_admin_disable_account_failed(
                    target_user_id=target_user_id,
                    target_username=target_username,
                    target_previous_status=target_previous_status,
                    target_new_status=target_previous_status,
                    status=500,
                    outcome="failed",
                    reason="database_update_failed",
                    severity="error",
                )

                cur.close()
                conn.close()

                return flask.render_template(
                    "error.html",
                    status_code=500,
                    title="Disable Failed",
                    message="The account could not be disabled.",
                ), 500

            conn.commit()

            utils.log_admin_disable_account_success(
                target_user_id=target_user_id,
                target_username=target_username,
                target_previous_status="enabled",
                target_new_status="disabled",
            )

            cur.close()
            conn.close()

            return flask.redirect(flask.url_for("admin_users"))

        except psycopg2.Error:
            if conn:
                conn.rollback()

            utils.log_admin_disable_account_failed(
                target_user_id=target_user_id,
                target_username=target_username,
                target_previous_status=target_previous_status,
                target_new_status=target_previous_status,
                status=500,
                outcome="failed",
                reason="database_update_failed",
                severity="error",
            )

            if cur:
                cur.close()
            if conn:
                conn.close()

            return flask.render_template(
                "error.html",
                status_code=500,
                title="Database Error",
                message="The account could not be disabled.",
            ), 500

        except Exception:
            if conn:
                conn.rollback()

            utils.log_admin_disable_account_failed(
                target_user_id=target_user_id,
                target_username=target_username,
                target_previous_status=target_previous_status,
                target_new_status=target_previous_status,
                status=500,
                outcome="failed",
                reason="unexpected_exception",
                severity="error",
            )

            if cur:
                cur.close()
            if conn:
                conn.close()

            return flask.render_template(
                "error.html",
                status_code=500,
                title="Unexpected Error",
                message="An unexpected error occurred while disabling the account.",
            ), 500
            

    @app.route("/documents/<int:doc_id>/share", methods=["GET"])
    @login_required
    def share_document(doc_id):

        return flask.render_template("share_document.html", doc_id=doc_id)
    
    @app.route("/documents/<int:document_id>/share", methods=["POST"])
    @login_required
    def share_document_post(document_id):
        shared_with_username = flask.request.form.get("uname")
        shared_with_username = utils.sanitize_input(
            shared_with_username,
            allowed_chars="A-Za-z0-9._-",
            max_length=32,
        )

        owner_user_id = flask.session.get("user_id")

        conn = None
        cur = None
        target_user = None
        document_owner_id = None

        try:
            conn = get_db()
            cur = conn.cursor()

            # Fetch target user first so denied logs can include target_user_id if it exists.
            cur.execute(
                "SELECT id, username FROM users WHERE username = %s",
                (shared_with_username,),
            )
            target_user = cur.fetchone()

            target_user_id = target_user[0] if target_user else None
            target_username = target_user[1] if target_user else shared_with_username

            # Fetch document owner independently.
            cur.execute(
                "SELECT owner_id FROM documents WHERE id = %s",
                (document_id,),
            )
            document_row = cur.fetchone()
            document_owner_id = document_row[0] if document_row else None

            # Authenticated user tried to share a missing document or a document they do not own.
            if not document_row or document_owner_id != owner_user_id:
                utils.log_file_share_denied(
                    document_id=document_id,
                    document_owner_id=document_owner_id,
                    target_user_id=target_user_id,
                    target_username=target_username,
                    reason="not_document_owner",
                )

                cur.close()
                conn.close()

                return flask.render_template(
                    "error.html",
                    status_code=403,
                    title="Access Denied",
                    message="You can only share documents that you own.",
                ), 403

            # User owns the document, but target user does not exist.
            if not target_user:
                utils.log_file_share_target_not_found(
                    document_id=document_id,
                    document_owner_id=document_owner_id,
                    target_username=shared_with_username,
                )

                cur.close()
                conn.close()

                return flask.render_template(
                    "error.html",
                    status_code=404,
                    title="User Not Found",
                    message="The target user does not exist.",
                ), 404

            target_user_id = target_user[0]
            target_username = target_user[1]

            # detect duplicate share before inserting.
            cur.execute(
                """
                SELECT 1
                FROM document_shares
                WHERE document_id = %s
                AND shared_with = %s
                """,
                (document_id, target_user_id),
            )
            duplicate = cur.fetchone()

            if duplicate:
                utils.log_file_share_failed(
                    document_id=document_id,
                    document_owner_id=document_owner_id,
                    target_user_id=target_user_id,
                    target_username=target_username,
                    status=409,
                    reason="duplicate_share",
                )

                cur.close()
                conn.close()

                return flask.render_template(
                    "error.html",
                    status_code=409,
                    title="Duplicate Share",
                    message="This document is already shared with that user.",
                ), 409

            try:
                cur.execute(
                    """
                    INSERT INTO document_shares (document_id, shared_with)
                    VALUES (%s, %s)
                    """,
                    (document_id, target_user_id),
                )
                conn.commit()

            except psycopg2.IntegrityError:
                conn.rollback()

                utils.log_file_share_failed(
                    document_id=document_id,
                    document_owner_id=document_owner_id,
                    target_user_id=target_user_id,
                    target_username=target_username,
                    status=409,
                    reason="duplicate_share",
                )

                cur.close()
                conn.close()

                return flask.render_template(
                    "error.html",
                    status_code=409,
                    title="Duplicate Share",
                    message="This document is already shared with that user.",
                ), 409

            except psycopg2.Error:
                conn.rollback()

                utils.log_file_share_failed(
                    document_id=document_id,
                    document_owner_id=document_owner_id,
                    target_user_id=target_user_id,
                    target_username=target_username,
                    status=500,
                    reason="database_insert_failed",
                )

                cur.close()
                conn.close()

                return flask.render_template(
                    "error.html",
                    status_code=500,
                    title="Share Failed",
                    message="The document could not be shared.",
                ), 500

            utils.log_file_share_created(
                document_id=document_id,
                document_owner_id=document_owner_id,
                target_user_id=target_user_id,
                target_username=target_username,
            )

            cur.close()
            conn.close()

            return flask.redirect(flask.url_for("documents_page"))

        except psycopg2.OperationalError:
            if conn:
                conn.rollback()

            utils.log_file_share_failed(
                document_id=document_id,
                document_owner_id=document_owner_id,
                target_user_id=target_user[0] if target_user else None,
                target_username=target_user[1] if target_user else shared_with_username,
                status=500,
                reason="database_connection_failed",
            )

            if cur:
                cur.close()
            if conn:
                conn.close()

            return flask.render_template(
                "error.html",
                status_code=500,
                title="Database Error",
                message="Could not connect to the database.",
            ), 500

        except Exception:
            if conn:
                conn.rollback()

            utils.log_file_share_failed(
                document_id=document_id,
                document_owner_id=document_owner_id,
                target_user_id=target_user[0] if target_user else None,
                target_username=target_user[1] if target_user else shared_with_username,
                status=500,
                reason="unexpected_exception",
            )

            if cur:
                cur.close()
            if conn:
                conn.close()

            return flask.render_template(
                "error.html",
                status_code=500,
                title="Unexpected Error",
                message="An unexpected error occurred while sharing the document.",
            ), 500

    @app.route("/shared")
    @login_required
    def shared_documents():
        current_user_id = flask.session.get("user_id")
        
        conn = get_db()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT d.id, d.title, d.filename, d.metadata, d.uploaded_at, u.username
            FROM documents d
            INNER JOIN document_shares ds ON d.id = ds.document_id
            INNER JOIN users u ON d.owner_id = u.id
            WHERE ds.shared_with = %s
            ORDER BY d.uploaded_at DESC
        """, (current_user_id,))
        
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        documents = [
            {
                "id": row[0],
                "title": row[1],
                "filename": row[2],
                "original_filename": (json.loads(row[3]).get("original_filename") if row[3] else None)
                if isinstance(row[3], str)
                else None,
                "uploaded_at": row[4],
                "owner_username": row[5],
            }
            for row in rows
        ]
        
        return flask.render_template("shared_documents.html", documents=documents)
    
    @app.route("/shared/<int:document_id>/download")
    @login_required
    @limiter.limit("30 per 1 hour", key_func=rate_limit_key)
    def download_shared_document(document_id):
        current_user_id = flask.session.get("user_id")
        
        conn = get_db()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT d.filename, d.owner_id
            FROM documents d
            INNER JOIN document_shares ds ON d.id = ds.document_id
            WHERE d.id = %s AND ds.shared_with = %s
        """, (document_id, current_user_id))
        
        row = cur.fetchone()
        cur.close()
        conn.close()
        
        if not row:
            utils.log_file_download_failed(
                document_id=document_id,
                status=404,
                reason="document_not_found_or_access_denied",
                access_type="shared",
            )
            return "Document not found or access denied", 404
        
        filename, owner_id = row
        
        if not filename:
            utils.log_file_download_failed(
                document_id=document_id,
                document_owner_id=owner_id,
                status=404,
                reason="filename_missing",
                access_type="shared",
            )
            return "File not found", 404
        
        safe_name = pathlib.Path(filename).name
        if safe_name != filename:
            utils.log_file_download_failed(
                document_id=document_id,
                document_owner_id=owner_id,
                original_filename=filename,
                status=400,
                reason="invalid_filename",
                access_type="shared",
            )
            return "Invalid filename", 400
        
        storage_root = STORAGE_DIR.resolve()
        file_path = (storage_root / safe_name).resolve()

        if not str(file_path).startswith(str(storage_root)):
            return "Invalid file path", 400
        
        if not file_path.exists():
            utils.log_file_download_failed(
                document_id=document_id,
                document_owner_id=owner_id,
                original_filename=filename,
                file_path=file_path,
                status=404,
                reason="file_not_found_on_server",
                access_type="shared",
            )
            return "File not found on server", 404
        download_name = filename
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT metadata FROM documents WHERE id = %s", (document_id,))
            meta_row = cur.fetchone()
            cur.close()
            conn.close()
            if meta_row and meta_row[0]:
                meta = json.loads(meta_row[0])
                if isinstance(meta, dict) and meta.get("original_filename"):
                    download_name = str(meta["original_filename"])

            utils.log_file_download_success(
                document_id=document_id,
                document_owner_id=owner_id,
                original_filename=filename,
                file_path=file_path,
                access_type="shared",
            )
        except Exception:
            utils.log_file_download_failed(
                document_id=document_id,
                document_owner_id=owner_id,
                original_filename=filename,
                file_path=file_path,
                status=500,
                reason="storage_read_failed",
                access_type="shared",
            )
            pass

        return flask.send_file(file_path, as_attachment=True, download_name=download_name)
