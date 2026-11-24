import os
import re
import json
import logging
import hashlib
import mimetypes
import secrets
from datetime import datetime
from flask import request, g


#  input sanitizer using a whitelist (allowed characters).
# It removes any character not explicitly allowed and trims length.
def sanitize_input(value, allowed_chars=r"A-Za-z0-9._\- @", max_length=255):
    """
    Sanitize an arbitrary textual input by removing characters not in the
    allowed character set and truncating to `max_length`.

        - `allowed_chars` is a bracket content for a regex character class
            (without surrounding []). For example: "A-Za-z0-9._- @"
    - Returns an empty string for None inputs.
    """
    if value is None:
        return ""

    s = str(value).strip()
    s = s.replace("\x00", "")

    # Remove characters not in the allowed set
    pattern = f"[^{allowed_chars}]"
    s = re.sub(pattern, "", s)

    if len(s) > max_length:
        s = s[:max_length]

    return s


def sanitize_filename(filename, max_length=255):
    """
    Sanitize file names safely:
    - Strip NULLs and whitespace
    - Replace backslashes, remove path components
    - Whitelist characters to letters, numbers, space, dot, underscore, hyphen
    - Prevent traversal and collapse suspicious sequences
    - Ensure non-empty fallback
    """
    if filename is None:
        return "file"

    # Normalize and remove dangerous characters
    name = str(filename).strip()
    name = name.replace("\x00", "")
    name = name.replace("\\", "/")

    # Keep only the basename to prevent path traversal
    name = os.path.basename(name)

    # Whitelist allowed characters and remove the rest
    name = re.sub(r"[^A-Za-z0-9\.\-_ ]", "", name)

    # Remove sequences like ".." and collapse multiple dots
    name = name.replace("..", "")
    name = re.sub(r"\.{2,}", ".", name)

    name = name.strip()
    if not name:
        name = "file"

    if len(name) > max_length:
        name = name[:max_length]

    return name


def validate_username(username, min_len=3, max_len=32):
    """Return True if `username` matches a conservative allowed pattern."""
    if not username:
        return False
    s = str(username).strip()
    if len(s) < min_len or len(s) > max_len:
        return False
    # allow letters, numbers, dot, underscore and hyphen
    return re.fullmatch(r"[A-Za-z0-9._\-]+", s) is not None


def validate_password(password, min_len=8, max_len=256):
    if password is None:
        return False
    s = str(password)
    if len(s) < min_len or len(s) > max_len:
        return False
    # allow printable ASCII except control characters
    return re.fullmatch(r"[\x21-\x7E]+", s) is not None


# Structured logging configuration
logging.basicConfig(level=logging.INFO, format='%(message)s')
auth_logger = logging.getLogger('auth')

def _get_client_ip():
    """Extract client IP from request, accounting for proxies."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or "unknown"

#Check some failures
def _emit_auth_log(event_type, user_id=None, username=None, reason=None, request_id=None):
    """
    Emit a structured authentication log entry.
    
    Args:
        event_type: One of "auth.login_success", "auth.login_failed", "auth.logout"
        user_id: User ID (optional for failed logins)
        username: Username
        reason: Reason for event (e.g., "invalid_password", "success")
        request_id: Unique request identifier
    """
    log_entry = {
        "event_category": "auth",
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "user_id": str(user_id) if user_id is not None else "unknown",
        "username": username or "unknown",
        "source_ip": _get_client_ip(),
        "reason": reason or "",
        "request_id": request_id or "",
    }
    auth_logger.info(json.dumps(log_entry))

def log_auth_login_success(user_id, username, request_id=None):
    """Log successful login."""
    _emit_auth_log(
        event_type="auth.login_success",
        user_id=user_id,
        username=username,
        reason="success",
        request_id=request_id,
    )

def log_auth_login_failed(username, reason="invalid_credentials", request_id=None):
    """Log failed login attempt."""
    _emit_auth_log(
        event_type="auth.login_failed",
        username=username,
        reason=reason,
        request_id=request_id,
    )

def log_auth_logout(user_id, username, request_id=None):
    """Log user logout."""
    _emit_auth_log(
        event_type="auth.logout",
        user_id=user_id,
        username=username,
        reason="user_initiated",
        request_id=request_id,
    )

# Structured file event logger
file_logger = logging.getLogger("file")

def get_request_id():
    """
    Return a per-request ID.

    Prefer an incoming X-Request-ID header if one exists.
    Otherwise generate one and store it in Flask's request context.
    """
    incoming = request.headers.get("X-Request-ID")
    if incoming:
        return sanitize_input(incoming, allowed_chars=r"A-Za-z0-9._\-", max_length=128)

    if not hasattr(g, "request_id"):
        g.request_id = secrets.token_urlsafe(32)

    return g.request_id


def _get_user_agent():
    return request.headers.get("User-Agent", "")


def sha256_file(path):
    """Return the SHA-256 hash of a file without loading the whole file into memory."""
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def _detect_mime_type(path):
    mime_type, _ = mimetypes.guess_type(str(path))
    return mime_type or "application/octet-stream"


def _emit_file_download_log(
    *,
    event_type,
    severity,
    status,
    document_id,
    document_owner_id=None,
    original_filename=None,
    file_path=None,
    file_size_bytes=None,
    bytes_sent=None,
    file_hash_sha256=None,
    access_type=None,
    reason="",
):
    """
    Emit a structured file download log entry.

    event_type should be:
    - file.download_success
    - file.download_failed
    """
    username = None
    user_id = None

    try:
        from flask import session
        user_id = session.get("user_id")
        username = session.get("username")
    except Exception:
        pass

    file_extension = ""
    detected_mime_type = ""
    calculated_size = file_size_bytes
    calculated_hash = file_hash_sha256 or ""

    if file_path:
        try:
            suffix = file_path.suffix.lower().lstrip(".")
            file_extension = suffix

            detected_mime_type = _detect_mime_type(file_path)

            if calculated_size is None and file_path.exists():
                calculated_size = file_path.stat().st_size

            if not calculated_hash and file_path.exists():
                calculated_hash = sha256_file(file_path)
        except Exception:
            pass

    log_entry = {
        "event_category": "file",
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,

        "user_id": str(user_id) if user_id is not None else "unknown",
        "username": username or "unknown",
        "source_ip": _get_client_ip(),
        "user_agent": _get_user_agent(),
        "request_id": get_request_id(),

        "method": request.method,
        "endpoint": request.path,
        "status": status,

        "document_id": str(document_id) if document_id is not None else None,
        "document_owner_id": str(document_owner_id) if document_owner_id is not None else "unknown",
        "original_filename": original_filename or "",
        "file_extension": file_extension,
        "detected_mime_type": detected_mime_type,
        "file_size_bytes": calculated_size or 0,
        "bytes_sent": bytes_sent or 0,
        "file_hash_sha256": calculated_hash,

        "access_type": access_type or "unknown",
        "reason": reason or "",
    }

    file_logger.info(json.dumps(log_entry))


def log_file_download_success(
    *,
    document_id,
    document_owner_id,
    original_filename,
    file_path,
    access_type,
):
    file_size = file_path.stat().st_size

    _emit_file_download_log(
        event_type="file.download_success",
        severity="info",
        status=200,
        document_id=document_id,
        document_owner_id=document_owner_id,
        original_filename=original_filename,
        file_path=file_path,
        file_size_bytes=file_size,
        bytes_sent=file_size,
        access_type=access_type,
        reason="",
    )


def log_file_download_failed(
    *,
    document_id,
    status,
    reason,
    document_owner_id=None,
    original_filename=None,
    file_path=None,
    access_type=None,
):
    _emit_file_download_log(
        event_type="file.download_failed",
        severity="error",
        status=status,
        document_id=document_id,
        document_owner_id=document_owner_id,
        original_filename=original_filename,
        file_path=file_path,
        access_type=access_type,
        reason=reason,
    )

# Structured file upload event logger
def _analysis_value(analysis, *keys, default=None):
    if not isinstance(analysis, dict):
        return default

    for key in keys:
        value = analysis.get(key)
        if value is not None and value != "":
            return value

    return default


def _emit_file_upload_log(
    *,
    event_type,
    severity,
    status,
    outcome,
    reason="",
    document_id=None,
    document_owner_id=None,
    title=None,
    original_filename=None,
    stored_filename=None,
    file_path=None,
    analysis=None,
):
    """
    Emit a structured file upload log entry.

    event_type should be:
    - file.upload_success
    - file.upload_failed
    """
    try:
        from flask import session
        user_id = session.get("user_id")
        username = session.get("username")
    except Exception:
        user_id = None
        username = None

    file_size_bytes = 0
    if file_path:
        try:
            if file_path.exists():
                file_size_bytes = file_path.stat().st_size
        except Exception:
            file_size_bytes = 0

    analyzer_sha256 = _analysis_value(analysis, "sha256", "file_hash_sha256", default="")
    analyzer_mime = _analysis_value(
        analysis,
        "detected_mime_type",
        "mime_type",
        "content_type",
        default="application/pdf" if str(original_filename or "").lower().endswith(".pdf") else "",
    )
    analyzer_size = _analysis_value(analysis, "file_size_bytes", "size_bytes", "size", default=None)

    if analyzer_size is not None:
        try:
            file_size_bytes = int(analyzer_size)
        except Exception:
            pass

    file_extension = ""
    if original_filename:
        file_extension = str(original_filename).rsplit(".", 1)[-1].lower() if "." in str(original_filename) else ""

    log_entry = {
        "event_category": "file",
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,

        "user_id": str(user_id) if user_id is not None else "unknown",
        "username": username or "unknown",
        "source_ip": _get_client_ip(),
        "user_agent": _get_user_agent(),
        "request_id": get_request_id(),

        "method": request.method,
        "endpoint": request.path,
        "status": status,

        "document_id": str(document_id) if document_id is not None else None,
        "document_owner_id": str(document_owner_id) if document_owner_id is not None else None,
        "title": title or "",

        "original_filename": original_filename or "",
        "stored_filename": stored_filename or "",
        "file_extension": file_extension,
        "detected_mime_type": analyzer_mime,
        "file_size_bytes": file_size_bytes,
        "file_hash_sha256": analyzer_sha256,

        "analyzer_allowed": bool(event_type == "file.upload_success"),
        "analyzer_reason": _analysis_value(analysis, "reason", default="") or "",
        "outcome": outcome,
        "reason": reason or "",
    }

    file_logger.info(json.dumps(log_entry))


def log_file_upload_success(
    *,
    document_id,
    document_owner_id,
    title,
    original_filename,
    stored_filename,
    file_path,
    analysis,
):
    _emit_file_upload_log(
        event_type="file.upload_success",
        severity="info",
        status=302,
        outcome="success",
        reason="",
        document_id=document_id,
        document_owner_id=document_owner_id,
        title=title,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_path=file_path,
        analysis=analysis,
    )


def log_file_upload_failed(
    *,
    status,
    reason,
    title=None,
    original_filename=None,
    stored_filename=None,
    file_path=None,
    analysis=None,
    document_id=None,
    document_owner_id=None,
    severity="error",
    outcome="failed",
):
    _emit_file_upload_log(
        event_type="file.upload_failed",
        severity=severity,
        status=status,
        outcome=outcome,
        reason=reason,
        document_id=document_id,
        document_owner_id=document_owner_id,
        title=title,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_path=file_path,
        analysis=analysis,
    )

# Structured file share event logger

def _emit_file_share_log(
    *,
    event_type,
    severity,
    status,
    document_id,
    document_owner_id=None,
    target_user_id=None,
    target_username=None,
    permission="read",
    share_action="create",
    reason="",
):
    """
    Emit a structured file share log entry.

    event_type should be one of:
      - file.share_created
      - file.share_denied
      - file.share_target_not_found
      - file.share_failed
    """
    username = None
    user_id = None

    try:
        from flask import session
        user_id = session.get("user_id")
        username = session.get("username")
    except Exception:
        pass

    log_entry = {
        "event_category": "file",
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,

        "user_id": str(user_id) if user_id is not None else "unknown",
        "username": username or "unknown",
        "source_ip": _get_client_ip(),
        "request_id": get_request_id(),

        "method": request.method,
        "endpoint": request.path,
        "status": status,

        "document_id": str(document_id) if document_id is not None else None,
        "document_owner_id": str(document_owner_id) if document_owner_id is not None else None,

        "target_user_id": str(target_user_id) if target_user_id is not None else None,
        "target_username": target_username or "",

        "permission": permission,
        "share_action": share_action,
        "reason": reason or "",
    }

    file_logger.info(json.dumps(log_entry))


def log_file_share_created(
    *,
    document_id,
    document_owner_id,
    target_user_id,
    target_username,
):
    _emit_file_share_log(
        event_type="file.share_created",
        severity="info",
        status=302,
        document_id=document_id,
        document_owner_id=document_owner_id,
        target_user_id=target_user_id,
        target_username=target_username,
        permission="read",
        share_action="create",
        reason="",
    )


def log_file_share_denied(
    *,
    document_id,
    target_user_id=None,
    target_username=None,
    document_owner_id=None,
    reason="not_document_owner",
):
    _emit_file_share_log(
        event_type="file.share_denied",
        severity="high",
        status=403,
        document_id=document_id,
        document_owner_id=document_owner_id,
        target_user_id=target_user_id,
        target_username=target_username,
        permission="read",
        share_action="create",
        reason=reason,
    )


def log_file_share_target_not_found(
    *,
    document_id,
    document_owner_id=None,
    target_username=None,
):
    _emit_file_share_log(
        event_type="file.share_target_not_found",
        severity="medium",
        status=404,
        document_id=document_id,
        document_owner_id=document_owner_id,
        target_user_id=None,
        target_username=target_username,
        permission="read",
        share_action="create",
        reason="target_user_not_found",
    )


def log_file_share_failed(
    *,
    document_id,
    reason,
    status=500,
    document_owner_id=None,
    target_user_id=None,
    target_username=None,
):
    _emit_file_share_log(
        event_type="file.share_failed",
        severity="error",
        status=status,
        document_id=document_id,
        document_owner_id=document_owner_id,
        target_user_id=target_user_id,
        target_username=target_username,
        permission="read",
        share_action="create",
        reason=reason,
    )


# Structured admin event logger
admin_logger = logging.getLogger("admin")


def _account_status_from_disabled(is_disabled):
    if is_disabled is None:
        return None
    return "disabled" if bool(is_disabled) else "enabled"


def _emit_admin_disable_account_log(
    *,
    event_type,
    severity,
    actor_user_id=None,
    actor_username=None,
    target_user_id=None,
    target_username=None,
    target_previous_status=None,
    target_new_status=None,
    status,
    outcome,
    reason="",
    request_id=None,
):
    """
    Emit a structured admin account-disable log entry.

    event_type should be one of:
      - admin.disable_account_success
      - admin.disable_account_failed
      - admin.disable_account_denied
    """
    try:
        from flask import session
        actor_user_id = actor_user_id if actor_user_id is not None else session.get("user_id")
        actor_username = actor_username if actor_username is not None else session.get("username")
    except Exception:
        pass

    log_entry = {
        "event_category": "admin",
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,

        "actor_user_id": str(actor_user_id) if actor_user_id is not None else "unknown",
        "actor_username": actor_username or "unknown",
        "actor_role": "admin",

        "target_user_id": str(target_user_id) if target_user_id is not None else None,
        "target_username": target_username,
        "target_previous_status": target_previous_status,
        "target_new_status": target_new_status,

        "source_ip": _get_client_ip(),
        "user_agent": _get_user_agent(),
        "request_id": request_id or get_request_id(),

        "method": request.method,
        "endpoint": request.path,
        "status": status,

        "outcome": outcome,
        "reason": reason or "",
    }

    admin_logger.info(json.dumps(log_entry))


def log_admin_disable_account_success(
    *,
    target_user_id,
    target_username,
    target_previous_status,
    target_new_status="disabled",
):
    _emit_admin_disable_account_log(
        event_type="admin.disable_account_success",
        severity="info",
        target_user_id=target_user_id,
        target_username=target_username,
        target_previous_status=target_previous_status,
        target_new_status=target_new_status,
        status=302,
        outcome="success",
        reason="",
    )


def log_admin_disable_account_denied(
    *,
    target_user_id,
    target_username,
    target_previous_status=None,
    target_new_status=None,
    reason="self_account_change_blocked",
    status=400,
):
    _emit_admin_disable_account_log(
        event_type="admin.disable_account_denied",
        severity="high",
        target_user_id=target_user_id,
        target_username=target_username,
        target_previous_status=target_previous_status,
        target_new_status=target_new_status,
        status=status,
        outcome="denied",
        reason=reason,
    )


def log_admin_disable_account_failed(
    *,
    target_user_id=None,
    target_username=None,
    target_previous_status=None,
    target_new_status=None,
    status=500,
    outcome="failed",
    reason="unexpected_exception",
    severity="error",
):
    _emit_admin_disable_account_log(
        event_type="admin.disable_account_failed",
        severity=severity,
        target_user_id=target_user_id,
        target_username=target_username,
        target_previous_status=target_previous_status,
        target_new_status=target_new_status,
        status=status,
        outcome=outcome,
        reason=reason,
    )

def _emit_admin_enable_account_log(
    *,
    event_type,
    severity,
    actor_user_id=None,
    actor_username=None,
    target_user_id=None,
    target_username=None,
    target_previous_status=None,
    target_new_status=None,
    status,
    outcome,
    reason="",
    request_id=None,
):
    """
    Emit a structured admin account-enable log entry.

    event_type should be one of:
      - admin.enable_account_success
      - admin.enable_account_failed
      - admin.enable_account_denied
    """
    try:
        from flask import session
        actor_user_id = actor_user_id if actor_user_id is not None else session.get("user_id")
        actor_username = actor_username if actor_username is not None else session.get("username")
    except Exception:
        pass

    log_entry = {
        "event_category": "admin",
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,

        "actor_user_id": str(actor_user_id) if actor_user_id is not None else "unknown",
        "actor_username": actor_username or "unknown",
        "actor_role": "admin",

        "target_user_id": str(target_user_id) if target_user_id is not None else None,
        "target_username": target_username,
        "target_previous_status": target_previous_status,
        "target_new_status": target_new_status,

        "source_ip": _get_client_ip(),
        "user_agent": _get_user_agent(),
        "request_id": request_id or get_request_id(),

        "method": request.method,
        "endpoint": request.path,
        "status": status,

        "outcome": outcome,
        "reason": reason or "",
    }

    admin_logger.info(json.dumps(log_entry))


def log_admin_enable_account_success(
    *,
    target_user_id,
    target_username,
    target_previous_status,
    target_new_status="enabled",
):
    _emit_admin_enable_account_log(
        event_type="admin.enable_account_success",
        severity="info",
        target_user_id=target_user_id,
        target_username=target_username,
        target_previous_status=target_previous_status,
        target_new_status=target_new_status,
        status=302,
        outcome="success",
        reason="",
    )


def log_admin_enable_account_denied(
    *,
    target_user_id,
    target_username,
    target_previous_status=None,
    target_new_status=None,
    reason="self_account_change_blocked",
    status=400,
):
    _emit_admin_enable_account_log(
        event_type="admin.enable_account_denied",
        severity="high",
        target_user_id=target_user_id,
        target_username=target_username,
        target_previous_status=target_previous_status,
        target_new_status=target_new_status,
        status=status,
        outcome="denied",
        reason=reason,
    )


def log_admin_enable_account_failed(
    *,
    target_user_id=None,
    target_username=None,
    target_previous_status=None,
    target_new_status=None,
    status=500,
    outcome="failed",
    reason="unexpected_exception",
    severity="error",
):
    _emit_admin_enable_account_log(
        event_type="admin.enable_account_failed",
        severity=severity,
        target_user_id=target_user_id,
        target_username=target_username,
        target_previous_status=target_previous_status,
        target_new_status=target_new_status,
        status=status,
        outcome=outcome,
        reason=reason,
    )

def log_admin_register_account(
    *,
    target_user_id=None,
    target_username=None,
    target_previous_status=None,
    target_new_status=None,
    status,
    outcome,
    reason="",
    severity="info",
    request_id=None,
):
    """
    Emit a structured account registration log.

    event_type:
        - admin.register_account

    outcome values:
        - success
        - denied
        - failed
    """
    log_entry = {
        "event_category": "admin",
        "event_type": "admin.register_account",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,

        # Registration is performed by an unauthenticated user.
        "actor_user_id": None,
        "actor_username": None,
        "actor_role": "anonymous",

        "target_user_id": str(target_user_id) if target_user_id is not None else None,
        "target_username": target_username,
        "target_previous_status": target_previous_status,
        "target_new_status": target_new_status,

        "source_ip": _get_client_ip(),
        "user_agent": _get_user_agent(),
        "request_id": request_id or get_request_id(),

        "method": request.method,
        "endpoint": request.path,
        "status": status,

        "outcome": outcome,
        "reason": reason or "",
    }

    admin_logger.info(json.dumps(log_entry))

# Structured security event logger
security_logger = logging.getLogger("security")


def _security_log_level(severity):
    return {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "low": logging.INFO,
        "medium": logging.WARNING,
        "high": logging.WARNING,
        "error": logging.ERROR,
    }.get(severity, logging.INFO)


def _emit_security_log(
    *,
    event_type,
    severity,
    status,
    outcome,
    reason="",
    request_id=None,
    csrf_description=None,
    rate_limit=None,
    retry_after_seconds=None,
    limit_key=None,
):
    """
    Emit a structured security log entry.

    event_type should be one of:
    - security.csrf_failed
    - security.rate_limit_exceeded
    """
    try:
        from flask import session
        user_id = session.get("user_id")
        username = session.get("username")
    except Exception:
        user_id = None
        username = None

    log_entry = {
        "event_category": "security",
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,

        "user_id": str(user_id) if user_id is not None else "anonymous",
        "username": username or "anonymous",

        "source_ip": _get_client_ip(),
        "user_agent": _get_user_agent(),
        "request_id": request_id or get_request_id(),

        "method": request.method,
        "endpoint": request.path,
        "status": status,

        "outcome": outcome,
        "reason": reason or "",

        # Event-specific fields
        "csrf_description": csrf_description,
        "rate_limit": rate_limit,
        "retry_after_seconds": retry_after_seconds,
        "limit_key": limit_key,
    }

    security_logger.log(_security_log_level(severity), json.dumps(log_entry))


def log_security_csrf_failed(*, csrf_description=None, reason="csrf_token_invalid"):
    _emit_security_log(
        event_type="security.csrf_failed",
        severity="high",
        status=400,
        outcome="denied",
        reason=reason,
        csrf_description=csrf_description,
    )


def log_security_rate_limit_exceeded(
    *,
    rate_limit=None,
    retry_after_seconds=None,
    limit_key=None,
    reason="rate_limit_exceeded",
):
    _emit_security_log(
        event_type="security.rate_limit_exceeded",
        severity="medium",
        status=429,
        outcome="denied",
        reason=reason,
        rate_limit=rate_limit,
        retry_after_seconds=retry_after_seconds,
        limit_key=limit_key,
    )

def log_auth_session_expired(
    user_id=None,
    username=None,
    reason="session_timeout",
    request_id=None,
):
    _emit_auth_log(
        event_type="auth.session_expired",
        user_id=user_id,
        username=username,
        reason=reason,
        request_id=request_id,
    )


def log_auth_unauthorized_access(
    reason="authentication_required",
    request_id=None,
):
    try:
        from flask import session

        user_id = session.get("user_id")
        username = session.get("username")
    except Exception:
        user_id = None
        username = None

    _emit_auth_log(
        event_type="auth.unauthorized_access",
        user_id=user_id,
        username=username,
        reason=reason,
        request_id=request_id,
    )


def log_admin_access_denied(
    *,
    reason,
    status=403,
    target_resource=None,
    request_id=None,
):
    try:
        from flask import session

        actor_user_id = session.get("user_id")
        actor_username = session.get("username")
    except Exception:
        actor_user_id = None
        actor_username = None

    log_entry = {
        "event_category": "admin",
        "event_type": "admin.access_denied",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": "high",

        "actor_user_id": str(actor_user_id) if actor_user_id is not None else "anonymous",
        "actor_username": actor_username or "anonymous",
        "actor_role": "user",

        "source_ip": _get_client_ip(),
        "user_agent": _get_user_agent(),
        "request_id": request_id or get_request_id(),

        "method": request.method,
        "endpoint": request.path,
        "status": status,

        "target_resource": target_resource or request.path,

        "outcome": "denied",
        "reason": reason,
    }

    admin_logger.warning(json.dumps(log_entry))