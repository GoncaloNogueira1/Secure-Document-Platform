import json
import logging
import os
from datetime import datetime, timezone

from flask import request


analyzer_logger = logging.getLogger("document-analyzer")


def configure_json_logging(level_name="INFO"):
    logging.basicConfig(
        level=getattr(logging, level_name, logging.INFO),
        format="%(message)s",
    )


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "unknown"


def _log_level_for_severity(severity):
    return {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "medium": logging.WARNING,
        "high": logging.WARNING,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }.get(severity, logging.INFO)


def emit_analyzer_log(
    *,
    event_type,
    severity,
    request_id,
    status,
    outcome,
    verdict,
    reason="",
    path=None,
    path_allowed=None,
    file_size_bytes=None,
    file_hash_sha256=None,
    clamav_status=None,
    clamav_signature=None,
    clamav_error=None,
    qpdf_ok=None,
    qpdf_warnings=None,
    qpdf_error=None,
    pdfid_flags=None,
    elapsed_ms=None,
):
    log_entry = {
        "event_category": "analyzer",
        "event_type": event_type,
        "timestamp": _utc_now(),
        "severity": severity,

        "service_name": "document-analyzer",
        "request_id": request_id,

        "source_ip": _get_client_ip(),
        "user_agent": request.headers.get("User-Agent", ""),

        "method": request.method,
        "endpoint": request.path,
        "status": status,

        "outcome": outcome,
        "verdict": verdict,
        "reason": reason or "",

        # Do not log the full filesystem path unless you really need it.
        "staging_filename": os.path.basename(path) if isinstance(path, str) else None,
        "path_allowed": path_allowed,

        "file_size_bytes": file_size_bytes,
        "file_hash_sha256": file_hash_sha256,

        "clamav_status": clamav_status,
        "clamav_signature": clamav_signature,
        "clamav_error": clamav_error,

        "qpdf_ok": qpdf_ok,
        "qpdf_warnings": qpdf_warnings,
        "qpdf_error": qpdf_error,

        "pdfid_flags": pdfid_flags,

        "elapsed_ms": elapsed_ms,
    }

    level = _log_level_for_severity(severity)
    analyzer_logger.log(level, json.dumps(log_entry))