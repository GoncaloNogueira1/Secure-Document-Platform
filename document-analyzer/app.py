import hashlib
import logging
import os
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass

from flask import Flask, jsonify, request

from analyzer_logging import configure_json_logging, emit_analyzer_log

# Minimal Document Analyzer service (MVP).
# This sits "between" the application server and document storage:
# the app writes to /data/staging, asks us to analyze, and only stores to /data/storage on OK.
DATA_ROOT = os.getenv("DATA_ROOT", "/data")
STAGING_ROOT = os.path.join(DATA_ROOT, "staging")

CLAMD_HOST = os.getenv("CLAMD_HOST", "clamd")
CLAMD_PORT = int(os.getenv("CLAMD_PORT", "3310"))
CLAMD_TIMEOUT_SECONDS = float(os.getenv("CLAMD_TIMEOUT_SECONDS", "30"))
LOG_LEVEL = os.getenv("ANALYZER_LOG_LEVEL", "INFO").upper()
LOG_CLAM_RAW_RESPONSE = os.getenv("LOG_CLAM_RAW_RESPONSE", "false").lower() == "true"

MAX_SCAN_BYTES = int(os.getenv("MAX_SCAN_BYTES", str(32 * 1024 * 1024)))  # 32MB


configure_json_logging(LOG_LEVEL)
logger = logging.getLogger("document-analyzer")


# We implement a conservative "pdfid-like" policy based on keyword indicators.
# It's intentionally strict (academic setting): we prefer false positives over allowing active content.
SUSPICIOUS_TOKENS = [
    b"/JS",
    b"/JavaScript",
    b"/OpenAction",
    b"/Launch",
    b"/EmbeddedFile",
    b"/AA",
]


@dataclass(frozen=True)
class ClamAVResult:
    status: str  # clean | infected | error
    signature: str | None = None
    error: str | None = None


def _is_under_root(path: str, root: str) -> bool:
    # Prevent arbitrary file reads: analyzer must only touch files in /data/staging.
    try:
        path_real = os.path.realpath(path)
        root_real = os.path.realpath(root)
        return os.path.commonpath([path_real, root_real]) == root_real
    except Exception:
        return False


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def pdfid_like_flags(path: str) -> dict:
    # Lightweight pdfid-like heuristic: count occurrences of suspicious tokens.
    # This is intentionally conservative for the academic project.
    counts = {t.decode("ascii"): 0 for t in SUSPICIOUS_TOKENS}
    with open(path, "rb") as f:
        data = f.read()
    for token in SUSPICIOUS_TOKENS:
        counts[token.decode("ascii")] = data.count(token)
    return counts


def qpdf_check(path: str, request_id: str) -> tuple[bool, str]:
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            ["qpdf", "--check", path],
            capture_output=True,
            text=True,
            timeout=20,
        )
        # qpdf return codes:
        # 0: no warnings/errors
        # 2: errors (failed to process)
        # 3: warnings but recovered
        # For our MVP, accept 0 and 3, but keep warnings for metadata/debugging.
        out = (proc.stderr or proc.stdout or "").strip()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        if proc.returncode in (0, 3):
            logger.info(
                "request_id=%s stage=qpdf verdict=ok return_code=%s elapsed_ms=%s warnings=%s",
                request_id,
                proc.returncode,
                elapsed_ms,
                "yes" if proc.returncode == 3 else "no",
            )
            return True, out if proc.returncode == 3 else ""
        logger.warning(
            "request_id=%s stage=qpdf verdict=failed return_code=%s elapsed_ms=%s",
            request_id,
            proc.returncode,
            elapsed_ms,
        )
        return False, out
    except Exception as e:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        logger.exception(
            "request_id=%s stage=qpdf verdict=error elapsed_ms=%s error=%s",
            request_id,
            elapsed_ms,
            e,
        )
        return False, str(e)


def clamd_instream_scan(path: str, request_id: str) -> ClamAVResult:
    started = time.perf_counter()
    try:
        size = os.path.getsize(path)
        if size > MAX_SCAN_BYTES:
            logger.warning(
                "request_id=%s stage=clamav verdict=error reason=file_too_large size=%s max_scan_bytes=%s",
                request_id,
                size,
                MAX_SCAN_BYTES,
            )
            return ClamAVResult(status="error", error=f"file_too_large_for_scan:{size}")

        logger.info(
            "request_id=%s stage=clamav event=connect target=%s:%s file_size=%s",
            request_id,
            CLAMD_HOST,
            CLAMD_PORT,
            size,
        )

        with socket.create_connection(
            (CLAMD_HOST, CLAMD_PORT), timeout=CLAMD_TIMEOUT_SECONDS
        ) as s:
            # INSTREAM avoids sharing the file with clamd via a shared socket/volume;
            # we stream bytes directly over TCP and get back a single verdict line.
            s.sendall(b"zINSTREAM\0")

            with open(path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    s.sendall(len(chunk).to_bytes(4, "big") + chunk)
            s.sendall((0).to_bytes(4, "big"))

            s.settimeout(CLAMD_TIMEOUT_SECONDS)
            resp = b""
            while not resp.endswith(b"\n"):
                part = s.recv(4096)
                if not part:
                    break
                resp += part

        line = resp.decode("utf-8", errors="replace").replace("\x00", "").strip()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        if LOG_CLAM_RAW_RESPONSE:
            logger.info(
                "request_id=%s stage=clamav event=raw_response elapsed_ms=%s response=%s",
                request_id,
                elapsed_ms,
                line,
            )
        # Examples:
        # stream: OK
        # stream: Eicar-Signature FOUND
        if line.endswith("OK"):
            logger.info(
                "request_id=%s stage=clamav verdict=clean elapsed_ms=%s",
                request_id,
                elapsed_ms,
            )
            return ClamAVResult(status="clean")
        if "FOUND" in line:
            sig = line.split(":", 1)[-1].replace("FOUND", "").strip()
            logger.warning(
                "request_id=%s stage=clamav verdict=infected signature=%s elapsed_ms=%s",
                request_id,
                sig or "unknown",
                elapsed_ms,
            )
            return ClamAVResult(status="infected", signature=sig or None)
        logger.error(
            "request_id=%s stage=clamav verdict=error reason=unexpected_response elapsed_ms=%s response=%s",
            request_id,
            elapsed_ms,
            line,
        )
        return ClamAVResult(status="error", error=f"unexpected_response:{line}")
    except Exception as e:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        logger.exception(
            "request_id=%s stage=clamav verdict=error elapsed_ms=%s error=%s",
            request_id,
            elapsed_ms,
            e,
        )
        return ClamAVResult(status="error", error=str(e))


app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.post("/analyze")
def analyze():
    started = time.perf_counter()

    body = request.get_json(silent=True) or {}
    path = body.get("path")
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]

    def finish(
        *,
        payload,
        http_status,
        event_type,
        severity,
        outcome,
        verdict,
        reason="",
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
    ):
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        emit_analyzer_log(
            event_type=event_type,
            severity=severity,
            request_id=request_id,
            status=http_status,
            outcome=outcome,
            verdict=verdict,
            reason=reason,
            path=path,
            path_allowed=path_allowed,
            file_size_bytes=file_size_bytes,
            file_hash_sha256=file_hash_sha256,
            clamav_status=clamav_status,
            clamav_signature=clamav_signature,
            clamav_error=clamav_error,
            qpdf_ok=qpdf_ok,
            qpdf_warnings=qpdf_warnings,
            qpdf_error=qpdf_error,
            pdfid_flags=pdfid_flags,
            elapsed_ms=elapsed_ms,
        )

        return jsonify(payload), http_status

    if not isinstance(path, str) or not path:
        return finish(
            payload={
                "ok": False,
                "reason": "missing_path",
                "request_id": request_id,
            },
            http_status=400,
            event_type="analyzer.analysis_rejected",
            severity="medium",
            outcome="denied",
            verdict="reject",
            reason="missing_path",
            path_allowed=False,
        )

    path_allowed = _is_under_root(path, STAGING_ROOT)

    if not path_allowed:
        return finish(
            payload={
                "ok": False,
                "reason": "path_not_allowed",
                "request_id": request_id,
            },
            http_status=400,
            event_type="analyzer.analysis_rejected",
            severity="high",
            outcome="denied",
            verdict="reject",
            reason="path_not_allowed",
            path_allowed=False,
        )

    if not os.path.exists(path):
        return finish(
            payload={
                "ok": False,
                "reason": "file_not_found",
                "request_id": request_id,
            },
            http_status=404,
            event_type="analyzer.analysis_rejected",
            severity="medium",
            outcome="denied",
            verdict="reject",
            reason="file_not_found",
            path_allowed=True,
        )

    file_size_bytes = os.path.getsize(path)

    clam = clamd_instream_scan(path, request_id)

    if clam.status == "infected":
        return finish(
            payload={
                "ok": False,
                "reason": "malware_detected",
                "clamav_status": clam.status,
                "clamav_signature": clam.signature,
                "request_id": request_id,
            },
            http_status=400,
            event_type="analyzer.analysis_rejected",
            severity="high",
            outcome="denied",
            verdict="reject",
            reason="malware_detected",
            path_allowed=True,
            file_size_bytes=file_size_bytes,
            clamav_status=clam.status,
            clamav_signature=clam.signature,
        )

    if clam.status == "error":
        return finish(
            payload={
                "ok": False,
                "reason": "clamav_error",
                "clamav_status": clam.status,
                "clamav_error": clam.error,
                "request_id": request_id,
            },
            http_status=502,
            event_type="analyzer.analysis_failed",
            severity="error",
            outcome="failed",
            verdict="error",
            reason="clamav_error",
            path_allowed=True,
            file_size_bytes=file_size_bytes,
            clamav_status=clam.status,
            clamav_error=clam.error,
        )

    qpdf_ok, qpdf_warn_or_err = qpdf_check(path, request_id)
    flags = pdfid_like_flags(path)

    suspicious = (
        flags.get("/JS", 0) > 0
        or flags.get("/JavaScript", 0) > 0
        or flags.get("/Launch", 0) > 0
        or flags.get("/OpenAction", 0) > 0
        or flags.get("/EmbeddedFile", 0) > 0
    )

    if not qpdf_ok:
        return finish(
            payload={
                "ok": False,
                "reason": "qpdf_failed",
                "qpdf_ok": False,
                "qpdf_error": qpdf_warn_or_err,
                "pdfid_flags": flags,
                "clamav_status": clam.status,
                "request_id": request_id,
            },
            http_status=400,
            event_type="analyzer.analysis_rejected",
            severity="high",
            outcome="denied",
            verdict="reject",
            reason="qpdf_failed",
            path_allowed=True,
            file_size_bytes=file_size_bytes,
            clamav_status=clam.status,
            qpdf_ok=False,
            qpdf_error=qpdf_warn_or_err,
            pdfid_flags=flags,
        )

    if suspicious:
        return finish(
            payload={
                "ok": False,
                "reason": "pdfid_policy_reject",
                "qpdf_ok": True,
                "pdfid_flags": flags,
                "clamav_status": clam.status,
                "request_id": request_id,
            },
            http_status=400,
            event_type="analyzer.analysis_rejected",
            severity="high",
            outcome="denied",
            verdict="reject",
            reason="pdfid_policy_reject",
            path_allowed=True,
            file_size_bytes=file_size_bytes,
            clamav_status=clam.status,
            qpdf_ok=True,
            pdfid_flags=flags,
        )

    digest = sha256_file(path)
    st = os.stat(path)

    return finish(
        payload={
            "ok": True,
            "sha256": digest,
            "size_bytes": st.st_size,
            "detected_mime_type": "application/pdf",
            "scanned_at": int(time.time()),
            "qpdf_ok": True,
            "qpdf_warnings": qpdf_warn_or_err or None,
            "pdfid_flags": flags,
            "clamav_status": clam.status,
            "request_id": request_id,
        },
        http_status=200,
        event_type="analyzer.analysis_accepted",
        severity="info",
        outcome="success",
        verdict="accept",
        reason="",
        path_allowed=True,
        file_size_bytes=st.st_size,
        file_hash_sha256=digest,
        clamav_status=clam.status,
        qpdf_ok=True,
        qpdf_warnings=qpdf_warn_or_err or None,
        pdfid_flags=flags,
    )


if __name__ == "__main__":
    # Bind on all interfaces for Docker networking
    app.run(host="0.0.0.0", port=9000)

