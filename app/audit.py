import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from fastapi import Request
from google.cloud import firestore


DEFAULT_TTL_DAYS = int(os.getenv("AUDIT_TTL_DAYS", "30"))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def ttl_utc(days: int = DEFAULT_TTL_DAYS) -> datetime:
    return now_utc() + timedelta(days=days)


def _safe_str(v: Any, max_len: int = 512) -> str:
    try:
        s = str(v)
        return s if len(s) <= max_len else s[:max_len] + "…"
    except Exception:
        return "<unstringifiable>"


def write_audit_log(
    db: firestore.Client,
    *,
    event_type: str,
    request: Optional[Request] = None,
    status_code: Optional[int] = None,
    actor_uid: Optional[str] = None,
    actor_role: Optional[str] = None,
    key_id: Optional[str] = None,
    violation_type: Optional[str] = None,
    duration_ms: Optional[float] = None,
    detail: Optional[Dict[str, Any]] = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> str:
    """
    Writes an audit log entry to Firestore collection: audit_logs
    - Exception-safe: never raises (returns log_id best-effort).
    - TTL: expires_at_utc field (Firestore TTL policy should target this).
    """
    log_id = uuid.uuid4().hex[:20]

    doc: Dict[str, Any] = {
        "event_type": event_type,
        "ts": now_utc(),
        "expires_at_utc": ttl_utc(ttl_days),
    }

    if request is not None:
        # request_id propagated by middleware (fallback to header if missing)
        req_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-Id")
        if req_id:
            doc["request_id"] = _safe_str(req_id, 64)

        doc["method"] = request.method
        doc["path"] = request.url.path
        doc["query"] = _safe_str(request.url.query, 2048) if request.url.query else ""

        # Best-effort client IP (Cloud Run behind proxy: prefer X-Forwarded-For)
        xff = request.headers.get("X-Forwarded-For", "")
        ip = xff.split(",")[0].strip() if xff else (request.client.host if request.client else "")
        doc["ip"] = _safe_str(ip, 128)

        ua = request.headers.get("User-Agent", "")
        if ua:
            doc["user_agent"] = _safe_str(ua, 512)

    if status_code is not None:
        doc["status_code"] = int(status_code)

    if duration_ms is not None:
        # store as float (ms)
        doc["duration_ms"] = float(duration_ms)

    if actor_uid:
        doc["actor_uid"] = _safe_str(actor_uid, 128)

    if actor_role:
        doc["actor_role"] = _safe_str(actor_role, 64)

    if key_id:
        doc["key_id"] = _safe_str(key_id, 128)

    if violation_type:
        doc["violation_type"] = _safe_str(violation_type, 64)

    if detail:
        # keep it bounded; don't store secrets
        doc["detail"] = detail

    try:
        db.collection("audit_logs").document(log_id).set(doc)
    except Exception as e:
        # Never break requests for audit write failures.
        print(
            {
                "type": "audit_write_failed",
                "event_type": event_type,
                "log_id": log_id,
                "error": _safe_str(e, 1024),
                "utc": now_utc().isoformat(),
            }
        )

    return log_id