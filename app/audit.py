# app/audit.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from google.cloud import firestore


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_audit_log(
    db: firestore.Client,
    *,
    event_type: str,
    actor_uid: Optional[str] = None,
    actor_email: Optional[str] = None,
    role: Optional[str] = None,
    key_id: Optional[str] = None,
    path: Optional[str] = None,
    method: Optional[str] = None,
    status: Optional[int] = None,
    request_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Writes a single audit log entry to Firestore: audit_logs/{log_id}

    Design goals:
    - safe defaults (no secrets)
    - stable schema
    - compatible with Cloud Run + FastAPI request-id tracing
    """
    doc: Dict[str, Any] = {
        "event_type": event_type,
        "utc": _utc_now_iso(),
    }

    if actor_uid is not None:
        doc["actor_uid"] = actor_uid
    if actor_email is not None:
        doc["actor_email"] = actor_email
    if role is not None:
        doc["role"] = role

    if key_id is not None:
        doc["key_id"] = key_id

    if path is not None:
        doc["path"] = path
    if method is not None:
        doc["method"] = method
    if status is not None:
        doc["status"] = int(status)

    if request_id is not None:
        doc["request_id"] = request_id
    if ip is not None:
        doc["ip"] = ip
    if user_agent is not None:
        doc["user_agent"] = user_agent

    if extra:
        # Ensure the payload stays JSON-ish and reasonably sized (Firestore limit is 1 MiB per doc).
        doc["extra"] = extra

    ref = db.collection("audit_logs").document()
    ref.set(doc)
    return ref.id


def audit_from_request(
    request,
    *,
    event_type: str,
    db: firestore.Client,
    actor_uid: Optional[str] = None,
    actor_email: Optional[str] = None,
    role: Optional[str] = None,
    key_id: Optional[str] = None,
    status: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Convenience wrapper when you have a FastAPI Request available.
    """
    request_id = getattr(getattr(request, "state", None), "request_id", None)
    headers = getattr(request, "headers", {}) or {}

    ip = None
    try:
        # Prefer X-Forwarded-For if present
        xff = headers.get("x-forwarded-for")
        if xff:
            ip = xff.split(",")[0].strip()
        else:
            client = getattr(request, "client", None)
            ip = getattr(client, "host", None)
    except Exception:
        ip = None

    ua = None
    try:
        ua = headers.get("user-agent")
    except Exception:
        ua = None

    return write_audit_log(
        db,
        event_type=event_type,
        actor_uid=actor_uid,
        actor_email=actor_email,
        role=role,
        key_id=key_id,
        path=str(getattr(getattr(request, "url", None), "path", None) or ""),
        method=str(getattr(request, "method", None) or ""),
        status=status,
        request_id=request_id,
        ip=ip,
        user_agent=ua,
        extra=extra,
    )