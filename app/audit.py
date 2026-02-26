import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from fastapi import Request
from google.cloud import firestore


def _now():
    return datetime.now(timezone.utc)


def _ttl() -> datetime:
    # Firestore TTL should be enabled on the "expires_at_utc" field in Console
    days = int(os.getenv("AUDIT_TTL_DAYS", "30"))
    return _now() + timedelta(days=days)


def _client_ip(request: Optional[Request]) -> Optional[str]:
    if not request:
        return None
    # Cloud Run behind LB sets X-Forwarded-For = client, proxy1, proxy2...
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


def write_audit_log(
    db: firestore.Client,
    *,
    event_type: str,
    request: Optional[Request] = None,
    status_code: Optional[int] = None,
    duration_ms: Optional[float] = None,
    actor_uid: Optional[str] = None,
    actor_role: Optional[str] = None,
    key_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Best-effort audit log writer. Never raises.
    Collection: audit_logs (top-level)
    TTL Field: expires_at_utc
    """
    try:
        doc: Dict[str, Any] = {
            "event_type": event_type,
            "ts": _now(),
            "expires_at_utc": _ttl(),
        }

        if request is not None:
            doc.update(
                {
                    "path": request.url.path,
                    "method": request.method,
                    "query": dict(request.query_params),
                    "request_id": getattr(request.state, "request_id", None)
                    or request.headers.get("X-Request-Id"),
                    "ip": _client_ip(request),
                    "user_agent": request.headers.get("User-Agent"),
                }
            )

        if status_code is not None:
            doc["status_code"] = int(status_code)
        if duration_ms is not None:
            doc["duration_ms"] = float(duration_ms)

        if actor_uid is not None:
            doc["actor_uid"] = actor_uid
        if actor_role is not None:
            doc["actor_role"] = actor_role
        if key_id is not None:
            doc["key_id"] = key_id

        if detail is not None:
            # Keep lean; avoid huge blobs
            doc["detail"] = detail

        db.collection("audit_logs").add(doc)
    except Exception:
        # Intentionally swallow; audit must not break requests
        return