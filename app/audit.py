from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Request
from google.cloud import firestore


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now_dt().isoformat()


def get_client_ip(request: Request) -> Optional[str]:
    """
    Cloud Run / proxies often set X-Forwarded-For: client, proxy1, proxy2
    Prefer first IP.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip() or None
    return request.client.host if request.client else None


def write_audit_event(
    db: firestore.Client,
    *,
    event_type: str,
    request: Optional[Request] = None,
    status_code: Optional[int] = None,
    actor_uid: Optional[str] = None,
    actor_email: Optional[str] = None,
    key_id: Optional[str] = None,
    request_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Best-effort audit logging. Never raise.
    Stores:
      - ts (datetime, for range queries)
      - utc (string)
      - event_type
      - actor_* (for Firebase admin actions)
      - key_id (for API key actions)
      - request metadata (path/method/ip/ua)
      - status_code
      - request_id
      - extra (small dict)
    """
    try:
        payload: Dict[str, Any] = {
            "ts": utc_now_dt(),
            "utc": utc_now_iso(),
            "event_type": event_type,
            "status_code": status_code,
            "actor_uid": actor_uid,
            "actor_email": actor_email,
            "key_id": key_id,
            "request_id": request_id,
        }

        if request is not None:
            payload.update(
                {
                    "path": request.url.path,
                    "method": request.method,
                    "ip": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent"),
                }
            )

        if extra:
            # Keep "extra" bounded; don't dump huge objects here
            payload["extra"] = extra

        db.collection("audit_logs").add(payload)
    except Exception:
        # Must never impact request handling
        return