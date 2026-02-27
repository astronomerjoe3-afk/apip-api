# app/audit.py
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from google.cloud import firestore


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe(v: Any) -> Any:
    """
    Make values Firestore-safe and JSON-ish.
    """
    try:
        # Firestore can store many native types, but keep it safe for logs.
        if isinstance(v, (str, int, float, bool)) or v is None:
            return v
        if isinstance(v, dict):
            return {str(k): _safe(val) for k, val in v.items()}
        if isinstance(v, list):
            return [_safe(x) for x in v]
        return str(v)
    except Exception:
        return str(v)


@dataclass(frozen=True)
class AuditEvent:
    # Stable, query-friendly schema
    event_type: str
    utc: str

    actor_uid: Optional[str]
    actor_email: Optional[str]
    role: Optional[str]  # student / instructor / admin / service

    request_id: Optional[str]
    path: str
    method: str
    status: Optional[int]

    ip: Optional[str]
    user_agent: Optional[str]

    key_id: Optional[str]
    details: Dict[str, Any]


def write_audit_log(
    *,
    event_type: str,
    actor_uid: Optional[str],
    actor_email: Optional[str] = None,
    role: Optional[str] = None,
    key_id: Optional[str] = None,
    path: str,
    method: str,
    status: Optional[int],
    request_id: Optional[str],
    ip: Optional[str],
    user_agent: Optional[str],
    details: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    Best-effort audit log write to Firestore collection: audit_logs

    IMPORTANT:
    - Must never raise (observability must not break prod).
    - Returns document id if write succeeds, else None.
    """
    try:
        db = firestore.Client()
        ev = AuditEvent(
            event_type=str(event_type),
            utc=utc_now(),
            actor_uid=actor_uid,
            actor_email=actor_email,
            role=role,
            request_id=request_id,
            path=str(path),
            method=str(method),
            status=status,
            ip=ip,
            user_agent=user_agent,
            key_id=key_id,
            details=_safe(details or {}),
        )

        doc_ref = db.collection("audit_logs").document()
        doc_ref.set(asdict(ev))
        return doc_ref.id
    except Exception:
        # Never block the request path.
        return None