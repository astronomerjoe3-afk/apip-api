from __future__ import annotations

import datetime as dt
import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from google.cloud import firestore

from app.db.firestore import get_firestore_client


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _json_safe(obj: Any) -> Any:
    try:
        json.dumps(obj)
        return obj
    except Exception:
        return str(obj)


@dataclass(frozen=True)
class AuditEvent:
    # Schema-stable fields (lock these now to avoid rework later)
    event_type: str
    utc: str

    actor_uid: str | None
    actor_role: str | None  # student/instructor/admin/service
    key_id: str | None

    request_id: str | None
    path: str
    method: str
    status: int | None

    ip: str | None
    user_agent: str | None

    details: Mapping[str, Any]


def build_audit_event(
    *,
    event_type: str,
    path: str,
    method: str,
    status: int | None,
    request_id: str | None,
    actor_uid: str | None,
    actor_role: str | None,
    key_id: str | None,
    ip: str | None,
    user_agent: str | None,
    details: Mapping[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        utc=utc_now_iso(),
        actor_uid=actor_uid,
        actor_role=actor_role,
        key_id=key_id,
        request_id=request_id,
        path=path,
        method=method,
        status=status,
        ip=ip,
        user_agent=user_agent,
        details={k: _json_safe(v) for k, v in (details or {}).items()},
    )


def write_audit_event(event: AuditEvent) -> str | None:
    """
    Best-effort audit log write. Must never throw (observability should not break prod).
    Returns doc_id if written, else None.
    """
    try:
        client: firestore.Client = get_firestore_client()
        doc_ref = client.collection("audit_logs").document()
        payload = asdict(event)

        # Make it query-friendly
        payload["event_type"] = str(payload["event_type"])
        payload["path"] = str(payload["path"])
        payload["method"] = str(payload["method"])

        doc_ref.set(payload)
        return doc_ref.id
    except Exception:
        return None