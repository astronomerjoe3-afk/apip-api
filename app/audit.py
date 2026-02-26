# app/audit.py
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from google.cloud import firestore


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_audit_log(
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
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Best-effort audit logger.
    Writes one Firestore doc per event into: audit_logs/{log_id}

    IMPORTANT:
    - Never raise to caller (audit must not take down API).
    - Keep payload small (Firestore costs).
    """

    try:
        db = firestore.Client()

        log_id = str(uuid.uuid4())
        doc = {
            "event_type": event_type,
            "actor_uid": actor_uid,
            "actor_email": actor_email,
            "role": role,
            "key_id": key_id,
            "path": path,
            "method": method,
            "status": status,
            "request_id": request_id,
            "ip": ip,
            "user_agent": user_agent,
            "details": details or {},
            "utc": _utc_now(),
            "service": os.getenv("K_SERVICE"),
            "revision": os.getenv("K_REVISION"),
            "project_id": os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT"),
        }

        # Firestore server timestamp would be nice, but keep explicit utc as well.
        db.collection("audit_logs").document(log_id).set(doc)

    except Exception as e:
        # Best-effort: do not raise. Print to logs for diagnosis.
        print(
            {
                "type": "audit_log_error",
                "error": str(e),
                "event_type": event_type,
                "request_id": request_id,
                "utc": _utc_now(),
            }
        )