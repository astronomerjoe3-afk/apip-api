from datetime import datetime, timezone
from typing import Optional
import uuid
import traceback

from google.cloud import firestore

# -------------------------------------------------------
# Firestore Client (singleton)
# -------------------------------------------------------

_db = firestore.Client()


# -------------------------------------------------------
# Safe Audit Writer
# -------------------------------------------------------

def write_audit_log(
    *,
    event_type: str,
    actor_uid: Optional[str] = None,
    key_id: Optional[str] = None,
    path: Optional[str] = None,
    method: Optional[str] = None,
    status: Optional[int] = None,
    request_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    """
    Writes a security / operational audit log entry.

    IMPORTANT:
    - This function must NEVER raise.
    - Audit failures must not break request handling.
    """

    try:
        log_id = str(uuid.uuid4())

        doc = {
            "event_type": event_type,
            "actor_uid": actor_uid,
            "key_id": key_id,
            "path": path,
            "method": method,
            "status": status,
            "request_id": request_id,
            "ip": ip,
            "user_agent": user_agent,
            "metadata": metadata or {},
            "utc": datetime.now(timezone.utc),
        }

        _db.collection("audit_logs").document(log_id).set(doc)

        # Structured console log (Cloud Run JSON ingestion)
        print({
            "type": "audit_log_written",
            "event_type": event_type,
            "request_id": request_id,
            "status": status,
            "utc": doc["utc"].isoformat(),
        })

    except Exception as e:
        # NEVER allow audit to break app logic
        print({
            "type": "audit_log_error",
            "error": str(e),
            "trace": traceback.format_exc(),
            "utc": datetime.now(timezone.utc).isoformat(),
        })


# -------------------------------------------------------
# Helper Event Wrappers (optional convenience)
# -------------------------------------------------------

def audit_rate_limit_violation(
    *,
    actor_uid: Optional[str],
    key_id: Optional[str],
    path: str,
    method: str,
    status: int,
    request_id: Optional[str],
    ip: Optional[str],
    user_agent: Optional[str],
    violation_type: str,
):
    write_audit_log(
        event_type="rate_limit_violation",
        actor_uid=actor_uid,
        key_id=key_id,
        path=path,
        method=method,
        status=status,
        request_id=request_id,
        ip=ip,
        user_agent=user_agent,
        metadata={
            "violation_type": violation_type
        }
    )


def audit_admin_action(
    *,
    actor_uid: Optional[str],
    action: str,
    path: str,
    method: str,
    status: int,
    request_id: Optional[str],
    ip: Optional[str],
    user_agent: Optional[str],
    metadata: Optional[dict] = None,
):
    write_audit_log(
        event_type="admin_action",
        actor_uid=actor_uid,
        key_id=None,
        path=path,
        method=method,
        status=status,
        request_id=request_id,
        ip=ip,
        user_agent=user_agent,
        metadata={
            "action": action,
            **(metadata or {})
        }
    )