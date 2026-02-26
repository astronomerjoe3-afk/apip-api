import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request
from google.cloud import firestore
import firebase_admin
from firebase_admin import auth

# Firestore client (singleton)
_db = firestore.Client()

# Ensure Firebase is initialized (your project already uses firebase_admin_init.py,
# but this makes deps safe even if imported first)
if not firebase_admin._apps:
    firebase_admin.initialize_app()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _get_bearer_token(request: Request) -> str:
    """
    Extracts Bearer token from Authorization header.
    """
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization: Bearer <token>")
    return parts[1].strip()


def require_authenticated_user(request: Request) -> Dict[str, Any]:
    """
    Verifies Firebase ID token and returns decoded claims.
    """
    token = _get_bearer_token(request)

    try:
        decoded = auth.verify_id_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired Firebase ID token")

    # Basic expected fields
    uid = decoded.get("uid") or decoded.get("user_id") or decoded.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Token missing uid")

    return decoded


def require_admin(request: Request) -> Dict[str, Any]:
    """
    Requires Firebase custom claim role=admin OR bootstrap admin UID (break-glass).
    """
    decoded = require_authenticated_user(request)

    role = decoded.get("role")
    uid = decoded.get("uid") or decoded.get("user_id") or decoded.get("sub")

    # Optional: allow a bootstrap UID from env for break-glass
    bootstrap_uid = os.getenv("BOOTSTRAP_ADMIN_UID", "").strip()

    if role == "admin":
        return decoded

    if bootstrap_uid and uid == bootstrap_uid:
        # Treat as admin
        decoded["role"] = "admin"
        return decoded

    raise HTTPException(status_code=403, detail="Admin role required")


def require_instructor_or_admin(request: Request) -> Dict[str, Any]:
    """
    Role gate for instructor dashboards.
    """
    decoded = require_authenticated_user(request)
    role = decoded.get("role")

    if role in ("admin", "instructor"):
        return decoded

    # bootstrap admin UID also qualifies
    uid = decoded.get("uid") or decoded.get("user_id") or decoded.get("sub")
    bootstrap_uid = os.getenv("BOOTSTRAP_ADMIN_UID", "").strip()
    if bootstrap_uid and uid == bootstrap_uid:
        decoded["role"] = "admin"
        return decoded

    raise HTTPException(status_code=403, detail="Instructor or admin role required")


def require_student_or_self(request: Request, uid: str) -> Dict[str, Any]:
    """
    Enforces that a student can only access their own uid, while instructors/admins can access any.
    Useful for /progress/{uid}/..., /attempts/{uid}/...
    """
    decoded = require_authenticated_user(request)
    role = decoded.get("role")

    token_uid = decoded.get("uid") or decoded.get("user_id") or decoded.get("sub")
    if not token_uid:
        raise HTTPException(status_code=401, detail="Token missing uid")

    if role in ("admin", "instructor"):
        return decoded

    if role == "student" and token_uid == uid:
        return decoded

    # bootstrap admin UID also qualifies
    bootstrap_uid = os.getenv("BOOTSTRAP_ADMIN_UID", "").strip()
    if bootstrap_uid and token_uid == bootstrap_uid:
        decoded["role"] = "admin"
        return decoded

    raise HTTPException(status_code=403, detail="Forbidden: student can only access own resources")


# Small accessor if you ever need it elsewhere
def get_db() -> firestore.Client:
    return _db