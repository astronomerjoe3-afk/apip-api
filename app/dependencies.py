from typing import Any, Dict

from fastapi import HTTPException, Request

from app.core.config import settings
from app.firebase_admin_init import verify_id_token


LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _get_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing/invalid Authorization header")
    return parts[1].strip()


def _local_dev_student(request: Request) -> Dict[str, Any] | None:
    if not settings.enable_local_dev_student:
        return None

    client = request.client.host if request.client else ""
    host = (client or "").strip().lower()
    if host not in LOOPBACK_HOSTS:
        return None

    return {
        "uid": settings.local_dev_student_uid,
        "email": settings.local_dev_student_email,
        "email_verified": True,
        "role": "student",
        "claims": {
            "uid": settings.local_dev_student_uid,
            "email": settings.local_dev_student_email,
            "role": "student",
            "dev_mode": True,
        },
    }


def require_authenticated_user(request: Request) -> Dict[str, Any]:
    """
    Validates Firebase ID token and returns normalized identity dict.
    Expects a custom claim: role in {"student","instructor","admin"}.
    """
    local_user = _local_dev_student(request)
    if local_user is not None:
        return local_user

    token = _get_bearer_token(request)

    try:
        decoded = verify_id_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    uid = decoded.get("uid") or decoded.get("user_id") or decoded.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Token missing uid")

    role = decoded.get("role")
    if not role:
        # Safer default: deny if role claim missing (avoid accidental privilege)
        raise HTTPException(status_code=403, detail="Missing role claim")

    return {
        "uid": uid,
        "email": decoded.get("email"),
        "email_verified": decoded.get("email_verified"),
        "role": role,
        "claims": decoded,
    }


def require_admin(request: Request) -> Dict[str, Any]:
    user = require_authenticated_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def require_instructor_or_admin(request: Request) -> Dict[str, Any]:
    user = require_authenticated_user(request)
    if user.get("role") not in ("instructor", "admin"):
        raise HTTPException(status_code=403, detail="Instructor/Admin role required")
    return user
