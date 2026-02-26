from typing import Any, Dict, Optional

from fastapi import HTTPException, Request
from app.firebase_admin_init import verify_id_token


def _get_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing/invalid Authorization header")
    return parts[1].strip()


def require_authenticated_user(request: Request) -> Dict[str, Any]:
    """
    Validates Firebase ID token and returns normalized identity dict.
    Expected custom claim: role in {"student","instructor","admin"} (admin already used by you)
    """
    token = _get_bearer_token(request)

    try:
        decoded = verify_id_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Normalize identity
    uid = decoded.get("uid") or decoded.get("user_id") or decoded.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Token missing uid")

    role = decoded.get("role") or decoded.get("customClaims", {}).get("role")
    # If role is absent, you can either default to student or deny.
    # For safety, deny access to protected endpoints without a role.
    if not role:
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


def require_student_or_self(request: Request, uid: str) -> Dict[str, Any]:
    user = require_authenticated_user(request)
    role = user.get("role")
    if role == "admin" or role == "instructor":
        return user
    if role == "student" and user.get("uid") == uid:
        return user
    raise HTTPException(status_code=403, detail="Not allowed")