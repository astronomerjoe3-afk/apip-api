from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.audit import write_audit_log
from app.common import get_client_ip
from app.dependencies import require_authenticated_user
from app.schemas.auth import SessionLoginRequest, SessionLoginResponse, SessionStatusResponse
from app.services.session_service import issue_session_from_firebase_id_token, revoke_session_token

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/session/login", response_model=SessionLoginResponse)
def login_session(payload: SessionLoginRequest, request: Request):
    result = issue_session_from_firebase_id_token(payload.id_token, request)
    user = result["user"]
    write_audit_log(
        event_type="auth.session.login",
        actor_uid=user.get("uid"),
        actor_email=user.get("email"),
        role=user.get("role"),
        path="/auth/session/login",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"auth_type": "firebase_exchange"},
    )
    return {"ok": True, **result}


@router.get("/session", response_model=SessionStatusResponse)
def current_session(user=Depends(require_authenticated_user)):
    return {
        "ok": True,
        "user": {
            "uid": (user or {}).get("uid"),
            "email": (user or {}).get("email"),
            "email_verified": (user or {}).get("email_verified"),
            "role": (user or {}).get("role"),
        },
    }


@router.post("/session/logout")
def logout_session(request: Request, user=Depends(require_authenticated_user)):
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        revoke_session_token(parts[1])

    write_audit_log(
        event_type="auth.session.logout",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/auth/session/logout",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"auth_type": (user or {}).get("auth_type")},
    )
    return {"ok": True}
