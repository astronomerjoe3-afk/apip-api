from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from app.audit import write_audit_log
from app.common import get_client_ip, utc_now
from app.dependencies import require_authenticated_user
from app.schemas.progress import ProgressEventIn, ProgressEventWriteResponse, ProgressMeResponse
from app.services.monetization_service import require_module_access
from app.services.progress_service import fetch_progress_me, process_progress_event

router = APIRouter(tags=["progress"])


@router.post("/progress/{module_id}/event", response_model=ProgressEventWriteResponse)
def post_progress_event(
    module_id: str,
    request: Request,
    user=Depends(require_authenticated_user),
    payload: ProgressEventIn = Body(...),
):
    uid = (user or {}).get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    require_module_access(uid, module_id, role=(user or {}).get("role"))
    result = process_progress_event(
        uid=uid,
        module_id=module_id,
        payload=payload.model_dump(),
        request_id=getattr(request.state, "request_id", None),
    )

    write_audit_log(
        event_type="progress.event.write",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=None,
        path=f"/progress/{module_id}/event",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "module_id": module_id,
            "event_id": result["event_id"],
            "stored_event": result["stored_event"],
        },
    )

    return result


@router.get("/progress/me", response_model=ProgressMeResponse)
def get_progress_me(
    request: Request,
    user=Depends(require_authenticated_user),
    limit_recent_events: int = Query(20, ge=0, le=50),
):
    uid = (user or {}).get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    result = fetch_progress_me(uid=uid, limit_recent_events=limit_recent_events)

    write_audit_log(
        event_type="progress.me.read",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=None,
        path="/progress/me",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "modules": len(result["modules"]),
            "recent_events": len(result["recent_events"]),
            "warnings": result["warnings"],
        },
    )

    return {
        "ok": True,
        "utc": utc_now(),
        "uid": uid,
        "role": (user or {}).get("role"),
        "warnings": result["warnings"],
        "mastery_map": result["mastery_map"],
        "modules": result["modules"],
        "recent_events": result["recent_events"],
    }