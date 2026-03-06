from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.audit import write_audit_log
from app.common import get_client_ip
from app.dependencies import require_authenticated_user
from app.schemas.student_progression import (
    StudentLessonProgressResponse,
    StudentModuleProgressResponse,
)
from app.services.student_progression_service import (
    get_student_lesson_progress,
    get_student_module_progress,
)

router = APIRouter(tags=["student-progression"])


@router.get(
    "/student/modules/{module_id}/progress",
    response_model=StudentModuleProgressResponse,
)
def read_student_module_progress(
    module_id: str,
    request: Request,
    user=Depends(require_authenticated_user),
):
    uid = (user or {}).get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    payload = get_student_module_progress(uid=uid, module_id=module_id)

    write_audit_log(
        event_type="student.module.progress.read",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path=f"/student/modules/{module_id}/progress",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "module_id": module_id,
            "lesson_count": len(payload["lessons"]),
        },
    )

    return {"ok": True, **payload}


@router.get(
    "/student/modules/{module_id}/lessons/{lesson_id}/progress",
    response_model=StudentLessonProgressResponse,
)
def read_student_lesson_progress(
    module_id: str,
    lesson_id: str,
    request: Request,
    user=Depends(require_authenticated_user),
):
    uid = (user or {}).get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    payload = get_student_lesson_progress(uid=uid, module_id=module_id, lesson_id=lesson_id)

    write_audit_log(
        event_type="student.lesson.progress.read",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path=f"/student/modules/{module_id}/lessons/{lesson_id}/progress",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "module_id": module_id,
            "lesson_id": lesson_id,
            "completed": payload["lesson"]["completed"],
            "best_score": payload["lesson"]["best_score"],
        },
    )

    return {"ok": True, **payload}
