from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.audit import write_audit_log
from app.common import get_client_ip
from app.dependencies import require_authenticated_user
from app.schemas.student_runner import StudentRunnerLessonResponse
from app.services.student_runner_service import build_student_runner_contract

router = APIRouter(tags=["student-runner"])


@router.get(
    "/student/modules/{module_id}/lessons/{lesson_id}/runner",
    response_model=StudentRunnerLessonResponse,
)
def read_student_runner_contract(
    module_id: str,
    lesson_id: str,
    request: Request,
    user=Depends(require_authenticated_user),
):
    uid = (user or {}).get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    payload = build_student_runner_contract(uid=uid, module_id=module_id, lesson_id=lesson_id)

    write_audit_log(
        event_type="student.lesson.runner.read",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path=f"/student/modules/{module_id}/lessons/{lesson_id}/runner",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "module_id": module_id,
            "lesson_id": lesson_id,
            "next_recommended_action": payload["lesson"]["next_recommended_action"],
            "can_advance": payload["lesson"]["can_advance"],
        },
    )

    return {"ok": True, **payload}
