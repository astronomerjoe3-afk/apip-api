from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request

from app.audit import write_audit_log
from app.common import get_client_ip, normalize_module_id
from app.dependencies import require_authenticated_user
from app.db.firestore import get_firestore_client
from app.schemas.student_progression import (
    StudentLessonProgressResponse,
    StudentModuleProgressResponse,
)
from app.services.monetization_service import require_module_access
from app.services.student_progression_service import (
    get_student_lesson_progress,
    get_student_module_progress,
)

router = APIRouter(tags=["student-progression"])


def _normalized_lesson_id(value: str) -> str:
    return str(value or "").replace("-", "_")


def _event_lesson_id(event: Dict[str, Any]) -> str:
    details = event.get("details")
    if not isinstance(details, dict):
        return ""
    return _normalized_lesson_id(str(details.get("lesson_id") or ""))


def _restart_student_lesson_progress(uid: str, module_id: str, lesson_id: str) -> Dict[str, Any]:
    db = get_firestore_client()
    normalized_lesson_id = _normalized_lesson_id(lesson_id)
    docs = (
        db.collection("progress_events")
        .where("uid", "==", uid)
        .where("module_id", "==", module_id)
        .stream()
    )
    matching_refs = []
    for doc in docs:
        data = doc.to_dict() or {}
        if _event_lesson_id(data) == normalized_lesson_id:
            matching_refs.append(doc.reference)
    deleted_events = 0
    for index in range(0, len(matching_refs), 400):
        batch = db.batch()
        batch_refs = matching_refs[index : index + 400]
        for ref in batch_refs:
            batch.delete(ref)
        batch.commit()
        deleted_events += len(batch_refs)
    db.collection("progress").document(uid).collection("modules").document(module_id).collection("lessons").document(normalized_lesson_id).delete()
    return {
        "module_id": module_id,
        "lesson_id": normalized_lesson_id,
        "deleted_progress_events": deleted_events,
    }


def _restart_student_module_progress(uid: str, module_id: str) -> Dict[str, Any]:
    db = get_firestore_client()
    docs = (
        db.collection("progress_events")
        .where("uid", "==", uid)
        .where("module_id", "==", module_id)
        .stream()
    )
    matching_refs = [doc.reference for doc in docs]
    deleted_events = 0
    for index in range(0, len(matching_refs), 400):
        batch = db.batch()
        batch_refs = matching_refs[index : index + 400]
        for ref in batch_refs:
            batch.delete(ref)
        batch.commit()
        deleted_events += len(batch_refs)
    lesson_docs = (
        db.collection("progress")
        .document(uid)
        .collection("modules")
        .document(module_id)
        .collection("lessons")
        .stream()
    )
    lesson_refs = [doc.reference for doc in lesson_docs]
    for index in range(0, len(lesson_refs), 400):
        batch = db.batch()
        batch_refs = lesson_refs[index : index + 400]
        for ref in batch_refs:
            batch.delete(ref)
        batch.commit()
    return {
        "module_id": module_id,
        "deleted_progress_events": deleted_events,
    }


@router.get(
    "/student/modules/{module_id}/progress",
    response_model=StudentModuleProgressResponse,
)
def read_student_module_progress(
    module_id: str,
    request: Request,
    user=Depends(require_authenticated_user),
):
    normalized_module_id = normalize_module_id(module_id)
    uid = (user or {}).get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    require_module_access(uid, normalized_module_id, role=(user or {}).get("role"))
    payload = get_student_module_progress(uid=uid, module_id=normalized_module_id)

    write_audit_log(
        event_type="student.module.progress.read",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path=f"/student/modules/{normalized_module_id}/progress",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "module_id": normalized_module_id,
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
    normalized_module_id = normalize_module_id(module_id)
    uid = (user or {}).get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    require_module_access(uid, normalized_module_id, role=(user or {}).get("role"))
    payload = get_student_lesson_progress(uid=uid, module_id=normalized_module_id, lesson_id=lesson_id)

    write_audit_log(
        event_type="student.lesson.progress.read",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path=f"/student/modules/{normalized_module_id}/lessons/{lesson_id}/progress",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "module_id": normalized_module_id,
            "lesson_id": lesson_id,
            "completed": payload["lesson"]["completed"],
            "best_score": payload["lesson"]["best_score"],
        },
    )

    return {"ok": True, **payload}


@router.post("/student/modules/{module_id}/restart")
def restart_student_module(
    module_id: str,
    request: Request,
    user=Depends(require_authenticated_user),
):
    normalized_module_id = normalize_module_id(module_id)
    uid = (user or {}).get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    require_module_access(uid, normalized_module_id, role=(user or {}).get("role"))
    payload = _restart_student_module_progress(uid=uid, module_id=normalized_module_id)

    write_audit_log(
        event_type="student.module.progress.restart",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path=f"/student/modules/{normalized_module_id}/restart",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "module_id": normalized_module_id,
            "deleted_progress_events": payload["deleted_progress_events"],
        },
    )

    return {"ok": True, **payload}


@router.post("/student/modules/{module_id}/lessons/{lesson_id}/restart")
def restart_student_lesson(
    module_id: str,
    lesson_id: str,
    request: Request,
    user=Depends(require_authenticated_user),
):
    normalized_module_id = normalize_module_id(module_id)
    uid = (user or {}).get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    require_module_access(uid, normalized_module_id, role=(user or {}).get("role"))
    payload = _restart_student_lesson_progress(uid=uid, module_id=normalized_module_id, lesson_id=lesson_id)

    write_audit_log(
        event_type="student.lesson.progress.restart",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path=f"/student/modules/{normalized_module_id}/lessons/{lesson_id}/restart",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "module_id": normalized_module_id,
            "lesson_id": payload["lesson_id"],
            "deleted_progress_events": payload["deleted_progress_events"],
        },
    )

    return {"ok": True, **payload}
