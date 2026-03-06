from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, Request

from app.audit import write_audit_log
from app.common import get_client_ip
from app.dependencies import require_authenticated_user
from app.schemas.catalog import (
    CurriculaResponse,
    LessonResponse,
    LessonsResponse,
    ModuleResponse,
    ModulesResponse,
    SimLabResponse,
)
from app.services.catalog_service import (
    fetch_curricula,
    fetch_module,
    fetch_module_lesson,
    fetch_module_lessons,
    fetch_modules,
    fetch_sim_lab,
)

router = APIRouter(tags=["catalog"])


@router.get("/curricula", response_model=CurriculaResponse)
def get_curricula(user=Depends(require_authenticated_user)):
    result = fetch_curricula()
    return {"ok": True, "curricula": result}


@router.get("/modules", response_model=ModulesResponse)
def get_modules(
    curriculum_id: Optional[str] = Query(None),
    user=Depends(require_authenticated_user),
):
    result = fetch_modules(curriculum_id=curriculum_id)
    return {"ok": True, "modules": result}


@router.get("/modules/{module_id}", response_model=ModuleResponse)
def get_module(module_id: str, user=Depends(require_authenticated_user)):
    module = fetch_module(module_id)
    return {"ok": True, "module": module}


@router.get("/modules/{module_id}/lessons", response_model=LessonsResponse)
def get_module_lessons(module_id: str, request: Request, user=Depends(require_authenticated_user)):
    lessons, warnings = fetch_module_lessons(module_id)

    write_audit_log(
        event_type="catalog.module_lessons.read",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path=f"/modules/{module_id}/lessons",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"module_id": module_id, "returned": len(lessons), "warnings": warnings},
    )

    return {"ok": True, "lessons": lessons, "warnings": warnings}


@router.get("/modules/{module_id}/lessons/{lesson_id}", response_model=LessonResponse)
def get_module_lesson(
    module_id: str,
    lesson_id: str,
    request: Request,
    user=Depends(require_authenticated_user),
):
    lesson = fetch_module_lesson(module_id, lesson_id)
    normalized = lesson_id.replace("-", "_")

    write_audit_log(
        event_type="catalog.module_lesson.read",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path=f"/modules/{module_id}/lessons/{lesson_id}",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"module_id": module_id, "lesson_id": normalized},
    )

    return {"ok": True, "lesson": lesson}


@router.get("/sim-labs/{lab_id}", response_model=SimLabResponse)
def get_sim_lab(lab_id: str, user=Depends(require_authenticated_user)):
    lab = fetch_sim_lab(lab_id)
    return {"ok": True, "sim_lab": lab}
