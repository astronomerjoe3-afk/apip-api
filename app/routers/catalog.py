from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.audit import write_audit_log
from app.common import get_client_ip, is_missing_index_error
from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq
from app.dependencies import require_authenticated_user

router = APIRouter(tags=["catalog"])


@router.get("/curricula")
def get_curricula(user=Depends(require_authenticated_user)):
    db = get_firestore_client()
    docs = db.collection("curricula").stream()
    result: List[Dict[str, Any]] = []

    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        result.append(data)

    return {"ok": True, "curricula": result}


@router.get("/modules")
def get_modules(
    curriculum_id: Optional[str] = Query(None),
    user=Depends(require_authenticated_user),
):
    db = get_firestore_client()
    query_ref = db.collection("modules")

    if curriculum_id:
        query_ref = where_eq(query_ref, "curriculum_id", curriculum_id)

    docs = query_ref.stream()
    result: List[Dict[str, Any]] = []

    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        result.append(data)

    return {"ok": True, "modules": result}


@router.get("/modules/{module_id}")
def get_module(module_id: str, user=Depends(require_authenticated_user)):
    db = get_firestore_client()
    doc = db.collection("modules").document(module_id).get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Module not found")

    data = doc.to_dict() or {}
    data["id"] = doc.id
    return {"ok": True, "module": data}


@router.get("/modules/{module_id}/lessons")
def get_module_lessons(module_id: str, request: Request, user=Depends(require_authenticated_user)):
    db = get_firestore_client()
    warnings: List[str] = []
    lessons: List[Dict[str, Any]] = []

    try:
        docs = (
            where_eq(db.collection("lessons"), "module_id", module_id)
            .order_by("sequence")
            .stream()
        )
        for d in docs:
            data = d.to_dict() or {}
            data["id"] = d.id
            lessons.append(data)
    except Exception as e:
        if is_missing_index_error(e):
            warnings.append(f"lessons_ordering_fallback_missing_index: {str(e)[:200]}")
            try:
                docs = where_eq(db.collection("lessons"), "module_id", module_id).stream()
                for d in docs:
                    data = d.to_dict() or {}
                    data["id"] = d.id
                    lessons.append(data)
                lessons.sort(key=lambda x: int(x.get("sequence", 10**9) or 10**9))
            except Exception as e2:
                raise HTTPException(status_code=500, detail=f"Failed to load lessons: {str(e2)[:200]}")
        else:
            raise HTTPException(status_code=500, detail=f"Failed to load lessons: {str(e)[:200]}")

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


@router.get("/modules/{module_id}/lessons/{lesson_id}")
def get_module_lesson(
    module_id: str,
    lesson_id: str,
    request: Request,
    user=Depends(require_authenticated_user),
):
    db = get_firestore_client()
    normalized = lesson_id.replace("-", "_")

    # 1) Try direct document lookup
    doc = db.collection("lessons").document(normalized).get()
    if doc.exists:
        data = doc.to_dict() or {}
        if data.get("module_id") == module_id:
            data["id"] = doc.id
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
                details={"module_id": module_id, "lesson_id": normalized, "lookup": "doc_id"},
            )
            return {"ok": True, "lesson": data}

    # 2) Fallback query by field values
    qs = (
        where_eq(where_eq(db.collection("lessons"), "module_id", module_id), "lesson_id", normalized)
        .limit(1)
        .stream()
    )

    hit = None
    for d in qs:
        hit = d
        break

    if not hit:
        raise HTTPException(status_code=404, detail="Lesson not found")

    data = hit.to_dict() or {}
    data["id"] = hit.id

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
        details={"module_id": module_id, "lesson_id": normalized, "lookup": "field_query"},
    )

    return {"ok": True, "lesson": data}


@router.get("/sim-labs/{lab_id}")
def get_sim_lab(lab_id: str, user=Depends(require_authenticated_user)):
    db = get_firestore_client()
    doc = db.collection("sim_labs").document(lab_id).get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Simulation lab not found")

    data = doc.to_dict() or {}
    data["id"] = doc.id
    return {"ok": True, "sim_lab": data}
