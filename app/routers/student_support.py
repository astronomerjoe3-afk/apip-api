from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from google.cloud import firestore

from app.audit import write_audit_log
from app.common import get_client_ip, normalize_module_id, utc_now
from app.db.firestore import get_firestore_client
from app.dependencies import require_authenticated_user, require_instructor_or_admin
from app.schemas.support import HelpRequestCreateIn, HelpRequestCreateResponse, HelpRequestListResponse

router = APIRouter(tags=["student-support"])


def _support_collection():
    return get_firestore_client().collection("student_help_requests")


def _trimmed(value: str | None, *, max_len: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:max_len]


def _summary(doc_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": doc_id,
        "category": str(payload.get("category") or "general"),
        "status": str(payload.get("status") or "open"),
        "subject": str(payload.get("subject") or ""),
        "message": str(payload.get("message") or ""),
        "module_id": _trimmed(payload.get("module_id"), max_len=32),
        "module_title": _trimmed(payload.get("module_title"), max_len=160),
        "lesson_id": _trimmed(payload.get("lesson_id"), max_len=32),
        "lesson_title": _trimmed(payload.get("lesson_title"), max_len=160),
        "page_path": _trimmed(payload.get("page_path"), max_len=240),
        "created_utc": _trimmed(payload.get("created_utc"), max_len=64),
        "updated_utc": _trimmed(payload.get("updated_utc"), max_len=64),
        "student_uid": _trimmed(payload.get("student_uid"), max_len=128),
        "student_email": _trimmed(payload.get("student_email"), max_len=160),
        "student_role": _trimmed(payload.get("student_role"), max_len=32),
    }


@router.post("/student/help-requests", response_model=HelpRequestCreateResponse)
def create_help_request(
    request: Request,
    user=Depends(require_authenticated_user),
    payload: HelpRequestCreateIn = Body(...),
):
    uid = str((user or {}).get("uid") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    now = utc_now()
    normalized_module_id = normalize_module_id(payload.module_id) if payload.module_id else None
    module_title = _trimmed(payload.module_title, max_len=160)
    lesson_id = _trimmed(payload.lesson_id, max_len=32)
    lesson_title = _trimmed(payload.lesson_title, max_len=160)
    page_path = _trimmed(payload.page_path, max_len=240)
    if page_path and not page_path.startswith("/"):
        page_path = "/" + page_path

    subject = _trimmed(payload.subject, max_len=160)
    message = _trimmed(payload.message, max_len=2000)
    category = _trimmed(payload.category, max_len=80) or "general"
    if not subject or not message:
        raise HTTPException(status_code=422, detail="Subject and message are required")

    doc_ref = _support_collection().document()
    doc = {
        "student_uid": uid,
        "student_email": _trimmed((user or {}).get("email"), max_len=160),
        "student_role": _trimmed((user or {}).get("role"), max_len=32),
        "category": category,
        "subject": subject,
        "message": message,
        "module_id": normalized_module_id,
        "module_title": module_title,
        "lesson_id": lesson_id,
        "lesson_title": lesson_title,
        "page_path": page_path,
        "status": "open",
        "created_utc": now,
        "updated_utc": now,
    }
    doc_ref.set(doc)

    write_audit_log(
        event_type="student.help_request.create",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/student/help-requests",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "help_request_id": doc_ref.id,
            "module_id": normalized_module_id,
            "lesson_id": lesson_id,
            "category": category,
        },
    )

    return {"ok": True, "request": _summary(doc_ref.id, doc)}


@router.get("/instructor/help-requests", response_model=HelpRequestListResponse)
def list_help_requests(
    request: Request,
    user=Depends(require_instructor_or_admin),
    limit: int = Query(12, ge=1, le=100),
    status: str = Query("open"),
    module_id: str | None = Query(default=None),
):
    normalized_status = str(status or "open").strip().lower()
    normalized_module_id = normalize_module_id(module_id) if module_id else None

    query_limit = max(limit * 4, limit)
    documents: List[Dict[str, Any]] = []
    try:
        query = (
            _support_collection()
            .order_by("created_utc", direction=firestore.Query.DESCENDING)
            .limit(query_limit)
        )
        for snap in query.stream():
            data = snap.to_dict() or {}
            data["id"] = snap.id
            documents.append(data)
    except Exception:
        for snap in _support_collection().stream():
            data = snap.to_dict() or {}
            data["id"] = snap.id
            documents.append(data)
        documents.sort(key=lambda item: str(item.get("created_utc") or ""), reverse=True)

    inquiries: List[Dict[str, Any]] = []
    for item in documents:
        item_status = str(item.get("status") or "open").strip().lower()
        item_module_id = normalize_module_id(item.get("module_id")) if item.get("module_id") else None
        if normalized_status != "all" and item_status != normalized_status:
            continue
        if normalized_module_id and item_module_id != normalized_module_id:
            continue
        inquiries.append(_summary(str(item.get("id") or ""), item))
        if len(inquiries) >= limit:
            break

    write_audit_log(
        event_type="instructor.help_request.read",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/instructor/help-requests",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "returned": len(inquiries),
            "status": normalized_status,
            "module_id": normalized_module_id,
        },
    )

    return {"ok": True, "inquiries": inquiries}
