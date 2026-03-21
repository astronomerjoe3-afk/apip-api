from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from google.cloud import firestore

from app.common import normalize_module_id
from app.db.firestore import get_firestore_client
from app.dependencies import require_authenticated_user  # enforces Authorization header

router = APIRouter(prefix="/modules", tags=["modules"])


def _module_ref(client: firestore.Client, module_id: str):
    return client.collection("modules").document(module_id)


@router.get("/{module_id}")
def get_module(module_id: str, _: Any = Depends(require_authenticated_user)) -> Dict[str, Any]:
    """
    Returns a single module document.
    """
    client = get_firestore_client()
    normalized_module_id = normalize_module_id(module_id)
    snap = _module_ref(client, normalized_module_id).get()
    resolved_module_id = normalized_module_id
    if not snap.exists and normalized_module_id != module_id:
        snap = _module_ref(client, module_id).get()
        resolved_module_id = module_id
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Module not found")

    doc = snap.to_dict() or {}
    doc.setdefault("id", resolved_module_id)
    return doc


def _read_lessons_top_level(client: firestore.Client, module_id: str) -> List[Dict[str, Any]]:
    """
    Preferred path (schema-agnostic): top-level lessons collection filtered by moduleId.
    """
    q = (
        client.collection("lessons")
        .where("moduleId", "==", module_id)
        .order_by("order")
    )
    out: List[Dict[str, Any]] = []
    for s in q.stream():
        d = s.to_dict() or {}
        d.setdefault("id", s.id)
        out.append(d)
    return out


def _read_lessons_top_level_any(client: firestore.Client, module_ids: List[str]) -> List[Dict[str, Any]]:
    for candidate in module_ids:
        lessons = _read_lessons_top_level(client, candidate)
        if lessons:
            return lessons
    return []


def _read_lessons_subcollection(client: firestore.Client, module_id: str) -> List[Dict[str, Any]]:
    """
    Fallback path: modules/{moduleId}/lessons subcollection.
    """
    q = _module_ref(client, module_id).collection("lessons").order_by("order")
    out: List[Dict[str, Any]] = []
    for s in q.stream():
        d = s.to_dict() or {}
        d.setdefault("id", s.id)
        out.append(d)
    return out


@router.get("/{module_id}/lessons")
def list_module_lessons(module_id: str, _: Any = Depends(require_authenticated_user)) -> List[Dict[str, Any]]:
    """
    Returns lessons for a module in a stable order.
    We prefer top-level `lessons` collection (moduleId filter) and fall back to subcollection.
    This guarantees the runner receives the new phases payload no matter which schema is used.
    """
    client = get_firestore_client()
    normalized_module_id = normalize_module_id(module_id)
    candidate_module_ids = [normalized_module_id]
    if normalized_module_id != module_id:
        candidate_module_ids.append(module_id)

    lessons = _read_lessons_top_level_any(client, candidate_module_ids)
    if lessons:
        return lessons

    # fallback
    for candidate in candidate_module_ids:
        lessons = _read_lessons_subcollection(client, candidate)
        if lessons:
            return lessons

    raise HTTPException(status_code=404, detail="No lessons found for module")


@router.get("/{module_id}/lessons/{lesson_id}")
def get_module_lesson(module_id: str, lesson_id: str, _: Any = Depends(require_authenticated_user)) -> Dict[str, Any]:
    """
    Debug-friendly endpoint. Tries top-level lessons/{lessonId} first, then subcollection.
    """
    client = get_firestore_client()
    normalized_module_id = normalize_module_id(module_id)
    candidate_module_ids = {normalized_module_id, module_id}

    # top-level
    snap = client.collection("lessons").document(lesson_id).get()
    if snap.exists:
        d = snap.to_dict() or {}
        lesson_module_id = normalize_module_id(d.get("moduleId") or d.get("module_id"))
        if lesson_module_id not in candidate_module_ids:
            raise HTTPException(status_code=404, detail="Lesson not found in this module")
        d.setdefault("id", lesson_id)
        return d

    # subcollection
    for candidate in candidate_module_ids:
        snap = _module_ref(client, candidate).collection("lessons").document(lesson_id).get()
        if snap.exists:
            d = snap.to_dict() or {}
            d.setdefault("id", lesson_id)
            return d

    raise HTTPException(status_code=404, detail="Lesson not found")
