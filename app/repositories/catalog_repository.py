from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq


def list_curricula() -> List[Dict[str, Any]]:
    db = get_firestore_client()
    docs = db.collection("curricula").stream()

    result: List[Dict[str, Any]] = []
    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        result.append(data)
    return result


def list_modules(curriculum_id: Optional[str] = None) -> List[Dict[str, Any]]:
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

    return result


def get_module_by_id(module_id: str) -> Optional[Dict[str, Any]]:
    db = get_firestore_client()
    doc = db.collection("modules").document(module_id).get()

    if not doc.exists:
        return None

    data = doc.to_dict() or {}
    data["id"] = doc.id
    return data


def list_lessons_for_module(module_id: str) -> List[Dict[str, Any]]:
    db = get_firestore_client()

    docs = (
        where_eq(db.collection("lessons"), "module_id", module_id)
        .order_by("sequence")
        .stream()
    )

    result: List[Dict[str, Any]] = []
    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        result.append(data)

    return result


def list_lessons_for_module_unordered(module_id: str) -> List[Dict[str, Any]]:
    db = get_firestore_client()

    docs = where_eq(db.collection("lessons"), "module_id", module_id).stream()

    result: List[Dict[str, Any]] = []
    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        result.append(data)

    return result


def get_lesson_by_doc_id(lesson_doc_id: str) -> Optional[Dict[str, Any]]:
    db = get_firestore_client()
    doc = db.collection("lessons").document(lesson_doc_id).get()

    if not doc.exists:
        return None

    data = doc.to_dict() or {}
    data["id"] = doc.id
    return data


def get_lesson_by_fields(module_id: str, lesson_id: str) -> Optional[Dict[str, Any]]:
    db = get_firestore_client()

    qs = (
        where_eq(
            where_eq(db.collection("lessons"), "module_id", module_id),
            "lesson_id",
            lesson_id,
        )
        .limit(1)
        .stream()
    )

    hit = None
    for d in qs:
        hit = d
        break

    if not hit:
        return None

    data = hit.to_dict() or {}
    data["id"] = hit.id
    return data


def get_sim_lab_by_id(lab_id: str) -> Optional[Dict[str, Any]]:
    db = get_firestore_client()
    doc = db.collection("sim_labs").document(lab_id).get()

    if not doc.exists:
        return None

    data = doc.to_dict() or {}
    data["id"] = doc.id
    return data
