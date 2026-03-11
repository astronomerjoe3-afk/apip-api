from __future__ import annotations

from typing import Any, Dict, List, Optional

from google.cloud import firestore

from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq
from app.services.local_catalog import (
    get_local_lesson_by_doc_id,
    get_local_lesson_by_fields,
    get_local_module_by_id,
    get_local_sim_lab_by_id,
    list_local_lessons_for_module,
    list_local_modules,
)


def _safe_int(value: Any, default: int = 10**9) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _is_missing_index_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return (
        "requires an index" in msg
        or "create it here" in msg
        or "failed_precondition" in msg
    )


def _with_id(snap: firestore.DocumentSnapshot) -> Dict[str, Any]:
    data = snap.to_dict() or {}
    data["id"] = snap.id
    return data


# -------------------------------------------------------------------
# Canonical accessors
# -------------------------------------------------------------------

def get_curricula() -> List[Dict[str, Any]]:
    db = get_firestore_client()
    docs = list(db.collection("curricula").stream())
    return [_with_id(d) for d in docs]


def get_modules(curriculum_id: Optional[str] = None) -> List[Dict[str, Any]]:
    db = get_firestore_client()
    query = db.collection("modules")
    if curriculum_id:
        query = where_eq(query, "curriculum_id", curriculum_id)
    docs = list(query.stream())
    modules = [_with_id(d) for d in docs]
    by_id = {str(module.get("id") or module.get("module_id") or ""): module for module in modules}
    for module in list_local_modules(curriculum_id=curriculum_id):
        module_id = str(module.get("id") or module.get("module_id") or "")
        if module_id and module_id not in by_id:
            by_id[module_id] = module
    merged = [module for key, module in by_id.items() if key]
    merged.sort(key=lambda row: _safe_int(row.get("sequence")))
    return merged


def get_module_by_id(module_id: str) -> Optional[Dict[str, Any]]:
    db = get_firestore_client()
    snap = db.collection("modules").document(module_id).get()
    if snap.exists:
        return _with_id(snap)
    return get_local_module_by_id(module_id)


def list_lessons_for_module_unordered(module_id: str) -> List[Dict[str, Any]]:
    """
    Unordered lesson listing used as a safe fallback when ordered queries
    require a composite index.
    """
    db = get_firestore_client()

    docs = list(where_eq(db.collection("lessons"), "module_id", module_id).stream())
    lessons = [_with_id(d) for d in docs]
    if lessons:
        return lessons

    sub_docs = list(
        db.collection("modules").document(module_id).collection("lessons").stream()
    )
    lessons = [_with_id(d) for d in sub_docs]
    if lessons:
        return lessons

    return list_local_lessons_for_module(module_id)


def get_module_lessons(module_id: str) -> List[Dict[str, Any]]:
    """
    Canonical lesson listing for a module.

    Read order:
    1) top-level lessons collection filtered by module_id
    2) modules/{module_id}/lessons subcollection fallback
    3) local fallback content for built-in modules

    Returned lessons are sorted by sequence ascending.
    """
    db = get_firestore_client()
    lessons: List[Dict[str, Any]] = []

    try:
        query = (
            where_eq(db.collection("lessons"), "module_id", module_id)
            .order_by("sequence", direction=firestore.Query.ASCENDING)
        )
        docs = list(query.stream())
        lessons = [_with_id(d) for d in docs]
    except Exception as exc:
        if _is_missing_index_error(exc):
            lessons = list_lessons_for_module_unordered(module_id)
            lessons.sort(key=lambda x: _safe_int(x.get("sequence") or x.get("order")))
        else:
            raise

    if lessons:
        return lessons

    sub_docs = list(
        db.collection("modules").document(module_id).collection("lessons").stream()
    )
    lessons = [_with_id(d) for d in sub_docs]
    if lessons:
        lessons.sort(key=lambda x: _safe_int(x.get("sequence") or x.get("order")))
        return lessons

    lessons = list_local_lessons_for_module(module_id)
    lessons.sort(key=lambda x: _safe_int(x.get("sequence") or x.get("order")))
    return lessons


def get_lesson_by_doc_id(lesson_doc_id: str) -> Optional[Dict[str, Any]]:
    db = get_firestore_client()
    snap = db.collection("lessons").document(lesson_doc_id).get()
    if snap.exists:
        return _with_id(snap)
    return get_local_lesson_by_doc_id(lesson_doc_id)


def get_lesson_by_fields(module_id: str, lesson_id: str) -> Optional[Dict[str, Any]]:
    db = get_firestore_client()
    normalized = str(lesson_id).replace("-", "_")

    docs = list(
        where_eq(
            where_eq(db.collection("lessons"), "module_id", module_id),
            "lesson_id",
            normalized,
        ).stream()
    )
    if docs:
        rows = [_with_id(d) for d in docs]
        rows.sort(key=lambda x: _safe_int(x.get("sequence") or x.get("order")))
        return rows[0]

    snap = (
        db.collection("modules")
        .document(module_id)
        .collection("lessons")
        .document(normalized)
        .get()
    )
    if snap.exists:
        return _with_id(snap)

    sub_docs = list(
        db.collection("modules").document(module_id).collection("lessons").stream()
    )
    matches: List[Dict[str, Any]] = []
    for d in sub_docs:
        row = _with_id(d)
        row_lesson_id = str(row.get("lesson_id") or row.get("id") or "").replace("-", "_")
        if row_lesson_id == normalized:
            matches.append(row)

    if matches:
        matches.sort(key=lambda x: _safe_int(x.get("sequence") or x.get("order")))
        return matches[0]

    return get_local_lesson_by_fields(module_id, normalized)


def get_sim_lab_by_id(lab_id: str) -> Optional[Dict[str, Any]]:
    db = get_firestore_client()
    snap = db.collection("sim_labs").document(lab_id).get()
    if snap.exists:
        return _with_id(snap)
    return get_local_sim_lab_by_id(lab_id)


# -------------------------------------------------------------------
# Backward-compatible aliases expected by service layer
# -------------------------------------------------------------------

def list_curricula() -> List[Dict[str, Any]]:
    return get_curricula()


def list_modules(curriculum_id: Optional[str] = None) -> List[Dict[str, Any]]:
    return get_modules(curriculum_id=curriculum_id)


def get_module(module_id: str) -> Optional[Dict[str, Any]]:
    return get_module_by_id(module_id)


def list_module_lessons(module_id: str) -> List[Dict[str, Any]]:
    return get_module_lessons(module_id)


def list_lessons_for_module(module_id: str) -> List[Dict[str, Any]]:
    return get_module_lessons(module_id)


def get_lesson(module_id: str, lesson_id: str) -> Optional[Dict[str, Any]]:
    normalized = str(lesson_id).replace("-", "_")

    lesson = get_lesson_by_doc_id(normalized)
    if lesson and lesson.get("module_id") == module_id:
        return lesson

    return get_lesson_by_fields(module_id, normalized)


def get_module_lesson(module_id: str, lesson_id: str) -> Optional[Dict[str, Any]]:
    return get_lesson(module_id, lesson_id)


def get_sim_lab(lab_id: str) -> Optional[Dict[str, Any]]:
    return get_sim_lab_by_id(lab_id)


def get_simulation_lab(lab_id: str) -> Optional[Dict[str, Any]]:
    return get_sim_lab_by_id(lab_id)
