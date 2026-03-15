from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional

from google.cloud import firestore

from app.common import normalize_module_id
from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq


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


def _catalog_modules() -> List[Dict[str, Any]]:
    from app.services.catalog_bootstrap import CATALOG_MODULES

    return list(CATALOG_MODULES)


def _bootstrap_module_bundle(module_id: str) -> Optional[Dict[str, Any]]:
    normalized_module_id = normalize_module_id(module_id)
    for bundle in _catalog_modules():
        if normalize_module_id(bundle.get("module_id")) == normalized_module_id:
            return bundle
    return None


def _bootstrap_module_row(module_id: str) -> Optional[Dict[str, Any]]:
    bundle = _bootstrap_module_bundle(module_id)
    if not bundle:
        return None

    row = deepcopy(bundle["module_doc"])
    row["id"] = row.get("id") or row.get("module_id") or normalize_module_id(module_id)
    return row


def _bootstrap_lessons_for_module(module_id: str) -> List[Dict[str, Any]]:
    bundle = _bootstrap_module_bundle(module_id)
    if not bundle:
        return []

    lessons: List[Dict[str, Any]] = []
    for doc_id, payload in bundle["lessons"]:
        row = deepcopy(payload)
        row["id"] = row.get("id") or doc_id
        lessons.append(row)

    lessons.sort(key=lambda row: _safe_int(row.get("sequence")))
    return lessons


def _bootstrap_lesson_by_doc_id(lesson_doc_id: str) -> Optional[Dict[str, Any]]:
    normalized_lesson_id = str(lesson_doc_id or "").replace("-", "_")
    for bundle in _catalog_modules():
        for doc_id, payload in bundle["lessons"]:
            row = deepcopy(payload)
            row_id = str(row.get("id") or row.get("lesson_id") or doc_id).replace("-", "_")
            if row_id == normalized_lesson_id:
                row["id"] = row.get("id") or doc_id
                return row
    return None


def _bootstrap_sim_lab_by_id(lab_id: str) -> Optional[Dict[str, Any]]:
    normalized_lab_id = str(lab_id or "").strip()
    for bundle in _catalog_modules():
        for doc_id, payload in bundle["sim_labs"]:
            row = deepcopy(payload)
            row_id = str(row.get("id") or row.get("lab_id") or doc_id).strip()
            if row_id == normalized_lab_id:
                row["id"] = row.get("id") or row.get("lab_id") or doc_id
                return row
    return None


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

    module_map: Dict[str, Dict[str, Any]] = {}
    for doc in docs:
        row = _with_id(doc)
        module_key = normalize_module_id(row.get("id") or row.get("module_id"))
        if module_key:
            module_map[module_key] = row

    if not curriculum_id:
        for bundle in _catalog_modules():
            module_key = normalize_module_id(bundle.get("module_id"))
            if module_key and module_key not in module_map:
                row = _bootstrap_module_row(module_key)
                if row:
                    module_map[module_key] = row

    modules = list(module_map.values())
    modules.sort(
        key=lambda row: (
            _safe_int(row.get("sequence")),
            str(row.get("title") or row.get("module_id") or row.get("id") or "").lower(),
        )
    )
    return modules


def get_module_by_id(module_id: str) -> Optional[Dict[str, Any]]:
    normalized_module_id = normalize_module_id(module_id)
    db = get_firestore_client()
    snap = db.collection("modules").document(normalized_module_id).get()
    if snap.exists:
        return _with_id(snap)
    return _bootstrap_module_row(normalized_module_id)


def list_lessons_for_module_unordered(module_id: str) -> List[Dict[str, Any]]:
    """
    Unordered lesson listing used as a safe fallback when ordered queries
    require a composite index.
    """
    normalized_module_id = normalize_module_id(module_id)
    db = get_firestore_client()

    docs = list(where_eq(db.collection("lessons"), "module_id", normalized_module_id).stream())
    lessons = [_with_id(d) for d in docs]
    if lessons:
        return lessons

    sub_docs = list(
        db.collection("modules").document(normalized_module_id).collection("lessons").stream()
    )
    lessons = [_with_id(d) for d in sub_docs]
    if lessons:
        return lessons

    return _bootstrap_lessons_for_module(normalized_module_id)


def get_module_lessons(module_id: str) -> List[Dict[str, Any]]:
    """
    Canonical lesson listing for a module.

    Read order:
    1) top-level lessons collection filtered by module_id
    2) modules/{module_id}/lessons subcollection fallback
    3) bootstrap bundle fallback

    Returned lessons are sorted by sequence ascending.
    """
    normalized_module_id = normalize_module_id(module_id)
    db = get_firestore_client()
    lessons: List[Dict[str, Any]] = []

    try:
        query = (
            where_eq(db.collection("lessons"), "module_id", normalized_module_id)
            .order_by("sequence", direction=firestore.Query.ASCENDING)
        )
        docs = list(query.stream())
        lessons = [_with_id(d) for d in docs]
    except Exception as exc:
        if _is_missing_index_error(exc):
            lessons = list_lessons_for_module_unordered(normalized_module_id)
            lessons.sort(key=lambda x: _safe_int(x.get("sequence")))
        else:
            raise

    if lessons:
        return lessons

    sub_docs = list(
        db.collection("modules").document(normalized_module_id).collection("lessons").stream()
    )
    lessons = [_with_id(d) for d in sub_docs]
    if lessons:
        lessons.sort(key=lambda x: _safe_int(x.get("sequence")))
        return lessons

    return _bootstrap_lessons_for_module(normalized_module_id)


def get_lesson_by_doc_id(lesson_doc_id: str) -> Optional[Dict[str, Any]]:
    normalized_lesson_id = str(lesson_doc_id or "").replace("-", "_")
    db = get_firestore_client()
    snap = db.collection("lessons").document(normalized_lesson_id).get()
    if snap.exists:
        return _with_id(snap)
    return _bootstrap_lesson_by_doc_id(normalized_lesson_id)


def get_lesson_by_fields(module_id: str, lesson_id: str) -> Optional[Dict[str, Any]]:
    db = get_firestore_client()
    normalized_module_id = normalize_module_id(module_id)
    normalized_lesson_id = str(lesson_id or "").replace("-", "_")

    docs = list(
        where_eq(
            where_eq(db.collection("lessons"), "module_id", normalized_module_id),
            "lesson_id",
            normalized_lesson_id,
        ).stream()
    )
    if docs:
        rows = [_with_id(d) for d in docs]
        rows.sort(key=lambda x: _safe_int(x.get("sequence")))
        return rows[0]

    snap = (
        db.collection("modules")
        .document(normalized_module_id)
        .collection("lessons")
        .document(normalized_lesson_id)
        .get()
    )
    if snap.exists:
        return _with_id(snap)

    sub_docs = list(
        db.collection("modules").document(normalized_module_id).collection("lessons").stream()
    )
    matches: List[Dict[str, Any]] = []
    for d in sub_docs:
        row = _with_id(d)
        row_lesson_id = str(row.get("lesson_id") or row.get("id") or "").replace("-", "_")
        if row_lesson_id == normalized_lesson_id:
            matches.append(row)

    if matches:
        matches.sort(key=lambda x: _safe_int(x.get("sequence")))
        return matches[0]

    lessons = _bootstrap_lessons_for_module(normalized_module_id)
    for lesson in lessons:
        row_lesson_id = str(lesson.get("lesson_id") or lesson.get("id") or "").replace("-", "_")
        if row_lesson_id == normalized_lesson_id:
            return lesson

    return None


def get_sim_lab_by_id(lab_id: str) -> Optional[Dict[str, Any]]:
    normalized_lab_id = str(lab_id or "").strip()
    db = get_firestore_client()
    snap = db.collection("sim_labs").document(normalized_lab_id).get()
    if snap.exists:
        return _with_id(snap)
    return _bootstrap_sim_lab_by_id(normalized_lab_id)


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
    normalized = str(lesson_id or "").replace("-", "_")

    lesson = get_lesson_by_doc_id(normalized)
    if lesson and normalize_module_id(lesson.get("module_id")) == normalize_module_id(module_id):
        return lesson

    return get_lesson_by_fields(module_id, normalized)


def get_module_lesson(module_id: str, lesson_id: str) -> Optional[Dict[str, Any]]:
    return get_lesson(module_id, lesson_id)


def get_sim_lab(lab_id: str) -> Optional[Dict[str, Any]]:
    return get_sim_lab_by_id(lab_id)


def get_simulation_lab(lab_id: str) -> Optional[Dict[str, Any]]:
    return get_sim_lab_by_id(lab_id)
