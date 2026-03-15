from __future__ import annotations

from typing import Any, Dict, List

from app.common import normalize_module_id
from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq
from app.repositories.catalog_repository import list_lessons_for_module


def get_module_lessons(module_id: str) -> List[Dict[str, Any]]:
    return list_lessons_for_module(normalize_module_id(module_id))


def get_module_progress(uid: str, module_id: str) -> Dict[str, Any]:
    normalized_module_id = normalize_module_id(module_id)
    db = get_firestore_client()
    snap = (
        db.collection("progress")
        .document(uid)
        .collection("modules")
        .document(normalized_module_id)
        .get()
    )
    return snap.to_dict() if snap.exists else {}


def get_progress_events(uid: str, module_id: str) -> List[Dict[str, Any]]:
    normalized_module_id = normalize_module_id(module_id)
    db = get_firestore_client()
    docs = (
        where_eq(
            where_eq(db.collection("progress_events"), "uid", uid),
            "module_id",
            normalized_module_id,
        )
        .stream()
    )

    result: List[Dict[str, Any]] = []
    for d in docs:
        data = d.to_dict() or {}
        data["_doc_id"] = d.id
        result.append(data)

    return result
