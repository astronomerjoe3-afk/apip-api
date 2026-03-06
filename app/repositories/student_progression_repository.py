from __future__ import annotations

from typing import Any, Dict, List

from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq


def get_module_lessons(module_id: str) -> List[Dict[str, Any]]:
    db = get_firestore_client()
    docs = (
        where_eq(db.collection("lessons"), "module_id", module_id)
        .stream()
    )

    result: List[Dict[str, Any]] = []
    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        result.append(data)

    result.sort(key=lambda x: int(x.get("sequence", 10**9) or 10**9))
    return result


def get_module_progress(uid: str, module_id: str) -> Dict[str, Any]:
    db = get_firestore_client()
    snap = (
        db.collection("progress")
        .document(uid)
        .collection("modules")
        .document(module_id)
        .get()
    )
    return snap.to_dict() if snap.exists else {}


def get_progress_events(uid: str, module_id: str) -> List[Dict[str, Any]]:
    db = get_firestore_client()
    docs = (
        where_eq(
            where_eq(db.collection("progress_events"), "uid", uid),
            "module_id",
            module_id,
        )
        .stream()
    )

    result: List[Dict[str, Any]] = []
    for d in docs:
        data = d.to_dict() or {}
        data["_doc_id"] = d.id
        result.append(data)

    return result
