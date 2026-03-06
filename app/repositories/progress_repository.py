from __future__ import annotations

from typing import Any, Dict, List, Optional

from google.cloud import firestore

from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq


def progress_doc(uid: str):
    db = get_firestore_client()
    return db.collection("progress").document(uid)


def module_progress_doc(uid: str, module_id: str):
    return progress_doc(uid).collection("modules").document(module_id)


def get_module_progress(uid: str, module_id: str) -> Dict[str, Any]:
    snap = module_progress_doc(uid, module_id).get()
    return snap.to_dict() if snap.exists else {}


def set_module_progress(uid: str, module_id: str, payload: Dict[str, Any]) -> None:
    module_progress_doc(uid, module_id).set(payload, merge=True)


def set_progress_root(uid: str, payload: Dict[str, Any]) -> None:
    progress_doc(uid).set(payload, merge=True)


def persist_progress_event(event_doc_id: str, payload: Dict[str, Any]) -> None:
    db = get_firestore_client()
    db.collection("progress_events").document(event_doc_id).set(payload)


def list_progress_modules(uid: str) -> List[Dict[str, Any]]:
    docs = list(progress_doc(uid).collection("modules").stream())
    result: List[Dict[str, Any]] = []

    for d in docs:
        data = d.to_dict() or {}
        data["module_id"] = d.id
        result.append(data)

    return result


def list_recent_progress_events(uid: str, limit_recent_events: int) -> List[Dict[str, Any]]:
    db = get_firestore_client()

    q = (
        where_eq(db.collection("progress_events"), "uid", uid)
        .order_by("utc", direction=firestore.Query.DESCENDING)
        .limit(limit_recent_events)
    )

    result: List[Dict[str, Any]] = []
    for s in q.stream():
        result.append(s.to_dict() or {})

    return result
