from __future__ import annotations

from typing import Any, Dict, List

from google.cloud import firestore

from app.common import normalize_module_id
from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq


def progress_doc(uid: str):
    db = get_firestore_client()
    return db.collection("progress").document(uid)


def module_progress_doc(uid: str, module_id: str):
    normalized_module_id = normalize_module_id(module_id)
    return progress_doc(uid).collection("modules").document(normalized_module_id)


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
        data["module_id"] = normalize_module_id(d.id) or d.id
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


def list_recent_transfer_events_for_module(
    uid: str,
    module_id: str,
    limit_events: int = 200,
) -> List[Dict[str, Any]]:
    """
    Canonical mastery source:
    transfer events for one learner/module only.

    Fallback strategy:
    1) preferred ordered query
    2) unordered query if index is missing
    3) in-app filter + sort
    """
    normalized_module_id = normalize_module_id(module_id)
    db = get_firestore_client()
    result: List[Dict[str, Any]] = []

    try:
        q = (
            where_eq(
                where_eq(
                    where_eq(db.collection("progress_events"), "uid", uid),
                    "module_id",
                    normalized_module_id,
                ),
                "event_type",
                "transfer",
            )
            .order_by("utc", direction=firestore.Query.DESCENDING)
            .limit(limit_events)
        )

        for s in q.stream():
            result.append(s.to_dict() or {})

        return result
    except Exception:
        pass

    try:
        q = (
            where_eq(
                where_eq(
                    where_eq(db.collection("progress_events"), "uid", uid),
                    "module_id",
                    normalized_module_id,
                ),
                "event_type",
                "transfer",
            )
            .limit(limit_events)
        )

        for s in q.stream():
            result.append(s.to_dict() or {})

        result.sort(key=lambda x: str(x.get("utc") or ""), reverse=True)
        return result
    except Exception:
        pass

    q = where_eq(db.collection("progress_events"), "uid", uid).limit(limit_events * 5)

    scanned: List[Dict[str, Any]] = []
    for s in q.stream():
        data = s.to_dict() or {}
        if normalize_module_id(data.get("module_id")) != normalized_module_id:
            continue
        if str(data.get("event_type") or "").strip().lower() != "transfer":
            continue
        scanned.append(data)

    scanned.sort(key=lambda x: str(x.get("utc") or ""), reverse=True)
    return scanned[:limit_events]
