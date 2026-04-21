from __future__ import annotations

from typing import Any, Dict, Iterable

from app.db.firestore import get_firestore_client
from app.firebase_admin_init import auth as firebase_auth, init_firebase_admin


RETAINED_RECORDS = [
    "billing, refund, and invoice records where legally required",
    "security, abuse, and audit logs needed to protect the platform",
    "records tied to active disputes, investigations, or legal obligations",
]


def _delete_document_tree(doc_ref) -> int:
    deleted = 0

    for collection in doc_ref.collections():
        for doc in collection.stream():
            deleted += _delete_document_tree(doc.reference)

    if doc_ref.get().exists:
        doc_ref.delete()
        deleted += 1

    return deleted


def _batched_delete(doc_refs: Iterable[Any], *, chunk_size: int = 400) -> int:
    refs = list(doc_refs)
    if not refs:
        return 0

    db = get_firestore_client()
    deleted = 0

    for index in range(0, len(refs), chunk_size):
        batch = db.batch()
        chunk = refs[index:index + chunk_size]
        for ref in chunk:
            batch.delete(ref)
        batch.commit()
        deleted += len(chunk)

    return deleted


def _delete_query_documents(collection_name: str, field_name: str, value: str) -> int:
    db = get_firestore_client()
    docs = db.collection(collection_name).where(field_name, "==", value).stream()
    return _batched_delete(doc.reference for doc in docs)


def _delete_firebase_user(uid: str) -> bool:
    init_firebase_admin()
    try:
        firebase_auth.delete_user(uid)
        return True
    except Exception as exc:
        message = str(exc or "")
        if "No user record found" in message or "USER_NOT_FOUND" in message:
            return False
        raise


def delete_user_account(uid: str) -> Dict[str, Any]:
    db = get_firestore_client()
    normalized_uid = str(uid or "").strip()
    if not normalized_uid:
        return {
            "firebase_auth_deleted": False,
            "profile_documents_deleted": 0,
            "progress_documents_deleted": 0,
            "progress_events_deleted": 0,
            "help_requests_deleted": 0,
            "sessions_deleted": 0,
            "retained_records": RETAINED_RECORDS,
        }

    return {
        "firebase_auth_deleted": _delete_firebase_user(normalized_uid),
        "profile_documents_deleted": _delete_document_tree(db.collection("users").document(normalized_uid)),
        "progress_documents_deleted": _delete_document_tree(db.collection("progress").document(normalized_uid)),
        "progress_events_deleted": _delete_query_documents("progress_events", "uid", normalized_uid),
        "help_requests_deleted": _delete_query_documents("student_help_requests", "student_uid", normalized_uid),
        "sessions_deleted": _delete_query_documents("auth_sessions", "uid", normalized_uid),
        "retained_records": RETAINED_RECORDS,
    }
