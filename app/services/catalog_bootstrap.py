from __future__ import annotations

from typing import Iterable, Tuple

from app.core.config import settings
from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq
from scripts.seed_f2_module import F2_LESSONS, F2_MODULE_DOC, F2_MODULE_ID, F2_SIM_LABS


def _has_top_level_docs(collection: str, field: str, module_id: str) -> bool:
    db = get_firestore_client()
    query = where_eq(db.collection(collection), field, module_id).limit(1)
    return any(True for _ in query.stream())


def _seed_documents() -> Iterable[Tuple[str, str, dict]]:
    yield "modules", F2_MODULE_ID, F2_MODULE_DOC
    for doc_id, payload in F2_LESSONS:
        yield "lessons", doc_id, payload
    for doc_id, payload in F2_SIM_LABS:
        yield "sim_labs", doc_id, payload


def ensure_catalog_seeded() -> bool:
    project_id = str(getattr(settings, "google_cloud_project", "") or "").strip().lower()
    if project_id in ("", "local", "none"):
        return False

    db = get_firestore_client()
    module_exists = db.collection("modules").document(F2_MODULE_ID).get().exists
    lessons_exist = _has_top_level_docs("lessons", "module_id", F2_MODULE_ID)
    sim_labs_exist = _has_top_level_docs("sim_labs", "module_id", F2_MODULE_ID)

    if module_exists and lessons_exist and sim_labs_exist:
        return False

    batch = db.batch()
    for collection, doc_id, payload in _seed_documents():
        ref = db.collection(collection).document(doc_id)
        batch.set(ref, payload, merge=True)
    batch.commit()
    return True