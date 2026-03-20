from __future__ import annotations

from typing import Iterable, Tuple

from app.core.config import settings
from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq
from scripts.seed_f1_module import F1_CONTENT_VERSION, F1_LESSONS, F1_MODULE_DOC, F1_MODULE_ID, F1_SIM_LABS
from scripts.seed_f2_module import F2_CONTENT_VERSION, F2_LESSONS, F2_MODULE_DOC, F2_MODULE_ID, F2_SIM_LABS
from scripts.seed_f3_module import F3_CONTENT_VERSION, F3_LESSONS, F3_MODULE_DOC, F3_MODULE_ID, F3_SIM_LABS
from scripts.seed_f4_module import F4_CONTENT_VERSION, F4_LESSONS, F4_MODULE_DOC, F4_MODULE_ID, F4_SIM_LABS
from scripts.seed_m1_module import M1_CONTENT_VERSION, M1_LESSONS, M1_MODULE_DOC, M1_MODULE_ID, M1_SIM_LABS
from scripts.seed_m2_module import M2_CONTENT_VERSION, M2_LESSONS, M2_MODULE_DOC, M2_MODULE_ID, M2_SIM_LABS
from scripts.seed_m3_module import M3_CONTENT_VERSION, M3_LESSONS, M3_MODULE_DOC, M3_MODULE_ID, M3_SIM_LABS
from scripts.seed_m4_module import M4_CONTENT_VERSION, M4_LESSONS, M4_MODULE_DOC, M4_MODULE_ID, M4_SIM_LABS
from scripts.seed_m5_module import M5_CONTENT_VERSION, M5_LESSONS, M5_MODULE_DOC, M5_MODULE_ID, M5_SIM_LABS


CATALOG_MODULES = [
    {
        "module_id": F1_MODULE_ID,
        "content_version": F1_CONTENT_VERSION,
        "module_doc": F1_MODULE_DOC,
        "lessons": F1_LESSONS,
        "sim_labs": F1_SIM_LABS,
    },
    {
        "module_id": F2_MODULE_ID,
        "content_version": F2_CONTENT_VERSION,
        "module_doc": F2_MODULE_DOC,
        "lessons": F2_LESSONS,
        "sim_labs": F2_SIM_LABS,
    },
    {
        "module_id": F3_MODULE_ID,
        "content_version": F3_CONTENT_VERSION,
        "module_doc": F3_MODULE_DOC,
        "lessons": F3_LESSONS,
        "sim_labs": F3_SIM_LABS,
    },
    {
        "module_id": F4_MODULE_ID,
        "content_version": F4_CONTENT_VERSION,
        "module_doc": F4_MODULE_DOC,
        "lessons": F4_LESSONS,
        "sim_labs": F4_SIM_LABS,
    },
    {
        "module_id": M1_MODULE_ID,
        "content_version": M1_CONTENT_VERSION,
        "module_doc": M1_MODULE_DOC,
        "lessons": M1_LESSONS,
        "sim_labs": M1_SIM_LABS,
    },
    {
        "module_id": M2_MODULE_ID,
        "content_version": M2_CONTENT_VERSION,
        "module_doc": M2_MODULE_DOC,
        "lessons": M2_LESSONS,
        "sim_labs": M2_SIM_LABS,
    },
    {
        "module_id": M3_MODULE_ID,
        "content_version": M3_CONTENT_VERSION,
        "module_doc": M3_MODULE_DOC,
        "lessons": M3_LESSONS,
        "sim_labs": M3_SIM_LABS,
    },
    {
        "module_id": M4_MODULE_ID,
        "content_version": M4_CONTENT_VERSION,
        "module_doc": M4_MODULE_DOC,
        "lessons": M4_LESSONS,
        "sim_labs": M4_SIM_LABS,
    },
    {
        "module_id": M5_MODULE_ID,
        "content_version": M5_CONTENT_VERSION,
        "module_doc": M5_MODULE_DOC,
        "lessons": M5_LESSONS,
        "sim_labs": M5_SIM_LABS,
    },
]


def _top_level_doc_count(collection: str, field: str, module_id: str) -> int:
    db = get_firestore_client()
    query = where_eq(db.collection(collection), field, module_id)
    return sum(1 for _ in query.stream())


def _seed_documents() -> Iterable[Tuple[str, str, dict]]:
    for module in CATALOG_MODULES:
        yield "modules", module["module_id"], module["module_doc"]
        for doc_id, payload in module["lessons"]:
            yield "lessons", doc_id, payload
        for doc_id, payload in module["sim_labs"]:
            yield "sim_labs", doc_id, payload


def _module_is_ready(module: dict) -> bool:
    db = get_firestore_client()
    module_id = str(module["module_id"])
    module_snap = db.collection("modules").document(module_id).get()
    module_data = module_snap.to_dict() or {}
    version_matches = str(module_data.get("content_version") or "").strip() == str(module["content_version"])
    lessons_ready = _top_level_doc_count("lessons", "module_id", module_id) >= len(module["lessons"])
    sim_labs_ready = _top_level_doc_count("sim_labs", "module_id", module_id) >= len(module["sim_labs"])
    return module_snap.exists and version_matches and lessons_ready and sim_labs_ready


def _active_project_id() -> str:
    configured = str(getattr(settings, "google_cloud_project", "") or "").strip().lower()
    if configured not in ("", "local", "none"):
        return configured
    try:
        return str(getattr(get_firestore_client(), "project", "") or "").strip().lower()
    except Exception:
        return configured


def ensure_catalog_seeded() -> bool:
    project_id = _active_project_id()
    if project_id in ("", "local", "none"):
        return False

    if all(_module_is_ready(module) for module in CATALOG_MODULES):
        return False

    db = get_firestore_client()
    batch = db.batch()
    for collection, doc_id, payload in _seed_documents():
        ref = db.collection(collection).document(doc_id)
        batch.set(ref, payload, merge=True)
    batch.commit()
    return True
