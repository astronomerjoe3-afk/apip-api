from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from importlib import import_module
from typing import Any, Dict, Iterable, List, Tuple

from app.common import normalize_module_id
from app.core.config import settings
from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq
_MODULE_IMPORT_SPECS = (
    ("F1", "scripts.seed_f1_module", "F1_CONTENT_VERSION", "F1_MODULE_DOC", "F1_LESSONS", "F1_SIM_LABS"),
    ("F2", "scripts.seed_f2_module", "F2_CONTENT_VERSION", "F2_MODULE_DOC", "F2_LESSONS", "F2_SIM_LABS"),
    ("F3", "scripts.seed_f3_module", "F3_CONTENT_VERSION", "F3_MODULE_DOC", "F3_LESSONS", "F3_SIM_LABS"),
    ("F4", "scripts.seed_f4_module", "F4_CONTENT_VERSION", "F4_MODULE_DOC", "F4_LESSONS", "F4_SIM_LABS"),
    ("M1", "scripts.seed_m1_module", "M1_CONTENT_VERSION", "M1_MODULE_DOC", "M1_LESSONS", "M1_SIM_LABS"),
    ("M2", "scripts.seed_m2_module", "M2_CONTENT_VERSION", "M2_MODULE_DOC", "M2_LESSONS", "M2_SIM_LABS"),
    ("M3", "scripts.seed_m3_module", "M3_CONTENT_VERSION", "M3_MODULE_DOC", "M3_LESSONS", "M3_SIM_LABS"),
    ("M4", "scripts.seed_m4_module", "M4_CONTENT_VERSION", "M4_MODULE_DOC", "M4_LESSONS", "M4_SIM_LABS"),
    ("M5", "scripts.seed_m5_module", "M5_CONTENT_VERSION", "M5_MODULE_DOC", "M5_LESSONS", "M5_SIM_LABS"),
    ("M6", "scripts.seed_m6_module", "M6_CONTENT_VERSION", "M6_MODULE_DOC", "M6_LESSONS", "M6_SIM_LABS"),
    ("M7", "scripts.seed_m7_module", "M7_CONTENT_VERSION", "M7_MODULE_DOC", "M7_LESSONS", "M7_SIM_LABS"),
    ("M8", "scripts.seed_m8_module", "M8_CONTENT_VERSION", "M8_MODULE_DOC", "M8_LESSONS", "M8_SIM_LABS"),
    ("M9", "scripts.seed_m9_module", "M9_CONTENT_VERSION", "M9_MODULE_DOC", "M9_LESSONS", "M9_SIM_LABS"),
    ("M10", "scripts.seed_m10_module", "M10_CONTENT_VERSION", "M10_MODULE_DOC", "M10_LESSONS", "M10_SIM_LABS"),
    ("M11", "scripts.seed_m11_module", "M11_CONTENT_VERSION", "M11_MODULE_DOC", "M11_LESSONS", "M11_SIM_LABS"),
    ("M12", "scripts.seed_m12_module", "M12_CONTENT_VERSION", "M12_MODULE_DOC", "M12_LESSONS", "M12_SIM_LABS"),
    ("M13", "scripts.seed_m13_module", "M13_CONTENT_VERSION", "M13_MODULE_DOC", "M13_LESSONS", "M13_SIM_LABS"),
)

_MODULE_IMPORT_INDEX = {module_id: spec for module_id, *spec in _MODULE_IMPORT_SPECS}


def get_catalog_module_ids() -> Tuple[str, ...]:
    return tuple(module_id for module_id, *_ in _MODULE_IMPORT_SPECS)


@lru_cache(maxsize=None)
def get_catalog_module(module_id: str) -> dict | None:
    spec = _MODULE_IMPORT_INDEX.get(str(module_id))
    if not spec:
        return None

    module_path, content_version_name, module_doc_name, lessons_name, sim_labs_name = spec
    seed_module = import_module(module_path)
    return {
        "module_id": str(module_id),
        "content_version": getattr(seed_module, content_version_name),
        "module_doc": getattr(seed_module, module_doc_name),
        "lessons": getattr(seed_module, lessons_name),
        "sim_labs": getattr(seed_module, sim_labs_name),
    }


@lru_cache(maxsize=1)
def get_catalog_modules() -> Tuple[dict, ...]:
    bundles = []
    for module_id in get_catalog_module_ids():
        bundle = get_catalog_module(module_id)
        if bundle:
            bundles.append(bundle)
    return tuple(bundles)


def get_catalog_module_row(module_id: str) -> Dict[str, Any] | None:
    normalized_module_id = normalize_module_id(module_id)
    if not normalized_module_id:
        return None

    bundle = get_catalog_module(normalized_module_id)
    if not bundle:
        return None

    row = deepcopy(bundle["module_doc"])
    row["id"] = row.get("id") or row.get("module_id") or normalized_module_id
    return row


def get_catalog_lessons_for_module(module_id: str) -> List[Dict[str, Any]]:
    normalized_module_id = normalize_module_id(module_id)
    if not normalized_module_id:
        return []

    bundle = get_catalog_module(normalized_module_id)
    if not bundle:
        return []

    lessons: List[Dict[str, Any]] = []
    for doc_id, payload in bundle["lessons"]:
        row = deepcopy(payload)
        row["id"] = row.get("id") or doc_id
        lessons.append(row)

    return lessons


def _top_level_doc_count(collection: str, field: str, module_id: str) -> int:
    db = get_firestore_client()
    query = where_eq(db.collection(collection), field, module_id)
    return sum(1 for _ in query.stream())


def _seed_documents() -> Iterable[Tuple[str, str, dict]]:
    for module in get_catalog_modules():
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

    catalog_modules = get_catalog_modules()
    if all(_module_is_ready(module) for module in catalog_modules):
        return False

    db = get_firestore_client()
    batch = db.batch()
    for collection, doc_id, payload in _seed_documents():
        ref = db.collection(collection).document(doc_id)
        batch.set(ref, payload, merge=True)
    batch.commit()
    return True
