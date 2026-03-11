from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional

try:
    from scripts.seed_f1_module import F1_LESSONS, F1_MODULE_DOC, F1_SIM_LABS
    from scripts.seed_f2_module import F2_LESSONS, F2_MODULE_DOC, F2_SIM_LABS
except Exception:
    F1_MODULE_DOC = {}
    F2_MODULE_DOC = {}
    F1_LESSONS = []
    F2_LESSONS = []
    F1_SIM_LABS = []
    F2_SIM_LABS = []


def _safe_int(value: Any, default: int = 10**9) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _normalize_module(module: Dict[str, Any]) -> Dict[str, Any]:
    payload = deepcopy(module)
    module_id = str(payload.get("id") or payload.get("module_id") or "").strip()
    if not module_id:
        return payload
    payload.setdefault("id", module_id)
    payload.setdefault("module_id", module_id)
    return payload


def _normalize_lesson(doc_id: str, lesson: Dict[str, Any]) -> Dict[str, Any]:
    payload = deepcopy(lesson)
    payload.setdefault("id", doc_id)
    payload.setdefault("lesson_id", doc_id)
    if payload.get("module_id") is None and payload.get("moduleId") is not None:
        payload["module_id"] = payload.get("moduleId")
    if payload.get("moduleId") is None and payload.get("module_id") is not None:
        payload["moduleId"] = payload.get("module_id")
    if payload.get("sequence") is None and payload.get("order") is not None:
        payload["sequence"] = payload.get("order")
    if payload.get("order") is None and payload.get("sequence") is not None:
        payload["order"] = payload.get("sequence")
    return payload


def _normalize_lab(doc_id: str, lab: Dict[str, Any]) -> Dict[str, Any]:
    payload = deepcopy(lab)
    payload.setdefault("id", doc_id)
    payload.setdefault("lab_id", doc_id)
    return payload


_LOCAL_MODULES = {
    module["id"]: module
    for module in [
        _normalize_module(F1_MODULE_DOC) if F1_MODULE_DOC else {},
        _normalize_module(F2_MODULE_DOC) if F2_MODULE_DOC else {},
    ]
    if module.get("id")
}

_LOCAL_LESSONS_BY_MODULE: Dict[str, List[Dict[str, Any]]] = {}
for doc_id, lesson in [*F1_LESSONS, *F2_LESSONS]:
    payload = _normalize_lesson(doc_id, lesson)
    module_id = str(payload.get("module_id") or payload.get("moduleId") or "").strip()
    if not module_id:
        continue
    _LOCAL_LESSONS_BY_MODULE.setdefault(module_id, []).append(payload)

for module_id, lessons in _LOCAL_LESSONS_BY_MODULE.items():
    lessons.sort(key=lambda row: _safe_int(row.get("sequence") or row.get("order")))

_LOCAL_LESSONS_BY_ID = {
    str(lesson.get("id") or lesson.get("lesson_id") or ""): deepcopy(lesson)
    for lessons in _LOCAL_LESSONS_BY_MODULE.values()
    for lesson in lessons
    if str(lesson.get("id") or lesson.get("lesson_id") or "")
}

_LOCAL_SIM_LABS = {
    lab_id: _normalize_lab(lab_id, payload)
    for lab_id, payload in [*F1_SIM_LABS, *F2_SIM_LABS]
}


def list_local_modules(curriculum_id: Optional[str] = None) -> List[Dict[str, Any]]:
    modules = []
    for module in _LOCAL_MODULES.values():
        if curriculum_id and str(module.get("curriculum_id") or "") != curriculum_id:
            continue
        modules.append(deepcopy(module))
    modules.sort(key=lambda row: _safe_int(row.get("sequence")))
    return modules


def get_local_module_by_id(module_id: str) -> Optional[Dict[str, Any]]:
    module = _LOCAL_MODULES.get(str(module_id).strip())
    return deepcopy(module) if module else None


def list_local_lessons_for_module(module_id: str) -> List[Dict[str, Any]]:
    return [deepcopy(lesson) for lesson in _LOCAL_LESSONS_BY_MODULE.get(str(module_id).strip(), [])]


def get_local_lesson_by_doc_id(lesson_doc_id: str) -> Optional[Dict[str, Any]]:
    lesson = _LOCAL_LESSONS_BY_ID.get(str(lesson_doc_id).replace("-", "_"))
    return deepcopy(lesson) if lesson else None


def get_local_lesson_by_fields(module_id: str, lesson_id: str) -> Optional[Dict[str, Any]]:
    normalized = str(lesson_id).replace("-", "_")
    for lesson in _LOCAL_LESSONS_BY_MODULE.get(str(module_id).strip(), []):
        row_lesson_id = str(lesson.get("lesson_id") or lesson.get("id") or "").replace("-", "_")
        if row_lesson_id == normalized:
            return deepcopy(lesson)
    return None


def get_local_sim_lab_by_id(lab_id: str) -> Optional[Dict[str, Any]]:
    lab = _LOCAL_SIM_LABS.get(str(lab_id).strip())
    return deepcopy(lab) if lab else None
