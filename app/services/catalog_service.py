from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

from app.common import is_missing_index_error
from app.repositories.catalog_repository import (
    get_lesson_by_doc_id,
    get_lesson_by_fields,
    get_module_by_id,
    get_sim_lab_by_id,
    list_curricula,
    list_lessons_for_module,
    list_lessons_for_module_unordered,
    list_modules,
)
from app.services.content_normalizer import to_student_lesson_view, to_student_lessons_view
from app.services.monetization_service import enrich_module_for_student


def fetch_curricula() -> List[Dict[str, Any]]:
    return list_curricula()


def fetch_modules(curriculum_id: Optional[str] = None, uid: Optional[str] = None) -> List[Dict[str, Any]]:
    return [enrich_module_for_student(module, uid) for module in list_modules(curriculum_id=curriculum_id)]


def fetch_module(module_id: str, uid: Optional[str] = None) -> Dict[str, Any]:
    module = get_module_by_id(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    return enrich_module_for_student(module, uid)


def fetch_module_lessons(module_id: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    warnings: List[str] = []

    try:
        lessons = list_lessons_for_module(module_id)
        lessons = to_student_lessons_view(lessons)
        return lessons, warnings
    except Exception as e:
        if is_missing_index_error(e):
            warnings.append(f"lessons_ordering_fallback_missing_index: {str(e)[:200]}")
            try:
                lessons = list_lessons_for_module_unordered(module_id)
                lessons.sort(key=lambda x: int(x.get("sequence", 10**9) or 10**9))
                lessons = to_student_lessons_view(lessons)
                return lessons, warnings
            except Exception as e2:
                raise HTTPException(status_code=500, detail=f"Failed to load lessons: {str(e2)[:200]}")
        raise HTTPException(status_code=500, detail=f"Failed to load lessons: {str(e)[:200]}")


def fetch_module_lesson(module_id: str, lesson_id: str) -> Dict[str, Any]:
    normalized = lesson_id.replace("-", "_")

    lesson = get_lesson_by_doc_id(normalized)
    if lesson and lesson.get("module_id") == module_id:
        return to_student_lesson_view(lesson)

    lesson = get_lesson_by_fields(module_id, normalized)
    if lesson:
        return to_student_lesson_view(lesson)

    raise HTTPException(status_code=404, detail="Lesson not found")


def fetch_sim_lab(lab_id: str) -> Dict[str, Any]:
    lab = get_sim_lab_by_id(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Simulation lab not found")
    return lab
