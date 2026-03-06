from __future__ import annotations

from typing import Any, Dict, List

from app.repositories.catalog_repository import get_lesson_by_doc_id, get_lesson_by_fields
from app.services.student_progression_service import get_student_lesson_progress


MASTERY_THRESHOLD = 0.80


def _load_lesson(module_id: str, lesson_id: str) -> Dict[str, Any] | None:
    normalized = str(lesson_id).replace("-", "_")

    lesson = get_lesson_by_doc_id(normalized)
    if lesson and lesson.get("module_id") == module_id:
        return lesson

    lesson = get_lesson_by_fields(module_id, normalized)
    if lesson:
        return lesson

    return None


def _has_diagnostic(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    diagnostic = phases.get("diagnostic") or {}
    items = diagnostic.get("items") or []
    return len(items) > 0


def _has_scaffolded_teaching(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    analogical = phases.get("analogical_grounding") or {}
    reconstruction = phases.get("concept_reconstruction") or {}
    return bool(analogical.get("analogy_text")) or bool(reconstruction.get("prompts"))


def _has_sim_lab(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    sim = phases.get("simulation_inquiry") or {}
    return bool(sim.get("lab_id"))


def _has_transfer(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    transfer = phases.get("transfer") or {}
    items = transfer.get("items") or []
    return len(items) > 0


def build_student_runner_contract(uid: str, module_id: str, lesson_id: str) -> Dict[str, Any]:
    lesson = _load_lesson(module_id, lesson_id)
    progression = get_student_lesson_progress(uid=uid, module_id=module_id, lesson_id=lesson_id)

    lesson_progress = progression["lesson"]
    module_progress = progression["module"]

    normalized = str(lesson_id).replace("-", "_")

    if lesson is None:
        return {
            "module": module_progress,
            "lesson": {
                "lesson_id": normalized,
                "title": None,
                "sequence": None,
                "best_score": 0.0,
                "mastery_threshold": MASTERY_THRESHOLD,
                "mastery_achieved": False,
                "can_advance": False,
                "lesson_status": "not_found",
                "next_recommended_action": "lesson_not_found",
                "stages": [],
            },
        }

    best_score = float(lesson_progress.get("best_score") or 0.0)
    mastery_achieved = best_score >= MASTERY_THRESHOLD
    lab_available = bool(lesson_progress.get("lab_available"))
    lab_used = bool(lesson_progress.get("lab_used"))
    lesson_status = str(lesson_progress.get("status") or "not_started")

    has_diag = _has_diagnostic(lesson)
    has_teaching = _has_scaffolded_teaching(lesson)
    has_lab = _has_sim_lab(lesson)
    has_transfer = _has_transfer(lesson)

    stages: List[Dict[str, Any]] = []

    stages.append(
        {
            "key": "diagnostic",
            "label": "Initial diagnostic",
            "available": has_diag,
            "completed": lesson_status != "not_started",
            "active": lesson_status == "not_started" and has_diag,
        }
    )

    stages.append(
        {
            "key": "scaffolded_teaching",
            "label": "Guided concept building",
            "available": has_teaching,
            "completed": lesson_status in ("attempted_not_completed", "completed"),
            "active": lesson_status in ("attempted_not_completed", "not_started") and has_teaching,
        }
    )

    stages.append(
        {
            "key": "simulation",
            "label": "Sim Lab",
            "available": has_lab and (lab_available or lab_used),
            "completed": lab_used,
            "active": has_lab and lab_available and not mastery_achieved,
        }
    )

    stages.append(
        {
            "key": "mastery_check",
            "label": "Mastery check",
            "available": has_transfer,
            "completed": mastery_achieved,
            "active": has_transfer and not mastery_achieved,
        }
    )

    if lesson_status == "not_started":
        next_action = "start_diagnostic"
    elif not mastery_achieved and has_teaching:
        next_action = "continue_scaffolded_teaching"
    elif not mastery_achieved and has_lab and lab_available:
        next_action = "run_sim_lab"
    elif not mastery_achieved:
        next_action = "attempt_mastery_check"
    else:
        next_action = "advance_to_next_sub_unit"

    return {
        "module": module_progress,
        "lesson": {
            "lesson_id": lesson_progress["lesson_id"],
            "title": lesson_progress.get("title"),
            "sequence": lesson_progress.get("sequence"),
            "best_score": best_score,
            "mastery_threshold": MASTERY_THRESHOLD,
            "mastery_achieved": mastery_achieved,
            "can_advance": mastery_achieved,
            "lesson_status": lesson_status,
            "next_recommended_action": next_action,
            "stages": stages,
        },
    }
