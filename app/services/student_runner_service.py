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


def _has_teaching(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}

    analogical = phases.get("analogical_grounding") or {}
    reconstruction = phases.get("concept_reconstruction") or {}

    has_analogy = bool(analogical.get("analogy_text"))
    has_reconstruction = bool(reconstruction.get("prompts") or [])

    return has_analogy or has_reconstruction


def _has_sim_lab(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    sim = phases.get("simulation_inquiry") or {}
    return bool(sim.get("lab_id"))


def _has_transfer(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    transfer = phases.get("transfer") or {}
    items = transfer.get("items") or []
    return len(items) > 0


def _derive_current_stage(
    lesson_status: str,
    mastery_achieved: bool,
    has_diag: bool,
    has_teaching: bool,
    has_lab: bool,
    lab_available: bool,
    lab_used: bool,
    has_transfer: bool,
) -> str:
    if mastery_achieved:
        return "done"

    if lesson_status == "not_started":
        if has_diag:
            return "diagnostic"
        if has_teaching:
            return "scaffolded_teaching"
        if has_lab and lab_available:
            return "simulation"
        if has_transfer:
            return "mastery_check"
        return "done"

    # once diagnostic/attempt exists, move learner into teaching first
    if has_teaching:
        return "scaffolded_teaching"

    if has_lab and lab_available and not lab_used:
        return "simulation"

    if has_transfer:
        return "mastery_check"

    return "done"


def _stage_row(
    key: str,
    label: str,
    available: bool,
    completed: bool,
    active_key: str,
) -> Dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "available": available,
        "completed": completed,
        "active": available and (active_key == key),
    }


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
    has_teaching = _has_teaching(lesson)
    has_lab = _has_sim_lab(lesson)
    has_transfer = _has_transfer(lesson)

    current_stage = _derive_current_stage(
        lesson_status=lesson_status,
        mastery_achieved=mastery_achieved,
        has_diag=has_diag,
        has_teaching=has_teaching,
        has_lab=has_lab,
        lab_available=lab_available,
        lab_used=lab_used,
        has_transfer=has_transfer,
    )

    diagnostic_completed = lesson_status != "not_started"
    teaching_completed = lesson_status in ("attempted_not_completed", "completed")
    simulation_completed = lab_used
    mastery_check_completed = mastery_achieved

    stages: List[Dict[str, Any]] = [
        _stage_row(
            key="diagnostic",
            label="Initial diagnostic",
            available=has_diag,
            completed=diagnostic_completed,
            active_key=current_stage,
        ),
        _stage_row(
            key="scaffolded_teaching",
            label="Guided concept building",
            available=has_teaching,
            completed=teaching_completed,
            active_key=current_stage,
        ),
        _stage_row(
            key="simulation",
            label="Sim Lab",
            available=has_lab,
            completed=simulation_completed,
            active_key=current_stage if lab_available else "",
        ),
        _stage_row(
            key="mastery_check",
            label="Mastery check",
            available=has_transfer,
            completed=mastery_check_completed,
            active_key=current_stage,
        ),
    ]

    if mastery_achieved:
        next_action = "advance_to_next_sub_unit"
    elif current_stage == "diagnostic":
        next_action = "start_diagnostic"
    elif current_stage == "scaffolded_teaching":
        next_action = "continue_scaffolded_teaching"
    elif current_stage == "simulation":
        next_action = "run_sim_lab"
    elif current_stage == "mastery_check":
        next_action = "attempt_mastery_check"
    else:
        next_action = "wait"

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
