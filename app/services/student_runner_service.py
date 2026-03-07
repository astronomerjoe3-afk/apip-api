from __future__ import annotations

from typing import Any, Dict, List

from app.repositories.catalog_repository import get_lesson_by_doc_id, get_lesson_by_fields
from app.services.student_progression_service import get_student_lesson_progress

MASTERY_THRESHOLD = 0.80
DIAGNOSTIC_MIN_QUESTIONS = 2
DIAGNOSTIC_MAX_QUESTIONS = 5
MASTERY_MIN_QUESTIONS = 5
MASTERY_MAX_QUESTIONS = 10


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
    mastery_achieved: bool,
    has_diag: bool,
    has_teaching: bool,
    has_lab: bool,
    has_transfer: bool,
    diagnostic_completed: bool,
    guided_concept_completed: bool,
    concept_gate_completed: bool,
    lab_available: bool,
    lab_used: bool,
    mastery_check_count: int,
) -> str:
    if mastery_achieved:
        return "done"

    if not diagnostic_completed and has_diag:
        return "diagnostic"

    if diagnostic_completed and not guided_concept_completed and has_teaching:
        return "scaffolded_teaching"

    if guided_concept_completed and not concept_gate_completed:
        return "concept_gate"

    if has_lab and concept_gate_completed and lab_available and not lab_used:
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
                "diagnostic": {
                    "min_questions": DIAGNOSTIC_MIN_QUESTIONS,
                    "max_questions": DIAGNOSTIC_MAX_QUESTIONS,
                    "target_question_count": DIAGNOSTIC_MIN_QUESTIONS,
                    "completed": False,
                },
                "mastery_check": {
                    "min_questions": MASTERY_MIN_QUESTIONS,
                    "max_questions": MASTERY_MAX_QUESTIONS,
                    "selected_question_count": MASTERY_MIN_QUESTIONS,
                    "threshold": MASTERY_THRESHOLD,
                    "attempt_count": 0,
                    "best_score": 0.0,
                    "eligible_for_immediate_retest": False,
                    "review_required": False,
                    "review_recommended": False,
                    "weak_concepts": [],
                    "recommended_review_refs": [],
                },
                "stages": [],
            },
        }

    best_score = float(lesson_progress.get("best_score") or 0.0)
    mastery_achieved = best_score >= MASTERY_THRESHOLD
    lab_available = bool(lesson_progress.get("lab_available"))
    lab_used = bool(lesson_progress.get("lab_used"))
    lesson_status = str(lesson_progress.get("status") or "not_started")
    diagnostic_completed = bool(lesson_progress.get("diagnostic_completed"))
    guided_concept_completed = bool(lesson_progress.get("guided_concept_completed"))
    concept_gate_completed = bool(lesson_progress.get("concept_gate_completed"))
    mastery_check_count = int(lesson_progress.get("mastery_check_count") or 0)

    has_diag = _has_diagnostic(lesson)
    has_teaching = _has_teaching(lesson)
    has_lab = _has_sim_lab(lesson)
    has_transfer = _has_transfer(lesson)

    current_stage = _derive_current_stage(
        mastery_achieved=mastery_achieved,
        has_diag=has_diag,
        has_teaching=has_teaching,
        has_lab=has_lab,
        has_transfer=has_transfer,
        diagnostic_completed=diagnostic_completed,
        guided_concept_completed=guided_concept_completed,
        concept_gate_completed=concept_gate_completed,
        lab_available=lab_available,
        lab_used=lab_used,
        mastery_check_count=mastery_check_count,
    )

    diagnostic_stage_completed = diagnostic_completed
    teaching_stage_completed = guided_concept_completed
    concept_gate_stage_completed = concept_gate_completed
    simulation_completed = lab_used
    mastery_check_completed = mastery_achieved

    stages: List[Dict[str, Any]] = [
        _stage_row(
            key="diagnostic",
            label="Initial diagnostic",
            available=has_diag,
            completed=diagnostic_stage_completed,
            active_key=current_stage,
        ),
        _stage_row(
            key="scaffolded_teaching",
            label="Guided concept building",
            available=has_teaching,
            completed=teaching_stage_completed,
            active_key=current_stage,
        ),
        _stage_row(
            key="concept_gate",
            label="Concept gate",
            available=has_teaching,
            completed=concept_gate_stage_completed,
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
        next_action = "continue_guided_concept_building"
    elif current_stage == "concept_gate":
        next_action = "attempt_concept_gate"
    elif current_stage == "simulation":
        next_action = "run_sim_lab"
    elif current_stage == "mastery_check":
        if bool(lesson_progress.get("review_required")):
            next_action = "review_required_before_retest"
        elif mastery_check_count >= 1:
            next_action = "review_or_retest"
        else:
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
            "diagnostic": {
                "min_questions": DIAGNOSTIC_MIN_QUESTIONS,
                "max_questions": DIAGNOSTIC_MAX_QUESTIONS,
                "target_question_count": int(
                    lesson_progress.get("diagnostic_target_question_count") or DIAGNOSTIC_MIN_QUESTIONS
                ),
                "completed": diagnostic_completed,
                "asked_count": int(lesson_progress.get("diagnostic_count") or 0),
                "latest_score": float(lesson_progress.get("latest_diagnostic_score") or 0.0),
            },
            "mastery_check": {
                "min_questions": MASTERY_MIN_QUESTIONS,
                "max_questions": MASTERY_MAX_QUESTIONS,
                "selected_question_count": int(
                    lesson_progress.get("mastery_question_count") or MASTERY_MIN_QUESTIONS
                ),
                "threshold": MASTERY_THRESHOLD,
                "attempt_count": mastery_check_count,
                "best_score": best_score,
                "required_correct": int(
                    lesson_progress.get("mastery_required_correct") or MASTERY_MIN_QUESTIONS
                ),
                "eligible_for_immediate_retest": bool(
                    lesson_progress.get("eligible_for_immediate_retest")
                ),
                "review_required": bool(lesson_progress.get("review_required")),
                "review_recommended": bool(lesson_progress.get("review_recommended")),
                "weak_concepts": lesson_progress.get("weak_concepts") or [],
                "recommended_review_refs": lesson_progress.get("recommended_review_refs") or [],
            },
            "stages": stages,
        },
    }