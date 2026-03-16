from __future__ import annotations

from math import ceil
from typing import Any, Dict, List

from app.common import normalize_module_id
from app.repositories.catalog_repository import get_lesson_by_doc_id, get_lesson_by_fields
from app.services.student_progression_service import get_student_lesson_progress

MASTERY_THRESHOLD = 0.80
DIAGNOSTIC_MIN_QUESTIONS = 2
DIAGNOSTIC_MAX_QUESTIONS = 5
MASTERY_MIN_QUESTIONS = 5
MASTERY_MAX_QUESTIONS = 10


def _load_lesson(module_id: str, lesson_id: str) -> Dict[str, Any] | None:
    normalized_module_id = normalize_module_id(module_id)
    normalized = str(lesson_id).replace("-", "_")

    lesson = get_lesson_by_doc_id(normalized)
    if lesson and normalize_module_id(lesson.get("module_id")) == normalized_module_id:
        return lesson

    lesson = get_lesson_by_fields(normalized_module_id, normalized)
    if lesson:
        return lesson

    return None


def _phases(lesson: Dict[str, Any]) -> Dict[str, Any]:
    phases = lesson.get("phases") or {}
    return phases if isinstance(phases, dict) else {}


def _has_diagnostic(lesson: Dict[str, Any]) -> bool:
    diagnostic = _phases(lesson).get("diagnostic") or {}
    items = diagnostic.get("items") or []
    return len(items) > 0


def _has_teaching(lesson: Dict[str, Any]) -> bool:
    phases = _phases(lesson)
    analogical = phases.get("analogical_grounding") or {}
    reconstruction = phases.get("concept_reconstruction") or {}

    has_analogy = bool(analogical.get("analogy_text"))
    has_micro_prompts = bool(analogical.get("micro_prompts") or [])
    has_prompts = bool(reconstruction.get("prompts") or [])
    has_capsules = bool(reconstruction.get("capsules") or [])
    return has_analogy or has_micro_prompts or has_prompts or has_capsules


def _has_concept_gate(lesson: Dict[str, Any]) -> bool:
    reconstruction = _phases(lesson).get("concept_reconstruction") or {}
    capsules = reconstruction.get("capsules") or []

    for capsule in capsules:
        if not isinstance(capsule, dict):
            continue
        if capsule.get("checks"):
            return True

    transfer = _phases(lesson).get("transfer") or {}
    return len(transfer.get("items") or []) > 0


def _has_reflection(lesson: Dict[str, Any]) -> bool:
    reconstruction = _phases(lesson).get("concept_reconstruction") or {}
    if reconstruction.get("prompts"):
        return True

    for capsule in reconstruction.get("capsules") or []:
        if not isinstance(capsule, dict):
            continue
        if capsule.get("prompt"):
            return True

    return False


def _has_sim_lab(lesson: Dict[str, Any]) -> bool:
    sim = _phases(lesson).get("simulation_inquiry") or {}
    return bool(sim.get("lab_id"))


def _has_transfer(lesson: Dict[str, Any]) -> bool:
    transfer = _phases(lesson).get("transfer") or {}
    items = transfer.get("items") or []
    return len(items) > 0


def _question_count(lesson: Dict[str, Any], phase_key: str) -> int:
    phase = _phases(lesson).get(phase_key) or {}
    items = phase.get("items") or []
    return len(items)


def _capsule_check_count(lesson: Dict[str, Any]) -> int:
    reconstruction = _phases(lesson).get("concept_reconstruction") or {}
    capsules = reconstruction.get("capsules") or []
    total = 0
    for capsule in capsules:
        if not isinstance(capsule, dict):
            continue
        total += len(capsule.get("checks") or [])
    return total


def _estimated_mastery_bank_size(lesson: Dict[str, Any]) -> int:
    base_count = _question_count(lesson, "transfer") + _capsule_check_count(lesson)
    if base_count <= 0:
        return 0

    phases = _phases(lesson)
    analogical = phases.get("analogical_grounding") or {}
    reconstruction = phases.get("concept_reconstruction") or {}
    support_count = len(analogical.get("micro_prompts") or []) + len(reconstruction.get("prompts") or [])
    estimated = base_count + support_count + 4
    return max(base_count, min(MASTERY_MAX_QUESTIONS, estimated))

def _target_diagnostic_question_count(latest_score: float | None) -> int:
    score = 0.0 if latest_score is None else max(0.0, min(1.0, float(latest_score)))
    if score < 0.4:
        return 2
    if score < 0.6:
        return 3
    if score < 0.8:
        return 4
    return 5


def _target_mastery_question_count(question_bank_size: int, performance_score: float | None) -> int:
    bounded_bank = max(0, int(question_bank_size))
    if bounded_bank <= 0:
        return 0

    lower_bound = min(MASTERY_MIN_QUESTIONS, bounded_bank)
    upper_bound = min(MASTERY_MAX_QUESTIONS, bounded_bank)

    if performance_score is None:
        target = lower_bound
    elif performance_score < 0.4:
        target = 5
    elif performance_score < 0.55:
        target = 6
    elif performance_score < 0.7:
        target = 7
    elif performance_score < 0.8:
        target = 8
    elif performance_score < 0.9:
        target = 9
    else:
        target = 10

    return max(lower_bound, min(upper_bound, target))


def _required_correct(selected_question_count: int, threshold: float) -> int:
    if selected_question_count <= 0:
        return 0
    return int(ceil(selected_question_count * threshold))


def _derive_current_stage(
    lesson_status: str,
    mastery_achieved: bool,
    has_diag: bool,
    has_teaching: bool,
    has_concept_gate: bool,
    has_lab: bool,
    lab_available: bool,
    lab_used: bool,
    has_reflection: bool,
    reflection_completed: bool,
    has_transfer: bool,
) -> str:
    if mastery_achieved:
        return "done"

    if lesson_status == "not_started":
        if has_diag:
            return "diagnostic"
        if has_teaching:
            return "scaffolded_teaching"
        if has_concept_gate:
            return "concept_gate"
        if has_lab and lab_available:
            return "simulation"
        if has_reflection and not reflection_completed:
            return "reflection"
        if has_transfer:
            return "mastery_check"
        return "done"

    if lesson_status == "diagnostic_completed":
        if has_teaching:
            return "scaffolded_teaching"
        if has_concept_gate:
            return "concept_gate"
        if has_lab and lab_available and not lab_used:
            return "simulation"
        if has_reflection and not reflection_completed:
            return "reflection"
        if has_transfer:
            return "mastery_check"
        return "done"

    if lesson_status == "teaching_completed":
        if has_concept_gate:
            return "concept_gate"
        if has_lab and lab_available and not lab_used:
            return "simulation"
        if has_reflection and not reflection_completed:
            return "reflection"
        if has_transfer:
            return "mastery_check"
        return "done"

    if lesson_status == "concept_gate_completed":
        if has_lab and lab_available and not lab_used:
            return "simulation"
        if has_reflection and not reflection_completed:
            return "reflection"
        if has_transfer:
            return "mastery_check"
        return "done"

    if lesson_status == "simulation_completed":
        if has_reflection and not reflection_completed:
            return "reflection"
        if has_transfer:
            return "mastery_check"
        return "done"

    if lesson_status == "reflection_completed":
        if has_transfer:
            return "mastery_check"
        return "done"

    if lesson_status == "attempted_not_completed":
        if has_transfer:
            return "mastery_check"
        if has_reflection and not reflection_completed:
            return "reflection"
        if has_lab and lab_available and not lab_used:
            return "simulation"
        return "done"

    if has_teaching:
        return "scaffolded_teaching"
    if has_concept_gate:
        return "concept_gate"
    if has_lab and lab_available and not lab_used:
        return "simulation"
    if has_reflection and not reflection_completed:
        return "reflection"
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


def _diagnostic_contract(lesson: Dict[str, Any], lesson_progress: Dict[str, Any]) -> Dict[str, Any]:
    total_items = _question_count(lesson, "diagnostic")
    latest_score = lesson_progress.get("diagnostic_latest_score")

    target_count = min(
        max(DIAGNOSTIC_MIN_QUESTIONS, _target_diagnostic_question_count(latest_score)),
        min(DIAGNOSTIC_MAX_QUESTIONS, total_items if total_items > 0 else DIAGNOSTIC_MAX_QUESTIONS),
    )

    return {
        "min_questions": DIAGNOSTIC_MIN_QUESTIONS,
        "max_questions": DIAGNOSTIC_MAX_QUESTIONS,
        "target_question_count": target_count,
        "completed": int(lesson_progress.get("diagnostic_count") or 0) >= 1,
        "asked_count": int(lesson_progress.get("diagnostic_asked_count") or 0),
        "latest_score": latest_score,
    }


def _mastery_contract(lesson: Dict[str, Any], lesson_progress: Dict[str, Any]) -> Dict[str, Any]:
    bank_size = _estimated_mastery_bank_size(lesson)
    performance_score = lesson_progress.get("best_score") if int(lesson_progress.get("mastery_check_count") or 0) >= 1 else lesson_progress.get("diagnostic_latest_score")
    selected_count = _target_mastery_question_count(bank_size, performance_score)
    best_score = float(lesson_progress.get("best_score") or 0.0)
    latest_score = lesson_progress.get("latest_score")
    attempt_count = int(lesson_progress.get("mastery_check_count") or 0)

    weak_concepts: List[str] = []
    recommended_review_refs: List[str] = []

    if best_score < MASTERY_THRESHOLD and attempt_count >= 1:
        recommended_review_refs = [
            "concept_precision_accuracy",
            "concept_unit_conversion",
            "concept_prefix_scaling",
        ]

    return {
        "min_questions": MASTERY_MIN_QUESTIONS,
        "max_questions": MASTERY_MAX_QUESTIONS,
        "selected_question_count": selected_count,
        "threshold": MASTERY_THRESHOLD,
        "attempt_count": attempt_count,
        "best_score": round(best_score, 4),
        "latest_score": round(float(latest_score), 4) if latest_score is not None else None,
        "required_correct": _required_correct(selected_count, MASTERY_THRESHOLD),
        "eligible_for_immediate_retest": attempt_count >= 1 and best_score < MASTERY_THRESHOLD,
        "review_required": attempt_count >= 1 and best_score < MASTERY_THRESHOLD,
        "review_recommended": attempt_count >= 1 and best_score < MASTERY_THRESHOLD,
        "weak_concepts": weak_concepts,
        "recommended_review_refs": recommended_review_refs,
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
                "latest_score": None,
                "mastery_threshold": MASTERY_THRESHOLD,
                "mastery_achieved": False,
                "can_advance": False,
                "lesson_status": "not_found",
                "active_stage": "diagnostic",
                "next_recommended_action": "lesson_not_found",
                "diagnostic": {
                    "min_questions": DIAGNOSTIC_MIN_QUESTIONS,
                    "max_questions": DIAGNOSTIC_MAX_QUESTIONS,
                    "target_question_count": DIAGNOSTIC_MIN_QUESTIONS,
                    "completed": False,
                    "asked_count": 0,
                    "latest_score": None,
                },
                "mastery_check": {
                    "min_questions": MASTERY_MIN_QUESTIONS,
                    "max_questions": MASTERY_MAX_QUESTIONS,
                    "selected_question_count": 0,
                    "threshold": MASTERY_THRESHOLD,
                    "attempt_count": 0,
                    "best_score": 0.0,
                    "latest_score": None,
                    "required_correct": 0,
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
    latest_score = lesson_progress.get("latest_score")
    mastery_achieved = best_score >= MASTERY_THRESHOLD
    lab_available = bool(lesson_progress.get("lab_available"))
    lab_used = bool(lesson_progress.get("lab_used"))
    reflection_completed = bool(lesson_progress.get("reflection_completed"))
    lesson_status = str(lesson_progress.get("status") or "not_started")

    has_diag = _has_diagnostic(lesson)
    has_teaching = _has_teaching(lesson)
    has_concept_gate = _has_concept_gate(lesson)
    has_lab = _has_sim_lab(lesson)
    has_reflection = _has_reflection(lesson)
    has_transfer = _has_transfer(lesson)

    current_stage = _derive_current_stage(
        lesson_status=lesson_status,
        mastery_achieved=mastery_achieved,
        has_diag=has_diag,
        has_teaching=has_teaching,
        has_concept_gate=has_concept_gate,
        has_lab=has_lab,
        lab_available=lab_available,
        lab_used=lab_used,
        has_reflection=has_reflection,
        reflection_completed=reflection_completed,
        has_transfer=has_transfer,
    )

    diagnostic_completed = has_diag and lesson_status in (
        "diagnostic_completed",
        "teaching_completed",
        "concept_gate_completed",
        "simulation_completed",
        "reflection_completed",
        "attempted_not_completed",
        "completed",
    )
    teaching_completed = has_teaching and lesson_status in (
        "teaching_completed",
        "concept_gate_completed",
        "simulation_completed",
        "reflection_completed",
        "attempted_not_completed",
        "completed",
    )
    concept_gate_completed = has_concept_gate and lesson_status in (
        "concept_gate_completed",
        "simulation_completed",
        "reflection_completed",
        "attempted_not_completed",
        "completed",
    )
    simulation_completed = has_lab and lesson_status in (
        "simulation_completed",
        "reflection_completed",
        "attempted_not_completed",
        "completed",
    )
    reflection_stage_completed = has_reflection and lesson_status in (
        "reflection_completed",
        "attempted_not_completed",
        "completed",
    )
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
            label="Guided lesson",
            available=has_teaching,
            completed=teaching_completed,
            active_key=current_stage,
        ),
        _stage_row(
            key="concept_gate",
            label="Concept check",
            available=has_concept_gate,
            completed=concept_gate_completed,
            active_key=current_stage,
        ),
        _stage_row(
            key="simulation",
            label="Try it out",
            available=has_lab,
            completed=simulation_completed,
            active_key=current_stage if lab_available or simulation_completed else "",
        ),
        _stage_row(
            key="reflection",
            label="Explain it back",
            available=has_reflection,
            completed=reflection_stage_completed,
            active_key=current_stage,
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
    elif current_stage == "concept_gate":
        next_action = "pass_concept_gate"
    elif current_stage == "simulation":
        next_action = "run_sim_lab"
    elif current_stage == "reflection":
        next_action = "submit_reflection"
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
            "best_score": round(best_score, 4),
            "latest_score": round(float(latest_score), 4) if latest_score is not None else None,
            "mastery_threshold": MASTERY_THRESHOLD,
            "mastery_achieved": mastery_achieved,
            "can_advance": mastery_achieved or bool(lesson_progress.get("can_advance")),
            "lesson_status": lesson_status,
            "active_stage": current_stage,
            "next_recommended_action": next_action,
            "diagnostic": _diagnostic_contract(lesson, lesson_progress),
            "mastery_check": _mastery_contract(lesson, lesson_progress),
            "stages": stages,
        },
    }
