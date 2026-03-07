from __future__ import annotations

import math
from typing import Any, Dict, List

from app.common import parse_iso_utc
from app.repositories.student_progression_repository import (
    get_module_lessons,
    get_module_progress,
    get_progress_events,
)

COMPLETION_THRESHOLD = 0.80
DIAGNOSTIC_MIN_QUESTIONS = 2
DIAGNOSTIC_MAX_QUESTIONS = 5
MASTERY_MIN_QUESTIONS = 5
MASTERY_MAX_QUESTIONS = 10
MASTERY_EVENT_TYPES = {"transfer"}


def _safe_score(v: Any) -> float:
    try:
        if v is None:
            return 0.0
        return max(0.0, min(1.0, float(v)))
    except Exception:
        return 0.0


def _event_lesson_id(ev: Dict[str, Any]) -> str | None:
    details = ev.get("details")
    if not isinstance(details, dict):
        return None
    lesson_id = details.get("lesson_id")
    if not lesson_id:
        return None
    return str(lesson_id).replace("-", "_")


def _event_type(ev: Dict[str, Any]) -> str:
    return str(ev.get("event_type") or "").strip().lower()


def _event_details(ev: Dict[str, Any]) -> Dict[str, Any]:
    details = ev.get("details")
    return details if isinstance(details, dict) else {}


def _event_source(ev: Dict[str, Any]) -> str:
    return str(_event_details(ev).get("source") or "").strip().lower()


def _event_stage(ev: Dict[str, Any]) -> str:
    return str(_event_details(ev).get("stage") or "").strip().lower()


def _lesson_has_lab(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    sim = phases.get("simulation_inquiry") or {}
    return bool(sim.get("lab_id"))


def _lesson_has_diagnostic_items(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    diagnostic = phases.get("diagnostic") or {}
    items = diagnostic.get("items") or []
    return bool(items)


def _lesson_has_teaching(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    analogical = phases.get("analogical_grounding") or {}
    reconstruction = phases.get("concept_reconstruction") or {}
    has_analogy = bool(analogical.get("analogy_text"))
    has_reconstruction = bool(reconstruction.get("prompts") or [])
    return has_analogy or has_reconstruction


def _lesson_has_transfer_items(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    transfer = phases.get("transfer") or {}
    items = transfer.get("items") or []
    return bool(items)


def _diagnostic_target_question_count(score: float) -> int:
    if score < 0.40:
        return 2
    if score < 0.60:
        return 3
    if score < 0.80:
        return 4
    return 5


def _mastery_target_question_count(readiness_score: float) -> int:
    if readiness_score < 0.40:
        return 5
    if readiness_score < 0.55:
        return 6
    if readiness_score < 0.70:
        return 7
    if readiness_score < 0.80:
        return 8
    if readiness_score < 0.90:
        return 9
    return 10


def _review_required(score: float) -> bool:
    return score < 0.40


def _review_recommended(score: float) -> bool:
    return 0.40 <= score < COMPLETION_THRESHOLD


def _extract_review_refs(tags: List[str]) -> List[str]:
    ref_map = {
        "unit_conversion": "concept_unit_conversion",
        "si_prefixes": "concept_prefix_scaling",
        "scalar_vs_vector": "concept_scalar_vector_difference",
        "reading_scales": "concept_reading_scales",
        "significant_figures": "concept_significant_figures",
        "rounding_rules": "concept_rounding_rules",
        "precision_vs_accuracy": "concept_precision_accuracy",
        "random_vs_systematic_error": "concept_random_systematic_error",
        "uncertainty_estimation": "concept_uncertainty_estimation",
        "density_concept": "concept_density_meaning",
        "density_units": "concept_density_units",
    }
    refs: List[str] = []
    for tag in tags:
        ref = ref_map.get(tag)
        if ref and ref not in refs:
            refs.append(ref)
    return refs[:6]


def _build_lesson_progress(
    lesson: Dict[str, Any],
    lesson_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    lesson_id = str(lesson.get("lesson_id") or lesson.get("id") or "")
    title = lesson.get("title")
    sequence = lesson.get("sequence")

    lesson_events = sorted(
        lesson_events,
        key=lambda ev: parse_iso_utc(ev.get("utc")),
    )

    mastery_scores: List[float] = []
    mastery_attempts: List[Dict[str, Any]] = []
    diagnostic_scores: List[float] = []
    diagnostic_event_count = 0
    lab_used = False
    guided_concept_completed = False
    concept_gate_completed = False
    last_mastery_check_utc = None
    weak_concepts: List[str] = []

    for ev in lesson_events:
        et = _event_type(ev)
        source = _event_source(ev)
        stage = _event_stage(ev)
        score = _safe_score(ev.get("score"))
        tags = ev.get("misconception_tags") or []
        if not isinstance(tags, list):
            tags = []

        if et == "diagnostic":
            diagnostic_event_count += 1
            diagnostic_scores.append(score)

        if et in MASTERY_EVENT_TYPES:
            mastery_scores.append(score)
            mastery_attempts.append(
                {
                    "score": score,
                    "utc": ev.get("utc"),
                    "tags": [str(tag) for tag in tags[:10]],
                }
            )
            ev_utc = ev.get("utc")
            if last_mastery_check_utc is None or parse_iso_utc(ev_utc) > parse_iso_utc(last_mastery_check_utc):
                last_mastery_check_utc = ev_utc
                weak_concepts = [str(tag) for tag in tags[:10]]

        if et == "simulation":
            lab_used = True

        if et == "reflection":
            if source in {
                "student_runner_scaffolded_teaching",
                "student_runner_concept_reconstruction",
                "student_runner_guided_concept_building",
            } or stage == "scaffolded_teaching":
                guided_concept_completed = True

            if source in {
                "student_runner_concept_gate",
                "student_runner_concept_gate_check",
            } or stage == "concept_gate":
                concept_gate_completed = True

    latest_diagnostic_score = diagnostic_scores[-1] if diagnostic_scores else 0.0
    diagnostic_target_question_count = _diagnostic_target_question_count(latest_diagnostic_score)
    diagnostic_completed = diagnostic_event_count >= 1

    best_score = max(mastery_scores) if mastery_scores else 0.0
    completed = best_score >= COMPLETION_THRESHOLD

    latest_mastery_score = mastery_scores[-1] if mastery_scores else 0.0
    mastery_check_count = len(mastery_scores)
    readiness_score = max(latest_diagnostic_score, latest_mastery_score, 0.0)
    mastery_question_count = _mastery_target_question_count(readiness_score)
    mastery_required_correct = int(math.ceil(mastery_question_count * COMPLETION_THRESHOLD))

    has_lab = _lesson_has_lab(lesson)
    has_teaching = _lesson_has_teaching(lesson)

    if completed:
        status = "completed"
    elif mastery_check_count >= 1:
        status = "attempted_not_completed"
    elif concept_gate_completed:
        status = "concept_gate_completed"
    elif guided_concept_completed:
        status = "guided_concept_completed"
    elif diagnostic_completed:
        status = "diagnostic_completed"
    else:
        status = "not_started"

    return {
        "lesson_id": lesson_id,
        "title": title,
        "sequence": sequence,
        "best_score": round(best_score, 4),
        "attempt_count": mastery_check_count,
        "completed": completed,
        "can_advance": completed,
        "lab_available": has_lab and (not lab_used),
        "lab_used": lab_used,
        "status": status,
        "diagnostic_count": diagnostic_event_count,
        "diagnostic_completed": diagnostic_completed,
        "diagnostic_target_question_count": diagnostic_target_question_count,
        "guided_concept_completed": guided_concept_completed or not has_teaching,
        "concept_gate_completed": concept_gate_completed,
        "mastery_check_count": mastery_check_count,
        "last_mastery_check_utc": last_mastery_check_utc,
        "latest_mastery_score": round(latest_mastery_score, 4),
        "mastery_question_count": mastery_question_count,
        "mastery_required_correct": mastery_required_correct,
        "eligible_for_immediate_retest": mastery_check_count >= 1 and not completed,
        "review_required": _review_required(latest_mastery_score) if mastery_check_count else False,
        "review_recommended": _review_recommended(latest_mastery_score) if mastery_check_count else False,
        "weak_concepts": weak_concepts[:6],
        "recommended_review_refs": _extract_review_refs(weak_concepts),
        "latest_diagnostic_score": round(latest_diagnostic_score, 4),
    }


def _module_mastery_from_lessons(lesson_progress_rows: List[Dict[str, Any]]) -> float:
    if not lesson_progress_rows:
        return 0.0
    total = sum(float(row.get("best_score") or 0.0) for row in lesson_progress_rows)
    return round(total / len(lesson_progress_rows), 4)


def get_student_module_progress(uid: str, module_id: str) -> Dict[str, Any]:
    lessons = get_module_lessons(module_id)
    events = get_progress_events(uid, module_id)
    _ = get_module_progress(uid, module_id)

    by_lesson: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        lesson_id = _event_lesson_id(ev)
        if not lesson_id:
            continue
        by_lesson.setdefault(lesson_id, []).append(ev)

    lesson_rows: List[Dict[str, Any]] = []
    for lesson in lessons:
        lesson_id = str(lesson.get("lesson_id") or lesson.get("id") or "")
        row = _build_lesson_progress(lesson, by_lesson.get(lesson_id, []))
        lesson_rows.append(row)

    module_mastery = _module_mastery_from_lessons(lesson_rows)
    lessons_completed_count = sum(1 for row in lesson_rows if row.get("completed") is True)

    module = {
        "module_id": module_id,
        "module_mastery": module_mastery,
        "lessons_completed_count": lessons_completed_count,
        "total_lessons": len(lesson_rows),
    }

    return {
        "module": module,
        "lessons": lesson_rows,
    }


def get_student_lesson_progress(uid: str, module_id: str, lesson_id: str) -> Dict[str, Any]:
    normalized = str(lesson_id).replace("-", "_")
    payload = get_student_module_progress(uid, module_id)

    for lesson in payload["lessons"]:
        if lesson["lesson_id"] == normalized:
            return {
                "module": payload["module"],
                "lesson": lesson,
            }

    return {
        "module": payload["module"],
        "lesson": {
            "lesson_id": normalized,
            "title": None,
            "sequence": None,
            "best_score": 0.0,
            "attempt_count": 0,
            "completed": False,
            "can_advance": False,
            "lab_available": False,
            "lab_used": False,
            "status": "not_found",
            "diagnostic_count": 0,
            "diagnostic_completed": False,
            "diagnostic_target_question_count": DIAGNOSTIC_MIN_QUESTIONS,
            "guided_concept_completed": False,
            "concept_gate_completed": False,
            "mastery_check_count": 0,
            "last_mastery_check_utc": None,
            "latest_mastery_score": 0.0,
            "mastery_question_count": MASTERY_MIN_QUESTIONS,
            "mastery_required_correct": int(math.ceil(MASTERY_MIN_QUESTIONS * COMPLETION_THRESHOLD)),
            "eligible_for_immediate_retest": False,
            "review_required": False,
            "review_recommended": False,
            "weak_concepts": [],
            "recommended_review_refs": [],
            "latest_diagnostic_score": 0.0,
        },
    }