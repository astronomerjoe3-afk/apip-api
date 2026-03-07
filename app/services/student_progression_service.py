from __future__ import annotations

from typing import Any, Dict, List

from app.common import parse_iso_utc
from app.repositories.student_progression_repository import (
    get_module_lessons,
    get_module_progress,
    get_progress_events,
)

COMPLETION_THRESHOLD = 0.80
MASTERY_EVENT_TYPES = {"transfer"}

TEACHING_VIEW_SOURCES = {
    "student_runner_scaffolded_teaching",
    "student_runner_scaffolded_teaching_viewed",
}
TEACHING_RECONSTRUCTION_SOURCES = {
    "student_runner_concept_reconstruction",
}
CONCEPT_GATE_SOURCES = {
    "student_runner_concept_gate",
}


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


def _event_source(ev: Dict[str, Any]) -> str:
    details = ev.get("details")
    if not isinstance(details, dict):
        return ""
    return str(details.get("source") or "").strip().lower()


def _lesson_has_lab(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    sim = phases.get("simulation_inquiry") or {}
    return bool(sim.get("lab_id"))


def _build_lesson_progress(
    lesson: Dict[str, Any],
    lesson_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    lesson_id = str(lesson.get("lesson_id") or lesson.get("id") or "")
    title = lesson.get("title")
    sequence = lesson.get("sequence")

    mastery_scores: List[float] = []
    attempt_count = 0
    diagnostic_count = 0
    lab_used = False
    last_mastery_check_utc = None

    teaching_view_count = 0
    teaching_reconstruction_count = 0
    concept_gate_count = 0
    concept_gate_best_score = 0.0

    for ev in lesson_events:
        et = _event_type(ev)
        source = _event_source(ev)

        if et == "diagnostic":
            diagnostic_count += 1

        if et in ("attempt", "transfer"):
            attempt_count += 1

        if et in MASTERY_EVENT_TYPES:
            score = _safe_score(ev.get("score"))
            mastery_scores.append(score)
            ev_utc = ev.get("utc")
            if last_mastery_check_utc is None or parse_iso_utc(ev_utc) > parse_iso_utc(last_mastery_check_utc):
                last_mastery_check_utc = ev_utc

        if et == "simulation":
            lab_used = True

        if et == "reflection":
            if source in TEACHING_VIEW_SOURCES:
                teaching_view_count += 1
            elif source in TEACHING_RECONSTRUCTION_SOURCES:
                teaching_reconstruction_count += 1
            elif source in CONCEPT_GATE_SOURCES:
                concept_gate_count += 1
                concept_gate_best_score = max(concept_gate_best_score, _safe_score(ev.get("score")))

    best_score = max(mastery_scores) if mastery_scores else 0.0
    completed = best_score >= COMPLETION_THRESHOLD

    teaching_engaged = (teaching_view_count + teaching_reconstruction_count) >= 1
    teaching_completed = teaching_reconstruction_count >= 1 or teaching_view_count >= 1
    concept_gate_completed = concept_gate_count >= 1

    # Product rule:
    # - lesson completion only at 80%+ mastery check
    # - learner may move on after at least one mastery-check attempt
    can_advance = completed or len(mastery_scores) >= 1

    if completed:
        status = "completed"
    elif len(mastery_scores) >= 1:
        status = "attempted_not_completed"
    elif concept_gate_completed:
        status = "concept_gate_completed"
    elif teaching_completed:
        status = "teaching_completed"
    elif diagnostic_count >= 1:
        status = "diagnostic_completed"
    else:
        status = "not_started"

    has_lab = _lesson_has_lab(lesson)

    return {
        "lesson_id": lesson_id,
        "title": title,
        "sequence": sequence,
        "best_score": round(best_score, 4),
        "attempt_count": attempt_count,
        "completed": completed,
        "can_advance": can_advance,
        "lab_available": has_lab and (not lab_used),
        "lab_used": lab_used,
        "status": status,
        "diagnostic_count": diagnostic_count,
        "teaching_view_count": teaching_view_count,
        "teaching_reconstruction_count": teaching_reconstruction_count,
        "teaching_engaged": teaching_engaged,
        "teaching_completed": teaching_completed,
        "concept_gate_count": concept_gate_count,
        "concept_gate_completed": concept_gate_completed,
        "concept_gate_best_score": round(concept_gate_best_score, 4),
        "mastery_check_count": len(mastery_scores),
        "last_mastery_check_utc": last_mastery_check_utc,
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
            "teaching_view_count": 0,
            "teaching_reconstruction_count": 0,
            "teaching_engaged": False,
            "teaching_completed": False,
            "concept_gate_count": 0,
            "concept_gate_completed": False,
            "concept_gate_best_score": 0.0,
            "mastery_check_count": 0,
            "last_mastery_check_utc": None,
        },
    }