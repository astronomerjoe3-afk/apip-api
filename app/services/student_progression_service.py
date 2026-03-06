from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app.common import parse_iso_utc
from app.repositories.student_progression_repository import (
    get_module_lessons,
    get_module_progress,
    get_progress_events,
)


COMPLETION_THRESHOLD = 0.80


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


def _lesson_has_lab(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    sim = phases.get("simulation_inquiry") or {}
    lab_id = sim.get("lab_id")
    return bool(lab_id)


def _build_lesson_progress(
    lesson: Dict[str, Any],
    lesson_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    lesson_id = str(lesson.get("lesson_id") or lesson.get("id") or "")
    title = lesson.get("title")
    sequence = lesson.get("sequence")

    scored_events: List[Tuple[float, float]] = []
    attempt_count = 0
    lab_used = False

    for ev in lesson_events:
        et = _event_type(ev)
        if et in ("attempt", "transfer", "diagnostic"):
            score = _safe_score(ev.get("score"))
            ts = parse_iso_utc(ev.get("utc"))
            scored_events.append((score, ts))
            if et in ("attempt", "transfer"):
                attempt_count += 1

        if et == "simulation":
            lab_used = True

    best_score = 0.0
    if scored_events:
        best_score = max(score for score, _ in scored_events)

    completed = best_score >= COMPLETION_THRESHOLD

    # Product rule:
    # - if first attempt < 80%, student may move on
    # - but lesson is only "Completed" at 80–100%
    # So can_advance is true if:
    #   a) completed, or
    #   b) at least one attempt exists
    can_advance = completed or attempt_count >= 1

    if completed:
        status = "completed"
    elif attempt_count >= 1:
        status = "attempted_not_completed"
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
    }


def _module_mastery_from_lessons(lesson_progress_rows: List[Dict[str, Any]]) -> float:
    if not lesson_progress_rows:
        return 0.0
    total = sum(float(row.get("best_score") or 0.0) for row in lesson_progress_rows)
    return round(total / len(lesson_progress_rows), 4)


def get_student_module_progress(uid: str, module_id: str) -> Dict[str, Any]:
    lessons = get_module_lessons(module_id)
    events = get_progress_events(uid, module_id)
    _ = get_module_progress(uid, module_id)  # kept for future parity, even if not used directly

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

    # If lesson is missing from canonical lesson list, return a safe default
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
        },
    }
