from __future__ import annotations

from typing import Any, Dict, List

from app.repositories.student_progression_repository import (
    get_module_lessons,
    get_module_progress,
    list_lesson_progress,
    get_progress_events,
)
from app.services.lesson_progress_state import (
    COMPLETION_THRESHOLD,
    apply_progress_event_to_snapshot,
    empty_lesson_progress_snapshot,
    event_lesson_id,
    normalize_lesson_progress_snapshot,
)


def _lesson_has_lab(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    sim = phases.get("simulation_inquiry") or {}
    return bool(sim.get("lab_id"))


def _lesson_has_reflection(lesson: Dict[str, Any]) -> bool:
    phases = lesson.get("phases") or {}
    reconstruction = phases.get("concept_reconstruction") or {}
    if reconstruction.get("prompts"):
        return True

    for capsule in reconstruction.get("capsules") or []:
        if not isinstance(capsule, dict):
            continue
        if capsule.get("prompt"):
            return True

    authoring = lesson.get("authoring_contract") or {}
    reflection_prompts = authoring.get("reflection_prompts") or []
    if isinstance(reflection_prompts, list):
        return any(str(prompt or "").strip() for prompt in reflection_prompts)

    return False


def _derive_instructional_status(
    *,
    diagnostic_count: int,
    teaching_completed: bool,
    concept_gate_completed: bool,
    mastery_attempt_count: int,
    completed: bool,
) -> str:
    if completed:
        return "completed"
    if mastery_attempt_count >= 1:
        return "attempted_not_completed"
    if concept_gate_completed:
        return "concept_gate_completed"
    if teaching_completed:
        return "teaching_completed"
    if diagnostic_count >= 1:
        return "diagnostic_completed"
    return "not_started"


def _derive_legacy_status(
    *,
    diagnostic_count: int,
    teaching_completed: bool,
    concept_gate_completed: bool,
    simulation_completed: bool,
    reflection_completed: bool,
    mastery_attempt_count: int,
    completed: bool,
) -> str:
    if completed:
        return "completed"
    if mastery_attempt_count >= 1:
        return "attempted_not_completed"
    if reflection_completed:
        return "reflection_completed"
    if simulation_completed:
        return "simulation_completed"
    if concept_gate_completed:
        return "concept_gate_completed"
    if teaching_completed:
        return "teaching_completed"
    if diagnostic_count >= 1:
        return "diagnostic_completed"
    return "not_started"


def _lesson_progress_snapshot_from_events(
    lesson_id: str,
    lesson_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    snapshot = empty_lesson_progress_snapshot(lesson_id)
    for ev in lesson_events:
        snapshot = apply_progress_event_to_snapshot(
            snapshot,
            lesson_id=lesson_id,
            event_type_value=ev.get("event_type"),
            score=ev.get("score"),
            details=ev.get("details") if isinstance(ev.get("details"), dict) else {},
            utc=ev.get("utc"),
        )
    return snapshot


def _merged_lesson_progress_snapshot(
    lesson_id: str,
    lesson_events: List[Dict[str, Any]],
    stored_progress: Dict[str, Any] | None,
) -> Dict[str, Any]:
    event_snapshot = normalize_lesson_progress_snapshot(
        _lesson_progress_snapshot_from_events(lesson_id, lesson_events),
        lesson_id,
    )
    if not stored_progress:
        return event_snapshot

    stored_snapshot = normalize_lesson_progress_snapshot(stored_progress, lesson_id)

    diagnostic_prefers_stored = (
        stored_snapshot.get("diagnostic_last_utc")
        and stored_snapshot.get("diagnostic_last_utc") >= event_snapshot.get("diagnostic_last_utc")
    )
    mastery_prefers_stored = (
        stored_snapshot.get("last_mastery_check_utc")
        and stored_snapshot.get("last_mastery_check_utc") >= event_snapshot.get("last_mastery_check_utc")
    )

    return {
        "lesson_id": lesson_id,
        "diagnostic_count": max(
            int(event_snapshot.get("diagnostic_count") or 0),
            int(stored_snapshot.get("diagnostic_count") or 0),
        ),
        "diagnostic_latest_score": (
            stored_snapshot.get("diagnostic_latest_score")
            if diagnostic_prefers_stored
            else event_snapshot.get("diagnostic_latest_score")
        ),
        "diagnostic_asked_count": (
            int(stored_snapshot.get("diagnostic_asked_count") or 0)
            if diagnostic_prefers_stored
            else int(event_snapshot.get("diagnostic_asked_count") or 0)
        ),
        "diagnostic_last_utc": (
            stored_snapshot.get("diagnostic_last_utc")
            if diagnostic_prefers_stored
            else event_snapshot.get("diagnostic_last_utc")
        ),
        "teaching_event_count": max(
            int(event_snapshot.get("teaching_event_count") or 0),
            int(stored_snapshot.get("teaching_event_count") or 0),
        ),
        "teaching_view_count": max(
            int(event_snapshot.get("teaching_view_count") or 0),
            int(stored_snapshot.get("teaching_view_count") or 0),
        ),
        "teaching_reconstruction_count": max(
            int(event_snapshot.get("teaching_reconstruction_count") or 0),
            int(stored_snapshot.get("teaching_reconstruction_count") or 0),
        ),
        "concept_gate_count": max(
            int(event_snapshot.get("concept_gate_count") or 0),
            int(stored_snapshot.get("concept_gate_count") or 0),
        ),
        "concept_gate_best_score": max(
            float(event_snapshot.get("concept_gate_best_score") or 0.0),
            float(stored_snapshot.get("concept_gate_best_score") or 0.0),
        ),
        "lab_used": bool(event_snapshot.get("lab_used")) or bool(stored_snapshot.get("lab_used")),
        "mastery_check_count": max(
            int(event_snapshot.get("mastery_check_count") or 0),
            int(stored_snapshot.get("mastery_check_count") or 0),
        ),
        "best_score": max(
            float(event_snapshot.get("best_score") or 0.0),
            float(stored_snapshot.get("best_score") or 0.0),
        ),
        "latest_score": (
            stored_snapshot.get("latest_score")
            if mastery_prefers_stored
            else event_snapshot.get("latest_score")
        ),
        "last_mastery_check_utc": (
            stored_snapshot.get("last_mastery_check_utc")
            if mastery_prefers_stored
            else event_snapshot.get("last_mastery_check_utc")
        ),
        "last_event_utc": max(
            str(event_snapshot.get("last_event_utc") or ""),
            str(stored_snapshot.get("last_event_utc") or ""),
        ) or None,
        "updated_utc": max(
            str(event_snapshot.get("updated_utc") or ""),
            str(stored_snapshot.get("updated_utc") or ""),
        ) or None,
    }


def _build_lesson_progress(
    lesson: Dict[str, Any],
    lesson_events: List[Dict[str, Any]],
    stored_progress: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    lesson_id = str(lesson.get("lesson_id") or lesson.get("id") or "")
    title = lesson.get("title")
    sequence = lesson.get("sequence")
    snapshot = _merged_lesson_progress_snapshot(lesson_id, lesson_events, stored_progress)

    mastery_attempt_count = int(snapshot.get("mastery_check_count") or 0)
    diagnostic_count = int(snapshot.get("diagnostic_count") or 0)
    diagnostic_latest_score = snapshot.get("diagnostic_latest_score")
    diagnostic_asked_count = int(snapshot.get("diagnostic_asked_count") or 0)
    lab_used = bool(snapshot.get("lab_used"))
    last_mastery_check_utc = snapshot.get("last_mastery_check_utc")
    latest_mastery_score = snapshot.get("latest_score")
    teaching_event_count = int(snapshot.get("teaching_event_count") or 0)
    teaching_view_count = int(snapshot.get("teaching_view_count") or 0)
    teaching_reconstruction_count = int(snapshot.get("teaching_reconstruction_count") or 0)
    concept_gate_count = int(snapshot.get("concept_gate_count") or 0)
    concept_gate_best_score = float(snapshot.get("concept_gate_best_score") or 0.0)
    best_score = float(snapshot.get("best_score") or 0.0)
    completed = best_score >= COMPLETION_THRESHOLD
    has_lab = _lesson_has_lab(lesson)
    has_reflection = _lesson_has_reflection(lesson)
    reached_mastery_stage = mastery_attempt_count >= 1 or completed
    reached_reflection_stage = teaching_reconstruction_count >= 1 or reached_mastery_stage
    reached_simulation_stage = lab_used or reached_reflection_stage
    reached_concept_gate_stage = concept_gate_count >= 1 or reached_simulation_stage
    reached_teaching_stage = teaching_event_count >= 1 or reached_concept_gate_stage

    teaching_engaged = teaching_event_count >= 1 or concept_gate_count >= 1 or lab_used or teaching_reconstruction_count >= 1
    teaching_completed = reached_teaching_stage
    concept_gate_completed = reached_concept_gate_stage
    simulation_completed = reached_simulation_stage if has_lab else False
    reflection_completed = reached_reflection_stage if has_reflection else False

    instructional_status = _derive_instructional_status(
        diagnostic_count=diagnostic_count,
        teaching_completed=teaching_completed,
        concept_gate_completed=concept_gate_completed,
        mastery_attempt_count=mastery_attempt_count,
        completed=completed,
    )
    status = _derive_legacy_status(
        diagnostic_count=diagnostic_count,
        teaching_completed=teaching_completed,
        concept_gate_completed=concept_gate_completed,
        simulation_completed=simulation_completed,
        reflection_completed=reflection_completed,
        mastery_attempt_count=mastery_attempt_count,
        completed=completed,
    )
    can_advance = completed or mastery_attempt_count >= 1

    return {
        "lesson_id": lesson_id,
        "title": title,
        "sequence": sequence,
        "best_score": round(best_score, 4),
        "latest_score": round(latest_mastery_score, 4) if latest_mastery_score is not None else None,
        "attempt_count": mastery_attempt_count,
        "completed": completed,
        "can_advance": can_advance,
        "instructional_can_advance": completed,
        "lab_available": has_lab and (not lab_used),
        "lab_used": lab_used,
        "status": status,
        "instructional_status": instructional_status,
        "diagnostic_count": diagnostic_count,
        "diagnostic_latest_score": round(diagnostic_latest_score, 4) if diagnostic_latest_score is not None else None,
        "diagnostic_asked_count": diagnostic_asked_count,
        "teaching_event_count": teaching_event_count,
        "teaching_view_count": teaching_view_count,
        "teaching_reconstruction_count": teaching_reconstruction_count,
        "teaching_engaged": teaching_engaged,
        "teaching_completed": teaching_completed,
        "concept_gate_count": concept_gate_count,
        "concept_gate_completed": concept_gate_completed,
        "concept_gate_best_score": round(concept_gate_best_score, 4),
        "simulation_completed": simulation_completed,
        "reflection_completed": reflection_completed,
        "mastery_check_count": mastery_attempt_count,
        "last_mastery_check_utc": last_mastery_check_utc,
    }


def _module_mastery_from_lessons(lesson_progress_rows: List[Dict[str, Any]]) -> float:
    if not lesson_progress_rows:
        return 0.0

    scored_rows = [row for row in lesson_progress_rows if row.get("latest_score") is not None]
    if not scored_rows:
        return 0.0

    total = sum(float(row.get("latest_score") or 0.0) for row in scored_rows)
    return round(total / len(scored_rows), 4)


def get_student_module_progress(uid: str, module_id: str) -> Dict[str, Any]:
    lessons = get_module_lessons(module_id)
    events = get_progress_events(uid, module_id)
    _ = get_module_progress(uid, module_id)
    stored_rows = list_lesson_progress(uid, module_id)

    by_lesson: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        lesson_id = event_lesson_id(ev)
        if not lesson_id:
            continue
        by_lesson.setdefault(lesson_id, []).append(ev)

    stored_by_lesson: Dict[str, Dict[str, Any]] = {}
    for row in stored_rows:
        normalized_lesson_id = str(row.get("lesson_id") or "")
        if normalized_lesson_id:
            stored_by_lesson[normalized_lesson_id] = row

    lesson_rows: List[Dict[str, Any]] = []
    for lesson in lessons:
        lesson_id = str(lesson.get("lesson_id") or lesson.get("id") or "")
        row = _build_lesson_progress(
            lesson,
            by_lesson.get(lesson_id, []),
            stored_by_lesson.get(lesson_id),
        )
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
            "latest_score": None,
            "attempt_count": 0,
            "completed": False,
            "can_advance": False,
            "instructional_can_advance": False,
            "lab_available": False,
            "lab_used": False,
            "status": "not_found",
            "instructional_status": "not_found",
            "diagnostic_count": 0,
            "diagnostic_latest_score": None,
            "diagnostic_asked_count": 0,
            "teaching_event_count": 0,
            "teaching_view_count": 0,
            "teaching_reconstruction_count": 0,
            "teaching_engaged": False,
            "teaching_completed": False,
            "concept_gate_count": 0,
            "concept_gate_completed": False,
            "concept_gate_best_score": 0.0,
            "simulation_completed": False,
            "reflection_completed": False,
            "mastery_check_count": 0,
            "last_mastery_check_utc": None,
        },
    }
