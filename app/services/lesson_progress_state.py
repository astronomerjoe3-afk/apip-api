from __future__ import annotations

from typing import Any, Dict

from app.common import parse_iso_utc

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
TEACHING_EVENT_SOURCES = TEACHING_VIEW_SOURCES | TEACHING_RECONSTRUCTION_SOURCES


def normalize_lesson_id(value: Any) -> str:
    return str(value or "").replace("-", "_")


def safe_score(value: Any) -> float:
    try:
        if value is None:
            return 0.0
        return max(0.0, min(1.0, float(value)))
    except Exception:
        return 0.0


def event_type(event: Dict[str, Any]) -> str:
    return str(event.get("event_type") or "").strip().lower()


def event_source(event: Dict[str, Any]) -> str:
    details = event.get("details")
    if not isinstance(details, dict):
        return ""
    return str(details.get("source") or "").strip().lower()


def event_lesson_id(event: Dict[str, Any]) -> str | None:
    details = event.get("details")
    if not isinstance(details, dict):
        return None
    lesson_id = details.get("lesson_id")
    if not lesson_id:
        return None
    return normalize_lesson_id(lesson_id)


def empty_lesson_progress_snapshot(lesson_id: str = "") -> Dict[str, Any]:
    normalized_lesson_id = normalize_lesson_id(lesson_id)
    return {
        "lesson_id": normalized_lesson_id,
        "diagnostic_count": 0,
        "diagnostic_latest_score": None,
        "diagnostic_asked_count": 0,
        "diagnostic_last_utc": None,
        "teaching_event_count": 0,
        "teaching_view_count": 0,
        "teaching_reconstruction_count": 0,
        "concept_gate_count": 0,
        "concept_gate_best_score": 0.0,
        "lab_used": False,
        "mastery_check_count": 0,
        "best_score": 0.0,
        "latest_score": None,
        "last_mastery_check_utc": None,
        "last_event_utc": None,
        "updated_utc": None,
    }


def normalize_lesson_progress_snapshot(snapshot: Dict[str, Any] | None, lesson_id: str = "") -> Dict[str, Any]:
    baseline = empty_lesson_progress_snapshot(lesson_id)
    raw = snapshot if isinstance(snapshot, dict) else {}

    lesson_value = normalize_lesson_id(raw.get("lesson_id") or baseline["lesson_id"])
    baseline["lesson_id"] = lesson_value
    baseline["diagnostic_count"] = max(0, int(raw.get("diagnostic_count") or 0))
    diagnostic_latest_score = raw.get("diagnostic_latest_score")
    baseline["diagnostic_latest_score"] = (
        round(safe_score(diagnostic_latest_score), 4) if diagnostic_latest_score is not None else None
    )
    baseline["diagnostic_asked_count"] = max(0, int(raw.get("diagnostic_asked_count") or 0))
    baseline["diagnostic_last_utc"] = raw.get("diagnostic_last_utc")
    baseline["teaching_event_count"] = max(0, int(raw.get("teaching_event_count") or 0))
    baseline["teaching_view_count"] = max(0, int(raw.get("teaching_view_count") or 0))
    baseline["teaching_reconstruction_count"] = max(0, int(raw.get("teaching_reconstruction_count") or 0))
    baseline["concept_gate_count"] = max(0, int(raw.get("concept_gate_count") or 0))
    baseline["concept_gate_best_score"] = round(safe_score(raw.get("concept_gate_best_score")), 4)
    baseline["lab_used"] = bool(raw.get("lab_used"))
    baseline["mastery_check_count"] = max(0, int(raw.get("mastery_check_count") or 0))
    baseline["best_score"] = round(safe_score(raw.get("best_score")), 4)
    latest_score = raw.get("latest_score")
    baseline["latest_score"] = round(safe_score(latest_score), 4) if latest_score is not None else None
    baseline["last_mastery_check_utc"] = raw.get("last_mastery_check_utc")
    baseline["last_event_utc"] = raw.get("last_event_utc")
    baseline["updated_utc"] = raw.get("updated_utc")
    return baseline


def apply_progress_event_to_snapshot(
    snapshot: Dict[str, Any] | None,
    *,
    lesson_id: str,
    event_type_value: str,
    score: Any,
    details: Dict[str, Any] | None,
    utc: Any,
) -> Dict[str, Any]:
    normalized_details = details if isinstance(details, dict) else {}
    current = normalize_lesson_progress_snapshot(snapshot, lesson_id)
    event_name = str(event_type_value or "").strip().lower()
    event_score = safe_score(score) if score is not None else None
    event_utc = str(utc or "")
    source = str(normalized_details.get("source") or "").strip().lower()

    if event_name == "diagnostic":
        current["diagnostic_count"] = int(current["diagnostic_count"]) + 1
        if parse_iso_utc(event_utc) >= parse_iso_utc(current.get("diagnostic_last_utc")):
            current["diagnostic_latest_score"] = round(event_score or 0.0, 4)
            current["diagnostic_asked_count"] = max(0, int(normalized_details.get("asked_count") or 0))
            current["diagnostic_last_utc"] = event_utc

    if event_name in MASTERY_EVENT_TYPES:
        current["mastery_check_count"] = int(current["mastery_check_count"]) + 1
        mastery_score = round(event_score or 0.0, 4)
        current["best_score"] = round(max(float(current.get("best_score") or 0.0), mastery_score), 4)
        if parse_iso_utc(event_utc) >= parse_iso_utc(current.get("last_mastery_check_utc")):
            current["latest_score"] = mastery_score
            current["last_mastery_check_utc"] = event_utc

    if event_name == "simulation":
        current["lab_used"] = True

    if event_name == "reflection":
        if source in TEACHING_VIEW_SOURCES:
            current["teaching_view_count"] = int(current["teaching_view_count"]) + 1
        if source in TEACHING_RECONSTRUCTION_SOURCES:
            current["teaching_reconstruction_count"] = int(current["teaching_reconstruction_count"]) + 1
        if source in TEACHING_EVENT_SOURCES:
            current["teaching_event_count"] = int(current["teaching_event_count"]) + 1
        if source in CONCEPT_GATE_SOURCES:
            current["concept_gate_count"] = int(current["concept_gate_count"]) + 1
            current["concept_gate_best_score"] = round(
                max(float(current.get("concept_gate_best_score") or 0.0), event_score or 0.0),
                4,
            )

    current["lesson_id"] = normalize_lesson_id(lesson_id)
    current["last_event_utc"] = event_utc or current.get("last_event_utc")
    current["updated_utc"] = event_utc or current.get("updated_utc")
    return current
