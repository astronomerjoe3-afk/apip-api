from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

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
SPACED_REVIEW_INTERVAL_DAYS = [1, 3, 7, 14, 30]


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


def _normalized_misconception_profile(value: Any) -> Dict[str, Any]:
    record = value if isinstance(value, dict) else {}
    tags_value = record.get("tags")
    tags: Dict[str, float] = {}

    if isinstance(tags_value, dict):
        for key, raw_score in tags_value.items():
            try:
                tags[str(key)] = round(max(0.0, min(1.0, float(raw_score))), 4)
            except Exception:
                continue

    return {
        "tags": tags,
        "updated_utc": record.get("updated_utc"),
    }


def _normalized_spaced_mastery(value: Any) -> Dict[str, Any]:
    record = value if isinstance(value, dict) else {}

    interval_days = record.get("interval_days")
    try:
        interval_days = int(interval_days) if interval_days is not None else None
    except Exception:
        interval_days = None
    if interval_days is not None:
        interval_days = max(0, interval_days)

    review_count = record.get("review_count")
    try:
        review_count = int(review_count) if review_count is not None else 0
    except Exception:
        review_count = 0

    last_score = record.get("last_score")
    return {
        "state": str(record.get("state") or "not_started"),
        "due_utc": record.get("due_utc"),
        "last_review_utc": record.get("last_review_utc"),
        "interval_days": interval_days,
        "review_count": max(0, review_count),
        "last_score": round(safe_score(last_score), 4) if last_score is not None else None,
        "updated_utc": record.get("updated_utc"),
    }


def _merge_misconception_profile(
    current: Dict[str, Any],
    misconception_tags: List[str],
    updated_utc: str,
) -> Dict[str, Any]:
    profile = _normalized_misconception_profile(current)
    tags = dict(profile["tags"])

    for tag in misconception_tags:
        normalized_tag = str(tag or "").strip()
        if not normalized_tag:
            continue
        prior_score = float(tags.get(normalized_tag, 0.10))
        tags[normalized_tag] = round(min(0.95, prior_score + 0.05), 4)

    return {
        "tags": tags,
        "updated_utc": updated_utc if misconception_tags else profile.get("updated_utc"),
    }


def _spaced_due_state(spaced_mastery: Dict[str, Any], event_utc: str) -> str:
    due_utc = spaced_mastery.get("due_utc")
    if spaced_mastery.get("state") == "scheduled" and parse_iso_utc(due_utc) <= parse_iso_utc(event_utc):
        return "due"
    return str(spaced_mastery.get("state") or "not_started")


def _next_spaced_review(event_utc: str, review_count: int, score: float) -> Dict[str, Any]:
    if score >= COMPLETION_THRESHOLD:
        next_review_count = max(1, review_count + 1)
        interval_days = SPACED_REVIEW_INTERVAL_DAYS[min(next_review_count - 1, len(SPACED_REVIEW_INTERVAL_DAYS) - 1)]
        try:
            base_time = datetime.fromisoformat(str(event_utc)).astimezone(timezone.utc)
        except Exception:
            base_time = datetime.now(timezone.utc)
        due_at = base_time + timedelta(days=interval_days)
        return {
            "state": "scheduled",
            "due_utc": due_at.isoformat(),
            "last_review_utc": event_utc,
            "interval_days": interval_days,
            "review_count": next_review_count,
            "last_score": round(score, 4),
            "updated_utc": event_utc,
        }

    return {
        "state": "due",
        "due_utc": event_utc,
        "last_review_utc": event_utc,
        "interval_days": 0,
        "review_count": 0,
        "last_score": round(score, 4),
        "updated_utc": event_utc,
    }


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
        "misconception_profile": {
            "tags": {},
            "updated_utc": None,
        },
        "spaced_mastery": {
            "state": "not_started",
            "due_utc": None,
            "last_review_utc": None,
            "interval_days": None,
            "review_count": 0,
            "last_score": None,
            "updated_utc": None,
        },
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
    baseline["misconception_profile"] = _normalized_misconception_profile(raw.get("misconception_profile"))
    baseline["spaced_mastery"] = _normalized_spaced_mastery(raw.get("spaced_mastery"))
    baseline["updated_utc"] = raw.get("updated_utc")
    return baseline


def apply_progress_event_to_snapshot(
    snapshot: Dict[str, Any] | None,
    *,
    lesson_id: str,
    event_type_value: str,
    score: Any,
    misconception_tags: List[str] | None,
    details: Dict[str, Any] | None,
    utc: Any,
) -> Dict[str, Any]:
    normalized_details = details if isinstance(details, dict) else {}
    current = normalize_lesson_progress_snapshot(snapshot, lesson_id)
    event_name = str(event_type_value or "").strip().lower()
    event_score = safe_score(score) if score is not None else None
    event_utc = str(utc or "")
    source = str(normalized_details.get("source") or "").strip().lower()
    normalized_tags = [str(tag or "").strip() for tag in (misconception_tags or []) if str(tag or "").strip()]

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
        current_spaced_mastery = _normalized_spaced_mastery(current.get("spaced_mastery"))
        current["spaced_mastery"] = _next_spaced_review(
            event_utc,
            int(current_spaced_mastery.get("review_count") or 0),
            mastery_score,
        )

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

    current["misconception_profile"] = _merge_misconception_profile(
        current.get("misconception_profile") or {},
        normalized_tags,
        event_utc,
    )
    current["spaced_mastery"] = _normalized_spaced_mastery(current.get("spaced_mastery"))
    current["spaced_mastery"]["state"] = _spaced_due_state(current["spaced_mastery"], event_utc)
    current["lesson_id"] = normalize_lesson_id(lesson_id)
    current["last_event_utc"] = event_utc or current.get("last_event_utc")
    current["updated_utc"] = event_utc or current.get("updated_utc")
    return current
