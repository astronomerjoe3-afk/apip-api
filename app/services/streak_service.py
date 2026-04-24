from __future__ import annotations

from datetime import date, datetime
from typing import Any, Dict, Optional

QUALIFYING_STREAK_SOURCES = {
    "student_runner_concept_gate",
    "student_runner_mastery_check",
}


def _parse_utc_datetime(value: Any) -> Optional[datetime]:
    try:
        if not value:
            return None
        normalized = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except Exception:
        return None


def _date_key(value: Any) -> Optional[str]:
    dt = _parse_utc_datetime(value)
    return dt.date().isoformat() if dt else None


def _days_since(date_key: Optional[str], now_utc: str) -> Optional[int]:
    if not date_key:
        return None
    try:
        last_date = date.fromisoformat(date_key)
        now_date = _parse_utc_datetime(now_utc)
        if not now_date:
            return None
        return (now_date.date() - last_date).days
    except Exception:
        return None


def default_learning_streak() -> Dict[str, Any]:
    return {
        "current_days": 0,
        "best_days": 0,
        "total_learning_days": 0,
        "last_earned_date_utc": None,
        "last_earned_utc": None,
        "updated_utc": None,
    }


def normalize_learning_streak(value: Any) -> Dict[str, Any]:
    state = value if isinstance(value, dict) else {}
    normalized = default_learning_streak()

    for key in ("current_days", "best_days", "total_learning_days"):
        try:
            normalized[key] = max(0, int(state.get(key) or 0))
        except Exception:
            normalized[key] = 0

    last_earned_date = str(state.get("last_earned_date_utc") or "").strip() or None
    last_earned_utc = str(state.get("last_earned_utc") or "").strip() or None
    updated_utc = str(state.get("updated_utc") or "").strip() or None

    normalized["last_earned_date_utc"] = last_earned_date
    normalized["last_earned_utc"] = last_earned_utc
    normalized["updated_utc"] = updated_utc
    return normalized


def event_counts_toward_learning_streak(event_type: str, details: Any) -> bool:
    detail_map = details if isinstance(details, dict) else {}
    source = str(detail_map.get("source") or "").strip().lower()
    normalized_type = str(event_type or "").strip().lower()

    if normalized_type == "reflection" and source == "student_runner_concept_gate":
        return True
    if normalized_type == "transfer" and source == "student_runner_mastery_check":
        return True
    return False


def update_learning_streak(root_progress: Dict[str, Any], event_type: str, details: Any, utc: str) -> Dict[str, Any]:
    current = normalize_learning_streak((root_progress or {}).get("learning_streak"))
    current["updated_utc"] = utc

    if not event_counts_toward_learning_streak(event_type, details):
        return current

    earned_date = _date_key(utc)
    if not earned_date:
        return current

    last_date = current.get("last_earned_date_utc")
    if last_date == earned_date:
        current["last_earned_utc"] = utc
        current["updated_utc"] = utc
        return current

    day_gap = _days_since(last_date, utc)
    if day_gap == 1:
        current["current_days"] = max(1, int(current.get("current_days") or 0) + 1)
    else:
        current["current_days"] = 1

    current["best_days"] = max(int(current.get("best_days") or 0), current["current_days"])
    current["total_learning_days"] = max(0, int(current.get("total_learning_days") or 0)) + 1
    current["last_earned_date_utc"] = earned_date
    current["last_earned_utc"] = utc
    current["updated_utc"] = utc
    return current


def summarize_learning_streak(value: Any, now_utc: str) -> Dict[str, Any]:
    state = normalize_learning_streak(value)
    current_days = max(0, int(state.get("current_days") or 0))
    best_days = max(0, int(state.get("best_days") or 0))
    total_learning_days = max(0, int(state.get("total_learning_days") or 0))
    last_earned_date_utc = state.get("last_earned_date_utc")
    last_earned_utc = state.get("last_earned_utc")
    day_gap = _days_since(last_earned_date_utc, now_utc)

    today_completed = day_gap == 0
    if current_days <= 0 or last_earned_date_utc is None:
        status = "new"
    elif day_gap == 0:
        status = "active"
    elif day_gap == 1:
        status = "at_risk"
    else:
        status = "paused"

    return {
        "current_days": current_days,
        "best_days": best_days,
        "total_learning_days": total_learning_days,
        "today_completed": today_completed,
        "status": status,
        "last_earned_date_utc": last_earned_date_utc,
        "last_earned_utc": last_earned_utc,
    }
