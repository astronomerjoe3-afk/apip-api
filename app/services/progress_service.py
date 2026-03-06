from __future__ import annotations

import secrets
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import HTTPException

from app.common import clamp01, parse_iso_utc, safe_list_str, utc_now
from app.repositories.progress_repository import (
    get_module_progress,
    list_progress_modules,
    list_recent_progress_events,
    persist_progress_event,
    set_module_progress,
    set_progress_root,
)

EventType = Literal["diagnostic", "simulation", "reflection", "transfer", "attempt"]


def new_event_id() -> str:
    return secrets.token_urlsafe(10).replace("-", "").replace("_", "")[:16]


def compute_mastery_delta(event_type: str, score: Optional[float]) -> float:
    s = clamp01(score)
    if s is None:
        return 0.0
    if event_type == "transfer":
        return (s - 0.5) * 0.20
    if event_type == "attempt":
        return (s - 0.5) * 0.10
    if event_type == "diagnostic":
        return (s - 0.5) * 0.05
    return 0.0


def should_persist_event(event_type: str) -> bool:
    return event_type in ("transfer", "diagnostic")


def normalize_progress_event_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    event_type: str = str(payload.get("event_type") or "").strip().lower()
    if event_type not in ("diagnostic", "simulation", "reflection", "transfer", "attempt"):
        raise HTTPException(status_code=400, detail="Invalid event_type")

    duration_seconds = payload.get("duration_seconds")
    try:
        duration_seconds = int(duration_seconds) if duration_seconds is not None else 0
    except Exception:
        duration_seconds = 0
    duration_seconds = max(0, min(duration_seconds, 60 * 60))

    score = clamp01(payload.get("score"))
    confidence = clamp01(payload.get("confidence"))
    conflict_level = clamp01(payload.get("conflict_level"))

    sim_depth = payload.get("sim_depth")
    try:
        sim_depth = int(sim_depth) if sim_depth is not None else None
    except Exception:
        sim_depth = None
    if sim_depth is not None:
        sim_depth = max(0, min(sim_depth, 1000))

    misconception_tags = safe_list_str(payload.get("misconception_tags"), max_items=25, max_len=64)

    outcome = payload.get("outcome")
    if outcome is not None:
        outcome = str(outcome)[:80]

    details = payload.get("details") or {}
    if not isinstance(details, dict):
        details = {"value": str(details)}

    trimmed_details: Dict[str, Any] = {}
    for k, v in list(details.items())[:30]:
        key = str(k)[:64]
        if isinstance(v, (str, int, float, bool)) or v is None:
            trimmed_details[key] = v if not isinstance(v, str) else v[:500]
        else:
            trimmed_details[key] = str(v)[:500]

    return {
        "event_type": event_type,
        "duration_seconds": duration_seconds,
        "score": score,
        "confidence": confidence,
        "conflict_level": conflict_level,
        "sim_depth": sim_depth,
        "misconception_tags": misconception_tags,
        "outcome": outcome,
        "details": trimmed_details,
    }


def process_progress_event(
    uid: str,
    module_id: str,
    payload: Dict[str, Any],
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    normalized = normalize_progress_event_payload(payload)

    event_type = normalized["event_type"]
    duration_seconds = normalized["duration_seconds"]
    score = normalized["score"]
    confidence = normalized["confidence"]
    conflict_level = normalized["conflict_level"]
    sim_depth = normalized["sim_depth"]
    misconception_tags = normalized["misconception_tags"]
    outcome = normalized["outcome"]
    trimmed_details = normalized["details"]

    event_id = new_event_id()
    now = utc_now()

    mp = get_module_progress(uid, module_id)

    prev_mastery = float((mp.get("mastery") or {}).get("score") or 0.0)
    mastery_delta = compute_mastery_delta(event_type, score)
    new_mastery = max(0.0, min(1.0, prev_mastery + mastery_delta))

    mp_mis = (mp.get("misconception_profile") or {}).get("tags") or {}
    if not isinstance(mp_mis, dict):
        mp_mis = {}

    for tag in misconception_tags:
        prev = mp_mis.get(tag)
        try:
            prev_f = float(prev) if prev is not None else 0.10
        except Exception:
            prev_f = 0.10
        mp_mis[tag] = round(min(0.95, prev_f + 0.05), 4)

    counters = mp.get("counters") or {}
    if not isinstance(counters, dict):
        counters = {}

    def inc(name: str):
        counters[name] = int(counters.get(name, 0) or 0) + 1

    inc("events_total")
    if event_type == "diagnostic":
        inc("diagnostics")
    elif event_type == "simulation":
        inc("sim_sessions")
    elif event_type == "reflection":
        inc("reflections")
    elif event_type == "transfer":
        inc("transfers")
    elif event_type == "attempt":
        inc("attempts")

    engagement_seconds = int(mp.get("engagement_seconds", 0) or 0) + duration_seconds

    readiness_state = "not_ready"
    if new_mastery >= 0.80:
        readiness_state = "ready"
    elif new_mastery >= 0.50:
        readiness_state = "developing"

    mp_update = {
        "module_id": module_id,
        "last_event_utc": now,
        "engagement_seconds": engagement_seconds,
        "counters": counters,
        "mastery": {
            "score": round(new_mastery, 4),
            "level": readiness_state,
            "updated_utc": now,
        },
        "readiness": {
            "state": readiness_state,
            "reason": "mastery_score_threshold",
            "updated_utc": now,
        },
        "misconception_profile": {
            "tags": mp_mis,
            "updated_utc": now,
        },
        "updated_utc": now,
    }

    set_module_progress(uid, module_id, mp_update)
    set_progress_root(uid, {"uid": uid, "updated_utc": now, "last_event_utc": now})

    stored_event = False
    if should_persist_event(event_type):
        event_doc_id = f"{uid}_{module_id}_{event_id}"
        event_doc = {
            "uid": uid,
            "module_id": module_id,
            "event_id": event_id,
            "event_type": event_type,
            "utc": now,
            "duration_seconds": duration_seconds,
            "score": score,
            "confidence": confidence,
            "conflict_level": conflict_level,
            "sim_depth": sim_depth,
            "misconception_tags": misconception_tags,
            "outcome": outcome,
            "details": trimmed_details,
            "request_id": request_id,
        }
        persist_progress_event(event_doc_id, event_doc)
        stored_event = True

    return {
        "ok": True,
        "utc": now,
        "event_id": event_id,
        "module_id": module_id,
        "stored_event": stored_event,
        "mastery": mp_update["mastery"],
        "readiness": mp_update["readiness"],
        "misconception_profile": {
            "top_tags": sorted(mp_mis.items(), key=lambda kv: kv[1], reverse=True)[:10]
        },
    }


def fetch_progress_me(uid: str, limit_recent_events: int) -> Dict[str, Any]:
    warnings: List[str] = []

    modules = list_progress_modules(uid)

    recent: List[Dict[str, Any]] = []
    if limit_recent_events > 0:
        try:
            recent = list_recent_progress_events(uid, limit_recent_events)
            for e in recent:
                if isinstance(e.get("details"), dict):
                    e["details"] = {k: e["details"][k] for k in list(e["details"].keys())[:10]}
        except Exception as e:
            warnings.append(f"recent_events_unavailable: {str(e)[:180]}")
            recent = []

    mastery_map: List[Dict[str, Any]] = []
    for m in modules:
        mastery = m.get("mastery") or {}
        readiness = m.get("readiness") or {}
        mastery_map.append(
            {
                "module_id": m.get("module_id"),
                "mastery_score": mastery.get("score", 0.0),
                "readiness": readiness.get("state", "not_ready"),
                "engagement_seconds": m.get("engagement_seconds", 0),
                "last_event_utc": m.get("last_event_utc"),
            }
        )

    return {
        "warnings": warnings,
        "mastery_map": mastery_map,
        "modules": modules,
        "recent_events": recent,
    }
