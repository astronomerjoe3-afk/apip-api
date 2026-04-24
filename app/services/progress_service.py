from __future__ import annotations

import secrets
from typing import Any, Dict, List, Literal, Optional

from fastapi import HTTPException

from app.common import clamp01, parse_iso_utc, safe_list_str, utc_now
from app.repositories.progress_repository import (
    get_lesson_progress,
    get_module_progress,
    list_recent_progress_events,
    list_recent_transfer_events_for_module,
    list_progress_modules,
    persist_progress_event,
    set_lesson_progress,
    set_module_progress,
    set_progress_root,
)
from app.services.lesson_progress_state import apply_progress_event_to_snapshot, normalize_lesson_id
from app.services.misconception_catalog import misconception_summaries_for_tags
from app.services.student_progression_service import get_student_module_progress

EventType = Literal["diagnostic", "simulation", "reflection", "transfer", "attempt"]

MASTERY_THRESHOLD = 0.80


def new_event_id() -> str:
    return secrets.token_urlsafe(10).replace("-", "").replace("_", "")[:16]


def should_persist_event(event_type: str) -> bool:
    return event_type in ("transfer", "diagnostic", "simulation", "reflection", "attempt")


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


def _derive_readiness_state_from_mastery(mastery_score: float) -> str:
    if mastery_score >= MASTERY_THRESHOLD:
        return "ready"
    if mastery_score >= 0.50:
        return "developing"
    return "not_ready"


def _update_misconception_profile(
    existing_tags: Dict[str, Any],
    misconception_tags: List[str],
) -> Dict[str, float]:
    tags = existing_tags if isinstance(existing_tags, dict) else {}
    out: Dict[str, float] = {}

    for k, v in tags.items():
        try:
            out[str(k)] = float(v)
        except Exception:
            continue

    for tag in misconception_tags:
        prev = out.get(tag, 0.10)
        bumped = min(0.95, float(prev) + 0.05)
        out[tag] = round(bumped, 4)

    return out


def _canonical_mastery_from_transfer_history(
    uid: str,
    module_id: str,
    current_event_type: str,
    current_score: Optional[float],
) -> float:
    """
    Canonical rule:
    - ONLY transfer events contribute to mastery.
    - Diagnostic, simulation, reflection, and attempt never contribute.
    - Recompute from transfer history every time so legacy contaminated
      mastery values are cleaned automatically.
    """
    scores: List[float] = []

    if current_event_type == "transfer" and current_score is not None:
        scores.append(float(current_score))

    prior_transfer_events = list_recent_transfer_events_for_module(
        uid=uid,
        module_id=module_id,
        limit_events=200,
    )

    for ev in prior_transfer_events:
        s = clamp01(ev.get("score"))
        if s is not None:
            scores.append(float(s))

    if not scores:
        return 0.0

    return round(max(scores), 4)


def _top_misconception_tags(modules: List[Dict[str, Any]], limit_tags: int = 6) -> List[str]:
    aggregate: Dict[str, float] = {}

    for module_row in modules:
        profile = module_row.get("misconception_profile") or {}
        tags = profile.get("tags") if isinstance(profile, dict) else {}
        if not isinstance(tags, dict):
            continue

        for tag, raw_score in tags.items():
            normalized_tag = str(tag or "").strip()
            if not normalized_tag:
                continue
            try:
                aggregate[normalized_tag] = float(aggregate.get(normalized_tag, 0.0)) + float(raw_score)
            except Exception:
                continue

    return [
        tag
        for tag, _ in sorted(aggregate.items(), key=lambda item: item[1], reverse=True)[:limit_tags]
    ]


def _review_queue_for_modules(uid: str, module_ids: List[str], warnings: List[str]) -> List[Dict[str, Any]]:
    queue: List[Dict[str, Any]] = []

    for module_id in module_ids:
        try:
            module_progress = get_student_module_progress(uid=uid, module_id=module_id)
        except Exception as exc:
            warnings.append(f"review_queue_unavailable:{module_id}:{str(exc)[:120]}")
            continue

        for lesson in module_progress.get("lessons") or []:
            review_state = str(lesson.get("review_state") or "").strip().lower()
            review_due_utc = lesson.get("review_due_utc")
            if review_state not in {"due", "scheduled"} and not review_due_utc:
                continue

            lesson_id = normalize_lesson_id(lesson.get("lesson_id"))
            queue.append(
                {
                    "module_id": module_id,
                    "lesson_id": lesson_id,
                    "title": lesson.get("title"),
                    "route": f"/student/module/{module_id}?lesson={lesson_id}",
                    "review_due": bool(lesson.get("review_due")),
                    "review_state": review_state or ("due" if lesson.get("review_due") else "scheduled"),
                    "review_due_utc": review_due_utc,
                    "review_count": int(lesson.get("review_count") or 0),
                    "last_score": lesson.get("last_review_score"),
                    "misconception_tags": safe_list_str(lesson.get("misconception_tags"), max_items=4, max_len=64),
                    "misconception_summaries": misconception_summaries_for_tags(
                        safe_list_str(lesson.get("misconception_tags"), max_items=4, max_len=64),
                        limit=3,
                    ),
                }
            )

    queue.sort(
        key=lambda item: (
            0 if item.get("review_due") else 1,
            parse_iso_utc(item.get("review_due_utc")) or 0.0,
            str(item.get("module_id") or ""),
            str(item.get("lesson_id") or ""),
        )
    )
    return queue


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
    lesson_id = normalize_lesson_id(trimmed_details.get("lesson_id"))

    counters = mp.get("counters") or {}
    if not isinstance(counters, dict):
        counters = {}

    def inc(name: str) -> None:
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

    existing_mis_tags = (mp.get("misconception_profile") or {}).get("tags") or {}
    mp_mis = _update_misconception_profile(existing_mis_tags, misconception_tags)

    # Always recompute from transfer-only history.
    new_mastery_score = _canonical_mastery_from_transfer_history(
        uid=uid,
        module_id=module_id,
        current_event_type=event_type,
        current_score=score,
    )
    readiness_state = _derive_readiness_state_from_mastery(new_mastery_score)

    mp_update = {
        "module_id": module_id,
        "last_event_utc": now,
        "engagement_seconds": engagement_seconds,
        "counters": counters,
        "mastery": {
            "score": round(new_mastery_score, 4),
            "level": readiness_state,
            "updated_utc": now,
            "source": "transfer_only",
        },
        "readiness": {
            "state": readiness_state,
            "reason": "mastery_check_threshold",
            "updated_utc": now,
        },
        "misconception_profile": {
            "tags": mp_mis,
            "updated_utc": now,
        },
        "updated_utc": now,
    }

    set_module_progress(uid, module_id, mp_update)
    if lesson_id:
        existing_lesson_progress = get_lesson_progress(uid, module_id, lesson_id)
        lesson_progress_update = apply_progress_event_to_snapshot(
            existing_lesson_progress,
            lesson_id=lesson_id,
            event_type_value=event_type,
            score=score,
            misconception_tags=misconception_tags,
            details=trimmed_details,
            utc=now,
        )
        set_lesson_progress(uid, module_id, lesson_id, lesson_progress_update)
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

    module_ids = [str(module_row.get("module_id") or "").strip() for module_row in modules if str(module_row.get("module_id") or "").strip()]
    review_queue = _review_queue_for_modules(uid, module_ids, warnings)
    review_due_count = sum(1 for item in review_queue if item.get("review_due"))
    next_review_utc = review_queue[0].get("review_due_utc") if review_queue else None

    return {
        "warnings": warnings,
        "mastery_map": mastery_map,
        "modules": modules,
        "recent_events": recent,
        "review_due_count": review_due_count,
        "next_review_utc": next_review_utc,
        "review_queue": review_queue[:12],
        "top_misconception_tags": _top_misconception_tags(modules),
        "top_misconception_summaries": misconception_summaries_for_tags(_top_misconception_tags(modules), limit=4),
    }
