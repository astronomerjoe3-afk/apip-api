from __future__ import annotations

import secrets
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from google.cloud import firestore

from app.audit import write_audit_log
from app.common import clamp01, get_client_ip, parse_iso_utc, safe_list_str, utc_now
from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq
from app.dependencies import require_authenticated_user

router = APIRouter(tags=["progress"])

EventType = Literal["diagnostic", "simulation", "reflection", "transfer", "attempt"]


def _progress_doc(uid: str):
    db = get_firestore_client()
    return db.collection("progress").document(uid)


def _module_progress_doc(uid: str, module_id: str):
    return _progress_doc(uid).collection("modules").document(module_id)


def _new_event_id() -> str:
    return secrets.token_urlsafe(10).replace("-", "").replace("_", "")[:16]


def _compute_mastery_delta(event_type: str, score: Optional[float]) -> float:
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


def _should_persist_event(event_type: str) -> bool:
    return event_type in ("transfer", "diagnostic")


@router.post("/progress/{module_id}/event")
def post_progress_event(
    module_id: str,
    request: Request,
    user=Depends(require_authenticated_user),
    payload: Dict[str, Any] = Body(...),
):
    db = get_firestore_client()

    uid = (user or {}).get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

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

    event_id = _new_event_id()
    now = utc_now()

    mp_ref = _module_progress_doc(uid, module_id)
    mp_snap = mp_ref.get()
    mp = mp_snap.to_dict() if mp_snap.exists else {}

    prev_mastery = float((mp.get("mastery") or {}).get("score") or 0.0)
    mastery_delta = _compute_mastery_delta(event_type, score)
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

    def _inc(name: str):
        counters[name] = int(counters.get(name, 0) or 0) + 1

    _inc("events_total")
    if event_type == "diagnostic":
        _inc("diagnostics")
    elif event_type == "simulation":
        _inc("sim_sessions")
    elif event_type == "reflection":
        _inc("reflections")
    elif event_type == "transfer":
        _inc("transfers")
    elif event_type == "attempt":
        _inc("attempts")

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

    mp_ref.set(mp_update, merge=True)

    stored_event = False
    if _should_persist_event(event_type):
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
            "request_id": getattr(request.state, "request_id", None),
        }
        db.collection("progress_events").document(event_doc_id).set(event_doc)
        stored_event = True

    _progress_doc(uid).set(
        {"uid": uid, "updated_utc": now, "last_event_utc": now},
        merge=True,
    )

    write_audit_log(
        event_type="progress.event.write",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=None,
        path=f"/progress/{module_id}/event",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "module_id": module_id,
            "event_type": event_type,
            "event_id": event_id,
            "stored_event": stored_event,
        },
    )

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


@router.get("/progress/me")
def get_progress_me(
    request: Request,
    user=Depends(require_authenticated_user),
    limit_recent_events: int = Query(20, ge=0, le=50),
):
    db = get_firestore_client()

    uid = (user or {}).get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    warnings: List[str] = []

    mods = list(_progress_doc(uid).collection("modules").stream())
    modules: List[Dict[str, Any]] = []
    for d in mods:
        data = d.to_dict() or {}
        data["module_id"] = d.id
        modules.append(data)

    recent: List[Dict[str, Any]] = []
    if limit_recent_events > 0:
        try:
            q = (
                where_eq(db.collection("progress_events"), "uid", uid)
                .order_by("utc", direction=firestore.Query.DESCENDING)
                .limit(limit_recent_events)
            )
            for s in q.stream():
                e = s.to_dict() or {}
                if isinstance(e.get("details"), dict):
                    e["details"] = {k: e["details"][k] for k in list(e["details"].keys())[:10]}
                recent.append(e)
        except Exception as e:
            warnings.append(f"recent_events_unavailable: {str(e)[:180]}")
            recent = []

    write_audit_log(
        event_type="progress.me.read",
        actor_uid=uid,
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=None,
        path="/progress/me",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"modules": len(modules), "recent_events": len(recent), "warnings": warnings},
    )

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
        "ok": True,
        "utc": utc_now(),
        "uid": uid,
        "role": (user or {}).get("role"),
        "warnings": warnings,
        "mastery_map": mastery_map,
        "modules": modules,
        "recent_events": recent,
    }
