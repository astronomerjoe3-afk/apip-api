from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.audit import write_audit_log
from app.common import get_client_ip, normalize_module_id, parse_iso_utc
from app.db.firestore import get_firestore_client
from app.db.firestore_query import where_eq
from app.dependencies import require_instructor_or_admin
from app.repositories.progress_repository import list_lesson_progress

router = APIRouter(tags=["instructor"])


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_score_snapshot(score: Any, utc: Any) -> Dict[str, Any] | None:
    try:
        parsed_score = float(score) if score is not None else None
    except Exception:
        parsed_score = None

    if parsed_score is None:
        return None

    snapshot: Dict[str, Any] = {"score": parsed_score}
    if utc:
        snapshot["utc"] = str(utc)
    return snapshot


def _build_activity_snapshots(lesson_rows: List[Dict[str, Any]]) -> tuple[Dict[str, Any] | None, Dict[str, Any] | None, Dict[str, Dict[str, Any]]]:
    last_diag: Dict[str, Any] | None = None
    last_transfer: Dict[str, Any] | None = None
    per_lesson: Dict[str, Dict[str, Any]] = {}

    for row in lesson_rows:
        if not isinstance(row, dict):
            continue

        lesson_id = str(row.get("lesson_id") or "").replace("-", "_")
        diagnostic = _safe_score_snapshot(row.get("diagnostic_latest_score"), row.get("diagnostic_last_utc"))
        transfer = _safe_score_snapshot(row.get("latest_score"), row.get("last_mastery_check_utc"))

        if lesson_id and (diagnostic or transfer):
            snapshot: Dict[str, Any] = {}
            if diagnostic:
                snapshot["diagnostic"] = diagnostic
            if transfer:
                snapshot["transfer"] = transfer
            per_lesson[lesson_id] = snapshot

        if diagnostic and (
            last_diag is None or parse_iso_utc(diagnostic.get("utc")) > parse_iso_utc(last_diag.get("utc"))
        ):
            last_diag = diagnostic

        if transfer and (
            last_transfer is None
            or parse_iso_utc(transfer.get("utc")) > parse_iso_utc(last_transfer.get("utc"))
        ):
            last_transfer = transfer

    return last_diag, last_transfer, per_lesson


@router.get("/instructor/module/{module_id}/students")
def instructor_module_students(
    module_id: str,
    request: Request,
    user=Depends(require_instructor_or_admin),
    limit: int = Query(30, ge=1, le=200),
    max_events_per_student: int = Query(60, ge=10, le=200),
):
    normalized_module_id = normalize_module_id(module_id)
    db = get_firestore_client()
    warnings: List[str] = []

    students: List[Dict[str, Any]] = []
    try:
        qs = where_eq(db.collection("users"), "role", "student").limit(limit).stream()
        for d in qs:
            u = d.to_dict() or {}
            students.append(
                {
                    "uid": d.id,
                    "email": u.get("email"),
                    "role": u.get("role"),
                    "display_name": u.get("display_name"),
                }
            )
    except Exception as e:
        warnings.append(f"users_role_query_failed_fallback: {str(e)[:200]}")
        try:
            qs = db.collection("users").limit(limit * 3).stream()
            for d in qs:
                u = d.to_dict() or {}
                if u.get("role") == "student":
                    students.append({"uid": d.id, "email": u.get("email"), "role": u.get("role")})
                if len(students) >= limit:
                    break
        except Exception as e2:
            raise HTTPException(status_code=500, detail=f"Failed to list students: {str(e2)[:200]}")

    rows: List[Dict[str, Any]] = []

    for s in students:
        uid = s.get("uid")
        if not uid:
            continue

        mp: Dict[str, Any] = {}
        try:
            snap = db.collection("progress").document(uid).collection("modules").document(normalized_module_id).get()
            mp = snap.to_dict() if snap.exists else {}
        except Exception as e:
            warnings.append(f"progress_read_failed:{uid}:{str(e)[:120]}")
            mp = {}

        mastery = _safe_dict(mp.get("mastery"))
        readiness = _safe_dict(mp.get("readiness"))
        counters = _safe_dict(mp.get("counters"))
        mis = _safe_dict(_safe_dict(mp.get("misconception_profile")).get("tags"))

        top_mis = sorted(
            [(k, float(v)) for k, v in mis.items() if k],
            key=lambda kv: kv[1],
            reverse=True,
        )[:8]

        lesson_rows: List[Dict[str, Any]] = []
        try:
            lesson_rows = list_lesson_progress(uid, normalized_module_id)
        except Exception as e:
            warnings.append(f"lesson_progress_read_failed:{uid}:{str(e)[:160]}")
            lesson_rows = []

        last_diag, last_transfer, per_lesson = _build_activity_snapshots(lesson_rows)

        engagement_seconds = int(mp.get("engagement_seconds", 0) or 0)
        attempts_total = int(counters.get("attempts", 0) or 0)
        reflections_total = int(counters.get("reflections", 0) or 0)

        rows.append(
            {
                "uid": uid,
                "email": s.get("email"),
                "display_name": s.get("display_name"),
                "module_id": normalized_module_id,
                "mastery_score": float(mastery.get("score") or 0.0),
                "readiness": readiness.get("state") or "not_ready",
                "readiness_reason": readiness.get("reason") or "unknown",
                "engagement_seconds": engagement_seconds,
                "activity_counters": {
                    "attempts": attempts_total,
                    "reflections": reflections_total,
                },
                "last_event_utc": mp.get("last_event_utc"),
                "top_misconceptions": [{"tag": k, "p": v} for k, v in top_mis],
                "last_diagnostic": last_diag,
                "last_transfer": last_transfer,
                "per_lesson": per_lesson,
            }
        )

    rows.sort(key=lambda r: (-float(r.get("mastery_score") or 0.0), str(r.get("email") or "")))

    write_audit_log(
        event_type="instructor.module.students.read",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path=f"/instructor/module/{normalized_module_id}/students",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"module_id": normalized_module_id, "returned": len(rows), "warnings": warnings},
    )

    return {"ok": True, "module_id": normalized_module_id, "students": rows, "warnings": warnings}
