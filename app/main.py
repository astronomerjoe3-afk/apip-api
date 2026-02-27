# app/main.py
import os
import uuid
import time
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Literal

from fastapi import FastAPI, Depends, HTTPException, Request, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from google.cloud import firestore
from starlette.middleware.base import BaseHTTPMiddleware

from app.dependencies import require_admin, require_authenticated_user
from app.audit import write_audit_log

# -------------------------------------------------------
# App Init
# -------------------------------------------------------

app = FastAPI(title="APIP API", version="0.3.0")

FIRESTORE_PROJECT = (
    os.getenv("GOOGLE_CLOUD_PROJECT")
    or os.getenv("GCP_PROJECT")
    or os.getenv("GCLOUD_PROJECT")
    or "local"
)

db = firestore.Client(project=FIRESTORE_PROJECT)

# -------------------------------------------------------
# CORS (tighten later)
# -------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: use env allowlist later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def get_client_ip(request: Request) -> Optional[str]:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None

def _clamp01(x: Optional[float]) -> Optional[float]:
    if x is None:
        return None
    try:
        v = float(x)
    except Exception:
        return None
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v

def _safe_list_str(v: Any, max_items: int = 25, max_len: int = 64) -> List[str]:
    out: List[str] = []
    if v is None:
        return out
    if isinstance(v, str):
        parts = [p.strip() for p in v.split(",") if p.strip()]
    elif isinstance(v, list):
        parts = v
    else:
        parts = [str(v)]
    for p in parts[:max_items]:
        s = str(p).strip()
        if not s:
            continue
        out.append(s[:max_len])
    return out

# -------------------------------------------------------
# Request ID Middleware
# -------------------------------------------------------

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))
        request.state.request_id = request_id

        start = time.time()
        response = await call_next(request)
        duration_ms = round((time.time() - start) * 1000, 2)

        response.headers["X-Request-Id"] = request_id

        print(
            {
                "type": "http_request",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "utc": utc_now(),
            }
        )
        return response

app.add_middleware(RequestIDMiddleware)

# -------------------------------------------------------
# Health + Build
# -------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "utc": utc_now()}

@app.get("/healthz")
def healthz():
    return {"ok": True, "utc": utc_now()}

@app.get("/__build")
@app.get("/_build")
def build():
    app_commit = os.getenv("GIT_COMMIT_SHA") or "dev"
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT") or "local"

    return {
        "app_name": "apip-api",
        "app_version": "0.3.0",
        "app_commit": app_commit,
        "firebase_project_id": project_id,
        "service": os.getenv("K_SERVICE"),
        "revision": os.getenv("K_REVISION"),
        "utc": utc_now(),
    }

# -------------------------------------------------------
# Profile (useful for web dashboard sanity checks)
# -------------------------------------------------------

@app.get("/profile")
def profile(user=Depends(require_authenticated_user)):
    u = user or {}
    return {
        "ok": True,
        "uid": u.get("uid"),
        "email": u.get("email"),
        "email_verified": u.get("email_verified"),
        "role": u.get("role"),
        "firebase_project_id": os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT") or "local",
        "utc": utc_now(),
    }

# -------------------------------------------------------
# Content Catalog Endpoints (read-only)
# -------------------------------------------------------

@app.get("/curricula")
def get_curricula(user=Depends(require_authenticated_user)):
    docs = db.collection("curricula").stream()
    result = []
    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        result.append(data)
    return {"ok": True, "curricula": result}

@app.get("/modules")
def get_modules(
    curriculum_id: Optional[str] = Query(None),
    user=Depends(require_authenticated_user),
):
    query_ref = db.collection("modules")
    if curriculum_id:
        query_ref = query_ref.where("curriculum_id", "==", curriculum_id)

    docs = query_ref.stream()
    result = []
    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        result.append(data)
    return {"ok": True, "modules": result}

@app.get("/modules/{module_id}")
def get_module(module_id: str, user=Depends(require_authenticated_user)):
    doc = db.collection("modules").document(module_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Module not found")
    data = doc.to_dict() or {}
    data["id"] = doc.id
    return {"ok": True, "module": data}

@app.get("/modules/{module_id}/lessons")
def get_module_lessons(module_id: str, user=Depends(require_authenticated_user)):
    docs = (
        db.collection("lessons")
        .where("module_id", "==", module_id)
        .order_by("sequence")
        .stream()
    )
    result = []
    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        result.append(data)
    return {"ok": True, "lessons": result}

@app.get("/sim-labs/{lab_id}")
def get_sim_lab(lab_id: str, user=Depends(require_authenticated_user)):
    doc = db.collection("sim_labs").document(lab_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Simulation lab not found")
    data = doc.to_dict() or {}
    data["id"] = doc.id
    return {"ok": True, "sim_lab": data}

# -------------------------------------------------------
# Admin Metrics
# -------------------------------------------------------

@app.get("/admin/metrics")
def admin_metrics(request: Request, user=Depends(require_admin), top_n: int = Query(10, ge=1, le=50)):
    keys_docs = db.collection("api_keys").stream()

    total = 0
    active = 0
    auto_disabled = 0

    for d in keys_docs:
        total += 1
        data = d.to_dict() or {}
        if data.get("active") is True:
            active += 1
        if data.get("auto_disabled") is True:
            auto_disabled += 1

    payload = {
        "ok": True,
        "utc": utc_now(),
        "keys": {"total": total, "active": active, "auto_disabled": auto_disabled},
        "rate_limit": {
            "top_n": top_n,
            "global_last_hour": {"total": 0},
            "global_last_24h": {"total": 0},
            "top_keys_last_hour": [],
            "top_keys_last_24h": [],
        },
        "warnings": [],
    }

    write_audit_log(
        event_type="admin.metrics.read",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/admin/metrics",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"top_n": top_n},
    )
    return payload

# -------------------------------------------------------
# Admin Keys
# -------------------------------------------------------

def _public_key_view(key_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "key_id": key_id,
        "label": data.get("label"),
        "active": bool(data.get("active", False)),
        "scopes": data.get("scopes", []),
        "created_utc": data.get("created_utc"),
        "updated_utc": data.get("updated_utc"),
        "rate_limit": data.get("rate_limit", {}) or {},
        "daily_limit": data.get("daily_limit"),
        "auto_disabled": bool(data.get("auto_disabled", False)),
        "last_used_utc": data.get("last_used_utc"),
    }

@app.get("/admin/keys")
def admin_list_keys(
    request: Request,
    user=Depends(require_admin),
    limit: int = Query(20, ge=1, le=200),
):
    docs = db.collection("api_keys").limit(limit).stream()
    keys: List[Dict[str, Any]] = []
    for d in docs:
        data = d.to_dict() or {}
        keys.append(_public_key_view(d.id, data))

    write_audit_log(
        event_type="admin.keys.list",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/admin/keys",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"limit": limit, "returned": len(keys)},
    )
    return {"ok": True, "keys": keys, "limit": limit, "utc": utc_now()}

@app.get("/admin/keys/{key_id}")
def admin_get_key(request: Request, key_id: str, user=Depends(require_admin)):
    doc = db.collection("api_keys").document(key_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    data = doc.to_dict() or {}
    write_audit_log(
        event_type="admin.keys.get",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=key_id,
        path=f"/admin/keys/{key_id}",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    return {"ok": True, "key": _public_key_view(key_id, data)}

@app.post("/admin/keys")
def admin_create_key(
    request: Request,
    user=Depends(require_admin),
    payload: Dict[str, Any] = Body(...),
):
    label = str(payload.get("label") or "web-admin-created").strip()
    scopes_raw = payload.get("scopes") or ["profile:read"]
    if isinstance(scopes_raw, str):
        scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()]
    else:
        scopes = [str(s).strip() for s in scopes_raw if str(s).strip()]

    window_limit = int(payload.get("window_limit") or 10)
    window_seconds = int(payload.get("window_seconds") or 60)
    bucket_seconds = int(payload.get("bucket_seconds") or 10)
    daily_limit = int(payload.get("daily_limit") or 500)

    key_id = secrets.token_urlsafe(12).replace("-", "").replace("_", "")[:16]
    api_key_secret = secrets.token_urlsafe(32)

    doc = {
        "label": label,
        "scopes": scopes,
        "active": True,
        "auto_disabled": False,
        "secret_hash": sha256_hex(api_key_secret),
        "created_utc": utc_now(),
        "updated_utc": utc_now(),
        "rate_limit": {
            "window_limit": window_limit,
            "window_seconds": window_seconds,
            "bucket_seconds": bucket_seconds,
        },
        "daily_limit": daily_limit,
    }

    db.collection("api_keys").document(key_id).set(doc)

    write_audit_log(
        event_type="admin.keys.create",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=key_id,
        path="/admin/keys",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"label": label, "scopes": scopes, "daily_limit": daily_limit},
    )

    return {
        "ok": True,
        "key_id": key_id,
        "active": True,
        "label": label,
        "scopes": scopes,
        "api_key": api_key_secret,
        "utc": utc_now(),
    }

@app.post("/admin/keys/{key_id}/enable")
def admin_enable_key(request: Request, key_id: str, user=Depends(require_admin)):
    ref = db.collection("api_keys").document(key_id)
    doc = ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update({"active": True, "updated_utc": utc_now()})

    write_audit_log(
        event_type="admin.keys.enable",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=key_id,
        path=f"/admin/keys/{key_id}/enable",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    return {"ok": True, "key_id": key_id, "enabled": True}

@app.post("/admin/keys/{key_id}/disable")
def admin_disable_key(request: Request, key_id: str, user=Depends(require_admin)):
    ref = db.collection("api_keys").document(key_id)
    doc = ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update({"active": False, "updated_utc": utc_now()})

    write_audit_log(
        event_type="admin.keys.disable",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=key_id,
        path=f"/admin/keys/{key_id}/disable",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    return {"ok": True, "key_id": key_id, "disabled": True}

@app.post("/admin/keys/{key_id}/reset-counters")
def admin_reset_counters(request: Request, key_id: str, user=Depends(require_admin)):
    to_delete = [
        ("rl_state", key_id),
        ("api_key_abuse_1h", key_id),
        ("api_key_abuse_24h", key_id),
    ]

    deleted: List[str] = []
    errors: List[str] = []

    for col, doc_id in to_delete:
        try:
            ref = db.collection(col).document(doc_id)
            if ref.get().exists:
                ref.delete()
            deleted.append(f"{col}/{doc_id}")
        except Exception as e:
            errors.append(f"{col}/{doc_id}: {str(e)}")

    write_audit_log(
        event_type="admin.keys.reset_counters",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=key_id,
        path=f"/admin/keys/{key_id}/reset-counters",
        method="POST",
        status=200 if not errors else 207,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"deleted": deleted, "errors": errors},
    )

    return {"ok": True, "key_id": key_id, "reset": True, "details": {"deleted": deleted, "errors": errors}}

# -------------------------------------------------------
# Step 3: Progress + Mastery Endpoints
# -------------------------------------------------------

EventType = Literal["diagnostic", "simulation", "reflection", "transfer", "attempt"]

def _progress_doc(uid: str):
    return db.collection("progress").document(uid)

def _module_progress_doc(uid: str, module_id: str):
    return _progress_doc(uid).collection("modules").document(module_id)

def _new_event_id() -> str:
    return secrets.token_urlsafe(10).replace("-", "").replace("_", "")[:16]

def _compute_mastery_delta(event_type: str, score: Optional[float]) -> float:
    s = _clamp01(score)
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
    # User requirement: only transfer + diagnostic are stored per-event
    return event_type in ("transfer", "diagnostic")

@app.post("/progress/{module_id}/event")
def post_progress_event(
    module_id: str,
    request: Request,
    user=Depends(require_authenticated_user),
    payload: Dict[str, Any] = Body(...),
):
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
    if duration_seconds < 0:
        duration_seconds = 0
    if duration_seconds > 60 * 60:
        duration_seconds = 60 * 60

    score = _clamp01(payload.get("score"))
    confidence = _clamp01(payload.get("confidence"))
    conflict_level = _clamp01(payload.get("conflict_level"))
    sim_depth = payload.get("sim_depth")
    try:
        sim_depth = int(sim_depth) if sim_depth is not None else None
    except Exception:
        sim_depth = None
    if sim_depth is not None and sim_depth < 0:
        sim_depth = 0
    if sim_depth is not None and sim_depth > 1000:
        sim_depth = 1000

    misconception_tags = _safe_list_str(payload.get("misconception_tags"), max_items=25, max_len=64)

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

    # Read existing module progress
    mp_ref = _module_progress_doc(uid, module_id)
    mp_snap = mp_ref.get()
    mp = mp_snap.to_dict() if mp_snap.exists else {}

    prev_mastery = float((mp.get("mastery") or {}).get("score") or 0.0)
    mastery_delta = _compute_mastery_delta(event_type, score)
    new_mastery = prev_mastery + mastery_delta
    if new_mastery < 0.0:
        new_mastery = 0.0
    if new_mastery > 1.0:
        new_mastery = 1.0

    # Misconception probabilities (simple bump model)
    mp_mis = (mp.get("misconception_profile") or {}).get("tags") or {}
    if not isinstance(mp_mis, dict):
        mp_mis = {}
    for tag in misconception_tags:
        prev = mp_mis.get(tag)
        try:
            prev_f = float(prev) if prev is not None else 0.10
        except Exception:
            prev_f = 0.10
        bumped = prev_f + 0.05
        if bumped > 0.95:
            bumped = 0.95
        mp_mis[tag] = round(bumped, 4)

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

    # Writes:
    # - Always update module progress (1 write)
    mp_ref.set(mp_update, merge=True)

    # - Store per-event only for diagnostic + transfer
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

    # Light merge on parent progress doc
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
        details={"module_id": module_id, "event_type": event_type, "event_id": event_id, "stored_event": stored_event},
    )

    return {
        "ok": True,
        "utc": now,
        "event_id": event_id,
        "module_id": module_id,
        "stored_event": stored_event,
        "mastery": mp_update["mastery"],
        "readiness": mp_update["readiness"],
        "misconception_profile": {"top_tags": sorted(mp_mis.items(), key=lambda kv: kv[1], reverse=True)[:10]},
    }

@app.get("/progress/me")
def get_progress_me(
    request: Request,
    user=Depends(require_authenticated_user),
    limit_recent_events: int = Query(20, ge=0, le=50),
):
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
        # This query may require a Firestore composite index (uid + utc).
        # We treat index absence as a non-fatal condition to avoid 500s.
        try:
            q = (
                db.collection("progress_events")
                .where("uid", "==", uid)
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

    mastery_map = []
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