import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from fastapi import FastAPI, Depends, HTTPException, Request, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from google.cloud import firestore
from starlette.middleware.base import BaseHTTPMiddleware

from app.dependencies import (
    require_admin,
    require_authenticated_user,
    require_instructor_or_admin,
)
from app.audit import write_audit_log

# -------------------------------------------------------
# App Init
# -------------------------------------------------------

APP_NAME = "apip-api"
APP_VERSION = "0.3.0"  # bump for Step 3

app = FastAPI(title="APIP API", version=APP_VERSION)
db = firestore.Client()


def now_utc():
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now_utc().isoformat()


# -------------------------------------------------------
# CORS
# -------------------------------------------------------

origins_env = os.getenv("ALLOWED_ORIGINS", "*").strip()
if origins_env == "*" or not origins_env:
    allowed_origins = ["*"]
else:
    allowed_origins = [o.strip() for o in origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------
# Security Headers
# -------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return resp

app.add_middleware(SecurityHeadersMiddleware)

# -------------------------------------------------------
# Request ID + Latency + Audit middleware (exception-safe)
# -------------------------------------------------------

class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id

        start = time.time()
        response = None
        status_code = 500
        err_text = None

        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-Id"] = request_id
            return response
        except HTTPException as he:
            status_code = he.status_code
            err_text = str(he.detail) if he.detail else "http_error"
            resp = JSONResponse(status_code=he.status_code, content={"detail": he.detail, "request_id": request_id})
            resp.headers["X-Request-Id"] = request_id
            return resp
        except Exception as e:
            status_code = 500
            err_text = str(e)[:512]
            resp = JSONResponse(status_code=500, content={"detail": "Internal Server Error", "request_id": request_id})
            resp.headers["X-Request-Id"] = request_id
            return resp
        finally:
            duration_ms = round((time.time() - start) * 1000, 2)

            print(
                {
                    "type": "http_request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": status_code,
                    "duration_ms": duration_ms,
                    "utc": now_iso(),
                    "error": err_text,
                }
            )

            write_audit_log(
                db,
                event_type="api.request",
                request=request,
                status_code=status_code,
                duration_ms=duration_ms,
                detail={"error": err_text} if err_text else None,
            )

app.add_middleware(RequestContextMiddleware)

# -------------------------------------------------------
# Health + Build
# -------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "utc": now_iso(), "commit": os.getenv("GIT_COMMIT_SHA", "unknown")}

@app.get("/__build")
@app.get("/_build")
def build():
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "app_commit": os.getenv("GIT_COMMIT_SHA", "unknown"),
        "firebase_project_id": os.getenv("GOOGLE_CLOUD_PROJECT"),
        "utc": now_iso(),
    }

# -------------------------------------------------------
# Profile
# -------------------------------------------------------

@app.get("/profile")
def profile(user=Depends(require_authenticated_user)):
    return {
        "ok": True,
        "uid": user.get("uid"),
        "email": user.get("email"),
        "email_verified": user.get("email_verified"),
        "role": user.get("role"),
        "firebase_project_id": os.getenv("GOOGLE_CLOUD_PROJECT"),
        "utc": now_iso(),
    }

# -------------------------------------------------------
# Content Catalog Endpoints (read-only first)
# -------------------------------------------------------

@app.get("/curricula")
def get_curricula(user=Depends(require_authenticated_user)):
    docs = db.collection("curricula").stream()
    out = []
    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        out.append(data)
    return {"ok": True, "curricula": out}

@app.get("/modules")
def get_modules(
    curriculum_id: Optional[str] = Query(None),
    user=Depends(require_authenticated_user),
):
    q = db.collection("modules")
    if curriculum_id:
        q = q.where("curriculum_id", "==", curriculum_id)

    docs = q.stream()
    out = []
    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        out.append(data)
    return {"ok": True, "modules": out}

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
    out = []
    for d in docs:
        data = d.to_dict() or {}
        data["id"] = d.id
        out.append(data)
    return {"ok": True, "lessons": out}

@app.get("/sim-labs/{lab_id}")
def get_sim_lab(lab_id: str, user=Depends(require_authenticated_user)):
    doc = db.collection("sim_labs").document(lab_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Simulation lab not found")
    data = doc.to_dict() or {}
    data["id"] = doc.id
    return {"ok": True, "sim_lab": data}

# -------------------------------------------------------
# Step 3 — Progress + Mastery (learner state)
#
# Firestore:
# - progress/{uid}/modules/{module_id}
# - attempts/{uid}/items/{attempt_id}
# -------------------------------------------------------

@app.get("/progress/me")
def get_progress_me(user=Depends(require_authenticated_user)):
    uid = user["uid"]
    docs = db.collection("progress").document(uid).collection("modules").stream()
    out = []
    for d in docs:
        data = d.to_dict() or {}
        data["module_id"] = d.id
        out.append(data)
    return {"ok": True, "uid": uid, "modules": out}

@app.get("/progress/me/{module_id}")
def get_progress_me_module(module_id: str, user=Depends(require_authenticated_user)):
    uid = user["uid"]
    doc = db.collection("progress").document(uid).collection("modules").document(module_id).get()
    if not doc.exists:
        return {"ok": True, "uid": uid, "module_id": module_id, "progress": None}
    data = doc.to_dict() or {}
    data["module_id"] = module_id
    return {"ok": True, "uid": uid, "module_id": module_id, "progress": data}

@app.post("/progress/{module_id}/event")
def post_progress_event(
    request: Request,
    module_id: str,
    payload: Dict[str, Any] = Body(...),
    user=Depends(require_authenticated_user),
):
    """
    Records a learning event/attempt and updates module progress.

    Expected payload (flexible):
    {
      "lesson_id": "L1",
      "type": "concept|simulation|reflection|assessment|transfer",
      "score": 0.0-1.0 (optional),
      "answers": {...} (optional),
      "misconception_tags": ["..."] (optional),
      "duration_ms": 1234 (optional),
      "mastery_pct": 0-100 (optional)  # client can supply
      "readiness_score": 0-100 (optional)
      "status": "locked|in_progress|mastered" (optional)
      "meta": {...} (optional)
    }
    """
    uid = user["uid"]
    role = user.get("role")

    event_type = str(payload.get("type") or "event")
    lesson_id = payload.get("lesson_id")
    score = payload.get("score")
    duration_ms = payload.get("duration_ms")
    misconception_tags = payload.get("misconception_tags") or []
    answers = payload.get("answers")
    meta = payload.get("meta") or {}

    attempt_id = uuid.uuid4().hex[:20]
    ts = now_utc()

    # 1) Write attempt
    attempt_doc = {
        "attempt_id": attempt_id,
        "uid": uid,
        "module_id": module_id,
        "lesson_id": lesson_id,
        "type": event_type,
        "score": score,
        "answers": answers,
        "misconception_tags": misconception_tags,
        "duration_ms": duration_ms,
        "meta": meta,
        "utc": ts,
    }
    db.collection("attempts").document(uid).collection("items").document(attempt_id).set(attempt_doc)

    # 2) Update progress (merge)
    progress_ref = db.collection("progress").document(uid).collection("modules").document(module_id)
    current = progress_ref.get()
    current_data = current.to_dict() if current.exists else {}

    # Defaults
    new_status = payload.get("status") or current_data.get("status") or "in_progress"
    new_mastery = payload.get("mastery_pct")
    new_readiness = payload.get("readiness_score")

    # If assessment score present and mastery not explicitly provided, do a simple mapping
    # (You can replace later with your validated mastery model.)
    if new_mastery is None and isinstance(score, (int, float)):
        # convert 0..1 -> 0..100
        mapped = max(0.0, min(100.0, float(score) * 100.0))
        # keep best-so-far
        prev = float(current_data.get("mastery_pct") or 0.0)
        new_mastery = max(prev, mapped)

    progress_update: Dict[str, Any] = {
        "module_id": module_id,
        "status": new_status,
        "last_activity_utc": ts,
        "last_event_type": event_type,
        "last_attempt_id": attempt_id,
    }
    if new_mastery is not None:
        progress_update["mastery_pct"] = float(new_mastery)
    if new_readiness is not None:
        progress_update["readiness_score"] = float(new_readiness)

    progress_ref.set(progress_update, merge=True)

    # 3) Audit
    write_audit_log(
        db,
        event_type="progress.event",
        request=request,
        status_code=200,
        actor_uid=uid,
        actor_role=role,
        detail={
            "module_id": module_id,
            "lesson_id": lesson_id,
            "type": event_type,
            "attempt_id": attempt_id,
        },
    )

    return {"ok": True, "attempt_id": attempt_id, "module_id": module_id}

# -------------------------------------------------------
# Admin Metrics (reads from api_keys)
# -------------------------------------------------------

@app.get("/admin/metrics")
def admin_metrics(request: Request, admin=Depends(require_admin)):
    uid = admin.get("uid")
    role = admin.get("role")

    total = 0
    active = 0
    auto_disabled = 0

    # IMPORTANT: per your instruction, read from api_keys
    for d in db.collection("api_keys").stream():
        total += 1
        data = d.to_dict() or {}
        if data.get("active"):
            active += 1
        if data.get("auto_disabled"):
            auto_disabled += 1

    write_audit_log(
        db,
        event_type="admin.metrics.read",
        request=request,
        status_code=200,
        actor_uid=uid,
        actor_role=role,
        detail={"keys_total": total, "keys_active": active, "auto_disabled": auto_disabled},
    )

    return {
        "ok": True,
        "utc": now_iso(),
        "keys": {"total": total, "active": active, "auto_disabled": auto_disabled},
    }