import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from google.cloud import firestore
from starlette.middleware.base import BaseHTTPMiddleware

from app.dependencies import require_admin, require_authenticated_user
from app.audit import write_audit_log

# -------------------------------------------------------
# App Init
# -------------------------------------------------------

APP_NAME = "apip-api"
APP_VERSION = "0.2.0"

app = FastAPI(title="APIP API", version=APP_VERSION)
db = firestore.Client()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# -------------------------------------------------------
# CORS
# -------------------------------------------------------
# Keep permissive for now; tighten later using env:
# ALLOWED_ORIGINS="https://api.cognispark.tech,https://app.cognispark.tech,http://localhost:3000"
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
        err = None

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception as e:
            err = e
            status_code = 500
            # Return a controlled JSON error so request_id is always present
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal Server Error", "request_id": request_id},
            )
        finally:
            duration_ms = round((time.time() - start) * 1000, 2)

            # Always attach header if response exists
            try:
                if response is not None:
                    response.headers["X-Request-Id"] = request_id
            except Exception:
                pass

            # Structured log to stdout (Cloud Run picks it up)
            print(
                {
                    "type": "http_request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": status_code,
                    "duration_ms": duration_ms,
                    "utc": now_iso(),
                    "error": str(err)[:512] if err else None,
                }
            )

            # Audit log (best-effort; never breaks request)
            write_audit_log(
                db,
                event_type="api.request",
                request=request,
                status_code=status_code,
                duration_ms=duration_ms,
                detail={"error": str(err)[:512]} if err else None,
            )

app.add_middleware(RequestContextMiddleware)

# -------------------------------------------------------
# Health + Build
# -------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "utc": now_iso()}

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
# Profile (handy for Step 3.x web testing)
# -------------------------------------------------------

@app.get("/profile")
def profile(user=Depends(require_authenticated_user)):
    uid = user.get("uid") or user.get("user_id") or user.get("sub")
    return {
        "ok": True,
        "uid": uid,
        "email": user.get("email"),
        "email_verified": user.get("email_verified"),
        "role": user.get("role"),
        "firebase_project_id": os.getenv("GOOGLE_CLOUD_PROJECT"),
        "utc": now_iso(),
    }

# -------------------------------------------------------
# Content Catalog Endpoints (read-only first)
# Collections:
# - curricula/{curriculum_id}
# - modules/{module_id}
# - lessons/{lesson_id} (module_id + sequence)
# - sim_labs/{lab_id}
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
    query = db.collection("modules")
    if curriculum_id:
        query = query.where("curriculum_id", "==", curriculum_id)

    docs = query.stream()
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
# Admin Metrics (Minimal Observability)
# IMPORTANT: read keys from collection "api_keys" (per your instruction)
# -------------------------------------------------------

@app.get("/admin/metrics")
def admin_metrics(request: Request, admin=Depends(require_admin)):
    uid = admin.get("uid") or admin.get("user_id") or admin.get("sub")
    role = admin.get("role")

    total = 0
    active = 0
    auto_disabled = 0

    keys_docs = db.collection("api_keys").stream()
    for d in keys_docs:
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