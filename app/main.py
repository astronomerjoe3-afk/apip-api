import os
import uuid
import time
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from google.cloud import firestore
from starlette.middleware.base import BaseHTTPMiddleware

from app.dependencies import require_admin, require_authenticated_user
from app.firebase_admin_init import verify_id_token
from app.audit import write_audit_log

# -------------------------------------------------------
# App Init
# -------------------------------------------------------

app = FastAPI(title="APIP API", version="0.2.0")

db = firestore.Client()

# -------------------------------------------------------
# CORS
# -------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

        print({
            "type": "http_request",
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": duration_ms,
            "utc": datetime.now(timezone.utc).isoformat(),
        })

        return response

app.add_middleware(RequestIDMiddleware)

# -------------------------------------------------------
# Health + Build
# -------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "utc": datetime.now(timezone.utc).isoformat()
    }

@app.get("/__build")
@app.get("/_build")
def build():
    return {
        "app_name": "apip-api",
        "app_version": "0.2.0",
        "app_commit": os.getenv("GIT_COMMIT_SHA", "unknown"),
        "firebase_project_id": os.getenv("GOOGLE_CLOUD_PROJECT"),
        "utc": datetime.now(timezone.utc).isoformat(),
    }

# -------------------------------------------------------
# Content Catalog Endpoints
# -------------------------------------------------------

@app.get("/curricula")
def get_curricula(user=Depends(require_authenticated_user)):
    docs = db.collection("curricula").stream()
    result = []
    for d in docs:
        data = d.to_dict()
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
        data = d.to_dict()
        data["id"] = d.id
        result.append(data)

    return {"ok": True, "modules": result}

@app.get("/modules/{module_id}")
def get_module(module_id: str, user=Depends(require_authenticated_user)):
    doc = db.collection("modules").document(module_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Module not found")

    data = doc.to_dict()
    data["id"] = doc.id
    return {"ok": True, "module": data}

@app.get("/modules/{module_id}/lessons")
def get_module_lessons(module_id: str, user=Depends(require_authenticated_user)):
    docs = db.collection("lessons") \
        .where("module_id", "==", module_id) \
        .order_by("sequence") \
        .stream()

    result = []
    for d in docs:
        data = d.to_dict()
        data["id"] = d.id
        result.append(data)

    return {"ok": True, "lessons": result}

@app.get("/sim-labs/{lab_id}")
def get_sim_lab(lab_id: str, user=Depends(require_authenticated_user)):
    doc = db.collection("sim_labs").document(lab_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Simulation lab not found")

    data = doc.to_dict()
    data["id"] = doc.id
    return {"ok": True, "sim_lab": data}

# -------------------------------------------------------
# Admin Metrics (Minimal Observability)
# -------------------------------------------------------

@app.get("/admin/metrics")
def admin_metrics(user=Depends(require_admin)):
    keys_docs = db.collection("api_keys").stream()

    total = 0
    active = 0
    auto_disabled = 0

    for d in keys_docs:
        total += 1
        data = d.to_dict()
        if data.get("active"):
            active += 1
        if data.get("auto_disabled"):
            auto_disabled += 1

    return {
        "ok": True,
        "utc": datetime.now(timezone.utc).isoformat(),
        "keys": {
            "total": total,
            "active": active,
            "auto_disabled": auto_disabled,
        },
    }