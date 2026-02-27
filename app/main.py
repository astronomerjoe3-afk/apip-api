# app/main.py
import os
import uuid
import time
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

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

# Prefer canonical env var; fall back to legacy; final fallback to "local" so smoke tests don't 500.
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
    # Cloud Run: X-Forwarded-For may include multiple IPs; first is original.
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None

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
    # IMPORTANT: never return "unknown" – smoke tests should be deterministic.
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
# Admin Metrics (reads from api_keys as requested)
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
# Admin Keys (RESTORED for web dashboard)
# -------------------------------------------------------

def _public_key_view(key_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    # Never return secret_hash
    return {
        "key_id": key_id,
        "label": data.get("label"),
        "active": bool(data.get("active", False)),
        "scopes": data.get("scopes", []),
        "created_utc": data.get("created_utc"),
        "updated_utc": data.get("updated_utc"),
        "rate_limit": data.get("rate_limit", {}),
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
    """
    Minimal key creation to support dashboard flows.
    Returns api_key (secret) ONCE.
    Firestore doc stored in api_keys/{key_id} with secret_hash only.
    """
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
        "api_key": api_key_secret,  # RETURN ONCE
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
    # Keep names consistent with what your rate limiter uses.
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