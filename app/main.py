import os
import json
import time
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from google.cloud import firestore

import firebase_admin
from firebase_admin import auth

from app.rate_limit import enforce_rate_limit


APP_NAME = os.getenv("APP_NAME", "apip-api")
APP_VERSION = os.getenv("APP_VERSION", "0.1.0")
APP_COMMIT = os.getenv("APP_COMMIT", os.getenv("K_REVISION", "dev"))

FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", os.getenv("GOOGLE_CLOUD_PROJECT", ""))

# CORS for local dashboard + optionally your production frontend.
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()]

AUDIT_TTL_DAYS = int(os.getenv("AUDIT_TTL_DAYS", "30"))
COUNTER_TTL_HOURS_1H = int(os.getenv("COUNTER_TTL_HOURS_1H", "2"))     # keep a buffer beyond 1h window
COUNTER_TTL_HOURS_24H = int(os.getenv("COUNTER_TTL_HOURS_24H", "30"))  # keep a buffer beyond 24h window


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def expires_at(days: int) -> datetime:
    return now_utc() + timedelta(days=days)


def expires_at_hours(hours: int) -> datetime:
    return now_utc() + timedelta(hours=hours)


def safe_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return default
        return int(x)
    except Exception:
        return default


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def log_json(obj: Dict[str, Any]) -> None:
    # Cloud Run picks this up as structured log if it's valid JSON.
    try:
        print(json.dumps(obj, default=str), flush=True)
    except Exception:
        print(str(obj), flush=True)


app = FastAPI()
db = firestore.Client()

if not firebase_admin._apps:
    firebase_admin.initialize_app()


# -------------------------
# CORS (needed for Step 3.1)
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=[
        "X-Request-Id",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "X-RateLimit-Daily-Limit",
        "X-RateLimit-Daily-Remaining",
        "X-RateLimit-Daily-Reset",
        "X-RateLimit-Violation",
        "X-API-Key-Auto-Disabled",
        "Retry-After",
    ],
)


# -------------------------
# Security headers
# -------------------------
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def with_security_headers(resp: JSONResponse) -> JSONResponse:
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


# -------------------------
# Request ID + latency + audit
# -------------------------
@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("X-Request-Id") or (uuid.uuid4().hex[:16])
    start = time.time()

    # attach early so handlers can use it
    request.state.request_id = request_id

    status_code = 500
    response: Optional[JSONResponse] = None
    error_class: Optional[str] = None

    try:
        response = await call_next(request)
        status_code = getattr(response, "status_code", 200)
        return response
    except Exception as e:
        error_class = e.__class__.__name__
        raise
    finally:
        duration_ms = int((time.time() - start) * 1000)

        # best-effort audit logging (never break requests)
        try:
            key_id = getattr(request.state, "key_id", None)
            uid = getattr(request.state, "uid", None)

            audit_doc = {
                "event_type": "api.request",
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "key_id": key_id,
                "uid": uid,
                "ts": now_utc(),
                "expires_at_utc": expires_at(AUDIT_TTL_DAYS),
            }
            if error_class:
                audit_doc["error_class"] = error_class

            db.collection("audit_logs").add(audit_doc)

            log_json({
                "severity": "INFO" if status_code < 500 else "ERROR",
                "message": "request",
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "key_id": key_id,
                "uid": uid,
                "error_class": error_class,
            })
        except Exception as _:
            pass


@app.middleware("http")
async def add_response_headers(request: Request, call_next):
    resp = await call_next(request)
    # request id always present
    rid = getattr(request.state, "request_id", None) or (uuid.uuid4().hex[:16])
    resp.headers.setdefault("X-Request-Id", rid)
    # security headers
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


# -------------------------
# Auth helpers
# -------------------------
def _bearer_token(request: Request) -> str:
    h = request.headers.get("Authorization", "")
    if not h:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = h.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return parts[1].strip()


def require_user(request: Request) -> Dict[str, Any]:
    token = _bearer_token(request)
    try:
        decoded = auth.verify_id_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid ID token")

    request.state.uid = decoded.get("uid") or decoded.get("sub")
    return decoded


def require_admin(request: Request) -> Dict[str, Any]:
    decoded = require_user(request)
    if decoded.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return decoded


# -------------------------
# API key auth + RL
# -------------------------
def _parse_key_id(api_key: str) -> str:
    # Format: ak_<key_id>.<secret>
    if not api_key.startswith("ak_") or "." not in api_key:
        raise HTTPException(status_code=401, detail="Invalid API key format")
    key_id = api_key.split(".", 1)[0].replace("ak_", "").strip()
    if not key_id:
        raise HTTPException(status_code=401, detail="Invalid API key format")
    return key_id


def build_rate_headers(policy: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, str]:
    headers = {
        "X-RateLimit-Limit": str(policy.get("rl_window_limit", "")),
        "X-RateLimit-Remaining": str(meta.get("window_remaining", "")),
        "X-RateLimit-Reset": str(meta.get("window_reset", "")),
        "X-RateLimit-Daily-Limit": str(policy.get("rl_daily_limit", "")),
        "X-RateLimit-Daily-Remaining": str(meta.get("daily_remaining", "")),
        "X-RateLimit-Daily-Reset": str(meta.get("daily_reset", "")),
    }
    if meta.get("violation"):
        headers["X-RateLimit-Violation"] = str(meta["violation"])
    if meta.get("retry_after") is not None:
        headers["Retry-After"] = str(meta["retry_after"])
    if meta.get("auto_disabled"):
        headers["X-API-Key-Auto-Disabled"] = "1"
    return headers


def require_api_key(request: Request) -> str:
    api_key = request.headers.get("X-API-Key", "")
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key")

    key_id = _parse_key_id(api_key)

    snap = db.collection("keys").document(key_id).get()
    if not snap.exists:
        raise HTTPException(status_code=403, detail="Key not found")

    policy = snap.to_dict() or {}
    if not policy.get("active", False):
        raise HTTPException(status_code=403, detail="Key disabled")

    # Optional: validate secret cheaply (prevents guessing key_id alone).
    # Store only secret_hash in Firestore.
    stored_hash = policy.get("secret_hash")
    if stored_hash:
        secret = api_key.split(".", 1)[1]
        if sha256_hex(secret) != stored_hash:
            raise HTTPException(status_code=403, detail="Key invalid")

    allowed, meta = enforce_rate_limit(db=db, key_id=key_id, policy=policy)

    request.state.key_id = key_id
    request.state.policy = policy
    request.state.rate_meta = meta

    if not allowed:
        headers = build_rate_headers(policy, meta)
        return with_security_headers(JSONResponse(status_code=429, content={"detail": "Rate limited"}, headers=headers))

    # best-effort usage counters
    try:
        db.collection("keys").document(key_id).update({
            "last_used_at_utc": now_utc(),
            "total_requests": firestore.Increment(1),
        })
    except Exception:
        pass

    return key_id


# -------------------------
# Smoke tests / build info
# -------------------------
@app.get("/health")
def health():
    return {"status": "ok", "firebase_project_id": FIREBASE_PROJECT_ID, "commit": APP_COMMIT}


@app.get("/__build")
@app.get("/_build")
def build_info():
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "app_commit": APP_COMMIT,
        "firebase_project_id": FIREBASE_PROJECT_ID,
        "utc": now_utc().isoformat(),
    }


# -------------------------
# Step 3.1: /profile endpoint (fix dashboard API 404)
# -------------------------
@app.get("/profile")
def profile(request: Request, user=Depends(require_user)):
    # This is what your dashboard wants to fetch.
    # It reflects server-trusted token claims.
    return {
        "ok": True,
        "uid": user.get("uid") or user.get("sub"),
        "email": user.get("email"),
        "email_verified": user.get("email_verified", False),
        "role": user.get("role"),
        "firebase_project_id": FIREBASE_PROJECT_ID,
        "utc": now_utc().isoformat(),
    }


# -------------------------
# Protected endpoint (API-key)
# -------------------------
@app.get("/protected")
def protected(request: Request, key_id: str = Depends(require_api_key)):
    headers = build_rate_headers(request.state.policy, request.state.rate_meta)
    return with_security_headers(JSONResponse({"ok": True, "key_id": key_id}, headers=headers))


# -------------------------
# Admin: minimal metrics (keep compatible)
# (Your project has a richer metrics set already; this keeps Step 3.1 safe.)
# -------------------------
@app.get("/admin/metrics")
def admin_metrics(request: Request, admin=Depends(require_admin), top_n: int = 10):
    # Uses TTL counter collections (fast, no audit scan).
    top_n = max(1, min(int(top_n), 50))

    def _get_count(doc_path: str) -> int:
        s = db.document(doc_path).get()
        if not s.exists:
            return 0
        return safe_int((s.to_dict() or {}).get("count", 0), 0)

    keys_total = 0
    keys_active = 0
    keys_auto_disabled = 0
    try:
        # small dataset so get() is OK; if it grows, switch to count aggregation.
        all_keys = db.collection("keys").get()
        keys_total = len(all_keys)
        for k in all_keys:
            d = k.to_dict() or {}
            if d.get("active", False):
                keys_active += 1
            if d.get("auto_disabled", False):
                keys_auto_disabled += 1
    except Exception:
        pass

    global_1h_total = _get_count("global_abuse_1h/global")
    global_24h_total = _get_count("global_abuse_24h/global")

    def _top(coll: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            qs = db.collection(coll).order_by("count", direction=firestore.Query.DESCENDING).limit(top_n)
            for s in qs.stream():
                d = s.to_dict() or {}
                out.append({"key_id": s.id, "count": safe_int(d.get("count", 0), 0)})
        except Exception:
            pass
        return out

    top_1h = _top("api_key_abuse_1h")
    top_24h = _top("api_key_abuse_24h")

    warnings: List[str] = []
    if global_1h_total >= 1:
        warnings.append(f"global_violations_1h={global_1h_total}")
    if global_24h_total >= 1:
        warnings.append(f"global_violations_24h={global_24h_total}")

    return {
        "ok": True,
        "utc": now_utc().isoformat(),
        "keys": {"total": keys_total, "active": keys_active, "auto_disabled": keys_auto_disabled},
        "rate_limit": {
            "global_last_hour": {"total": global_1h_total},
            "global_last_24h": {"total": global_24h_total},
            "top_keys_last_hour": top_1h,
            "top_keys_last_24h": top_24h,
            "top_n": top_n,
        },
        "warnings": warnings,
    }
