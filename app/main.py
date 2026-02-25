import os
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from google.cloud import firestore
import firebase_admin
from firebase_admin import auth, credentials
from app.rate_limit import enforce_rate_limit

app = FastAPI()
db = firestore.Client()

if not firebase_admin._apps:
    firebase_admin.initialize_app()

def now():
    return datetime.now(timezone.utc)

def ttl():
    return now() + timedelta(days=30)

# =========================
# REQUEST ID + LATENCY
# =========================
@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = str(uuid.uuid4())[:16]
    start = time.time()

    response = None
    try:
        response = await call_next(request)
    finally:
        duration_ms = int((time.time() - start) * 1000)

        db.collection("audit_logs").add({
            "event_type": "api.request",
            "path": request.url.path,
            "method": request.method,
            "status_code": response.status_code if response else 500,
            "duration_ms": duration_ms,
            "ts": now(),
            "expires_at_utc": ttl(),
        })

    response.headers["X-Request-Id"] = request_id
    return response

# =========================
# AUTH
# =========================
def require_admin(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(401)

    token = auth_header.split(" ")[1]
    decoded = auth.verify_id_token(token)
    if decoded.get("role") != "admin":
        raise HTTPException(403)
    return decoded

def require_api_key(request: Request):
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(401)

    key_id = api_key.split(".")[0].replace("ak_", "")
    doc = db.collection("keys").document(key_id).get()
    if not doc.exists or not doc.to_dict().get("active"):
        raise HTTPException(403)

    policy = doc.to_dict()

    allowed, meta = enforce_rate_limit(key_id, policy)
    if not allowed:
        headers = build_headers(policy, meta)
        return JSONResponse(status_code=429, content={"detail": "Rate limited"}, headers=headers)

    # increment usage counters
    db.collection("keys").document(key_id).update({
        "last_used_at_utc": now(),
        "total_requests": firestore.Increment(1),
    })

    request.state.rate_meta = meta
    request.state.policy = policy
    request.state.key_id = key_id
    return key_id

def build_headers(policy: Dict[str, Any], meta: Dict[str, Any]):
    return {
        "X-RateLimit-Limit": str(policy.get("rl_window_limit")),
        "X-RateLimit-Remaining": str(meta.get("window_remaining")),
        "X-RateLimit-Reset": str(meta.get("window_reset")),
        "X-RateLimit-Daily-Limit": str(policy.get("rl_daily_limit")),
        "X-RateLimit-Daily-Remaining": str(meta.get("daily_remaining")),
        "X-RateLimit-Daily-Reset": str(meta.get("daily_reset")),
        "Retry-After": str(meta.get("retry_after", 0)),
    }

# =========================
# PROTECTED ENDPOINT
# =========================
@app.get("/protected")
def protected(request: Request, key_id: str = Depends(require_api_key)):
    headers = build_headers(request.state.policy, request.state.rate_meta)
    return JSONResponse({"ok": True}, headers=headers)

# =========================
# ADMIN METRICS
# =========================
@app.get("/admin/metrics")
def metrics(admin=Depends(require_admin)):

    one_hour = now() - timedelta(hours=1)
    one_day = now() - timedelta(hours=24)

    def count(event, since):
        docs = (
            db.collection_group("audit_logs")
            .where("event_type", "==", event)
            .where("ts", ">=", since)
            .get()
        )
        return len(docs)

    window_1h = count("api_key.rate_limited.window", one_hour)
    daily_1h = count("api_key.rate_limited.daily", one_hour)

    window_24h = count("api_key.rate_limited.window", one_day)
    daily_24h = count("api_key.rate_limited.daily", one_day)

    return {
        "ok": True,
        "utc": now(),
        "rate_limit": {
            "window_429_last_hour": window_1h,
            "daily_429_last_hour": daily_1h,
            "window_429_last_24h": window_24h,
            "daily_429_last_24h": daily_24h,
        }
    }