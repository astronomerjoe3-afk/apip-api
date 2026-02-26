from __future__ import annotations

import os
import time
import uuid
import json
import hashlib
import secrets as py_secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, List, Callable

from fastapi import FastAPI, Depends, Header, HTTPException, Body, Request, Response, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import firebase_admin
from firebase_admin import auth as fb_auth
from firebase_admin import credentials

from google.cloud import firestore
from google.api_core import exceptions as g_exceptions

from app.rate_limit import enforce_rate_limit, reset_key_counters


APP_NAME = "apip-api"
APP_VERSION = "0.1.0"

API_KEY_HEADER = "X-API-Key"
API_KEY_PREFIX = "ak_"

# -------------------------
# Env
# -------------------------
BOOTSTRAP_ADMIN_UID = os.getenv("BOOTSTRAP_ADMIN_UID", "").strip()
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "").strip()
APP_COMMIT = os.getenv("APP_COMMIT", "(unset)").strip()

ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()  # optional

_CORS_ORIGINS_ENV = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
if _CORS_ORIGINS_ENV:
    CORS_ALLOW_ORIGINS = [o.strip() for o in _CORS_ORIGINS_ENV.split(",") if o.strip()]
else:
    CORS_ALLOW_ORIGINS = [
        "http://localhost:3000",
        "https://cognispark.tech",
        "https://www.cognispark.tech",
    ]


# -------------------------
# Firebase / Firestore init
# -------------------------
def _ensure_firebase() -> None:
    if firebase_admin._apps:
        return
    # ADC in Cloud Run
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)

def get_firestore() -> firestore.Client:
    _ensure_firebase()
    if FIREBASE_PROJECT_ID:
        return firestore.Client(project=FIREBASE_PROJECT_ID)
    return firestore.Client()

db = get_firestore()


# -------------------------
# Time helpers
# -------------------------
def now_utc_dt() -> datetime:
    return datetime.now(timezone.utc)

def ttl_dt(days: int = 30) -> datetime:
    return now_utc_dt() + timedelta(days=days)


# -------------------------
# App
# -------------------------
app = FastAPI(title=APP_NAME, version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------------
# Security headers
# -------------------------
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


# -------------------------
# Audit logging
# -------------------------
def _safe_client_ip(request: Request) -> Optional[str]:
    # Cloud Run / proxies: X-Forwarded-For may contain multiple, take first
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None

def audit_log(event_type: str, payload: Dict[str, Any]) -> None:
    """
    Best-effort audit log.
    Writes into collection "audit_logs" with TTL field "expires_at_utc".
    """
    try:
        doc = {
            "event_type": event_type,
            "ts": now_utc_dt(),
            "expires_at_utc": ttl_dt(30),
            **payload,
        }
        db.collection("audit_logs").add(doc)
    except Exception:
        # never break request due to audit failure
        return

def log_json(message: str, fields: Dict[str, Any]) -> None:
    """
    Cloud Run structured logs: print JSON line.
    """
    try:
        out = {"message": message, **fields}
        print(json.dumps(out, default=str))
    except Exception:
        print(message)


# -------------------------
# Middleware: request id + latency + attach headers
# -------------------------
@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = uuid.uuid4().hex[:16]
    request.state.request_id = request_id
    start = time.time()

    response: Optional[Response] = None
    exc: Optional[BaseException] = None

    try:
        response = await call_next(request)
        return response
    except BaseException as e:
        exc = e
        raise
    finally:
        duration_ms = int((time.time() - start) * 1000)

        status_code = 500
        if response is not None:
            status_code = getattr(response, "status_code", 500)

        key_id = getattr(request.state, "api_key_id", None)
        violation = getattr(request.state, "rate_limit_violation", "")

        # attach request id & security headers if response exists
        if response is not None:
            response.headers["X-Request-Id"] = request_id
            for k, v in SECURITY_HEADERS.items():
                response.headers[k] = v

            # attach any rl headers captured in request.state
            rl_headers = getattr(request.state, "rate_limit_headers", None)
            if isinstance(rl_headers, dict):
                for k, v in rl_headers.items():
                    response.headers[k] = str(v)

        # audit + structured logs (best effort)
        audit_log("api.request", {
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
            "status_code": status_code,
            "duration_ms": duration_ms,
            "key_id": key_id,
            "violation": violation or None,
            "ip": _safe_client_ip(request),
            "ua": request.headers.get("user-agent"),
        })

        log_json("request", {
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
            "status_code": status_code,
            "duration_ms": duration_ms,
            "key_id": key_id,
            "violation": violation or None,
            "error_type": type(exc).__name__ if exc else None,
        })


# -------------------------
# Auth helpers (Firebase ID tokens)
# -------------------------
def _extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None
    if parts[0].lower() != "bearer":
        return None
    return parts[1].strip()

def verify_firebase_id_token(authorization: Optional[str]) -> Dict[str, Any]:
    token = _extract_bearer_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    try:
        _ensure_firebase()
        decoded = fb_auth.verify_id_token(token)
        return decoded
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_id_token", "message": str(e), "type": type(e).__name__},
        )

def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    decoded = verify_firebase_id_token(authorization)
    uid = decoded.get("uid") or decoded.get("sub")
    email = decoded.get("email")
    role = decoded.get("role") or "user"
    return {
        "uid": uid,
        "email": email,
        "role": role,
        "claims": decoded,
    }

def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    uid = user.get("uid")
    role = user.get("role")

    if BOOTSTRAP_ADMIN_UID and uid == BOOTSTRAP_ADMIN_UID:
        return user

    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# -------------------------
# API Key helpers
# -------------------------
def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()

def _now_utc_iso() -> str:
    return now_utc_dt().isoformat()

def _parse_api_key(api_key: str) -> Optional[Dict[str, str]]:
    if not api_key:
        return None
    api_key = api_key.strip()
    if not api_key.startswith(API_KEY_PREFIX):
        return None
    rest = api_key[len(API_KEY_PREFIX):]
    if "." not in rest:
        return None
    key_id, secret = rest.split(".", 1)
    key_id = key_id.strip()
    secret = secret.strip()
    if not key_id or not secret:
        return None
    return {"key_id": key_id, "secret": secret}

def get_api_key_record(key_id: str) -> Optional[Dict[str, Any]]:
    snap = db.collection("api_keys").document(key_id).get()
    if not snap.exists:
        return None
    data = snap.to_dict() or {}
    data["key_id"] = key_id
    return data

def require_api_key(required_scopes: Optional[List[str]] = None) -> Callable[..., Dict[str, Any]]:
    def _dep(
        request: Request,
        x_api_key: Optional[str] = Header(default=None, alias=API_KEY_HEADER),
    ) -> Dict[str, Any]:
        if not x_api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key")

        parsed = _parse_api_key(x_api_key)
        if not parsed:
            raise HTTPException(status_code=401, detail="Invalid API key format")

        rec = get_api_key_record(parsed["key_id"])
        if not rec:
            raise HTTPException(status_code=401, detail="Invalid API key")

        if not rec.get("active", False):
            raise HTTPException(status_code=403, detail="API key disabled")

        expected_hash = rec.get("secret_hash") or ""
        provided_hash = _hash_secret(parsed["secret"])
        if not py_secrets.compare_digest(str(expected_hash), str(provided_hash)):
            raise HTTPException(status_code=401, detail="Invalid API key")

        scopes = rec.get("scopes") or []
        if required_scopes:
            for s in required_scopes:
                if s not in scopes and "admin:*" not in scopes:
                    raise HTTPException(status_code=403, detail=f"Missing scope: {s}")

        # make key_id available to middleware/logging
        request.state.api_key_id = rec.get("key_id")
        return rec

    return _dep


# -------------------------
# Rate limit dependency
# -------------------------
def rate_limit_dep() -> Callable[..., Any]:
    def _dep(request: Request, api_key: Dict[str, Any] = Depends(require_api_key())) -> Any:
        key_id = api_key["key_id"]

        # enforce using Firestore transaction-backed limiter
        decision = enforce_rate_limit(db, key_id, api_key)

        # attach headers on all responses
        request.state.rate_limit_headers = decision.headers
        request.state.rate_limit_violation = decision.violation

        if not decision.allowed:
            # If key was auto-disabled, also mark
            if decision.auto_disabled:
                request.state.rate_limit_headers = {
                    **decision.headers,
                    "X-API-Key-Auto-Disabled": "1",
                }
                # Audit the disable posture (best effort)
                audit_log("api_key.auto_disabled", {
                    "request_id": getattr(request.state, "request_id", None),
                    "key_id": key_id,
                    "reason": f"threshold_exceeded:{decision.violation}",
                })

            # Audit RL violation event_type split (window vs daily)
            if decision.violation in ("window", "daily"):
                audit_log(f"api_key.rate_limited.{decision.violation}", {
                    "request_id": getattr(request.state, "request_id", None),
                    "key_id": key_id,
                })

            # return 429 with headers
            raise HTTPException(status_code=429, detail="Rate limited")

        # record last used + total_requests
        try:
            db.collection("api_keys").document(key_id).update({
                "last_used_at_utc": now_utc_dt(),
                "total_requests": firestore.Increment(1),
                "updated_at_utc": now_utc_dt(),
            })
        except Exception:
            pass

        return True

    return _dep


# -------------------------
# Models
# -------------------------
from pydantic import BaseModel

class CreateKeyRequest(BaseModel):
    label: Optional[str] = None
    scopes: Optional[List[str]] = None
    rl_window_limit: Optional[int] = None
    rl_window_seconds: Optional[int] = None
    rl_bucket_seconds: Optional[int] = None
    rl_daily_limit: Optional[int] = None

class CreateKeyResponse(BaseModel):
    ok: bool
    key_id: str
    api_key: str
    created_at_utc: str

class RevokeKeyResponse(BaseModel):
    ok: bool
    key_id: str
    revoked: bool

class EnableKeyResponse(BaseModel):
    ok: bool
    key_id: str
    enabled: bool

class ResetCountersResponse(BaseModel):
    ok: bool
    key_id: str
    reset: bool
    details: Dict[str, Any]

class PatchRateLimitReq(BaseModel):
    rl_window_limit: Optional[int] = None
    rl_window_seconds: Optional[int] = None
    rl_bucket_seconds: Optional[int] = None
    rl_daily_limit: Optional[int] = None


# -------------------------
# Basic routes
# -------------------------
@app.get("/health")
def health():
    return {
        "status": "ok",
        "firebase_project_id": FIREBASE_PROJECT_ID or "(unset)",
        "commit": APP_COMMIT,
    }

@app.get("/__build")
def build_marker():
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "app_commit": APP_COMMIT,
        "firebase_project_id": FIREBASE_PROJECT_ID or "(unset)",
        "utc": now_utc_dt().isoformat(),
    }

@app.get("/_build")
def build_marker_alias():
    return build_marker()


# -------------------------
# Admin: keys CRUD
# -------------------------
@app.post("/keys", response_model=CreateKeyResponse)
def create_api_key(
    req: CreateKeyRequest = Body(default_factory=CreateKeyRequest),
    admin: Dict[str, Any] = Depends(require_admin),
):
    # key_id is doc id; secret returned once
    key_id = py_secrets.token_urlsafe(12).replace("-", "").replace("_", "")
    secret = py_secrets.token_urlsafe(32)

    api_key = f"{API_KEY_PREFIX}{key_id}.{secret}"
    secret_hash = _hash_secret(secret)

    doc = {
        "key_id": key_id,
        "secret_hash": secret_hash,
        "active": True,
        "label": req.label,
        "scopes": req.scopes or [],
        "created_at_utc": _now_utc_iso(),
        "created_by_uid": admin["uid"],
        "created_by_email": admin.get("email"),
        "updated_at_utc": now_utc_dt(),
        "last_used_at_utc": None,
        "total_requests": 0,

        # per-key RL policy
        "rl_window_limit": req.rl_window_limit,
        "rl_window_seconds": req.rl_window_seconds,
        "rl_bucket_seconds": req.rl_bucket_seconds,
        "rl_daily_limit": req.rl_daily_limit,

        # posture fields
        "auto_disabled": False,
        "auto_disabled_at_utc": None,
        "auto_disabled_reason": None,
        "revoked_at_utc": None,
        "revoked_by_uid": None,
    }

    try:
        db.collection("api_keys").document(key_id).set(doc)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "firestore_write_failed", "message": str(e)})

    audit_log("api_key.created", {
        "key_id": key_id,
        "actor_uid": admin["uid"],
        "actor_email": admin.get("email"),
        "label": req.label,
        "scopes": req.scopes or [],
    })

    return {"ok": True, "key_id": key_id, "api_key": api_key, "created_at_utc": doc["created_at_utc"]}


@app.post("/keys/{key_id}/revoke", response_model=RevokeKeyResponse)
def revoke_api_key(key_id: str, admin: Dict[str, Any] = Depends(require_admin)):
    ref = db.collection("api_keys").document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update({
        "active": False,
        "revoked_at_utc": _now_utc_iso(),
        "revoked_by_uid": admin["uid"],
        "updated_at_utc": now_utc_dt(),
    })

    audit_log("api_key.revoked", {
        "key_id": key_id,
        "actor_uid": admin["uid"],
        "actor_email": admin.get("email"),
    })

    return {"ok": True, "key_id": key_id, "revoked": True}


@app.patch("/keys/{key_id}/rate-limit")
def patch_rate_limit_policy(
    key_id: str,
    body: PatchRateLimitReq,
    admin: Dict[str, Any] = Depends(require_admin),
):
    ref = db.collection("api_keys").document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    patch: Dict[str, Any] = {"updated_at_utc": now_utc_dt()}
    for f in ("rl_window_limit", "rl_window_seconds", "rl_bucket_seconds", "rl_daily_limit"):
        v = getattr(body, f, None)
        if v is not None:
            patch[f] = int(v)

    ref.update(patch)

    audit_log("api_key.rate_limit_updated", {
        "key_id": key_id,
        "actor_uid": admin["uid"],
        "actor_email": admin.get("email"),
        "patch": {k: patch[k] for k in patch.keys() if k != "updated_at_utc"},
    })

    return {"ok": True, "key_id": key_id, "updated": True, "rate_limit": patch}


@app.get("/keys")
def admin_list_keys(
    limit: int = Query(default=20, ge=1, le=200),
    admin: Dict[str, Any] = Depends(require_admin),
):
    try:
        snaps = db.collection("api_keys").limit(limit).stream()
        keys = []
        for s in snaps:
            d = s.to_dict() or {}
            d["key_id"] = s.id
            d.pop("secret_hash", None)
            keys.append(d)
        return {"ok": True, "count": len(keys), "keys": keys}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "list_failed", "message": str(e)})


@app.get("/keys/{key_id}")
def admin_get_key(
    key_id: str,
    admin: Dict[str, Any] = Depends(require_admin),
):
    rec = get_api_key_record(key_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Key not found")
    rec.pop("secret_hash", None)
    return {"ok": True, "key": rec}


# =========================
# Step 2.5.4 — NEW ENDPOINTS
# =========================
@app.post("/keys/{key_id}/enable", response_model=EnableKeyResponse)
def admin_enable_key(
    key_id: str,
    admin: Dict[str, Any] = Depends(require_admin),
):
    ref = db.collection("api_keys").document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    now_iso = _now_utc_iso()

    # Re-enable + clear posture fields
    ref.update({
        "active": True,
        "auto_disabled": False,
        "auto_disabled_at_utc": None,
        "auto_disabled_reason": None,
        "revoked_at_utc": None,
        "revoked_by_uid": None,
        "updated_at_utc": now_utc_dt(),
        "enabled_at_utc": now_iso,
        "enabled_by_uid": admin["uid"],
        "enabled_by_email": admin.get("email"),
    })

    audit_log("api_key.enabled", {
        "key_id": key_id,
        "actor_uid": admin["uid"],
        "actor_email": admin.get("email"),
    })

    return {"ok": True, "key_id": key_id, "enabled": True}


@app.post("/keys/{key_id}/reset-counters", response_model=ResetCountersResponse)
def admin_reset_key_counters(
    key_id: str,
    admin: Dict[str, Any] = Depends(require_admin),
):
    # Ensure key exists
    ref = db.collection("api_keys").document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    details = reset_key_counters(db, key_id)

    # optional: clear visible posture stats on key doc (if present)
    try:
        ref.update({
            "updated_at_utc": now_utc_dt(),
            "counters_reset_at_utc": _now_utc_iso(),
            "counters_reset_by_uid": admin["uid"],
            "counters_reset_by_email": admin.get("email"),
        })
    except Exception:
        pass

    audit_log("api_key.counters_reset", {
        "key_id": key_id,
        "actor_uid": admin["uid"],
        "actor_email": admin.get("email"),
        "details": details,
    })

    return {"ok": True, "key_id": key_id, "reset": True, "details": details}


# -------------------------
# Protected route (API key + RL)
# -------------------------
@app.get("/protected")
def protected(
    request: Request,
    _api_key: Dict[str, Any] = Depends(require_api_key(required_scopes=["profile:read"])),
    _rl: Any = Depends(rate_limit_dep()),
):
    # RL headers are attached by middleware via request.state.rate_limit_headers
    return {"ok": True, "message": "API key accepted"}


# -------------------------
# Admin metrics
# -------------------------
def _count_doc_total(col: str, doc_id: str) -> Optional[int]:
    try:
        snap = db.collection(col).document(doc_id).get()
        if not snap.exists:
            return 0
        data = snap.to_dict() or {}
        return int(data.get("total", 0))
    except Exception:
        return None

def _top_keys_from_abuse(col: str, top_n: int) -> List[Dict[str, Any]]:
    """
    Fast top keys without audit scan:
    uses TTL docs in api_key_abuse_* where total is stored per key.
    """
    try:
        q = db.collection(col).order_by("total", direction=firestore.Query.DESCENDING).limit(top_n)
        out: List[Dict[str, Any]] = []
        for s in q.stream():
            d = s.to_dict() or {}
            out.append({"key_id": s.id, "count": int(d.get("total", 0))})
        return out
    except Exception:
        return []

@app.get("/admin/metrics")
def admin_metrics(
    top_n: int = Query(default=10, ge=1, le=50),
    admin: Dict[str, Any] = Depends(require_admin),
):
    warnings: List[str] = []

    # keys stats
    try:
        # cheap scan capped
        snaps = list(db.collection("api_keys").limit(2000).stream())
        total = len(snaps)
        active = sum(1 for s in snaps if (s.to_dict() or {}).get("active", False))
        auto_disabled = sum(1 for s in snaps if (s.to_dict() or {}).get("auto_disabled", False))
    except Exception as e:
        total, active, auto_disabled = 0, 0, 0
        warnings.append(f"keys_count_failed:{type(e).__name__}")

    # global violation totals from TTL docs (no audit scan)
    g1h = _count_doc_total("global_abuse_1h", "global")
    g24h = _count_doc_total("global_abuse_24h", "global")

    if g1h is None:
        warnings.append("global_violations_1h_unavailable")
        g1h = 0
    if g24h is None:
        warnings.append("global_violations_24h_unavailable")
        g24h = 0

    if g1h >= 1:
        warnings.append(f"global_violations_1h={g1h}")
    if g24h >= 1:
        warnings.append(f"global_violations_24h={g24h}")

    # top keys (use abuse TTL docs)
    top_1h = _top_keys_from_abuse("api_key_abuse_1h", top_n)
    top_24h = _top_keys_from_abuse("api_key_abuse_24h", top_n)

    posture = {
        "alerts": "disabled" if not ALERT_WEBHOOK_URL else "enabled",
    }
    if not ALERT_WEBHOOK_URL:
        warnings.append("alerts=disabled")

    return {
        "ok": True,
        "utc": now_utc_dt().isoformat(),
        "keys": {
            "total": total,
            "active": active,
            "auto_disabled": auto_disabled,
        },
        "rate_limit": {
            "global_last_hour": g1h,
            "global_last_24h": g24h,
            "top_keys_last_hour": top_1h,
            "top_keys_last_24h": top_24h,
            "top_n": top_n,
        },
        "posture": posture,
        "warnings": warnings,
    }