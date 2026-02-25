import os
import time
import uuid
import json
import hashlib
import secrets as py_secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from fastapi import FastAPI, Depends, Header, HTTPException, Body, Request, Response, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import firebase_admin
from firebase_admin import auth as fb_auth
from firebase_admin import credentials

from google.cloud import firestore

from app.rate_limit import (
    enforce_rate_limit_or_429,
    COL_ABUSE_1H,
    COL_ABUSE_24H,
    COL_GLOBAL_ABUSE_1H,
    COL_GLOBAL_ABUSE_24H,
    COL_SECURITY,
)

APP_NAME = "apip-api"
APP_VERSION = "0.1.0"

API_KEY_HEADER = "X-API-Key"
API_KEY_PREFIX = "ak_"

BOOTSTRAP_ADMIN_UID = os.getenv("BOOTSTRAP_ADMIN_UID", "").strip()
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "").strip()
APP_COMMIT = os.getenv("APP_COMMIT", "(unset)").strip()

COL_KEYS = "api_keys"
COL_AUDIT = "audit_logs"

# Optional: enforce HTTPS-only downstream clients (Cloud Run already terminates TLS)
SEC_HSTS = os.getenv("SEC_HSTS", "1").strip() == "1"


# -------------------------
# CORS origins
# -------------------------
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
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)


def get_firestore() -> firestore.Client:
    _ensure_firebase()
    if FIREBASE_PROJECT_ID:
        return firestore.Client(project=FIREBASE_PROJECT_ID)
    return firestore.Client()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


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
        return fb_auth.verify_id_token(token)
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
    return {"uid": uid, "email": email, "role": role, "claims": decoded}


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    uid = user.get("uid")
    role = user.get("role")
    if BOOTSTRAP_ADMIN_UID and uid == BOOTSTRAP_ADMIN_UID:
        return user
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


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


def _get_api_key_record(db: firestore.Client, key_id: str) -> Optional[Dict[str, Any]]:
    snap = db.collection(COL_KEYS).document(key_id).get()
    if not snap.exists:
        return None
    d = snap.to_dict() or {}
    d["key_id"] = key_id
    return d


def _log_json(payload: Dict[str, Any]) -> None:
    # Cloud Run captures stdout to Cloud Logging
    try:
        print(json.dumps(payload, ensure_ascii=False))
    except Exception:
        pass


# -------------------------
# App
# -------------------------
app = FastAPI(title=APP_NAME, version=APP_VERSION)
app.state.db = get_firestore()

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# Exception handlers: guarantee Request-Id + RL headers
# =========================
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    headers = dict(exc.headers or {})
    rid = getattr(request.state, "request_id", None)
    if rid:
        headers.setdefault("X-Request-Id", rid)

    rl_headers = getattr(request.state, "rate_limit_headers", None)
    if isinstance(rl_headers, dict):
        for k, v in rl_headers.items():
            headers.setdefault(k, str(v))

    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=headers)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Always give request id for debugging
    rid = getattr(request.state, "request_id", None)
    headers: Dict[str, str] = {}
    if rid:
        headers["X-Request-Id"] = rid

    # Best-effort structured log
    _log_json(
        {
            "severity": "ERROR",
            "event": "api.unhandled_exception",
            "request_id": rid,
            "path": str(request.url.path),
            "method": str(request.method),
            "utc": _now().isoformat(),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    )
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"}, headers=headers)


# =========================
# Middleware: request-id, latency, security headers, structured logs, audit
# =========================
@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = uuid.uuid4().hex[:16]
    request.state.request_id = request_id

    start = time.perf_counter()
    status_code = 500

    try:
        response = await call_next(request)
        status_code = response.status_code
    except HTTPException as e:
        status_code = e.status_code
        raise
    finally:
        duration_ms = int((time.perf_counter() - start) * 1000)

        # Structured latency log (Cloud Logging friendly)
        _log_json(
            {
                "severity": "INFO",
                "event": "api.request",
                "request_id": request_id,
                "path": str(request.url.path),
                "method": str(request.method),
                "status_code": status_code,
                "duration_ms": duration_ms,
                "key_id": getattr(request.state, "api_key_id", None),
                "utc": _now().isoformat(),
            }
        )

        # Best-effort audit write (keep as you already use)
        try:
            db: firestore.Client = request.app.state.db
            db.collection(COL_AUDIT).add(
                {
                    "event_type": "api.request",
                    "ts": _now(),
                    "request_id": request_id,
                    "path": request.url.path,
                    "method": request.method,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                    "key_id": getattr(request.state, "api_key_id", None),
                }
            )
        except Exception:
            pass

    # Attach headers on normal responses
    response.headers["X-Request-Id"] = request_id

    # Security headers
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    # You can tighten CSP once frontend is fixed:
    response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
    if SEC_HSTS:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    # Rate limit headers (success-path)
    rl_headers = getattr(request.state, "rate_limit_headers", None)
    if isinstance(rl_headers, dict):
        for k, v in rl_headers.items():
            response.headers[k] = str(v)

    return response


# -------------------------
# Models
# -------------------------
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
    return {"status": "ok", "firebase_project_id": FIREBASE_PROJECT_ID or "(unset)", "commit": APP_COMMIT}


@app.get("/__build")
def build_marker():
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "app_commit": APP_COMMIT,
        "firebase_project_id": FIREBASE_PROJECT_ID or "(unset)",
        "utc": _now().isoformat(),
    }


@app.get("/_build")
def build_marker_alias():
    return build_marker()


# -------------------------
# API Key dependency (+ RL)
# -------------------------
def require_api_key(required_scopes: Optional[List[str]] = None):
    def _dep(
        request: Request,
        x_api_key: Optional[str] = Header(default=None, alias=API_KEY_HEADER),
    ) -> Dict[str, Any]:
        if not x_api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key")

        parsed = _parse_api_key(x_api_key)
        if not parsed:
            raise HTTPException(status_code=401, detail="Invalid API key format")

        db: firestore.Client = request.app.state.db
        rec = _get_api_key_record(db, parsed["key_id"])
        if not rec:
            raise HTTPException(status_code=401, detail="Invalid API key")

        if not rec.get("active", False):
            raise HTTPException(status_code=403, detail="API key revoked/disabled")

        expected_hash = str(rec.get("secret_hash") or "")
        provided_hash = _hash_secret(parsed["secret"])
        if not py_secrets.compare_digest(expected_hash, provided_hash):
            raise HTTPException(status_code=401, detail="Invalid API key")

        scopes = rec.get("scopes") or []
        if required_scopes:
            for s in required_scopes:
                if s not in scopes and "admin:*" not in scopes:
                    raise HTTPException(status_code=403, detail=f"Missing scope: {s}")

        request.state.api_key_id = rec["key_id"]

        # RL (may raise HTTPException(429) with headers)
        enforce_rate_limit_or_429(db, request, rec["key_id"], rec)

        # Usage counters best-effort
        try:
            db.collection(COL_KEYS).document(rec["key_id"]).set(
                {
                    "last_used_at_utc": _now(),
                    "total_requests": firestore.Increment(1),
                    "updated_at_utc": _now(),
                },
                merge=True,
            )
        except Exception:
            pass

        return {"key_id": rec["key_id"], "label": rec.get("label"), "scopes": scopes, "active": rec.get("active", False)}

    return _dep


# -------------------------
# Protected routes
# -------------------------
@app.get("/protected")
def protected(api_key: Dict[str, Any] = Depends(require_api_key(required_scopes=["profile:read"]))):
    return {"ok": True, "key_id": api_key["key_id"]}


# -------------------------
# Keys (admin)
# -------------------------
@app.post("/keys", response_model=CreateKeyResponse)
def create_key(req: CreateKeyRequest = Body(...), admin: Dict[str, Any] = Depends(require_admin)):
    db = app.state.db

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
        "created_at_utc": _now().isoformat(),
        "created_by_uid": admin.get("uid"),
        "created_by_email": admin.get("email"),
        "auto_disabled_at_utc": None,
        "auto_disabled_reason": None,
        "total_requests": 0,
        "last_used_at_utc": None,
        "updated_at_utc": _now(),
        "rl_window_limit": req.rl_window_limit,
        "rl_window_seconds": req.rl_window_seconds,
        "rl_bucket_seconds": req.rl_bucket_seconds,
        "rl_daily_limit": req.rl_daily_limit,
    }

    db.collection(COL_KEYS).document(key_id).set(doc)
    return {"ok": True, "key_id": key_id, "api_key": api_key, "created_at_utc": doc["created_at_utc"]}


@app.patch("/keys/{key_id}/rate-limit")
def patch_rate_limit(key_id: str, body: PatchRateLimitReq, admin: Dict[str, Any] = Depends(require_admin)):
    db = app.state.db
    ref = db.collection(COL_KEYS).document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    updates: Dict[str, Any] = {"updated_at_utc": _now()}
    for f in ["rl_window_limit", "rl_window_seconds", "rl_bucket_seconds", "rl_daily_limit"]:
        v = getattr(body, f)
        if v is not None:
            updates[f] = v

    ref.set(updates, merge=True)
    return {"ok": True, "key_id": key_id, "updated": True, "rate_limit": updates}


# -------------------------
# Admin metrics (global + top keys from TTL counters)
# -------------------------
def _doc_int(d: Dict[str, Any], k: str) -> int:
    try:
        return int(d.get(k) or 0)
    except Exception:
        return 0


@app.get("/admin/metrics")
def admin_metrics(admin: Dict[str, Any] = Depends(require_admin), top_n: int = Query(default=10, ge=1, le=50)):
    db = app.state.db

    # Key counts (simple scan ok at small scale; later move to agg)
    total_keys = 0
    active_keys = 0
    auto_disabled = 0
    for s in db.collection(COL_KEYS).get():
        total_keys += 1
        d = s.to_dict() or {}
        if d.get("active", False):
            active_keys += 1
        if d.get("auto_disabled_at_utc"):
            auto_disabled += 1

    g1 = db.collection(COL_GLOBAL_ABUSE_1H).document("global").get()
    g24 = db.collection(COL_GLOBAL_ABUSE_24H).document("global").get()
    g1d = g1.to_dict() if g1.exists else {}
    g24d = g24.to_dict() if g24.exists else {}

    top_1h: List[Dict[str, Any]] = []
    for s in db.collection(COL_ABUSE_1H).order_by("count_total", direction=firestore.Query.DESCENDING).limit(top_n).get():
        d = s.to_dict() or {}
        top_1h.append({"key_id": s.id, "count": _doc_int(d, "count_total")})

    top_24h: List[Dict[str, Any]] = []
    for s in db.collection(COL_ABUSE_24H).order_by("count_total", direction=firestore.Query.DESCENDING).limit(top_n).get():
        d = s.to_dict() or {}
        top_24h.append({"key_id": s.id, "count": _doc_int(d, "count_total")})

    posture = db.collection(COL_SECURITY).document("posture").get()
    pd = posture.to_dict() if posture.exists else {}

    warnings: List[str] = []
    if auto_disabled > 0:
        warnings.append(f"auto_disabled_keys={auto_disabled}")
    if _doc_int(g1d, "count_total") > 0:
        warnings.append(f"global_violations_1h={_doc_int(g1d,'count_total')}")
    if _doc_int(g24d, "count_total") > 0:
        warnings.append(f"global_violations_24h={_doc_int(g24d,'count_total')}")

    return {
        "ok": True,
        "utc": _now().isoformat(),
        "keys": {"total": total_keys, "active": active_keys, "auto_disabled": auto_disabled},
        "rate_limit": {
            "global_last_hour": {
                "total": _doc_int(g1d, "count_total"),
                "window": _doc_int(g1d, "count_window"),
                "daily": _doc_int(g1d, "count_daily"),
            },
            "global_last_24h": {
                "total": _doc_int(g24d, "count_total"),
                "window": _doc_int(g24d, "count_window"),
                "daily": _doc_int(g24d, "count_daily"),
            },
            "top_keys_last_hour": top_1h,
            "top_keys_last_24h": top_24h,
            "top_n": top_n,
        },
        "posture": {
            "auto_disabled_total": _doc_int(pd, "auto_disabled_total"),
            "auto_disabled_last_at_utc": pd.get("auto_disabled_last_at_utc"),
        },
        "warnings": warnings,
    }