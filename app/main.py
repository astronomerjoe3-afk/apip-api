from __future__ import annotations

import hashlib
import os
import secrets as py_secrets
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import firebase_admin
from firebase_admin import auth as fb_auth
from firebase_admin import credentials

from google.cloud import firestore

from app.rate_limit import RateLimitDepends, build_rate_limit_headers


# =========================
# Config
# =========================

APP_NAME = "apip-api"
APP_VERSION = "0.1.0"

FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "").strip()
BOOTSTRAP_ADMIN_UID = os.getenv("BOOTSTRAP_ADMIN_UID", "").strip()
APP_COMMIT = os.getenv("APP_COMMIT", os.getenv("K_REVISION", "(unset)")).strip()

# TTLs (days) for audit logs (observability)
AUDIT_LOG_TTL_DAYS = int(os.getenv("AUDIT_LOG_TTL_DAYS", "30"))

# Auto-disable (optional; step 2+ feature) - safe defaults off
AUTO_DISABLE_ENABLED = os.getenv("AUTO_DISABLE_ENABLED", "0").strip() == "1"
AUTO_DISABLE_429_WINDOW_THRESHOLD = int(os.getenv("AUTO_DISABLE_429_WINDOW_THRESHOLD", "0"))  # 0 = disabled
AUTO_DISABLE_429_DAILY_THRESHOLD = int(os.getenv("AUTO_DISABLE_429_DAILY_THRESHOLD", "0"))    # 0 = disabled

API_KEY_HEADER = "X-API-Key"
API_KEY_PREFIX = "ak_"

# Canonical collections (standardize here)
COL_KEYS = "api_keys"
COL_AUDIT = "audit_logs"

# CORS
_CORS_ORIGINS_ENV = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
if _CORS_ORIGINS_ENV:
    CORS_ALLOW_ORIGINS = [o.strip() for o in _CORS_ORIGINS_ENV.split(",") if o.strip()]
else:
    CORS_ALLOW_ORIGINS = [
        "http://localhost:3000",
        "https://cognispark.tech",
        "https://www.cognispark.tech",
    ]


# =========================
# Firebase init
# =========================

def _ensure_firebase() -> None:
    if firebase_admin._apps:
        return
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _audit_expires_at() -> datetime:
    return _now() + timedelta(days=AUDIT_LOG_TTL_DAYS)


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _extract_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None
    if parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


# =========================
# App
# =========================

app = FastAPI(title=APP_NAME, version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Firestore client in app state
try:
    _ensure_firebase()
    app.state.db = firestore.Client(project=FIREBASE_PROJECT_ID) if FIREBASE_PROJECT_ID else firestore.Client()
except Exception:
    app.state.db = None


# =========================
# Middleware: Request-ID + latency + audit log
# =========================

@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = uuid.uuid4().hex[:16]
    request.state.request_id = request_id

    start = time.perf_counter()
    response: Optional[Response] = None
    status_code = 500

    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration_ms = int((time.perf_counter() - start) * 1000)

        # always attach request id if we have a response
        if response is not None:
            response.headers["X-Request-Id"] = request_id

        # attach RL headers captured by RateLimitDepends (even on 429 via exception handler below)
        # (normal path sets request.state.rate_limit_headers and we attach in the next middleware)
        # but this finally block runs after call_next; keep only audit logging here.

        db: Optional[firestore.Client] = getattr(request.app.state, "db", None)
        if db is None:
            return

        # Safe audit log - never log secrets/tokens
        key_id = getattr(request.state, "api_key_id", None)
        user_uid = getattr(request.state, "user_uid", None)

        try:
            db.collection(COL_AUDIT).add({
                "event_type": "api.request",
                "ts": _now(),
                "expires_at_utc": _audit_expires_at(),
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "key_id": key_id,
                "user_uid": user_uid,
            })
        except Exception:
            # best-effort; never break request path
            pass


# =========================
# Middleware: attach RL headers to all responses
# =========================

@app.middleware("http")
async def attach_rate_limit_headers(request: Request, call_next):
    try:
        response: Response = await call_next(request)
    except HTTPException as e:
        # If RateLimitDepends raised 429, we want headers on the 429 too.
        # We'll construct JSONResponse and attach headers if present.
        if e.status_code == 429:
            headers = getattr(request.state, "rate_limit_headers", None)
            r = JSONResponse(status_code=429, content={"detail": e.detail})
            if isinstance(headers, dict):
                for k, v in headers.items():
                    r.headers[k] = str(v)
            # always include request id
            rid = getattr(request.state, "request_id", None)
            if rid:
                r.headers["X-Request-Id"] = rid
            return r
        raise

    headers = getattr(request.state, "rate_limit_headers", None)
    if isinstance(headers, dict):
        for k, v in headers.items():
            response.headers[k] = str(v)

    # request id already set in request_context middleware, but keep defensive
    rid = getattr(request.state, "request_id", None)
    if rid:
        response.headers.setdefault("X-Request-Id", rid)

    return response


# =========================
# Auth (Firebase)
# =========================

def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    token = _extract_bearer(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    try:
        _ensure_firebase()
        decoded = fb_auth.verify_id_token(token)
        uid = decoded.get("uid") or decoded.get("sub")
        role = decoded.get("role") or "user"
        return {"uid": uid, "role": role, "email": decoded.get("email"), "claims": decoded}
    except Exception as e:
        raise HTTPException(status_code=401, detail={"error": "invalid_id_token", "message": str(e)})


def require_admin(request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    request.state.user_uid = user.get("uid")
    uid = user.get("uid")
    role = user.get("role")

    if BOOTSTRAP_ADMIN_UID and uid == BOOTSTRAP_ADMIN_UID:
        return user
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# =========================
# API Key helpers
# =========================

def _parse_api_key(api_key: str) -> Optional[Dict[str, str]]:
    """
    Expected: ak_<key_id>.<secret>
    """
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


def _get_db(request: Optional[Request] = None) -> firestore.Client:
    db: Optional[firestore.Client] = app.state.db
    if request is not None:
        db = getattr(request.app.state, "db", None)
    if db is None:
        raise HTTPException(status_code=503, detail="Firestore not available")
    return db


def _get_key_doc(db: firestore.Client, key_id: str) -> Optional[Dict[str, Any]]:
    snap = db.collection(COL_KEYS).document(key_id).get()
    if not snap.exists:
        return None
    d = snap.to_dict() or {}
    d["key_id"] = key_id
    return d


def require_api_key(required_scopes: Optional[List[str]] = None):
    """
    Validates X-API-Key, loads key policy into request.state.key_policy,
    sets request.state.api_key_id (for RL and audit), and returns key record.
    """
    def _dep(request: Request, x_api_key: Optional[str] = Header(default=None, alias=API_KEY_HEADER)) -> Dict[str, Any]:
        if not x_api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key")

        parsed = _parse_api_key(x_api_key)
        if not parsed:
            raise HTTPException(status_code=401, detail="Invalid API key format")

        db = _get_db(request)
        rec = _get_key_doc(db, parsed["key_id"])
        if not rec:
            raise HTTPException(status_code=401, detail="Invalid API key")

        if not rec.get("active", False):
            raise HTTPException(status_code=403, detail="API key revoked")

        expected_hash = str(rec.get("secret_hash") or "")
        provided_hash = _hash_secret(parsed["secret"])
        if not py_secrets.compare_digest(expected_hash, provided_hash):
            raise HTTPException(status_code=401, detail="Invalid API key")

        scopes = rec.get("scopes") or []
        if required_scopes:
            for s in required_scopes:
                if s not in scopes and "admin:*" not in scopes:
                    raise HTTPException(status_code=403, detail=f"Missing scope: {s}")

        # attach to request for RL + audit
        request.state.api_key_id = rec.get("key_id")
        request.state.key_policy = rec

        # usage counters (lightweight)
        try:
            db.collection(COL_KEYS).document(rec["key_id"]).update({
                "last_used_at_utc": _now(),
                "total_requests": firestore.Increment(1),
            })
        except Exception:
            pass

        return {
            "key_id": rec.get("key_id"),
            "label": rec.get("label"),
            "scopes": scopes,
            "active": rec.get("active", False),
            "created_at_utc": rec.get("created_at_utc"),
        }

    return _dep


# =========================
# Models
# =========================

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


class PatchRateLimitRequest(BaseModel):
    rl_window_limit: Optional[int] = None
    rl_window_seconds: Optional[int] = None
    rl_bucket_seconds: Optional[int] = None
    rl_daily_limit: Optional[int] = None


# =========================
# Build/health endpoints (smoke tests)
# =========================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "firebase_project_id": FIREBASE_PROJECT_ID or "(unset)",
        "commit": APP_COMMIT,
    }


@app.get("/__build")
@app.get("/_build")
def build_marker():
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "app_commit": APP_COMMIT,
        "firebase_project_id": FIREBASE_PROJECT_ID or "(unset)",
        "utc": _now().isoformat(),
    }


# =========================
# API Keys (admin)
# =========================

@app.post("/keys", response_model=CreateKeyResponse)
def create_key(
    req: CreateKeyRequest = Body(default_factory=CreateKeyRequest),
    admin: Dict[str, Any] = Depends(require_admin),
):
    db = _get_db()
    key_id = py_secrets.token_urlsafe(12).replace("-", "").replace("_", "")
    secret = py_secrets.token_urlsafe(32)
    api_key = f"{API_KEY_PREFIX}{key_id}.{secret}"

    doc = {
        "key_id": key_id,
        "secret_hash": _hash_secret(secret),
        "active": True,
        "label": req.label,
        "scopes": req.scopes or [],
        "created_at_utc": _now().isoformat(),
        "created_by_uid": admin.get("uid"),
        "created_by_email": admin.get("email"),
        "revoked_at_utc": None,
        "revoked_reason": None,
        # RL policy
        "rl_window_limit": req.rl_window_limit,
        "rl_window_seconds": req.rl_window_seconds,
        "rl_bucket_seconds": req.rl_bucket_seconds,
        "rl_daily_limit": req.rl_daily_limit,
        # usage
        "last_used_at_utc": None,
        "total_requests": 0,
        # violation counters (for later hardening steps)
        "violations_window_429": 0,
        "violations_daily_429": 0,
        "auto_disabled_at_utc": None,
    }

    db.collection(COL_KEYS).document(key_id).set(doc)

    # audit (best effort)
    try:
        db.collection(COL_AUDIT).add({
            "event_type": "api_key.created",
            "ts": _now(),
            "expires_at_utc": _audit_expires_at(),
            "key_id": key_id,
            "admin_uid": admin.get("uid"),
        })
    except Exception:
        pass

    return {
        "ok": True,
        "key_id": key_id,
        "api_key": api_key,
        "created_at_utc": doc["created_at_utc"],
    }


@app.get("/keys")
def list_keys(
    limit: int = 50,
    admin: Dict[str, Any] = Depends(require_admin),
):
    db = _get_db()
    limit = max(1, min(200, int(limit)))

    snaps = db.collection(COL_KEYS).order_by("created_at_utc", direction=firestore.Query.DESCENDING).limit(limit).stream()
    keys = []
    for s in snaps:
        d = s.to_dict() or {}
        d.pop("secret_hash", None)
        keys.append(d)

    return {"ok": True, "count": len(keys), "keys": keys}


@app.get("/keys/{key_id}")
def get_key(
    key_id: str,
    admin: Dict[str, Any] = Depends(require_admin),
):
    db = _get_db()
    rec = _get_key_doc(db, key_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Key not found")
    rec.pop("secret_hash", None)
    return {"ok": True, "key": rec}


@app.patch("/keys/{key_id}/rate-limit")
def patch_key_rate_limit(
    key_id: str,
    patch: PatchRateLimitRequest,
    admin: Dict[str, Any] = Depends(require_admin),
):
    db = _get_db()
    ref = db.collection(COL_KEYS).document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    updates: Dict[str, Any] = {}
    for f in ["rl_window_limit", "rl_window_seconds", "rl_bucket_seconds", "rl_daily_limit"]:
        v = getattr(patch, f, None)
        if v is not None:
            updates[f] = int(v)

    if not updates:
        return {"ok": True, "key_id": key_id, "updated": False, "rate_limit": {}}

    ref.update(updates)

    try:
        db.collection(COL_AUDIT).add({
            "event_type": "api_key.rate_limit.updated",
            "ts": _now(),
            "expires_at_utc": _audit_expires_at(),
            "key_id": key_id,
            "admin_uid": admin.get("uid"),
            "updates": updates,
        })
    except Exception:
        pass

    return {"ok": True, "key_id": key_id, "updated": True, "rate_limit": updates}


@app.post("/keys/{key_id}/revoke")
def revoke_key(
    key_id: str,
    admin: Dict[str, Any] = Depends(require_admin),
):
    db = _get_db()
    ref = db.collection(COL_KEYS).document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update({
        "active": False,
        "revoked_at_utc": _now().isoformat(),
        "revoked_reason": "revoked_by_admin",
    })

    try:
        db.collection(COL_AUDIT).add({
            "event_type": "api_key.revoked",
            "ts": _now(),
            "expires_at_utc": _audit_expires_at(),
            "key_id": key_id,
            "admin_uid": admin.get("uid"),
        })
    except Exception:
        pass

    return {"ok": True, "key_id": key_id, "revoked": True}


# =========================
# Protected routes (API key + rate-limited)
# =========================

@app.get("/protected")
def protected(
    request: Request,
    api_key: Dict[str, Any] = Depends(require_api_key(required_scopes=["profile:read"])),
    _rl: Any = Depends(RateLimitDepends()),
):
    # RateLimitDepends already attached headers to request.state.rate_limit_headers,
    # and middleware will apply them to the response.
    return {"ok": True, "message": "API key accepted", "key_id": api_key["key_id"]}


# =========================
# Admin metrics (observability)
# =========================

def _scan_audit_for_429(
    db: firestore.Client,
    *,
    since: datetime,
    scan_limit: int,
    top_n: int,
) -> Dict[str, Any]:
    """
    Scan recent audit_logs for rate-limit events (bounded by scan_limit).
    Works without composite indexes because it orders by ts and filters in-memory.
    """
    snaps = (
        db.collection(COL_AUDIT)
          .order_by("ts", direction=firestore.Query.DESCENDING)
          .limit(scan_limit)
          .stream()
    )

    total_429 = 0
    per_key: Dict[str, int] = {}

    # We count both:
    # - api_key.rate_limited.window
    # - api_key.rate_limited.daily
    for s in snaps:
        d = s.to_dict() or {}
        ts = d.get("ts")
        if not isinstance(ts, datetime):
            continue
        if ts < since:
            # because ordered DESC, we can break once older than 'since'
            break

        et = d.get("event_type")
        if et not in ("api_key.rate_limited.window", "api_key.rate_limited.daily"):
            continue

        total_429 += 1
        kid = d.get("key_id") or "(unknown)"
        per_key[kid] = per_key.get(kid, 0) + 1

    top = sorted(per_key.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    return {
        "count": total_429,
        "top_keys": [{"key_id": k, "count": c} for (k, c) in top],
    }


@app.get("/admin/metrics")
def admin_metrics(admin: Dict[str, Any] = Depends(require_admin)):
    db = _get_db()

    # key counts
    # (simple scan limited; for big scale you’d use Firestore count aggregation + indexes)
    keys_snaps = db.collection(COL_KEYS).limit(2000).stream()
    total = 0
    active = 0
    for s in keys_snaps:
        total += 1
        d = s.to_dict() or {}
        if d.get("active", False):
            active += 1

    scan_limit = 2000
    top_n = 10
    one_hour = _now() - timedelta(hours=1)
    one_day = _now() - timedelta(hours=24)

    rl_1h = _scan_audit_for_429(db, since=one_hour, scan_limit=scan_limit, top_n=top_n)
    rl_24h = _scan_audit_for_429(db, since=one_day, scan_limit=scan_limit, top_n=top_n)

    warnings: List[str] = []

    # Optional: warn if many 429s and auto-disable is off
    if (rl_1h["count"] or 0) >= 50 and not AUTO_DISABLE_ENABLED:
        warnings.append("High 429 volume last hour; consider enabling AUTO_DISABLE_ENABLED=1")

    return {
        "ok": True,
        "utc": _now().isoformat(),
        "keys": {"total": total, "active": active},
        "rate_limit": {
            "429_last_hour": rl_1h["count"],
            "429_last_24h": rl_24h["count"],
            "top_keys_last_hour": rl_1h["top_keys"],
            "top_keys_last_24h": rl_24h["top_keys"],
            "scan_limit": scan_limit,
            "top_n": top_n,
        },
        "warnings": warnings,
    }