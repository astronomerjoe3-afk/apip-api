import os
import time
import secrets as py_secrets
import hashlib
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, List, Callable, Tuple

from fastapi import FastAPI, Depends, Header, HTTPException, Body, Request, Response, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import firebase_admin
from firebase_admin import auth as fb_auth
from firebase_admin import credentials

from google.cloud import firestore

from app.rate_limit import RateLimitDepends
from app.audit import write_audit_event


APP_NAME = "apip-api"
APP_VERSION = "0.1.0"

# -------------------------
# Env
# -------------------------

BOOTSTRAP_ADMIN_UID = os.getenv("BOOTSTRAP_ADMIN_UID", "").strip()
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "").strip()
APP_COMMIT = os.getenv("APP_COMMIT", "(unset)").strip()

API_KEY_CACHE_TTL_SECONDS = int(os.getenv("API_KEY_CACHE_TTL_SECONDS", "10"))

# CORS origins
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
    """Initialize firebase_admin exactly once."""
    if firebase_admin._apps:
        return
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)


def get_firestore() -> Optional[firestore.Client]:
    """
    Returns a Firestore client or None if initialization fails.
    Prefer using explicit project if FIREBASE_PROJECT_ID is set.
    """
    try:
        _ensure_firebase()
        if FIREBASE_PROJECT_ID:
            return firestore.Client(project=FIREBASE_PROJECT_ID)
        return firestore.Client()
    except Exception:
        return None


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
# Request-ID + error-safe middleware + RL header attachment + audit on failures
# -------------------------

REQUEST_ID_HEADER = "X-Request-Id"


def _make_request_id() -> str:
    # URL-safe, short enough for logs/headers
    return py_secrets.token_urlsafe(12)


def _should_audit_failure(path: str, status_code: int) -> bool:
    # Focus on API-key path failures and admin auth failures (optional)
    if status_code in (401, 403, 429):
        # Audit failures primarily for API-key-protected routes
        if path.startswith("/protected"):
            return True
        # Also audit admin key ops failures (optional)
        if path.startswith("/keys") or path.startswith("/admin"):
            return True
    return False


@app.middleware("http")
async def request_id_rl_and_audit_middleware(request: Request, call_next):
    # 1) request id
    rid = request.headers.get(REQUEST_ID_HEADER) or _make_request_id()
    request.state.request_id = rid

    # 2) execute + catch errors so we can always attach headers
    try:
        response: Response = await call_next(request)
    except HTTPException as exc:
        # Preserve any headers FastAPI would have sent (e.g., RateLimitDepends sets headers on 429)
        hdrs = dict(exc.headers or {})
        response = JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=hdrs,
        )
    except Exception:
        response = JSONResponse(status_code=500, content={"detail": "Internal Server Error"})

    # 3) attach RL headers if present on request.state (for 200 responses)
    rl_headers = getattr(request.state, "rate_limit_headers", None)
    if isinstance(rl_headers, dict):
        for k, v in rl_headers.items():
            response.headers[k] = str(v)

    # 4) always attach request id
    response.headers[REQUEST_ID_HEADER] = rid

    # 5) audit failures (best effort)
    status = int(getattr(response, "status_code", 0) or 0)
    if _should_audit_failure(request.url.path, status):
        db = get_firestore()
        if db:
            key_id = getattr(request.state, "api_key_id", None)
            write_audit_event(
                db,
                event_type=(
                    "api_key.rate_limited" if status == 429 else
                    "auth.forbidden" if status == 403 else
                    "auth.unauthorized"
                ),
                request=request,
                status_code=status,
                key_id=key_id,
                request_id=rid,
                extra={"provider": "api_key" if request.url.path.startswith("/protected") else "firebase"},
            )

    return response


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
    role = decoded.get("role") or "user"  # custom claim

    return {
        "uid": uid,
        "email": email,
        "role": role,
        "claims": decoded,
        "provider": decoded.get("firebase", {}).get("sign_in_provider"),
        "aud": decoded.get("aud"),
        "iss": decoded.get("iss"),
    }


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    uid = user.get("uid")
    role = user.get("role")

    # Break-glass bootstrap admin UID
    if BOOTSTRAP_ADMIN_UID and uid == BOOTSTRAP_ADMIN_UID:
        return user

    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# -------------------------
# API Key helpers (Option 2)
# -------------------------

API_KEY_HEADER = "X-API-Key"
API_KEY_PREFIX = "ak_"


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_api_key(api_key: str) -> Optional[Dict[str, str]]:
    """
    Expected format: ak_<key_id>.<secret>
    Returns {"key_id":..., "secret":...} or None
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


def _cache_now() -> float:
    return time.time()


_api_key_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_api_key_cache_lock = threading.Lock()


def _cache_get(key_id: str) -> Optional[Dict[str, Any]]:
    if API_KEY_CACHE_TTL_SECONDS <= 0:
        return None
    now = _cache_now()
    with _api_key_cache_lock:
        item = _api_key_cache.get(key_id)
        if not item:
            return None
        exp, rec = item
        if exp <= now:
            _api_key_cache.pop(key_id, None)
            return None
        return dict(rec)


def _cache_put(key_id: str, rec: Dict[str, Any]) -> None:
    if API_KEY_CACHE_TTL_SECONDS <= 0:
        return
    exp = _cache_now() + float(API_KEY_CACHE_TTL_SECONDS)
    with _api_key_cache_lock:
        _api_key_cache[key_id] = (exp, dict(rec))


def _cache_invalidate(key_id: str) -> None:
    with _api_key_cache_lock:
        _api_key_cache.pop(key_id, None)


def get_api_key_record(db: firestore.Client, key_id: str) -> Optional[Dict[str, Any]]:
    snap = db.collection("api_keys").document(key_id).get()
    if not snap.exists:
        return None
    data = snap.to_dict() or {}
    data["key_id"] = key_id
    return data


def get_api_key_record_cached(db: firestore.Client, key_id: str) -> Optional[Dict[str, Any]]:
    cached = _cache_get(key_id)
    if cached is not None:
        return cached
    rec = get_api_key_record(db, key_id)
    if rec is not None:
        _cache_put(key_id, rec)
    return rec


def require_api_key(required_scopes: Optional[List[str]] = None) -> Callable[..., Dict[str, Any]]:
    """
    Dependency factory. Verifies X-API-Key, checks active, checks secret hash, checks scopes.
    Sets request.state.api_key_id for rate limiting + audit logging.
    Uses TTL cache to reduce Firestore reads per instance.
    """
    def _dep(
        request: Request,
        x_api_key: Optional[str] = Header(default=None, alias=API_KEY_HEADER),
    ) -> Dict[str, Any]:
        if not x_api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key")

        parsed = _parse_api_key(x_api_key)
        if not parsed:
            raise HTTPException(status_code=401, detail="Invalid API key format")

        db = get_firestore()
        if not db:
            raise HTTPException(status_code=503, detail="Firestore not available")

        rec = get_api_key_record_cached(db, parsed["key_id"])
        if not rec:
            raise HTTPException(status_code=401, detail="Invalid API key")

        if not rec.get("active", False):
            _cache_invalidate(parsed["key_id"])
            raise HTTPException(status_code=403, detail="API key revoked")

        expected_hash = rec.get("secret_hash") or ""
        provided_hash = _hash_secret(parsed["secret"])

        if not py_secrets.compare_digest(str(expected_hash), str(provided_hash)):
            raise HTTPException(status_code=401, detail="Invalid API key")

        scopes = rec.get("scopes") or []
        if required_scopes:
            for s in required_scopes:
                if s not in scopes and "admin:*" not in scopes:
                    raise HTTPException(status_code=403, detail=f"Missing scope: {s}")

        request.state.api_key_id = rec.get("key_id")

        return {
            "key_id": rec.get("key_id"),
            "label": rec.get("label"),
            "scopes": scopes,
            "created_at_utc": rec.get("created_at_utc"),
            "created_by_uid": rec.get("created_by_uid"),
            "created_by_email": rec.get("created_by_email"),
            "active": rec.get("active", False),
        }

    return _dep


def _sanitize_key_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "key_id": rec.get("key_id"),
        "label": rec.get("label"),
        "scopes": rec.get("scopes") or [],
        "active": bool(rec.get("active", False)),
        "created_at_utc": rec.get("created_at_utc"),
        "created_by_uid": rec.get("created_by_uid"),
        "created_by_email": rec.get("created_by_email"),
        "revoked_at_utc": rec.get("revoked_at_utc"),
        "revoked_by_uid": rec.get("revoked_by_uid"),
        "rl_window_limit": rec.get("rl_window_limit"),
        "rl_window_seconds": rec.get("rl_window_seconds"),
        "rl_bucket_seconds": rec.get("rl_bucket_seconds"),
        "rl_daily_limit": rec.get("rl_daily_limit"),
    }


# -------------------------
# Models
# -------------------------

class CreateKeyRequest(BaseModel):
    label: Optional[str] = None
    scopes: Optional[List[str]] = None

    rl_window_limit: Optional[int] = Field(default=None, ge=1)
    rl_window_seconds: Optional[int] = Field(default=None, ge=1)
    rl_bucket_seconds: Optional[int] = Field(default=None, ge=1)
    rl_daily_limit: Optional[int] = Field(default=None, ge=0)


class CreateKeyResponse(BaseModel):
    ok: bool
    key_id: str
    api_key: str
    created_at_utc: str


class RevokeKeyResponse(BaseModel):
    ok: bool
    key_id: str
    revoked: bool


class SetRoleReq(BaseModel):
    role: str


class UpdateRateLimitRequest(BaseModel):
    rl_window_limit: Optional[int] = Field(default=None, ge=1)
    rl_window_seconds: Optional[int] = Field(default=None, ge=1)
    rl_bucket_seconds: Optional[int] = Field(default=None, ge=1)
    rl_daily_limit: Optional[int] = Field(default=None, ge=0)


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
        "utc": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/me")
def me(user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "uid": user["uid"],
        "email": user.get("email"),
        "role": user.get("role"),
        "provider": user.get("provider"),
        "aud": user.get("aud"),
        "iss": user.get("iss"),
    }


@app.get("/profile")
def profile(user: Dict[str, Any] = Depends(get_current_user)):
    return {"message": "ok", "uid": user["uid"], "email": user.get("email"), "role": user.get("role")}


# -------------------------
# Admin: user management (with audit)
# -------------------------

@app.post("/admin/users/{uid}/role")
def admin_set_user_role(uid: str, body: SetRoleReq, request: Request, admin: Dict[str, Any] = Depends(require_admin)):
    try:
        _ensure_firebase()
        fb_auth.set_custom_user_claims(uid, {"role": body.role})

        db = get_firestore()
        if db:
            write_audit_event(
                db,
                event_type="admin.role_set",
                request=request,
                status_code=200,
                actor_uid=admin.get("uid"),
                actor_email=admin.get("email"),
                request_id=getattr(request.state, "request_id", None),
                extra={"target_uid": uid, "role": body.role},
            )

        return {"ok": True, "uid": uid, "role": body.role}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "set_role_failed", "message": str(e)})


# -------------------------
# API Keys (with audit)
# -------------------------

@app.post("/keys", response_model=CreateKeyResponse)
def create_api_key(
    req: CreateKeyRequest = Body(default_factory=CreateKeyRequest),
    request: Request = None,  # FastAPI injects
    admin: Dict[str, Any] = Depends(require_admin),
):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

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
        "created_at_utc": _now_utc(),
        "created_by_uid": admin["uid"],
        "created_by_email": admin.get("email"),
        "revoked_at_utc": None,
        "revoked_by_uid": None,
        "rl_window_limit": req.rl_window_limit,
        "rl_window_seconds": req.rl_window_seconds,
        "rl_bucket_seconds": req.rl_bucket_seconds,
        "rl_daily_limit": req.rl_daily_limit,
    }

    try:
        db.collection("api_keys").document(key_id).set(doc)
        _cache_put(key_id, doc)

        write_audit_event(
            db,
            event_type="api_key.created",
            request=request,
            status_code=200,
            actor_uid=admin.get("uid"),
            actor_email=admin.get("email"),
            key_id=key_id,
            request_id=getattr(request.state, "request_id", None),
            extra={"label": req.label, "scopes": req.scopes or []},
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "firestore_write_failed", "message": str(e)})

    return {"ok": True, "key_id": key_id, "api_key": api_key, "created_at_utc": doc["created_at_utc"]}


@app.post("/keys/{key_id}/revoke", response_model=RevokeKeyResponse)
def revoke_api_key(
    key_id: str,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    ref = db.collection("api_keys").document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update({"active": False, "revoked_at_utc": _now_utc(), "revoked_by_uid": admin["uid"]})
    _cache_invalidate(key_id)

    write_audit_event(
        db,
        event_type="api_key.revoked",
        request=request,
        status_code=200,
        actor_uid=admin.get("uid"),
        actor_email=admin.get("email"),
        key_id=key_id,
        request_id=getattr(request.state, "request_id", None),
    )

    return {"ok": True, "key_id": key_id, "revoked": True}


@app.patch("/keys/{key_id}/rate-limit")
def admin_update_key_rate_limit(
    key_id: str,
    body: UpdateRateLimitRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    ref = db.collection("api_keys").document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    updates: Dict[str, Any] = {}
    if body.rl_window_limit is not None:
        updates["rl_window_limit"] = int(body.rl_window_limit)
    if body.rl_window_seconds is not None:
        updates["rl_window_seconds"] = int(body.rl_window_seconds)
    if body.rl_bucket_seconds is not None:
        updates["rl_bucket_seconds"] = int(body.rl_bucket_seconds)
    if body.rl_daily_limit is not None:
        updates["rl_daily_limit"] = int(body.rl_daily_limit)

    if not updates:
        return {"ok": True, "key_id": key_id, "updated": False, "message": "No fields provided"}

    try:
        ref.update(updates)
        _cache_invalidate(key_id)

        write_audit_event(
            db,
            event_type="api_key.rate_limit_policy_updated",
            request=request,
            status_code=200,
            actor_uid=admin.get("uid"),
            actor_email=admin.get("email"),
            key_id=key_id,
            request_id=getattr(request.state, "request_id", None),
            extra=updates,
        )

        return {"ok": True, "key_id": key_id, "updated": True, "rate_limit": updates}

    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "firestore_update_failed", "message": str(e)})


# -------------------------
# Admin: get/list keys (existing)
# -------------------------

@app.get("/keys/{key_id}")
def admin_get_key(key_id: str, _: Dict[str, Any] = Depends(require_admin)):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    rec = get_api_key_record(db, key_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Key not found")

    return {"ok": True, "key": _sanitize_key_record(rec)}


@app.get("/keys")
def admin_list_keys(limit: int = Query(default=50, ge=1, le=200), _: Dict[str, Any] = Depends(require_admin)):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    try:
        q = db.collection("api_keys").order_by("created_at_utc", direction=firestore.Query.DESCENDING).limit(int(limit))
        keys: List[Dict[str, Any]] = []
        for snap in q.stream():
            rec = snap.to_dict() or {}
            rec["key_id"] = snap.id
            keys.append(_sanitize_key_record(rec))
        return {"ok": True, "count": len(keys), "keys": keys}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "list_keys_failed", "message": str(e)})


# -------------------------
# ✅ Admin metrics (new)
# -------------------------

def _count_query_safe(q) -> Optional[int]:
    """
    Best-effort Firestore count aggregation (fast) with fallback to streaming count (slower).
    """
    # Aggregation count() exists in newer firestore client versions.
    try:
        agg = q.count()
        res = agg.get()
        if res and hasattr(res[0], "value"):
            return int(res[0].value)
        # Some versions use .to_dict()
        if res and hasattr(res[0], "to_dict"):
            d = res[0].to_dict()
            # key may vary; try common patterns
            for k in ("count", "value"):
                if k in d:
                    return int(d[k])
    except Exception:
        pass

    # Fallback: stream and count (avoid if large datasets)
    try:
        n = 0
        for _ in q.stream():
            n += 1
        return n
    except Exception:
        return None


@app.get("/admin/metrics")
def admin_metrics(request: Request, admin: Dict[str, Any] = Depends(require_admin)):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    # Key counts
    total_keys = _count_query_safe(db.collection("api_keys"))
    active_keys = _count_query_safe(db.collection("api_keys").where("active", "==", True))

    # Audit counts: 429 (rate limited) last hour / last 24h
    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)
    one_day_ago = now - timedelta(hours=24)

    rate_limited_last_hour: Optional[int] = None
    rate_limited_last_24h: Optional[int] = None
    audit_warn: Optional[str] = None

    try:
        q1 = (
            db.collection("audit_logs")
            .where("event_type", "==", "api_key.rate_limited")
            .where("ts", ">=", one_hour_ago)
        )
        rate_limited_last_hour = _count_query_safe(q1)

        q2 = (
            db.collection("audit_logs")
            .where("event_type", "==", "api_key.rate_limited")
            .where("ts", ">=", one_day_ago)
        )
        rate_limited_last_24h = _count_query_safe(q2)
    except Exception as e:
        # Firestore may require a composite index (event_type + ts). Return metrics anyway.
        audit_warn = f"audit_count_unavailable: {type(e).__name__}: {str(e)}"

    # Audit the metrics access (optional but recommended)
    write_audit_event(
        db,
        event_type="admin.metrics_read",
        request=request,
        status_code=200,
        actor_uid=admin.get("uid"),
        actor_email=admin.get("email"),
        request_id=getattr(request.state, "request_id", None),
        extra={"total_keys": total_keys, "active_keys": active_keys},
    )

    return {
        "ok": True,
        "utc": now.isoformat(),
        "keys": {"total": total_keys, "active": active_keys},
        "rate_limit": {"429_last_hour": rate_limited_last_hour, "429_last_24h": rate_limited_last_24h},
        "warnings": [audit_warn] if audit_warn else [],
    }


# -------------------------
# API-key protected routes (rate limited)
# -------------------------

@app.get("/protected")
def protected(
    api_key: Dict[str, Any] = Depends(require_api_key(required_scopes=["profile:read"])),
    _rl: Any = RateLimitDepends(),
):
    return {
        "ok": True,
        "message": "API key accepted",
        "api_key": {
            "key_id": api_key["key_id"],
            "label": api_key.get("label"),
            "scopes": api_key.get("scopes", []),
            "created_at_utc": api_key.get("created_at_utc"),
            "active": api_key.get("active"),
        },
    }


@app.get("/protected/admin")
def protected_admin(
    api_key: Dict[str, Any] = Depends(require_api_key(required_scopes=["admin:*"])),
    _rl: Any = RateLimitDepends(),
):
    return {
        "ok": True,
        "message": "API key has admin scope",
        "key_id": api_key["key_id"],
        "scopes": api_key.get("scopes", []),
    }