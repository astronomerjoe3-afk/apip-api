import os
import time
import uuid
import hashlib
import secrets as py_secrets
from datetime import datetime, timezone, timedelta
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
    build_rate_limit_headers,
    COL_ABUSE_1H,
    COL_ABUSE_24H,
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


# -------------------------
# CORS
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


def _audit_expires_at(days: int = 30) -> datetime:
    # Firestore TTL expects a timestamp field in a document.
    return _now() + timedelta(days=days)


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


def _parse_api_key(api_key: str) -> Optional[Dict[str, str]]:
    """
    Expected format: ak_<key_id>.<secret>
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


def _get_api_key_record(db: firestore.Client, key_id: str) -> Optional[Dict[str, Any]]:
    snap = db.collection(COL_KEYS).document(key_id).get()
    if not snap.exists:
        return None
    d = snap.to_dict() or {}
    d["key_id"] = key_id
    return d


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
# Middleware: Request ID + latency + audit (NO return in finally)
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

        # Attach request id header if response exists
        if response is not None:
            response.headers["X-Request-Id"] = request_id

        # Attach RL headers (200 and 429) if present
        rl_headers = getattr(request.state, "rate_limit_headers", None)
        if response is not None and isinstance(rl_headers, dict):
            for k, v in rl_headers.items():
                response.headers[k] = str(v)

        # Best-effort audit write
        db: firestore.Client = request.app.state.db
        try:
            db.collection(COL_AUDIT).add(
                {
                    "event_type": "api.request",
                    "ts": _now(),
                    "expires_at_utc": _audit_expires_at(30),
                    "request_id": request_id,
                    "path": request.url.path,
                    "method": request.method,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                    "key_id": getattr(request.state, "api_key_id", None),
                    "user_uid": getattr(request.state, "user_uid", None),
                }
            )
        except Exception:
            pass


# -------------------------
# Models
# -------------------------
class CreateKeyRequest(BaseModel):
    label: Optional[str] = None
    scopes: Optional[List[str]] = None

    # per-key RL policy overrides
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


@app.get("/me")
def me(user: Dict[str, Any] = Depends(get_current_user), request: Request = None):
    if request is not None:
        request.state.user_uid = user.get("uid")
    return {"uid": user["uid"], "email": user.get("email"), "role": user.get("role")}


@app.get("/profile")
def profile(user: Dict[str, Any] = Depends(get_current_user), request: Request = None):
    # backward compatibility
    if request is not None:
        request.state.user_uid = user.get("uid")
    return {"message": "ok", "uid": user["uid"], "email": user.get("email"), "role": user.get("role")}


# -------------------------
# API Key auth dependency (+ Step 2.2 RL)
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

        # secret hash check
        expected_hash = str(rec.get("secret_hash") or "")
        provided_hash = _hash_secret(parsed["secret"])
        if not py_secrets.compare_digest(expected_hash, provided_hash):
            raise HTTPException(status_code=401, detail="Invalid API key")

        # scope check
        scopes = rec.get("scopes") or []
        if required_scopes:
            for s in required_scopes:
                if s not in scopes and "admin:*" not in scopes:
                    raise HTTPException(status_code=403, detail=f"Missing scope: {s}")

        # Make available to middleware/audit
        request.state.api_key_id = rec.get("key_id")

        # Step 2.2 RL enforcement (may raise 429 with headers)
        enforce_rate_limit_or_429(db, request, rec["key_id"], rec)

        # update usage counters (best-effort)
        try:
            db.collection(COL_KEYS).document(rec["key_id"]).update(
                {
                    "last_used_at_utc": _now(),
                    "total_requests": firestore.Increment(1),
                    "updated_at_utc": _now(),
                }
            )
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


# -------------------------
# Protected (API key)
# -------------------------
@app.get("/protected")
def protected(api_key: Dict[str, Any] = Depends(require_api_key(required_scopes=["profile:read"]))):
    return {"ok": True, "key_id": api_key["key_id"], "label": api_key.get("label"), "scopes": api_key.get("scopes", [])}


@app.get("/protected/admin")
def protected_admin(api_key: Dict[str, Any] = Depends(require_api_key(required_scopes=["admin:*"]))):
    return {"ok": True, "key_id": api_key["key_id"], "scopes": api_key.get("scopes", [])}


# -------------------------
# API Keys: admin CRUD
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
        "revoked_at_utc": None,
        "revoked_by_uid": None,
        "auto_disabled_at_utc": None,
        "auto_disabled_reason": None,
        "total_requests": 0,
        "last_used_at_utc": None,
        "updated_at_utc": _now(),
        # RL policy overrides
        "rl_window_limit": req.rl_window_limit,
        "rl_window_seconds": req.rl_window_seconds,
        "rl_bucket_seconds": req.rl_bucket_seconds,
        "rl_daily_limit": req.rl_daily_limit,
    }

    db.collection(COL_KEYS).document(key_id).set(doc)

    return {"ok": True, "key_id": key_id, "api_key": api_key, "created_at_utc": doc["created_at_utc"]}


@app.post("/keys/{key_id}/revoke", response_model=RevokeKeyResponse)
def revoke_key(key_id: str, admin: Dict[str, Any] = Depends(require_admin)):
    db = app.state.db
    ref = db.collection(COL_KEYS).document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update(
        {
            "active": False,
            "revoked_at_utc": _now().isoformat(),
            "revoked_by_uid": admin.get("uid"),
            "updated_at_utc": _now(),
        }
    )
    return {"ok": True, "key_id": key_id, "revoked": True}


@app.get("/keys/{key_id}")
def get_key(key_id: str, admin: Dict[str, Any] = Depends(require_admin)):
    db = app.state.db
    rec = _get_api_key_record(db, key_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Key not found")

    # Never expose secret_hash in response
    rec.pop("secret_hash", None)
    return {"ok": True, "key": rec}


@app.get("/keys")
def list_keys(
    admin: Dict[str, Any] = Depends(require_admin),
    limit: int = Query(default=50, ge=1, le=200),
):
    db = app.state.db
    snaps = db.collection(COL_KEYS).order_by("created_at_utc", direction=firestore.Query.DESCENDING).limit(limit).get()
    keys: List[Dict[str, Any]] = []
    for s in snaps:
        d = s.to_dict() or {}
        d["key_id"] = s.id
        d.pop("secret_hash", None)
        keys.append(d)
    return {"ok": True, "count": len(keys), "keys": keys}


@app.patch("/keys/{key_id}/rate-limit")
def patch_rate_limit(key_id: str, body: PatchRateLimitReq, admin: Dict[str, Any] = Depends(require_admin)):
    db = app.state.db
    ref = db.collection(COL_KEYS).document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    updates = {"updated_at_utc": _now()}
    for f in ["rl_window_limit", "rl_window_seconds", "rl_bucket_seconds", "rl_daily_limit"]:
        v = getattr(body, f)
        if v is not None:
            updates[f] = v

    ref.update(updates)
    return {"ok": True, "key_id": key_id, "updated": True, "rate_limit": updates}


# -------------------------
# Admin metrics (NO audit scan)
# -------------------------
def _read_doc_count_fields(doc: Optional[Dict[str, Any]]) -> Dict[str, int]:
    d = doc or {}
    def gi(k: str) -> int:
        try:
            return int(d.get(k) or 0)
        except Exception:
            return 0
    return {
        "total": gi("count_total"),
        "window": gi("count_window"),
        "daily": gi("count_daily"),
    }


@app.get("/admin/metrics")
def admin_metrics(admin: Dict[str, Any] = Depends(require_admin), top_n: int = Query(default=10, ge=1, le=50)):
    db = app.state.db
    utc = _now().isoformat()

    # Keys count
    snaps = db.collection(COL_KEYS).get()
    total_keys = 0
    active_keys = 0
    auto_disabled_keys = 0
    for s in snaps:
        total_keys += 1
        d = s.to_dict() or {}
        if d.get("active", False):
            active_keys += 1
        if d.get("auto_disabled_at_utc"):
            auto_disabled_keys += 1

    # Top abusive keys: order_by count_total DESC (single-field index is automatic)
    top_1h = []
    try:
        for s in db.collection(COL_ABUSE_1H).order_by("count_total", direction=firestore.Query.DESCENDING).limit(top_n).get():
            d = s.to_dict() or {}
            top_1h.append({"key_id": s.id, "count": int(d.get("count_total") or 0)})
    except Exception:
        top_1h = []

    top_24h = []
    try:
        for s in db.collection(COL_ABUSE_24H).order_by("count_total", direction=firestore.Query.DESCENDING).limit(top_n).get():
            d = s.to_dict() or {}
            top_24h.append({"key_id": s.id, "count": int(d.get("count_total") or 0)})
    except Exception:
        top_24h = []

    # Aggregate totals by scanning top docs only is not accurate; keep simple:
    # Use counts from the top docs and expose as "top_keys".
    # If you need global totals later, we can maintain a global counter doc.
    warnings: List[str] = []

    return {
        "ok": True,
        "utc": utc,
        "keys": {"total": total_keys, "active": active_keys, "auto_disabled": auto_disabled_keys},
        "rate_limit": {
            "top_keys_last_hour": top_1h,
            "top_keys_last_24h": top_24h,
            "top_n": top_n,
        },
        "warnings": warnings,
    }