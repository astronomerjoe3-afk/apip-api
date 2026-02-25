# app/main.py
import os
import time
import uuid
import hashlib
import secrets as py_secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, List, Tuple

from fastapi import FastAPI, Request, Response, Depends, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

import firebase_admin
from firebase_admin import auth as fb_auth
from firebase_admin import credentials as fb_credentials

from google.cloud import firestore
from google.cloud.firestore import Client as FirestoreClient

from app.rate_limit import enforce_rate_limit


# ============================================================
# Config
# ============================================================

APP_NAME = os.getenv("APP_NAME", "apip-api").strip()
APP_VERSION = os.getenv("APP_VERSION", "0.1.0").strip()
APP_COMMIT = os.getenv("APP_COMMIT", "(unset)").strip()

FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "").strip()
BOOTSTRAP_ADMIN_UID = os.getenv("BOOTSTRAP_ADMIN_UID", "").strip()

# Collection names (keep configurable to match your existing data)
API_KEYS_COLLECTION = os.getenv("API_KEYS_COLLECTION", "api_keys").strip()  # set to "keys" if your docs are there
AUDIT_COLLECTION = os.getenv("AUDIT_COLLECTION", "audit_logs").strip()

# Audit TTL (Firestore TTL policy should be configured on this field name)
AUDIT_TTL_DAYS = int(os.getenv("AUDIT_TTL_DAYS", "30"))

# Auto-disable API keys after too many violations (per day by default)
AUTO_DISABLE_ENABLED = os.getenv("AUTO_DISABLE_ENABLED", "true").lower() in ("1", "true", "yes")
AUTO_DISABLE_DAILY_THRESHOLD = int(os.getenv("AUTO_DISABLE_DAILY_THRESHOLD", "100"))  # disable after N violations/day
AUTO_DISABLE_WINDOW_THRESHOLD = int(os.getenv("AUTO_DISABLE_WINDOW_THRESHOLD", "200"))  # disable after N window 429/day

# CORS
_cors_env = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
if _cors_env:
    CORS_ALLOW_ORIGINS = [o.strip() for o in _cors_env.split(",") if o.strip()]
else:
    CORS_ALLOW_ORIGINS = ["http://localhost:3000", "https://cognispark.tech", "https://www.cognispark.tech"]

# RateLimit headers
API_KEY_HEADER = "X-API-Key"
API_KEY_PREFIX = "ak_"


# ============================================================
# App + clients
# ============================================================

app = FastAPI(title=APP_NAME, version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Firestore client (ADC works on Cloud Run)
_db: Optional[FirestoreClient] = None


def _ensure_firestore() -> FirestoreClient:
    global _db
    if _db is None:
        if FIREBASE_PROJECT_ID:
            _db = firestore.Client(project=FIREBASE_PROJECT_ID)
        else:
            _db = firestore.Client()
    return _db


def _ensure_firebase() -> None:
    """Initialize firebase_admin exactly once using ADC."""
    if firebase_admin._apps:
        return
    # ApplicationDefault works on Cloud Run / locally if gcloud auth set
    cred = fb_credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)


# ============================================================
# Helpers
# ============================================================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def ttl_utc(days: int = AUDIT_TTL_DAYS) -> datetime:
    return now_utc() + timedelta(days=days)


def _extract_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None
    if parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _parse_api_key(raw: str) -> Optional[Tuple[str, str]]:
    """
    Expected format: ak_<key_id>.<secret>
    Returns (key_id, secret) or None
    """
    if not raw:
        return None
    raw = raw.strip()
    if not raw.startswith(API_KEY_PREFIX):
        return None
    rest = raw[len(API_KEY_PREFIX):]
    if "." not in rest:
        return None
    key_id, secret = rest.split(".", 1)
    key_id = key_id.strip()
    secret = secret.strip()
    if not key_id or not secret:
        return None
    return (key_id, secret)


def _build_rl_headers(policy: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, str]:
    # meta is produced by enforce_rate_limit; we standardize expected keys here
    # (missing keys become empty strings to avoid PS header issues)
    def s(x: Any) -> str:
        return "" if x is None else str(x)

    return {
        "X-RateLimit-Limit": s(policy.get("rl_window_limit")),
        "X-RateLimit-Remaining": s(meta.get("window_remaining")),
        "X-RateLimit-Reset": s(meta.get("window_reset_epoch")),
        "X-RateLimit-Daily-Limit": s(policy.get("rl_daily_limit")),
        "X-RateLimit-Daily-Remaining": s(meta.get("daily_remaining")),
        "X-RateLimit-Daily-Reset": s(meta.get("daily_reset_epoch")),
        "Retry-After": s(meta.get("retry_after", 0)),
    }


def _audit_log(event: Dict[str, Any]) -> None:
    """
    Best-effort audit writer. Never blocks a response if Firestore is unavailable.
    """
    try:
        db = _ensure_firestore()
        base = {
            "ts": now_utc(),
            "expires_at_utc": ttl_utc(),
            "commit": APP_COMMIT,
            "service": APP_NAME,
        }
        base.update(event)
        db.collection(AUDIT_COLLECTION).add(base)
    except Exception:
        # Intentionally swallow to keep request path resilient.
        pass


def _build_payload() -> Dict[str, Any]:
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "app_commit": APP_COMMIT,
        "firebase_project_id": FIREBASE_PROJECT_ID or "(unset)",
        "utc": now_utc().isoformat(),
    }


# ============================================================
# Middleware: Request-Id + latency + attach RL headers to ALL responses
# ============================================================

@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = uuid.uuid4().hex[:16]
    request.state.request_id = request_id
    start = time.time()

    response: Optional[Response] = None
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration_ms = int((time.time() - start) * 1000)

        # Attach request id to response if possible
        try:
            if response is not None:
                response.headers["X-Request-Id"] = request_id
        except Exception:
            pass

        # Attach rate limit headers (success OR failure paths that set state)
        try:
            rl_headers = getattr(request.state, "rate_limit_headers", None)
            if response is not None and isinstance(rl_headers, dict):
                for k, v in rl_headers.items():
                    response.headers[k] = str(v)
        except Exception:
            pass

        # Latency + basic request audit (best-effort)
        _audit_log({
            "event_type": "api.request",
            "path": request.url.path,
            "method": request.method,
            "status_code": status_code,
            "duration_ms": duration_ms,
            "request_id": request_id,
            "api_key_id": getattr(request.state, "api_key_id", None),
            "user_uid": getattr(request.state, "user_uid", None),
        })


# ============================================================
# Auth: Admin via Firebase ID token / RBAC
# ============================================================

def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    token = _extract_bearer(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    try:
        _ensure_firebase()
        decoded = fb_auth.verify_id_token(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail={"error": "invalid_id_token", "message": str(e)})

    uid = decoded.get("uid") or decoded.get("sub")
    if uid:
        # make available for middleware audit
        # (FastAPI dependency has no Request unless injected; we set in require_admin below)
        pass

    return decoded


def require_admin(request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    uid = user.get("uid") or user.get("sub")
    role = user.get("role")

    request.state.user_uid = uid

    if BOOTSTRAP_ADMIN_UID and uid == BOOTSTRAP_ADMIN_UID:
        return user
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# ============================================================
# API Key auth + RL + counters + auto-disable
# ============================================================

def _get_key_doc(db: FirestoreClient, key_id: str) -> Optional[Dict[str, Any]]:
    snap = db.collection(API_KEYS_COLLECTION).document(key_id).get()
    if not snap.exists:
        return None
    data = snap.to_dict() or {}
    data["key_id"] = key_id
    return data


def _update_key_counters(
    db: FirestoreClient,
    key_id: str,
    *,
    ok: bool,
    violation_type: Optional[str] = None,  # "window" | "daily" | "revoked" | "invalid" ...
) -> None:
    """
    Per-key counters (monotonic) + last_used tracking.
    - total_requests increments on every authenticated request attempt (ok or 429).
    - total_ok increments on successful protected responses.
    - violation counters increment on 429.
    """
    updates: Dict[str, Any] = {
        "last_used_at_utc": now_utc(),
        "total_requests": firestore.Increment(1),
    }

    if ok:
        updates["total_ok"] = firestore.Increment(1)

    if violation_type == "window":
        updates["violations_window_total"] = firestore.Increment(1)
        updates["violations_window_today"] = firestore.Increment(1)
        updates["violations_last_at_utc"] = now_utc()
    elif violation_type == "daily":
        updates["violations_daily_total"] = firestore.Increment(1)
        updates["violations_daily_today"] = firestore.Increment(1)
        updates["violations_last_at_utc"] = now_utc()

    db.collection(API_KEYS_COLLECTION).document(key_id).update(updates)


def _maybe_auto_disable(
    db: FirestoreClient,
    key_doc: Dict[str, Any],
    violation_type: str,
) -> None:
    """
    Auto-disable based on today's violation counters. This assumes you have a daily reset job
    OR you store day-bound counters as part of rate_limit.py TTL counters.
    This implementation uses the fields in the key doc itself (best-effort).
    """
    if not AUTO_DISABLE_ENABLED:
        return

    key_id = key_doc["key_id"]

    # read fresh to avoid stale doc fields
    fresh = _get_key_doc(db, key_id) or key_doc

    w_today = int(fresh.get("violations_window_today") or 0)
    d_today = int(fresh.get("violations_daily_today") or 0)

    disable = False
    reason = None

    if violation_type == "window" and w_today >= AUTO_DISABLE_WINDOW_THRESHOLD:
        disable = True
        reason = f"auto_disabled_window_threshold_{AUTO_DISABLE_WINDOW_THRESHOLD}"
    if violation_type == "daily" and d_today >= AUTO_DISABLE_DAILY_THRESHOLD:
        disable = True
        reason = f"auto_disabled_daily_threshold_{AUTO_DISABLE_DAILY_THRESHOLD}"

    if not disable:
        return

    db.collection(API_KEYS_COLLECTION).document(key_id).update({
        "active": False,
        "revoked_at_utc": now_utc(),
        "revoked_reason": reason,
    })

    _audit_log({
        "event_type": "api_key.auto_disabled",
        "key_id": key_id,
        "reason": reason,
    })


def require_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias=API_KEY_HEADER),
) -> Dict[str, Any]:
    """
    - Validates API key (format, active, secret hash if present).
    - Enforces rate limit via app.rate_limit.enforce_rate_limit(key_id, policy).
    - Writes audit events: accepted, rate_limited.window, rate_limited.daily
    - Updates per-key counters and optional auto-disable.
    - Sets request.state.rate_limit_headers so middleware attaches them to ALL responses.
    """
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key")

    parsed = _parse_api_key(x_api_key)
    if not parsed:
        raise HTTPException(status_code=401, detail="Invalid API key format")

    key_id, secret = parsed
    request.state.api_key_id = key_id  # for audit middleware

    db = _ensure_firestore()
    key_doc = _get_key_doc(db, key_id)
    if not key_doc:
        _audit_log({"event_type": "api_key.invalid", "key_id": key_id})
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not bool(key_doc.get("active", False)):
        _audit_log({"event_type": "api_key.revoked", "key_id": key_id})
        raise HTTPException(status_code=403, detail="API key revoked")

    # Optional secret validation if your docs store secret_hash
    expected_hash = (key_doc.get("secret_hash") or "").strip()
    if expected_hash:
        provided_hash = _hash_secret(secret)
        if not py_secrets.compare_digest(str(expected_hash), str(provided_hash)):
            _audit_log({"event_type": "api_key.invalid", "key_id": key_id})
            raise HTTPException(status_code=401, detail="Invalid API key")

    # Policy: allow per-key overrides, with sane defaults
    policy: Dict[str, Any] = {
        "rl_window_limit": int(key_doc.get("rl_window_limit") or 10),
        "rl_window_seconds": int(key_doc.get("rl_window_seconds") or 60),
        "rl_bucket_seconds": int(key_doc.get("rl_bucket_seconds") or 10),
        "rl_daily_limit": int(key_doc.get("rl_daily_limit") or 1000),
        # TTL support for RL counters can be implemented inside rate_limit.py.
        "rl_ttl_days": int(key_doc.get("rl_ttl_days") or 2),
    }

    allowed, meta = enforce_rate_limit(key_id, policy)

    # Always attach RL headers for observability (even on 429)
    rl_headers = _build_rl_headers(policy, meta)
    request.state.rate_limit_headers = rl_headers

    if not allowed:
        vtype = str(meta.get("violation_type") or "window")  # "window" or "daily"
        event_type = f"api_key.rate_limited.{vtype}"

        _audit_log({
            "event_type": event_type,
            "key_id": key_id,
            "path": request.url.path,
            "method": request.method,
            "request_id": getattr(request.state, "request_id", None),
            "meta": {
                "retry_after": meta.get("retry_after"),
                "window_remaining": meta.get("window_remaining"),
                "daily_remaining": meta.get("daily_remaining"),
                "window_reset_epoch": meta.get("window_reset_epoch"),
                "daily_reset_epoch": meta.get("daily_reset_epoch"),
            },
        })

        # Per-key counters
        try:
            _update_key_counters(db, key_id, ok=False, violation_type=vtype)
        except Exception:
            pass

        # Auto-disable if threshold hit
        try:
            _maybe_auto_disable(db, {"key_id": key_id}, vtype)
        except Exception:
            pass

        # Raise 429 with headers
        raise HTTPException(status_code=429, detail="Rate limited", headers=rl_headers)

    # success path counters + accepted audit
    try:
        _update_key_counters(db, key_id, ok=True)
    except Exception:
        pass

    _audit_log({
        "event_type": "api_key.accepted",
        "key_id": key_id,
        "path": request.url.path,
        "method": request.method,
        "request_id": getattr(request.state, "request_id", None),
    })

    return {
        "key_id": key_id,
        "label": key_doc.get("label"),
        "scopes": key_doc.get("scopes") or [],
        "active": bool(key_doc.get("active", False)),
        "created_at_utc": key_doc.get("created_at_utc"),
        "rate_limit": policy,
    }


# ============================================================
# Core routes
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "firebase_project_id": FIREBASE_PROJECT_ID or "(unset)",
        "commit": APP_COMMIT,
    }


@app.get("/__build")
def build_marker():
    return _build_payload()


# Backward-compat for any CI smoke test using /_build
@app.get("/_build")
def build_marker_compat():
    return _build_payload()


@app.get("/protected")
def protected(_key: Dict[str, Any] = Depends(require_api_key)):
    # RL headers are attached by middleware via request.state.rate_limit_headers
    return {"ok": True, "message": "API key accepted"}


# ============================================================
# Admin metrics (expanded + index-safe scanning)
# ============================================================

@app.get("/admin/metrics")
def admin_metrics(
    request: Request,
    _admin: Dict[str, Any] = Depends(require_admin),
    scan_limit: int = Query(default=2000, ge=100, le=20000),
    top_n: int = Query(default=10, ge=1, le=50),
):
    """
    Index-safe metrics strategy:
    - Query the most recent N audit logs ordered by ts desc (single-field index).
    - Filter + aggregate in memory for 1h/24h windows.
    This avoids composite-index requirements.
    """
    db = _ensure_firestore()
    cutoff_1h = now_utc() - timedelta(hours=1)
    cutoff_24h = now_utc() - timedelta(hours=24)

    # aggregates
    counts_1h = {"window": 0, "daily": 0}
    counts_24h = {"window": 0, "daily": 0}
    top_1h: Dict[str, int] = {}
    top_24h: Dict[str, int] = {}
    warnings: List[str] = []

    # optional environment health warnings
    if not FIREBASE_PROJECT_ID:
        warnings.append("env:FIREBASE_PROJECT_ID is unset (Firestore client uses default project).")
    if not BOOTSTRAP_ADMIN_UID:
        warnings.append("env:BOOTSTRAP_ADMIN_UID is unset (only role=admin claims grant admin).")

    try:
        query = (
            db.collection(AUDIT_COLLECTION)
            .order_by("ts", direction=firestore.Query.DESCENDING)
            .limit(scan_limit)
        )

        for snap in query.stream():
            d = snap.to_dict() or {}
            ts = d.get("ts")
            if not isinstance(ts, datetime):
                continue

            event_type = str(d.get("event_type") or "")
            key_id = d.get("key_id") or d.get("api_key_id")

            # 429 event types
            if event_type == "api_key.rate_limited.window":
                if ts >= cutoff_1h:
                    counts_1h["window"] += 1
                    if key_id:
                        top_1h[str(key_id)] = top_1h.get(str(key_id), 0) + 1
                if ts >= cutoff_24h:
                    counts_24h["window"] += 1
                    if key_id:
                        top_24h[str(key_id)] = top_24h.get(str(key_id), 0) + 1

            elif event_type == "api_key.rate_limited.daily":
                if ts >= cutoff_1h:
                    counts_1h["daily"] += 1
                    if key_id:
                        top_1h[str(key_id)] = top_1h.get(str(key_id), 0) + 1
                if ts >= cutoff_24h:
                    counts_24h["daily"] += 1
                    if key_id:
                        top_24h[str(key_id)] = top_24h.get(str(key_id), 0) + 1

    except Exception as e:
        warnings.append(f"audit_scan_failed:{type(e).__name__}:{str(e)}")

    def _top_list(m: Dict[str, int]) -> List[Dict[str, Any]]:
        items = sorted(m.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
        return [{"key_id": k, "count": v} for k, v in items]

    # Basic keys stats (counts)
    keys_total = None
    keys_active = None
    try:
        # note: .stream() + len can be expensive; you can replace with count aggregation later
        # (this is fine for small collections)
        all_keys = list(db.collection(API_KEYS_COLLECTION).stream())
        keys_total = len(all_keys)
        keys_active = sum(1 for s in all_keys if bool((s.to_dict() or {}).get("active", False)))
    except Exception as e:
        warnings.append(f"keys_count_failed:{type(e).__name__}:{str(e)}")

    return {
        "ok": True,
        "utc": now_utc().isoformat(),
        "keys": {
            "collection": API_KEYS_COLLECTION,
            "total": keys_total,
            "active": keys_active,
        },
        "rate_limit": {
            "window_429_last_hour": counts_1h["window"],
            "daily_429_last_hour": counts_1h["daily"],
            "window_429_last_24h": counts_24h["window"],
            "daily_429_last_24h": counts_24h["daily"],
            "top_keys_last_hour": _top_list(top_1h),
            "top_keys_last_24h": _top_list(top_24h),
            "scan_limit": scan_limit,
            "top_n": top_n,
        },
        "warnings": warnings,
    }