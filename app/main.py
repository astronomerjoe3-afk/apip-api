import os
import secrets as py_secrets
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Callable

from fastapi import FastAPI, Depends, Header, HTTPException, Body, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import firebase_admin
from firebase_admin import auth as fb_auth
from firebase_admin import credentials

from google.cloud import firestore

from app.rate_limit import RateLimitDepends


APP_NAME = "apip-api"
APP_VERSION = "0.1.0"

# -------------------------
# Env
# -------------------------

BOOTSTRAP_ADMIN_UID = os.getenv("BOOTSTRAP_ADMIN_UID", "").strip()
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "").strip()
APP_COMMIT = os.getenv("APP_COMMIT", "(unset)").strip()

# CORS origins: comma-separated. Falls back to common dev/prod.
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
# App (✅ DEFINE FIRST)
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
# ✅ Middleware: attach RL headers to ALL responses (200 + 429)
# -------------------------

@app.middleware("http")
async def attach_rate_limit_headers(request: Request, call_next):
    response: Response = await call_next(request)
    rl_headers = getattr(request.state, "rate_limit_headers", None)
    if isinstance(rl_headers, dict):
        for k, v in rl_headers.items():
            response.headers[k] = str(v)
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


def get_api_key_record(db: firestore.Client, key_id: str) -> Optional[Dict[str, Any]]:
    snap = db.collection("api_keys").document(key_id).get()
    if not snap.exists:
        return None
    data = snap.to_dict() or {}
    data["key_id"] = key_id
    return data


def require_api_key(required_scopes: Optional[List[str]] = None) -> Callable[..., Dict[str, Any]]:
    """
    Dependency factory. Verifies X-API-Key, checks active, checks secret hash, checks scopes.
    ✅ Patch: sets request.state.api_key_id for rate limiting.
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

        rec = get_api_key_record(db, parsed["key_id"])
        if not rec:
            raise HTTPException(status_code=401, detail="Invalid API key")

        if not rec.get("active", False):
            raise HTTPException(status_code=403, detail="API key revoked")

        expected_hash = rec.get("secret_hash") or ""
        provided_hash = _hash_secret(parsed["secret"])

        # constant-time compare
        if not py_secrets.compare_digest(str(expected_hash), str(provided_hash)):
            raise HTTPException(status_code=401, detail="Invalid API key")

        scopes = rec.get("scopes") or []
        if required_scopes:
            for s in required_scopes:
                if s not in scopes and "admin:*" not in scopes:
                    raise HTTPException(status_code=403, detail=f"Missing scope: {s}")

        # ✅ make key id available for rate limiter
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


# -------------------------
# Models
# -------------------------

class CreateKeyRequest(BaseModel):
    label: Optional[str] = None
    scopes: Optional[List[str]] = None

    # Optional per-key RL policy (Option B)
    rl_window_limit: Optional[int] = None
    rl_window_seconds: Optional[int] = None
    rl_bucket_seconds: Optional[int] = None
    rl_daily_limit: Optional[int] = None


class CreateKeyResponse(BaseModel):
    ok: bool
    key_id: str
    api_key: str  # returned only once
    created_at_utc: str


class RevokeKeyResponse(BaseModel):
    ok: bool
    key_id: str
    revoked: bool


class SetRoleReq(BaseModel):
    role: str


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
    # kept for frontend compatibility
    return {
        "message": "ok",
        "uid": user["uid"],
        "email": user.get("email"),
        "role": user.get("role"),
    }


@app.get("/admin-only")
def admin_only(admin: Dict[str, Any] = Depends(require_admin)):
    return {"message": "Hello admin", "uid": admin["uid"], "role": admin["role"]}


# -------------------------
# Admin: user management
# -------------------------

@app.post("/admin/users/{uid}/role")
def admin_set_user_role(uid: str, body: SetRoleReq, _: Dict[str, Any] = Depends(require_admin)):
    try:
        _ensure_firebase()
        fb_auth.set_custom_user_claims(uid, {"role": body.role})
        return {"ok": True, "uid": uid, "role": body.role}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "set_role_failed", "message": str(e)})


# -------------------------
# API Keys
# -------------------------

@app.post("/keys", response_model=CreateKeyResponse)
def create_api_key(
    req: CreateKeyRequest = Body(default_factory=CreateKeyRequest),
    admin: Dict[str, Any] = Depends(require_admin),
):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    # key_id is the Firestore doc id; secret is only returned once
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

        # Option B: per-key RL policy
        "rl_window_limit": req.rl_window_limit,
        "rl_window_seconds": req.rl_window_seconds,
        "rl_bucket_seconds": req.rl_bucket_seconds,
        "rl_daily_limit": req.rl_daily_limit,
    }

    try:
        db.collection("api_keys").document(key_id).set(doc)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "firestore_write_failed", "message": str(e)})

    return {
        "ok": True,
        "key_id": key_id,
        "api_key": api_key,
        "created_at_utc": doc["created_at_utc"],
    }


@app.post("/keys/{key_id}/revoke", response_model=RevokeKeyResponse)
def revoke_api_key(
    key_id: str,
    admin: Dict[str, Any] = Depends(require_admin),
):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    ref = db.collection("api_keys").document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update(
        {
            "active": False,
            "revoked_at_utc": _now_utc(),
            "revoked_by_uid": admin["uid"],
        }
    )
    return {"ok": True, "key_id": key_id, "revoked": True}


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