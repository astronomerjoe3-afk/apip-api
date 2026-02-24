import os
import json
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from fastapi import FastAPI, Depends, Header, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import firebase_admin
from firebase_admin import auth as fb_auth
from firebase_admin import credentials

from google.cloud import firestore


APP_NAME = "apip-api"
APP_VERSION = "0.1.0"


# -------------------------
# Firebase / Firestore init
# -------------------------

def _ensure_firebase() -> None:
    """Initialize firebase_admin exactly once."""
    if firebase_admin._apps:
        return

    # Cloud Run typically uses application default credentials automatically.
    # If you later choose to use a service account JSON, you can add it here.
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)


def get_firestore() -> Optional[firestore.Client]:
    try:
        _ensure_firebase()
        return firestore.Client()
    except Exception:
        return None


# -------------------------
# Auth helpers
# -------------------------

BOOTSTRAP_ADMIN_UID = os.getenv("BOOTSTRAP_ADMIN_UID", "").strip()
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "").strip()


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

        # If FIREBASE_PROJECT_ID is set, enforce it via 'audience' check
        # Firebase Admin SDK already validates 'aud'/'iss' for the project it’s configured for.
        decoded = fb_auth.verify_id_token(token)
        return decoded
    except Exception as e:
        # Return structured error for debugging
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
# API key models
# -------------------------

class CreateKeyRequest(BaseModel):
    # Optional metadata fields (safe defaults)
    label: Optional[str] = None
    scopes: Optional[List[str]] = None  # future use
    expires_in_days: Optional[int] = None  # future use


class CreateKeyResponse(BaseModel):
    ok: bool
    key_id: str
    api_key: str  # returned only once
    created_at_utc: str


class RevokeKeyResponse(BaseModel):
    ok: bool
    key_id: str
    revoked: bool


# -------------------------
# App
# -------------------------

app = FastAPI(title=APP_NAME, version=APP_VERSION)

# CORS (adjust for your web app domains)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://cognispark.tech", "https://www.cognispark.tech"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "firebase_project_id": FIREBASE_PROJECT_ID or "(unset)"}


@app.get("/__build")
def build_marker():
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "app_commit": os.getenv("APP_COMMIT", "(unset)"),
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
    # same as /me, but kept because your frontend uses /profile
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

@app.get("/admin/users/{uid}")
def admin_get_user(uid: str, _: Dict[str, Any] = Depends(require_admin)):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")
    return doc.to_dict()


class SetRoleReq(BaseModel):
    role: str


@app.post("/admin/users/{uid}/role")
def admin_set_user_role(uid: str, body: SetRoleReq, _: Dict[str, Any] = Depends(require_admin)):
    try:
        _ensure_firebase()
        fb_auth.set_custom_user_claims(uid, {"role": body.role})
        return {"ok": True, "uid": uid, "role": body.role}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "set_role_failed", "message": str(e)})


# -------------------------
# API Keys (Phase 1)
# -------------------------

def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.post("/keys", response_model=CreateKeyResponse)
def create_api_key(
    req: CreateKeyRequest = Body(default=CreateKeyRequest()),
    admin: Dict[str, Any] = Depends(require_admin),
):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    # key_id is the Firestore doc id; secret is only returned once
    key_id = secrets.token_urlsafe(12).replace("-", "").replace("_", "")
    secret = secrets.token_urlsafe(32)

    api_key = f"ak_{key_id}.{secret}"
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