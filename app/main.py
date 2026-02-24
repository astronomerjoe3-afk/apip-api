import os
import json
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import firebase_admin
from firebase_admin import credentials, auth as fb_auth

from google.cloud import firestore


APP_NAME = "apip-api"
APP_VERSION = "0.1.0"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if v is not None and v != "" else default


FIREBASE_PROJECT_ID = get_env("FIREBASE_PROJECT_ID")
APP_COMMIT = get_env("APP_COMMIT", "unknown")
BOOTSTRAP_ADMIN_UID = get_env("BOOTSTRAP_ADMIN_UID")  # break-glass admin UID


app = FastAPI(title=APP_NAME, version=APP_VERSION)

# CORS (adjust as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://app.cognispark.tech",
        "https://cognispark.tech",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# Firebase Admin init (safe)
# -----------------------------
def init_firebase_admin() -> None:
    """
    Initializes Firebase Admin SDK if possible.
    Supports:
      - Application Default Credentials (recommended on Cloud Run)
      - GOOGLE_APPLICATION_CREDENTIALS (JSON file path)
      - FIREBASE_SERVICE_ACCOUNT_JSON (raw JSON)
    """
    if firebase_admin._apps:
        return

    # Raw JSON env option
    raw = get_env("FIREBASE_SERVICE_ACCOUNT_JSON")
    if raw:
        try:
            info = json.loads(raw)
            cred = credentials.Certificate(info)
            firebase_admin.initialize_app(cred)
            return
        except Exception as e:
            raise RuntimeError(f"Failed to init Firebase from FIREBASE_SERVICE_ACCOUNT_JSON: {e}")

    # Default credentials (Cloud Run)
    try:
        firebase_admin.initialize_app()
    except Exception as e:
        # If this fails, many endpoints can still work but auth will fail.
        raise RuntimeError(f"Failed to init Firebase Admin SDK: {e}")


def get_firestore():
    """
    Returns Firestore client or None if not available.
    """
    try:
        # Firestore client uses ADC on Cloud Run if IAM is set properly
        return firestore.Client(project=FIREBASE_PROJECT_ID) if FIREBASE_PROJECT_ID else firestore.Client()
    except Exception:
        return None


# -----------------------------
# Auth helpers
# -----------------------------
def parse_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0].lower(), parts[1].strip()
    if scheme != "bearer" or not token:
        return None
    return token


def verify_id_token(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    token = parse_bearer(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    try:
        init_firebase_admin()
        decoded = fb_auth.verify_id_token(token, check_revoked=False)
        return decoded
    except Exception as e:
        # Keep errors readable for debugging
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_id_token",
                "message": str(e),
                "type": e.__class__.__name__,
            },
        )


def is_admin(decoded: Dict[str, Any]) -> bool:
    uid = decoded.get("uid") or decoded.get("user_id") or decoded.get("sub")
    role = decoded.get("role")
    if BOOTSTRAP_ADMIN_UID and uid == BOOTSTRAP_ADMIN_UID:
        return True
    return role == "admin"


def require_admin(decoded: Dict[str, Any] = Depends(verify_id_token)) -> Dict[str, Any]:
    if not is_admin(decoded):
        raise HTTPException(status_code=403, detail="Admin only")
    return decoded


# -----------------------------
# Public endpoints
# -----------------------------
@app.get("/health")
def health():
    return {
        "status": "ok",
        "firebase_project_id": FIREBASE_PROJECT_ID,
    }


@app.get("/__build")
def build_marker():
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "app_commit": APP_COMMIT,
        "firebase_project_id": FIREBASE_PROJECT_ID,
        "utc": utc_now_iso(),
    }


@app.get("/me")
def me(decoded: Dict[str, Any] = Depends(verify_id_token)):
    uid = decoded.get("uid") or decoded.get("user_id") or decoded.get("sub")
    return {
        "uid": uid,
        "email": decoded.get("email"),
        "role": decoded.get("role") or "user",
        "provider": decoded.get("firebase", {}).get("sign_in_provider"),
        "aud": decoded.get("aud"),
        "iss": decoded.get("iss"),
    }


@app.get("/profile")
def profile(decoded: Dict[str, Any] = Depends(verify_id_token)):
    uid = decoded.get("uid") or decoded.get("user_id") or decoded.get("sub")
    role = decoded.get("role") or "user"
    return {
        "message": "Secure profile",
        "uid": uid,
        "email": decoded.get("email"),
        "role": role,
    }


@app.get("/admin-only")
def admin_only(admin: Dict[str, Any] = Depends(require_admin)):
    uid = admin.get("uid") or admin.get("user_id") or admin.get("sub")
    return {"message": "Hello admin", "uid": uid, "role": "admin"}


# -----------------------------
# Admin user management
# -----------------------------
@app.get("/admin/users/{uid}")
def admin_get_user(uid: str, admin: Dict[str, Any] = Depends(require_admin)):
    db = get_firestore()
    if not db:
        return {"error": "Firestore not available"}

    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")
    return doc.to_dict()


@app.post("/admin/users/{uid}/role")
def admin_set_user_role(uid: str, body: Dict[str, Any], admin: Dict[str, Any] = Depends(require_admin)):
    """
    Body example:
      {"role":"admin"} or {"role":"user"}
    """
    role = (body or {}).get("role")
    if role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")

    try:
        init_firebase_admin()
        fb_auth.set_custom_user_claims(uid, {"role": role})
        return {"ok": True, "uid": uid, "role": role}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to set role: {e}")


# -----------------------------
# API Key system (Phase 1)
# -----------------------------
def hash_key(api_key: str) -> str:
    # stable hash; in production you can add per-key salt if desired
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """
    Optional for now; you can start enforcing this on certain routes later.
    Looks up key hash in Firestore.
    """
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key")

    db = get_firestore()
    if not db:
        raise HTTPException(status_code=500, detail="Firestore not available")

    h = hash_key(x_api_key)
    q = db.collection("api_keys").where("hash", "==", h).limit(1).stream()
    doc = next(q, None)
    if not doc:
        raise HTTPException(status_code=401, detail="Invalid API key")

    data = doc.to_dict() or {}
    if data.get("revoked") is True:
        raise HTTPException(status_code=403, detail="API key revoked")

    return {"key_id": doc.id, **data}


@app.post("/keys")
def create_api_key(admin: Dict[str, Any] = Depends(require_admin)):
    """
    Creates a new API key.
    Returns the raw key ONCE (store it client-side).
    """
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=500, detail="Firestore not available")

    raw_key = "apip_" + secrets.token_urlsafe(32)
    key_hash = hash_key(raw_key)

    uid = admin.get("uid") or admin.get("user_id") or admin.get("sub")

    doc_ref = db.collection("api_keys").document()
    doc_ref.set(
        {
            "hash": key_hash,
            "created_at": utc_now_iso(),
            "created_by_uid": uid,
            "revoked": False,
            "revoked_at": None,
            "revoked_by_uid": None,
        }
    )

    return {
        "ok": True,
        "key_id": doc_ref.id,
        "api_key": raw_key,  # shown once
    }


@app.get("/keys")
def list_api_keys(admin: Dict[str, Any] = Depends(require_admin)):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=500, detail="Firestore not available")

    out = []
    for doc in db.collection("api_keys").order_by("created_at", direction=firestore.Query.DESCENDING).stream():
        d = doc.to_dict() or {}
        # do not expose hash in UI unless you want to
        out.append(
            {
                "key_id": doc.id,
                "created_at": d.get("created_at"),
                "created_by_uid": d.get("created_by_uid"),
                "revoked": d.get("revoked", False),
                "revoked_at": d.get("revoked_at"),
                "revoked_by_uid": d.get("revoked_by_uid"),
            }
        )
    return {"ok": True, "keys": out}


@app.post("/keys/{key_id}/revoke")
def revoke_api_key(key_id: str, admin: Dict[str, Any] = Depends(require_admin)):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=500, detail="Firestore not available")

    uid = admin.get("uid") or admin.get("user_id") or admin.get("sub")

    ref = db.collection("api_keys").document(key_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="API key not found")

    ref.update(
        {
            "revoked": True,
            "revoked_at": utc_now_iso(),
            "revoked_by_uid": uid,
        }
    )
    return {"ok": True, "key_id": key_id, "revoked": True}