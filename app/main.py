import os
import datetime
import secrets
import hashlib
from typing import Any, Dict, Optional

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware

import firebase_admin
from firebase_admin import auth as fb_auth
from firebase_admin import credentials
from firebase_admin import firestore

# ----------------------------
# API KEY UTILITIES
# ----------------------------

def generate_api_key() -> str:
    return "ak_live_" + secrets.token_urlsafe(32)

def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()

# ----------------------------
# App metadata / build markers
# ----------------------------
APP_NAME = os.getenv("APP_NAME", "apip-api")
APP_VERSION = os.getenv("APP_VERSION", "0.1.0")
APP_COMMIT = os.getenv("APP_COMMIT")  # set by GitHub Actions / Cloud Run
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")  # MUST match Firebase token aud/iss project
BOOTSTRAP_ADMIN_UID = os.getenv("BOOTSTRAP_ADMIN_UID", "").strip()

# Comma-separated list of allowed origins
# Example:
#   CORS_ORIGINS=https://app.cognispark.tech,http://localhost:3000
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

app = FastAPI(title=APP_NAME, version=APP_VERSION)

# ----------------------------
# CORS (required for browser fetch)
# ----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in CORS_ORIGINS if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# Firebase Admin init
# ----------------------------
def init_firebase_admin() -> None:
    """
    Initialize Firebase Admin exactly once.
    Cloud Run provides Application Default Credentials (ADC).
    Passing projectId reduces project mismatch issues.
    """
    if firebase_admin._apps:
        return

    try:
        cred = credentials.ApplicationDefault()
        opts = {"projectId": FIREBASE_PROJECT_ID} if FIREBASE_PROJECT_ID else None
        firebase_admin.initialize_app(cred, opts)
    except Exception as e:
        # Don’t crash container; surface errors through /health and auth checks
        print(f"[WARN] Firebase Admin init failed: {repr(e)}")


init_firebase_admin()


def get_firestore():
    try:
        if not firebase_admin._apps:
            return None
        return firestore.client()
    except Exception as e:
        print(f"[WARN] Firestore client init failed: {repr(e)}")
        return None


# ----------------------------
# Auth helpers
# ----------------------------
def _extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authorization must be: Bearer <token>")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return token


def verify_firebase_token(authorization: Optional[str]) -> Dict[str, Any]:
    token = _extract_bearer_token(authorization)

    if not firebase_admin._apps:
        raise HTTPException(status_code=500, detail="Firebase Admin not initialized")

    try:
        decoded = fb_auth.verify_id_token(token, check_revoked=False)
        return decoded
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_id_token",
                "message": str(e),
                "type": e.__class__.__name__,
            },
        )


def require_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    return verify_firebase_token(authorization)


from fastapi import Depends, HTTPException
from typing import Any, Dict

def require_admin(user: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    """
    Allows admin access if:
      - token custom claim role == "admin"
      - OR caller uid matches BOOTSTRAP_ADMIN_UID (break-glass admin)
    """
    uid = (user.get("uid") or "").strip()
    role = (user.get("role") or "").strip()

    # Break-glass admin: allow if uid matches env var
    if BOOTSTRAP_ADMIN_UID and uid == BOOTSTRAP_ADMIN_UID:
        # Normalize role to admin for downstream
        user["role"] = "admin"
        return user

    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    return user
def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore unavailable")

    hashed = hash_key(x_api_key)

    docs = db.collection("api_keys").where("hashed_key", "==", hashed).limit(1).stream()
    key_doc = next(docs, None)

    if not key_doc:
        raise HTTPException(status_code=401, detail="Invalid API key")

    data = key_doc.to_dict()

    if data.get("revoked"):
        raise HTTPException(status_code=403, detail="API key revoked")

    db.collection("api_keys").document(key_doc.id).update({
        "lastUsedAt": firestore.SERVER_TIMESTAMP
    })

    return data


# ----------------------------
# Public endpoints
# ----------------------------
@app.get("/health")
def health():
    return {"status": "ok", "firebase_project_id": FIREBASE_PROJECT_ID}


@app.get("/__build")
def build_marker():
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "app_commit": APP_COMMIT,
        "firebase_project_id": FIREBASE_PROJECT_ID,
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


# ----------------------------
# Authenticated endpoints
# ----------------------------
@app.get("/me")
def me(user: Dict[str, Any] = Depends(require_user)):
    return {
        "uid": user.get("uid"),
        "email": user.get("email"),
        "role": user.get("role"),
        "provider": user.get("firebase", {}).get("sign_in_provider"),
        "aud": user.get("aud"),
        "iss": user.get("iss"),
    }


@app.get("/profile")
def profile(user: Dict[str, Any] = Depends(require_user)):
    return {
        "message": "Secure profile",
        "uid": user.get("uid"),
        "email": user.get("email"),
        "role": user.get("role"),
    }


@app.get("/admin-only")
def admin_only(admin_user: Dict[str, Any] = Depends(require_admin)):
    return {"message": "Hello admin", "uid": admin_user.get("uid"), "role": admin_user.get("role")}


# ----------------------------
# USER API KEY MANAGEMENT
# ----------------------------

@app.post("/keys")
def create_api_key(user: Dict[str, Any] = Depends(require_user)):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore unavailable")

    raw_key = generate_api_key()
    hashed = hash_key(raw_key)

    doc_ref = db.collection("api_keys").document()

    doc_ref.set({
        "uid": user["uid"],
        "name": "Default Key",
        "hashed_key": hashed,
        "createdAt": firestore.SERVER_TIMESTAMP,
        "revoked": False,
        "lastUsedAt": None
    })

    return {
        "id": doc_ref.id,
        "api_key": raw_key   # Only returned once
    }


@app.get("/keys")
def list_keys(user: Dict[str, Any] = Depends(require_user)):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore unavailable")

    docs = db.collection("api_keys").where("uid", "==", user["uid"]).stream()

    results = []
    for doc in docs:
        d = doc.to_dict()
        results.append({
            "id": doc.id,
            "createdAt": d.get("createdAt"),
            "revoked": d.get("revoked"),
            "lastUsedAt": d.get("lastUsedAt")
        })

    return results


@app.delete("/keys/{key_id}")
def revoke_key(key_id: str, user: Dict[str, Any] = Depends(require_user)):
    db = get_firestore()
    doc = db.collection("api_keys").document(key_id).get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    data = doc.to_dict()

    if data.get("uid") != user["uid"]:
        raise HTTPException(status_code=403, detail="Not your key")

    db.collection("api_keys").document(key_id).update({
        "revoked": True
    })

    return {"revoked": True}


# ----------------------------
# ADMIN: user management
# ----------------------------
@app.get("/admin/users/{uid}")
def admin_get_user(uid: str, admin_user: Dict[str, Any] = Depends(require_admin)):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")

    return {"uid": uid, **(doc.to_dict() or {})}


@app.post("/admin/users/{uid}/role")
def admin_set_user_role(
    uid: str,
    body: Dict[str, Any],
    admin_user: Dict[str, Any] = Depends(require_admin),
):
    """
    Body example:
      {"role":"admin"}  or {"role":"user"}
    """
    role = (body or {}).get("role")
    if role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")

    # Set Firebase custom claim
    try:
        fb_auth.set_custom_user_claims(uid, {"role": role})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to set custom claim: {e}")

    # Optional: store role in Firestore for quick lookup
    db = get_firestore()
    if db:
        try:
            db.collection("users").document(uid).set(
                {
                    "role": role,
                    "updatedAt": firestore.SERVER_TIMESTAMP,
                    "updatedBy": admin_user.get("uid"),
                },
                merge=True,
            )
        except Exception as e:
            print(f"[WARN] Firestore write failed: {repr(e)}")

    return {"ok": True, "uid": uid, "role": role}