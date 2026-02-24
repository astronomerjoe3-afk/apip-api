import os
import datetime
from typing import Any, Dict, Optional

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware

import firebase_admin
from firebase_admin import auth as fb_auth
from firebase_admin import credentials
from firebase_admin import firestore

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