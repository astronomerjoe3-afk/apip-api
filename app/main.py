import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

import firebase_admin
from firebase_admin import auth as fb_auth
from firebase_admin import credentials

try:
    from google.cloud import firestore
except Exception:
    firestore = None


APP_VERSION = os.getenv("APP_VERSION", "2026-02-23.1")
APP_COMMIT = os.getenv("APP_COMMIT", "unknown")
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")  # must match token aud/iss


app = FastAPI(title="apip-api", version="0.1.0")


# -----------------------------
# Firebase Admin init (lazy, safe)
# -----------------------------
_firebase_inited = False


def init_firebase() -> None:
    global _firebase_inited
    if _firebase_inited:
        return

    # Cloud Run: Application Default Credentials are available if IAM is correct
    # Local dev: you can set GOOGLE_APPLICATION_CREDENTIALS
    try:
        firebase_admin.get_app()
        _firebase_inited = True
        return
    except Exception:
        pass

    try:
        cred = credentials.ApplicationDefault()
        firebase_admin.initialize_app(cred, {"projectId": FIREBASE_PROJECT_ID} if FIREBASE_PROJECT_ID else None)
        _firebase_inited = True
    except Exception as e:
        raise RuntimeError(f"Failed to init firebase_admin: {e}") from e


def get_firestore():
    if firestore is None:
        return None
    if not FIREBASE_PROJECT_ID:
        return None
    try:
        return firestore.Client(project=FIREBASE_PROJECT_ID)
    except Exception:
        return None


# -----------------------------
# Auth helpers
# -----------------------------
def _extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0].strip(), parts[1].strip()
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def require_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    token = _extract_bearer_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    try:
        init_firebase()
        decoded = fb_auth.verify_id_token(token, check_revoked=False)
    except Exception as e:
        # Surface a clean error for debugging
        raise HTTPException(status_code=401, detail={"error": "invalid_id_token", "message": str(e), "type": e.__class__.__name__})

    # Optional but very useful: enforce project match explicitly
    if FIREBASE_PROJECT_ID:
        aud = decoded.get("aud")
        iss = decoded.get("iss")
        expected_iss = f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}"
        if aud != FIREBASE_PROJECT_ID or iss != expected_iss:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "invalid_project_token",
                    "message": f"Token aud/iss mismatch. aud={aud} iss={iss}",
                    "expected": {"aud": FIREBASE_PROJECT_ID, "iss": expected_iss},
                },
            )

    return decoded


def require_admin(user: Dict[str, Any] = Depends(require_user)) -> Dict[str, Any]:
    role = user.get("role")  # custom claim comes top-level after verify_id_token
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# -----------------------------
# Models
# -----------------------------
class RoleBody(BaseModel):
    role: str = Field(..., min_length=1)


# -----------------------------
# Public endpoints
# -----------------------------
@app.get("/health")
def health():
    return {"status": "ok", "firebase_project_id": FIREBASE_PROJECT_ID}


@app.get("/__build")
def build_marker():
    return {
        "app_version": APP_VERSION,
        "app_commit": APP_COMMIT,
        "firebase_project_id": FIREBASE_PROJECT_ID,
        "time": datetime.now(timezone.utc).isoformat(),
    }


# -----------------------------
# Authenticated endpoints
# -----------------------------
@app.get("/me")
def me(user: Dict[str, Any] = Depends(require_user)):
    firebase_block = user.get("firebase") or {}
    provider = firebase_block.get("sign_in_provider")

    return {
        "uid": user.get("uid"),
        "email": user.get("email"),
        "role": user.get("role"),
        "provider": provider,
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
    return {"message": "Admin OK", "uid": admin_user.get("uid"), "email": admin_user.get("email")}


# -----------------------------
# Admin user management
# -----------------------------
@app.get("/admin/users/{uid}")
def admin_get_user(uid: str, admin_user: Dict[str, Any] = Depends(require_admin)):
    uid = uid.strip()
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")

    out = doc.to_dict() or {}
    out["uid"] = uid
    return out


@app.post("/admin/users/{uid}/role")
def admin_set_user_role(uid: str, body: RoleBody, admin_user: Dict[str, Any] = Depends(require_admin)):
    uid = uid.strip()
    role = (body.role or "").strip().lower()

    if role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail='role must be "admin" or "user"')

    try:
        init_firebase()
        fb_auth.set_custom_user_claims(uid, {"role": role})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "set_claim_failed", "message": str(e)})

    # Optional Firestore mirror
    db = get_firestore()
    if db:
        try:
            db.collection("users").document(uid).set(
                {"uid": uid, "role": role, "updated_at": datetime.now(timezone.utc).isoformat()},
                merge=True,
            )
        except Exception:
            # Don't fail the whole request if Firestore write fails
            pass

    return {"ok": True, "uid": uid, "role": role}