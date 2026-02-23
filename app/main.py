from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import firebase_admin
from firebase_admin import auth, credentials
from firebase_admin import exceptions as fb_exceptions

logger = logging.getLogger("apip-api")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

# Env
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")  # must match Firebase Project ID: apip-dev-487809-c949c

app = FastAPI(title="apip-api", version="0.1.0")

# CORS: allow your frontend + local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://app.cognispark.tech",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Firebase Admin init (Cloud Run uses ADC) ----
if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()
    # NOTE: Do not pass projectId here; verify_id_token uses aud/iss from token.
    firebase_admin.initialize_app(cred)
    logger.info("Firebase Admin initialized (ADC).")


# ---- Helpers ----
def _extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return authorization.split(" ", 1)[1].strip()


def _verify_expected_project(decoded: Dict[str, Any]) -> None:
    """
    Ensure the ID token is from the expected Firebase project.
    Firebase ID token typically has:
      aud == <project_id>
      iss == https://securetoken.google.com/<project_id>
    """
    if not FIREBASE_PROJECT_ID:
        # If you want to HARD require this env var, flip this to raise 500.
        logger.warning("FIREBASE_PROJECT_ID is not set; skipping aud/iss check.")
        return

    aud = decoded.get("aud")
    iss = decoded.get("iss")

    expected_aud = FIREBASE_PROJECT_ID
    expected_iss = f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}"

    if aud != expected_aud or iss != expected_iss:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "firebase_project_mismatch",
                "expected": {"aud": expected_aud, "iss": expected_iss},
                "got": {"aud": aud, "iss": iss},
            },
        )


def get_current_user(authorization: str | None = Header(default=None)) -> Dict[str, Any]:
    token = _extract_bearer_token(authorization)

    try:
        decoded = auth.verify_id_token(token)
        _verify_expected_project(decoded)
        return decoded
    except auth.ExpiredIdTokenError as e:
        raise HTTPException(status_code=401, detail={"error": "expired_id_token", "message": str(e)})
    except auth.RevokedIdTokenError as e:
        raise HTTPException(status_code=401, detail={"error": "revoked_id_token", "message": str(e)})
    except auth.InvalidIdTokenError as e:
        raise HTTPException(status_code=401, detail={"error": "invalid_id_token", "message": str(e)})
    except fb_exceptions.FirebaseError as e:
        logger.exception("FirebaseError in verify_id_token")
        raise HTTPException(status_code=500, detail={"error": "firebase_error", "message": str(e)})
    except Exception as e:
        logger.exception("Unexpected error in verify_id_token")
        raise HTTPException(status_code=500, detail={"error": "unexpected_error", "message": str(e)})


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    role = user.get("role")  # custom claim
    if role != "admin":
        raise HTTPException(
            status_code=403,
            detail={"error": "forbidden", "message": "Admin role required", "role": role},
        )
    return user


# ---- Optional Firestore mirror (won't crash if Firestore not installed/enabled) ----
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_user_doc(uid: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mirror user info to Firestore: users/{uid}
    This is NOT used for authorization; it is only for UI/querying.
    """
    try:
        from google.cloud import firestore  # type: ignore
    except Exception:
        return {"firestore": "skipped", "reason": "google-cloud-firestore not installed"}

    try:
        db = firestore.Client(project=FIREBASE_PROJECT_ID or None)
        ref = db.collection("users").document(uid)
        ref.set(data, merge=True)
        return {"firestore": "ok"}
    except Exception as e:
        # Don’t kill auth flows just because Firestore is unavailable
        logger.warning("Firestore upsert failed: %r", e)
        return {"firestore": "failed", "reason": str(e)}


# ---- Models ----
class SetRoleBody(BaseModel):
    role: str = Field(..., description="Role name (e.g. 'admin' or 'user')")


# ---- Routes ----
@app.get("/health")
def health():
    return {"status": "ok", "firebase_project_id": FIREBASE_PROJECT_ID}


@app.get("/me")
def me(user: Dict[str, Any] = Depends(get_current_user)):
    # Custom claims are directly in decoded token (e.g. user['role']).
    return {
        "uid": user.get("uid") or user.get("sub"),
        "email": user.get("email"),
        "role": user.get("role"),
        "provider": (user.get("firebase") or {}).get("sign_in_provider"),
        "aud": user.get("aud"),
        "iss": user.get("iss"),
    }


@app.get("/profile")
def profile(user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "message": "Secure profile",
        "uid": user.get("uid") or user.get("sub"),
        "email": user.get("email"),
        "role": user.get("role"),
    }


@app.post("/admin/users/{uid}/role")
def admin_set_role(
    uid: str,
    body: SetRoleBody,
    admin_user: Dict[str, Any] = Depends(require_admin),
):
    # Optional: normalize role values
    role = body.role.strip().lower()
    if role not in {"admin", "user"}:
        raise HTTPException(status_code=400, detail={"error": "invalid_role", "allowed": ["admin", "user"]})

    # 1) Set custom claim (SOURCE OF TRUTH)
    auth.set_custom_user_claims(uid, {"role": role})

    # 2) Verify what’s currently stored for that user
    rec = auth.get_user(uid)
    claims = rec.custom_claims or {}

    # 3) Mirror to Firestore (OPTIONAL; not used for auth)
    mirror = upsert_user_doc(
        uid,
        {
            "uid": uid,
            "role": role,
            "updatedAt": _now_iso(),
            "updatedBy": admin_user.get("uid") or admin_user.get("sub"),
        },
    )

    return {
        "ok": True,
        "uid": uid,
        "role_set_to": role,
        "current_custom_claims": claims,
        "mirror": mirror,
    }