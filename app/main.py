from __future__ import annotations

import logging
import os
from typing import Optional, Any, Dict

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware

import firebase_admin
from firebase_admin import auth, credentials
from firebase_admin import exceptions as fb_exceptions

logger = logging.getLogger("apip-api")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

app = FastAPI()

# ---- Config ----
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")  # should be apip-dev-487809-c949c

# CORS: allow your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.cognispark.tech", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Firebase Admin init (FORCE correct projectId) ----
# ADC on Cloud Run works automatically.
# Locally: gcloud auth application-default login
if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()
    options = {}
    if FIREBASE_PROJECT_ID:
        options["projectId"] = FIREBASE_PROJECT_ID
    firebase_admin.initialize_app(cred, options)


def _extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return authorization.split(" ", 1)[1].strip()


def get_current_user(authorization: str | None = Header(default=None)) -> Dict[str, Any]:
    token = _extract_bearer_token(authorization)

    try:
        decoded = auth.verify_id_token(token)
        return decoded

    except auth.ExpiredIdTokenError as e:
        raise HTTPException(status_code=401, detail={"error": "expired_id_token", "message": str(e)})

    except auth.RevokedIdTokenError as e:
        raise HTTPException(status_code=401, detail={"error": "revoked_id_token", "message": str(e)})

    except auth.InvalidIdTokenError as e:
        # Includes: wrong aud/iss, malformed token, etc.
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_id_token", "message": str(e), "type": e.__class__.__name__},
        )

    except fb_exceptions.FirebaseError as e:
        logger.exception("FirebaseError during verify_id_token")
        raise HTTPException(
            status_code=500,
            detail={"error": "firebase_error", "message": str(e), "type": e.__class__.__name__},
        )

    except Exception as e:
        logger.exception("Unexpected error during verify_id_token")
        raise HTTPException(
            status_code=500,
            detail={"error": "unexpected_error", "message": str(e), "type": e.__class__.__name__},
        )


def require_role(required_role: str):
    def _dep(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        role = user.get("role")  # custom claim from set_custom_user_claims
        if role != required_role:
            raise HTTPException(
                status_code=403,
                detail={"error": "forbidden", "required_role": required_role, "got_role": role},
            )
        return user

    return _dep


@app.get("/health")
def health():
    return {"status": "ok", "firebase_project_id": FIREBASE_PROJECT_ID}


@app.get("/me")
def me(user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "uid": user.get("uid"),
        "email": user.get("email"),
        "role": user.get("role"),
        "provider": (user.get("firebase") or {}).get("sign_in_provider"),
        "aud": user.get("aud"),
        "iss": user.get("iss"),
    }


@app.get("/profile")
def profile(user: Dict[str, Any] = Depends(get_current_user)):
    return {"message": "Secure profile", "uid": user.get("uid"), "email": user.get("email"), "role": user.get("role")}


@app.get("/admin-only")
def admin_only(user: Dict[str, Any] = Depends(require_role("admin"))):
    return {"ok": True, "message": "You are admin ✅", "uid": user.get("uid"), "email": user.get("email"), "role": user.get("role")}