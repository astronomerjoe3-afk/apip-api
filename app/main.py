from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import firebase_admin
from firebase_admin import auth, credentials
from firebase_admin import exceptions as fb_exceptions

# NOTE:
# This file assumes you already have app/token_debug.py with decode_jwt_no_verify()
# If you do NOT have it, tell me and I’ll paste that file too.
from app.token_debug import decode_jwt_no_verify

logger = logging.getLogger("apip-api")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

app = FastAPI()

# Frontend origins allowed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.cognispark.tech", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Firebase project id your backend should accept tokens from
EXPECTED_FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")

# Initialize Firebase Admin using ADC (Cloud Run uses its service account automatically)
# Locally, run:
#   gcloud auth application-default login
if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)


def _extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return authorization.split(" ", 1)[1].strip()


def _verify_expected_project(decoded: Dict[str, Any]) -> None:
    """
    Guardrail: ensure token belongs to the expected Firebase project.
    Firebase ID token typically has:
      aud == <project_id>
      iss == https://securetoken.google.com/<project_id>
    """
    if not EXPECTED_FIREBASE_PROJECT_ID:
        return

    aud = decoded.get("aud")
    iss = decoded.get("iss")

    expected_aud = EXPECTED_FIREBASE_PROJECT_ID
    expected_iss = f"https://securetoken.google.com/{EXPECTED_FIREBASE_PROJECT_ID}"

    if aud != expected_aud or iss != expected_iss:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "firebase_project_mismatch",
                "expected": {"aud": expected_aud, "iss": expected_iss},
                "got": {"aud": aud, "iss": iss},
            },
        )


def get_current_user(authorization: str | None = Header(default=None)):
    token = _extract_bearer_token(authorization)

    # Decode without verification just for logs (DO NOT TRUST for auth)
    try:
        unverified = decode_jwt_no_verify(token)
        logger.info(
            "Incoming token (unverified) aud=%s iss=%s sub=%s kid=%s",
            unverified.get("payload", {}).get("aud"),
            unverified.get("payload", {}).get("iss"),
            unverified.get("payload", {}).get("sub"),
            unverified.get("header", {}).get("kid"),
        )
    except Exception as e:
        logger.warning("Could not decode JWT for debugging: %s", repr(e))

    try:
        decoded = auth.verify_id_token(token)
        _verify_expected_project(decoded)
        return decoded

    except auth.ExpiredIdTokenError as e:
        raise HTTPException(status_code=401, detail={"error": "expired_id_token", "message": str(e)})

    except auth.RevokedIdTokenError as e:
        raise HTTPException(status_code=401, detail={"error": "revoked_id_token", "message": str(e)})

    except auth.InvalidIdTokenError as e:
        # Audience/issuer mismatch, invalid signature, malformed token, etc.
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_id_token", "message": str(e), "type": e.__class__.__name__},
        )

    except fb_exceptions.FirebaseError as e:
        logger.exception("Firebase error during token verification")
        raise HTTPException(
            status_code=500,
            detail={"error": "firebase_error", "message": str(e), "type": e.__class__.__name__},
        )

    except Exception as e:
        logger.exception("Unexpected error during token verification")
        raise HTTPException(
            status_code=500,
            detail={"error": "unexpected_error", "message": str(e), "type": e.__class__.__name__},
        )


def require_admin(user=Depends(get_current_user)):
    """
    Requires custom claim role == 'admin'
    NOTE: Firebase Admin puts custom claims at top-level in decoded token.
    """
    role = user.get("role")
    if role != "admin":
        raise HTTPException(
            status_code=403,
            detail={"error": "admin_required", "role_seen": role},
        )
    return user


@app.get("/health")
def health():
    return {"status": "ok", "expected_firebase_project_id": EXPECTED_FIREBASE_PROJECT_ID}


@app.get("/me")
def me(user=Depends(get_current_user)):
    return {
        "uid": user.get("uid"),
        "email": user.get("email"),
        "role": user.get("role"),
        "provider": (user.get("firebase") or {}).get("sign_in_provider"),
    }


@app.get("/profile")
def profile(user=Depends(get_current_user)):
    return {"message": "Secure profile", "uid": user.get("uid"), "email": user.get("email"), "role": user.get("role")}


@app.get("/admin-only")
def admin_only(user=Depends(require_admin)):
    return {"message": "You are an admin", "uid": user.get("uid"), "email": user.get("email"), "role": user.get("role")}


@app.get("/debug-token")
def debug_token(authorization: str | None = Header(default=None)):
    """
    TEMP endpoint: decodes JWT header/payload WITHOUT verifying signature.
    Remove after debugging.
    """
    token = _extract_bearer_token(authorization)
    return decode_jwt_no_verify(token)