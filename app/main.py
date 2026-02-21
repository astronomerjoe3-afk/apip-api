from __future__ import annotations

import logging
import os
from typing import Optional, Any, Dict

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware

import firebase_admin
from firebase_admin import auth, credentials
from firebase_admin import exceptions as fb_exceptions

from app.token_debug import decode_jwt_no_verify

logger = logging.getLogger("apip-api")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

app = FastAPI()

# CORS: allow your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.cognispark.tech", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Optional: if set, we will validate token aud/iss matches this Firebase project.
# This should be your Firebase project id, e.g. "my-project-123".
EXPECTED_FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")

# Initialize Firebase Admin using ADC (works on Cloud Run)
# Locally, run: gcloud auth application-default login
import os
import firebase_admin
from firebase_admin import credentials

project_id = os.getenv("FIREBASE_PROJECT_ID")

if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred, {"projectId": project_id})


def _extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return authorization.split(" ", 1)[1].strip()


def _verify_expected_project(decoded: Dict[str, Any]) -> None:
    """
    Extra guardrail: ensure frontend Firebase project matches backend expectation.
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

    # Decode without verification so we can log aud/iss even if verification fails.
    # This is safe for *logging/debugging only*; do not trust these claims for auth.
    try:
        unverified = decode_jwt_no_verify(token)
        logger.info(
            "Incoming token (unverified) aud=%s iss=%s sub=%s provider=%s kid=%s",
            unverified["claims_of_interest"].get("aud"),
            unverified["claims_of_interest"].get("iss"),
            unverified["claims_of_interest"].get("sub"),
            unverified["claims_of_interest"].get("firebase.sign_in_provider"),
            (unverified.get("header") or {}).get("kid"),
        )
    except Exception as e:
        logger.warning("Could not base64-decode JWT for debugging: %s", repr(e))

    try:
        decoded = auth.verify_id_token(token)
        _verify_expected_project(decoded)
        return decoded  # includes uid, email (if available), etc.

    except auth.ExpiredIdTokenError as e:
        logger.warning("verify_id_token failed: ExpiredIdTokenError: %s", repr(e))
        raise HTTPException(status_code=401, detail={"error": "expired_id_token", "message": str(e)})

    except auth.RevokedIdTokenError as e:
        logger.warning("verify_id_token failed: RevokedIdTokenError: %s", repr(e))
        raise HTTPException(status_code=401, detail={"error": "revoked_id_token", "message": str(e)})

    except auth.InvalidIdTokenError as e:
        # This is the common bucket for: bad signature, wrong project/aud/iss, malformed token, etc.
        logger.warning("verify_id_token failed: InvalidIdTokenError: %s", repr(e))
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_id_token", "message": str(e), "type": e.__class__.__name__},
        )

    except fb_exceptions.FirebaseError as e:
        # Catches broader Firebase Admin errors (credential, transport, etc.)
        logger.exception("verify_id_token failed: FirebaseError")
        raise HTTPException(
            status_code=500,
            detail={"error": "firebase_error", "message": str(e), "type": e.__class__.__name__},
        )

    except Exception as e:
        logger.exception("verify_id_token failed: Unexpected error")
        raise HTTPException(
            status_code=500,
            detail={"error": "unexpected_error", "message": str(e), "type": e.__class__.__name__},
        )


@app.get("/debug-token")
def debug_token(authorization: str | None = Header(default=None)):
    """
    TEMP endpoint for debugging.
    Returns decoded JWT header/payload WITHOUT verifying signature.
    Remove after debugging.
    """
    token = _extract_bearer_token(authorization)
    try:
        return decode_jwt_no_verify(token)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={"error": "cannot_decode_token", "message": str(e), "type": e.__class__.__name__},
        )


@app.get("/me")
def me(user=Depends(get_current_user)):
    return {
        "uid": user.get("uid"),
        "email": user.get("email"),
        "provider": user.get("firebase", {}).get("sign_in_provider"),
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "expected_firebase_project_id": EXPECTED_FIREBASE_PROJECT_ID,
    }


@app.get("/profile")
async def profile(user=Depends(get_current_user)):
    return {
        "message": "Secure profile",
        "uid": user["uid"],
        "email": user.get("email"),
    }