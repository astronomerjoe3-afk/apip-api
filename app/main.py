from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import firebase_admin
from firebase_admin import auth, credentials
from firebase_admin import exceptions as fb_exceptions

from google.cloud import firestore


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger("apip-api")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

# -----------------------------------------------------------------------------
# App
# -----------------------------------------------------------------------------
app = FastAPI(title="apip-api", version="0.1.0")

# -----------------------------------------------------------------------------
# CORS
# -----------------------------------------------------------------------------
ALLOW_ORIGINS = os.getenv(
    "CORS_ALLOW_ORIGINS",
    "https://app.cognispark.tech,http://localhost:3000",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOW_ORIGINS if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Firebase Admin init (Cloud Run-friendly)
# -----------------------------------------------------------------------------
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")

if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()
    options = {"projectId": FIREBASE_PROJECT_ID} if FIREBASE_PROJECT_ID else None
    firebase_admin.initialize_app(cred, options=options)

# -----------------------------------------------------------------------------
# Firestore client
# -----------------------------------------------------------------------------
# Uses ADC under the hood on Cloud Run. If FIREBASE_PROJECT_ID is set, we pass it.
FS_PROJECT_ID = FIREBASE_PROJECT_ID or os.getenv("GOOGLE_CLOUD_PROJECT")
db = firestore.Client(project=FS_PROJECT_ID) if FS_PROJECT_ID else firestore.Client()


# -----------------------------------------------------------------------------
# Optional debug token decoder
# -----------------------------------------------------------------------------
try:
    from app.token_debug import decode_jwt_no_verify
except Exception:  # pragma: no cover
    decode_jwt_no_verify = None  # type: ignore


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return authorization.split(" ", 1)[1].strip()


def _claims(decoded: Dict[str, Any]) -> Dict[str, Any]:
    role = decoded.get("role")
    return {
        "uid": decoded.get("uid"),
        "email": decoded.get("email"),
        "role": role,
        "firebase": decoded.get("firebase", {}),
        "aud": decoded.get("aud"),
        "iss": decoded.get("iss"),
    }


def _require_role(decoded: Dict[str, Any], required_role: str) -> None:
    role = decoded.get("role")
    if role != required_role:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "forbidden",
                "required_role": required_role,
                "got_role": role,
            },
        )


def upsert_user_doc(decoded: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create/update users/{uid} in Firestore.
    - Creates on first login
    - Updates last_login_at each time
    - Stores role + email for easy querying
    - Includes placeholders for the Physics curriculum architecture
    """
    c = _claims(decoded)
    uid = c["uid"]
    if not uid:
        raise HTTPException(status_code=500, detail="Token missing uid")

    user_ref = db.collection("users").document(uid)
    snap = user_ref.get()

    now_iso = datetime.now(timezone.utc).isoformat()

    base_data = {
        "uid": uid,
        "email": c["email"],
        "role": c["role"] or "user",
        "updated_at": firestore.SERVER_TIMESTAMP,
        "last_login_at": firestore.SERVER_TIMESTAMP,
        "last_login_at_iso": now_iso,  # convenient for debugging
        # --- Physics product architecture fields (extend later) ---
        "product": "best-way-to-learn-physics",
        "curriculum": {
            "curriculum_id": "physics-core-v1",
            "current_unit": None,
            "current_lesson": None,
            "progress_pct": 0,
        },
        "profile": {
            "display_name": None,
            "goal_band": None,
        },
    }

    if not snap.exists:
        # First login
        first_data = {
            **base_data,
            "created_at": firestore.SERVER_TIMESTAMP,
            "created_at_iso": now_iso,
        }
        user_ref.set(first_data, merge=True)
        return {"created": True, "uid": uid}

    # Existing user
    user_ref.set(base_data, merge=True)
    return {"created": False, "uid": uid}


# -----------------------------------------------------------------------------
# Auth dependency
# -----------------------------------------------------------------------------
def get_current_user(authorization: str | None = Header(default=None)) -> Dict[str, Any]:
    token = _extract_bearer_token(authorization)

    # Optional debug logging only
    if decode_jwt_no_verify is not None:
        try:
            unverified = decode_jwt_no_verify(token)
            hdr = unverified.get("header") or {}
            coi = unverified.get("claims_of_interest") or {}
            logger.info(
                "Incoming token (unverified) aud=%s iss=%s sub=%s kid=%s provider=%s",
                coi.get("aud"),
                coi.get("iss"),
                coi.get("sub"),
                hdr.get("kid"),
                coi.get("firebase.sign_in_provider"),
            )
        except Exception as e:
            logger.warning("Token debug decode failed (ignored): %r", e)

    try:
        decoded = auth.verify_id_token(token)

        # Guardrail: ensure project matches expected project id
        if FIREBASE_PROJECT_ID:
            expected_aud = FIREBASE_PROJECT_ID
            expected_iss = f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}"
            if decoded.get("aud") != expected_aud or decoded.get("iss") != expected_iss:
                raise HTTPException(
                    status_code=401,
                    detail={
                        "error": "firebase_project_mismatch",
                        "expected": {"aud": expected_aud, "iss": expected_iss},
                        "got": {"aud": decoded.get("aud"), "iss": decoded.get("iss")},
                    },
                )

        return decoded

    except auth.ExpiredIdTokenError as e:
        raise HTTPException(
            status_code=401,
            detail={"error": "expired_id_token", "message": str(e), "type": e.__class__.__name__},
        )

    except auth.RevokedIdTokenError as e:
        raise HTTPException(
            status_code=401,
            detail={"error": "revoked_id_token", "message": str(e), "type": e.__class__.__name__},
        )

    except auth.InvalidIdTokenError as e:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_id_token", "message": str(e), "type": e.__class__.__name__},
        )

    except fb_exceptions.FirebaseError as e:
        logger.exception("Firebase Admin error during verify_id_token")
        raise HTTPException(
            status_code=500,
            detail={"error": "firebase_error", "message": str(e), "type": e.__class__.__name__},
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.exception("Unexpected error during verify_id_token")
        raise HTTPException(
            status_code=500,
            detail={"error": "unexpected_error", "message": str(e), "type": e.__class__.__name__},
        )


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    _require_role(user, "admin")
    return user


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "firebase_project_id": FIREBASE_PROJECT_ID}


@app.get("/me")
def me(user: Dict[str, Any] = Depends(get_current_user)):
    # Auto-provision user doc on ANY authenticated hit
    provision = upsert_user_doc(user)

    c = _claims(user)
    return {
        "uid": c["uid"],
        "email": c["email"],
        "role": c["role"],
        "provider": (c["firebase"] or {}).get("sign_in_provider"),
        "provisioned": provision,
    }


@app.get("/profile")
def profile(user: Dict[str, Any] = Depends(get_current_user)):
    # Auto-provision here too (in case you prefer using /profile on the client)
    provision = upsert_user_doc(user)

    c = _claims(user)
    return {
        "message": "Secure profile",
        "uid": c["uid"],
        "email": c["email"],
        "role": c["role"],
        "provisioned": provision,
    }


@app.get("/admin-only")
def admin_only(user: Dict[str, Any] = Depends(require_admin)):
    # Optional: ensure admin users also get provisioned
    provision = upsert_user_doc(user)

    c = _claims(user)
    return {
        "message": "Admin access granted",
        "uid": c["uid"],
        "email": c["email"],
        "role": c["role"],
        "provisioned": provision,
    }


@app.get("/debug-token")
def debug_token(authorization: str | None = Header(default=None)):
    """
    TEMP endpoint for debugging only.
    Returns decoded JWT header/payload WITHOUT verifying signature.
    Remove after debugging.
    """
    if decode_jwt_no_verify is None:
        raise HTTPException(status_code=404, detail="debug-token not enabled")
    token = _extract_bearer_token(authorization)
    return decode_jwt_no_verify(token)