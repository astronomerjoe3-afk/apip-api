import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import firebase_admin
from firebase_admin import auth, credentials

# Firestore is optional (but enabled in your project now)
try:
    from google.cloud import firestore  # type: ignore
except Exception:
    firestore = None  # type: ignore


APP_COMMIT = os.getenv("APP_COMMIT", "dev")
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT")
ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")


def init_firebase() -> None:
    """Initialize Firebase Admin once per process."""
    if firebase_admin._apps:
        return

    cred = credentials.ApplicationDefault()

    # IMPORTANT:
    # - In Cloud Run: ADC works automatically via service account.
    # - Providing projectId avoids "audience mismatch" / missing project id errors.
    opts: Dict[str, Any] = {}
    if FIREBASE_PROJECT_ID:
        opts["projectId"] = FIREBASE_PROJECT_ID

    firebase_admin.initialize_app(cred, opts)


def get_firestore():
    """Return firestore client or None if not available."""
    if firestore is None:
        return None
    # Firestore client will use ADC + project from env/options.
    # If FIREBASE_PROJECT_ID is set, pass it explicitly to be safe.
    try:
        if FIREBASE_PROJECT_ID:
            return firestore.Client(project=FIREBASE_PROJECT_ID)
        return firestore.Client()
    except Exception:
        return None


def _extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Malformed Authorization header. Use: Bearer <token>")
    return parts[1].strip()


def verify_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """
    Verifies Firebase ID token and returns a dict:
      uid, email, role, provider, aud, iss, claims
    """
    init_firebase()
    token = _extract_bearer_token(authorization)

    try:
        decoded = auth.verify_id_token(token, check_revoked=False)
    except Exception as e:
        # Keep the error message useful for debugging.
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_id_token", "message": str(e), "type": e.__class__.__name__},
        )

    uid = decoded.get("uid") or decoded.get("sub")
    email = decoded.get("email")
    role = decoded.get("role")  # your custom claim
    firebase_block = decoded.get("firebase", {}) or {}
    provider = firebase_block.get("sign_in_provider")
    aud = decoded.get("aud")
    iss = decoded.get("iss")

    return {
        "uid": uid,
        "email": email,
        "role": role,
        "provider": provider,
        "aud": aud,
        "iss": iss,
        "claims": decoded,
    }


def require_admin(user: Dict[str, Any] = Depends(verify_user)) -> Dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


app = FastAPI(title="apip-api", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS] if ALLOWED_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "firebase_project_id": FIREBASE_PROJECT_ID}


@app.get("/__build")
def build_marker():
    return {
        "app_commit": APP_COMMIT,
        "firebase_project_id": FIREBASE_PROJECT_ID,
        "utc": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/me")
def me(user: Dict[str, Any] = Depends(verify_user)):
    # Minimal introspection payload
    return {
        "uid": user.get("uid"),
        "email": user.get("email"),
        "role": user.get("role"),
        "provider": user.get("provider"),
        "aud": user.get("aud"),
        "iss": user.get("iss"),
    }


@app.get("/profile")
def profile(user: Dict[str, Any] = Depends(verify_user)):
    return {
        "message": "Secure profile",
        "uid": user.get("uid"),
        "email": user.get("email"),
        "role": user.get("role"),
    }


@app.get("/admin-only")
def admin_only(admin_user: Dict[str, Any] = Depends(require_admin)):
    return {
        "message": "Admin access granted",
        "uid": admin_user.get("uid"),
        "email": admin_user.get("email"),
        "role": admin_user.get("role"),
    }


# -----------------------------
# ADMIN: User Management
# -----------------------------

@app.get("/admin/users/{uid}")
def admin_get_user(uid: str, admin_user: Dict[str, Any] = Depends(require_admin)):
    db = get_firestore()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore not available")

    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")

    data = doc.to_dict() or {}
    data["uid"] = uid
    return data


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
    role = (body.get("role") or "").strip()
    if role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")

    init_firebase()

    # 1) Set custom claim on Firebase Auth user
    try:
        auth.set_custom_user_claims(uid, {"role": role})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed setting custom claims: {e}")

    # 2) Also write into Firestore users/{uid} for easy admin UI queries (optional)
    db = get_firestore()
    if db:
        db.collection("users").document(uid).set(
            {
                "uid": uid,
                "role": role,
                "updatedAt": datetime.now(timezone.utc).isoformat(),
                "updatedBy": admin_user.get("uid"),
            },
            merge=True,
        )

    return {"ok": True, "uid": uid, "role": role}