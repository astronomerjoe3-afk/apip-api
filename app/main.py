from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import firebase_admin
from firebase_admin import auth, credentials

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level="INFO")
logger = logging.getLogger("apip-api")

FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")

app = FastAPI(title="apip-api", version="1.0.0")

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

# -----------------------------
# Firebase Admin Init
# -----------------------------
if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)
    logger.info("Firebase Admin initialized")


# -----------------------------
# Helpers
# -----------------------------
def _extract_token(auth_header: Optional[str]) -> str:
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return auth_header.split(" ", 1)[1]


def get_current_user(authorization: str | None = Header(default=None)) -> Dict[str, Any]:
    token = _extract_token(authorization)
    try:
        decoded = auth.verify_id_token(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

    if FIREBASE_PROJECT_ID:
        expected_iss = f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}"
        if decoded.get("aud") != FIREBASE_PROJECT_ID or decoded.get("iss") != expected_iss:
            raise HTTPException(status_code=401, detail="Firebase project mismatch")

    return decoded


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin required")
    return user


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# -----------------------------
# Firestore (optional mirror)
# -----------------------------
def get_firestore():
    try:
        from google.cloud import firestore
        return firestore.Client(project=FIREBASE_PROJECT_ID or None)
    except Exception:
        return None


# -----------------------------
# Models
# -----------------------------
class RoleBody(BaseModel):
    role: str


# -----------------------------
# Routes
# -----------------------------
@app.get("/health")
def health():
    return {"status": "ok", "firebase_project_id": FIREBASE_PROJECT_ID}


@app.get("/me")
def me(user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "uid": user.get("uid") or user.get("sub"),
        "email": user.get("email"),
        "role": user.get("role"),
    }


@app.get("/profile")
def profile(user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "message": "Secure profile",
        "uid": user.get("uid") or user.get("sub"),
        "email": user.get("email"),
        "role": user.get("role"),
    }


# -----------------------------
# ADMIN: Set Role
# -----------------------------
@app.post("/admin/users/{uid}/role")
def set_role(
    uid: str,
    body: RoleBody,
    admin_user: Dict[str, Any] = Depends(require_admin),
):
    role = body.role.strip().lower()
    if role not in {"admin", "user"}:
        raise HTTPException(status_code=400, detail="Invalid role")

    auth.set_custom_user_claims(uid, {"role": role})

    # Mirror to Firestore (optional)
    db = get_firestore()
    if db:
        db.collection("users").document(uid).set(
            {
                "uid": uid,
                "role": role,
                "updatedAt": now_iso(),
                "updatedBy": admin_user.get("uid"),
            },
            merge=True,
        )

    return {
        "ok": True,
        "uid": uid,
        "role_set_to": role,
    }


# -----------------------------
# ADMIN: List Users (Firestore)
# -----------------------------
@app.get("/admin/users")
def list_users(admin_user: Dict[str, Any] = Depends(require_admin)):
    db = get_firestore()
    if not db:
        return {"error": "Firestore not available"}

    users = []
    for doc in db.collection("users").stream():
        data = doc.to_dict()
        users.append(data)

    return {"count": len(users), "users": users}


# -----------------------------
# ADMIN: Get One User
# -----------------------------
@app.get("/admin/users/{uid}")
def get_user(uid: str, admin_user: Dict[str, Any] = Depends(require_admin)):
    db = get_firestore()
    if not db:
        return {"error": "Firestore not available"}

    doc = db.collection("users").document(uid).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found")

    return doc.to_dict()