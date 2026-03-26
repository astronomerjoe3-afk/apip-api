from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException

from app.common import utc_now
from app.core.config import settings
from app.dependencies import require_authenticated_user

router = APIRouter(tags=["system"])


@router.get("/health")
def health():
    return {"status": "ok", "utc": utc_now()}


@router.get("/healthz")
def healthz():
    return {"ok": True, "utc": utc_now()}


@router.get("/__build")
@router.get("/_build")
def build():
    if not settings.expose_build_metadata:
        raise HTTPException(status_code=404, detail="Not found")

    app_commit = os.getenv("GIT_COMMIT_SHA") or os.getenv("APP_COMMIT") or "dev"
    project_id = (
        os.getenv("GOOGLE_CLOUD_PROJECT")
        or os.getenv("GCP_PROJECT")
        or os.getenv("GCLOUD_PROJECT")
        or "local"
    )

    return {
        "app_name": "apip-api",
        "app_version": "0.4.0",
        "app_commit": app_commit,
        "firebase_project_id": project_id,
        "service": os.getenv("K_SERVICE"),
        "revision": os.getenv("K_REVISION"),
        "utc": utc_now(),
    }


@router.get("/profile")
def profile(user=Depends(require_authenticated_user)):
    u = user or {}
    return {
        "ok": True,
        "uid": u.get("uid"),
        "email": u.get("email"),
        "email_verified": u.get("email_verified"),
        "role": u.get("role"),
        "utc": utc_now(),
    }
