from __future__ import annotations

import os

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from app.audit import write_audit_log
from app.common import get_client_ip, utc_now
from app.core.config import settings
from app.dependencies import require_authenticated_user
from app.firebase_admin_init import auth as firebase_auth, init_firebase_admin
from app.schemas.system import (
    ProfileDeleteRequest,
    ProfileDeleteResponse,
    ProfileLearningStateUpdateRequest,
    ProfilePreferencesUpdateRequest,
    ProfileResponse,
    ProfileUpdateRequest,
)
from app.services.account_deletion_service import delete_user_account
from app.services.user_security_service import (
    build_user_profile_summary,
    update_user_learning_state,
    update_user_preferences,
    update_user_profile,
)

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


@router.get("/profile", response_model=ProfileResponse)
def profile(user=Depends(require_authenticated_user)):
    u = user or {}
    return {
        "ok": True,
        **build_user_profile_summary(
            u.get("uid"),
            email=u.get("email"),
            role=u.get("role"),
            email_verified=u.get("email_verified"),
        ),
        "utc": utc_now(),
    }


@router.patch("/profile", response_model=ProfileResponse)
def update_profile(
    request: Request,
    payload: ProfileUpdateRequest = Body(...),
    user=Depends(require_authenticated_user),
):
    u = user or {}
    uid = str(u.get("uid") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    updated = update_user_profile(
        uid,
        display_name=payload.display_name,
        email=u.get("email"),
        role=u.get("role"),
        email_verified=u.get("email_verified"),
    )

    try:
        init_firebase_admin()
        firebase_auth.update_user(uid, display_name=payload.display_name)
    except Exception:
        pass

    write_audit_log(
        event_type="user.profile.update",
        actor_uid=uid,
        actor_email=u.get("email"),
        role=u.get("role"),
        path="/profile",
        method="PATCH",
        status=200,
        request_id=getattr(request.state, "request_id", None) if request else None,
        ip=get_client_ip(request) if request else None,
        user_agent=request.headers.get("User-Agent") if request else None,
        details={"display_name": updated.get("display_name")},
    )

    return {
        "ok": True,
        **build_user_profile_summary(
            uid,
            email=u.get("email"),
            role=u.get("role"),
            email_verified=u.get("email_verified"),
        ),
        "utc": utc_now(),
    }


@router.patch("/profile/preferences", response_model=ProfileResponse)
def update_profile_preferences(
    request: Request,
    payload: ProfilePreferencesUpdateRequest = Body(...),
    user=Depends(require_authenticated_user),
):
    u = user or {}
    uid = str(u.get("uid") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    updated = update_user_preferences(
        uid,
        favorite_modules=payload.favorite_modules,
        favorite_lessons=payload.favorite_lessons,
        email=u.get("email"),
        role=u.get("role"),
        email_verified=u.get("email_verified"),
    )

    write_audit_log(
        event_type="user.profile.preferences.update",
        actor_uid=uid,
        actor_email=u.get("email"),
        role=u.get("role"),
        path="/profile/preferences",
        method="PATCH",
        status=200,
        request_id=getattr(request.state, "request_id", None) if request else None,
        ip=get_client_ip(request) if request else None,
        user_agent=request.headers.get("User-Agent") if request else None,
        details={
            "favorite_modules_count": len(updated.get("preferences", {}).get("favorite_modules", []))
            if isinstance(updated.get("preferences"), dict)
            else 0,
            "favorite_lessons_count": len(updated.get("preferences", {}).get("favorite_lessons", []))
            if isinstance(updated.get("preferences"), dict)
            else 0,
        },
    )

    return {
        "ok": True,
        **build_user_profile_summary(
            uid,
            email=u.get("email"),
            role=u.get("role"),
            email_verified=u.get("email_verified"),
        ),
        "utc": utc_now(),
    }


@router.patch("/profile/learning-state", response_model=ProfileResponse)
def update_profile_learning_state(
    request: Request,
    payload: ProfileLearningStateUpdateRequest = Body(...),
    user=Depends(require_authenticated_user),
):
    u = user or {}
    uid = str(u.get("uid") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    updated = update_user_learning_state(
        uid,
        last_module_id=payload.last_module_id,
        last_lesson_id=payload.last_lesson_id,
        last_lesson_title=payload.last_lesson_title,
        last_route=payload.last_route,
        email=u.get("email"),
        role=u.get("role"),
        email_verified=u.get("email_verified"),
    )

    learning_state = updated.get("learning_state") if isinstance(updated.get("learning_state"), dict) else {}

    write_audit_log(
        event_type="user.profile.learning_state.update",
        actor_uid=uid,
        actor_email=u.get("email"),
        role=u.get("role"),
        path="/profile/learning-state",
        method="PATCH",
        status=200,
        request_id=getattr(request.state, "request_id", None) if request else None,
        ip=get_client_ip(request) if request else None,
        user_agent=request.headers.get("User-Agent") if request else None,
        details={
            "last_module_id": learning_state.get("last_module_id"),
            "last_lesson_id": learning_state.get("last_lesson_id"),
            "last_route": learning_state.get("last_route"),
        },
    )

    return {
        "ok": True,
        **build_user_profile_summary(
            uid,
            email=u.get("email"),
            role=u.get("role"),
            email_verified=u.get("email_verified"),
        ),
        "utc": utc_now(),
    }


@router.post("/profile/delete", response_model=ProfileDeleteResponse)
def delete_profile(
    payload: ProfileDeleteRequest,
    request: Request,
    user=Depends(require_authenticated_user),
):
    u = user or {}
    uid = str(u.get("uid") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Missing uid")

    if str(payload.confirm_text or "").strip().upper() != "DELETE":
        raise HTTPException(status_code=400, detail='Type "DELETE" to confirm account deletion.')

    deleted = delete_user_account(uid)

    write_audit_log(
        event_type="user.profile.delete",
        actor_uid=uid,
        actor_email=u.get("email"),
        role=u.get("role"),
        path="/profile/delete",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "firebase_auth_deleted": deleted.get("firebase_auth_deleted"),
            "progress_documents_deleted": deleted.get("progress_documents_deleted"),
            "progress_events_deleted": deleted.get("progress_events_deleted"),
            "help_requests_deleted": deleted.get("help_requests_deleted"),
            "sessions_deleted": deleted.get("sessions_deleted"),
        },
    )

    return {
        "ok": True,
        "deleted": deleted,
        "utc": utc_now(),
    }
