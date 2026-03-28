from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.db.firestore import get_firestore_client
from app.roles import normalize_role, VALID_ROLES


USER_COLLECTION = "users"
PASSWORD_POLICY_VERSION = 1


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _string(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _user_ref(uid: str):
    return get_firestore_client().collection(USER_COLLECTION).document(uid)


def read_user_doc(uid: str) -> Dict[str, Any]:
    normalized_uid = _string(uid)
    if not normalized_uid:
        return {}

    snapshot = _user_ref(normalized_uid).get()
    return snapshot.to_dict() if snapshot.exists else {}


def ensure_user_profile(
    uid: str,
    *,
    email: Optional[str] = None,
    role: Optional[str] = None,
    email_verified: Optional[bool] = None,
) -> Dict[str, Any]:
    normalized_uid = _string(uid)
    if not normalized_uid:
        return {}

    current = read_user_doc(normalized_uid)
    current_role = normalize_role(_string(current.get("role")), default="")
    normalized_role = normalize_role(_string(role), default="")
    now_iso = _utc_now_iso()

    patch: Dict[str, Any] = {
        "uid": normalized_uid,
        "updated_utc": now_iso,
        "last_seen_utc": now_iso,
    }

    normalized_email = _string(email)
    if normalized_email:
        patch["email"] = normalized_email

    if not _string(current.get("created_utc")):
        patch["created_utc"] = now_iso

    if current_role not in VALID_ROLES and normalized_role in VALID_ROLES:
        patch["role"] = normalized_role

    security_row = current.get("security") if isinstance(current.get("security"), dict) else {}
    security_patch: Dict[str, Any] = {}
    if email_verified is True:
        security_patch["email_verified_utc"] = _string(security_row.get("email_verified_utc")) or now_iso

    if not security_row:
        security_patch["password_policy_version"] = int(security_row.get("password_policy_version") or 0)

    if security_patch:
        patch["security"] = security_patch

    _user_ref(normalized_uid).set(patch, merge=True)
    return read_user_doc(normalized_uid)


def build_user_security_summary(uid: str, *, email_verified: Optional[bool] = None) -> Dict[str, Any]:
    user_doc = read_user_doc(uid)
    security_row = user_doc.get("security") if isinstance(user_doc.get("security"), dict) else {}

    try:
        password_policy_version = int(security_row.get("password_policy_version") or 0)
    except Exception:
        password_policy_version = 0

    strong_password_confirmed_utc = _string(security_row.get("strong_password_confirmed_utc"))
    email_verified_utc = _string(security_row.get("email_verified_utc"))
    email_verified_flag = bool(email_verified)
    strong_password_confirmed = (
        password_policy_version >= PASSWORD_POLICY_VERSION and bool(strong_password_confirmed_utc)
    )
    hardening_complete = strong_password_confirmed and email_verified_flag

    recommended_actions: list[str] = []
    if not strong_password_confirmed:
        recommended_actions.append("upgrade_password")
    if not email_verified_flag:
        recommended_actions.append("verify_email")
    if hardening_complete:
        recommended_actions.append("enable_2fa")

    recommended_next_step = recommended_actions[0] if recommended_actions else None

    return {
        "password_policy_version": password_policy_version,
        "password_policy_target_version": PASSWORD_POLICY_VERSION,
        "strong_password_confirmed": strong_password_confirmed,
        "strong_password_confirmed_utc": strong_password_confirmed_utc,
        "email_verified": email_verified_flag,
        "email_verified_utc": email_verified_utc,
        "hardening_complete": hardening_complete,
        "recommended_actions": recommended_actions,
        "recommended_next_step": recommended_next_step,
    }


def record_password_policy_completion(
    uid: str,
    *,
    password_policy_version: int,
    email: Optional[str] = None,
    role: Optional[str] = None,
    email_verified: Optional[bool] = None,
) -> Dict[str, Any]:
    normalized_uid = _string(uid)
    if not normalized_uid:
        return build_user_security_summary("", email_verified=email_verified)

    ensure_user_profile(
        normalized_uid,
        email=email,
        role=role,
        email_verified=email_verified,
    )

    effective_version = max(PASSWORD_POLICY_VERSION, int(password_policy_version or 0))
    now_iso = _utc_now_iso()
    security_patch: Dict[str, Any] = {
        "password_policy_version": effective_version,
        "strong_password_confirmed_utc": now_iso,
    }
    if email_verified is True:
        existing_summary = build_user_security_summary(normalized_uid, email_verified=email_verified)
        security_patch["email_verified_utc"] = existing_summary.get("email_verified_utc") or now_iso

    patch: Dict[str, Any] = {
        "updated_utc": now_iso,
        "security": security_patch,
    }
    normalized_email = _string(email)
    if normalized_email:
        patch["email"] = normalized_email

    _user_ref(normalized_uid).set(patch, merge=True)
    return build_user_security_summary(normalized_uid, email_verified=email_verified)
