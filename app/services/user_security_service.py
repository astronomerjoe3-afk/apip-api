from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.db.firestore import get_firestore_client
from app.roles import normalize_role, VALID_ROLES


USER_COLLECTION = "users"
PASSWORD_POLICY_VERSION = 1
DISPLAY_NAME_MAX_LENGTH = 120
LESSON_TITLE_MAX_LENGTH = 160
ROUTE_MAX_LENGTH = 256
PREFERENCE_LIMIT = 200
PREFERENCE_VALUE_MAX_LENGTH = 96


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _string(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _display_name(value: Any) -> Optional[str]:
    text = _string(value)
    if text is None:
        return None
    return text[:DISPLAY_NAME_MAX_LENGTH]


def _string_list(value: Any, *, max_items: int = PREFERENCE_LIMIT, max_length: int = PREFERENCE_VALUE_MAX_LENGTH) -> list[str]:
    if not isinstance(value, list):
        return []

    seen: set[str] = set()
    items: list[str] = []
    for raw in value:
        text = _string(raw)
        if not text:
            continue
        text = text[:max_length]
        if text in seen:
            continue
        seen.add(text)
        items.append(text)
        if len(items) >= max_items:
            break
    return items


def _student_preferences(value: Any) -> Dict[str, list[str]]:
    row = value if isinstance(value, dict) else {}
    return {
        "favorite_modules": _string_list(row.get("favorite_modules")),
        "favorite_lessons": _string_list(row.get("favorite_lessons")),
    }


def _student_learning_state(value: Any) -> Dict[str, Optional[str]]:
    row = value if isinstance(value, dict) else {}
    lesson_title = _string(row.get("last_lesson_title"))

    last_route = _string(row.get("last_route"))
    if last_route and not last_route.startswith("/student"):
        last_route = None

    return {
        "last_module_id": _string(row.get("last_module_id")),
        "last_lesson_id": _string(row.get("last_lesson_id")),
        "last_lesson_title": lesson_title[:LESSON_TITLE_MAX_LENGTH] if lesson_title else None,
        "last_route": last_route[:ROUTE_MAX_LENGTH] if last_route else None,
        "last_visited_utc": _string(row.get("last_visited_utc")),
    }


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
    display_name: Optional[str] = None,
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

    normalized_display_name = _display_name(display_name)
    if normalized_display_name:
        patch["display_name"] = normalized_display_name

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


def update_user_profile(
    uid: str,
    *,
    display_name: Optional[str] = None,
    email: Optional[str] = None,
    role: Optional[str] = None,
    email_verified: Optional[bool] = None,
) -> Dict[str, Any]:
    normalized_uid = _string(uid)
    if not normalized_uid:
        return {}

    now_iso = _utc_now_iso()
    patch: Dict[str, Any] = {
        "updated_utc": now_iso,
        "last_seen_utc": now_iso,
    }

    normalized_display_name = _display_name(display_name)
    if normalized_display_name is not None:
        patch["display_name"] = normalized_display_name

    normalized_email = _string(email)
    if normalized_email:
        patch["email"] = normalized_email

    normalized_role = normalize_role(_string(role), default="")
    if normalized_role in VALID_ROLES:
        patch["role"] = normalized_role

    if email_verified is True:
        current = read_user_doc(normalized_uid)
        security_row = current.get("security") if isinstance(current.get("security"), dict) else {}
        patch["security"] = {
            "email_verified_utc": _string(security_row.get("email_verified_utc")) or now_iso,
        }

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


def build_user_preferences_summary(uid: str) -> Dict[str, list[str]]:
    user_doc = read_user_doc(uid)
    return _student_preferences(user_doc.get("preferences"))


def build_user_learning_state_summary(uid: str) -> Dict[str, Optional[str]]:
    user_doc = read_user_doc(uid)
    return _student_learning_state(user_doc.get("learning_state"))


def build_user_profile_summary(
    uid: str,
    *,
    email: Optional[str] = None,
    role: Optional[str] = None,
    email_verified: Optional[bool] = None,
) -> Dict[str, Any]:
    normalized_uid = _string(uid) or ""
    user_doc = read_user_doc(normalized_uid)
    security_row = user_doc.get("security") if isinstance(user_doc.get("security"), dict) else {}

    resolved_email_verified = (
        bool(email_verified)
        if email_verified is not None
        else bool(_string(security_row.get("email_verified_utc")))
    )
    resolved_role = normalize_role(
        _string(user_doc.get("role")) or _string(role),
        default="unknown",
    )

    return {
        "uid": _string(user_doc.get("uid")) or normalized_uid,
        "email": _string(user_doc.get("email")) or _string(email),
        "display_name": _display_name(user_doc.get("display_name")),
        "email_verified": resolved_email_verified,
        "role": resolved_role or "unknown",
        "security": build_user_security_summary(
            normalized_uid,
            email_verified=resolved_email_verified,
        ),
        "preferences": _student_preferences(user_doc.get("preferences")),
        "learning_state": _student_learning_state(user_doc.get("learning_state")),
    }


def update_user_preferences(
    uid: str,
    *,
    favorite_modules: Optional[list[str]] = None,
    favorite_lessons: Optional[list[str]] = None,
    email: Optional[str] = None,
    role: Optional[str] = None,
    email_verified: Optional[bool] = None,
) -> Dict[str, Any]:
    normalized_uid = _string(uid)
    if not normalized_uid:
        return {}

    ensure_user_profile(
        normalized_uid,
        email=email,
        role=role,
        email_verified=email_verified,
    )

    now_iso = _utc_now_iso()
    patch: Dict[str, Any] = {
        "updated_utc": now_iso,
        "last_seen_utc": now_iso,
        "preferences": {
            "favorite_modules": _string_list(favorite_modules),
            "favorite_lessons": _string_list(favorite_lessons),
        },
    }

    _user_ref(normalized_uid).set(patch, merge=True)
    return read_user_doc(normalized_uid)


def update_user_learning_state(
    uid: str,
    *,
    last_module_id: Optional[str] = None,
    last_lesson_id: Optional[str] = None,
    last_lesson_title: Optional[str] = None,
    last_route: Optional[str] = None,
    email: Optional[str] = None,
    role: Optional[str] = None,
    email_verified: Optional[bool] = None,
) -> Dict[str, Any]:
    normalized_uid = _string(uid)
    if not normalized_uid:
        return {}

    ensure_user_profile(
        normalized_uid,
        email=email,
        role=role,
        email_verified=email_verified,
    )

    normalized_route = _string(last_route)
    if normalized_route and not normalized_route.startswith("/student"):
        normalized_route = None
    normalized_lesson_title = _string(last_lesson_title)

    now_iso = _utc_now_iso()
    patch: Dict[str, Any] = {
        "updated_utc": now_iso,
        "last_seen_utc": now_iso,
        "learning_state": {
            "last_module_id": _string(last_module_id),
            "last_lesson_id": _string(last_lesson_id),
            "last_lesson_title": normalized_lesson_title[:LESSON_TITLE_MAX_LENGTH] if normalized_lesson_title else None,
            "last_route": normalized_route[:ROUTE_MAX_LENGTH] if normalized_route else None,
            "last_visited_utc": now_iso,
        },
    }

    _user_ref(normalized_uid).set(patch, merge=True)
    return read_user_doc(normalized_uid)


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
