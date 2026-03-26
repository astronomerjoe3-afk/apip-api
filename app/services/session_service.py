from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request

from app.common import get_client_ip, sha256_hex
from app.core.config import settings
from app.db.firestore import get_firestore_client
from app.firebase_admin_init import verify_id_token


SESSION_TOKEN_PREFIX = "sess_"
SESSION_COLLECTION = "auth_sessions"
VALID_ROLES = {"student", "instructor", "admin"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _string(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _user_agent_hash(user_agent: Optional[str]) -> Optional[str]:
    normalized = _string(user_agent)
    if not normalized:
        return None
    return sha256_hex(normalized[:512])


def _session_ref(token_hash: str):
    return get_firestore_client().collection(SESSION_COLLECTION).document(token_hash)


def _normalized_role(decoded: Dict[str, Any], uid: str) -> str:
    from app.dependencies import _role_from_user_doc

    role = _string(decoded.get("role"))
    if role in VALID_ROLES:
        return role
    return _role_from_user_doc(uid) or "student"


def _normalized_user_claims(decoded: Dict[str, Any]) -> Dict[str, Any]:
    uid = decoded.get("uid") or decoded.get("user_id") or decoded.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Token missing uid")

    role = _normalized_role(decoded, str(uid))
    claims = dict(decoded)
    claims["role"] = role
    return {
        "uid": str(uid),
        "email": decoded.get("email"),
        "email_verified": decoded.get("email_verified"),
        "role": role,
        "claims": claims,
    }


def issue_session_from_firebase_id_token(id_token: str, request: Request) -> Dict[str, Any]:
    normalized_token = _string(id_token)
    if not normalized_token:
        raise HTTPException(status_code=400, detail="id_token is required")

    try:
        decoded = verify_id_token(normalized_token, check_revoked=True)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = _normalized_user_claims(decoded)
    now = _utc_now()
    expires_at = now + timedelta(hours=max(1, settings.session_ttl_hours))
    raw_token = SESSION_TOKEN_PREFIX + secrets.token_urlsafe(48)
    token_hash = sha256_hex(raw_token)
    user_agent = request.headers.get("User-Agent")

    _session_ref(token_hash).set(
        {
            "uid": user["uid"],
            "email": user.get("email"),
            "email_verified": bool(user.get("email_verified")),
            "role": user["role"],
            "claims": user["claims"],
            "created_utc": now.isoformat(),
            "updated_utc": now.isoformat(),
            "expires_utc": expires_at.isoformat(),
            "revoked": False,
            "ip": get_client_ip(request),
            "user_agent_hash": _user_agent_hash(user_agent),
            "last_seen_utc": now.isoformat(),
        },
        merge=True,
    )

    return {
        "session_token": raw_token,
        "expires_utc": expires_at.isoformat(),
        "user": {
            "uid": user["uid"],
            "email": user.get("email"),
            "email_verified": user.get("email_verified"),
            "role": user["role"],
        },
    }


def _read_session(token: str) -> Dict[str, Any]:
    normalized_token = _string(token)
    if not normalized_token or not normalized_token.startswith(SESSION_TOKEN_PREFIX):
        raise HTTPException(status_code=401, detail="Invalid session token")

    snapshot = _session_ref(sha256_hex(normalized_token)).get()
    if not snapshot.exists:
        raise HTTPException(status_code=401, detail="Unknown session")

    data = snapshot.to_dict() or {}
    if data.get("revoked") is True:
        raise HTTPException(status_code=401, detail="Session revoked")

    expires_raw = _string(data.get("expires_utc"))
    try:
        expires_at = datetime.fromisoformat(expires_raw) if expires_raw else None
    except Exception:
        expires_at = None
    if expires_at is None or expires_at <= _utc_now():
        raise HTTPException(status_code=401, detail="Session expired")

    return data


def authenticate_session_token(token: str, request: Request) -> Dict[str, Any]:
    session = _read_session(token)
    expected_ua_hash = _string(session.get("user_agent_hash"))
    current_ua_hash = _user_agent_hash(request.headers.get("User-Agent"))
    if expected_ua_hash and current_ua_hash and expected_ua_hash != current_ua_hash:
        raise HTTPException(status_code=401, detail="Session fingerprint mismatch")

    now = _utc_now()
    last_seen_raw = _string(session.get("last_seen_utc"))
    should_refresh = True
    if last_seen_raw:
        try:
            last_seen = datetime.fromisoformat(last_seen_raw)
            should_refresh = (now - last_seen) >= timedelta(
                minutes=max(1, settings.session_idle_refresh_minutes)
            )
        except Exception:
            should_refresh = True

    if should_refresh:
        _session_ref(sha256_hex(token)).set(
            {
                "last_seen_utc": now.isoformat(),
                "updated_utc": now.isoformat(),
            },
            merge=True,
        )

    claims = session.get("claims") if isinstance(session.get("claims"), dict) else {}
    return {
        "uid": session.get("uid"),
        "email": session.get("email"),
        "email_verified": session.get("email_verified"),
        "role": session.get("role") or "student",
        "claims": claims,
        "auth_type": "session",
    }


def revoke_session_token(token: str) -> None:
    normalized_token = _string(token)
    if not normalized_token or not normalized_token.startswith(SESSION_TOKEN_PREFIX):
        return

    _session_ref(sha256_hex(normalized_token)).set(
        {
            "revoked": True,
            "revoked_utc": _utc_now_iso(),
            "updated_utc": _utc_now_iso(),
        },
        merge=True,
    )
