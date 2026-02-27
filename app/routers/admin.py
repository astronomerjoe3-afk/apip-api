from __future__ import annotations

import datetime as dt
import secrets
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from google.cloud import firestore
from pydantic import BaseModel, Field

from app.audit import build_audit_event, write_audit_event
from app.core.config import settings
from app.db.firestore import get_firestore_client

router = APIRouter(prefix="/admin", tags=["admin"])


# -------------------------
# Auth (minimal + safe)
# -------------------------
def require_admin(request: Request) -> None:
    """
    You should replace this with your existing Firebase custom-claims RBAC dependency.
    This implementation supports:
      1) Firebase auth integration if your middleware sets request.state.actor_role == "admin"
      2) Optional break-glass bearer token (disabled by default)
    """
    # Preferred: upstream auth sets these
    actor_role = getattr(request.state, "actor_role", None)
    if actor_role == "admin":
        return

    # Optional break-glass (explicitly enabled via env)
    if settings.enable_breakglass_admin_token and settings.admin_bearer_token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and auth.removeprefix("Bearer ").strip() == settings.admin_bearer_token:
            request.state.actor_role = "admin"
            request.state.actor_uid = "breakglass"
            return

    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")


# -------------------------
# Models
# -------------------------
class KeyCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    scopes: List[str] = Field(default_factory=list)
    rate_limit_per_minute: int = Field(default=120, ge=1, le=10_000)


class KeyOut(BaseModel):
    key_id: str
    name: str
    status: str
    scopes: List[str]
    created_at_utc: str
    last_used_at_utc: Optional[str] = None
    counters: Dict[str, int] = Field(default_factory=dict)
    rate_limit_per_minute: int


class KeyCreateOut(BaseModel):
    key_id: str
    api_key: str
    doc: KeyOut


# -------------------------
# Helpers
# -------------------------
def _utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _keys_col(client: firestore.Client):
    return client.collection("api_keys")


def _to_key_out(key_id: str, doc: Dict[str, Any]) -> KeyOut:
    return KeyOut(
        key_id=key_id,
        name=str(doc.get("name", "")),
        status=str(doc.get("status", "disabled")),
        scopes=list(doc.get("scopes", [])),
        created_at_utc=str(doc.get("created_at_utc", "")),
        last_used_at_utc=doc.get("last_used_at_utc"),
        counters=dict(doc.get("counters", {}) or {}),
        rate_limit_per_minute=int(doc.get("rate_limit_per_minute", 120)),
    )


def _audit(request: Request, event_type: str, status_code: int, details: Dict[str, Any]) -> None:
    event = build_audit_event(
        event_type=event_type,
        path=str(request.url.path),
        method=request.method,
        status=status_code,
        request_id=request.headers.get("X-Request-Id") or getattr(request.state, "request_id", None),
        actor_uid=getattr(request.state, "actor_uid", None),
        actor_role=getattr(request.state, "actor_role", None),
        key_id=details.get("key_id"),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent"),
        details=details,
    )
    write_audit_event(event)


# -------------------------
# Endpoints
# -------------------------
@router.get("/metrics")
def admin_metrics(request: Request, _: None = Depends(require_admin)) -> Dict[str, Any]:
    """
    Dashboard metrics. Canonical source: Firestore collection `api_keys`.
    """
    client = get_firestore_client()
    docs = list(_keys_col(client).stream())

    total = len(docs)
    enabled = 0
    disabled = 0

    total_requests = 0
    blocked_requests = 0

    for d in docs:
        data = d.to_dict() or {}
        st = str(data.get("status", "disabled")).lower()
        if st == "enabled":
            enabled += 1
        else:
            disabled += 1

        counters = data.get("counters", {}) or {}
        total_requests += int(counters.get("total_requests", 0))
        blocked_requests += int(counters.get("blocked_requests", 0))

    payload = {
        "api_keys": {
            "total": total,
            "enabled": enabled,
            "disabled": disabled,
        },
        "traffic": {
            "total_requests": total_requests,
            "blocked_requests": blocked_requests,
        },
        "build": {
            "git_commit_sha": settings.git_commit_sha,
            "google_cloud_project": settings.google_cloud_project,
            "environment": settings.environment,
        },
        "utc": _utc_now_iso(),
    }

    _audit(request, "admin.metrics.read", 200, {"api_keys_total": total})
    return payload


@router.get("/keys", response_model=List[KeyOut])
def list_keys(request: Request, _: None = Depends(require_admin)) -> List[KeyOut]:
    client = get_firestore_client()
    docs = list(_keys_col(client).stream())
    out: List[KeyOut] = []
    for d in docs:
        out.append(_to_key_out(d.id, d.to_dict() or {}))

    _audit(request, "admin.keys.list", 200, {"count": len(out)})
    return sorted(out, key=lambda x: x.created_at_utc)


@router.get("/keys/{key_id}", response_model=KeyOut)
def get_key(key_id: str, request: Request, _: None = Depends(require_admin)) -> KeyOut:
    client = get_firestore_client()
    snap = _keys_col(client).document(key_id).get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    doc = snap.to_dict() or {}
    _audit(request, "admin.keys.get", 200, {"key_id": key_id})
    return _to_key_out(key_id, doc)


@router.post("/keys", response_model=KeyCreateOut, status_code=201)
def create_key(body: KeyCreateIn, request: Request, _: None = Depends(require_admin)) -> KeyCreateOut:
    client = get_firestore_client()

    # Store only hash in prod if you don’t want plaintext keys in Firestore.
    # For now (dashboard ops), store the generated key in the doc; you can migrate later.
    api_key = secrets.token_urlsafe(32)
    key_id = secrets.token_urlsafe(10)

    doc = {
        "name": body.name,
        "status": "enabled",
        "scopes": body.scopes,
        "rate_limit_per_minute": body.rate_limit_per_minute,
        "created_at_utc": _utc_now_iso(),
        "last_used_at_utc": None,
        "api_key": api_key,
        "counters": {
            "total_requests": 0,
            "blocked_requests": 0,
        },
    }

    _keys_col(client).document(key_id).set(doc)

    _audit(request, "admin.keys.create", 201, {"key_id": key_id, "name": body.name})
    return KeyCreateOut(key_id=key_id, api_key=api_key, doc=_to_key_out(key_id, doc))


@router.post("/keys/{key_id}/enable")
def enable_key(key_id: str, request: Request, _: None = Depends(require_admin)) -> Dict[str, Any]:
    client = get_firestore_client()
    ref = _keys_col(client).document(key_id)
    if not ref.get().exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update({"status": "enabled"})
    _audit(request, "admin.keys.enable", 200, {"key_id": key_id})
    return {"ok": True, "key_id": key_id, "status": "enabled"}


@router.post("/keys/{key_id}/disable")
def disable_key(key_id: str, request: Request, _: None = Depends(require_admin)) -> Dict[str, Any]:
    client = get_firestore_client()
    ref = _keys_col(client).document(key_id)
    if not ref.get().exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update({"status": "disabled"})
    _audit(request, "admin.keys.disable", 200, {"key_id": key_id})
    return {"ok": True, "key_id": key_id, "status": "disabled"}


@router.post("/keys/{key_id}/reset-counters")
def reset_counters(key_id: str, request: Request, _: None = Depends(require_admin)) -> Dict[str, Any]:
    client = get_firestore_client()
    ref = _keys_col(client).document(key_id)
    if not ref.get().exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update(
        {
            "counters.total_requests": 0,
            "counters.blocked_requests": 0,
        }
    )
    _audit(request, "admin.keys.reset_counters", 200, {"key_id": key_id})
    return {"ok": True, "key_id": key_id, "counters": {"total_requests": 0, "blocked_requests": 0}}