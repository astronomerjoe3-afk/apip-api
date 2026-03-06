from __future__ import annotations

import secrets
from typing import Any, Dict, List

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from app.audit import write_audit_log
from app.common import get_client_ip, sha256_hex, utc_now
from app.db.firestore import get_firestore_client
from app.dependencies import require_admin

router = APIRouter(tags=["admin"])


def _public_key_view(key_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "key_id": key_id,
        "label": data.get("label"),
        "active": bool(data.get("active", False)),
        "scopes": data.get("scopes", []),
        "created_utc": data.get("created_utc"),
        "updated_utc": data.get("updated_utc"),
        "rate_limit": data.get("rate_limit", {}) or {},
        "daily_limit": data.get("daily_limit"),
        "auto_disabled": bool(data.get("auto_disabled", False)),
        "last_used_utc": data.get("last_used_utc"),
    }


@router.get("/admin/metrics")
def admin_metrics(request: Request, user=Depends(require_admin), top_n: int = Query(10, ge=1, le=50)):
    db = get_firestore_client()
    keys_docs = db.collection("api_keys").stream()

    total = 0
    active = 0
    auto_disabled = 0

    for d in keys_docs:
        total += 1
        data = d.to_dict() or {}
        if data.get("active") is True:
            active += 1
        if data.get("auto_disabled") is True:
            auto_disabled += 1

    payload = {
        "ok": True,
        "utc": utc_now(),
        "keys": {"total": total, "active": active, "auto_disabled": auto_disabled},
        "rate_limit": {
            "top_n": top_n,
            "global_last_hour": {"total": 0},
            "global_last_24h": {"total": 0},
            "top_keys_last_hour": [],
            "top_keys_last_24h": [],
        },
        "warnings": [],
    }

    write_audit_log(
        event_type="admin.metrics.read",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/admin/metrics",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"top_n": top_n},
    )

    return payload


@router.get("/admin/keys")
def admin_list_keys(
    request: Request,
    user=Depends(require_admin),
    limit: int = Query(20, ge=1, le=200),
):
    db = get_firestore_client()
    docs = db.collection("api_keys").limit(limit).stream()
    keys: List[Dict[str, Any]] = []

    for d in docs:
        data = d.to_dict() or {}
        keys.append(_public_key_view(d.id, data))

    write_audit_log(
        event_type="admin.keys.list",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/admin/keys",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"limit": limit, "returned": len(keys)},
    )

    return {"ok": True, "keys": keys, "limit": limit, "utc": utc_now()}


@router.get("/admin/keys/{key_id}")
def admin_get_key(request: Request, key_id: str, user=Depends(require_admin)):
    db = get_firestore_client()
    doc = db.collection("api_keys").document(key_id).get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    data = doc.to_dict() or {}

    write_audit_log(
        event_type="admin.keys.get",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=key_id,
        path=f"/admin/keys/{key_id}",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )

    return {"ok": True, "key": _public_key_view(key_id, data)}


@router.post("/admin/keys")
def admin_create_key(
    request: Request,
    user=Depends(require_admin),
    payload: Dict[str, Any] = Body(...),
):
    db = get_firestore_client()

    label = str(payload.get("label") or "web-admin-created").strip()
    scopes_raw = payload.get("scopes") or ["profile:read"]

    if isinstance(scopes_raw, str):
        scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()]
    else:
        scopes = [str(s).strip() for s in scopes_raw if str(s).strip()]

    window_limit = int(payload.get("window_limit") or 10)
    window_seconds = int(payload.get("window_seconds") or 60)
    bucket_seconds = int(payload.get("bucket_seconds") or 10)
    daily_limit = int(payload.get("daily_limit") or 500)

    key_id = secrets.token_urlsafe(12).replace("-", "").replace("_", "")[:16]
    api_key_secret = secrets.token_urlsafe(32)

    doc = {
        "label": label,
        "scopes": scopes,
        "active": True,
        "auto_disabled": False,
        "secret_hash": sha256_hex(api_key_secret),
        "created_utc": utc_now(),
        "updated_utc": utc_now(),
        "rate_limit": {
            "window_limit": window_limit,
            "window_seconds": window_seconds,
            "bucket_seconds": bucket_seconds,
        },
        "daily_limit": daily_limit,
    }

    db.collection("api_keys").document(key_id).set(doc)

    write_audit_log(
        event_type="admin.keys.create",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=key_id,
        path="/admin/keys",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"label": label, "scopes": scopes, "daily_limit": daily_limit},
    )

    return {
        "ok": True,
        "key_id": key_id,
        "active": True,
        "label": label,
        "scopes": scopes,
        "api_key": api_key_secret,
        "utc": utc_now(),
    }


@router.post("/admin/keys/{key_id}/enable")
def admin_enable_key(request: Request, key_id: str, user=Depends(require_admin)):
    db = get_firestore_client()
    ref = db.collection("api_keys").document(key_id)
    doc = ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update({"active": True, "updated_utc": utc_now()})

    write_audit_log(
        event_type="admin.keys.enable",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=key_id,
        path=f"/admin/keys/{key_id}/enable",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )

    return {"ok": True, "key_id": key_id, "enabled": True}


@router.post("/admin/keys/{key_id}/disable")
def admin_disable_key(request: Request, key_id: str, user=Depends(require_admin)):
    db = get_firestore_client()
    ref = db.collection("api_keys").document(key_id)
    doc = ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Key not found")

    ref.update({"active": False, "updated_utc": utc_now()})

    write_audit_log(
        event_type="admin.keys.disable",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=key_id,
        path=f"/admin/keys/{key_id}/disable",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )

    return {"ok": True, "key_id": key_id, "disabled": True}


@router.post("/admin/keys/{key_id}/reset-counters")
def admin_reset_counters(request: Request, key_id: str, user=Depends(require_admin)):
    db = get_firestore_client()

    to_delete = [
        ("rl_state", key_id),
        ("api_key_abuse_1h", key_id),
        ("api_key_abuse_24h", key_id),
    ]

    deleted: List[str] = []
    errors: List[str] = []

    for col, doc_id in to_delete:
        try:
            ref = db.collection(col).document(doc_id)
            if ref.get().exists:
                ref.delete()
            deleted.append(f"{col}/{doc_id}")
        except Exception as e:
            errors.append(f"{col}/{doc_id}: {str(e)}")

    write_audit_log(
        event_type="admin.keys.reset_counters",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        key_id=key_id,
        path=f"/admin/keys/{key_id}/reset-counters",
        method="POST",
        status=200 if not errors else 207,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"deleted": deleted, "errors": errors},
    )

    return {"ok": True, "key_id": key_id, "reset": True, "details": {"deleted": deleted, "errors": errors}}
