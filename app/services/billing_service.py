from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import stripe
from fastapi import HTTPException

from app.core.config import settings
from app.db.firestore import get_firestore_client
from app.repositories.catalog_repository import get_module_by_id
from app.services.monetization_service import (
    FREE_ACCESS_TIER,
    REVIEW_BYPASS_ROLES,
    build_module_access,
    get_billing_catalog,
    get_student_entitlements,
    module_access_tier,
    module_offer_for_module,
)


ACTIVE_SUBSCRIPTION_STATUSES = {"active", "trialing", "grace_period"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalized_role(role: Optional[str]) -> str:
    return str(role or "").strip().lower()


def stripe_is_configured() -> bool:
    return bool(str(settings.stripe_secret_key or "").strip())


def stripe_webhook_is_configured() -> bool:
    return bool(str(settings.stripe_webhook_secret or "").strip())


def _require_stripe() -> Any:
    if not stripe_is_configured():
        raise HTTPException(status_code=503, detail="Billing checkout is not configured yet.")

    stripe.api_key = str(settings.stripe_secret_key).strip()
    return stripe


def _string(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _obj_get(value: Any, key: str, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, dict):
        return value.get(key, default)
    try:
        return value.get(key, default)
    except Exception:
        return getattr(value, key, default)


def _extract_id(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return _string(value)
    return _string(_obj_get(value, "id"))


def _unix_to_iso(value: Any) -> Optional[str]:
    try:
        if value in (None, ""):
            return None
        timestamp = int(value)
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except Exception:
        return None


def _student_billing_ref(uid: str):
    return get_firestore_client().collection("student_billing").document(uid)


def _billing_customer_ref(customer_id: str):
    return get_firestore_client().collection("billing_customers").document(customer_id)


def _billing_event_ref(event_id: str):
    return get_firestore_client().collection("billing_events").document(event_id)


def _read_student_billing(uid: str) -> Dict[str, Any]:
    if not uid:
        return {}
    snap = _student_billing_ref(uid).get()
    return snap.to_dict() if snap.exists else {}


def _read_customer_mapping(customer_id: str) -> Dict[str, Any]:
    if not customer_id:
        return {}
    snap = _billing_customer_ref(customer_id).get()
    return snap.to_dict() if snap.exists else {}


def _store_customer_mapping(uid: str, customer_id: str, email: Optional[str]) -> None:
    if not uid or not customer_id:
        return

    _student_billing_ref(uid).set(
        {
            "stripe_customer_id": customer_id,
            "stripe_customer_email": _string(email),
            "updated_utc": _utc_now_iso(),
        },
        merge=True,
    )
    _billing_customer_ref(customer_id).set(
        {
            "uid": uid,
            "email": _string(email),
            "updated_utc": _utc_now_iso(),
        },
        merge=True,
    )


def _plan_price_id(plan_id: str) -> Optional[str]:
    normalized_plan_id = _string(plan_id)
    if not normalized_plan_id:
        return None

    for plan in get_billing_catalog().get("subscription_plans", []):
        if _string(plan.get("id")) != normalized_plan_id:
            continue
        explicit = _string(plan.get("stripe_price_id"))
        if explicit:
            return explicit
        break

    return {
        "premium_monthly": _string(settings.stripe_price_premium_monthly),
        "premium_six_month": _string(settings.stripe_price_premium_six_month),
        "premium_yearly": _string(settings.stripe_price_premium_yearly),
    }.get(normalized_plan_id)


def _module_price_env_name(module_id: str) -> str:
    normalized = re.sub(r"[^A-Z0-9]+", "_", str(module_id or "").upper()).strip("_")
    return f"STRIPE_PRICE_MODULE_{normalized}"


def _module_price_id(module_id: str) -> Optional[str]:
    module_offer = module_offer_for_module(module_id)
    explicit = _string(module_offer.get("stripe_price_id"))
    if explicit:
        return explicit

    specific = _string(os.getenv(_module_price_env_name(module_id)))
    if specific:
        return specific

    return _string(settings.stripe_price_module_unlock_default)


def _plan_id_from_price_id(price_id: Optional[str]) -> Optional[str]:
    normalized_price_id = _string(price_id)
    if not normalized_price_id:
        return None

    for plan in get_billing_catalog().get("subscription_plans", []):
        if _string(plan.get("stripe_price_id")) == normalized_price_id:
            return _string(plan.get("id"))

    env_matches = {
        _string(settings.stripe_price_premium_monthly): "premium_monthly",
        _string(settings.stripe_price_premium_six_month): "premium_six_month",
        _string(settings.stripe_price_premium_yearly): "premium_yearly",
    }
    return env_matches.get(normalized_price_id)


def _allowed_origins() -> set[str]:
    origins = {
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "https://127.0.0.1:3000",
        "https://localhost:3000",
    }
    base = _string(settings.app_base_url)
    if base:
        origins.add(base.rstrip("/"))

    for value in str(settings.allowed_app_origins or "").split(","):
        origin = _string(value)
        if origin:
            origins.add(origin.rstrip("/"))

    return origins


def _resolve_origin(origin: Optional[str]) -> str:
    candidate = _string(origin)
    if candidate:
        candidate = candidate.rstrip("/")
        if candidate in _allowed_origins():
            return candidate
        raise HTTPException(status_code=400, detail="Return origin is not allowed.")

    fallback = _string(settings.app_base_url)
    if not fallback:
        raise HTTPException(status_code=500, detail="APP_BASE_URL is not configured.")
    return fallback.rstrip("/")


def _app_url(origin: Optional[str], path: Optional[str], fallback_path: str) -> str:
    chosen_origin = _resolve_origin(origin)
    raw_path = _string(path) or fallback_path

    parsed = urlparse(raw_path)
    if parsed.scheme and parsed.netloc:
        absolute_origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        if absolute_origin not in _allowed_origins():
            raise HTTPException(status_code=400, detail="Return URL origin is not allowed.")
        return raw_path

    if not raw_path.startswith("/"):
        raw_path = "/" + raw_path
    return chosen_origin + raw_path


def _merge_query(url: str, **params: Any) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in params.items():
        if value is None:
            continue
        query[key] = str(value)
    return urlunparse(parsed._replace(query=urlencode(query)))


def _billing_customer_id(uid: str) -> Optional[str]:
    billing = _read_student_billing(uid)
    return _string(billing.get("stripe_customer_id"))


def _customer_email(uid: str, email: Optional[str]) -> Optional[str]:
    stored = _string(_read_student_billing(uid).get("stripe_customer_email"))
    return stored or _string(email)


def _ensure_customer(uid: str, email: Optional[str]) -> str:
    existing = _billing_customer_id(uid)
    if existing:
        _store_customer_mapping(uid, existing, _customer_email(uid, email))
        return existing

    stripe_api = _require_stripe()
    customer = stripe_api.Customer.create(
        email=_customer_email(uid, email),
        metadata={"uid": uid},
    )
    customer_id = _extract_id(customer)
    if not customer_id:
        raise HTTPException(status_code=502, detail="Billing provider did not return a customer id.")

    _store_customer_mapping(uid, customer_id, _string(_obj_get(customer, "email")) or _string(email))
    return customer_id


def _module_access_or_error(uid: str, role: Optional[str], module_id: str) -> Dict[str, Any]:
    module = get_module_by_id(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="Module not found.")

    if module_access_tier(module) == FREE_ACCESS_TIER:
        raise HTTPException(status_code=400, detail="This module is already free.")

    access = build_module_access(module, uid, role=role)
    if access.get("is_unlocked") is True:
        raise HTTPException(status_code=409, detail="This module is already unlocked for your account.")

    return {"module": module, "access": access}


def _checkout_success_url(origin: Optional[str], path: Optional[str], fallback_path: str) -> str:
    return _merge_query(_app_url(origin, path, fallback_path), checkout="success", session_id="{CHECKOUT_SESSION_ID}")


def _checkout_cancel_url(origin: Optional[str], path: Optional[str], fallback_path: str) -> str:
    return _merge_query(_app_url(origin, path, fallback_path), checkout="cancelled")


def _write_module_unlock(
    uid: str,
    module_id: str,
    *,
    customer_id: Optional[str],
    customer_email: Optional[str],
    offer_id: Optional[str],
    session_id: Optional[str],
    payment_intent_id: Optional[str],
) -> None:
    unlock_row = {
        module_id: {
            "status": "active",
            "module_id": module_id,
            "offer_id": offer_id,
            "purchased_utc": _utc_now_iso(),
            "source": "stripe_checkout",
            "stripe_checkout_session_id": session_id,
            "stripe_payment_intent_id": payment_intent_id,
        }
    }
    patch: Dict[str, Any] = {
        "module_unlocks": unlock_row,
        "updated_utc": _utc_now_iso(),
    }
    if customer_id:
        patch["stripe_customer_id"] = customer_id
    if customer_email:
        patch["stripe_customer_email"] = customer_email

    _student_billing_ref(uid).set(patch, merge=True)
    if customer_id:
        _store_customer_mapping(uid, customer_id, customer_email)


def _sync_subscription(subscription: Any, uid_hint: Optional[str] = None) -> Optional[str]:
    customer_id = _extract_id(_obj_get(subscription, "customer"))
    metadata = _obj_get(subscription, "metadata", {}) or {}
    uid = _string(metadata.get("uid")) or _string(uid_hint)
    if not uid and customer_id:
        uid = _string(_read_customer_mapping(customer_id).get("uid"))
    if not uid:
        return None

    items = _obj_get(_obj_get(subscription, "items", {}), "data", []) or []
    first_item = items[0] if items else None
    price_id = _extract_id(_obj_get(first_item, "price"))
    raw_status = (_string(_obj_get(subscription, "status")) or "inactive").lower()
    stored_status = "grace_period" if raw_status == "past_due" else raw_status
    subscription_row = {
        "status": stored_status,
        "provider_status": raw_status,
        "plan_id": _string(metadata.get("plan_id")) or _plan_id_from_price_id(price_id),
        "ends_utc": _unix_to_iso(_obj_get(subscription, "current_period_end")),
        "started_utc": _unix_to_iso(_obj_get(subscription, "start_date") or _obj_get(subscription, "created")),
        "stripe_subscription_id": _extract_id(subscription),
        "stripe_price_id": price_id,
        "stripe_customer_id": customer_id,
        "cancel_at_period_end": bool(_obj_get(subscription, "cancel_at_period_end")),
        "source": "stripe_subscription",
    }

    patch: Dict[str, Any] = {
        "subscription": subscription_row,
        "updated_utc": _utc_now_iso(),
    }
    if customer_id:
        patch["stripe_customer_id"] = customer_id

    customer_email = _string(_customer_email(uid, None))
    if customer_email:
        patch["stripe_customer_email"] = customer_email

    _student_billing_ref(uid).set(patch, merge=True)
    if customer_id:
        _store_customer_mapping(uid, customer_id, customer_email)
    return uid


def _checkout_session_uid(session: Any) -> Optional[str]:
    metadata = _obj_get(session, "metadata", {}) or {}
    uid = _string(metadata.get("uid")) or _string(_obj_get(session, "client_reference_id"))
    if uid:
        return uid

    customer_id = _extract_id(_obj_get(session, "customer"))
    if customer_id:
        return _string(_read_customer_mapping(customer_id).get("uid"))
    return None


def _sync_checkout_session(session: Any, uid_hint: Optional[str] = None) -> Optional[str]:
    metadata = _obj_get(session, "metadata", {}) or {}
    uid = _checkout_session_uid(session) or _string(uid_hint)
    if not uid:
        return None

    customer_id = _extract_id(_obj_get(session, "customer"))
    customer_email = _string(_obj_get(session, "customer_details", {}).get("email")) or _customer_email(uid, None)
    if customer_id:
        _store_customer_mapping(uid, customer_id, customer_email)

    session_id = _extract_id(session)
    mode = (_string(_obj_get(session, "mode")) or "").lower()

    _student_billing_ref(uid).set(
        {
            "last_checkout_session_id": session_id,
            "last_checkout_completed_utc": _utc_now_iso(),
            "updated_utc": _utc_now_iso(),
        },
        merge=True,
    )

    if mode == "payment":
        payment_status = (_string(_obj_get(session, "payment_status")) or "").lower()
        if payment_status not in {"paid", "no_payment_required"}:
            return uid

        module_id = _string(metadata.get("module_id"))
        if module_id:
            _write_module_unlock(
                uid,
                module_id,
                customer_id=customer_id,
                customer_email=customer_email,
                offer_id=_string(metadata.get("offer_id")),
                session_id=session_id,
                payment_intent_id=_extract_id(_obj_get(session, "payment_intent")),
            )
        return uid

    if mode == "subscription":
        subscription_obj = _obj_get(session, "subscription")
        subscription_id = _extract_id(subscription_obj)
        if not subscription_id:
            return uid
        stripe_api = _require_stripe()
        subscription = (
            subscription_obj
            if not isinstance(subscription_obj, str)
            else stripe_api.Subscription.retrieve(subscription_id, expand=["items.data.price"])
        )
        _sync_subscription(subscription, uid_hint=uid)
        return uid

    return uid


def build_billing_summary(uid: str, role: Optional[str] = None) -> Dict[str, Any]:
    student_billing = _read_student_billing(uid)
    entitlements = get_student_entitlements(uid)
    customer_id = _string(student_billing.get("stripe_customer_id"))
    subscription = student_billing.get("subscription") if isinstance(student_billing.get("subscription"), dict) else None

    return {
        "configured": stripe_is_configured(),
        "webhook_configured": stripe_webhook_is_configured(),
        "can_checkout": stripe_is_configured() and _normalized_role(role) not in REVIEW_BYPASS_ROLES,
        "portal_enabled": stripe_is_configured() and bool(customer_id),
        "has_customer": bool(customer_id),
        "customer_email": _string(student_billing.get("stripe_customer_email")),
        "purchased_module_ids": entitlements.get("purchased_module_ids", []),
        "active_subscription_plan_id": entitlements.get("active_subscription_plan_id"),
        "subscription_expires_utc": entitlements.get("subscription_expires_utc"),
        "has_active_subscription": bool(entitlements.get("has_active_subscription")),
        "subscription": subscription,
    }


def create_checkout_session_for_student(
    *,
    uid: str,
    email: Optional[str],
    role: Optional[str],
    purchase_kind: str,
    module_id: Optional[str] = None,
    plan_id: Optional[str] = None,
    origin: Optional[str] = None,
    success_path: Optional[str] = None,
    cancel_path: Optional[str] = None,
) -> Dict[str, Any]:
    if _normalized_role(role) in REVIEW_BYPASS_ROLES:
        raise HTTPException(status_code=403, detail="Review-access accounts do not need student billing checkout.")

    stripe_api = _require_stripe()
    customer_id = _ensure_customer(uid, email)

    metadata = {
        "uid": uid,
        "email": _string(email) or "",
        "purchase_kind": purchase_kind,
    }

    if purchase_kind == "module_unlock":
        normalized_module_id = _string(module_id)
        if not normalized_module_id:
            raise HTTPException(status_code=400, detail="module_id is required for a module unlock checkout.")

        access = _module_access_or_error(uid, role, normalized_module_id)
        module_offer = access["access"].get("module_purchase") or module_offer_for_module(normalized_module_id)
        price_id = _module_price_id(normalized_module_id)
        if not price_id:
            raise HTTPException(
                status_code=503,
                detail=f"No Stripe price id is configured for {normalized_module_id}.",
            )

        metadata.update(
            {
                "module_id": normalized_module_id,
                "offer_id": _string(module_offer.get("id")) or "module_unlock_default",
            }
        )

        session = stripe_api.checkout.Session.create(
            mode="payment",
            customer=customer_id,
            client_reference_id=uid,
            success_url=_checkout_success_url(origin, success_path, f"/student/module/{normalized_module_id}"),
            cancel_url=_checkout_cancel_url(origin, cancel_path, f"/student/module/{normalized_module_id}"),
            line_items=[{"price": price_id, "quantity": 1}],
            metadata=metadata,
            payment_intent_data={"metadata": metadata},
        )
        return {
            "checkout_url": _string(_obj_get(session, "url")),
            "session_id": _extract_id(session),
        }

    if purchase_kind == "subscription":
        normalized_plan_id = _string(plan_id)
        if not normalized_plan_id:
            raise HTTPException(status_code=400, detail="plan_id is required for a subscription checkout.")

        entitlements = get_student_entitlements(uid)
        if entitlements.get("has_active_subscription"):
            raise HTTPException(status_code=409, detail="Your subscription is already active. Use manage billing instead.")

        price_id = _plan_price_id(normalized_plan_id)
        if not price_id:
            raise HTTPException(
                status_code=503,
                detail=f"No Stripe price id is configured for {normalized_plan_id}.",
            )

        metadata.update({"plan_id": normalized_plan_id})
        session = stripe_api.checkout.Session.create(
            mode="subscription",
            customer=customer_id,
            client_reference_id=uid,
            success_url=_checkout_success_url(origin, success_path, "/student"),
            cancel_url=_checkout_cancel_url(origin, cancel_path, "/student"),
            line_items=[{"price": price_id, "quantity": 1}],
            metadata=metadata,
            subscription_data={"metadata": metadata},
        )
        return {
            "checkout_url": _string(_obj_get(session, "url")),
            "session_id": _extract_id(session),
        }

    raise HTTPException(status_code=400, detail="Unsupported purchase_kind.")


def create_portal_session_for_student(
    *,
    uid: str,
    email: Optional[str],
    origin: Optional[str] = None,
    return_path: Optional[str] = None,
) -> Dict[str, Any]:
    stripe_api = _require_stripe()
    customer_id = _ensure_customer(uid, email)
    session = stripe_api.billing_portal.Session.create(
        customer=customer_id,
        return_url=_merge_query(_app_url(origin, return_path, "/student"), billing="return"),
    )
    return {
        "portal_url": _string(_obj_get(session, "url")),
        "session_id": _extract_id(session),
    }


def confirm_checkout_session_for_student(
    *,
    uid: str,
    role: Optional[str],
    session_id: str,
    module_id: Optional[str] = None,
) -> Dict[str, Any]:
    stripe_api = _require_stripe()
    session = stripe_api.checkout.Session.retrieve(
        session_id,
        expand=["customer", "subscription", "line_items"],
    )

    session_uid = _checkout_session_uid(session)
    if session_uid and session_uid != uid:
        raise HTTPException(status_code=403, detail="That checkout session belongs to a different account.")

    resolved_uid = _sync_checkout_session(session, uid_hint=uid) or uid
    summary = build_billing_summary(resolved_uid, role=role)

    response: Dict[str, Any] = {"billing": summary}
    normalized_module_id = _string(module_id) or _string((_obj_get(session, "metadata", {}) or {}).get("module_id"))
    if normalized_module_id:
        module = get_module_by_id(normalized_module_id)
        if module:
            response["module_access"] = build_module_access(module, resolved_uid, role=role)

    return response


def process_stripe_webhook(payload: bytes, signature: Optional[str]) -> Dict[str, Any]:
    stripe_api = _require_stripe()
    webhook_secret = _string(settings.stripe_webhook_secret)
    if not webhook_secret:
        raise HTTPException(status_code=503, detail="Billing webhook is not configured yet.")

    try:
        event = stripe_api.Webhook.construct_event(payload, signature or "", webhook_secret)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid webhook payload: {exc}") from exc
    except stripe.error.SignatureVerificationError as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature.") from exc

    event_id = _extract_id(event)
    if not event_id:
        raise HTTPException(status_code=400, detail="Webhook event id is missing.")

    event_ref = _billing_event_ref(event_id)
    if event_ref.get().exists:
        return {"ok": True, "duplicate": True, "event_id": event_id}

    event_type = _string(_obj_get(event, "type")) or "unknown"
    payload_object = _obj_get(_obj_get(event, "data", {}), "object", {}) or {}

    try:
        processed = False
        resolved_uid = None
        if event_type == "checkout.session.completed":
            resolved_uid = _sync_checkout_session(payload_object)
            processed = True
        elif event_type in {
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.deleted",
        }:
            resolved_uid = _sync_subscription(payload_object)
            processed = True

        event_ref.set(
            {
                "event_type": event_type,
                "processed": processed,
                "processed_utc": _utc_now_iso(),
                "uid": resolved_uid,
            },
            merge=True,
        )
        return {
            "ok": True,
            "duplicate": False,
            "processed": processed,
            "event_id": event_id,
            "event_type": event_type,
        }
    except Exception as exc:
        event_ref.set(
            {
                "event_type": event_type,
                "processed": False,
                "processed_utc": _utc_now_iso(),
                "error": str(exc),
            },
            merge=True,
        )
        raise
