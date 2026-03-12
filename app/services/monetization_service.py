from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.common import parse_iso_utc
from app.core.config import settings
from app.db.firestore import get_firestore_client
from app.repositories.catalog_repository import get_module_by_id

MONETIZATION_VERSION = "20260312_launch_pricing_v1"
FREE_ACCESS_TIER = "free"
PREMIUM_ACCESS_TIER = "premium"
FREE_MODULE_IDS = {"F1"}

DEFAULT_MODULE_UNLOCK = {
    "id": "module_unlock_default",
    "kind": "module_unlock",
    "title": "Unlock this module forever",
    "currency": "USD",
    "amount_cents": 999,
    "description": "One-time purchase for a permanent unlock of a single premium module.",
    "active": True,
    "rank": 10,
}

DEFAULT_SUBSCRIPTION_PLANS = [
    {
        "id": "premium_monthly",
        "kind": "subscription",
        "title": "Premium monthly",
        "currency": "USD",
        "amount_cents": 1299,
        "billing_period_months": 1,
        "description": "Unlock all premium modules while your subscription is active.",
        "active": True,
        "rank": 20,
    },
    {
        "id": "premium_six_month",
        "kind": "subscription",
        "title": "Premium 6 months",
        "currency": "USD",
        "amount_cents": 5999,
        "billing_period_months": 6,
        "description": "Lower monthly cost for medium-term study plans.",
        "active": True,
        "rank": 30,
    },
    {
        "id": "premium_yearly",
        "kind": "subscription",
        "title": "Premium yearly",
        "currency": "USD",
        "amount_cents": 9999,
        "billing_period_months": 12,
        "description": "Best value for full-year access to every premium module.",
        "active": True,
        "rank": 40,
    },
]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _format_usd(amount_cents: int) -> str:
    return f"${amount_cents / 100:.2f}"


def _module_id_from_row(module: Dict[str, Any]) -> str:
    return str(module.get("id") or module.get("module_id") or "").strip()


def _pricing_doc_with_labels(doc: Dict[str, Any]) -> Dict[str, Any]:
    row = dict(doc)
    amount_cents = int(row.get("amount_cents") or 0)
    row["price_label"] = _format_usd(amount_cents)

    billing_period_months = row.get("billing_period_months")
    if isinstance(billing_period_months, int) and billing_period_months > 0:
        effective_monthly = round(amount_cents / billing_period_months)
        row["effective_monthly_cents"] = effective_monthly
        row["effective_monthly_label"] = _format_usd(effective_monthly) + "/mo"
        if billing_period_months == 1:
            row["billing_label"] = "monthly"
        elif billing_period_months == 6:
            row["billing_label"] = "every 6 months"
        elif billing_period_months == 12:
            row["billing_label"] = "yearly"
        else:
            row["billing_label"] = f"every {billing_period_months} months"
    else:
        row["billing_label"] = "one-time"

    return row


def _default_catalog() -> Dict[str, Any]:
    return {
        "module_unlock_default": _pricing_doc_with_labels(DEFAULT_MODULE_UNLOCK),
        "subscription_plans": [
            _pricing_doc_with_labels(plan)
            for plan in sorted(DEFAULT_SUBSCRIPTION_PLANS, key=lambda item: int(item.get("rank") or 0))
        ],
    }


def _load_catalog_docs() -> Dict[str, Dict[str, Any]]:
    db = get_firestore_client()
    result: Dict[str, Dict[str, Any]] = {}
    for snap in db.collection("billing_catalog").stream():
        row = snap.to_dict() or {}
        row["id"] = snap.id
        result[snap.id] = row
    return result


def get_billing_catalog() -> Dict[str, Any]:
    defaults = _default_catalog()

    try:
        docs = _load_catalog_docs()
    except Exception:
        docs = {}

    module_unlock = _pricing_doc_with_labels(
        docs.get("module_unlock_default") or defaults["module_unlock_default"]
    )

    subscription_rows: List[Dict[str, Any]] = []
    for plan in defaults["subscription_plans"]:
        subscription_rows.append(
            _pricing_doc_with_labels(docs.get(str(plan["id"])) or plan)
        )
    subscription_rows.sort(key=lambda row: int(row.get("rank") or 0))

    module_overrides: Dict[str, Dict[str, Any]] = {}
    for doc_id, doc in docs.items():
        if not doc_id.startswith("module_"):
            continue
        module_id = str(doc.get("module_id") or doc_id.replace("module_", "", 1)).strip()
        if not module_id:
            continue
        module_overrides[module_id] = _pricing_doc_with_labels(doc)

    return {
        "module_unlock_default": module_unlock,
        "module_overrides": module_overrides,
        "subscription_plans": subscription_rows,
    }


def _read_student_billing(uid: str) -> Dict[str, Any]:
    if not uid:
        return {}

    db = get_firestore_client()
    snap = db.collection("student_billing").document(uid).get()
    return snap.to_dict() if snap.exists else {}


def _module_unlock_ids(student_billing: Dict[str, Any]) -> List[str]:
    unlocks = student_billing.get("module_unlocks")
    result: List[str] = []

    if isinstance(unlocks, list):
        for value in unlocks:
            if isinstance(value, str) and value.strip():
                result.append(value.strip())
        return sorted(set(result))

    if not isinstance(unlocks, dict):
        return []

    for module_id, payload in unlocks.items():
        module_key = str(module_id or "").strip()
        if not module_key:
            continue

        if payload is True:
            result.append(module_key)
            continue

        if isinstance(payload, dict):
            status = str(payload.get("status") or "active").strip().lower()
            if status in {"active", "purchased", "granted"}:
                result.append(module_key)

    return sorted(set(result))


def _active_subscription(student_billing: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    subscription = student_billing.get("subscription")
    if not isinstance(subscription, dict):
        return None

    status = str(subscription.get("status") or "").strip().lower()
    if status not in {"active", "trialing", "grace_period"}:
        return None

    ends_utc = str(subscription.get("ends_utc") or "").strip()
    if ends_utc and parse_iso_utc(ends_utc) < parse_iso_utc(_utc_now_iso()):
        return None

    return subscription


def get_student_entitlements(uid: Optional[str]) -> Dict[str, Any]:
    if not uid:
        return {
            "purchased_module_ids": [],
            "active_subscription_plan_id": None,
            "subscription_expires_utc": None,
            "has_active_subscription": False,
        }

    student_billing = _read_student_billing(uid)
    subscription = _active_subscription(student_billing)
    purchased_module_ids = _module_unlock_ids(student_billing)

    active_subscription_plan_id = None
    subscription_expires_utc = None
    if subscription:
        active_subscription_plan_id = str(subscription.get("plan_id") or "").strip() or None
        subscription_expires_utc = str(subscription.get("ends_utc") or "").strip() or None

    return {
        "purchased_module_ids": purchased_module_ids,
        "active_subscription_plan_id": active_subscription_plan_id,
        "subscription_expires_utc": subscription_expires_utc,
        "has_active_subscription": subscription is not None,
    }


def module_access_tier(module: Dict[str, Any]) -> str:
    configured = str(module.get("access_tier") or "").strip().lower()
    if configured in {FREE_ACCESS_TIER, PREMIUM_ACCESS_TIER}:
        return configured

    module_id = _module_id_from_row(module)
    if module_id in FREE_MODULE_IDS:
        return FREE_ACCESS_TIER

    return PREMIUM_ACCESS_TIER


def module_offer_for_module(module_id: str) -> Dict[str, Any]:
    catalog = get_billing_catalog()
    return dict(
        catalog["module_overrides"].get(module_id) or catalog["module_unlock_default"]
    )


def build_module_access(module: Dict[str, Any], uid: Optional[str]) -> Dict[str, Any]:
    module_id = _module_id_from_row(module)
    tier = module_access_tier(module)
    entitlements = get_student_entitlements(uid)
    module_offer = module_offer_for_module(module_id)
    subscription_plans = list(get_billing_catalog()["subscription_plans"])

    if tier == FREE_ACCESS_TIER:
        return {
            "tier": tier,
            "is_unlocked": True,
            "unlock_reason": "free_module",
            "message": "This module is free for all students.",
            "module_purchase": None,
            "subscription_plans": subscription_plans,
            "subscription_expires_utc": entitlements["subscription_expires_utc"],
        }

    purchased = module_id in entitlements["purchased_module_ids"]
    subscribed = bool(entitlements["has_active_subscription"])

    if purchased:
        reason = "module_purchase"
        message = "You own this module."
    elif subscribed:
        reason = "active_subscription"
        message = "Your premium subscription unlocks this module."
    else:
        reason = "payment_required"
        message = (
            f"Unlock this module forever for {module_offer['price_label']} or choose a premium subscription."
        )

    return {
        "tier": tier,
        "is_unlocked": purchased or subscribed,
        "unlock_reason": reason,
        "message": message,
        "module_purchase": module_offer,
        "subscription_plans": subscription_plans,
        "subscription_expires_utc": entitlements["subscription_expires_utc"],
    }


def enrich_module_for_student(module: Dict[str, Any], uid: Optional[str]) -> Dict[str, Any]:
    row = dict(module)
    row["access_tier"] = module_access_tier(row)
    row["access"] = build_module_access(row, uid)
    return row


def require_module_access(uid: str, module_id: str) -> Dict[str, Any]:
    module = get_module_by_id(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")

    access = build_module_access(module, uid)
    if access.get("is_unlocked") is True:
        return enrich_module_for_student(module, uid)

    module_offer = access.get("module_purchase") or module_offer_for_module(module_id)
    raise HTTPException(
        status_code=402,
        detail=(
            f"{module.get('title') or module_id} is a premium module. "
            f"Unlock it for {module_offer.get('price_label', '$9.99')} or subscribe to premium access."
        ),
    )


def ensure_monetization_seeded() -> bool:
    project_id = str(getattr(settings, "google_cloud_project", "") or "").strip().lower()
    if project_id in {"", "local", "none"}:
        return False

    db = get_firestore_client()
    settings_snap = db.collection("billing_catalog").document("settings").get()
    settings_data = settings_snap.to_dict() or {}
    version_matches = str(settings_data.get("pricing_version") or "").strip() == MONETIZATION_VERSION

    f1_tier = ""
    f2_tier = ""
    f1_snap = db.collection("modules").document("F1").get()
    if f1_snap.exists:
        f1_tier = str((f1_snap.to_dict() or {}).get("access_tier") or "").strip().lower()
    f2_snap = db.collection("modules").document("F2").get()
    if f2_snap.exists:
        f2_tier = str((f2_snap.to_dict() or {}).get("access_tier") or "").strip().lower()

    if version_matches and f1_tier == FREE_ACCESS_TIER and f2_tier == PREMIUM_ACCESS_TIER:
        return False

    batch = db.batch()
    batch.set(
        db.collection("billing_catalog").document("settings"),
        {"pricing_version": MONETIZATION_VERSION},
        merge=True,
    )
    batch.set(
        db.collection("billing_catalog").document("module_unlock_default"),
        DEFAULT_MODULE_UNLOCK,
        merge=True,
    )
    for plan in DEFAULT_SUBSCRIPTION_PLANS:
        batch.set(
            db.collection("billing_catalog").document(str(plan["id"])),
            plan,
            merge=True,
        )
    batch.set(
        db.collection("modules").document("F1"),
        {"access_tier": FREE_ACCESS_TIER},
        merge=True,
    )
    batch.set(
        db.collection("modules").document("F2"),
        {"access_tier": PREMIUM_ACCESS_TIER},
        merge=True,
    )
    batch.commit()
    return True