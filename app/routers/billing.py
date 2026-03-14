from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.audit import write_audit_log
from app.common import get_client_ip
from app.dependencies import require_admin, require_authenticated_user
from app.schemas.billing import AdminSubscriptionResyncRequest, CheckoutConfirmRequest, CheckoutSessionRequest, PortalSessionRequest
from app.services.billing_service import (
    build_billing_summary,
    confirm_checkout_session_for_student,
    create_checkout_session_for_student,
    create_portal_session_for_student,
    process_stripe_webhook,
    resync_subscription_for_student,
)

router = APIRouter(prefix="/billing", tags=["billing"])


@router.get("/summary")
def get_billing_summary(request: Request, user=Depends(require_authenticated_user)):
    summary = build_billing_summary((user or {}).get("uid"), role=(user or {}).get("role"))
    write_audit_log(
        event_type="billing.summary.read",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/billing/summary",
        method="GET",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"has_customer": summary.get("has_customer"), "has_active_subscription": summary.get("has_active_subscription")},
    )
    return {"ok": True, "billing": summary}


@router.post("/checkout-session")
def create_checkout_session(
    payload: CheckoutSessionRequest,
    request: Request,
    user=Depends(require_authenticated_user),
):
    result = create_checkout_session_for_student(
        uid=(user or {}).get("uid"),
        email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        purchase_kind=payload.purchase_kind,
        module_id=payload.module_id,
        plan_id=payload.plan_id,
        origin=payload.origin,
        success_path=payload.success_path,
        cancel_path=payload.cancel_path,
    )
    write_audit_log(
        event_type="billing.checkout_session.create",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/billing/checkout-session",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "purchase_kind": payload.purchase_kind,
            "module_id": payload.module_id,
            "plan_id": payload.plan_id,
            "session_id": result.get("session_id"),
        },
    )
    return {"ok": True, **result}


@router.post("/checkout-session/confirm")
def confirm_checkout_session(
    payload: CheckoutConfirmRequest,
    request: Request,
    user=Depends(require_authenticated_user),
):
    result = confirm_checkout_session_for_student(
        uid=(user or {}).get("uid"),
        role=(user or {}).get("role"),
        session_id=payload.session_id,
        module_id=payload.module_id,
    )
    write_audit_log(
        event_type="billing.checkout_session.confirm",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/billing/checkout-session/confirm",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"session_id": payload.session_id, "module_id": payload.module_id},
    )
    return {"ok": True, **result}


@router.post("/portal-session")
def create_portal_session(
    payload: PortalSessionRequest,
    request: Request,
    user=Depends(require_authenticated_user),
):
    result = create_portal_session_for_student(
        uid=(user or {}).get("uid"),
        email=(user or {}).get("email"),
        origin=payload.origin,
        return_path=payload.return_path,
    )
    write_audit_log(
        event_type="billing.portal_session.create",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/billing/portal-session",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"session_id": result.get("session_id")},
    )
    return {"ok": True, **result}


@router.post("/webhook", include_in_schema=False)
async def stripe_webhook(request: Request):
    payload = await request.body()
    result = process_stripe_webhook(payload, request.headers.get("Stripe-Signature"))
    write_audit_log(
        event_type="billing.webhook.process",
        actor_uid=None,
        actor_email=None,
        role="service",
        path="/billing/webhook",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "event_id": result.get("event_id"),
            "event_type": result.get("event_type"),
            "duplicate": result.get("duplicate"),
            "processed": result.get("processed"),
        },
    )
    return result


@router.post("/admin/subscription-resync")
def admin_resync_subscription(
    payload: AdminSubscriptionResyncRequest,
    request: Request,
    user=Depends(require_admin),
):
    result = resync_subscription_for_student(
        uid=payload.uid,
        stripe_subscription_id=payload.stripe_subscription_id,
    )
    write_audit_log(
        event_type="billing.admin.subscription_resync",
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path="/billing/admin/subscription-resync",
        method="POST",
        status=200,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={
            "target_uid": payload.uid,
            "stripe_subscription_id": payload.stripe_subscription_id,
            "resolved_subscription_id": result.get("subscription_id"),
            "provider_status": result.get("provider_status"),
        },
    )
    return {"ok": True, **result}
