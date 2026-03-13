# Stripe Billing Setup

Required API environment variables:

- STRIPE_SECRET_KEY
- STRIPE_WEBHOOK_SECRET
- STRIPE_PRICE_MODULE_UNLOCK_DEFAULT
- STRIPE_PRICE_PREMIUM_MONTHLY
- STRIPE_PRICE_PREMIUM_SIX_MONTH
- STRIPE_PRICE_PREMIUM_YEARLY

GitHub Actions deploy wiring:

Repository variables expected by deploy-cloudrun.yml:

- APP_BASE_URL
- ALLOWED_APP_ORIGINS

Repository secrets expected by deploy-cloudrun.yml:

- STRIPE_SECRET_KEY
- STRIPE_WEBHOOK_SECRET
- STRIPE_PRICE_MODULE_UNLOCK_DEFAULT
- STRIPE_PRICE_PREMIUM_MONTHLY
- STRIPE_PRICE_PREMIUM_SIX_MONTH
- STRIPE_PRICE_PREMIUM_YEARLY
- STRIPE_PRICE_MODULE_F2
- STRIPE_PRICE_MODULE_F3
- STRIPE_PRICE_MODULE_F4

If the required Stripe secrets are missing during a deploy, the student paywall stays visible and checkout stays disabled in production.

Optional API environment variables:

- APP_BASE_URL
  Default: https://app.cognispark.tech
- ALLOWED_APP_ORIGINS
  Comma-separated extra origins allowed to start checkout and billing portal returns.
  Local defaults already allow localhost:3000 and 127.0.0.1:3000.
- STRIPE_PRICE_MODULE_F2
- STRIPE_PRICE_MODULE_F3
- STRIPE_PRICE_MODULE_F4
  Use module-specific price ids if any premium module needs a different one-time price.

Live endpoints added:

- GET /billing/summary
- POST /billing/checkout-session
- POST /billing/checkout-session/confirm
- POST /billing/portal-session
- POST /billing/webhook

Stripe webhook endpoint:

- POST https://api.cognispark.tech/billing/webhook

Stripe events to subscribe:

- checkout.session.completed
- customer.subscription.created
- customer.subscription.updated
- customer.subscription.deleted

Expected runtime behavior:

- Module unlock purchases are granted from completed Stripe checkout sessions.
- Premium subscriptions are synchronized from Stripe subscription events into student_billing.
- The student paywall launches Stripe Checkout.
- Students with a saved Stripe customer can open the Stripe billing portal.
- The success return path confirms the completed checkout session immediately so access refreshes without waiting for webhook timing.
