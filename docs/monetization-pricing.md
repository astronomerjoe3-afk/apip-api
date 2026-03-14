# Monetization Pricing Recommendation

Date checked: 2026-03-12

## Recommended launch prices

- F1 stays free.
- Premium module access pass: $9.99 for 1 month of access to one premium module.
- Premium monthly: $12.99 per month.
- Premium 6 months: $59.99 every 6 months ($10.00/month effective).
- Premium yearly: $99.99 per year ($8.33/month effective).

## Why these prices

- Inference: price below broad career-learning subscriptions because this catalog is narrower and still growing, but above lightweight study tools because the product includes diagnostics, guided lessons, simulations, and mastery checks.
- Keep the 1-month module access pass slightly below one month of premium so a student focused on one premium module can buy targeted access, while students taking multiple premium modules still have a clear reason to subscribe.

## Official market anchors checked on 2026-03-12

- Quizlet Upgrade: $35.99/year ($2.99/month) and $44.99/year ($3.74/month). https://quizlet.com/upgrade
- Codecademy Pricing: Plus is $29.99 monthly or $14.99/month billed annually; Pro is $39.99 monthly or $19.99/month billed annually. https://www.codecademy.com/pricing
- Coursera Plus: $59/month or $399/year, with a temporary promotional banner also shown on 2026-03-12. https://www.coursera.org/courseraplus
- Babbel Review: six-month plan at $13.45/month billed every 6 months and annual plan at $8.95/month billed yearly. https://www.babbel.com/babbel-review
- Babbel Help: multi-month plans are paid upfront for the whole term. https://support.babbel.com/hc/en-us/articles/205600328-Timing-of-subscription-payments

## Pricing rule for future modules

- Default every module except F1 to `access_tier: premium` unless you explicitly mark it free in Firestore.
- Use the same 1-month module access pass price for launch unless a future module is unusually large enough to justify its own Firestore price override.
