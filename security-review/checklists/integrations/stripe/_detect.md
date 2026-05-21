# Stripe integration — detection

This file describes how the recon agent detects Stripe use and activates checklists from `integrations/stripe/`. It is not a checklist — there are no vulnerability items.

## Stripe signals (composer + env + source)

`bin/recon/recipes/stripe_detect.py::detect_stripe()` marks the project as using Stripe if ANY of:

1. `composer.json` `require` / `require-dev` contains (all names verified on packagist):
   - `stripe/stripe-php` — official PHP SDK.
   - `laravel/cashier` — official Laravel Cashier (Stripe) bridge.
   - `omnipay/stripe` — Omnipay payment-gateway adapter.
2. `.env` / `.env.example` / `.env.local` / `.env.dist` declares any of `STRIPE_KEY`, `STRIPE_SECRET`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PUBLISHABLE_KEY`.
3. PHP source under `src/` or `app/` contains the substring `api.stripe.com` (the canonical service endpoint host).

The probe is intentionally lightweight (composer + env + bounded source scan with vendor-skip). On a hit, the recon agent adds `stripe` to `stack.integrations` in `CONTEXT.md`; `plan_waves.resolve_checklists(...)` then loads `integrations/stripe/{theme}.md`.

Note: Stripe does NOT imply `jwt-generic` / `oauth-oidc`. Webhook signatures use HMAC-SHA256 over the raw payload (`Stripe-Signature` header), not JWTs.

Canonical docs: [https://stripe.com/docs/api](https://stripe.com/docs/api), [https://stripe.com/docs/webhooks](https://stripe.com/docs/webhooks).
