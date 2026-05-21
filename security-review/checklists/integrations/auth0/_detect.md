# Auth0 integration — detection

This file describes how the recon agent detects Auth0 use and activates checklists from `integrations/auth0/`. It is not a checklist — there are no vulnerability items.

## Auth0 signals (composer + env + config)

`bin/recon/recipes/auth0_detect.py::detect_auth0()` marks the project as using Auth0 if ANY of:

1. `composer.json` `require` / `require-dev` contains (all names verified on packagist):
   - `auth0/auth0-php` — official PHP SDK.
   - `auth0/symfony` — official Symfony bundle.
   - `auth0/login` — canonical Laravel bridge.
   - `auth0/jwt-auth-bundle` — Symfony JWT bundle.
2. `.env` / `.env.example` / `.env.local` / `.env.dist` declares any of `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_AUDIENCE` — strong indicator even when the project uses a hand-rolled JWKS verifier.
3. `config/auth0.php` exists (Laravel `vendor:publish` output) OR `config/packages/auth0.yaml` exists (Symfony bundle config path).

The probe is intentionally lightweight (composer + env + filesystem checks only, no PHP parse). On a hit, the recon agent adds `auth0` to `stack.integrations` in `CONTEXT.md`; `plan_waves.resolve_checklists(...)` then loads `integrations/auth0/{theme}.md` after the generic `integrations/jwt-generic/` and `integrations/oauth-oidc/` layers, with the provider rules winning on conflict.

Canonical docs: [https://auth0.com/docs](https://auth0.com/docs).
