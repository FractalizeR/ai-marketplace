# Keycloak integration — detection

This file describes how the recon agent detects Keycloak use and activates checklists from `integrations/keycloak/`. It is not a checklist — there are no vulnerability items.

## Keycloak signals (composer + env + source)

`bin/recon/recipes/keycloak_detect.py::detect_keycloak()` marks the project as using Keycloak if ANY of:

1. `composer.json` `require` / `require-dev` contains (all names verified on packagist):
   - `stevenmaguire/oauth2-keycloak` — Keycloak provider for league/oauth2-client.
   - `robsontenorio/laravel-keycloak-guard` — Laravel JWT guard for Keycloak.
   - `vizir/laravel-keycloak-web-guard` — Laravel web guard for Keycloak.
   - `socialiteproviders/keycloak` — Laravel Socialite Keycloak provider.
   - `mohammad-waleed/keycloak-admin-client` — Keycloak admin REST client.
   - `fschmtt/keycloak-rest-api-client-php` — Keycloak REST API client.
   - `mainick/keycloak-client-bundle` — Symfony Keycloak client bundle.
   - `idci/keycloak-security-bundle` — Symfony Keycloak security bundle.

   Note: `nbgrp/oidc-bundle` is a GENERIC OIDC bundle (works with any
   provider — Auth0, Okta, Google, Keycloak, …), so it gates the
   `oauth-oidc` integration, NOT this one.
2. `.env` references `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, or `KEYCLOAK_CLIENT_SECRET`.
3. PHP source under `src/` or `app/` contains BOTH `/realms/` AND `/protocol/openid-connect/` substrings — the canonical Keycloak token / userinfo / JWKS URL shape. The conjunction is the precision floor: either substring alone is too ambiguous (`/realms/` appears in DDD code unrelated to auth; `/protocol/openid-connect/` is rare but appears in compliance docs); together they uniquely identify a Keycloak server URL.

The probe is bounded: at most 500 PHP files, 256 KB read per file; never walks the `vendor/` tree.

On a hit, the recon agent adds `keycloak` to `stack.integrations` in `CONTEXT.md`; `plan_waves.resolve_checklists(...)` then loads `integrations/keycloak/{theme}.md` after the generic `integrations/jwt-generic/` and `integrations/oauth-oidc/` layers, with the provider rules winning on conflict.

Canonical docs: [https://www.keycloak.org/documentation](https://www.keycloak.org/documentation).
