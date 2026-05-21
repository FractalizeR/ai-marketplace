# Okta integration — detection

This file describes how the recon agent detects Okta use and activates checklists from `integrations/okta/`. It is not a checklist — there are no vulnerability items.

## Okta signals (composer + env + source)

`bin/recon/recipes/okta_detect.py::detect_okta()` marks the project as using Okta if ANY of:

1. `composer.json` `require` / `require-dev` contains (all names verified on packagist):
   - `okta/jwt-verifier` — official JWT verifier.
   - `okta/sdk` — official SDK.
   - `socialiteproviders/okta` — Laravel Socialite Okta provider.
   - `foxworth42/oauth2-okta` — league/oauth2-client Okta provider.
2. `.env` references `OKTA_DOMAIN`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`, `OKTA_AUTH_SERVER_ID`, or `OKTA_ISSUER`.
3. PHP source under `src/` or `app/` contains an Okta tenant URL substring (`.okta.com` or `.oktapreview.com`).

The probe is bounded: at most 500 PHP files, 256 KB read per file; never walks the `vendor/` tree.

On a hit, the recon agent adds `okta` to `stack.integrations` in `CONTEXT.md`; `plan_waves.resolve_checklists(...)` then loads `integrations/okta/{theme}.md` after the generic `integrations/jwt-generic/` and `integrations/oauth-oidc/` layers, with the provider rules winning on conflict.

Canonical docs: [https://developer.okta.com/docs/concepts/](https://developer.okta.com/docs/concepts/).
