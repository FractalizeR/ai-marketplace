# WebAuthn / FIDO2 / Passkeys integration — detection

This file describes how the recon agent detects WebAuthn / Passkeys use and activates checklists from `integrations/webauthn-passkeys/`. It is not a checklist — there are no vulnerability items.

## WebAuthn signals (composer + env + source)

`bin/recon/recipes/webauthn_passkeys_detect.py::detect_webauthn_passkeys()` marks the project as using WebAuthn if ANY of:

1. `composer.json` `require` / `require-dev` contains (all names verified on packagist):
   - `web-auth/webauthn-lib` — core WebAuthn library.
   - `web-auth/webauthn-symfony-bundle` — Symfony bundle.
   - `web-auth/webauthn-framework` — umbrella package shipping the lib + ancillaries.
   - `lbuchs/webauthn` — community PHP WebAuthn library.
2. `.env` / `.env.example` / `.env.local` / `.env.dist` declares any of `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`.
3. PHP source under `src/` or `app/` contains either:
   - `Webauthn\PublicKeyCredentialOptions` — note the lowercase `a`; this is the actual PSR-4 namespace of `web-auth/webauthn-lib`'s credential-options factory.
   - `lbuchs\WebAuthn\WebAuthn` — entry-point class of `lbuchs/webauthn` (preserves the upstream capitalization).

The probe is intentionally lightweight (composer + env + bounded source scan with vendor-skip). Out of scope for Stage 7 simplicity: JS-side `navigator.credentials.create()` / `navigator.credentials.get()` scanning — the PHP-side signals already catch every real WebAuthn integration in our threat model.

On a hit, the recon agent adds `webauthn-passkeys` to `stack.integrations` in `CONTEXT.md`; `plan_waves.resolve_checklists(...)` then loads `integrations/webauthn-passkeys/{theme}.md`.

Note: `webauthn-passkeys` does NOT imply `jwt-generic` / `oauth-oidc` — WebAuthn is a public-key authentication protocol (CTAP / FIDO2), not a token-based one.

Canonical docs: [https://www.w3.org/TR/webauthn-3/](https://www.w3.org/TR/webauthn-3/).
