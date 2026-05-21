# Firebase Authentication integration — detection

This file describes how the recon agent detects Firebase Auth use and activates checklists from `integrations/firebase-auth/`. It is not a checklist — there are no vulnerability items.

## Firebase Auth signals (composer + env + service-account file)

`bin/recon/recipes/firebase_auth_detect.py::detect_firebase_auth()` marks the project as using Firebase Auth if ANY of:

1. `composer.json` `require` / `require-dev` contains a Firebase Admin SDK or framework bridge:
   - `kreait/firebase-php` — core PHP Admin SDK (the canonical entry point).
   - `kreait/firebase-bundle` — Symfony bundle.
   - `kreait/laravel-firebase` — Laravel bridge.
2. `.env` references `FIREBASE_PROJECT_ID`, `FIREBASE_CREDENTIALS`, or `FIREBASE_CREDENTIALS_PATH`. The generic `GOOGLE_APPLICATION_CREDENTIALS` is ALSO accepted, but ONLY when corroborated by a Firebase-specific hint in the same env file (a `FIREBASE…` token in any key/value, or the substring `firebase` anywhere in the file) — bare `GOOGLE_APPLICATION_CREDENTIALS` matches non-Firebase Google SDK use and is too broad alone.
3. A service-account JSON file matching `*firebase-adminsdk-<key-id>.json` exists in the repository root or in `config/`. The Firebase console actually downloads service accounts as `{project-id}-firebase-adminsdk-{key-id}.json` (e.g. `myproject-firebase-adminsdk-fbsvc-abc123.json`), so we match the `firebase-adminsdk-…` substring anywhere in the filename rather than requiring it at the start.

The probe is intentionally lightweight (composer + env + filesystem checks only, no PHP parse).

On a hit, the recon agent adds `firebase-auth` to `stack.integrations` in `CONTEXT.md`; `plan_waves.resolve_checklists(...)` then loads `integrations/firebase-auth/{theme}.md` after the generic `integrations/jwt-generic/` and `integrations/oauth-oidc/` layers, with the provider rules winning on conflict.

Canonical docs: [https://firebase.google.com/docs/auth](https://firebase.google.com/docs/auth).
