# Authentication / Authorization (Firebase Authentication)

> This checklist extends `core/auth.md` for projects that use Firebase Authentication. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

> **Layering note**: Firebase ID tokens are Google-signed JWTs. The worker also loads `integrations/jwt-generic/auth.md` and `integrations/oauth-oidc/auth.md` for the underlying mechanics. This file documents the **Firebase-specific** patterns on top of those.

## Confidence floor rules

- **Service-account JSON (`firebase-adminsdk-*.json` containing `private_key`) committed to git or in an unencrypted backup** → `hardcoded_secret` **confidence ≥ 10**. Absolute evidence. The service-account key grants Firebase Admin SDK access, which bypasses ALL Firebase Auth rules AND grants read access to the entire Realtime Database / Firestore / Cloud Storage for the project. Severity = critical regardless of attacker capability assumptions.
- **API key (`apiKey`) embedded in client JS used as if it were a secret on the server**: API keys on Firebase are NOT secrets (they're meant to be exposed in client-side code) — but they ARE rate-limit identifiers. Server-side code that treats `FIREBASE_API_KEY` as a credential is a category error; flag as architecture-level finding, not a `hardcoded_secret`.

## ID token validation specifics

- **`iss` exact match required**: Firebase ID tokens carry `iss = https://securetoken.google.com/{project_id}` — note the host `securetoken.google.com` (NOT `accounts.google.com`, which is Google Sign-In, a different product). A verifier configured for the wrong issuer rejects all Firebase tokens; the "fix" tends to be disabling the issuer check. Sink: `oidc_misconfig`.
- **JWKS endpoint**: Firebase uses Google's x509 cert format, fetched from `https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com`. The Admin SDK handles this automatically; hand-rolled verifiers often hit the wrong endpoint and disable signature checks "for now". Sink: `oidc_misconfig`.
- **`aud` validation**: `aud` must equal the Firebase project ID. A verifier that doesn't check `aud` accepts tokens from any Firebase project (cross-project token confusion). Sink: `oidc_misconfig`.

## Admin SDK: `verifyIdToken(token, checkRevoked)`

The Admin SDK's `verifyIdToken` has a second argument `checkRevoked` that defaults to `false`:

- **`checkRevoked` not set to `true` on sensitive endpoints**: when a user logs out OR an admin disables their account, their ID tokens remain "valid" until natural expiry (default 1 hour) because the verifier doesn't query the revocation list. For high-value endpoints (admin actions, financial mutation), `checkRevoked=true` is required. Architecture-level finding; cross-ref `integrations/jwt-generic/auth.md` for the generic JTI-revocation pattern.

## Custom claims

Firebase custom claims are stored on the user record and copied into the ID token at issuance.

- **Custom-claims size limit (1KB total)**: Firebase silently truncates / rejects custom claims over 1KB. Code that packs JSON-serialized payloads into custom claims may lose data without an error — security-sensitive claims (`tenant_id`, `roles`) may silently fall off. Sink: `oidc_misconfig`.
- **Custom claims written from a user-controlled input** (e.g., a self-service profile endpoint copies `request.body.role` to `setCustomUserClaims`) — direct privilege escalation. The Admin SDK has no built-in guard; this is the project's responsibility. Sink: `missing_authz`.
- **Reserved-name collision**: setting custom claims with names that overlap reserved JWT claims (`sub`, `iat`, `exp`, `aud`, `iss`) is silently dropped by Firebase. Code that reads the custom claim back gets `null` — silent fail-open if the verifier uses the missing value to gate access.

## `email_verified` and anonymous-user promotion

Firebase supports anonymous accounts that can later be linked (promoted) to a permanent identity. The anonymous UID is preserved across promotion.

- **`email_verified` not checked**: code that grants permissions based on email ownership without `email_verified === true` accepts unverified emails. Particularly dangerous when the user pool mixes Google sign-in (which sets `email_verified=true`) with email/password (which doesn't until the verification link is clicked). Sink: `missing_authz`.
- **Anonymous-to-permanent promotion accepts stolen sessions**: the anonymous user signs in (`signInAnonymously()`), an attacker captures the anonymous session (e.g. via stored XSS), the attacker calls `linkWithCredential` to bind their own credentials → the attacker now controls a stable identity that retains all data the anonymous user created. Mitigation: re-authentication before link, OR forbid anonymous promotion entirely. Sink: `missing_authz`.

## Firebase Auth REST API

The Firebase Auth REST API (`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=...`) takes the API key as a URL parameter.

- **API key exposed in client JS used to enumerate emails / brute-force passwords**: the API key + the REST endpoint give an attacker a rate-limited oracle for `accounts:signInWithPassword`. Failed attempts return distinct error codes for "email not registered" vs "wrong password" — email enumeration. App Check (Firebase's bot-protection layer) is the mitigation; without it, the API key + endpoint is an enumeration vector. Cross-ref `secret_in_response`. Architecture-level finding.

## Worker search patterns

- `Kreait\\Firebase\\Factory` — SDK construction; check the service-account source (env var path is OK, literal JSON in code is `hardcoded_secret`).
- `->auth()->verifyIdToken(` — check the second argument. Missing or `false` = no revocation check.
- `->auth()->setCustomUserClaims(` — check the value source. Anything sourced from a request body without server-side validation is a privilege-escalation vector.
- `firebase-adminsdk-*.json` filename in any of: repo root, `config/`, `secrets/`, CI artifacts. If found, that file MUST NOT be tracked by git AND must not be present in tarballs / docker images. Run `git log --all --diff-filter=A -- '*.json' | grep adminsdk` to spot historical commits.
- `.env` keys `FIREBASE_CREDENTIALS`, `FIREBASE_CREDENTIALS_PATH` — verify the value points to a path outside the repo OR loads JSON from a secret store, never a literal value in `.env`.
