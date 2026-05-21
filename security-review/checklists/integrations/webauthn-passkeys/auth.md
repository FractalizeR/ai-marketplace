# Authentication / Authorization (WebAuthn / FIDO2 / Passkeys)

> This checklist extends `core/auth.md` for projects that use WebAuthn / FIDO2 / Passkeys for authentication. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Confidence floor rules

- **Server does not verify the origin in the assertion response against the configured RP ID** — assertion verification accepts `clientDataJSON.origin` from any origin, or compares to a permissive allow-list — → `other:webauthn_misconfig` **confidence ≥ 8**. The phishing-resistance property of WebAuthn collapses without origin binding.
- **Counter check disabled** — server stores `signCount` but never compares against the previous value (or `signCount` is `0` and the server tolerates a stuck-at-zero clone) → `other:webauthn_misconfig` confidence ≥ 8. The authenticator's monotonic counter is the only signal of credential cloning.

## Origin / RP ID validation

WebAuthn binds credentials to a specific "Relying Party" — the server. Its identity is conveyed by two values:
- **RP ID** — a domain suffix (e.g. `example.com`); the credential is bound to this and the browser refuses to use it for any other origin.
- **Origin** — the full origin (e.g. `https://login.example.com:443`) of the client; the browser sets it in `clientDataJSON`, and the server MUST verify it.

Failure modes:
- **`rp.id` set to a TLD or eTLD+1 that the attacker controls a sibling of**: e.g. `rp.id = "example.com"` allows credentials from `phish.example.com` to be used against the main site if the attacker can run code there. Always set `rp.id` to the tightest possible suffix. Sink: `other:webauthn_misconfig` (or `missing_authz`).
- **Origin allow-list too broad in custom origin-checker implementations** (e.g. `'*'`, regex `.*`, or attacker-influenceable suffix matching). Canonical libraries like `web-auth/webauthn-lib` enforce explicit allow-listing via the `CheckOrigin` interface (`'*'` is not accepted as a literal there); this finding applies to projects with custom checker code that bypasses the library's safe default. Sink: `other:webauthn_misconfig`.
- **Origin not verified at all**: the AuthenticatorAssertionResponse handler ignores `clientDataJSON.origin`. See Confidence floor rules.
- **`crossOrigin: true` accepted on assertion**: assertions with `crossOrigin=true` originate from a different top-level origin than the form-action — accept only if the deployment explicitly supports iframe-embedded WebAuthn (rare and risky).

## Challenge replay and storage

WebAuthn registration and assertion both rely on a server-issued, cryptographically-random challenge that the authenticator signs over.

- **Challenge reused across operations**: same challenge stored in session and reused → an assertion from one session can be replayed against another. Each ceremony must mint a fresh challenge AND consume it on completion (delete on success/failure). Sink: `weak_random` if predictable, `other:webauthn_misconfig` if random but reused.
- **Challenge stored in a cookie not bound to the session**: cookie-only storage allows a passive attacker who replays the challenge alongside the assertion to log in as the victim. Use server-side session storage.
- **Challenge generated with weak randomness**: `mt_rand` / `rand` / time-based seeds → predictable challenge. Use `random_bytes(32)` (or library default). Sink: `weak_random`.

## User verification (UV) flag

The `userVerification` parameter ("discouraged" / "preferred" / "required") asks the authenticator to enforce a local user check (biometric, PIN, etc.).

- **`userVerification: "discouraged"` on a passwordless login flow**: the assertion succeeds with just presence (a touch), not identity confirmation — a left-behind unlocked authenticator suffices. For passwordless / sensitive operations, `required` is the standard. Sink: `other:webauthn_misconfig` (or `missing_authz`).
- **Server ignores the `UV` bit in the authenticator data**: client asked for `required` but server doesn't check the bit on assertion → bypass. The `flagsUserVerified` bit in `authenticatorData.flags` must be `true` when `userVerification: "required"` was requested.

## Counter check (signCount)

WebAuthn authenticators increment a monotonic counter on each assertion. The server should reject assertions with `signCount <= previous_signCount` for a given credential.

- **Counter not stored**: no detection of cloned authenticators. See Confidence floor rules.
- **Counter check skipped for `signCount = 0`**: Apple platform authenticators, Microsoft Hello, and synced passkeys (iCloud Keychain, Google Password Manager) generally send `0`. Hardware authenticators (Yubikey, Solokey) DO increment. The standard says servers MAY treat `0` as "counter not supported"; verify the policy is intentional and documented, not an accidental skip-all.
- **Counter rollback accepted**: assertion with `signCount < previous` is the canonical clone-detection signal. Look for `if ($newCounter <= $oldCounter)` patterns and ensure they reject (not log-and-continue).

## Attestation policy

`attestation: "none"` / `"indirect"` / `"direct"` / `"enterprise"` controls how much the authenticator proves about itself during registration.

- **`attestation: "none"` accepted without enterprise policy**: any authenticator, including a software-only attacker-controlled one, registers. For high-assurance environments, require `"direct"` and pin acceptable AAGUIDs to a list of certified authenticators. Sink: `other:webauthn_misconfig` (typically architecture-level).
- **Attestation statement not verified**: even with `"direct"` requested, the server must parse the attestation statement (packed / fido-u2f / tpm / android-key / apple) and validate the signature chain. If only the `clientDataJSON` is verified, the AAGUID is attacker-supplied.

## Backup eligibility / multi-device passkeys

Passkeys synced via iCloud Keychain / Google Password Manager / 1Password cross devices automatically. The `BE` (Backup Eligible) and `BS` (Backup State) bits in `authenticatorData.flags` signal this.

- **Code assumes all passkeys are hardware-bound for high-value operations**: a passkey synced across the user's devices (and to their cloud account) is reachable by anyone who compromises the cloud account. For step-up auth on financial mutation, prefer `BE = 0` (single-device passkey) or pair with a second factor.
- **Backup state change between registration and assertion**: `BS` flipping from `0` to `1` means the credential was added to a cloud sync — useful event to audit, not necessarily a vulnerability, but worth surfacing.

## Username enumeration via `allowCredentials`

In **server-side discoverable credential** flows the server sends `allowCredentials: [<list of credential IDs for the username the user entered>]`. This list reveals which usernames have registered passkeys.

- **`allowCredentials` populated based on user-supplied username on an unauthenticated endpoint**: attacker enters arbitrary usernames; an empty list reveals "no passkey registered", a non-empty list reveals "passkey exists". Defense: return a constant-length dummy list for unknown users, OR use the discoverable-credential (resident key) flow where the server passes `allowCredentials: []`.
- **Side channel via response timing**: even with constant-length responses, time-to-respond may differ when a real lookup is performed; verify constant-time handling.

## Account recovery

WebAuthn-only accounts cannot fall back to passwords. Recovery flows are where the threat usually moves to.

- **Password-reset email flow reactivates a non-passkey login**: the WebAuthn defense is fully bypassed by the recovery channel. The recovery channel must be at least as strong (e.g. requires a second registered passkey).
- **Magic link / OTP fallback always allowed**: same problem; flag as architectural finding.
- **No "list registered authenticators" UI for the user**: user can't notice that an attacker has registered a passkey on their account. Cross-ref `core/auth.md` (visibility of session changes).

## Worker search patterns

- `WebAuthn\\PublicKeyCredentialRpEntity` / `RelyingPartyEntity` — RP ID construction sites.
- `expectedOrigins\s*=` / `setOrigins\(` — origin allow-list scope.
- `userVerification\s*=>\s*['"]\w+['"]` — UV mode; check against the sensitivity of the calling flow.
- `signCount` / `getSignCount\(` — counter read/write; verify monotonic check.
- `attestation\s*=>\s*['"](\w+)['"]` — attestation policy.
- `allowCredentials` array construction near unauthenticated routes — enumeration vector.
- `random_bytes\(`, `bin2hex\(random_bytes\(` near challenge generation — verify entropy source.
