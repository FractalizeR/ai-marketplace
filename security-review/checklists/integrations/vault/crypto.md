# Cryptography / secret management (HashiCorp Vault)

> This checklist extends `core/crypto.md` for projects that use HashiCorp Vault for secret storage and dynamic credentials. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Confidence floor rules

- **TLS verification disabled** on a production Vault client — `VAULT_SKIP_VERIFY=true`, `verify_peer = false`, Guzzle / curl context `CURLOPT_SSL_VERIFYPEER => false`, or `allow_self_signed = true` against a non-localhost Vault address → `tls_validation_bypass` **confidence ≥ 9**. Vault's threat model relies entirely on TLS — without verification, any MitM intercepts the unwrap of every secret AND can substitute its own responses.
- **Vault root token (`hvs.root.` / `s.root.` legacy) committed to git or pasted into source** → `hardcoded_secret` **confidence ≥ 10**. The root token bypasses every policy; compromise = total Vault takeover.
- **Vault path constructed by direct concatenation of unsanitized user input**: `$client->read('/v1/secret/data/' . $_GET['path'])` → `path_traversal` confidence ≥ 9; cross-ref `core/injection.md`. Attacker reads arbitrary secret namespaces from the unauthenticated endpoint.

## Token lifecycle and rotation

Vault tokens are the primary auth credential — they have leases (TTLs) and can be renewed / revoked.

- **Long-lived root or admin token in `VAULT_TOKEN` env**: a non-rotating token granting `*` policy effectively turns Vault into a single shared password. Use AppRole / Kubernetes / AWS IAM auth methods that mint short-lived (TTL ≤ 1h) tokens scoped to the workload. Architecture-level finding; cross-ref `core/crypto.md`.
- **Token not revoked on logout / shutdown**: app should call `auth/token/revoke-self` on graceful shutdown. Without revocation, the token survives until its lease expires — a stolen log / memory dump that captures the token is usable for the remaining TTL.
- **Renewal-only loop without re-authentication ceiling**: a daemon that calls `auth/token/renew-self` indefinitely effectively keeps a token alive forever (each renewal extends TTL up to `max_ttl`). Re-authenticate via the underlying auth method on `max_ttl` expiry.

## TLS verification

See Confidence floor rules above. Additional cases:

- **CA bundle pinning bypassed**: hardcoded `ca_file = "/etc/ssl/ca-bundle.crt"` works in dev but is missing in production container → client silently falls back to system roots (or fails open if combined with `verify=false`). Architecture-level.
- **TLS 1.0 / 1.1 acceptable on the client**: Vault recommends TLS 1.3 (minimum 1.2). Old client libraries can negotiate weak versions. Cross-ref `core/crypto.md`.

## Path traversal and policy bypass

Vault HTTP paths follow `/v1/<mount>/data/<path>` for KV v2 or `/v1/<mount>/<path>` for KV v1. The path segment is the policy-enforcement key — policies grant `read` on specific paths or path globs.

- **User-controlled path passed to `Client::read`**: see Confidence floor rules. The danger isn't just traversal — Vault enforces policy on the path, but `secret/data/public/foo` and `secret/data/customers/foo` may both be readable under the application's policy, so attacker enumeration is unbounded.
- **Path normalization mismatch**: Vault normalizes paths internally; user-supplied paths with `..` or double-slashes may pass app-level checks but be normalized to a different policy decision. Defense: allow-list paths server-side, never concatenate.

## Policy scope (blast radius)

- **Policy granting `read` on `secret/*`** to every application service: any compromised service reads every secret. Each service should have its own policy with the minimum path scope.
- **Default policy not stripped**: `default` policy grants `lookup-self`, `renew-self`, etc. — fine for tokens. Application tokens may inadvertently retain `default` capabilities they don't need (e.g., `cubbyhole` write).
- **Wildcard capabilities (`"*"`)**: `capabilities = ["*"]` includes `delete` / `sudo` — far broader than `["read"]`.

## Dynamic secrets and lease management

Vault's killer feature: dynamic database / cloud / PKI credentials with short leases. Misuse:

- **`default_lease_ttl` > 24h on dynamic database engine**: defeats the dynamic-secret purpose; a compromised credential is reusable for a day. Recommended `default_lease_ttl` for DB engine: ≤ 1 hour.
- **`max_ttl` unbounded** (or set to `0`): renewals are unlimited; a token-+-secret pair never forces rotation.
- **App doesn't revoke leases on shutdown**: leftover DB credentials accumulate in the database (up to Vault revocation poll). Architecture-level.

## Audit logging

Vault audit devices write every request/response (with sensitive fields hashed) to a sink. No audit device = no forensic trail.

- **No audit device enabled** (visible if Vault config / Terraform is in repo): cross-ref `core/disclosure.md` (logging gaps).
- **Audit device sink is the local filesystem on a single Vault node**: failure of disk = Vault failure (audit is fail-closed by default). Reliability/availability issue, but worth flagging as it forces operators to disable audit during incidents — a documented Vault outage pattern.

## Worker search patterns

- `VAULT_SKIP_VERIFY` / `verify_peer\s*=\s*false` / `CURLOPT_SSL_VERIFYPEER\s*=>\s*(false|0)` — TLS bypass.
- `Client.*->read\(.*\$` / `Client.*->write\(.*\$` — user-input flowing into Vault path.
- `auth/token/(revoke|renew)-self` — verify lifecycle handling on logout / shutdown.
- `\bhvs\.[A-Za-z0-9]+\b` / `\bs\.[A-Za-z0-9]+\b` — Vault tokens in literals (s. = legacy SHA-1 tokens; hvs. = current).
- IAM policy JSON / HCL `path "secret/*"` blocks — review capability scope.
