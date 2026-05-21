# Cryptography / secret management (AWS Secrets Manager)

> This checklist extends `core/crypto.md` for projects that use AWS Secrets Manager for secret storage. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Confidence floor rules

- **Secret value logged on retrieval**: `logger->info('Got secret', ['value' => $secret->getSecretString()])` or any log call that captures the secret string after a `getSecretValue()` → `pii_in_logs` **confidence ≥ 9** (cross-listed as `secret_in_response` if returned to the client). Once a secret enters the log pipeline it is forwarded to CloudWatch / SIEM / log aggregators and survives rotation.
- **`getSecretValue()` call result returned to an HTTP response (even via a debug toggle)** → `secret_in_response` confidence ≥ 9. The endpoint exposes the entire managed-secret population to any caller with the trigger.

## Secret rotation

- **Rotation disabled** on a long-lived credential (database password, API key) — `getSecretValue()` calls without an associated `RotationConfiguration` / scheduled Lambda rotator. Long-lived credentials = compromise window growing without bound. Architecture-level finding.
- **Rotation handler logs the new secret** — even a temporary log line "Rotated to X" leaks the new credential before the rotation completes. Sink: `pii_in_logs`.
- **Old credential not invalidated on rotation** — in 4-state rotation (CURRENT/PENDING/PREVIOUS/AWSPREVIOUS), application that pins to a specific stage label across rotations keeps the old credential alive indefinitely. Architecture-level finding.

## KMS encryption key (customer-managed vs AWS-managed)

Secrets Manager encrypts secrets at rest with a KMS key. By default, `createSecret` / `updateSecret` calls without an explicit `KmsKeyId` fall back to the AWS-managed key `alias/aws/secretsmanager`. The AWS-managed key cannot have its policy edited — any IAM principal with `secretsmanager:GetSecretValue` on the secret implicitly gets `kms:Decrypt`.

- **No `KmsKeyId` on `createSecret` / `updateSecret`**: the resulting secret is encrypted under AWS-managed CMK; cross-account access and fine-grained KMS audit are impossible. Cross-ref `core/crypto.md` (KMS hygiene). Architecture-level finding.
- **Customer-managed CMK with overly broad key policy**: `kms:Decrypt` granted to `Principal: "*"` or to a role with no SCP guardrails. Sink: missing-defense; cross-ref `core/crypto.md`.

## IAM policy permissiveness

Secrets Manager access is granted via IAM. Worker may have visibility into IAM policy JSON (in `iam/`, `terraform/`, or a `serverless.yml`) but not into runtime-attached roles.

- **`secretsmanager:*` on `Resource: "*"`**: an over-broad role that can read every secret in the account. Sink: `missing_authz` (architectural). Especially dangerous on Lambda / ECS task roles that are reachable via SSRF.
- **`secretsmanager:GetSecretValue` on `Resource: "*"`** instead of a specific ARN list: same blast radius, applied to read-only paths.
- **Wildcard ARN prefix**: `arn:aws:secretsmanager:*:*:secret:prod/*` includes future prod secrets the role wasn't intended to access; principle of least privilege violated.

## Secret ARN exposure

Secret ARNs have the shape `arn:aws:secretsmanager:<region>:<account>:secret:<name>-<6char-suffix>`. The suffix is random (added by AWS to prevent ARN squatting after delete+create), so ARNs are NOT meant to be sensitive — but the secret NAME is informative.

- **Hardcoded ARN exposed in commit history**: the suffix is not a secret, but the name (and account ID) is reconnaissance value — an attacker who breaches IAM later can enumerate exactly which secrets exist.
- **Hardcoded ARN with embedded value** (config drift: someone pasted the secret value next to the ARN): `hardcoded_secret` confidence ≥ 10. Look for `arn:aws:secretsmanager:...` lines adjacent to literal API keys.

## Cross-region replication

Secrets Manager supports auto-replication of secrets to another region. Replication uses a separate KMS key per region.

- **Cross-region replication enabled but replica region has a more permissive key policy**: secret encrypted under tight key in `us-east-1`, replica in `eu-west-1` uses default AWS-managed key — effective access broader than intended.
- **Replication of a rotated secret may lag rotation** — applications reading from the replica region during the window between rotation and replication may see PREVIOUS while issuer is on CURRENT. Architecture-level; cross-ref availability over security.

## Caller-side defenses

- **Secret cached in memory across requests** without a TTL: rotated credentials are not picked up; rolled-over secret silently stops working. Standard pattern is a 5-15 minute TTL with refresh-on-error.
- **`getSecretValue()` called on hot paths**: O(requests) API cost AND each call is logged in CloudTrail — DoS by inflating CloudTrail volume / Secrets Manager bill. Architecture-level; cross-ref availability.
- **Secret stored in a process env var after retrieval**: `putenv("DB_PASS=" . $secret)` makes it visible to subprocesses and child processes; `/proc/<pid>/environ` exposes it to anyone with the right PID. Architecture-level finding.

## Worker search patterns

- `->getSecretValue\(` / `SecretsManagerClient` — the canonical access points; check what's done with the returned `SecretString`.
- `kmsKeyId` / `KmsKeyId` named arg in `createSecret` / `updateSecret` — verify it's set to a CMK ARN, not omitted.
- `logger->[a-z]+\(.*\$secret` — grep proximity of secret variable to log calls.
- `secretsmanager:` in IAM policy JSON / yaml — verify resource scope.
