# Output rendering / Serialization (Symfony + API Platform)

> This checklist extends `core/output-render.md` and `stacks/symfony/output-render.md` for projects using the API Platform bundle. On instruction conflict, this file takes precedence as the most specific layer. The worker loads all three files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Recipe-driven recall

When `recon_bags.addon.api-platform.resources.status == ok` walk `items[*]` and for each operation read `normalization_groups`/`denormalization_groups`. Until the extractor lands (current state: `status="unknown"`), fall back to grep on `#\[ApiResource` + `#\[Groups` + `normalizationContext` / `denormalizationContext` in `src/`.

## `#[ApiResource]` serialization groups

API Platform uses the Symfony Serializer with `#[Groups]` filtering. Without an explicit normalization context, the serializer enumerates every public getter on the Entity → all model fields leak.

- **`#[ApiResource]` without `normalizationContext.groups`** — all public-getter Entity fields are serialized for every operation. Fields like `accessToken`, `refreshToken`, `passwordHash`, `mfaSecret`, `apiToken`, `webhookSecret`, `clientSecret` leak to the client if they exist as Entity property/getter. Must be `#[Groups(['user:read'])]` on safe fields + `normalizationContext: ['groups' => ['user:read']]` on the operation. Sink_kind: `secret_in_response` or `sensitive_field_unmasked` (root_cause_family: `disclosure`).
- **`denormalizationContext.groups` missing** → mass-assignment: every Entity setter becomes a denormalization sink. The client supplies `{"roles": ["ROLE_ADMIN"], "owner": "/api/users/1"}` and the bundle calls every matching setter. Must whitelist with `denormalizationContext: ['groups' => ['user:write']]` and tag write-safe fields with `#[Groups(['user:write'])]`.
- **`output: false` / `input: false` without a DTO**: declaring `output: false` skips serialization but leaves the Entity exposed via `input` setters, and vice versa. Without an explicit DTO class (`output: UserOutputDto::class`), the Entity itself becomes both denormalization and normalization target → mass-assignment + over-exposure on the same operation.
- **`#[Groups]` configuration on Entity directly** without a separation between read-groups and write-groups: a single `#[Groups(['user'])]` on `passwordHash` makes it both readable AND writable. Always split: `#[Groups(['user:read', 'user:write'])]` are NOT the same set; reuse only when intentional.

## JSON-LD / Hydra context

API Platform emits Hydra/JSON-LD `@context` and `@type` metadata by default. The `@type` exposes the internal Resource class name.

- **`@type` leaks internal model names**: a Resource named `App\\Entity\\InternalLegacyUser` exposes `@type: InternalLegacyUser` in every response → information disclosure of the data model topology. Override via `#[ApiResource(types: ['https://schema.org/Person'])]` or `shortName: 'User'` when the implementation name is sensitive.
- **`@id` IRIs reveal existence of hidden resources**: `@id: "/api/secret_audit_logs/123"` appears in any embedded relation even when the linked resource is access-controlled → existence oracle. Cross-ref: `disclosure.md` → existence oracle.

## Custom Normalizers

- **Custom `NormalizerInterface` without Groups-aware projection**: a custom Normalizer that returns `$object` raw or `$object->toArray()` ignores the `groups` context and serializes everything → undoes `normalizationContext.groups` protection on the operations that use this Normalizer. Verify the implementation calls `$this->normalizer->normalize($data, $format, $context)` with the passed-through `$context` (Groups-aware) rather than building the array by hand.

## GraphQL output filtering (API Platform-specific)

> See `stacks/symfony/output-render.md` → GraphQL section for overblog/webonyx-specific patterns. Below is the api-platform side.

GraphQL is an alternative output channel; the same disclosure / secret leakage rules apply. Field-level authz (who sees) — in `auth.md`; here — what ends up in the response payload.

- **API Platform Resource without `#[Groups]`** (GraphQL branch) — all public-getter Entity fields are accessible via GraphQL field selection: `accessToken`, `refreshToken`, `passwordHash`, `mfaSecret`, `apiToken`, `webhookSecret` leak to the client if they exist as Entity property/getter. Same root cause as the REST case; mitigation is identical (`#[Groups(['user:read'])]` + `normalizationContext` on `graphQlOperations`). Sink_kind: `secret_in_response` or `sensitive_field_unmasked` (root_cause_family: `disclosure`).

**Cross-link**: `secret_in_response` for polluted output — see `core/crypto.md`. `sensitive_field_unmasked` — see `core/disclosure.md`.
