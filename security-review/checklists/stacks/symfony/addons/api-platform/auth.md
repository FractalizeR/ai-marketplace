# Authentication / Authorization (Symfony + API Platform)

> This checklist extends `core/auth.md` and `stacks/symfony/auth.md` for projects using the API Platform bundle. On instruction conflict, this file takes precedence as the most specific layer. The worker loads all three files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Recipe-driven recall

When `recon_bags.addon.api-platform.resources.status == ok` the worker walks `items[*].operations[*]` directly: each operation carries `verb`, `security`, `security_post_denormalize`, `normalization_groups`, `denormalization_groups`, `filters`, `pagination_max`, plus the parent class's `graphql_enabled`. Grep is a fallback. Until the extractor lands (current state: `status="unknown"`), use the grep path: `grep -rn "#\\[ApiResource\\|new Get\\|new Post\\|new Patch\\|new Put\\|new Delete\\|new GetCollection" src/`.

## REST: `#[ApiResource]` operation security

API Platform serializes Entities through `#[ApiResource]` declarations. Without per-operation `security` / `securityPostDenormalize`, every operation (Get/GetCollection/Post/Patch/Put/Delete) is anonymous-accessible. The bundle does not enforce a default deny — absence of `security` means "open".

- **`#[ApiResource]` without `security`/`securityPostDenormalize`**: a Resource declared as `#[ApiResource(operations: [new Get(), new GetCollection(), new Post()])]` without a class-level `security: "is_granted('ROLE_USER')"` AND without per-operation `security` → query/mutation accessible to everyone. Entity fields are serialized by `#[Groups]` without an owner check. Sink_kind: `missing_authz`.
- **Per-operation security missing on mutating verbs**: `Post`/`Patch`/`Put`/`Delete` operation without `security: "is_granted(...)"`, or worse with `security: "is_granted('PUBLIC_ACCESS')"` → write without authz. `PUBLIC_ACCESS` is a special API Platform attribute that grants everyone — should only appear on read-only public listing endpoints.
- **`securityPostDenormalize` absent when mass-assignment matters**: when `denormalization_groups` allow editing identity/ownership fields (`owner`, `tenant`, `userId`), and `security` only checks pre-denormalization context, the client can mutate ownership via the payload itself. The check must run AFTER denormalization (`securityPostDenormalize: "is_granted('EDIT', object)"`) to compare against the new state.
- **`security: "object.owner == user"` on `GetCollection`**: `object` is undefined for collection operations (no single object exists yet); the expression effectively short-circuits to false/skip → either everyone passes or no one does, depending on engine version. Collection authz belongs in a custom `QueryExtension` or `StateProvider`, not in the operation-level `security` expression.
- **State Provider / State Processor without authz**: a custom `ProviderInterface` (replaces the default `ItemProvider`/`CollectionProvider`) that reads from a service without invoking the security voter chain → bypass of the standard ApiResource `security` expression. Same for `ProcessorInterface` on write — must call `$this->security->isGranted(...)` or rely on a voter.
- **IRI deserialization on write → ownership shift**: API Platform accepts JSON-LD IRIs (`@id: "/api/users/42"`) to wire relations on POST/PATCH. If the Entity has a `setOwner(User $user)` setter inside denormalization groups, the client supplies someone else's `@id` → ownership shift mass-assignment. Mitigations: drop the field from `denormalization_groups`, use `security_post_denormalize` to verify `object.owner == user`, or wire a custom `Denormalizer` that pins ownership server-side.

## REST: docs surface authentication

API Platform ships built-in Swagger UI / Redoc / Hydra docs. By default these are exposed without the auth firewall — fine in dev, leak in prod.

- **`/api/docs` / `/api/docs.json` / `/api/contexts/...`** without firewall coverage in `security.yaml` → unauthenticated client gets the full OpenAPI schema (all Resource classes, all fields, all operations including admin-only) → information disclosure + attack-surface map (cross-ref `disclosure.md`).
- **GraphiQL at `/api/graphql`** in prod without firewall → same problem for the GraphQL schema (introspection-equivalent: GraphiQL itself queries `__schema`). See the GraphQL section below.

## GraphQL field authz (API Platform-specific)

> See `stacks/symfony/auth.md` → GraphQL section for overblog/webonyx-specific patterns. Below is the api-platform side.

API Platform's GraphQL bundle reuses the same `#[ApiResource]` operations metadata as REST. If a Resource enables GraphQL (`#[ApiResource(graphQlOperations: [new Query(), new Mutation(name: 'create')])]`), the authz model mirrors REST — but with the added introspection attack surface.

- **`#[ApiResource]` GraphQL operation without `security`**: `graphQlOperations: [new Query()]` without `security: "is_granted(...)"` on the operation → field-level GraphQL queries accessible anonymously. Same root cause as REST per-operation missing, but the worker must check `graphQlOperations` separately from `operations` (the REST list does not transfer).
- **Per-operation GraphQL `security` missing on mutations**: `new Mutation(name: 'create')` / `new Mutation(name: 'update')` / `new Mutation(name: 'delete')` without `security` → write mutations accessible without auth. Sink_kind: `missing_authz`.
- **Introspection enabled in prod**: API Platform leaves `__schema { types { name fields { name } } }` accessible by default. The setting `api_platform.graphql.introspection.enabled` (or absence of `enable_graphiql: false` + `enable_docs: false` + `enable_swagger_ui: false` for the docs surface) → attacker enumerates every Resource, every field, every mutation, including admin-only routes. Confidence floor **≥ 8** in prod. Sink_kind: `other:graphql_introspection_enabled` (root_cause_family: `disclosure`). Cross-ref: `disclosure.md`.
