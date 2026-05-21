# Information disclosure (Symfony + API Platform)

> This checklist extends `core/disclosure.md` and `stacks/symfony/disclosure.md` for projects using the API Platform bundle. On instruction conflict, this file takes precedence as the most specific layer. The worker loads all three files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Recipe-driven recall

When `recon_bags.addon.api-platform.resources.status == ok` walk `items[*]` to read each Resource's `graphql_enabled` flag plus any `enable_*` docs-surface configuration (`enable_swagger_ui`, `enable_graphiql`, `enable_re_doc`, `enable_docs`, `enable_swagger`). Until the extractor lands (current state: `status="unknown"`), fall back to grep on `#\[ApiResource`, `enable_swagger_ui`, `enable_graphiql`, `enable_re_doc`, `enable_docs`, `enable_swagger` in `config/packages/api_platform.{yaml,php}` and `src/`.

## API Platform docs and schema exposure

API Platform's docs surface is a one-stop attack-surface map. Each enabled docs UI describes every Resource, every field, every operation, and the security requirements applied — perfect reconnaissance.

- **`enable_swagger_ui: true` in prod without auth firewall** → unauthenticated `/api/docs` renders the full Swagger UI. Cross-ref: `auth.md` → docs surface authentication. Sink_kind: `stacktrace_exposed` or `other:openapi_disclosed` (root_cause_family: `disclosure`).
- **`enable_re_doc: true` (Redoc)** in prod without firewall → same disclosure via the alternate UI. The bundle ships both UIs; disabling one without disabling the other is partial mitigation.
- **`enable_docs: true`** (the umbrella flag) in prod → covers Swagger UI + Redoc + Hydra docs surfaces. Set `false` in `config/packages/prod/api_platform.yaml`, or firewall `^/api/docs` with `ROLE_ADMIN`.
- **OpenAPI raw JSON at `/api/docs.json`** public → full schema (every Resource, every field, every operation, security expressions) in machine-readable form. Default route is `_api_doc.json`; firewall it explicitly — disabling the UI does NOT disable the raw endpoint by default.

## GraphiQL / GraphQL introspection in prod

- **`enable_graphiql: true`** in `prod/api_platform.yaml` → interactive GraphQL playground accessible at `/api/graphql` (UI). GraphiQL itself issues introspection queries to render the type tree → equivalent to enabling introspection. Confidence floor ≥ 8 in prod.
- **GraphQL introspection enabled** (the underlying `__schema` query without GraphiQL UI) — cross-ref: `auth.md` → GraphQL field authz / Introspection in prod. The canonical placement of the introspection bullet is `auth.md` per the existing `stacks/symfony/auth.md` convention; this file cross-references it because some teams categorize introspection as disclosure rather than authz.

## Hydra / JSON-LD error verbosity

- **Hydra `hydra:description` returns exception `getMessage()` in prod**: API Platform's default error formatter copies `$exception->getMessage()` into the JSON-LD response (`{"@type": "hydra:Error", "hydra:description": "SQLSTATE[23000]: ..."}`) → SQL error / Doctrine schema / file paths leak. Sink_kind: `stacktrace_exposed`. Configure a custom `ErrorListener` / `ExceptionListener` in prod that masks vendor exception messages.
- **`hydra:title` in prod returns class name of exception** → discloses internal framework / library names (PHP version probing).

## Existence / topology oracles

- **`@id` IRI references reveal existence of hidden resources**: an embedded relation in a public Resource response contains `@id: "/api/admin_panels/42"` even when `admin_panels` is access-controlled → attacker enumerates IDs. Mitigation: exclude sensitive associations from public `normalizationContext.groups` entirely (the `@id` only appears when the relation is serialized).
- **`_links` (HAL format) similarly exposes URI templates** when `formats: ['jsonhal']` is enabled. Same existence-oracle risk.

## Format proliferation = attack surface expansion

- **`formats:` includes rarely-used formats** in `api_platform.yaml`: `jsonhal`, `jsonapi`, `xml`, `csv`, `yaml`. Each format is parsed by a different normalizer/decoder; rarely-used formats receive less audit attention upstream. Stick to `jsonld` + (optionally) `json`. Each extra format is a parser CVE surface — drop anything the clients don't actually consume.
