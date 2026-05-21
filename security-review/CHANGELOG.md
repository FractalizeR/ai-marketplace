# Changelog

All notable changes to this plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] — 2026-05-21

### Five-layer checklist resolver and integrations layer

Major architectural release. The checklist resolver moves from a flat two-level scheme (`core/` + `frameworks/`) to a five-layer chain that scales to multiple languages, sub-framework addons, and vendor / capability integrations. First content lands in the new `addons/` and `integrations/` layers.

### Added

- **Resolution chain.** Five layers, less specific to more specific: `core/` → `languages/{lang}/` → `stacks/{stack}/` → `stacks/{stack}/addons/{addon}/` → `integrations/{integration}/`. Precedence on conflict: integration > addon > stack > language > core. Integrations apply even when stack is `none` / `unknown`. New `ResolutionContext` dataclass with normalized addons/integrations.
- **Symfony addons.**
  - `stacks/symfony/addons/easyadmin/` and `.../sonata/` extracted from inline stack-checklist sections into dedicated addon files. Recipe-driven recall via `recon_bags.addon.easyadmin.crud_controllers` and `recon_bags.addon.sonata.admin_classes`.
  - `stacks/symfony/addons/api-platform/` — REST and GraphQL coverage: `_detect.md`, `auth.md`, `data-access.md`, `output-render.md`, `disclosure.md`. New `recon_bags.addon.api-platform.resources` schema slot (PHP sandbox extractor deferred; placeholder bag).
- **Integrations layer (12 directories total).**
  - Generic capabilities: `jwt-generic`, `oauth-oidc`.
  - Identity providers: `auth0`, `aws-cognito`, `okta`, `keycloak`, `firebase-auth`. Provider detection auto-includes generic JWT and OAuth/OIDC layers via `PROVIDER_IMPLIES_INTEGRATIONS`.
  - Vendor / capability integrations: `stripe` (fintech), `aws-secrets-manager` (crypto), `vault` (crypto), `saml` (auth), `webauthn-passkeys` (auth).
- **New core theme `security-headers.md`** covering CSP, frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS, COOP/COEP/CORP. Added as third theme of W3.
- **`## Trusted patterns (do NOT flag)`** convention (Anthropic `claude-code-security-review` precedent) — negative filter for safe-by-construction idioms. Seeded in `core/{auth, output-render, injection}.md` (CSPRNG primitives, default-escape templating, parameterized ORM queries).
- **Confidence caps** — new upper-bound rules complementing existing floors. `redirect_open` and `ssrf` capped at confidence 5 when only the URL path is attacker-controlled (host/scheme/port hardcoded). `race_condition` floor `≥ 8` only for TOCTOU on concrete state mutation; read-side cache races capped at 4.
- **`sink_kind` enum** extended from 30 to 41 values:
  - Security headers: `csp_missing`, `csp_unsafe_inline`, `clickjacking_unprotected`, `hsts_missing`, `mime_sniff_unprotected`.
  - JWT / OAuth: `jwks_spoof`, `oidc_misconfig`, `tls_validation_bypass`.
  - Injection sub-kinds: `ldap_injection`, `xpath_injection`, `nosql_injection`.
- **`root_cause_family` enum** extended with `clickjacking`.
- **Detection recipes** (10 new under `bin/recon/recipes/`): `easyadmin_detect.py`, `sonata_detect.py`, `api_platform_detect.py`, `jwt_generic_detect.py`, `oauth_oidc_detect.py`, `auth0_detect.py`, `aws_cognito_detect.py`, `okta_detect.py`, `keycloak_detect.py`, `firebase_auth_detect.py`, `stripe_detect.py`, `aws_secrets_manager_detect.py`, `vault_detect.py`, `saml_detect.py`, `webauthn_passkeys_detect.py`. Composer + env + bounded source-scan probes with vendor-skip and symlink containment.
- **`stack.addons` and `stack.integrations`** populated automatically in CONTEXT.md frontmatter from detection results; consumed by the resolver to load the corresponding checklist layers.
- 1024 unit/regression tests (+238 since 3.4.0).

### Changed

- **BREAKING.** Directory `checklists/frameworks/` renamed to `checklists/stacks/` (history preserved via `git mv`).
- **BREAKING.** `resolve_checklists(themes, stack, plugin_root)` signature changed to `resolve_checklists(themes, ctx: ResolutionContext, plugin_root)`. Callers must construct a `ResolutionContext` and read `stack.framework` from the frontmatter dict.
- **BREAKING.** CONTEXT.md bag namespace renamed: `framework_specific.{stack}.*` → `recon_bags.{kind}.{name}.*` where `kind ∈ {stack, addon, integration}`. Three-level shape replaces the previous two-level shape. ~240 references updated across code, tests, checklists, and worker prompts.
- **`_meta.md`** rewritten for the five-layer model with new diagrams, resolution chain, layer conventions, integration-anchor exception, disambiguation rows for the new sink_kinds, and the documented `## Trusted patterns` convention.
- **YAML subset emitter/parser** widened to accept kebab-case dict keys (needed for `recon_bags.addon["api-platform"].resources`). Leading-hyphen still rejected.
- **GraphQL detection** (`graphql_detect.py`) recognizes both `api-platform/core` (v3) and `api-platform/symfony` (v4).
- **`available_recipes()`** filters `*_detect.py` so addon/integration probes are not auto-loaded as stack recipes.
- **EasyAdmin and Sonata bag-collectors** moved into dedicated modules; backward-compat re-exports from `symfony.py` removed (no in-repo callers).
- **Symfony recipe `_empty_skeleton`** degraded path now runs composer-based addon and integration probes when `project_root` is available — addon / integration detection survives extractor failure.

### Fixed

- **`plan_waves.lookup_kind_for_file`** walked the bag at two levels after the namespace rename and silently returned `None` for every file. The masking unit test used the old two-level fixture shape. Fixed to walk three levels; new test exercises the addon namespace.
- **JWT and OAuth content** migrated from `core/auth.md` and `core/crypto.md` into `integrations/{jwt-generic,oauth-oidc}/`. Defense-in-depth `oauth_state_missing` floor retained in `core/auth.md` for projects that use custom OAuth without a detected SDK.
- **`#[ApiResource]` / GraphQL** sections previously embedded in `stacks/symfony/{auth, data-access, output-render}.md` moved into `stacks/symfony/addons/api-platform/` with the api-platform parts; overblog/webonyx-specific bullets remain in stack files. Section titles updated and breadcrumbs added.

### Composer-name accuracy

Two rounds of triple review (Stages 5 and 7) caught fictional composer package names in detector tables. Every package name in identity-provider and vendor-integration detectors is now packagist-verified against `https://repo.packagist.org/p2/...`. AWS Cognito, Okta, Auth0, Keycloak, Stripe, Vault, WebAuthn, and SAML lists were corrected. Worker tests that previously passed tautologically (using the same fake names as the detectors) now use real names.

### Notes

- **Provider integrations imply generic layers.** Detection of `auth0` / `aws-cognito` / `okta` / `keycloak` automatically activates `jwt-generic` and `oauth-oidc` layers. `firebase-auth` activates `jwt-generic` only (Firebase uses JWT but not standard OAuth/OIDC).
- **Stage 7 integrations are intentionally orthogonal** — `stripe`, `aws-secrets-manager`, `vault`, `saml`, `webauthn-passkeys` do NOT pull in `jwt-generic` or `oauth-oidc` (different protocol surfaces).
- **PHP sandbox extractor for `api-platform.resources` and JWT/OAuth call sites is deferred.** The bag is populated only with a placeholder status (`status: unknown` with a reason); content extraction lands in a follow-up release.
- **Reserved for future stages**: `languages/{php,python,node,go}/`, `stacks/{django,fastapi,express,nestjs}/`, additional providers (Azure AD B2C, Clerk, Supabase Auth), LLM-security integrations (prompt injection, output handling), compliance integrations (GDPR / HIPAA / PCI).

### Migration from 3.x

Internal-only refactor — no external consumers of the plugin format. Projects that use 3.4.0 CONTEXT.md fixtures need to:

1. Rename top-level `framework_specific:` → `recon_bags:` and restructure as `recon_bags.{kind}.{name}.<bag_key>` (kind ∈ `stack`, `addon`, `integration`).
2. Move EasyAdmin / Sonata bag entries from `framework_specific.symfony.easyadmin_crud_controllers` / `.sonata_admin_classes` to `recon_bags.addon.easyadmin.crud_controllers` / `recon_bags.addon.sonata.admin_classes`. Keep `admin_authz_coverage` under `recon_bags.stack.symfony.*` (cross-addon synthesis).
3. Add optional `stack.addons: [...]` and `stack.integrations: [...]` lists to the frontmatter; they're populated automatically by recon and consumed by the resolver to load the new layers.

## [3.4.0] — 2026-05-20

### Initial public release

First public release. Version 3.4.0 inherits the version number from a private predecessor for numbering continuity.

**What is included:**

- Slash commands `/fr-security-review:security-project` and `/fr-security-review:security-changes` for PHP projects.
- Recipe-driven recon with support for Symfony, Laravel, and generic PHP. Schema v2 (`<review_root>/CONTEXT.md` with frontmatter and closed shape specs).
- 6 focused worker waves: W1 auth/disclosure, W2 injection/data-access, W3 output-render, W4 serialization/crypto, W5 ssrf+fileops, W6 fintech + W∞ exploratory (cross-layer chains).
- Adversarial pass (second-pass refute) and the option to disable it via `--no-adversarial`.
- Detection: GraphQL (lighthouse, rebing-laravel, api-platform, webonyx), EasyAdmin, Sonata, Octane, messenger transports, sensitive columns.
- Detection regression: "removed-defense" — detection of removed validators/sanitizers in `/security-changes`.
- Deterministic deduplication (`dedupe_findings.py`) with split report `REPORT.md` + `REPORT/<root_cause_family>.md`.
- 767 unit/regression tests for recon, dedupe, and e2e pipeline (stdlib only, no third-party Python deps).
- Sandbox modes: `--no-console`, firejail, Docker.
- Project-level exclude via `<project_root>/CLAUDE.md` and `--exclude=<csv>`.

**License:** Elastic License 2.0.
