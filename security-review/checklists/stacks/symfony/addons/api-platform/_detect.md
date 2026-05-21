# API Platform addon — detection

This file describes how the recon agent detects an API Platform installation on top of Symfony and activates checklists from `stacks/symfony/addons/api-platform/`. It is not a checklist — there are no vulnerability items.

## API Platform signals (composer + config)

`bin/recon/recipes/api_platform_detect.py::detect_api_platform()` marks the project as using API Platform if ANY of:

1. `composer.json` contains `api-platform/core` in `require` / `require-dev` (v3.x).
2. `composer.json` contains `api-platform/symfony` in `require` / `require-dev` (v4.x transition package — the Symfony-specific bundle was extracted from `core`).
3. `config/packages/api_platform.yaml` exists (Symfony Flex auto-wiring).
4. `config/packages/api_platform.php` exists (modern Flex setups using PHP config).

The probe is intentionally lightweight (composer + filesystem checks only, no PHP parse) so addon-layer checklists are loaded even before the heavier ApiResource enumeration runs.

On a hit, the recon agent writes into `<review_root>/CONTEXT.md`:

```yaml
stack:
  framework: symfony
  addons:
    - api-platform
```

`plan_waves.resolve_checklists(...)` then appends, for each wave theme, the file `stacks/symfony/addons/api-platform/{theme}.md`, if present.

## What lands in the `recon_bags.addon.api-platform` bag

The recipe registers the key `resources` (see `bin/recon/recipes/symfony.py::RECON_BAGS_SCHEMA["addon"]["api-platform"]`) with planned shape:

```yaml
recon_bags.addon.api-platform.resources:
  status: ok | partial | none | unknown
  items:
    - class: <FQCN>
      file: src/...
      line: <int>
      operations:
        - verb: Get | GetCollection | Post | Patch | Put | Delete
          security: <expr> | null
          security_post_denormalize: <expr> | null
          normalization_groups: [<str>]
          denormalization_groups: [<str>]
          pagination_max: <int> | null
          filters: [<str>]
      graphql_enabled: <bool>
```

**Current status — extractor not yet implemented.** `collect_api_platform_resources()` returns `status="unknown"` when API Platform is detected (so the worker is alerted that the bag is intentionally empty) and `status="none"` when it isn't. The PHP extractor `api-platform-resources` will land in a follow-up PR; until then every checklist in this directory falls back to grep on `#\[ApiResource` and reads the relevant `*.php` source directly. The bag wiring (schema, sanity probe, build_inventory call) is in place so the future extractor can drop in without renaming keys.

## REST and GraphQL surfaces

API Platform exposes BOTH a REST API (default) and an optional GraphQL endpoint. Both surfaces share the same `#[ApiResource]` declaration — security / normalization groups / filters apply equally. The addon checklists cover both:

- **REST** patterns are the primary focus of `auth.md`, `data-access.md`, `output-render.md`, `disclosure.md`.
- **GraphQL** patterns specific to API Platform are folded into each theme's GraphQL subsection (introspection toggle, GraphiQL exposure, per-operation security in GraphQL operations). For overblog/graphql-bundle and webonyx engines on Symfony, see `stacks/symfony/{theme}.md` → GraphQL section instead.
