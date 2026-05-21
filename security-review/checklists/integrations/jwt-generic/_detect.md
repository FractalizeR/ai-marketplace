# JWT (generic) integration — detection

This file describes how the recon agent detects JSON Web Token use in the project and activates checklists from `integrations/jwt-generic/`. It is not a checklist — there are no vulnerability items.

## JWT signals (composer + env + config)

`bin/recon/recipes/jwt_generic_detect.py::detect_jwt_generic()` marks the project as using JWT if ANY of:

1. `composer.json` `require` / `require-dev` contains a known JWT package:
   - `firebase/php-jwt` — most common generic-PHP library.
   - `lcobucci/jwt` — modern OO library.
   - `web-token/jwt-framework` — full JWS/JWE/JWK suite.
   - `paragonie/paseto` — PASETO is treated as JWT-adjacent for this integration (overlapping threat model and checklist applicability); Stage 5 may introduce a dedicated `paseto` integration.
   - `tymon/jwt-auth`, `php-open-source-saver/jwt-auth` — Laravel JWT bundles.
   - `lexik/jwt-authentication-bundle` — Symfony JWT bundle.
2. `composer.json` has any package matching the broad wildcards `*/jwt-*` or `jwt-*/*` (catches community wrappers, forks, less-known SDKs).
3. `.env` / `.env.example` / `.env.local` / `.env.dist` declares any of `JWT_SECRET`, `JWT_PASSPHRASE`, `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY` — strong indicator even when the JWT helper is hand-rolled.
4. `config/packages/lexik_jwt_authentication.yaml` exists (Symfony Lexik bundle's canonical config path).

The probe is intentionally lightweight (composer + env + filesystem checks only, no PHP parse) so integration-layer checklists are loaded even on a generic-PHP stack with a custom JWT helper.

On a hit, the recon agent writes into `<review_root>/CONTEXT.md`:

```yaml
stack:
  framework: symfony   # OR laravel OR none (integrations are stack-independent)
  integrations:
    - jwt-generic
```

`plan_waves.resolve_checklists(...)` then appends, for each wave theme, the file `integrations/jwt-generic/{theme}.md`, if present (`auth.md`, `crypto.md`).

## Schema layout — no bag for Stage 4

There is no `recon_bags.integration.jwt-generic.*` in Stage 4: the schema reserves space for integration bags but no extractor is wired yet. Workers using this integration today must grep the source tree for JWT call sites (`->parse(`, `JWT::decode`, `JWS::loadFromSerializedJson`, etc.) and read the configuration files directly.

A future extractor `jwt-call-sites` will populate items shaped roughly as:

```yaml
recon_bags.integration.jwt-generic.call_sites:   # PROPOSED, not yet wired
  status: ok | partial | none | unknown
  items:
    - kind: encode | decode | verify
      library: firebase | lcobucci | web-token | lexik | custom
      file: src/...
      line: <int>
      configured_algorithms: [<str>]      # e.g. ["HS256", "RS256"]
      verifies_alg: <bool>                # passed explicit `algorithms` list
```

Until then the checklists in this directory work in graceful-fallback mode via grep — see `integrations/jwt-generic/auth.md` for the search patterns.

## Provider-specific extension (Stage 5+)

Provider integrations that ride on JWT (Auth0, AWS Cognito, Okta, KeyCloak, Firebase Auth) will be detected separately in Stage 5 and added to `stack.integrations` independently. Their checklists EXTEND this generic file: the worker loads `integrations/jwt-generic/{theme}.md` AND `integrations/<provider>/{theme}.md`, with provider rules winning on conflict.
