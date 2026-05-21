# OAuth 2.0 / OpenID Connect integration — detection

This file describes how the recon agent detects OAuth 2.0 / OpenID Connect client or server flow use in the project and activates checklists from `integrations/oauth-oidc/`. It is not a checklist — there are no vulnerability items.

## OAuth/OIDC signals (composer + env + config)

`bin/recon/recipes/oauth_oidc_detect.py::detect_oauth_oidc()` marks the project as using OAuth/OIDC if ANY of:

1. `composer.json` `require` / `require-dev` contains a known OAuth/OIDC package:
   - `league/oauth2-client`, `league/oauth2-server` — generic PHP OAuth2 client/server.
   - `bshaffer/oauth2-server-php` — legacy but still common server library.
   - `hybridauth/hybridauth` — generic social-login client.
   - `knpuniversity/oauth2-client-bundle`, `omines/oauth2-client-bundle` — Symfony OAuth2 client bundles.
   - `laravel/socialite` — Laravel social-login client.
   - `laravel/passport` — Laravel OAuth2 server.
2. `composer.json` has any package matching the broad wildcards `*/oauth2-*`, `oauth-*/*`, `*/openid-connect-*`, `*/oidc-*` (catches provider-specific clients of league: `league/oauth2-google`, `league/oauth2-github`, omines spreads, OIDC-specific libraries).
3. `.env` / `.env.example` / `.env.local` / `.env.dist` declares any of `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ISSUER` — strong indicator even when the OAuth client is hand-rolled.
4. `config/packages/knpu_oauth2_client.yaml` exists (Symfony KnpUOAuth2ClientBundle's canonical config path).
5. `config/services.php` contains a `'redirect' => ...` key (Laravel Socialite's canonical provider configuration shape).

The probe is intentionally lightweight (composer + env + filesystem checks only, no PHP parse) so integration-layer checklists are loaded even on a generic-PHP stack with a custom OAuth client.

On a hit, the recon agent writes into `<review_root>/CONTEXT.md`:

```yaml
stack:
  framework: symfony   # OR laravel OR none (integrations are stack-independent)
  integrations:
    - oauth-oidc
```

`plan_waves.resolve_checklists(...)` then appends, for each wave theme, the file `integrations/oauth-oidc/{theme}.md`, if present (`auth.md`).

## Schema layout — no bag for Stage 4

There is no `recon_bags.integration.oauth-oidc.*` in Stage 4: the schema reserves space for integration bags but no extractor is wired yet. Workers using this integration today must grep the source tree for OAuth client wiring (`->getAccessToken(`, `->getAuthorizationUrl(`, Socialite redirect handlers) and read the configuration files directly.

A future extractor `oauth-flow-config` will populate items shaped roughly as:

```yaml
recon_bags.integration.oauth-oidc.providers:   # PROPOSED, not yet wired
  status: ok | partial | none | unknown
  items:
    - provider: google | github | custom | <name>
      client_kind: confidential | public
      redirect_uri_pattern: <str>
      pkce_required: <bool>
      state_required: <bool>
      scopes: [<str>]
      file: src/...
      line: <int>
```

Until then the checklists in this directory work in graceful-fallback mode via grep — see `integrations/oauth-oidc/auth.md` for the search patterns.

## Provider-specific extension (Stage 5+)

Provider integrations (Auth0, AWS Cognito, Okta, KeyCloak, Firebase Auth) will be detected separately in Stage 5 and added to `stack.integrations` independently. Their checklists EXTEND this generic file: the worker loads `integrations/oauth-oidc/{theme}.md` AND `integrations/<provider>/{theme}.md`, with provider rules winning on conflict.

## Client vs server scope

This integration covers BOTH OAuth roles:

- **Client side** (project consumes external OAuth providers — Socialite, league/oauth2-client, KnpUOAuth2ClientBundle): `state` / PKCE / `redirect_uri` registration / token storage on the user side.
- **Server side** (project IS the OAuth provider — league/oauth2-server, Passport, bshaffer/oauth2-server-php): authorization endpoint hygiene, token introspection, refresh-token rotation, scope binding.

The checklist files do not gate items by client/server role — they apply to whichever role the worker observes in the audited code path.
