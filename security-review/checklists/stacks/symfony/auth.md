# Authentication / Authorization (Symfony)

> This checklist complements `core/auth.md` for symfony projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Confidence floor rules

- **`#[Route(..., methods: ['POST'])]`** without `#[IsGranted]` / `$this->denyAccessUnlessGranted` on non-anonymous functionality → **confidence ≥ 8** for missing_authz.
- **`recon_bags.stack.symfony.admin_authz_coverage.crud_controllers_without_voter` non-empty** → for each such controller go into `recon_bags.addon.easyadmin.crud_controllers` items (or `recon_bags.addon.sonata.admin_classes` for Sonata) by `class.endsWith(<short>)` and check editable identity fields (see `addons/easyadmin/auth.md` and `addons/sonata/auth.md` — auto-loaded when the corresponding addon is detected). By default sink_kind=`mass_assignment`, root_cause_family=`authz`, **confidence ≥ 7** when identity/role fields are present without modifiers (`setDisabled`/`onlyOnIndex`/`hideOnForm`).

## Symfony Security Bundle

- Missing `#[IsGranted(...)]` / `$this->denyAccessUnlessGranted(...)` on controllers handling private resources
- Errors in `config/packages/security.yaml`: overly broad `access_control` patterns (`^/admin` without regex boundary); `IS_AUTHENTICATED_ANONYMOUSLY` on mutating paths
- Misconfigured voters: `supports()` returns `true` for too broad attributes; `voteOnAttribute()` lets through when it should deny
- `switch_user` without `role: ROLE_ALLOWED_TO_SWITCH`; ability to switch_user via GET parameter without CSRF
- `remember_me` with predictable `secret` or without `httponly: true, secure: true`
- Session fixation: missing `session.migrate()` after login
- Login throttling bypass: missing `login_throttling` / rate limit on login firewall

### `IS_AUTHENTICATED_REMEMBERED` vs `FULLY` for sensitive operations

- Controller for a sensitive operation (password change, email change, payment confirm, 2FA disable, API-key rotation) protected via `#[IsGranted('IS_AUTHENTICATED_REMEMBERED')]` or `denyAccessUnlessGranted('IS_AUTHENTICATED_REMEMBERED')` — this **includes remember-me cookies** (no proof of recent password). It should be `IS_AUTHENTICATED_FULLY` (or `IS_AUTHENTICATED_2FA_IN_PROGRESS` for post-2FA operations).
- Same for `access_control` rules in `security.yaml`: `roles: IS_AUTHENTICATED_REMEMBERED` on paths with sensitive operations. Sink_kind: `missing_authz` (root_cause_family: `authz`), confidence ≥ 7.

### Voter anti-patterns

- `VoterInterface::supports($attribute, $subject)` returns `true` for too broad an `$attribute` (`return true` without checking a list, `return str_starts_with($attribute, 'POST_')` for a voter that handles only `POST_EDIT`/`POST_DELETE`, regex match like `'/^[A-Z_]+$/'`) → voter is applied to situations it was not written for → false-positive grant from `voteOnAttribute()`.
- `voteOnAttribute()` `default true` (case-block not matched → `return true` or `return Voter::ACCESS_GRANTED`) instead of `return false` / `Voter::ACCESS_DENIED` → grant by default. Especially dangerous when new attributes are added: they are automatically allowed without updating the voter.
- `voteOnAttribute()` without `$subject instanceof ExpectedClass` check — if supports() is too broad, the voter may be called with a foreign entity and will ignore the ownership check.

### `security.yaml` access_control regex precedence

- access_control rules match **in order** top-to-bottom; the first matching one is used, the rest are not checked. If a broad pattern stands above (`{ path: '^/admin', roles: ROLE_USER }`) and a narrow one with a stricter role stands below (`{ path: '^/admin/users/edit', roles: ROLE_SUPER_ADMIN }`), the narrow one **will never fire** → privilege escalation.
- Catch via manual analysis of rule ordering + cross-check with `recon_bags.stack.symfony.routes_authz_matrix` (if the section is present — see data-access.md). Sink_kind: `missing_authz`, confidence ≥ 7 when a narrow rule is overridden by a broad one.

### Request trust boundary (`framework.yaml` — trusted_proxies / trusted_hosts / trusted_headers)

`framework.trusted_proxies` + `framework.trusted_headers` govern how Symfony derives the *effective* client IP, host, and scheme from `X-Forwarded-*` headers. When Symfony trusts a proxy, `Request::getClientIp()` / `getHost()` return the attacker-controlled forwarded value. Anything downstream keyed on those — IP-based `access_control`, `login_throttling` / rate limiters, audit logs, `remember_me` binding, geoblocking — is then spoofable. Recon surfaces this in `recon_bags.stack.symfony.trusted_config` (`source_files: config/packages/framework.yaml`), routed into this wave's `target_files`.

- **`trusted_proxies` set to an over-broad range** (`0.0.0.0/0`, `::/0`, `REMOTE_ADDR`, or a wide private supernet a request can originate from) → attacker sends `X-Forwarded-For: <spoofed>` and `Request::getClientIp()` returns it. Any IP allowlist (`access_control` with a custom IP voter, admin-panel IP gate, internal-only endpoint) is bypassed. Sink_kind: `missing_authz` (root_cause_family: `authz`), confidence ≥ 7 when a concrete IP-gated sink exists; ≥ 6 for the misconfiguration alone.
- **`%env(...)%` indirection.** Modern configs write `trusted_proxies: '%env(TRUSTED_PROXIES)%'` — the *effective* value lives in `.env` / `.env.local` (routed to W4/secrets). You MUST resolve it: `framework.yaml` only proves the toggle is wired; a value of `0.0.0.0/0` / `REMOTE_ADDR` / `PRIVATE_SUBNETS` in `.env` is the actual vuln. Report only after tracing the resolved value; if the env var is unset at audit time, flag as a config-review gap, not a confirmed finding.
- **`trusted_headers` includes `x-forwarded-host` (or `x-forwarded-*` broadly) without a `framework.trusted_hosts` allowlist** → host header injection: password-reset / email links built from `Request::getSchemeAndHttpHost()` point at an attacker host; web-cache poisoning. Sink_kind: `other:host_header_injection` (root_cause_family: `disclosure`), confidence ≥ 7 when a reset/absolute-URL sink consuming the host is reachable.
- **`trusted_hosts` empty while the app builds absolute URLs from the request host** — same host-injection surface even without forwarded headers (direct `Host:` spoofing). Cross-link: `core/disclosure.md` → host header / open redirect.
- **Coverage caveat — recon parses `framework.yaml` only.** A project may set the trust boundary the legacy/programmatic way — `Request::setTrustedProxies(...)` / `Request::setTrustedHosts(...)` in `public/index.php` or a bootstrap/kernel — which recon does NOT surface (no `trusted_config` signal, framework.yaml not routed). If `trusted_config.status` is `none`/`unknown`, still grep `public/index.php` + bootstrap for `setTrustedProxies` / `setTrustedHosts` before concluding the boundary is unset.

## OAuth/OIDC (Symfony — KnpUOAuth2ClientBundle, league/oauth2-client)

See `core/auth.md` → OAuth/OIDC for generic patterns (state validation, PKCE, redirect_uri exact-match). Below are Symfony-specific notes.

- **KnpUOAuth2ClientBundle**: a callback controller that does not call `$client->retrieveAccessToken($state)` or an equivalent state-check immediately after receiving the authorization code → state→token race / state validation is missing. Sink_kind: `oauth_state_missing`.
- **`league/oauth2-client` `Provider::getAuthorizationUrl()` without an explicit `state` option**: the library will generate a random state in `$provider->getState()`, but if the developer did not save it in the session (`$_SESSION['oauth2state'] = $provider->getState()`) and did not compare on callback — state is effectively not validated. Typical code smell: a call to `getAuthorizationUrl()` without subsequently writing `getState()` into the session.
- **`redirect_uri` whitelist via `services.yaml` config**: substring match (`str_contains($redirect, $allowedDomain)`) instead of exact match → bypass via `https://attacker.com/?evil=allowed.com`. Must be an exact compare of the entire URI (including path) or a strict host whitelist via `parse_url()` + `in_array()`.
- **OAuth login via KnpU Authenticator (`SocialAuthenticator`)** without a verified-email check from the provider → account takeover when the provider does not verify email (some self-hosted OAuth servers).

## MFA (scheb/2fa-bundle)

See `core/auth.md` → MFA for generic patterns. Below are Symfony-specific notes.

- **`scheb/2fa-bundle` with `enabled: false`** in `config/packages/scheb_2fa.yaml` — the bundle is loaded but 2FA is disabled globally → IS_AUTHENTICATED_2FA_IN_PROGRESS does not fire, sensitive routes are unprotected.
- **Voter `IS_AUTHENTICATED_2FA_IN_PROGRESS` missing in `access_control` for protected routes**, while 2FA is enabled for the user. The route `^/account/sensitive` without `roles: IS_AUTHENTICATED_2FA_IN_PROGRESS` → a user with 2FA enabled can reach the route after initial login without the second factor.
- **Recovery codes are stored via `scheb/2fa-bundle` (`TwoFactorTrait::getBackupCodes()`)**, but `User::eraseRecoveryCode($code)` is not implemented or is implemented as a no-op → codes are reusable (single-use enforcement is missing). Sink_kind: `missing_authz`.
- **TOTP secret in `User` entity without encryption-at-rest** (`#[ORM\Column(type: 'string')] $totpSecret`) — DB compromise → attacker recovers TOTP codes for all users. Cross-link: `crypto.md` → persistent secrets in plain columns.

## JWT (lexik/jwt-authentication-bundle)

See `core/crypto.md` → JWT advanced (kid/jwk header injection, algorithm confusion RS256→HS256, aud/iss mismatch, nbf/iat skew). The Symfony implementation is identical — only bundle-specifics here.

- **`JWT_PASSPHRASE` / `JWT_PRIVATE_KEY` in a committed `.env`** (without `.env.local` override) → attacker re-signs tokens of any user. Sink_kind: `hardcoded_secret`. See also `crypto.md` → APP_SECRET.
- **`token_extractors.query_parameter.enabled: true` with cookie/header auth** — token ends up in the URL → leak via browser history, server access logs, `Referer` header when navigating to an external resource.
- **`kid` / `jwk` passthrough**: if the project has a **custom Authenticator** (not the bundle default) that passes the `kid` header into `JwtEncoderInterface` without a whitelist → kid header injection is possible (see core).
- **`Lcobucci\JWT\Configuration` directly (without the bundle)**: validation constraints (`SignedWith`, `IssuedBy`, `PermittedFor`) are optional — if the developer created `Configuration::forSymmetricSigner(...)` and forgot `setValidationConstraints([...])`, any signature/iss/aud is accepted. Grep for `Configuration::forSymmetricSigner` / `forAsymmetricSigner` without a subsequent `setValidationConstraints`.

## GraphQL field authz (overblog/graphql-bundle / webonyx)

- **overblog/graphql-bundle resolver without `#[Security('is_granted(...)')]`**: a resolver method (`#[GraphQL\Field]`, `#[GraphQL\Mutation]`) or a field in the schema YAML without `accessControl: "is_granted('ROLE_USER')"` / `access: "is_granted(...)"` → field/resolver accessible to anonymous users. Also `accessControl: "true"` (literal `true` without an expression) — pseudo-check.
- **webonyx native (`webonyx/graphql-php`)**: a resolver function (`'resolve' => fn($root, $args, $context) => ...`) does not check `$context['user']` / does not invoke a voter → field-level authz is missing. Especially dangerous for resolvers returning the entity directly without projection.
- **Introspection in prod (overblog)**: overblog enables `query Introspection { __schema { types { name fields { name } } } }` by default. If bundle config does not disable introspection in prod (`overblog_graphql.definitions.introspection.enabled: false`) → confidence floor **≥ 8** (information disclosure: attacker maps the entire schema, including admin-only fields and mutations). Sink_kind: `stacktrace_exposed` or `other:graphql_introspection_enabled` (root_cause_family: `disclosure`).

> API Platform-specific GraphQL patterns: see `addons/api-platform/auth.md` (auto-loaded when api-platform addon is detected).

## Symfony Form CSRF

- Forms without `csrf_protection: true` and without a CSRF token in the body — Symfony Form enables CSRF by default for `data_class` forms, but with `csrf_protection: false` or standalone controllers without the Form component — it disappears

## Admin bundle CRUD controllers (tenancy / mass_assignment)

> EasyAdmin/Sonata-specific patterns: see `addons/easyadmin/auth.md` and `addons/sonata/auth.md` (auto-loaded when the addon is detected).
