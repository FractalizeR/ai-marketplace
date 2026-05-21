# Authentication / Authorization (Laravel)

> This checklist complements `core/auth.md` for laravel projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Confidence floor rules

- **POST/PUT/PATCH/DELETE route without `auth`/`auth:sanctum`/`auth:api` middleware** on an endpoint dealing with private data → **confidence ≥ 8** for missing_authz.
- **Controller calls `Model::find($request->id)` without `Gate::authorize` / `$this->authorize` / Policy** → **confidence ≥ 8** for IDOR.

## Middleware and guards

- Route without `auth`, `auth:sanctum`, `auth:api`, `auth:web` middleware on a private operation — public access to the resource
- `Route::middleware` group without `auth.basic`/`auth.session` for the admin panel
- `config/auth.php`: multiple guards with overlapping providers — attacker can authorize via the weak guard and use the token in a more protected one
- Custom guards/providers without `validateCredentials` or with bypassable logic
- `auth:sanctum` on routes/api.php but Sanctum is not configured (`SANCTUM_STATEFUL_DOMAINS` / abilities) → tokens are accepted without scope check

## Policies / Gates

- Controller: `Model::find($id)->update(...)` without `$this->authorize('update', $model)` / `Gate::authorize('update', $model)` → IDOR
- `Gate::define('admin', fn($user) => $user->isAdmin)` without checking user activity/blocking
- Policy method returns `true` too broadly: `return $user->id === $model->user_id || $user->isAdmin` — but `isAdmin` is false for everyone
- `@can('update', $post)` in Blade without a controller check (Blade is defense-in-depth, not primary authz)
- `Gate::before(fn($user) => $user->isAdmin ? true : null)` — short-circuit for admin without audit

## Sanctum / Passport / Personal access tokens

- Creating a PAT (`$user->createToken(...)`) without specifying `abilities` → token with * scope
- API endpoint checking only `auth()->check()` without `tokenCan('ability')` → bypass of abilities
- `personal_access_tokens` stored in DB as plaintext (Sanctum hashes them by default, but custom code can break the invariant)
- Refresh-token rotation: missing revoke of the old token when issuing a new one — replay
- Passport: weak `Passport::tokensExpireIn` (infinite term); `personalAccessTokensExpireIn` — too long term

## Sessions / cookies

- `config/session.php`: `secure: false` on prod (cookies over HTTP); `same_site: 'none'` without `secure: true`; `http_only: false`
- Session fixation: missing `auth()->logoutOtherDevices($password)` after password change
- Custom `Auth::login($user, $remember=true)` without regenerating session id
- Remember-me token in `users.remember_token` without TTL — compromise = indefinite access
- `cookie('name', $value)` without `httpOnly`, `secure`, `sameSite` parameters

## CSRF

- `VerifyCsrfToken::$except = ['*']` — disables CSRF globally
- POST/PUT/PATCH/DELETE on routes/web.php without CSRF middleware (Laravel's web group includes it by default — absence of the group is critical)
- API endpoints on routes/api.php without `auth:sanctum` SPA flow (Sanctum CSRF cookie) — and also without token-based auth → CSRF
- `meta name="csrf-token"` is rendered, but JavaScript fetch does not add the header

## Login throttling / rate limiting

- Login route without `throttle:5,1` or RateLimiter::for('login') → brute-force
- Password reset endpoint without throttle → email flood / token brute
- `throttle:60,1` globally — too high a limit for sensitive endpoints (login/2FA)

## Multi-tenancy

- Eloquent global scope `addGlobalScope` for tenant filtering — but handler/job/listener calls `Model::withoutGlobalScopes()` without an explicit authz check
- `Model::find($id)` in a tenant-scoped controller without `where('tenant_id', auth()->user()->tenant_id)` — IDOR via predictable id
- `belongsToMany` through a pivot without a `wherePivot('tenant_id', ...)` filter

## Auth::loginUsingId / login without validate

- `Auth::loginUsingId($request->input('user_id'))` / `Auth::loginUsingId(request()->id)` — attacker controls user_id → impersonation of any user. **confidence ≥ 9** for a confirmed pattern (sink — direct user-controlled ID in `loginUsingId`), `sink_kind=missing_authz` / `idor` depending on context.
- `Auth::login(User::find(request()->id))` / `Auth::login(User::findOrFail($req->user_id))` — same thing: `find()` from a user-controlled id, then `login()`. **confidence ≥ 9**.
- `Auth::onceUsingId($req->id)` — stateless variant, but if used in an endpoint with side effects (order creation, token generation) — the same impersonation.
- `Auth::guard('api')->loginUsingId($req->id)` — guard does not change the essence, still a user-controlled id.

## OAuth/OIDC (Passport / Sanctum / Socialite)

> See `core/auth.md → OAuth/OIDC` for the generic description. Below are Laravel-specific notes.

- **Socialite stateless** — `Socialite::driver('google')->stateless()->user()` explicitly disables state check → CSRF attack on the OAuth callback cannot be detected → `oauth_state_missing` (confidence ≥ 9). Sometimes justified (mobile callback), but requires explanation and a compensating control (PKCE / nonce).
- **Sanctum SPA-mode without CSRF cookie** — client skips the `/sanctum/csrf-cookie` request before stateful requests → cookie-based CSRF protection is lost. Signal: `EnsureFrontendRequestsAreStateful` middleware is applied, but the frontend does not use `withCredentials: true` or does not hit the csrf-cookie endpoint.
- **Sanctum personal access token with `tokenCan('*')`** — token = full account control with no revocation strategy (no TTL, no per-feature scope). If `createToken('name', ['*'])` uses wildcard — a risky default.
- **Passport Authorization Code grant without PKCE for public clients** — `Passport::enableImplicitGrant()` is still used (deprecated in OAuth 2.1); public clients (SPA, mobile) without `Passport::client()->confidential = false` + mandatory PKCE → token interception on redirect.
- **Socialite without redirect URL allowlist** — `Socialite::driver(request()->provider)->redirect()` where `provider` is user-controlled → drive an arbitrary external OAuth provider.

## MFA (Fortify / Jetstream / pragmarx/google2fa)

> See `core/auth.md → MFA` for the generic description. Below are Laravel-specific notes.

- **Fortify two-factor disabled in config** — `config/fortify.php`: `Features::twoFactorAuthentication(['confirm' => true, 'enable' => false])` or features array without `Features::twoFactorAuthentication()` → 2FA is available in the UI but is not actually enforced. If session already has `'login.id'` (intermediate pre-2FA state) — bypass via direct POST to `/two-factor-challenge`.
- **Recovery codes race** — Fortify stores `two_factor_recovery_codes` as encrypted JSON. `RecoveryCodes::useCode()` marks a code as used, but without `lockForUpdate()` / row-level lock — parallel requests with one recovery code may both pass.
- **`pragmarx/google2fa` window > 1** — `Google2FA::setWindow(N)` accepts TOTP in a window of ±N×30s. Without drift tracking (history of used codes in DB) — replay of a previous TOTP in the same window.
- **Jetstream `confirmsTwoFactorAuthentication`** is not called — `Features::twoFactorAuthentication(['confirm' => false])` → attacker with access to the session activates 2FA on their device without password confirmation.

## JWT (`tymon/jwt-auth`, `php-open-source-saver/jwt-auth`)

> See `core/crypto.md → JWT advanced` for the generic description (alg confusion / kid injection / jku). Below are Laravel-specific notes.

- `JWT_SECRET` in a committed `.env` (not `.env.example`) — key leak = forging arbitrary tokens.
- Custom `JWTGuard`/`JWTValidator` handles the `kid` claim from the header and forms a path to the public key from a user-controlled value → path traversal or substitute attacker-controlled key. See `core/crypto.md → JWT advanced`.
- Algorithm confusion (RS256 → HS256) in custom `Tymon\JWTAuth\Providers\JWT\Provider::decode()` without enforcing the algorithm. See `core/crypto.md → JWT advanced`.
- `tymon/jwt-auth` `JWT_BLACKLIST_ENABLED=false` — logout does not invalidate the token → stolen token usable until natural expiry.
- `php-open-source-saver/jwt-auth` (tymon fork) — same risks (shared codebase); check both libraries identically.

## GraphQL field authz (`nuwave/lighthouse`, `rebing/graphql-laravel`)

- **Lighthouse `@guard` only on root mutation** — but not on a nested field → attacker can query nested without auth: `mutation { updateUser(id: 1) { secrets { token } } }` where `secrets` is a separate type without its own `@guard`.
- **Lighthouse `@can('action', model: User)` without a defined policy method** — if `viewAny`/`view`/`update` is not defined in the Policy for the model — Laravel Gate fall-through → policy returns `null` → ABAC short-circuit interprets as allow depending on `Gate::before()`. **confidence ≥ 7** for recall.
- **Rebing field permissions `'permissions' => null`** or unset in field-definition → public access. Check `app/GraphQL/Type/*.php` and `app/GraphQL/Mutation/*.php`.
- **Persisted-queries-only mode bypass** — even if `lighthouse.persisted_queries=true`, alias `__schema { types { name } }` may pass as a valid operation depending on middleware ordering. Verify that introspection is disabled (`lighthouse.security.disable_introspection=true`) on prod.
- **Lighthouse `@inject(context: "user.id")` for tenant scoping** — but resolver gets `$args['user_id']` directly from the client → tenant bypass.

## Octane singleton-bleed (gate: `recon_bags.stack.laravel.runtime.octane=true`)

> **Apply this subsection only if** `recon_bags.stack.laravel.runtime.status == ok` **and** `runtime.data.octane == true`. Otherwise skip the entire section (Symfony+FrankenPHP/Roadrunner are analogous, but not covered by this plugin version — accepted limitation).
>
> **Graceful fallback:** if the section is missing/`status != ok` — skip Octane items entirely. Do not try to guess from `composer.json` — a false positive is more expensive than a false negative.

- **Singleton with request-scoped state** — `$this->app->singleton(UserContext::class, ...)` (instead of `bind`/`scoped`) → instance is reused between requests → cross-tenant leak.
- **`auth()->user()` / `RequestStack` cached in constructor** — `public function __construct() { $this->user = auth()->user(); }` is fixed on the first request → subsequent requests see the first user.
- **`Cache::tags(['user.'.auth()->id()])`** in a singleton service — tag-key is computed on the first call and stays the same → cache misses/hits intersect between tenants.
- **Static class state** — `User::$cachedRole`, `static $loaded = []` in models/services accumulates between requests → accumulation of tenant data in one process.
- **Container `instance()` binding** — `$this->app->instance(Foo::class, $foo)` lives until worker restart; if `$foo` contains request data — leak.
- **Eloquent `boot()` hooks** registered in a singleton — `Model::saving(fn($m) => $m->user_id = auth()->id())` fires for all requests with the user_id of the first tenant (if `auth()->id()` is fixed in the closure via a captured variable).
