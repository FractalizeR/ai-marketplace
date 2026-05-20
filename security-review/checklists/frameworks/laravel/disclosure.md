# Information disclosure (Laravel)

> This checklist complements `core/disclosure.md` for laravel projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Debug / development tooling in production

- `APP_DEBUG=true` on prod → Whoops error page with full stacktrace + environment variables + DB credentials
- `config/app.php`: `'debug' => env('APP_DEBUG', true)` (default fallback to true) — an unsafe default
- `laravel/telescope` installed in production without an auth-guard on the `/telescope` route → SQL queries, jobs, cache, mail, requests, exceptions with body
- `barryvdh/laravel-debugbar` in production → SQL profiling exposed
- `spatie/laravel-ray` / `clockwork` not disabled

## API response leaks (Resources / toArray)

- `class UserResource extends JsonResource { public function toArray() { return parent::toArray($request); } }` — all model columns, including `password`, `remember_token`, internal flags
- `$user->toArray()` directly in `response()->json($user)` — bypasses `$hidden` if `makeVisible` is applied somewhere
- Eloquent `protected $hidden = ['password']` forgotten for a new sensitive field (`api_key`, `tax_id`, `ssn`)
- `User::with('privateRelation')->find($id)` emits foreign relations through JSON serialization without projection
- API endpoint `/users` without pagination + without `select(['id', 'name'])` — leak of the entire users table

## Logging / .env / secrets

- `Log::info($request->all())` — log injection + secrets in plaintext (passwords/tokens/credit cards in request body)
- `Log::error('failed', ['user' => $user])` — `$user` is serialized with all columns
- `.env` accessible via web (`/storage/logs/laravel.log`, `/.env` via misconfigured nginx)
- `config:cache` collects `.env` into `bootstrap/cache/config.php` — persists in shared storage between deploys
- Hardcoded credentials in `config/services.php` without an `env(...)` wrapper

## Exception messages on API

- `app/Exceptions/Handler.php::render` returns `$exception->getMessage()` in a JSON response with `'production'` env — message contains SQL/path/internal logic
- `abort(403, $detailedReason)` where `$detailedReason` reveals structure (e.g., `'user_id mismatch in tenant 42'`)
- Validation errors leak field names not meant to be exposed (`role`, `is_admin`)

## Storage / file access

- `Storage::disk('s3')->url($path)` — generates a signed URL only if `temporaryUrl`. `url()` for a public bucket emits a direct URL — works only for public files
- `public/` folder with user uploads without MIME check — directory listing if nginx is configured wrong
- `Route::get('/files/{path}', fn($p) => response()->file(storage_path($p)))` — path traversal via `../`

## Sentry / Bugsnag / monitoring

- Sentry SDK in Laravel without `traces_sample_rate=0` or without a `before_send` callback filter — request body / cookies / headers land in the issue payload
- Bugsnag without `notifyReleaseStages` restriction — dev traces land on the prod project
- `\Sentry\captureException($e, ['extra' => $request->all()])` — duplication of request data in the issue

## Password reset / verification

- Notification email contains a pre-filled token in a plain URL — email forwarded = compromised
- `password.reset` token TTL too long (e.g., 24 hours)
- Rate limit on `/password/email` missing — token enumeration through email validation messages
- `User::whereEmail($req->email)->first()` responds with different timing for existing/non-existing email — enumeration

## secret_in_response (Sanctum / Eloquent / API Resource)

> sink_kind: `secret_in_response`. See `core/disclosure.md → secret_in_response` for the generic description. Here — Laravel specifics.

- **Sanctum personal access token leak** — `$user->createToken('name')->plainTextToken` returns plaintext once (intended). But if the controller stores `plainTextToken` in DB (e.g., in an audit log), or returns it in response repeatedly (via a GET endpoint, via `User::with('tokens')` where an accessor emits plaintext) → leak. **confidence ≥ 9**.
- **`personal_access_tokens` JSON serialize** — `auth()->user()->tokens` returns an Eloquent collection → `toJson()` serializes, including the `token` column (sha256 hash, but still an auth credential on login replay) → must not land in API responses.
- **Eloquent without `protected $hidden`** — `User::find()->toJson()` / `response()->json($user)` includes `password` (bcrypt hash), `remember_token`, `two_factor_secret`, `two_factor_recovery_codes`. **confidence ≥ 9** for a confirmed endpoint returning a user. Especially dangerous for `/api/users/{id}` without projection.
- **API Resource without `toArray` override** — `class UserResource extends JsonResource { /* empty or parent::toArray($request) */ }` emits all Eloquent attributes. Including columns added later by migration (`api_key`, `webhook_secret`).
- **Sanctum/Passport rate-limit response with trace dump** — a diagnostic endpoint (`/api/debug/rate-limit`) or a custom 429 handler returns `['user_id' => $user->id, 'token' => $request->bearerToken()]` → echoing the bearer token back to the client, landing in proxy/CDN logs.
- **Mail rendering token** — Notification template Blade renders `{{ $token }}` for password reset, but `$token` also lands in the success response (`{'sent_to': 'a@b.com', 'reset_token': '...'}`) — debug helper, forgotten in prod.
- **OAuth client secret in response** — `Passport::client()->create(...)` returns a model with a `secret` column (plaintext). If the controller does `return response()->json($client)` — leak of client_secret to the client. Sanctum/Passport hash on store but return plaintext once; a repeated leak is unacceptable.

## Octane log context bleed (gate: `framework_specific.laravel.runtime.octane=true`)

> **Apply only if** `framework_specific.laravel.runtime.octane == true`. Otherwise skip the entire section (graceful fallback).

- **`Log::context(['tenant_id' => $tenantId])`** — context is statically attached to the channel → accumulates between requests → log entries of a foreign tenant land in the context of another. Especially critical with centralized log aggregation (ELK/Loki), where tenant_id is used for access control in Kibana.
- **`Log::shareContext(['user' => $user])`** without an explicit `Log::flushSharedContext()` in request middleware — shared context survives the request boundary.
- **`Log::withContext(...)`** in middleware applies to the monolog handler once; in Octane the handler is reused → context from the previous request is present in the logs of the current.
- **Custom monolog `processor`** with captured `$user` (`fn($r) use ($user) => $r->extra['user_id'] = $user->id`) — closure is instantiated once at boot, `$user` is fixed.
- **Sentry/Bugsnag scope** — `\Sentry\configureScope(fn(Scope $s) => $s->setUser([...]))` without `\Sentry\getCurrentHub()->popScope()` in request termination → user context in a Sentry issue payload of the previous request.
