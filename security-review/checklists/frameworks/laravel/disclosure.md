# Information disclosure (Laravel)

> Этот чек-лист дополняет `core/disclosure.md` для проектов на laravel. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Debug / development tooling в production

- `APP_DEBUG=true` на prod → Whoops error page с full stacktrace + переменные окружения + DB credentials
- `config/app.php`: `'debug' => env('APP_DEBUG', true)` (default fallback на true) — небезопасный default
- `laravel/telescope` установлен в production без auth-guard на `/telescope` route → SQL queries, jobs, cache, mail, requests, exceptions с body
- `barryvdh/laravel-debugbar` в production → SQL profiling exposed
- `spatie/laravel-ray` / `clockwork` без отключения

## API response leaks (Resources / toArray)

- `class UserResource extends JsonResource { public function toArray() { return parent::toArray($request); } }` — все колонки модели, включая `password`, `remember_token`, internal flags
- `$user->toArray()` напрямую в `response()->json($user)` — обходит `$hidden` если `makeVisible` где-то применён
- Eloquent `protected $hidden = ['password']` забыт для new sensitive поля (`api_key`, `tax_id`, `ssn`)
- `User::with('privateRelation')->find($id)` отдаёт чужие связи через JSON serialization без projection
- API endpoint `/users` без pagination + без `select(['id', 'name'])` — leak всей таблицы users

## Logging / .env / secrets

- `Log::info($request->all())` — log injection + secrets в plaintext (passwords/tokens/credit cards в request body)
- `Log::error('failed', ['user' => $user])` — `$user` сериализуется со всеми колонками
- `.env` доступен через web (`/storage/logs/laravel.log`, `/.env` через misconfigured nginx)
- `config:cache` собирает `.env` в `bootstrap/cache/config.php` — хранится в шаре между deploy-ами
- Hardcoded credentials в `config/services.php` без `env(...)`-обёртки

## Exception messages on API

- `app/Exceptions/Handler.php::render` отдаёт `$exception->getMessage()` в JSON-ответе с `'production'` env — message содержит SQL/path/internal logic
- `abort(403, $detailedReason)` где `$detailedReason` раскрывает структуру (например `'user_id mismatch in tenant 42'`)
- Validation errors leak field names не предполагавшиеся к выдаче (`role`, `is_admin`)

## Storage / file access

- `Storage::disk('s3')->url($path)` — generates signed URL только если `temporaryUrl`. `url()` для public bucket выдаёт прямой URL — работает только для публичных файлов
- `public/` папка с user uploads без проверки MIME — directory listing если nginx configured wrong
- `Route::get('/files/{path}', fn($p) => response()->file(storage_path($p)))` — path traversal через `../`

## Sentry / Bugsnag / monitoring

- Sentry SDK в Laravel без `traces_sample_rate=0` или без `before_send`-callback фильтра — request body / cookies / headers попадают в issue payload
- Bugsnag без `notifyReleaseStages` ограничения — dev-traces попадают на prod project
- `\Sentry\captureException($e, ['extra' => $request->all()])` — дублирование request data в issue

## Password reset / verification

- Notification email содержит pre-filled token в plain URL — email forwarded = compromised
- `password.reset` token TTL слишком long (e.g. 24 часа)
- Rate limit на `/password/email` отсутствует — token enumeration through email validation messages
- `User::whereEmail($req->email)->first()` отвечает разным timing для существующего/несуществующего email — enumeration

## secret_in_response (Sanctum / Eloquent / API Resource)

> sink_kind: `secret_in_response`. См. `core/disclosure.md → secret_in_response` для generic-описания. Здесь — Laravel-специфика.

- **Sanctum personal access token leak** — `$user->createToken('name')->plainTextToken` возвращает plaintext один раз (intended). Но если контроллер сохраняет `plainTextToken` в БД (например в audit log), либо возвращает в response повторно (через GET endpoint, через `User::with('tokens')` где accessor отдаёт plaintext) → leak. **confidence ≥ 9**.
- **`personal_access_tokens` JSON serialize** — `auth()->user()->tokens` возвращает Eloquent collection → `toJson()` сериализует, включая `token` колонку (sha256 hash, но всё равно auth credential при login replay) → не должно попадать в API responses.
- **Eloquent без `protected $hidden`** — `User::find()->toJson()` / `response()->json($user)` включает `password` (bcrypt hash), `remember_token`, `two_factor_secret`, `two_factor_recovery_codes`. **confidence ≥ 9** для подтверждённого endpoint, отдающего user'а. Особенно опасно для `/api/users/{id}` без projection.
- **API Resource без override `toArray`** — `class UserResource extends JsonResource { /* пусто или parent::toArray($request) */ }` отдаёт все Eloquent attributes. Включая колонки, добавленные позже миграцией (`api_key`, `webhook_secret`).
- **Sanctum/Passport rate-limit response с trace dump** — диагностический endpoint (`/api/debug/rate-limit`) или custom 429 handler возвращает `['user_id' => $user->id, 'token' => $request->bearerToken()]` → echoing bearer token обратно клиенту, попадает в логи прокси/CDN.
- **Mail rendering token** — Notification template Blade рендерит `{{ $token }}` для password reset, но `$token` также попадает в success response (`{'sent_to': 'a@b.com', 'reset_token': '...'}`) — debug-helper, забытый в prod.
- **OAuth client secret в response** — `Passport::client()->create(...)` возвращает model с `secret` колонкой (plaintext). Если контроллер `return response()->json($client)` — leak client_secret клиенту. Sanctum/Passport hash-ит при store, но возвращает plaintext один раз; повторный leak недопустим.

## Octane log context bleed (gate: `framework_specific.laravel.runtime.octane=true`)

> **Применяй только если** `framework_specific.laravel.runtime.octane == true`. Иначе — пропусти всю секцию (graceful fallback).

- **`Log::context(['tenant_id' => $tenantId])`** — context статически прикрепляется к channel → накапливается между запросами → log entries чужого tenant'а попадают в context другого. Особенно критично при централизованной log-aggregation (ELK/Loki), где tenant_id используется для access control в Kibana.
- **`Log::shareContext(['user' => $user])`** без явного `Log::flushSharedContext()` в request middleware — shared context переживает request boundary.
- **`Log::withContext(...)`** в middleware применяется к monolog handler один раз; в Octane handler reused → context из предыдущего запроса присутствует в logs текущего.
- **Custom monolog `processor`** с captured `$user` (`fn($r) use ($user) => $r->extra['user_id'] = $user->id`) — closure инстанцируется один раз при boot, `$user` зафиксирован.
- **Sentry/Bugsnag scope** — `\Sentry\configureScope(fn(Scope $s) => $s->setUser([...]))` без `\Sentry\getCurrentHub()->popScope()` в request termination → user context в Sentry issue payload предыдущего запроса.
