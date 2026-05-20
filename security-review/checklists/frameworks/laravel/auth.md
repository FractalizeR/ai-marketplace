# Authentication / Authorization (Laravel)

> Этот чек-лист дополняет `core/auth.md` для проектов на laravel. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Confidence floor rules

- **POST/PUT/PATCH/DELETE route без `auth`/`auth:sanctum`/`auth:api` middleware** на эндпоинте, работающем с приватными данными → **confidence ≥ 8** для missing_authz.
- **Контроллер обращается к `Model::find($request->id)` без `Gate::authorize` / `$this->authorize` / Policy** → **confidence ≥ 8** для IDOR.

## Middleware и guards

- Маршрут без middleware `auth`, `auth:sanctum`, `auth:api`, `auth:web` на приватной операции — публичный доступ к ресурсу
- `Route::middleware` группа без `auth.basic`/`auth.session` для админ-панели
- `config/auth.php`: множественные guards с пересекающимися providers — атакующий может авторизоваться через слабый guard и использовать токен в более защищённом
- Custom guards/providers без `validateCredentials` или с обходимой логикой
- `auth:sanctum` на routes/api.php но Sanctum не сконфигурирован (`SANCTUM_STATEFUL_DOMAINS` / abilities) → токены принимаются без проверки scope

## Policies / Gates

- Контроллер: `Model::find($id)->update(...)` без `$this->authorize('update', $model)` / `Gate::authorize('update', $model)` → IDOR
- `Gate::define('admin', fn($user) => $user->isAdmin)` без проверки активности/блокировки пользователя
- Policy-метод возвращает `true` слишком широко: `return $user->id === $model->user_id || $user->isAdmin` — но `isAdmin` false для всех
- `@can('update', $post)` в Blade без проверки в контроллере (Blade — defence-in-depth, не primary authz)
- `Gate::before(fn($user) => $user->isAdmin ? true : null)` — короткое замыкание для admin без аудита

## Sanctum / Passport / Personal access tokens

- Создание PAT (`$user->createToken(...)`) без указания `abilities` → токен с * scope
- API endpoint, проверяющий только `auth()->check()` без `tokenCan('ability')` → bypass abilities
- `personal_access_tokens` в БД хранятся как plaintext (Sanctum hashes их по умолчанию, но custom code может ломать инвариант)
- Refresh-token rotation: отсутствие revoke старого токена при выдаче нового — replay
- Passport: weak `Passport::tokensExpireIn` (бесконечный срок); `personalAccessTokensExpireIn` — слишком долгий срок

## Sessions / cookies

- `config/session.php`: `secure: false` на prod (cookies через HTTP); `same_site: 'none'` без `secure: true`; `http_only: false`
- Session fixation: отсутствие `auth()->logoutOtherDevices($password)` после смены пароля
- Custom `Auth::login($user, $remember=true)` без regenerate session id
- Remember-me токен в `users.remember_token` без TTL — компрометация = бессрочный доступ
- `cookie('name', $value)` без `httpOnly`, `secure`, `sameSite` parameters

## CSRF

- `VerifyCsrfToken::$except = ['*']` — отключает CSRF глобально
- POST/PUT/PATCH/DELETE на routes/web.php без CSRF middleware (web group у Laravel включает его по умолчанию — отсутствие группы критично)
- API endpoints на routes/api.php без `auth:sanctum` SPA flow (Sanctum CSRF cookie) — но и без token-based auth → CSRF
- `meta name="csrf-token"` рендерится, но JavaScript-fetch не добавляет заголовок

## Login throttling / rate limiting

- Login route без `throttle:5,1` или RateLimiter::for('login') → brute-force
- Password reset endpoint без throttle → email flood / token brute
- `throttle:60,1` глобально — слишком высокий лимит для sensitive endpoints (login/2FA)

## Multi-tenancy

- Eloquent global scope `addGlobalScope` для tenant filtering — но handler/job/listener вызывает `Model::withoutGlobalScopes()` без явной authz проверки
- `Model::find($id)` в tenant-scoped контроллере без `where('tenant_id', auth()->user()->tenant_id)` — IDOR через предсказуемый id
- `belongsToMany` через pivot без `wherePivot('tenant_id', ...)` фильтра

## Auth::loginUsingId / login без validate

- `Auth::loginUsingId($request->input('user_id'))` / `Auth::loginUsingId(request()->id)` — атакующий контролирует user_id → impersonation любого user'а. **confidence ≥ 9** для подтверждённого паттерна (sink — direct user-controlled ID в `loginUsingId`), `sink_kind=missing_authz` / `idor` в зависимости от контекста.
- `Auth::login(User::find(request()->id))` / `Auth::login(User::findOrFail($req->user_id))` — то же самое: `find()` от user-controlled id, затем `login()`. **confidence ≥ 9**.
- `Auth::onceUsingId($req->id)` — стейтлесс-вариант, но если используется в endpoint с side-effects (создание заказа, генерация токена) — тот же impersonation.
- `Auth::guard('api')->loginUsingId($req->id)` — guard не меняет суть, всё равно user-controlled id.

## OAuth/OIDC (Passport / Sanctum / Socialite)

> См. `core/auth.md → OAuth/OIDC` для generic-описания. Ниже — Laravel-уточнения.

- **Socialite stateless** — `Socialite::driver('google')->stateless()->user()` явно отключает state-проверку → CSRF атаку на OAuth callback нельзя задетектить → `oauth_state_missing` (confidence ≥ 9). Иногда оправдано (mobile callback), но требует объяснения и compensating control (PKCE / nonce).
- **Sanctum SPA-mode без CSRF cookie** — клиент опускает запрос `/sanctum/csrf-cookie` перед stateful-запросами → cookie-based CSRF protection теряется. Признак: `EnsureFrontendRequestsAreStateful` middleware применяется, но фронт не использует `withCredentials: true` или не дёргает csrf-cookie endpoint.
- **Sanctum personal access token с `tokenCan('*')`** — токен = full account control без revocation strategy (нет TTL, нет per-feature scope). Если в `createToken('name', ['*'])` используется wildcard — рискованный default.
- **Passport Authorization Code grant без PKCE для public clients** — `Passport::enableImplicitGrant()` всё ещё используется (deprecated в OAuth 2.1); public clients (SPA, mobile) без `Passport::client()->confidential = false` + PKCE обязательного → token interception на redirect.
- **Socialite без redirect URL allowlist** — `Socialite::driver(request()->provider)->redirect()` где `provider` user-controlled → drive arbitrary external OAuth provider.

## MFA (Fortify / Jetstream / pragmarx/google2fa)

> См. `core/auth.md → MFA` для generic-описания. Ниже — Laravel-уточнения.

- **Fortify two-factor disabled in config** — `config/fortify.php`: `Features::twoFactorAuthentication(['confirm' => true, 'enable' => false])` или features array без `Features::twoFactorAuthentication()` → 2FA доступен в UI, но реально не enforce-ится. Если в session уже стоит `'login.id'` (промежуточное состояние pre-2FA) — bypass через прямой POST на `/two-factor-challenge`.
- **Recovery codes race** — Fortify хранит `two_factor_recovery_codes` как encrypted JSON. `RecoveryCodes::useCode()` помечает код как использованный, но без `lockForUpdate()` / row-level lock — параллельные запросы с одним recovery code могут оба пройти.
- **`pragmarx/google2fa` window > 1** — `Google2FA::setWindow(N)` принимает TOTP в окне ±N×30s. Без drift-tracking (история использованных кодов в БД) — replay предыдущего TOTP в этом же окне.
- **Jetstream `confirmsTwoFactorAuthentication`** не вызван — `Features::twoFactorAuthentication(['confirm' => false])` → атакующий, имеющий доступ к session, активирует 2FA на свой device без подтверждения паролем.

## JWT (`tymon/jwt-auth`, `php-open-source-saver/jwt-auth`)

> См. `core/crypto.md → JWT advanced` для generic-описания (alg confusion / kid injection / jku). Ниже — Laravel-уточнения.

- `JWT_SECRET` в коммите `.env` (не `.env.example`) — leak ключа = forge произвольных токенов.
- Custom `JWTGuard`/`JWTValidator` обрабатывает `kid` claim из header и формирует путь к публичному ключу из user-controlled значения → path traversal или substitute attacker-controlled key. См. `core/crypto.md → JWT advanced`.
- Algorithm confusion (RS256 → HS256) при custom `Tymon\JWTAuth\Providers\JWT\Provider::decode()` без enforce алгоритма. См. `core/crypto.md → JWT advanced`.
- `tymon/jwt-auth` `JWT_BLACKLIST_ENABLED=false` — logout не invalidate токен → stolen token usable до natural expiry.
- `php-open-source-saver/jwt-auth` (форк tymon) — те же риски (общая кодовая база); проверяй обе библиотеки идентично.

## GraphQL field authz (`nuwave/lighthouse`, `rebing/graphql-laravel`)

- **Lighthouse `@guard` только на root mutation** — но не на nested field → атакующий может query nested без auth: `mutation { updateUser(id: 1) { secrets { token } } }` где `secrets` — отдельный type без своего `@guard`.
- **Lighthouse `@can('action', model: User)` без определённой policy method** — если `viewAny`/`view`/`update` не определён в Policy для модели — Laravel Gate fall-through → policy возвращает `null` → ABAC short-circuit интерпретирует как allow в зависимости от `Gate::before()`. **confidence ≥ 7** для recall.
- **Rebing field permissions `'permissions' => null`** или unset в field-definition → public access. Проверь `app/GraphQL/Type/*.php` и `app/GraphQL/Mutation/*.php`.
- **Persisted-queries-only mode bypass** — даже если `lighthouse.persisted_queries=true`, alias `__schema { types { name } }` может пройти как валидная operation в зависимости от middleware ordering. Проверь, что introspection отключён (`lighthouse.security.disable_introspection=true`) на prod.
- **Lighthouse `@inject(context: "user.id")` для tenant scoping** — но resolver получает `$args['user_id']` напрямую из client → tenant bypass.

## Octane singleton-bleed (gate: `framework_specific.laravel.runtime.octane=true`)

> **Применяй эту подсекцию только если** `framework_specific.laravel.runtime.status == ok` **и** `runtime.data.octane == true`. Иначе — пропусти всю секцию (Symfony+FrankenPHP/Roadrunner аналогичны, но не покрыты этой версией плагина — accepted limitation).
>
> **Graceful fallback:** если секция отсутствует/`status != ok` — пропускай Octane-пункты целиком. Не пытайся угадать по `composer.json` — false positive дороже false negative.

- **Singleton с request-scoped state** — `$this->app->singleton(UserContext::class, ...)` (вместо `bind`/`scoped`) → instance переиспользуется между запросами → cross-tenant leak.
- **`auth()->user()` / `RequestStack` cached в constructor** — `public function __construct() { $this->user = auth()->user(); }` фиксируется на первом запросе → последующие запросы видят первого пользователя.
- **`Cache::tags(['user.'.auth()->id()])`** в singleton service — tag-key вычисляется при первом вызове, остаётся прежним → cache misses/hits пересекаются между tenant'ами.
- **Static class state** — `User::$cachedRole`, `static $loaded = []` в моделях/сервисах накапливается между запросами → накопление tenant data в одном process.
- **Container `instance()` binding** — `$this->app->instance(Foo::class, $foo)` живёт до перезапуска worker'а; если `$foo` содержит request data — leak.
- **Eloquent `boot()` hooks** регистрируются в singleton — `Model::saving(fn($m) => $m->user_id = auth()->id())` срабатывает для всех запросов с user_id первого тенанта (если `auth()->id()` зафиксирован в closure через captured variable).
