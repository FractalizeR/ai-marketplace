# Data access / Eloquent ORM (Laravel)

> Этот чек-лист дополняет `core/data-access.md` для проектов на laravel. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Confidence floor rules

- **`Model::find($request->input('id'))`** в мутирующем контроллере без `$this->authorize(...)` / Policy → **confidence ≥ 8** для IDOR. Аргумент «может быть Policy в другом месте» не снижает confidence — ревьюер проверит.
- **Прямая конкатенация `$request->...` в `DB::raw()` / `whereRaw()` / `selectRaw()` / `orderByRaw()`** → **confidence ≥ 9** для sql_injection.

## Raw SQL injection

- `DB::raw($input)` где `$input` — пользовательский
- `DB::select("... WHERE x = $userInput")` — конкатенация в plain SQL
- `whereRaw("col = $userInput")` / `selectRaw("$userField")` без параметра-placeholder и `$bindings`
- `havingRaw("count > $count")` без параметризации
- `orderByRaw($_GET['sort'])` — нужен whitelist column names
- `DB::statement($sql)` с user input

## Query Builder dynamic patterns

- `->where('col', '=', $req->q)` — параметризовано, безопасно. Но `->whereRaw("col = '$value'")` — не безопасно
- `->orderBy($req->sort)` — нужен `in_array($req->sort, $allowed)` whitelist (column names не параметризуются)
- `->orderBy('col', $req->dir)` где `$dir` user-controlled и не валидируется (только asc/desc допустимы)
- Динамическая table в `DB::table($name)` без whitelist
- `->whereColumn($a, $b)` с user-controlled column names

## Eloquent mass assignment

- `Model::create($request->all())` или `->update($request->all())` без `$fillable` или с `$guarded = []` → mass assignment (admin/role/tenant_id и т.д.)
- `Model::forceCreate($request->all())` — обход $fillable; критичное использование
- `Model::fill($request->all())->save()` — обход guards если `$guarded = []`
- `Model::firstOrCreate(['id' => $req->id], $req->all())` — id как поиск + остальные как create данные
- `$user->update($request->only(['name', 'email']))` — корректно. `$request->only(['name', 'email', 'role'])` — забыли отфильтровать критичное поле
- Model с `protected $guarded = []` (default to no guard) — все колонки fillable

## Route-model binding

- Route `/posts/{post}` с implicit binding → Laravel вызывает `Post::findOrFail($id)`. Без Policy / `$this->authorize` в действии → IDOR
- Custom binding в `RouteServiceProvider::boot` без tenant scope — атакующий читает чужую запись по id
- `Route::bind('post', fn($id) => Post::find($id))` без projection scope
- Implicit binding с soft-deletes (`->withTrashed()`) — может вернуть удалённую запись
- Scoped binding `/users/{user}/posts/{post:slug}` — корректно. Без scope (`{post}` без `:column`) — bypass через slug коллизию

## Eloquent relationships / N+1 / data leak

- Eager loading чужих связей: `Post::with('user.privateData')->get()` — отдаёт internal через JSON serialization
- `belongsTo` / `hasMany` / `morphMany` без projection — `.toArray()` отдаёт все колонки
- `MorphMap` с user-controlled morph type — атакующий проставляет любой класс → Object Injection-like через polymorphic relations
- Lazy load `$post->user` в loop (N+1) — DoS-ish + потенциальный leak когда forgotten в auth context

## Soft deletes

- `Model::findOrFail` пропускает soft-deleted, но `withTrashed()->find()` — нет. Authz-проверка должна охватывать оба пути
- `restore()` без проверки оригинального ownership (запись могла быть передана между tenant-ами)

## Transaction boundaries

- `DB::transaction(fn() => ...)` с throw inside, перехватываемым внешним try/catch без revert audit log
- Race condition: `if (!$user->isLocked()) { $user->lock(); }` без `lockForUpdate()` / row lock
- Optimistic locking missing: `$model->update(['version' => $version, ...])` без version-field check

## Database raw migrations / seeds

- Migrations с `DB::statement("ALTER TABLE ... ADD COLUMN role DEFAULT 'admin'")` — все существующие пользователи становятся админами (миграция как backdoor)
- Seeds в production с `User::factory()->admin()->create()` без условия

## API Resources data exposure

- `class UserResource extends JsonResource { public function toArray() { return parent::toArray($request); } }` — `parent::toArray` отдаёт **все** колонки, включая `password_hash`/`remember_token`/internal flags
- Resource без `whenLoaded()` — отдаёт null или N+1 query
- Conditional attribute `'role' => $this->when($request->user()?->isAdmin, $this->role)` забыт — non-admin читает поле

## GraphQL data exposure (`nuwave/lighthouse`, `rebing/graphql-laravel`)

- **Query depth/complexity без лимита** — `lighthouse.security.max_query_depth=null` или `max_query_complexity=null` → атакующий шлёт глубоко вложенный query (`a { b { c { d { ... } } } }`) → DoS через resolver expansion и/или N+1 на каждом уровне.
- **Alias batching** — один HTTP запрос с N alias'ами на одной mutation → N выполнений резолвера → bypass rate limit (limit считает HTTP requests, не операции). Пример: `mutation { a: login(email:"e1") { token } b: login(email:"e2") { token } ... }`.
- **Persisted-queries-only bypass через client-side query manipulation** — server проверяет hash, но `extensions.persistedQuery.sha256Hash` совпадает с hash другой query с тем же текстом → коллизия / hash spoofing. Также: если режим `persisted_queries` accepts unknown hash и сохраняет → atta вкладывает свою query.
- **Lighthouse `@paginate` без `maxCount`** — `users { paginate(first: 999999) }` → выгрузка всей таблицы.
- **Rebing `pagination` без `max_per_page`** — то же самое.
- **Field-level data leak** — resolver возвращает Eloquent model directly (см. `output-render.md → GraphQL output filtering`).

## whereJsonContains / whereJsonPath с user input

- `User::where('roles', '@>', json_encode($req->input('roles')))` — JSON injection через user-контролируемый payload. `$req->input('roles')` может быть массивом/объектом → `json_encode` выдаёт JSON, который как WHERE-pattern matches любые записи (например `[]` matches all).
- `whereJsonContains('permissions', $req->input('perm'))` — без cast/validate `$req->input('perm')` может быть `null` (matches NULL JSON), `["admin"]` (escalation), вложенным объектом.
- `whereJsonPath('$.role', '=', $req->path)` — user-controlled JSON path → атакующий читает другие ветки JSON-документа: `$.password_reset.token`.
- `Model::whereJsonContains('settings->permissions', $req->permission)` — то же.
- Mitigation: явный cast (`(string)`, `(int)`, in_array allowlist) перед передачей в whereJson*.

## Recipe-driven mass_assignment (`routes_authz_matrix` + `sensitive_columns`)

> **Если `framework_specific.laravel.routes_authz_matrix.status == ok`** и **`framework_specific.laravel.sensitive_columns.status == ok`** — используй recipe-данные. Иначе — graceful fallback на grep.

**С recipe-данными:**

1. Для каждой записи в `routes_authz_matrix.routes[]` с mutating method (POST/PUT/PATCH/DELETE) **без** `authz_evidence` (или только soft-evidence без `strength=hard_deny`):
2. Прочитай контроллер по `controller_file:line`.
3. Если контроллер использует `Model::create($request->all())` / `$model->fill($request->all())` / `$model->update($request->all())` / `Model::firstOrCreate($req->...)` / `forceCreate(...)`:
   → **confidence ≥ 8** для `mass_assignment` (sink_kind), framework recall сообщает «route без authz + open mass-fill».
4. Если в составе assignable атрибутов модели (через `$fillable` или отсутствие `$guarded`) есть item из `sensitive_columns.items[]` (например `is_admin`, `role`, `user_id`, `tenant_id`) с `encryption_status: plaintext`:
   → **confidence ≥ 9** (escalation: пользователь может перезаписать privilege-поле через mass-fill).

**Без recipe-данных (graceful fallback на grep):**

- Grep по проекту: `\$request->all\(\)` / `Request::all\(\)` / `request\(\)->all\(\)` в контроллерах.
- Для каждого hit — открой модель из контекста (`User::create(...)` → `app/Models/User.php`), проверь:
  - наличие `protected $fillable = [...]` (allowlist) или `protected $guarded = ['id']` (denylist),
  - если `$guarded = []` (default) — все колонки fillable → **confidence ≥ 8**;
  - если в `$fillable` есть privilege-поля (`role`, `is_admin`, `tenant_id`) — **confidence ≥ 9**.
- Floor выше при отсутствии Policy/`authorize()` вызова в том же методе контроллера (grep `\$this->authorize|Gate::authorize|@can` в файле/методе).

## Octane Eloquent global scopes (gate: `framework_specific.laravel.runtime.octane=true`)

> **Применяй только если** `framework_specific.laravel.runtime.octane == true`. Без recipe-секции — пропусти (см. graceful fallback в auth.md).

- **Global scope с `static` cache** — tenant leak between requests:
  ```php
  class TenantScope implements Scope {
      private static $cachedTenantId; // <-- state survives request boundary
      public function apply(Builder $b, Model $m) {
          self::$cachedTenantId ??= auth()->id(); // первое значение становится постоянным
          $b->where('tenant_id', self::$cachedTenantId);
      }
  }
  ```
- **Eloquent observer / global event с captured `auth()->user()`** — `User::saving(function ($model) use ($user) { ... })` зарегистрирован один раз в ServiceProvider boot; `$user` фиксируется на первом запросе.
- **Model `$casts` / `$appends` mutator, делающий DB-вызов с `auth()->id()`** в getter — кэшируется в `$model->cache` атрибуте instance, но instance может переиспользоваться между запросами при определённых eager-load patterns.
- **`Model::$globalScopes` static** — booted один раз; если scope регистрируется условно (`if (auth()->check()) ...`) в `boot()` — состояние первого запроса.
