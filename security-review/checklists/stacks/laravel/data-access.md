# Data access / Eloquent ORM (Laravel)

> This checklist complements `core/data-access.md` for laravel projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Confidence floor rules

- **`Model::find($request->input('id'))`** in a mutating controller without `$this->authorize(...)` / Policy → **confidence ≥ 8** for IDOR. The argument "there may be a Policy elsewhere" does not lower confidence — the reviewer will verify.
- **Direct concatenation of `$request->...` into `DB::raw()` / `whereRaw()` / `selectRaw()` / `orderByRaw()`** → **confidence ≥ 9** for sql_injection.

## Raw SQL injection

- `DB::raw($input)` where `$input` is user-controlled
- `DB::select("... WHERE x = $userInput")` — concatenation in plain SQL
- `whereRaw("col = $userInput")` / `selectRaw("$userField")` without a placeholder parameter and `$bindings`
- `havingRaw("count > $count")` without parameterization
- `orderByRaw($_GET['sort'])` — whitelist of column names required
- `DB::statement($sql)` with user input

## Query Builder dynamic patterns

- `->where('col', '=', $req->q)` — parameterized, safe. But `->whereRaw("col = '$value'")` — not safe
- `->orderBy($req->sort)` — needs `in_array($req->sort, $allowed)` whitelist (column names are not parameterized)
- `->orderBy('col', $req->dir)` where `$dir` is user-controlled and not validated (only asc/desc allowed)
- Dynamic table in `DB::table($name)` without a whitelist
- `->whereColumn($a, $b)` with user-controlled column names

## Eloquent mass assignment

- `Model::create($request->all())` or `->update($request->all())` without `$fillable` or with `$guarded = []` → mass assignment (admin/role/tenant_id, etc.)
- `Model::forceCreate($request->all())` — bypass of $fillable; critical usage
- `Model::fill($request->all())->save()` — bypass of guards if `$guarded = []`
- `Model::firstOrCreate(['id' => $req->id], $req->all())` — id as lookup + the rest as create data
- `$user->update($request->only(['name', 'email']))` — correct. `$request->only(['name', 'email', 'role'])` — forgot to filter the critical field
- Model with `protected $guarded = []` (default to no guard) — all columns fillable

## Route-model binding

- Route `/posts/{post}` with implicit binding → Laravel calls `Post::findOrFail($id)`. Without Policy / `$this->authorize` in the action → IDOR
- Custom binding in `RouteServiceProvider::boot` without tenant scope — attacker reads someone else's record by id
- `Route::bind('post', fn($id) => Post::find($id))` without a projection scope
- Implicit binding with soft-deletes (`->withTrashed()`) — may return a deleted record
- Scoped binding `/users/{user}/posts/{post:slug}` — correct. Without scope (`{post}` without `:column`) — bypass via slug collision

## Eloquent relationships / N+1 / data leak

- Eager loading of foreign relations: `Post::with('user.privateData')->get()` — emits internals through JSON serialization
- `belongsTo` / `hasMany` / `morphMany` without projection — `.toArray()` emits all columns
- `MorphMap` with user-controlled morph type — attacker sets any class → Object Injection-like via polymorphic relations
- Lazy load `$post->user` in a loop (N+1) — DoS-ish + potential leak when forgotten in auth context

## Soft deletes

- `Model::findOrFail` skips soft-deleted, but `withTrashed()->find()` — no. Authz check must cover both paths
- `restore()` without checking original ownership (the record may have been transferred between tenants)

## Transaction boundaries

- `DB::transaction(fn() => ...)` with throw inside intercepted by an outer try/catch without reverting the audit log
- Race condition: `if (!$user->isLocked()) { $user->lock(); }` without `lockForUpdate()` / row lock
- Optimistic locking missing: `$model->update(['version' => $version, ...])` without a version-field check

## Database raw migrations / seeds

- Migrations with `DB::statement("ALTER TABLE ... ADD COLUMN role DEFAULT 'admin'")` — all existing users become admins (migration as a backdoor)
- Seeds in production with `User::factory()->admin()->create()` without a condition

## API Resources data exposure

- `class UserResource extends JsonResource { public function toArray() { return parent::toArray($request); } }` — `parent::toArray` emits **all** columns, including `password_hash`/`remember_token`/internal flags
- Resource without `whenLoaded()` — emits null or N+1 query
- Conditional attribute `'role' => $this->when($request->user()?->isAdmin, $this->role)` forgotten — non-admin reads the field

## GraphQL data exposure (`nuwave/lighthouse`, `rebing/graphql-laravel`)

- **Query depth/complexity without a limit** — `lighthouse.security.max_query_depth=null` or `max_query_complexity=null` → attacker sends a deeply nested query (`a { b { c { d { ... } } } }`) → DoS via resolver expansion and/or N+1 at every level.
- **Alias batching** — one HTTP request with N aliases of one mutation → N resolver executions → bypass of rate limit (limit counts HTTP requests, not operations). Example: `mutation { a: login(email:"e1") { token } b: login(email:"e2") { token } ... }`.
- **Persisted-queries-only bypass via client-side query manipulation** — server checks the hash, but `extensions.persistedQuery.sha256Hash` matches the hash of another query with the same text → collision / hash spoofing. Also: if `persisted_queries` mode accepts an unknown hash and stores it → attacker injects their query.
- **Lighthouse `@paginate` without `maxCount`** — `users { paginate(first: 999999) }` → dump of the entire table.
- **Rebing `pagination` without `max_per_page`** — same.
- **Field-level data leak** — resolver returns Eloquent model directly (see `output-render.md → GraphQL output filtering`).

## whereJsonContains / whereJsonPath with user input

- `User::where('roles', '@>', json_encode($req->input('roles')))` — JSON injection via user-controlled payload. `$req->input('roles')` may be an array/object → `json_encode` produces JSON which as a WHERE pattern matches any records (e.g., `[]` matches all).
- `whereJsonContains('permissions', $req->input('perm'))` — without cast/validate `$req->input('perm')` may be `null` (matches NULL JSON), `["admin"]` (escalation), a nested object.
- `whereJsonPath('$.role', '=', $req->path)` — user-controlled JSON path → attacker reads other branches of the JSON document: `$.password_reset.token`.
- `Model::whereJsonContains('settings->permissions', $req->permission)` — same.
- Mitigation: explicit cast (`(string)`, `(int)`, in_array allowlist) before passing into whereJson*.

## Recipe-driven mass_assignment (`routes_authz_matrix` + `sensitive_columns`)

> **If `recon_bags.stack.laravel.routes_authz_matrix.status == ok`** and **`recon_bags.stack.laravel.sensitive_columns.status == ok`** — use recipe data. Otherwise — graceful fallback to grep.

**With recipe data:**

1. For each record in `routes_authz_matrix.routes[]` with a mutating method (POST/PUT/PATCH/DELETE) **without** `authz_evidence` (or with only soft evidence without `strength=hard_deny`):
2. Read the controller by `controller_file:line`.
3. If the controller uses `Model::create($request->all())` / `$model->fill($request->all())` / `$model->update($request->all())` / `Model::firstOrCreate($req->...)` / `forceCreate(...)`:
   → **confidence ≥ 8** for `mass_assignment` (sink_kind), framework recall reports "route without authz + open mass-fill".
4. If among assignable model attributes (via `$fillable` or absence of `$guarded`) there is an item from `sensitive_columns.items[]` (e.g., `is_admin`, `role`, `user_id`, `tenant_id`) with `encryption_status: plaintext`:
   → **confidence ≥ 9** (escalation: user can overwrite a privilege field via mass-fill).

**Without recipe data (graceful fallback to grep):**

- Grep through the project: `\$request->all\(\)` / `Request::all\(\)` / `request\(\)->all\(\)` in controllers.
- For each hit — open the model from context (`User::create(...)` → `app/Models/User.php`), check:
  - presence of `protected $fillable = [...]` (allowlist) or `protected $guarded = ['id']` (denylist),
  - if `$guarded = []` (default) — all columns fillable → **confidence ≥ 8**;
  - if `$fillable` contains privilege fields (`role`, `is_admin`, `tenant_id`) — **confidence ≥ 9**.
- Higher floor if there is no Policy/`authorize()` call in the same controller method (grep `\$this->authorize|Gate::authorize|@can` in the file/method).

## Octane Eloquent global scopes (gate: `recon_bags.stack.laravel.runtime.octane=true`)

> **Apply only if** `recon_bags.stack.laravel.runtime.octane == true`. Without the recipe section — skip (see graceful fallback in auth.md).

- **Global scope with `static` cache** — tenant leak between requests:
  ```php
  class TenantScope implements Scope {
      private static $cachedTenantId; // <-- state survives request boundary
      public function apply(Builder $b, Model $m) {
          self::$cachedTenantId ??= auth()->id(); // first value becomes permanent
          $b->where('tenant_id', self::$cachedTenantId);
      }
  }
  ```
- **Eloquent observer / global event with captured `auth()->user()`** — `User::saving(function ($model) use ($user) { ... })` registered once in ServiceProvider boot; `$user` is fixed on the first request.
- **Model `$casts` / `$appends` mutator making a DB call with `auth()->id()`** in a getter — cached in the `$model->cache` attribute of the instance, but the instance may be reused between requests under certain eager-load patterns.
- **`Model::$globalScopes` static** — booted once; if the scope is registered conditionally (`if (auth()->check()) ...`) in `boot()` — state of the first request.
