# Data access / Doctrine ORM (Symfony)

> This checklist complements `core/data-access.md` for symfony projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Confidence floor rules

- **`$repo->find($request->get('id'))`** in a mutating controller without an owner check in the method or via a voter → **confidence ≥ 8** for IDOR. The argument "there may be authz in a lower layer" does not lower confidence — the reviewer will verify.
- **Direct concatenation of `$request->...` into DQL** (`createQuery('SELECT ... WHERE x = ' . $userInput)`) → **confidence ≥ 9** for dql_concat. No exceptions.

## DQL injection

- Concatenation of user input into DQL: `$em->createQuery("SELECT u FROM User u WHERE u.name = '$name'")`
- Use of `CONCAT()` in DQL with user input without parameterization
- Custom Repository methods building DQL via `.` (concatenation) instead of `->setParameter()`
- Dynamic ORDER BY via concatenation: `->orderBy('u.' . $_GET['sort'])` (whitelist required)
- `CASE WHEN ... THEN ... END` with user input in the condition

## QueryBuilder — typical mistakes

- `->where('u.name = ' . $name)` instead of `->where('u.name = :name')->setParameter('name', $name)`
- `->andWhere(...)` with a dynamic expression assembled via concatenation
- Literal values in `->expr()->in('u.id', $ids)` — parameters are used only if `$ids` is passed via `setParameter`

## Custom Repository methods

- Lack of user input validation before passing into the repository
- Repository method accepts `array $criteria` and passes it into `createQueryBuilder()->where()` without strict key validation
- `findBy($criteria)` with user-controlled keys — may lead to unexpected queries via `_or`, `_in` ORM specifics

## Doctrine Listeners

- `prePersist` / `preUpdate` listener invoking DQL with concatenation of changed fields
- `onFlush` with `executeQuery` on user-controlled values

## ParamConverter / Value resolvers

- Symfony `#[MapEntity]` / ParamConverter automatically pulls the entity by `{id}` without an authz check — the controller is required to check the owner
- Value resolvers with user-controlled criteria — may return any entity
- `MapRequestPayload` / `MapQueryString` without Symfony Validator validation or without `data_class` — accepts arbitrary fields (overlap with mass_assignment, see `injection.md`)

## GraphQL data exposure (api-platform / overblog/graphql-bundle / webonyx)

GraphQL endpoints act as a universal data-access layer: one HTTP request with an arbitrary selection set. Without explicit limits this becomes a DoS and enumeration vector. Field-level authz is covered in `auth.md` → GraphQL field authz; here — DoS, batching, and introspection as an enumeration vector.

- **Query depth/complexity without a limit**:
  - api-platform: absence of `api_platform.graphql.collection.pagination.maximum_items_per_page` and a custom `query_complexity` limit → client sends `query { user { friends { friends { friends { ... } } } } }` of depth N → N JOINs / batched queries.
  - webonyx: absence of `MaxQueryDepth` / `MaxQueryComplexity` rule in `GraphQL\Server`/`GraphQL::executeQuery()` → DoS via nested selections.
  - overblog/graphql-bundle: absence of `overblog_graphql.security.query_max_complexity` / `query_max_depth` in config → same.
  - Sink_kind: `other:graphql_unbounded_query` (root_cause_family: `business_logic`) or the closest `missing_authz` if depth bypasses pagination. Confidence ≥ 7 for prod endpoints without limits.
- **Alias batching DoS**: one HTTP request contains N aliases of one field (`{ a1: user(id:1) {...} a2: user(id:2) {...} ... a1000: user(id:1000) {...} }`) → N SQL queries / N resolver invocations per single HTTP request. Without an alias cap (overblog `query_max_complexity` helps partially) or rate limit on alias count → bypass of the regular per-request rate limit.
- **Introspection in prod as an enumeration vector**: attacker maps the **entire** schema via `__schema { types { name fields { name type { name } } } }` → knows PII fields, role fields, admin-only mutations → targeted attack. Introspection itself is information disclosure (see `auth.md` → GraphQL for the floor), plus it accelerates any downstream attacks. Sink_kind: `other:graphql_introspection_enabled` (root_cause_family: `disclosure`).
- **Resolver returns entity entirely without projection**: api-platform Resource without `#[Groups]`, overblog resolver returns `$entity->toArray()` / `$em->getRepository(...)->find($id)` directly → all fields (including `passwordHash`, `apiToken`, `mfaSecret`) leave to the client. Sink_kind: `secret_in_response` or `sensitive_field_unmasked` — see `output-render.md` → GraphQL output filtering in detail.

## Recipe-driven recall (`routes_authz_matrix`)

Wave 1-C added the concept `route_authz_matrix` → the recipe resolves it into `framework_specific.symfony.routes_authz_matrix`. Wave 2-D will actually start emitting this section from the recipe; until then the section may be absent. The checklist must work in both branches — **graceful fallback** to grep when the section is absent.

**Branch 1 — section is present (`framework_specific.symfony.routes_authz_matrix.status == ok`):**

- Walk `routes_authz_matrix.items[*]` directly. Each item contains at least: `route` (path/name), `methods` (GET/POST/...), `controller`, `authz_evidence` (an array of records like `{kind, source, strength}` where `kind ∈ {is_granted_attribute, deny_unless_granted_call, access_control_yaml, voter_call, none}`, `strength ∈ {hard_deny, soft, missing}`).
- **For each route with a mutating method (POST/PUT/PATCH/DELETE):**
  - If `authz_evidence` is empty or contains only records with `strength == soft` (e.g., only `IS_AUTHENTICATED_REMEMBERED` without a role check) → worker reports `missing_authz`, **confidence ≥ 8**.
  - If the route accepts an entity (`#[MapEntity]` / ParamConverter / `$repo->find($request->get('id'))` in the controller body) and `authz_evidence` is empty, **and** the entity lies in `framework_specific.symfony.data_access.items` (or the Doctrine entity bag equivalent) → worker reports `idor_lookup` / `missing_authz`, **confidence ≥ 8**.
  - Additionally: if the route is protected only by `IS_AUTHENTICATED_REMEMBERED` for a sensitive operation (see `auth.md` → IS_AUTHENTICATED_REMEMBERED vs FULLY) — a separate finding `missing_authz`, confidence ≥ 7.
- This does not exempt you from reading the source — recipe evidence only marks **what to look at first** and fixes the floor.

**Branch 2 — section is missing or `status != ok` (graceful fallback):**

- Use standard grep:
  - `grep -n "#\[Route(" src/Controller/` → find all routes;
  - for each with `methods: ['POST']` / `['PUT']` / `['PATCH']` / `['DELETE']` or without `methods` (meaning any method) — check the nearest `#[IsGranted(...)]` attribute on the method or class, or `denyAccessUnlessGranted(...)` in the method body;
  - additionally check `config/packages/security.yaml` access_control rules covering the route prefix.
- Confidence ≥ 7 for suspicious mutating routes without explicit protection (without recipe evidence we cannot guarantee that a voter in an adjacent file was not missed — hence the floor is lower than in Branch 1).
- **Do not lower findings just because the section is absent** — that reduces recall. Just use a more conservative floor.

In both branches the principle is the same: a mutating route without explicit authz protection + entity lookup → IDOR/missing_authz; the difference is only in the floor (8 with the section present, 7 with fallback) and in search speed.

## Admin bundle CRUD controllers (tenancy / mass_assignment) — cross-theme with auth

Admin bundles (EasyAdmin, SonataAdmin) auto-generate forms from field configuration. Without defenses, any Entity field becomes editable via admin UI — a classic mass-assignment on the admin surface. The threat is real even for admin-only URLs: the admin surface is reachable via XSS, CSRF, a compromised account, and also across tenants in multi-tenant systems.

### EasyAdmin

Forms are generated from `configureFields()`.

- **Identity fields editable in the form**: tenant-owner / external identifier / shared secret fields (e.g., `tenantId`, `ownerId`, `apiKey`, `domain` — actual names taken from the project Entity) in `configureFields()` without `->setDisabled()` / `->onlyOnIndex()` / `->hideOnForm()` → admin of one company changes owner → breaks tenant isolation.
- **Role/permission fields editable**: fields like `roles`, `permissions`, `isAdmin`, `isActive` in the form without a voter guard → privilege escalation.
- **Missing `createIndexQueryBuilder()` override in per-tenant admins**: admin sees Entity of all tenants, not just their own. Must be `andWhere` by the tenant key of the current user.
- **Missing `createEditFormBuilder()` / `createNewFormBuilder()` override** — allows editing of any entity by id from URL (IDOR on the admin surface).
- **`AssociationField` without query-filter**: dropdown of related entity shows objects of all tenants. Needs `->setQueryBuilder(fn($qb) => $qb->andWhere(...))`.
- **Actions without `createEntityActions` / voter**: `delete`/`edit`/`impersonate` accessible to all admins regardless of resource owner.
- **Batch actions**: bulk operations without per-entity authz check — break IDOR protection, even if single-action enforces it.

### SonataAdmin

Forms are generated from `configureFormFields()` in classes `extends AbstractAdmin`.

- **Identity fields editable in the form**: tenant-owner / external identifier / shared secret fields in `configureFormFields()` without `->setDisabled(true)` / removal from the form → admin of one company changes owner → breaks tenant isolation.
- **Role/permission fields editable**: fields like `roles`, `permissions`, `isAdmin`, `isActive` added via `->add()` without restrictions → privilege escalation.
- **Missing `createQuery()` override in per-tenant admins**: `configureQuery()` (Sonata 4+) / `createQuery()` does not filter by tenant key → admin sees Entity of all tenants.
- **Missing `preUpdate()` / `prePersist()` guard** — no check that the entity belongs to the current tenant before saving (IDOR on the admin surface).
- **`ModelAutocompleteType` / `ModelListType` without `callback` filter**: dropdown and autocomplete lists show objects of all tenants. Needs `'callback' => function($admin, $property, $value) { ... }` with a tenant filter.
- **Custom actions without `isGranted()` check**: actions in `configureDashboardAction()` / `configureRoutes()` accessible to all admins without ownership check.
- **Batch actions**: `configureBatchActions()` without per-entity authz check in `batchAction*()` methods.
