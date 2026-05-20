# Data access / Doctrine ORM (Symfony)

> Этот чек-лист дополняет `core/data-access.md` для проектов на symfony. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Confidence floor rules

- **`$repo->find($request->get('id'))`** в мутирующем контроллере без проверки владельца в методе или через voter → **confidence ≥ 8** для IDOR. Аргумент «может быть authz в слое ниже» не снижает confidence — ревьюер проверит.
- **Прямая конкатенация `$request->...` в DQL** (`createQuery('SELECT ... WHERE x = ' . $userInput)`) → **confidence ≥ 9** для dql_concat. Без исключений.

## DQL injection

- Конкатенация user input в DQL: `$em->createQuery("SELECT u FROM User u WHERE u.name = '$name'")`
- Использование `CONCAT()` в DQL с пользовательским вводом без параметризации
- Custom Repository методы, формирующие DQL через `.` (конкатенация) вместо `->setParameter()`
- Dynamic ORDER BY через конкатенацию: `->orderBy('u.' . $_GET['sort'])` (whitelist нужен)
- `CASE WHEN ... THEN ... END` с user input в условии

## QueryBuilder — типичные ошибки

- `->where('u.name = ' . $name)` вместо `->where('u.name = :name')->setParameter('name', $name)`
- `->andWhere(...)` с динамическим expression, собранным через конкатенацию
- Literal values в `->expr()->in('u.id', $ids)` — параметры используются только если `$ids` передан через `setParameter`

## Custom Repository методы

- Отсутствие валидации пользовательского ввода перед передачей в repository
- Repository-метод принимает `array $criteria` и передаёт в `createQueryBuilder()->where()` без строгой проверки ключей
- `findBy($criteria)` с user-controlled ключами — может привести к неожиданным query через `_or`, `_in` ORM-специфики

## Doctrine Listeners

- `prePersist` / `preUpdate` listener, вызывающий DQL с конкатенацией изменённых полей
- `onFlush` с `executeQuery` по user-controlled значениям

## ParamConverter / Value resolvers

- Symfony `#[MapEntity]` / ParamConverter автоматически подтягивает entity по `{id}` без authz-чека — контроллер обязан проверять владельца
- Value resolvers с user-controlled criteria — могут вернуть любую entity
- `MapRequestPayload` / `MapQueryString` без валидации Symfony Validator или без `data_class` — принимает произвольные поля (пересечение с mass_assignment, см. `injection.md`)

## GraphQL data exposure (api-platform / overblog/graphql-bundle / webonyx)

GraphQL endpoints работают как универсальный data-access layer: один HTTP-запрос с произвольным selection set. Без явных лимитов это превращается в DoS- и enumeration-вектор. Field-level authz покрыт в `auth.md` → GraphQL field authz; здесь — DoS, batching и introspection как enumeration vector.

- **Query depth/complexity без лимита**:
  - api-platform: отсутствие `api_platform.graphql.collection.pagination.maximum_items_per_page` и кастомного `query_complexity` лимита → клиент шлёт `query { user { friends { friends { friends { ... } } } } }` глубиной N → N JOIN'ов / batched queries.
  - webonyx: отсутствие `MaxQueryDepth` / `MaxQueryComplexity` rule в `GraphQL\Server`/`GraphQL::executeQuery()` → DoS через nested selections.
  - overblog/graphql-bundle: отсутствие `overblog_graphql.security.query_max_complexity` / `query_max_depth` в config → то же.
  - Sink_kind: `other:graphql_unbounded_query` (root_cause_family: `business_logic`) или ближайший `missing_authz` если глубина даёт обход pagination. Confidence ≥ 7 для prod-endpoint без лимитов.
- **Alias batching DoS**: один HTTP-запрос содержит N alias'ов одного field (`{ a1: user(id:1) {...} a2: user(id:2) {...} ... a1000: user(id:1000) {...} }`) → N SQL queries / N resolver invocations за один HTTP request. Без alias-cap (overblog `query_max_complexity` помогает частично) или rate limit на alias count → bypass обычного per-request rate limit.
- **Introspection в prod как enumeration vector**: атакующий через `__schema { types { name fields { name type { name } } } }` маппит **всю** schema → знает PII fields, role-fields, admin-only mutations → точечная атака. Сам по себе introspection — information disclosure (см. `auth.md` → GraphQL для floor), плюс ускоряет любые downstream-атаки. Sink_kind: `other:graphql_introspection_enabled` (root_cause_family: `disclosure`).
- **Resolver возвращает entity целиком без projection**: api-platform Resource без `#[Groups]`, overblog resolver возвращает `$entity->toArray()` / `$em->getRepository(...)->find($id)` напрямую → все поля (включая `passwordHash`, `apiToken`, `mfaSecret`) уезжают клиенту. Sink_kind: `secret_in_response` или `sensitive_field_unmasked` — детально см. `output-render.md` → GraphQL output filtering.

## Recipe-driven recall (`routes_authz_matrix`)

Wave 1-C добавил concept `route_authz_matrix` → recipe резолвит его в `framework_specific.symfony.routes_authz_matrix`. Wave 2-D начнёт реально эмитировать эту секцию из recipe; до того момента секция может отсутствовать. Чек-лист обязан работать в обеих ветвях — **graceful fallback** на grep при отсутствии секции.

**Ветвь 1 — секция есть (`framework_specific.symfony.routes_authz_matrix.status == ok`):**

- Идти прямо по `routes_authz_matrix.items[*]`. Каждый item содержит как минимум: `route` (путь/имя), `methods` (GET/POST/...), `controller`, `authz_evidence` (массив записей вида `{kind, source, strength}` где `kind ∈ {is_granted_attribute, deny_unless_granted_call, access_control_yaml, voter_call, none}`, `strength ∈ {hard_deny, soft, missing}`).
- **Для каждого route с mutating method (POST/PUT/PATCH/DELETE):**
  - Если `authz_evidence` пуст или содержит только записи со `strength == soft` (например, только `IS_AUTHENTICATED_REMEMBERED` без role check) → воркер репортит `missing_authz`, **confidence ≥ 8**.
  - Если route принимает entity (`#[MapEntity]` / ParamConverter / `$repo->find($request->get('id'))` в controller body) и `authz_evidence` пуст, **и** entity лежит в `framework_specific.symfony.data_access.items` (или эквивалент Doctrine entity bag) → воркер репортит `idor_lookup` / `missing_authz`, **confidence ≥ 8**.
  - Дополнительно: если route защищён только `IS_AUTHENTICATED_REMEMBERED` для sensitive операции (см. `auth.md` → IS_AUTHENTICATED_REMEMBERED vs FULLY) — отдельная находка `missing_authz`, confidence ≥ 7.
- Это не освобождает от чтения исходника — эвиденс из recipe только маркирует **что искать в первую очередь** и фиксирует floor.

**Ветвь 2 — секция отсутствует или `status != ok` (graceful fallback):**

- Использовать стандартный grep:
  - `grep -n "#\[Route(" src/Controller/` → находим все routes;
  - для каждого с `methods: ['POST']` / `['PUT']` / `['PATCH']` / `['DELETE']` или без `methods` (значит, любой метод) — проверяем ближайший `#[IsGranted(...)]` атрибут на методе или классе, или `denyAccessUnlessGranted(...)` в теле метода;
  - дополнительно проверить `config/packages/security.yaml` access_control rules, покрывающие route prefix.
- Confidence ≥ 7 для подозрительных mutating routes без явной защиты (без recipe-эвиденса нельзя гарантировать, что не пропущен voter в смежном файле — поэтому floor ниже, чем в Ветви 1).
- **Не понижать находки только потому, что секции нет** — это снижение recall. Просто использовать более консервативный floor.

В обеих ветвях принцип общий: mutating route без явной authz-защиты + entity-lookup → IDOR/missing_authz; разница только в floor (8 при наличии секции, 7 при fallback) и в скорости поиска.

## Admin bundle CRUD controllers (tenancy / mass_assignment) — cross-theme c auth

Admin-бандлы (EasyAdmin, SonataAdmin) автогенерируют формы из конфигурации полей. Без защит любое поле Entity становится editable через admin UI — классический mass-assignment для admin-surface. Угроза реальна даже для admin-only URL: admin surface достижима через XSS, CSRF, скомпрометированный аккаунт, а также между арендаторами в мульти-тенант системах.

### EasyAdmin

Формы генерируются из `configureFields()`.

- **Identity-поля редактируемы в форме**: поля tenant-owner / external identifier / shared secret (например `tenantId`, `ownerId`, `apiKey`, `domain` — реальные имена берутся из Entity проекта) в `configureFields()` без `->setDisabled()` / `->onlyOnIndex()` / `->hideOnForm()` → admin одной компании меняет owner → breaks tenant isolation.
- **Role/permission поля редактируемы**: поля типа `roles`, `permissions`, `isAdmin`, `isActive` в форме без guard через voter → privilege escalation.
- **Отсутствует `createIndexQueryBuilder()` override в per-tenant admin'ах**: admin видит Entity всех tenant'ов, а не только своего. Должен быть `andWhere` по tenant-ключу текущего пользователя.
- **Отсутствует `createEditFormBuilder()` / `createNewFormBuilder()` override** — разрешает редактирование любой сущности по id из URL (IDOR на admin-surface).
- **`AssociationField` без query-filter**: выпадающий список связанной сущности показывает объекты всех tenant'ов. Нужен `->setQueryBuilder(fn($qb) => $qb->andWhere(...))`.
- **Actions без `createEntityActions` / voter**: `delete`/`edit`/`impersonate` доступны всем admin'ам вне зависимости от владельца ресурса.
- **Batch actions**: массовые операции без per-entity authz check — ломают IDOR-защиту, даже если single-action её делает.

### SonataAdmin

Формы генерируются из `configureFormFields()` в классах `extends AbstractAdmin`.

- **Identity-поля редактируемы в форме**: поля tenant-owner / external identifier / shared secret в `configureFormFields()` без `->setDisabled(true)` / удаления из формы → admin одной компании меняет owner → breaks tenant isolation.
- **Role/permission поля редактируемы**: поля типа `roles`, `permissions`, `isAdmin`, `isActive` добавлены через `->add()` без ограничений → privilege escalation.
- **Отсутствует `createQuery()` override в per-tenant admin'ах**: `configureQuery()` (Sonata 4+) / `createQuery()` не фильтрует по tenant-ключу → admin видит Entity всех tenant'ов.
- **Отсутствует `preUpdate()` / `prePersist()` guard** — нет проверки, что сущность принадлежит текущему tenant'у перед сохранением (IDOR на admin-surface).
- **`ModelAutocompleteType` / `ModelListType` без `callback` фильтра**: выпадающие и автокомплит списки показывают объекты всех tenant'ов. Нужен `'callback' => function($admin, $property, $value) { ... }` с фильтром по tenant.
- **Custom actions без `isGranted()` check**: actions в `configureDashboardAction()` / `configureRoutes()` доступны всем admin'ам без проверки ownership.
- **Batch actions**: `configureBatchActions()` без per-entity authz check в `batchAction*()` методах.
