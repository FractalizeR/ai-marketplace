# Authentication / Authorization (Symfony)

> Этот чек-лист дополняет `core/auth.md` для проектов на symfony. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Confidence floor rules

- **`#[Route(..., methods: ['POST'])]`** без `#[IsGranted]` / `$this->denyAccessUnlessGranted` на неанонимном функционале → **confidence ≥ 8** для missing_authz.
- **`framework_specific.symfony.admin_authz_coverage.crud_controllers_without_voter` non-empty** → для каждого такого контроллера зайти в `framework_specific.symfony.easyadmin_crud_controllers` items (или `framework_specific.symfony.sonata_admin_classes` для Sonata) по `class.endsWith(<short>)` и проверить editable identity-поля (см. ниже EasyAdmin / SonataAdmin секции). По умолчанию sink_kind=`mass_assignment`, root_cause_family=`authz`, **confidence ≥ 7** при наличии identity/role-полей без модификаторов (`setDisabled`/`onlyOnIndex`/`hideOnForm`).

## Symfony Security Bundle

- Отсутствие `#[IsGranted(...)]` / `$this->denyAccessUnlessGranted(...)` на контроллерах, работающих с приватными ресурсами
- Ошибки в `config/packages/security.yaml`: слишком широкие `access_control` паттерны (`^/admin` без регэкспа границы); `IS_AUTHENTICATED_ANONYMOUSLY` на мутирующих путях
- Неправильная конфигурация voters: `supports()` возвращает `true` для слишком широких атрибутов; `voteOnAttribute()` пропускает когда должно отказать
- `switch_user` без `role: ROLE_ALLOWED_TO_SWITCH`; возможность switch_user через GET-параметр без CSRF
- `remember_me` с предсказуемым `secret` или без `httponly: true, secure: true`
- Session fixation: отсутствие `session.migrate()` после login
- Login throttling bypass: отсутствие `login_throttling` / rate limit на login firewall

### `IS_AUTHENTICATED_REMEMBERED` vs `FULLY` для sensitive операций

- Контроллер sensitive операции (password change, email change, payment confirm, 2FA disable, API-key rotation) защищён через `#[IsGranted('IS_AUTHENTICATED_REMEMBERED')]` или `denyAccessUnlessGranted('IS_AUTHENTICATED_REMEMBERED')` — это **включает remember-me cookies** (нет proof of recent password). Должно быть `IS_AUTHENTICATED_FULLY` (или `IS_AUTHENTICATED_2FA_IN_PROGRESS` для post-2FA операций).
- То же самое для `access_control` rules в `security.yaml`: `roles: IS_AUTHENTICATED_REMEMBERED` на путях с sensitive операциями. Sink_kind: `missing_authz` (root_cause_family: `authz`), confidence ≥ 7.

### Voter anti-patterns

- `VoterInterface::supports($attribute, $subject)` возвращает `true` для слишком широкого `$attribute` (`return true` без проверки списка, `return str_starts_with($attribute, 'POST_')` для voter, обрабатывающего только `POST_EDIT`/`POST_DELETE`, regex-match вида `'/^[A-Z_]+$/'`) → voter применяется к ситуациям, для которых не написан → false-positive grant из `voteOnAttribute()`.
- `voteOnAttribute()` `default true` (case-block не нашёлся → `return true` или `return Voter::ACCESS_GRANTED`) вместо `return false` / `Voter::ACCESS_DENIED` → grant by default. Особенно опасно при добавлении новых attributes: они автоматически разрешаются без обновления voter'а.
- `voteOnAttribute()` без проверки `$subject instanceof ExpectedClass` — если supports() слишком широкий, voter может быть вызван с чужой сущностью и проигнорирует ownership check.

### `security.yaml` access_control regex precedence

- access_control rules матчатся **по порядку** сверху вниз; первый совпавший — используется, остальные не проверяются. Если выше стоит широкий паттерн (`{ path: '^/admin', roles: ROLE_USER }`), а ниже — узкий с более строгой ролью (`{ path: '^/admin/users/edit', roles: ROLE_SUPER_ADMIN }`), узкий **никогда не сработает** → privilege escalation.
- Ловить через ручной анализ порядка rules + сверку с `framework_specific.symfony.routes_authz_matrix` (если секция есть — см. data-access.md). Sink_kind: `missing_authz`, confidence ≥ 7 при наличии узкого правила, перекрытого широким.

## OAuth/OIDC (Symfony — KnpUOAuth2ClientBundle, league/oauth2-client)

См. `core/auth.md` → OAuth/OIDC для generic-паттернов (state validation, PKCE, redirect_uri exact-match). Ниже — Symfony-уточнения.

- **KnpUOAuth2ClientBundle**: callback-контроллер, который не вызывает `$client->retrieveAccessToken($state)` или эквивалентный state-check сразу после получения authorization code → state→token race / отсутствует валидация state. Sink_kind: `oauth_state_missing`.
- **`league/oauth2-client` `Provider::getAuthorizationUrl()` без явной опции `state`**: библиотека сгенерирует случайный state в `$provider->getState()`, но если разработчик не сохранил его в session (`$_SESSION['oauth2state'] = $provider->getState()`) и не сравнил при callback — state по факту не валидируется. Типичный код-смелл: вызов `getAuthorizationUrl()` без последующей записи `getState()` в session.
- **`redirect_uri` whitelist через `services.yaml` config**: substring match (`str_contains($redirect, $allowedDomain)`) вместо exact match → bypass через `https://attacker.com/?evil=allowed.com`. Должен быть exact compare всей URI (включая path) или strict host whitelist через `parse_url()` + `in_array()`.
- **OAuth login через KnpU Authenticator (`SocialAuthenticator`)** без verified-email check провайдера → account takeover при провайдере, не верифицирующем email (некоторые self-hosted OAuth servers).

## MFA (scheb/2fa-bundle)

См. `core/auth.md` → MFA для generic-паттернов. Ниже — Symfony-уточнения.

- **`scheb/2fa-bundle` с `enabled: false`** в `config/packages/scheb_2fa.yaml` — bundle загружен, но 2FA выключен глобально → IS_AUTHENTICATED_2FA_IN_PROGRESS не срабатывает, sensitive routes не защищены.
- **Voter `IS_AUTHENTICATED_2FA_IN_PROGRESS` отсутствует в `access_control` для protected routes**, при этом 2FA включён для пользователя. Маршрут `^/account/sensitive` без `roles: IS_AUTHENTICATED_2FA_IN_PROGRESS` → пользователь с включённым 2FA может попасть на route после первичного логина без второго фактора.
- **Recovery codes хранятся через `scheb/2fa-bundle` (TwoFactorTrait::getBackupCodes()`)**, но `User::eraseRecoveryCode($code)` не реализован или реализован как no-op → коды переиспользуемы (single-use enforcement отсутствует). Sink_kind: `missing_authz`.
- **TOTP secret в `User` entity без encryption-at-rest** (`#[ORM\Column(type: 'string')] $totpSecret`) — DB compromise → атакующий восстанавливает TOTP коды всех пользователей. Cross-link: `crypto.md` → persistent secrets в plain columns.

## JWT (lexik/jwt-authentication-bundle)

См. `core/crypto.md` → JWT advanced (kid/jwk header injection, algorithm confusion RS256→HS256, aud/iss mismatch, nbf/iat skew). Symfony реализация одинакова — здесь только bundle-specifics.

- **`JWT_PASSPHRASE` / `JWT_PRIVATE_KEY` в коммитнутом `.env`** (без `.env.local` override) → атакующий ре-подписывает токены любого пользователя. Sink_kind: `hardcoded_secret`. См. также `crypto.md` → APP_SECRET.
- **`token_extractors.query_parameter.enabled: true` при cookie/header auth** — токен попадает в URL → утечка через browser history, server access logs, `Referer` header при переходе на внешний ресурс.
- **`kid` / `jwk` passthrough**: если в проекте есть **custom Authenticator** (не дефолтный из bundle), который передаёт `kid` header в `JwtEncoderInterface` без whitelist → возможен kid header injection (см. core).
- **`Lcobucci\JWT\Configuration` напрямую (без bundle)**: validation constraints (`SignedWith`, `IssuedBy`, `PermittedFor`) опциональны — если разработчик создал `Configuration::forSymmetricSigner(...)` и забыл `setValidationConstraints([...])`, любая подпись/iss/aud принимается. Грепать на `Configuration::forSymmetricSigner` / `forAsymmetricSigner` без последующего `setValidationConstraints`.

## GraphQL field authz (api-platform / overblog/graphql-bundle / webonyx)

- **api-platform `#[ApiResource]` без `security` / `securityPostDenormalize`**: `#[ApiResource(operations: [new Get(), new GetCollection(), new Post()])]` без `security: "is_granted('ROLE_USER')"` (или `securityPostDenormalize` для проверки после denormalization) → query/mutation доступны всем, поля Entity сериализуются по `#[Groups]` без owner-check. Sink_kind: `missing_authz`.
- **api-platform per-operation security отсутствует**: `Post`/`Patch`/`Delete` operation без `security: "is_granted(...)"` или с `security: "is_granted('PUBLIC_ACCESS')"` на mutating endpoint → write без authz.
- **overblog/graphql-bundle resolver без `#[Security('is_granted(...)')]`**: resolver-метод (`#[GraphQL\Field]`, `#[GraphQL\Mutation]`) или поле в schema YAML без `accessControl: "is_granted('ROLE_USER')"` / `access: "is_granted(...)"` → field/resolver доступен анонимам. Также `accessControl: "true"` (literal `true` без выражения) — pseudo-check.
- **webonyx native (`webonyx/graphql-php`)**: resolver function (`'resolve' => fn($root, $args, $context) => ...`) не проверяет `$context['user']` / не вызывает voter → field-level authz отсутствует. Особенно опасно для resolver'ов, возвращающих entity напрямую без проекции.
- **Introspection в prod**: api-platform / overblog по умолчанию включают `query Introspection { __schema { types { name fields { name } } } }`. Если bundle config не отключает introspection в prod (`overblog_graphql.definitions.introspection.enabled: false` для overblog или отсутствие `enable_graphiql: false` + `enable_docs: false` + `enable_swagger_ui: false` для api-platform) → confidence floor **≥ 8** (information disclosure: attacker маппит всю schema, включая admin-only поля и mutations). Sink_kind: `stacktrace_exposed` или `other:graphql_introspection_enabled` (root_cause_family: `disclosure`).

## Symfony Form CSRF

- Формы без `csrf_protection: true` и без CSRF токена в теле — Symfony Form по умолчанию включает CSRF для `data_class` форм, но при `csrf_protection: false` или standalone-controllers без Form компонента — пропадает

## Admin bundle CRUD controllers (tenancy / mass_assignment) — cross-theme c data-access

Admin-бандлы (EasyAdmin, SonataAdmin) автогенерируют формы из конфигурации полей. Без защит любое поле Entity становится editable через admin UI — классический mass-assignment для admin-surface. Угроза реальна даже для admin-only URL: admin surface достижима через XSS, CSRF, скомпрометированный аккаунт, а также между арендаторами в мульти-тенант системах.

### EasyAdmin

Формы генерируются из `configureFields()`. **Recipe-driven recall:** воркер получает уже готовый список CRUD-контроллеров и их полей в `framework_specific.symfony.easyadmin_crud_controllers.items[*].configure_fields` — каждое поле помечено `modifiers: []` (например `[setDisabled, hideOnForm, formatValue, onlyOnIndex]`). Идти прямо по этим items и фильтровать по правилам ниже **до** grep'а по исходникам.

- **Identity-поля редактируемы в форме**: поля tenant-owner / external identifier / shared secret (например `tenantId`, `ownerId`, `apiKey`, `domain` — реальные имена берутся из Entity проекта) в `configureFields()` без `->setDisabled()` / `->onlyOnIndex()` / `->hideOnForm()` → admin одной компании меняет owner → breaks tenant isolation. Recipe-driven hint: `configure_fields[].modifiers` пустой ⇔ поле редактируемо.
- **Role/permission поля редактируемы**: поля типа `roles`, `permissions`, `isAdmin`, `isActive` в форме без guard через voter → privilege escalation.
- **Отсутствует `createIndexQueryBuilder()` override в per-tenant admin'ах**: admin видит Entity всех tenant'ов, а не только своего. Должен быть `andWhere` по tenant-ключу текущего пользователя.
- **Отсутствует `createEditFormBuilder()` / `createNewFormBuilder()` override** — разрешает редактирование любой сущности по id из URL (IDOR на admin-surface).
- **`AssociationField` без query-filter**: выпадающий список связанной сущности показывает объекты всех tenant'ов. Нужен `->setQueryBuilder(fn($qb) => $qb->andWhere(...))`.
- **Actions без `createEntityActions` / voter**: `delete`/`edit`/`impersonate` доступны всем admin'ам вне зависимости от владельца ресурса.
- **Batch actions**: массовые операции без per-entity authz check — ломают IDOR-защиту, даже если single-action её делает.

### SonataAdmin

Формы генерируются из `configureFormFields()` в классах `extends AbstractAdmin`. **Recipe-driven recall:** воркер получает уже готовый список admin-классов и их полей в `framework_specific.symfony.sonata_admin_classes.items[*].form_fields` — это массив имён полей из `$form->add('name', ...)`. Идти прямо по этим items и фильтровать по правилам ниже **до** grep'а по исходникам. Если `sonata_admin_classes.status == none` — Sonata в проекте отсутствует.

- **Identity-поля редактируемы в форме**: поля tenant-owner / external identifier / shared secret в `configureFormFields()` без `->setDisabled(true)` / удаления из формы → admin одной компании меняет owner → breaks tenant isolation.
- **Role/permission поля редактируемы**: поля типа `roles`, `permissions`, `isAdmin`, `isActive` добавлены через `->add()` без ограничений → privilege escalation.
- **Отсутствует `createQuery()` override в per-tenant admin'ах**: `configureQuery()` (Sonata 4+) / `createQuery()` не фильтрует по tenant-ключу → admin видит Entity всех tenant'ов.
- **Отсутствует `preUpdate()` / `prePersist()` guard** — нет проверки, что сущность принадлежит текущему tenant'у перед сохранением (IDOR на admin-surface).
- **`ModelAutocompleteType` / `ModelListType` без `callback` фильтра**: выпадающие и автокомплит списки показывают объекты всех tenant'ов. Нужен `'callback' => function($admin, $property, $value) { ... }` с фильтром по tenant.
- **Custom actions без `isGranted()` check**: actions в `configureDashboardAction()` / `configureRoutes()` доступны всем admin'ам без проверки ownership.
- **Batch actions**: `configureBatchActions()` без per-entity authz check в `batchAction*()` методах.
