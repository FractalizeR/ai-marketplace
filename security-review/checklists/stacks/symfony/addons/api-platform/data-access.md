# Data access / Doctrine ORM (Symfony + API Platform)

> This checklist extends `core/data-access.md` and `stacks/symfony/data-access.md` for projects using the API Platform bundle. On instruction conflict, this file takes precedence as the most specific layer. The worker loads all three files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Recipe-driven recall

When `recon_bags.addon.api-platform.resources.status == ok` walk `items[*].operations[*]` directly to read `filters`, `pagination_max`, `normalization_groups`. Until the extractor lands (current state: `status="unknown"`), fall back to grep on `#\[ApiResource`, `#\[ApiFilter`, `paginationMaximumItemsPerPage`, `paginationClientItemsPerPage` in `src/`.

## Pagination

API Platform paginates collection operations by default, but the limits are client-controllable unless capped.

- **`paginationMaximumItemsPerPage` unset**: a Resource without an explicit max-per-page (default per bundle config is 30, but `paginationItemsPerPage` per-resource can override) → client can request `?itemsPerPage=10000` if `paginationClientItemsPerPage: true` is also set. Even at default 30, batched alias/page-flooding is a concern (see GraphQL section).
- **`paginationClientItemsPerPage: true` without `paginationMaximumItemsPerPage` cap**: client controls page size with no upper bound → DoS via `?itemsPerPage=999999`. Always pair with a hard `paginationMaximumItemsPerPage: <int>` ceiling.
- **`paginationEnabled: false` on collection operations**: returns the entire table on every request → unbounded read DoS + memory pressure. Only acceptable for tiny lookup tables (enum-like rows).

## Filters

API Platform `#[ApiFilter(...)]` attributes (or `Doctrine\Common\Filter` services) expose query-parameter-driven filtering directly on Resource collections. Each filter is a tiny ORM macro driven by client input.

- **`SearchFilter` with `partial`/`start`/`end` strategy on indexed fields without input sanitization**: `#[ApiFilter(SearchFilter::class, properties: ['name' => 'partial'])]` translates to `WHERE name LIKE '%input%'`. Acceptable for case-sensitive exact-match strategies, but `partial`/`start`/`end` enable LIKE-injection (% / _ in the user input expand the match window) and timing-oracle attacks on indexed columns.
- **`SearchFilter` without explicit fields whitelist**: a class-level `#[ApiFilter(SearchFilter::class)]` without `properties: [...]` whitelist → every Entity field becomes filterable, including `passwordHash`, `apiToken`, `webhookSecret`. Client filters by `?passwordHash=...` to enumerate. Must always pass an explicit `properties` map.
- **`OrderFilter` without whitelist**: `#[ApiFilter(OrderFilter::class)]` without `properties: [...]` → sortable-as-oracle on sensitive columns. `?order[passwordHash]=asc` returns rows in hash order — combined with pagination this leaks ordering information. Whitelist allowed sort columns.
- **Custom DQL filter with concatenation**: a project-local `AbstractFilter` subclass that builds DQL via `$queryBuilder->andWhere("e.$field = '$value'")` instead of `setParameter()` → DQL injection (cross-ref `core/injection.md`). The whole filter mechanism only works with `setParameter` — custom filters that bypass it are a smell.
- **`BooleanFilter`/`DateFilter`/`RangeFilter` on fields outside `normalization_groups`**: a field hidden from the response (not in any `normalization_groups`) but filterable → existence/value oracle. Client cannot read the field, but `?isAdmin=true` reveals which users are admins by row count.

## Subresources / ownership

- **`#[ApiResource(uriTemplate: '/users/{userId}/orders/{id}')]`** without an ownership check on the parent route segment → IDOR. The bundle injects `{userId}` into the query builder only when configured; without `security: "is_granted('VIEW', object.user)"` or a custom `ApiResource` URI variable validator, attacker swaps `userId` to traverse other users' orders. Sink_kind: `idor_lookup`.
- **`ApiSubresource` (legacy / v2 carryover)**: same pattern — verify the subresource's `getParent()` ownership.

## Mercure (real-time publish)

API Platform integrates with Mercure for SSE-style real-time updates. The `mercure` operation attribute controls who can subscribe to updates of a Resource.

- **`mercure: ['private' => false]`** on a sensitive Resource → real-time pub without authz. Every update is broadcast to all anonymous subscribers of the topic. Must be `private: true` paired with JWT-issued targets matching the user. Sink_kind: `missing_authz` (root_cause_family: `authz`).

## GraphQL pagination/complexity (API Platform-specific)

> See `stacks/symfony/data-access.md` → GraphQL section for overblog/webonyx-specific patterns. Below is the api-platform side.

- **API Platform GraphQL query depth/complexity without a limit**: absence of a custom `query_complexity` limit and missing `api_platform.graphql.collection.pagination.maximum_items_per_page` → client sends `query { user { friends { friends { friends { ... } } } } }` of depth N → N JOINs / batched queries. The recommended setup is to enable `MaxQueryDepth` + `MaxQueryComplexity` rules via a service-extending `GraphQL\Server`/`Executor`. Sink_kind: `other:graphql_unbounded_query` (root_cause_family: `business_logic`) or the closest `missing_authz` if depth bypasses pagination. Confidence ≥ 7 for prod endpoints without limits.
