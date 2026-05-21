# Data access / Doctrine ORM (Symfony + Sonata AdminBundle)

> This checklist extends `core/data-access.md` and `stacks/symfony/data-access.md` for projects using the Sonata bundle. On instruction conflict, this file takes precedence as the most specific layer. The worker loads all three files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Admin bundle CRUD controllers (tenancy / mass_assignment) — cross-theme with auth

Admin bundles auto-generate forms from field configuration. Without defenses, any Entity field becomes editable via admin UI — a classic mass-assignment on the admin surface. The threat is real even for admin-only URLs: the admin surface is reachable via XSS, CSRF, a compromised account, and also across tenants in multi-tenant systems.

Forms are generated from `configureFormFields()` in classes `extends AbstractAdmin`. **Recipe-driven recall:** walk `recon_bags.addon.sonata.admin_classes.items[*]` directly. Each item carries `class`, `entity_fqcn`, and `form_fields[]` (array of field names from `$form->add('name', ...)`). Cross-link to `recon_bags.stack.symfony.admin_authz_coverage` for voter coverage.

- **Identity fields editable in the form**: tenant-owner / external identifier / shared secret fields in `configureFormFields()` without `->setDisabled(true)` / removal from the form → admin of one company changes owner → breaks tenant isolation.
- **Role/permission fields editable**: fields like `roles`, `permissions`, `isAdmin`, `isActive` added via `->add()` without restrictions → privilege escalation.
- **Missing `createQuery()` override in per-tenant admins**: `configureQuery()` (Sonata 4+) / `createQuery()` does not filter by tenant key → admin sees Entity of all tenants.
- **Missing `preUpdate()` / `prePersist()` guard** — no check that the entity belongs to the current tenant before saving (IDOR on the admin surface).
- **`ModelAutocompleteType` / `ModelListType` without `callback` filter**: dropdown and autocomplete lists show objects of all tenants. Needs `'callback' => function($admin, $property, $value) { ... }` with a tenant filter.
- **Custom actions without `isGranted()` check**: actions in `configureDashboardAction()` / `configureRoutes()` accessible to all admins without ownership check.
- **Batch actions**: `configureBatchActions()` without per-entity authz check in `batchAction*()` methods.
