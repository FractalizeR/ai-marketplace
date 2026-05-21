# Authentication / Authorization (Symfony + EasyAdmin)

> This checklist extends `core/auth.md` and `stacks/symfony/auth.md` for projects using the EasyAdmin bundle. On instruction conflict, this file takes precedence as the most specific layer. The worker loads all three files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Admin bundle CRUD controllers (tenancy / mass_assignment) — cross-theme with data-access

Admin bundles auto-generate forms from field configuration. Without defenses, any Entity field becomes editable via admin UI — a classic mass-assignment on the admin surface. The threat is real even for admin-only URLs: the admin surface is reachable via XSS, CSRF, a compromised account, and also across tenants in multi-tenant systems.

Forms are generated from `configureFields()`. **Recipe-driven recall:** the worker receives a ready list of CRUD controllers and their fields in `recon_bags.addon.easyadmin.crud_controllers.items[*].configure_fields` — each field is tagged with `modifiers: []` (e.g., `[setDisabled, hideOnForm, formatValue, onlyOnIndex]`). Walk these items directly and filter by the rules below **before** grepping the source.

- **Identity fields editable in the form**: tenant-owner / external identifier / shared secret fields (e.g., `tenantId`, `ownerId`, `apiKey`, `domain` — actual names taken from the project Entity) in `configureFields()` without `->setDisabled()` / `->onlyOnIndex()` / `->hideOnForm()` → admin of one company changes owner → breaks tenant isolation. Recipe-driven hint: empty `configure_fields[].modifiers` ⇔ field is editable.
- **Role/permission fields editable**: fields like `roles`, `permissions`, `isAdmin`, `isActive` in the form without a voter guard → privilege escalation.
- **Missing `createIndexQueryBuilder()` override in per-tenant admins**: admin sees Entity of all tenants, not just their own. Must be `andWhere` by the tenant key of the current user.
- **Missing `createEditFormBuilder()` / `createNewFormBuilder()` override** — allows editing of any entity by id from URL (IDOR on the admin surface).
- **`AssociationField` without query-filter**: dropdown of related entity shows objects of all tenants. Needs `->setQueryBuilder(fn($qb) => $qb->andWhere(...))`.
- **Actions without `createEntityActions` / voter**: `delete`/`edit`/`impersonate` accessible to all admins regardless of resource owner.
- **Batch actions**: bulk operations without per-entity authz check — break IDOR protection, even if single-action enforces it.
