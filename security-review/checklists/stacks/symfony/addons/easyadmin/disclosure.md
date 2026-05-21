# Information disclosure (Symfony + EasyAdmin)

> This checklist extends `core/disclosure.md` and `stacks/symfony/disclosure.md` for projects using the EasyAdmin bundle. On instruction conflict, this file takes precedence as the most specific layer. The worker loads all three files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## EasyAdmin: sensitive fields exposed without mask

**Recipe-driven recall.** All EasyAdmin CRUD controllers and their fields are collected by the recipe into `recon_bags.addon.easyadmin.crud_controllers.items[*].configure_fields`. Each field is `{name, field_type, modifiers}`. Walk this list, not via grep — this gives deterministic recall on large admin sections.

Finding trigger: `field.name` matches the sensitive pattern (`accessToken|refreshToken|secretKey|apiKey|botToken|clientSecret|password|privateKey|webhookSecret|pat|pwd`) **and** `field.modifiers` does NOT contain at least one of the defensive ones: `formatValue`, `onlyOnIndex`, `hideOnForm`, `hideOnIndex`. A plain `TextField` / `EmailField` / `TextareaField` without masking → finding.

- `CrudController::configureFields()` returns `TextField::new('accessToken'|'refreshToken'|'secretKey'|'apiKey'|'botToken'|'clientSecret'|'password')` without `formatValue(fn ($v) => substr((string)$v, 0, 4) . '***')` or `->onlyOnIndex()/->hideOnForm()/->hideOnIndex()` → admin sees plaintext in index/detail/edit
- Sink_kind: `sensitive_field_unmasked` (root_cause_family `disclosure`)
- Threat: compromise of an admin account = mass exfiltration of tokens via UI; browser history / screenshots in slack/jira / screen recordings become leakage vectors
- Fix: either `formatValue()` with masked rendering, or a dedicated `ROLE_TOKEN_VIEW` voter with an explicit "Reveal token" action and audit-log
- **Limitation:** if the controller has `unresolved_fields: true` (configureFields delegates to parent), the recipe does not see the final set → fall back to grepping the source and BaseCrudController.
