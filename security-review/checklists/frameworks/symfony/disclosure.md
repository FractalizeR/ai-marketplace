# Information disclosure (Symfony)

> This checklist complements `core/disclosure.md` for symfony projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Symfony WDT / Profiler / Debug

- Symfony in production with `APP_DEBUG=1` → full Web Debug Toolbar and Profiler are accessible (routes `/_profiler`, `/_wdt/*`)
- `framework.web_link.enabled: true` on prod
- `render()` with `_debug_bar` / WebProfilerBundle included in the production composer install

## API response leaks (Symfony Serializer)

- Serializer without a `#[Groups(['public'])]` filter → the entire entity with internal fields (`hashedPassword`, `roles`, internal IDs) is emitted via `$serializer->serialize($entity, 'json')`

## EasyAdmin / Sonata: sensitive fields exposed without mask

**Recipe-driven recall (v3.2+).** All EasyAdmin CRUD controllers and their fields are collected by the recipe into `framework_specific.symfony.easyadmin_crud_controllers.items[*].configure_fields`. Each field is `{name, field_type, modifiers}`. Sonata analogue — `framework_specific.symfony.sonata_admin_classes.items[*].form_fields` (an array of field names; Sonata modifiers are not tracked by the recipe — fall back to grepping the body of `configureFormFields()` to verify masking). Walk these lists, not via grep — this gives deterministic recall on large admin sections.

Finding trigger (EasyAdmin): `field.name` matches the sensitive pattern (`accessToken|refreshToken|secretKey|apiKey|botToken|clientSecret|password|privateKey|webhookSecret|pat|pwd`) **and** `field.modifiers` does NOT contain at least one of the defensive ones: `formatValue`, `onlyOnIndex`, `hideOnForm`, `hideOnIndex`. A plain `TextField` / `EmailField` / `TextareaField` without masking → finding.

Finding trigger (Sonata): field name in `form_fields[]` matches the same sensitive pattern → grep the body of `configureFormFields()` to verify `->setDisabled(true)` / removal from the form / masking on render — without these — finding.

- `CrudController::configureFields()` returns `TextField::new('accessToken'|'refreshToken'|'secretKey'|'apiKey'|'botToken'|'clientSecret'|'password')` without `formatValue(fn ($v) => substr((string)$v, 0, 4) . '***')` or `->onlyOnIndex()/->hideOnForm()/->hideOnIndex()` → admin sees plaintext in index/detail/edit
- Sink_kind: `sensitive_field_unmasked` (root_cause_family `disclosure`)
- Threat: compromise of an admin account = mass exfiltration of tokens via UI; browser history / screenshots in slack/jira / screen recordings become leakage vectors
- Fix: either `formatValue()` with masked rendering, or a dedicated `ROLE_TOKEN_VIEW` voter with an explicit "Reveal token" action and audit-log
- **Limitation:** if the controller has `unresolved_fields: true` (configureFields/configureFormFields delegates to parent), the recipe does not see the final set → fall back to grepping the source and BaseCrudController.
