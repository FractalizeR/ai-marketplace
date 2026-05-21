# Information disclosure (Symfony + Sonata AdminBundle)

> This checklist extends `core/disclosure.md` and `stacks/symfony/disclosure.md` for projects using the Sonata bundle. On instruction conflict, this file takes precedence as the most specific layer. The worker loads all three files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Sonata: sensitive fields exposed without mask

**Recipe-driven recall.** Sonata admin classes and their fields are collected by the recipe into `recon_bags.addon.sonata.admin_classes.items[*].form_fields` — an array of field names from `$form->add('name', ...)`. Sonata modifiers are not tracked by the recipe — fall back to grepping the body of `configureFormFields()` to verify masking. Walk this list to seed candidates; verify each candidate by reading the configureFormFields() body.

Finding trigger: field name in `form_fields[]` matches the sensitive pattern (`accessToken|refreshToken|secretKey|apiKey|botToken|clientSecret|password|privateKey|webhookSecret|pat|pwd`) → grep the body of `configureFormFields()` to verify `->setDisabled(true)` / removal from the form / masking on render — without these — finding.

- Sink_kind: `sensitive_field_unmasked` (root_cause_family `disclosure`)
- Threat: compromise of an admin account = mass exfiltration of tokens via UI; browser history / screenshots in slack/jira / screen recordings become leakage vectors
- Fix: either masking on render (custom template, `show` action override), or a dedicated `ROLE_TOKEN_VIEW` voter with an explicit "Reveal token" action and audit-log
- **Limitation:** if the admin class has `unresolved_fields: true` (configureFormFields delegates to parent), the recipe does not see the final set → fall back to grepping the source and the parent admin class.
