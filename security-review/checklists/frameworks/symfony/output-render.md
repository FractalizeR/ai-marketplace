# Twig / Output rendering / SSTI (Symfony)

> This checklist complements `core/output-render.md` for symfony projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## `|raw` filter

- `{{ user_input|raw }}` — direct XSS
- `{{ content|striptags|raw }}` — `striptags` does not protect against all vectors (`javascript:` URIs, CSS expressions)
- User-controlled HTML passed through HTMLPurifier — safe, but only if Purifier is configured properly; without a white-list — dangerous

## Autoescape

- `{% autoescape false %}` block with user input inside
- `config/packages/twig.yaml` with `autoescape: false` globally
- Custom extensions returning `Twig\Markup` over user input — equivalent to `|raw`

## JavaScript context

- `<script>var data = {{ user_data|json_encode }};</script>` — **not safe**: `</script>` in data breaks context. Use `|json_encode` with the `JSON_HEX_TAG` flag, or `|e('js')`
- User input in `onclick="..."` without `|e('html_attr')`
- User input inside `<a href="{{ url }}">` — checking against `javascript:` / `data:` URIs is mandatory

## SSTI via dynamic template

- `$twig->createTemplate($userInput)->render([...])` — direct SSTI, RCE via `{{ ['id']|map('system') }}`
- `$this->render($request->get('tpl') . '.html.twig')` — reachability of foreign templates
- `{% include template_from_string(user_input) %}`
- `{{ include(user_input) }}`
- Mailer: `$email->htmlTemplate($userControlledName)` without a whitelist — dynamic Twig template name

## Mailer (Symfony Mailer)

- `TemplatedEmail::htmlTemplate($name)` with user-controlled `$name`
- `TemplatedEmail::textTemplate($name)` with user-controlled `$name`
- Passing user data into context without sanitization, then `|raw` in the email template
- User-controlled subject rendered through Twig without escape

## Notifier (Symfony Notifier)

- `Notification::content($userInput)` — if content is rendered through Twig in some channel
- Chat/SMS templates with `|raw` user input
- `EmailMessage::fromNotification()` with user-controlled context

## Error rendering

- Custom `ErrorRenderer` rendering stacktrace / exception message into HTML without escape
- `KernelEvents::EXCEPTION` listener returning a Response with user input in the body
- Default Symfony error page in production mode (must be disabled via `framework.web_link.enabled: false` and `debug: false`)

## XSS via non-obvious channels

- User data in `<title>{{ user_title }}</title>` — Twig escapes by default, but if `|raw` — XSS
- `<meta name="description" content="{{ user_desc }}">` — `|e('html_attr')` is mandatory for attributes
- RSS/Atom feeds with user content without `|e` or CDATA
- PDF/Document generators accepting user HTML (Dompdf, TCPDF) — custom HTML sanitization is required

## GraphQL output filtering (api-platform / overblog/graphql-bundle / webonyx)

GraphQL is an alternative output channel; the same disclosure / secret leakage rules as for REST/Twig. Field-level authz (who sees) — in `auth.md`; here — what ends up in the response payload.

- **api-platform Resource without `#[Groups]`** — all public-getter Entity fields are serialized for every operation: `accessToken`, `refreshToken`, `passwordHash`, `mfaSecret`, `apiToken`, `webhookSecret` leak to the client if they exist as Entity property/getter. Must be `#[Groups(['user:read'])]` on safe fields + `normalizationContext: ['groups' => ['user:read']]` on the operation. Sink_kind: `secret_in_response` or `sensitive_field_unmasked` (root_cause_family: `disclosure`).
- **overblog/graphql-bundle resolver returns `$entity` directly**: `'resolve' => fn($value, $args) => $em->getRepository(User::class)->find($args['id'])` without projection / without mapping into a DTO → schema-declared fields are serialized, but any `Computed`/`@Expose` extras may also leak. Grep for a resolver that returns a Doctrine entity without `->toArray()` / `->toPublicView()`.
- **webonyx native field resolver** does not call `->getPublicView()` / `->toArray()` filter and returns `$entity` or `$entity->getRecord()` entirely → the client via alias/fragment can select any field declared in the schema, including sensitive ones. If a secret field was accidentally declared in the schema — it is accessible.
- **`Type::nonNull($userType)` + field `passwordHash` in `$userType`**: even if field-level authz exists, the very presence of the field in the schema is information disclosure via introspection. Remove sensitive fields from the schema, do not rely solely on access control.
- **Error messages in response**: Doctrine exception (`UniqueConstraintViolationException`, `ForeignKeyConstraintViolationException`) propagates to the GraphQL response without handling → client sees table structure / column names. Sink_kind: `stacktrace_exposed`. In prod an ErrorHandler / formatter masking internal errors is required.

**Cross-link**: `secret_in_response` for polluted output — see `core/crypto.md`. `sensitive_field_unmasked` — see `core/disclosure.md`.
