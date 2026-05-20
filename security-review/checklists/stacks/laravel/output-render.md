# Blade / Output rendering / SSTI (Laravel)

> This checklist complements `core/output-render.md` for laravel projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Unescaped output (`{!! !!}`, `@php`)

- `{!! $userInput !!}` — direct XSS (Blade `{{ }}` escapes, `{!! !!}` does NOT escape)
- `{!! Purifier::clean($userInput) !!}` — safe if HTMLPurifier is configured properly. Without a custom whitelist — dangerous
- `@php echo $userInput; @endphp` inside Blade — bypass of auto-escape
- `<script>var data = {!! json_encode($data) !!}</script>` — `</script>` in data breaks context. Use `@json($data)` (Laravel built-in safe encoder) or `Js::from($data)` (Laravel 9+)

## Dynamic component / view rendering

- `view($userInput)->render()` — client controls the template name → SSTI / disclosure
- `view()->exists($userInput)` then `view($userInput)` — the check does not block reading a foreign view
- `Blade::render($userInputTemplate, $data)` — direct Blade SSTI via `{{ system('id') }}` if filters are bypassed
- `@include($userInput)` / `@includeIf($userInput)` — dynamic include with user-controlled name
- `<x-{{ $name }}-card />` — attacker picks any component class

## Component / props injection

- Custom Blade component with `@props` without type validation: `<x-alert :message="$userInput" />` — if the component does `{!! $message !!}` → XSS
- `Component::class` with `public ?string $html = null` rendered in template via `{!! $html !!}` without a guard

## Mail / notification HTML

- `mail($view, $data)` with `{!! $userMessage !!}` in the template — XSS in mail + potential server-side template injection with a dynamic view
- `MailMessage::line($content)` escapes correctly, but `MailMessage::view($name, $data)` — dynamic view name
- Markdown mailables: `@component('mail::message')` with user-controlled markdown via `Markdown::parse($input)` → HTML injection if the parser does not sanitize

## Inertia / Vue / React SSR

- Inertia `Inertia::render('Page', ['raw_html' => $userHtml])` → client renders via `v-html` / `dangerouslySetInnerHTML` → XSS
- Server-side render via V8/Vapor with user-controlled data — RCE via JS sandbox escape if any
- Inertia shared data through `HandleInertiaRequests::share` — global leak of private fields into the SSR payload

## URL / redirect

- `<a href="{{ $url }}">` where `$url` is user-controlled — check against `javascript:`/`data:` URI is mandatory
- `redirect($request->input('url'))` — open redirect / URL takeover. Use `Redirect::route(...)` with a whitelist
- `URL::to($input)` without validation
- Form action with `{{ url($request->returnTo) }}` — phishing redirect

## Error rendering

- `app/Exceptions/Handler.php::render` returns a stacktrace on prod (`debug=false` is mandatory)
- Custom error views render `{{ $exception->getMessage() }}` where the message contains SQL/path
- `dd($var)` / `dump($var)` forgotten in code — leak of full state via die
- Telescope / Debugbar in production — exposure of SQL/queries/auth/sessions

## File upload preview

- User upload preview via `<img src="{{ asset($userPath) }}" />` without MIME-type check → SVG XSS
- `Storage::url($userPath)` without prefix check — attacker reads a private disk

## GraphQL output filtering (`nuwave/lighthouse`, `rebing/graphql-laravel`)

- **Lighthouse resolver returns Eloquent model directly** — without `protected $hidden = ['password', 'remember_token']` or Resource projection all fields are serialized into the GraphQL response: `field { user { password } }` is not filtered automatically. Cross-link → `secret_in_response` (see `disclosure.md`).
- **Rebing field type returning whole model** — `'resolve' => fn($root, $args) => User::find($args['id'])` without projected `select(['id','name'])` → JSON serialize emits all columns.
- **`@field(resolver: ...)` without `@select`/`@with`** — N+1 + leak of related fields (`profile.api_token`).
- **`@inject(context: "user")` for returning user object** — even if scoped by `auth()->user()`, JSON serialize may include sensitive fields.
- **GraphQL union/interface types** — resolver `__resolveType` returns class name; if the class contains an attacker-injected type (via `MorphMap`) → instance with extra fields.
- **Introspection enabled on prod** — `lighthouse.security.disable_introspection=false` → `__schema` query reveals the schema (including internal/admin types) → attacker maps the attack surface.

## Octane Inertia / global share singleton bleed (gate: `framework_specific.laravel.runtime.octane=true`)

> **Apply only if** `framework_specific.laravel.runtime.octane == true`. Otherwise skip the entire section (graceful fallback).

- **`Inertia::share('user', auth()->user())`** in ServiceProvider `boot()` — eager-resolved value is cached in singleton → the old user remains on the next request → cross-tenant leak in SSR payload.
- **Correct**: `Inertia::share('user', fn() => auth()->user())` — closure is recomputed per-request.
- **`Inertia::share('flash', session('flash'))`** — eager → breaks on Octane. Correct: `Inertia::share('flash', fn() => session('flash'))`.
- **`HandleInertiaRequests::share()`** returning values computed in the constructor — same risks (constructor is called once when the middleware instance is created).
- **`View::share('currentUser', auth()->user())`** in ServiceProvider boot — global shared variable for all Blade views, eager-resolved → leak between requests.
- **`Blade::directive('xxx', $closure)`** with `use ($user)` capture — closure is instantiated once → captured user persists.
