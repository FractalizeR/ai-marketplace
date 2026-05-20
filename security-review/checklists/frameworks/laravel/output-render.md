# Blade / Output rendering / SSTI (Laravel)

> Этот чек-лист дополняет `core/output-render.md` для проектов на laravel. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Unescaped output (`{!! !!}`, `@php`)

- `{!! $userInput !!}` — прямой XSS (Blade `{{ }}` escapes, `{!! !!}` НЕ escapes)
- `{!! Purifier::clean($userInput) !!}` — безопасно если HTMLPurifier настроен правильно. Без custom whitelist — опасно
- `@php echo $userInput; @endphp` внутри Blade — байпас auto-escape
- `<script>var data = {!! json_encode($data) !!}</script>` — `</script>` в данных ломает context. Используй `@json($data)` (Laravel built-in safe encoder) или `Js::from($data)` (Laravel 9+)

## Dynamic component / view rendering

- `view($userInput)->render()` — клиент управляет именем шаблона → SSTI / disclosure
- `view()->exists($userInput)` затем `view($userInput)` — проверка не блокирует чтение чужого view
- `Blade::render($userInputTemplate, $data)` — прямой Blade SSTI через `{{ system('id') }}` если фильтры обходятся
- `@include($userInput)` / `@includeIf($userInput)` — динамический include с user-controlled name
- `<x-{{ $name }}-card />` — атакер выбирает любой component class

## Component / props injection

- Custom Blade component с `@props` без type validation: `<x-alert :message="$userInput" />` — если component делает `{!! $message !!}` → XSS
- `Component::class` с `public ?string $html = null` рендерится в template через `{!! $html !!}` без guard

## Mail / notification HTML

- `mail($view, $data)` с `{!! $userMessage !!}` в шаблоне — XSS в почте + потенциальный server-side template injection при динамическом view
- `MailMessage::line($content)` корректно escape-ит, но `MailMessage::view($name, $data)` — динамический view name
- Markdown mailables: `@component('mail::message')` с user-controlled markdown через `Markdown::parse($input)` → HTML injection если parser не sanitize

## Inertia / Vue / React SSR

- Inertia `Inertia::render('Page', ['raw_html' => $userHtml])` → клиент отрисовывает через `v-html` / `dangerouslySetInnerHTML` → XSS
- Server-side render через V8/Vapor с user-controlled data — RCE через JS sandbox escape если есть
- Inertia shared data через `HandleInertiaRequests::share` — глобальная утечка приватных полей в SSR payload

## URL / redirect

- `<a href="{{ $url }}">` где `$url` — user-controlled — проверка на `javascript:`/`data:` URI обязательна
- `redirect($request->input('url'))` — open redirect / URL takeover. Используй `Redirect::route(...)` с whitelist
- `URL::to($input)` без валидации
- Form action с `{{ url($request->returnTo) }}` — phishing redirect

## Error rendering

- `app/Exceptions/Handler.php::render` отдаёт stacktrace на prod (`debug=false` обязателен)
- Custom error views рендерят `{{ $exception->getMessage() }}` где message содержит SQL/path
- `dd($var)` / `dump($var)` забытый в коде — leak полного состояния через die
- Telescope / Debugbar в production — раскрытие SQL/queries/auth/sessions

## File upload preview

- User upload preview через `<img src="{{ asset($userPath) }}" />` без MIME-type check → SVG XSS
- `Storage::url($userPath)` без проверки prefix — атакующий читает приватный диск

## GraphQL output filtering (`nuwave/lighthouse`, `rebing/graphql-laravel`)

- **Lighthouse resolver возвращает Eloquent model directly** — без `protected $hidden = ['password', 'remember_token']` или Resource projection все поля сериализуются в GraphQL response: `field { user { password } }` не отфильтруется автоматически. Cross-link → `secret_in_response` (см. `disclosure.md`).
- **Rebing field type returning whole model** — `'resolve' => fn($root, $args) => User::find($args['id'])` без projected `select(['id','name'])` → JSON serialize отдаёт все колонки.
- **`@field(resolver: ...)` без `@select`/`@with`** — N+1 + leak связанных полей (`profile.api_token`).
- **`@inject(context: "user")` для возврата user object** — даже если scoped по `auth()->user()`, JSON serialize может включать sensitive поля.
- **GraphQL union/interface types** — резолвер `__resolveType` возвращает class name; если class содержит attacker-injected type (через `MorphMap`) → instance с extra fields.
- **Introspection enabled на prod** — `lighthouse.security.disable_introspection=false` → `__schema` query раскрывает schema (включая internal/admin types) → атакующий маппит attack surface.

## Octane Inertia / global share singleton bleed (gate: `framework_specific.laravel.runtime.octane=true`)

> **Применяй только если** `framework_specific.laravel.runtime.octane == true`. Иначе — пропусти всю секцию (graceful fallback).

- **`Inertia::share('user', auth()->user())`** в ServiceProvider `boot()` — eager-resolved value кэшируется в singleton → старый user остаётся на следующем запросе → cross-tenant leak в SSR payload.
- **Правильно**: `Inertia::share('user', fn() => auth()->user())` — closure пересчитывается per-request.
- **`Inertia::share('flash', session('flash'))`** — eager → ломается на Octane. Правильно: `Inertia::share('flash', fn() => session('flash'))`.
- **`HandleInertiaRequests::share()`** возвращающий значения, вычисленные в constructor — те же риски (constructor вызывается один раз при создании middleware instance).
- **`View::share('currentUser', auth()->user())`** в ServiceProvider boot — глобальная shared переменная для всех Blade views, eager-resolved → leak между запросами.
- **`Blade::directive('xxx', $closure)`** с `use ($user)` capture — closure инстанцируется один раз → captured user persists.
