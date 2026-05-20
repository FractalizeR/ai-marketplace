# Frontend JavaScript (Ember / Vue / Stimulus / plain JS)

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Recommended sink_kinds

- `unsafe_html_render` — `innerHTML` / `v-html` / `{{{...}}}` с пользовательским вводом
- `cors_misconfig` — `Access-Control-Allow-Origin: *` с credentials
- `hardcoded_secret` — токены в localStorage / sessionStorage

## Общий JavaScript

- `innerHTML`, `outerHTML`, `insertAdjacentHTML` с user input — XSS
- `eval(str)`, `new Function(str)`, `setTimeout(str, ...)`, `setInterval(str, ...)` с user input — RCE в браузере
- `document.write()`, `document.writeln()` с user input
- Prototype pollution: `Object.assign(target, userInput)` где userInput содержит `__proto__`
- CORS misconfiguration: `Access-Control-Allow-Origin: *` одновременно с `Access-Control-Allow-Credentials: true`
- `postMessage`: обработчик без проверки `event.origin`
- WebSocket: подключение к user-controlled URL без whitelist
- JWT в `localStorage` вместо httpOnly cookie
- Credentials в query params (logs, referer leak)
- Client-side routing: чувствительные данные (токен, email) в URL/query без redacting

## Ember.js

- Handlebars: `{{{unescaped}}}` (triple-stash) с user input — XSS
- `htmlSafe()`, `Ember.String.htmlSafe()` с недоверенными данными
- DOM manipulation через `this.$()` с конкатенацией
- Computed properties: race conditions при async с критичными данными
- Ember Data: утечка чувствительных атрибутов в JSON API responses
- Небезопасная сериализация relationships
- Services: хранение токенов в localStorage
- Actions: обработка user input без валидации перед отправкой на backend

## Vue.js

- `v-html="userInput"` — прямой XSS
- `:is="userInput"` (dynamic components) с недоверенным вводом
- `v-bind:innerHTML`, `domProps.innerHTML`
- Небезопасное биндинг в `href`, `src`: проверка на `javascript:` и `data:` URIs обязательна
- Vuex: хранение токенов/паролей в state (утечка через Vue DevTools в prod)
- `mounted()`, `created()` с user-controlled операциями без валидации

## Stimulus / asset pipelines

- Stimulus controllers, принимающие data attributes без валидации → DOM XSS если попадают в `innerHTML`
- `importmap.php`: import URL с user-controlled fragments
- Webpack entries с user-controlled параметрами в build config (редко, но возможно в dev-server)
- `HtmlWebpackPlugin` templates с небезопасной inject логикой

## API / AJAX calls

- Отсутствие CSRF токенов при мутирующих операциях через cookie auth
- Credentials (токены, API ключи) в query parameters
- User-controlled URL в `fetch()` / `XMLHttpRequest` без валидации (SSRF, открытый редирект во внешние URL)
- Отсутствие проверки `Content-Type` ответа перед разбором как JSON (MIME sniffing attacks)

## LocalStorage / SessionStorage

- Хранение паролей, JWT, secrets в plaintext
- Хранение user email/PII с XSS-риском (любой XSS → exfiltration)
- `localStorage.setItem('token', ...)` — токен доступен любому JS на странице
