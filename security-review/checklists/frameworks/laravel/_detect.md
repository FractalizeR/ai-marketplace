# Laravel stack — detection

Этот файл описывает, как `recipes/laravel` детектирует Laravel-проект и активирует чек-листы из `frameworks/laravel/`. Сам по себе чек-листом не является — пунктов с уязвимостями нет.

## Признаки Laravel-проекта (по `composer.json` и файловой структуре)

`bin/recon/recipes/laravel.py::detect()` отмечает проект как Laravel при сочетании сигналов: `composer.json` содержит `laravel/framework` в `require`/`require-dev`; в корне проекта присутствует `artisan` (CLI binary); `config/app.php` существует; `app/Models/` существует. Каждый сигнал даёт вес; сумма ≥ 0.7 → recipe выбран. См. `SIGNAL_WEIGHTS` в исходниках.

При срабатывании recon-агент пишет в `<review_root>/CONTEXT.md`:

```yaml
stack:
  framework: laravel
  framework_version: <constraint из composer.json require.laravel/framework>
  detected_via: composer.json+artisan+config+app/Models
```

`plan_waves.resolve_checklists(themes, stack="laravel", plugin_root)` тогда добавляет к каждой теме файл `frameworks/laravel/{theme}.md`, если он существует.

## Что попадает в `framework_specific.laravel` bag

Recipe заполняет (или помечает `status: unknown` с reason) ключи:

- `policies` — классы из `app/Policies/*` (имя класса, файл, конвенциальная связка с моделью);
- `service_providers` — классы из `app/Providers/*` (включая RouteServiceProvider, AppServiceProvider, custom-провайдеры);
- `middleware_groups` — содержимое `app/Http/Kernel.php`: `$middleware` (global), `$middlewareGroups` (web/api), `$middlewareAliases`/`$routeMiddleware` (route-level aliases);
- `form_requests` — классы из `app/Http/Requests/*` extending `Illuminate\Foundation\Http\FormRequest`;
- `graphql_layer` — present-if-detected: scalar `{library_name, schema_files, resolvers_dir}` для `nuwave/lighthouse`, `rebing/graphql-laravel`, `api-platform/core`, `webonyx/graphql-php`. См. `bin/recon/graphql_detect.py`.

См. `bin/recon/recipes/laravel.py::FRAMEWORK_SPECIFIC_SCHEMA` для точного shape.

## Известные ограничения детекции

- **Laravel 11+** перенесли middleware из `app/Http/Kernel.php` в `bootstrap/app.php` (closure-based). Recipe MVP не парсит bootstrap-стиль — `middleware_groups` будет `status: none`. Воркер должен прочитать `bootstrap/app.php` напрямую.
- **Lumen** не поддерживается — другая структура; detect не сработает.
- **Service-locator container bindings** (`$this->app->bind(...)`, deferred providers) парсятся только частично (имя класса провайдера, не его register/boot тело).

## Что значит «framework: none/unknown»

`none` — generic-PHP проект без фреймворка. `frameworks/laravel/*.md` не подгружаются. Worker работает только с core checklists.

`unknown` — detect не сработал (возможно, нестандартная установка). recon-агент пишет `recon_confidence: low`, plan_waves не активирует framework-секции.
