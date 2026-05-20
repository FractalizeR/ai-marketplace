# Laravel stack — detection

This file describes how `recipes/laravel` detects a Laravel project and activates checklists from `frameworks/laravel/`. It is not a checklist itself — there are no vulnerability items.

## Laravel project signals (by `composer.json` and file structure)

`bin/recon/recipes/laravel.py::detect()` marks the project as Laravel on a combination of signals: `composer.json` contains `laravel/framework` in `require`/`require-dev`; `artisan` (CLI binary) is present at the project root; `config/app.php` exists; `app/Models/` exists. Each signal carries a weight; sum ≥ 0.7 → recipe selected. See `SIGNAL_WEIGHTS` in the source.

On a hit, the recon agent writes into `<review_root>/CONTEXT.md`:

```yaml
stack:
  framework: laravel
  framework_version: <constraint from composer.json require.laravel/framework>
  detected_via: composer.json+artisan+config+app/Models
```

`plan_waves.resolve_checklists(themes, stack="laravel", plugin_root)` then adds to each theme the file `frameworks/laravel/{theme}.md`, if it exists.

## What lands in the `framework_specific.laravel` bag

The recipe fills in (or marks `status: unknown` with reason) the keys:

- `policies` — classes from `app/Policies/*` (class name, file, conventional pairing with the model);
- `service_providers` — classes from `app/Providers/*` (including RouteServiceProvider, AppServiceProvider, custom providers);
- `middleware_groups` — contents of `app/Http/Kernel.php`: `$middleware` (global), `$middlewareGroups` (web/api), `$middlewareAliases`/`$routeMiddleware` (route-level aliases);
- `form_requests` — classes from `app/Http/Requests/*` extending `Illuminate\Foundation\Http\FormRequest`;
- `graphql_layer` — present-if-detected: scalar `{library_name, schema_files, resolvers_dir}` for `nuwave/lighthouse`, `rebing/graphql-laravel`, `api-platform/core`, `webonyx/graphql-php`. See `bin/recon/graphql_detect.py`.

See `bin/recon/recipes/laravel.py::FRAMEWORK_SPECIFIC_SCHEMA` for the exact shape.

## Known detection limitations

- **Laravel 11+** moved middleware from `app/Http/Kernel.php` into `bootstrap/app.php` (closure-based). Recipe MVP does not parse bootstrap style — `middleware_groups` will be `status: none`. Worker must read `bootstrap/app.php` directly.
- **Lumen** is not supported — different structure; detect will not fire.
- **Service-locator container bindings** (`$this->app->bind(...)`, deferred providers) are parsed only partially (provider class name, not its register/boot body).

## What "framework: none/unknown" means

`none` — generic PHP project without a framework. `frameworks/laravel/*.md` are not loaded. Worker operates only with core checklists.

`unknown` — detect did not fire (possibly non-standard installation). The recon agent writes `recon_confidence: low`, plan_waves does not activate framework sections.
