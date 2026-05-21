# Information disclosure (Symfony)

> This checklist complements `core/disclosure.md` for symfony projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Symfony WDT / Profiler / Debug

- Symfony in production with `APP_DEBUG=1` → full Web Debug Toolbar and Profiler are accessible (routes `/_profiler`, `/_wdt/*`)
- `framework.web_link.enabled: true` on prod
- `render()` with `_debug_bar` / WebProfilerBundle included in the production composer install

## API response leaks (Symfony Serializer)

- Serializer without a `#[Groups(['public'])]` filter → the entire entity with internal fields (`hashedPassword`, `roles`, internal IDs) is emitted via `$serializer->serialize($entity, 'json')`

## Admin bundle sensitive fields exposed without mask

> EasyAdmin/Sonata-specific patterns: see `addons/easyadmin/disclosure.md` and `addons/sonata/disclosure.md` (auto-loaded when the addon is detected).
