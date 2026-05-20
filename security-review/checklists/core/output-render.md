# Output rendering / XSS / SSTI / template engine misuse (generic)

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Recommended sink_kinds

- `unsafe_html_render` — рендер HTML с непроэкранированным input
- `template_raw` — использование `|raw` или эквивалента (форсированный «no-escape» в template engine)
- `ssti` — server-side template injection (динамический template name / source)

## Generic XSS / template misuse

- Шаблон выключает встроенный escape для конкретного output (любой эквивалент `|raw` / `{!! ... !!}` / `safe`) и подаёт туда user input
- User input в `<script>var data = {{ x }};</script>` без context-aware encoding (`</script>` в теле строки ломает context — нужен JS-context escape, а не html-escape)
- Custom helpers / extensions, возвращающие "safe-marked" строки над user input (любой механизм «эта строка уже safe, не escape'ить»), фактически = `|raw`
