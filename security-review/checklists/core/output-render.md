# Output rendering / XSS / SSTI / template engine misuse (generic)

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `unsafe_html_render` — rendering HTML with unescaped input
- `template_raw` — use of `|raw` or equivalent (forced "no-escape" in a template engine)
- `ssti` — server-side template injection (dynamic template name / source)

## Generic XSS / template misuse

- Template disables the built-in escape for a specific output (any equivalent of `|raw` / `{!! ... !!}` / `safe`) and feeds it user input
- User input in `<script>var data = {{ x }};</script>` without context-aware encoding (`</script>` inside the string body breaks the context — a JS-context escape is required, not an html-escape)
- Custom helpers / extensions returning "safe-marked" strings over user input (any "this string is already safe, do not escape" mechanism), effectively = `|raw`
