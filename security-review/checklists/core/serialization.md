# Deserialization / object injection (generic)

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `unserialize_untrusted` — `unserialize()` or an equivalent API on untrusted data
- `mass_assignment` — unrestricted denormalization into privileged objects
- `missing_authz` — async message handler without permission check

## PHP native unserialize

- `unserialize($_GET['data'])` / cookies / session from an untrusted source — RCE via magic `__wakeup`, `__destruct`, `__toString`, `__call`
- `unserialize($data)` without `['allowed_classes' => false]` — accepts any objects
- Gadget chains: PHAR files with metadata loaded via `file_exists($phar_path)` / `fopen('phar://...')`
- Deserialization from a cache layer (memcached, redis) without integrity control

## YAML / JSON / TOML

- `yaml_parse()` with user input without `YAML_PARSE_NO_CODE` → RCE
- YAML loader with custom tags enabled and user input (any parser that supports tag execution)
- `json_decode()` is safe, but subsequent denormalization of the result into an object without a field whitelist — mass assignment

## Cookies / sessions

- Custom session handler that stores objects via `serialize()` and reads via `unserialize()` — acceptable, but if the cookie is protected only by a signature without encryption and the key is compromised, object injection is possible
- `signed_cookie` / `encrypted_cookie` with weak keys (see `crypto.md`)

## Webhook payloads

- Webhook deserialize without signature verification — attacker sends any payload (see also `auth.md`)
- Idempotency: repeated deserialize of the same webhook → duplicate side-effects
