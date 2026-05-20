# Injection (generic) — command, code, XXE, path traversal

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `command_exec` — `exec`/`shell_exec`/`Process` with user input
- `file_include_dynamic` — `include`/`require` with a dynamic path
- `path_traversal` — file operations with an unchecked user path
- `ssti` — Server-Side Template Injection (dynamic template name / source)
- `xxe` — XML External Entity
- `mass_assignment` — unrestricted unfolding of data into objects (see also `data-access.md`)

## Confidence floor rules

- **`exec()`/`shell_exec()`/`system()` with user input** (path traced from `$request` / `$_GET` / `$_POST` to the sink) → **confidence ≥ 9** for command_exec.
- **`eval()` with user-controlled data** → **confidence ≥ 10** for ssti/command_exec.
- **`include(<dynamic>)` / `require(<dynamic>)`** with part of the path from user input without a whitelist → **confidence ≥ 9** for file_include_dynamic.
- **`unserialize($userData)`** without `['allowed_classes' => false]` → **confidence ≥ 9** for unserialize_untrusted.

## Command injection

- `exec()`, `shell_exec()`, `system()`, `passthru()`, `popen()`, `` ` ` `` (backticks) with user input without `escapeshellarg`/`escapeshellcmd`
- Process abstraction with shell-string mode (e.g. `Process::fromShellCommandline($str)`) with user input — dangerous. The array-arguments version is safe
- `proc_open()` with a user-controlled cmd
- Parameters that reach the shell via environment variables if the application uses them in shell-exec

## Code injection / dynamic execution

- `eval()` with user input — RCE
- `assert($user_string)` — legacy RCE (in older PHP versions)
- `create_function()` (removed in 8.0, but legacy)
- `preg_replace()` with the `/e` modifier — RCE (up to 7.0)
- Dynamic execution:
  - `$$variable` — variable variables with user-controlled name
  - `$object->$method()` — dynamic method call
  - `call_user_func($fn, ...)`, `call_user_func_array($fn, ...)` with user-controlled `$fn`
  - `ReflectionClass::newInstanceArgs()` with user input

## File include / path traversal

- `include($_GET['page'] . '.php')`, `require($path)` with a user-controlled path — LFI/RFI
- `file_get_contents()`, `fopen()`, `readfile()` with a user-controlled path without `realpath()` and a whitelist
- `basename()` is insufficient: it does not protect against `../../../etc/passwd` (basename returns only the last segment)
- Bypassing `open_basedir` via symbolic links and URL wrappers (`php://`, `phar://`)
- Sanitization only against `..` without accounting for absolute paths (`/etc/passwd`), URL wrappers

## SSTI (Server-Side Template Injection) — see also

Anti-patterns for template engines live in `output-render.md` (core) and framework checklists. Only the sink_kind enum is here.

## XXE

- `simplexml_load_string($data)` without `LIBXML_NOENT = false` and without `libxml_disable_entity_loader(true)`
- `DOMDocument::loadXML()` without `LIBXML_NONET` / `LIBXML_NOENT = false`
- `XMLReader::xml()` with user input when external entities are not disabled
- SOAP client with user-controlled WSDL
- SAML responses, XML-RPC without protection against entity expansion

## LDAP / XPath / NoSQL

- LDAP injection: `(&(uid=$user))` with user input without escape (`ldap_escape`)
- XPath injection: `$xml->xpath("//user[name='$name']")` without escape
- NoSQL injection (MongoDB, if used): operator injection via JSON input (`{"$ne": null}` in the password field)

## PHP Object Injection

- `unserialize($_GET['data'])` with user-controlled input — RCE via magic methods `__wakeup()`, `__destruct()`, `__toString()`
- Storing cookies as serialized data and deserializing without `allowed_classes`
- See also `serialization.md`
