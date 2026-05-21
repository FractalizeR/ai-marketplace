# Injection (generic) — command, code, XXE, path traversal

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `command_exec` — `exec`/`shell_exec`/`Process` with user input
- `file_include_dynamic` — `include`/`require` with a dynamic path
- `path_traversal` — file operations with an unchecked user path
- `ssti` — Server-Side Template Injection (dynamic template name / source)
- `xxe` — XML External Entity
- `mass_assignment` — unrestricted unfolding of data into objects (see also `data-access.md`)
- `ldap_injection` — user input in LDAP filter / DN without `ldap_escape` and the appropriate flag
- `xpath_injection` — user input concatenated into an XPath expression (any XPath evaluator)
- `nosql_injection` — operator / `$where` / pipeline / DSL injection in NoSQL stores (Mongo, Couchbase, Redis EVAL, ElasticSearch)

## Confidence floor rules

- **`exec()`/`shell_exec()`/`system()` with user input** (path traced from `$request` / `$_GET` / `$_POST` to the sink) → **confidence ≥ 9** for command_exec.
- **`eval()` with user-controlled data** → **confidence ≥ 10** for ssti/command_exec.
- **`include(<dynamic>)` / `require(<dynamic>)`** with part of the path from user input without a whitelist → **confidence ≥ 9** for file_include_dynamic.
- **`unserialize($userData)`** without `['allowed_classes' => false]` → **confidence ≥ 9** for unserialize_untrusted.
- **LDAP filter with unescaped user input** routed into a sensitive bind / search (auth bind, group lookup, admin DN search) → **confidence ≥ 8** for `ldap_injection`. Missing `ldap_escape($value, "", LDAP_ESCAPE_FILTER)` for filter values, missing `LDAP_ESCAPE_DN` for DN components.
- **MongoDB query receiving an array directly from `$_GET` / `$_POST`** (PHP) or `request.GET` / `request.POST` (Python) → **confidence ≥ 8** for `nosql_injection`. PHP coerces `?password[$ne]=` to `['$ne' => '']`, bypassing equality conditions.

## Trusted patterns (do NOT flag)

- Doctrine `findOneBy(['email' => $email])`, `findBy(['user' => $user, 'status' => $status])` — Doctrine parameterizes scalar arguments via prepared statements. Flag only DQL string concatenation (`$em->createQuery("SELECT u FROM User u WHERE u.email = '$email'")`), `andWhere("col = '$val'")`, or `Native\Query::setSQL()` with concatenation. The criterion-array form is safe.
- Eloquent `User::where('email', $email)`, `Model::where(['col' => $val])` with scalar values — auto-parameterized. Flag only `whereRaw('email = "' . $email . '"')`, `selectRaw($userInput)`, `orderByRaw($userInput)`, `DB::raw($userInput)`, `DB::statement($userInput)` — i.e., the `Raw` family with user input.
- PDO with prepared statements and bound params: `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id])` — safe. Flag only when the SQL string itself is built by concatenation (`$pdo->prepare("... WHERE id = $id")`), regardless of subsequent `execute()` call shape.
- Symfony `QueryBuilder::setParameter('id', $id)` paired with `:id` placeholders — parameterized. Flag only `->where("u.id = $id")` direct concatenation.
- Mongo PHP driver `$collection->find(['email' => (string)$email])` with explicit `(string)` cast — the cast neutralizes the array-as-operator attack vector that the `nosql_injection` floor targets. Note: PHP emits `E_WARNING` on array→string cast and the query silently matches no documents. The safer recipe is explicit guard `if (!is_string($email)) { throw ...; }` or DTO-level type enforcement. The cast pattern is recognized as a **defense**, not a recommended **style**.

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

## LDAP injection

- LDAP filter built via string concatenation: `(&(uid=$user)(...))` — unescaped `$user`. Sink_kind: `ldap_injection`.
- `ldap_escape($x)` with no flag argument — escapes EVERY character to hex, which LDAP servers correctly resolve back to literals. Wasteful but **not** itself a vulnerability. The real bug is direct concatenation with NO `ldap_escape()` call, OR `ldap_escape($x, $ignore, LDAP_ESCAPE_DN)` used in a filter context (or vice versa).
- Distinguished Name (DN) injection — user input embedded in a DN without the `LDAP_ESCAPE_DN` flag; DN-component metacharacters (`,`, `=`, `+`, `<`, `>`, `;`) bypass scoping
- Attribute injection — user input chosen as the attribute *name* (vs value) without a whitelist; allows querying any attribute including operational ones (`userPassword`, `pwdReset`)
- Authentication bind with user-controlled DN/password without prior filter-only search → null-bind / anonymous-bind elevation

## XPath injection

- `xpath()` / `DOMXPath::query()` / `SimpleXMLElement->xpath()` with concatenated user input — XPath evaluation injection. Sink_kind: `xpath_injection`.
- Boolean-based blind XPath: response differs on truthy vs falsy injected predicate (`' or '1'='1`) → enumeration of node values
- **XPath 2.0 `doc()`** — Only engines that implement XPath 2.0 (SAXON, .NET via Saxon.NET, eXist-db). **Does NOT apply** to PHP `DOMXPath` / `SimpleXMLElement->xpath()` — both are XPath 1.0 and `doc()` is unavailable. The XPath-1.0 analogue is the XSLT `document()` function exposed by some XSLT 1.0 processors when an XSLT engine wraps the XPath evaluator.
- XPath result reflected verbatim into HTML/JSON without escape → secondary XSS

## NoSQL injection

- MongoDB operator injection: `db.users.find({user: $_GET['u']})` where `$_GET['u']` is an array → query operator (`$ne: null`, `$gt: ''`, `$regex: '.*'`) bypasses an equality condition. Sink_kind: `nosql_injection`.
- `$where` clause injection: `{$where: function() { return this.user == "$user" }}` with concatenated input → JavaScript injection inside the Mongo `$where` evaluator (RCE within the JS sandbox). Applies to deployments where server-side JS is enabled (`security.javascriptEnabled: true`); disabled by default since Mongo 4.4 and not present in many modern clusters.
- Aggregation pipeline injection — user-controlled `$lookup` / `$match` / `$graphLookup` stage allows reading other collections or constructing graph traversals against the schema
- Redis `EVAL` Lua script with concatenated input — script injection inside the Lua interpreter, can read/write any key visible to Redis
- Couchbase N1QL string concatenation (`SELECT * FROM bucket WHERE name = "' + name + '"`) — analogous to classic SQL injection but on JSON queries; bind parameters are the safe form
- ElasticSearch query DSL injection — user-controlled `_source` filter (exfiltrates excluded fields), or full request-body relay
- `script` field with a Painless script — DSL-level data exfiltration / side-channel computation / search-time DoS. RCE primitive only on legacy Groovy (deprecated, off by default since ES 5) or ES with a known scripting CVE.

## PHP Object Injection

- `unserialize($_GET['data'])` with user-controlled input — RCE via magic methods `__wakeup()`, `__destruct()`, `__toString()`
- Storing cookies as serialized data and deserializing without `allowed_classes`
- See also `serialization.md`
