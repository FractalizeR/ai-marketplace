# Serialization / deserialization (Laravel)

> This checklist complements `core/serialization.md` for laravel projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Encrypted cookies / Crypt facade

- `Crypt::decryptString($cookie)` on a user-controlled cookie without `decrypt(serialize: true/false)` explicitly — Laravel by default `decrypt($value, $unserialize = true)` → an attempt at PHP unserialize on the decrypted payload may lead to RCE if the key is known/weak
- `Cookie::get('name')` where the cookie was originally serialized by Laravel — key compromise = RCE via unserialize gadgets
- Custom cipher via `Encrypter::class` without AEAD (`AES-256-CBC` without HMAC check) — padding oracle

## Queue serializers

- `config/queue.php`: use of PHP serialization (default) on non-Redis transports — payload is serialized/deserialized between services; if the queue is shared (e.g., SQS) — an attacker with queue access can inject a gadget
- Custom job serializer via the `IlluminateQueueSerializesModels` trait — correct for Eloquent models, but custom value objects may rely on `__wakeup`
- `Queue::push(new Job(...))` where the Job stores a `Closure` (Closures are serialized via `Opis\Closure` or `Laravel\SerializableClosure`) — the closure may contain privileged code executed in the worker without re-authz

## Eloquent custom casts (`AsCustomCast`)

- Custom cast class `extends CastsAttributes` with `set/get` performing `unserialize()` on user-controlled DB values (if DB is compromised) — propagation from SQL injection to RCE
- `protected $casts = ['payload' => 'array']` where `payload` was originally stored via `serialize()` (e.g., legacy import) — getter performs `unserialize` implicitly

## API JSON deserialization

- `json_decode($request->getContent(), true)` without size limit / depth limit — DoS via deeply nested JSON
- `Http::asJson()->post($url, $userData)` where `$userData` is then deserialized by a foreign API — pivot
- API resource fromArray($json) with types: `Money::fromArray($req->money)` without structure validation — TypeError or Object Injection-like

## XML / SOAP

- `simplexml_load_string($xml)` / `LIBXML_NOENT` without explicit disabling of external entities → XXE → SSRF / file read
- SOAP: `SoapClient($wsdl, ['cache_wsdl' => 0])` where `$wsdl` is user-controlled — SSRF
- `DOMDocument::loadXML` without `LIBXML_NONET` → XXE with network fetching

## File-based session driver

- `config/session.php`: `driver: 'file'` on a shared host without proper directory permissions — session hijack via FS race
- `config/session.php`: encrypt=false on cookie sessions — session id is predictable + readable without a key
