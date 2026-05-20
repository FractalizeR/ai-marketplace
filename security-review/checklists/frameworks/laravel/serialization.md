# Serialization / deserialization (Laravel)

> Этот чек-лист дополняет `core/serialization.md` для проектов на laravel. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Encrypted cookies / Crypt facade

- `Crypt::decryptString($cookie)` на user-controlled cookie без `decrypt(serialize: true/false)` явно — Laravel по умолчанию `decrypt($value, $unserialize = true)` → попытка PHP unserialize на decrypted payload может привести к RCE если ключ известен/слаб
- `Cookie::get('name')` где cookie исходно сериализован Laravel'ом — компрометация ключа = RCE через unserialize gadgets
- Custom cipher через `Encrypter::class` без AEAD (`AES-256-CBC` без HMAC-проверки) — padding oracle

## Queue serializers

- `config/queue.php`: использование PHP serialization (default) на не-Redis transports — payload сериализован/десериализован между сервисами; если очередь shared (e.g. SQS) — атакующий с доступом к очереди может подсунуть gadget
- Custom job serializer через `IlluminateQueueSerializesModels` trait — корректно для Eloquent моделей, но кастомные value objects могут полагаться на `__wakeup`
- `Queue::push(new Job(...))` где Job хранит `Closure` (Closures сериализуются через `Opis\Closure` или `Laravel\SerializableClosure`) — закрытие может содержать privileged код, выполняющийся в worker'е без re-authz

## Eloquent custom casts (`AsCustomCast`)

- Custom cast класс `extends CastsAttributes` с `set/get`, выполняющим `unserialize()` на user-controlled значениях БД (если БД скомпрометирована) — propagation от SQL injection к RCE
- `protected $casts = ['payload' => 'array']` где `payload` исходно сохранялся через `serialize()` (например, legacy import) — getter делает `unserialize` неявно

## API JSON deserialization

- `json_decode($request->getContent(), true)` без size limit / depth limit — DoS через глубоко вложенный JSON
- `Http::asJson()->post($url, $userData)` где `$userData` затем десериализуется чужим API — pivot
- API resource fromArray($json) с типами: `Money::fromArray($req->money)` без валидации структуры — TypeError или Object Injection-like

## XML / SOAP

- `simplexml_load_string($xml)` / `LIBXML_NOENT` без явного отключения внешних entities → XXE → SSRF / file read
- SOAP: `SoapClient($wsdl, ['cache_wsdl' => 0])` где `$wsdl` user-controlled — SSRF
- `DOMDocument::loadXML` без `LIBXML_NONET` → XXE с network fetching

## File-based session driver

- `config/session.php`: `driver: 'file'` на shared host без proper directory permissions — session hijack через FS race
- `config/session.php`: encrypt=false на cookie sessions — session id предсказуем + читается без ключа
