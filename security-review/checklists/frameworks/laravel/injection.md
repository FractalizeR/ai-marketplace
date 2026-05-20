# Injection (Laravel) — Form requests, Validator, Queue trust

> Этот чек-лист дополняет `core/injection.md` для проектов на laravel. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Form Request mass-assignment

- `class FooRequest extends FormRequest`: `rules()` валидирует только нужные поля, но контроллер вызывает `$model->update($request->all())` (а не `$request->validated()`) → mass assignment проходит мимо
- `authorize()` возвращает `true` всегда — без проверки tenant/role/ownership
- `validated()` без явного whitelist через `$this->only([...])` — все валидные поля идут в Eloquent независимо от `$fillable` если `$guarded = []`
- `Request::merge([...])` в middleware/controller добавляет admin-флаг до validation → проходит rules

## Validator API мисюз

- `Validator::make($data, $rules)->validated()` без `failsOnFirst` или с suppressed exceptions → невалидные данные доходят до DB
- Custom rules через closures: `'role' => fn($attr, $value, $fail) => true` — пропускает любое значение
- `'array'` rule без вложенных правил `'array.*' => 'string'` — позволяет вложенный mass assignment
- `'sometimes'` rule на критичных полях (`role`, `is_admin`) — клиент может опустить или прислать
- `bail` rule забыт на критичных полях → multiple errors но первая ошибка обходится через bypass

## Inertia / livewire / API request injection

- Inertia: `Inertia::render('Page', ['data' => $request->all()])` — серверное состояние из request body
- Livewire: `public $editable = true;` без `#[Locked]` или без re-validation в `updated*` hook → клиент модифицирует свойство
- Livewire `wire:model.lazy` на admin-полях без re-authz при `updated*`
- API resource принимает `$request->json()->all()` без FormRequest и без validation → бесконтрольный mass assignment

## Queue job trust

- Job constructor принимает `$userId` / `$tenantId` / `$amount` от вызывающего без cryptographic binding → job-payload подменим в Redis-транспорте
- `dispatch(new Job($request->id))` где `$request->id` — id чужого ресурса, и handler не проверяет владельца → cross-tenant write через очередь
- `ShouldQueue` job, который потом dispatches другие jobs (`Bus::chain([...])`) без re-authz внутри chain — privilege drift
- Job `failed()` callback пишет user input в log — log injection / disclosure
- Custom serializer на queue (e.g. PHP serialize) — см. `serialization.md`

## Console commands

- Artisan command: `Artisan::call('db:seed', ['--class' => $userInput])` — выполняет произвольный seeder класс
- `system($input)` / `exec($input)` / `shell_exec($input)` в command handler
- `$this->call($subCommand, $request->input())` — клиент управляет аргументами CLI

## Mail / notification template injection

- `Mail::to($user)->send(new ApiUpdateMail($name))` где `$name` рендерится в Blade-mail template без `{{ }}` (escape) → HTML/email injection
- Notification с `$this->line($userInput)` — auto-escape работает, но `$this->line(new HtmlString($userInput))` ломает
- Mailable с `view($userInput, $data)` — динамическое имя view → доступ к чужим templates / рендеринг неожиданных данных
