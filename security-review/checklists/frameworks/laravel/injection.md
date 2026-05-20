# Injection (Laravel) — Form requests, Validator, Queue trust

> This checklist complements `core/injection.md` for laravel projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Form Request mass-assignment

- `class FooRequest extends FormRequest`: `rules()` validates only the needed fields, but the controller calls `$model->update($request->all())` (rather than `$request->validated()`) → mass assignment slips past
- `authorize()` always returns `true` — without tenant/role/ownership check
- `validated()` without an explicit whitelist via `$this->only([...])` — all valid fields go to Eloquent regardless of `$fillable` if `$guarded = []`
- `Request::merge([...])` in middleware/controller adds an admin flag before validation → passes rules

## Validator API misuse

- `Validator::make($data, $rules)->validated()` without `failsOnFirst` or with suppressed exceptions → invalid data reaches DB
- Custom rules via closures: `'role' => fn($attr, $value, $fail) => true` — lets through any value
- `'array'` rule without nested rules `'array.*' => 'string'` — allows nested mass assignment
- `'sometimes'` rule on critical fields (`role`, `is_admin`) — client may omit or send
- `bail` rule forgotten on critical fields → validation continues past the first failure, and the original error can be masked if later rules pass

## Inertia / livewire / API request injection

- Inertia: `Inertia::render('Page', ['data' => $request->all()])` — server state from request body
- Livewire: `public $editable = true;` without `#[Locked]` or without re-validation in `updated*` hook → client modifies the property
- Livewire `wire:model.lazy` on admin fields without re-authz on `updated*`
- API resource accepts `$request->json()->all()` without FormRequest and without validation → uncontrolled mass assignment

## Queue job trust

- Job constructor accepts `$userId` / `$tenantId` / `$amount` from the caller without cryptographic binding → job payload is substitutable in Redis transport
- `dispatch(new Job($request->id))` where `$request->id` is the id of a foreign resource, and the handler does not check the owner → cross-tenant write via queue
- `ShouldQueue` job that then dispatches other jobs (`Bus::chain([...])`) without re-authz inside the chain — privilege drift
- Job `failed()` callback writes user input into log — log injection / disclosure
- Custom serializer on queue (e.g., PHP serialize) — see `serialization.md`

## Console commands

- Artisan command: `Artisan::call('db:seed', ['--class' => $userInput])` — executes an arbitrary seeder class
- `system($input)` / `exec($input)` / `shell_exec($input)` in command handler
- `$this->call($subCommand, $request->input())` — client controls CLI arguments

## Mail / notification template injection

- `Mail::to($user)->send(new ApiUpdateMail($name))` where `$name` is rendered in a Blade-mail template without `{{ }}` (escape) → HTML/email injection
- Notification with `$this->line($userInput)` — auto-escape works, but `$this->line(new HtmlString($userInput))` breaks it
- Mailable with `view($userInput, $data)` — dynamic view name → access to foreign templates / rendering of unexpected data
