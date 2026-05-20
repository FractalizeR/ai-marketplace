# Information disclosure (Symfony)

> Этот чек-лист дополняет `core/disclosure.md` для проектов на symfony. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Symfony WDT / Profiler / Debug

- Symfony в production с `APP_DEBUG=1` → полный Web Debug Toolbar и Profiler доступны (route `/_profiler`, `/_wdt/*`)
- `framework.web_link.enabled: true` на prod
- `render()` с `_debug_bar` / WebProfilerBundle включён в production composer install

## API response leaks (Symfony Serializer)

- Serializer без `#[Groups(['public'])]` фильтра → весь entity с internal полями (`hashedPassword`, `roles`, internal IDs) отдаётся через `$serializer->serialize($entity, 'json')`

## EasyAdmin / Sonata: sensitive fields exposed без mask

**Recipe-driven recall (v3.2+).** Все EasyAdmin CRUD-контроллеры и их поля собраны recipe'ом в `framework_specific.symfony.easyadmin_crud_controllers.items[*].configure_fields`. Каждое поле — `{name, field_type, modifiers}`. Sonata-аналог — `framework_specific.symfony.sonata_admin_classes.items[*].form_fields` (массив имён полей; modifier'ы у Sonata не отслеживаются recipe'ом — fall back на grep тела `configureFormFields()` для проверки masking). Идти по этим спискам, не grep'ом — это даёт детерминированный recall на больших admin-секциях.

Триггер finding'а (EasyAdmin): `field.name` матчит чувствительный паттерн (`accessToken|refreshToken|secretKey|apiKey|botToken|clientSecret|password|privateKey|webhookSecret|pat|pwd`) **и** `field.modifiers` НЕ содержит хотя бы одного из защитных: `formatValue`, `onlyOnIndex`, `hideOnForm`, `hideOnIndex`. Plain `TextField` / `EmailField` / `TextareaField` без masking → finding.

Триггер finding'а (Sonata): имя поля в `form_fields[]` матчит тот же чувствительный паттерн → grep тела `configureFormFields()` для проверки `->setDisabled(true)` / удаления из формы / masking при render — без них finding.

- `CrudController::configureFields()` возвращает `TextField::new('accessToken'|'refreshToken'|'secretKey'|'apiKey'|'botToken'|'clientSecret'|'password')` без `formatValue(fn ($v) => substr((string)$v, 0, 4) . '***')` или `->onlyOnIndex()/->hideOnForm()/->hideOnIndex()` → admin видит plaintext в index/detail/edit
- Sink_kind: `sensitive_field_unmasked` (root_cause_family `disclosure`)
- Threat: компрометация admin-аккаунта = массовый exfiltration tokens через UI; browser history / скриншоты в slack/jira / screen-recordings становятся векторами утечки
- Fix: либо `formatValue()` с masked rendering, либо отдельный `ROLE_TOKEN_VIEW` voter с явным «Reveal token» action и audit-log
- **Limitation:** если у контроллера `unresolved_fields: true` (configureFields/configureFormFields делегирует в parent), recipe не видит итоговый набор → fall back на grep по исходникам и BaseCrudController'у.
