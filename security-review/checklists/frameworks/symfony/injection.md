# Injection (Symfony) — Form mass-assignment, Messenger transport trust

> Этот чек-лист дополняет `core/injection.md` для проектов на symfony. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Form mass-assignment (Symfony Form)

Формы Symfony Form-компонента — основной канал mass-assignment в Symfony-проектах. Без `data_class` и/или с `allow_extra_fields: true` форма пропускает любые поля от клиента.

- `Symfony\Component\Form\FormType` без `data_class` → пропускает любые поля (forms over arrays)
- FormType с `allow_extra_fields: true` — принимает любые дополнительные поля и десериализует их в entity
- `Serializer::denormalize($data, Entity::class)` из request body без `AbstractNormalizer::ATTRIBUTES` whitelist
- Direct setters на privileged fields достижимы через FormType: `setRoles`, `setIsAdmin`, `setPaid(true)` если поля добавлены в форму без guard
- Entity с public properties вместо setters — любой `Serializer::denormalize` / FormType заполнит всё

## Messenger transport trust

См. также `serialization.md` для PhpSerializer-related deserialization concerns. Здесь — анти-паттерны доверия handlers к содержимому сообщения:

- Handler полагается на то, что сообщение «откуда-то от доверенной системы», и не проверяет владельца / authz по `userId`/`tenantId` из body сообщения. См. также `auth.md` (tenancy trust) — async handler = тот же service-level firewall, без cryptographic binding.
