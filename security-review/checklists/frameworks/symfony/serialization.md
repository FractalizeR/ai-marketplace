# Deserialization (Symfony) — Symfony Serializer, Messenger, JMS

> Этот чек-лист дополняет `core/serialization.md` для проектов на symfony. При конфликте инструкций — приоритет за этим файлом, как более специфичным. Worker загружает оба файла одновременно.

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Symfony Serializer

- `$serializer->deserialize($request->getContent(), Entity::class, 'json')` без `AbstractNormalizer::ATTRIBUTES` whitelist — mass assignment
- `ObjectNormalizer` без ограничений для entity с privileged setters (`setRoles`, `setIsAdmin`)
- Отсутствие `#[Groups]` или неправильные группы → утечка внутренних полей в API response
- `getIgnoredAttributes()` не применяется для input
- Кастомный normalizer, вызывающий `unserialize()` на части payload

## Symfony Messenger

- Transport, десериализующий внешние сообщения: AMQP/Redis/Doctrine transports — формат PHP-сериализации по умолчанию означает unserialize
- `PhpSerializer` как serializer для транспорта, принимающего сообщения из ненадёжных источников
- Handler без проверки владельца / authz на данных сообщения:
  - сообщение содержит `userId`, handler выполняет операцию на этом user без сверки с actor
  - сообщение содержит `filePath`, handler читает файл без path validation
- Отсутствие `UserContext` / identity attached to message: в async handler не ясно, кто инициировал операцию → обходит authz
- Повторная обработка того же сообщения (no idempotency) → double-spend, duplicate emails
- `Throwable` в handler → сообщение retried бесконечно с side-effects
