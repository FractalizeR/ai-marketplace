# Deserialization (Symfony) — Symfony Serializer, Messenger, JMS

> This checklist complements `core/serialization.md` for symfony projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Symfony Serializer

- `$serializer->deserialize($request->getContent(), Entity::class, 'json')` without `AbstractNormalizer::ATTRIBUTES` whitelist — mass assignment
- `ObjectNormalizer` without restrictions for an entity with privileged setters (`setRoles`, `setIsAdmin`)
- Missing `#[Groups]` or wrong groups → leak of internal fields in API response
- `getIgnoredAttributes()` is not applied to input
- Custom normalizer calling `unserialize()` on part of the payload

## Symfony Messenger

- Transport deserializing external messages: AMQP/Redis/Doctrine transports — PHP-serialization format by default means unserialize
- `PhpSerializer` as the serializer for a transport accepting messages from untrusted sources
- Handler without owner / authz check on message data:
  - message contains `userId`, handler performs an operation on that user without cross-checking against the actor
  - message contains `filePath`, handler reads the file without path validation
- Missing `UserContext` / identity attached to the message: in async handler it is not clear who initiated the operation → bypasses authz
- Repeated processing of the same message (no idempotency) → double-spend, duplicate emails
- `Throwable` in handler → message retried indefinitely with side effects
