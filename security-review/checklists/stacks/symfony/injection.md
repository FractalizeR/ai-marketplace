# Injection (Symfony) — Form mass-assignment, Messenger transport trust

> This checklist complements `core/injection.md` for symfony projects. On conflicting instructions, this file takes priority as the more specific one. Worker loads both files simultaneously.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + a concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Form mass-assignment (Symfony Form)

Forms of the Symfony Form component are the main channel for mass-assignment in Symfony projects. Without `data_class` and/or with `allow_extra_fields: true`, the form lets through any fields from the client.

- `Symfony\Component\Form\FormType` without `data_class` → lets through any fields (forms over arrays)
- FormType with `allow_extra_fields: true` — accepts any additional fields and deserializes them into the entity
- `Serializer::denormalize($data, Entity::class)` from the request body without `AbstractNormalizer::ATTRIBUTES` whitelist
- Direct setters on privileged fields reachable through FormType: `setRoles`, `setIsAdmin`, `setPaid(true)` if the fields are added to the form without a guard
- Entity with public properties instead of setters — any `Serializer::denormalize` / FormType will fill everything

## Messenger transport trust

See also `serialization.md` for PhpSerializer-related deserialization concerns. Here — anti-patterns of handlers trusting message contents:

- Handler relies on the message being "from a trusted system somewhere" and does not check the owner / authz by `userId`/`tenantId` from the message body. See also `auth.md` (tenancy trust) — an async handler = the same service-level firewall, without cryptographic binding.
