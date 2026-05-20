# ai-marketplace

Маркетплейс плагинов для Claude Code и совместимых ИИ-агентов.

## Доступные плагины

| Плагин | Назначение |
| --- | --- |
| [`fr-security-review`](./security-review/) | Framework-aware static-first security audit для PHP/Symfony/Laravel: recon, фокусные волны воркеров, детерминированная дедупликация. |

## Установка marketplace в Claude Code

```bash
claude /plugin marketplace add github:FractalizeR/ai-marketplace
```

После этого плагины из marketplace становятся доступны для установки:

```bash
claude /plugin install fr-security-review@fractalizer-marketplace
```

## Лицензия

Все плагины в этом маркетплейсе распространяются под [Elastic License 2.0](./LICENSE).

**Кратко:** свободное использование разрешено, в том числе в коммерческих и проприетарных проектах. Запрещено: предоставление плагина третьим лицам как hosted/managed service, обход лицензионных механизмов, удаление copyright/attribution.

## Разработка

Pre-commit hook валидирует marketplace через `claude plugin validate .`. После клонирования один раз настрой хук:

```bash
git config core.hooksPath .githooks
```
