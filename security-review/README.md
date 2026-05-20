# fr-security-review

Framework-aware static-first security audit для Claude Code: recipe-driven recon, фокусные волны воркеров, детерминированная дедупликация.

Поддерживаемые стеки: Symfony, Laravel, generic PHP. GraphQL-слой (lighthouse, rebing-laravel, api-platform, webonyx) детектируется автоматически в Symfony и Laravel.

## Quick start

После установки плагина из marketplace используй две slash-команды:

| Команда | Назначение |
| --- | --- |
| `/fr-security-review:security-project` | Security audit всего проекта |
| `/fr-security-review:security-changes` | Security audit diff'а текущей ветки относительно master |

Минимальный прогон:

```
/fr-security-review:security-project
```

Артефакты записываются в `security-review-<label>/` в текущей рабочей директории. Папка автоматически добавляется в локальный `.gitignore` (`<review_root>/.gitignore` с содержимым `*`), проектный `.gitignore` не модифицируется.

## Pipeline

1. **Recon.** Recipe (Symfony / Laravel / generic PHP) собирает structured inventory проекта без LLM: routes, middleware, контроллеры, модели данных, voters, форм-классы, listeners, messenger handlers и т.п. Результат — `<review_root>/CONTEXT.md` (schema v2 с frontmatter и закрытыми shape-спеками).
2. **Plan waves.** `plan_waves.py` режет inventory на тематические волны (auth+disclosure, injection+data-access, output-render, serialization+crypto, ssrf+fileops, fintech, exploratory) и закрепляет за каждой свой набор чек-листов и target-файлов.
3. **Workers.** Параллельные воркеры по 6 за батч, balanced-profile моделей: opus для анализа trust boundaries (W1/W2/W6), sonnet для механического data-flow (W3/W4/W5/W∞).
4. **Dedupe.** `dedupe_findings.py` сшивает per-wave findings в split-отчёт: `REPORT.md` (executive summary + index) + `REPORT/<root_cause_family>.md` (детали).

### ⚠️ Расход токенов

`/fr-security-review:security-project` запускает несколько параллельных Opus/Sonnet воркеров на каждом прогоне (W1–W6 + W∞ + adversarial pass). Стоимость зависит от модели и размера проекта.

**Флаги для CI / экономии:**
- `--quick` — отключает W∞ (cross-layer chain analysis).
- `--no-adversarial` — отключает refute pass.
- `--ci` — alias для `--quick --no-adversarial`.

Для своего проекта — `bin/dedupe/cost.py estimate <review_root>` после первого прогона показывает фактические токены.

## Security model

**Что плагин читает и исполняет:**

- **Read-only.** Recipe и чек-листы только читают исходный код проекта; никогда не модифицируют файлы вне `<review_root>/`.
- **Console smoke по умолчанию.** Recon-утилита может запустить `bin/console list` (Symfony) или `php artisan list` (Laravel) для enrichment секций (доступные команды, зарегистрированные сервисы и т.п.). Таймаут 30 секунд, ограничения памяти — но **bootstrap-код проекта при этом исполняется**.
- **PHP metadata extractor.** `bin/recon/extract_php_metadata.php` парсит PHP-файлы через `token_get_all` без require/include — не исполняет код проекта. Subprocess-sandbox: `timeout=60s`, `memory_limit=256M`, path traversal через `Path.resolve() + is_relative_to(project_root)`.
- **Worker tools.** Воркеры — Read, Grep, Glob; никаких Write на проектные файлы, никаких git-команд кроме безопасных просмотровых, никакого исполнения кода.

**Когда нужна изоляция:**

- Аудит untrusted/hostile репозитория (composer post-install hooks, конструкторы сервисов с side-effects).
- CI/CD без runtime credentials.
- Sandbox-режим внутри корпоративной инфраструктуры.

**Два варианта изоляции:**

### Вариант 1 — флаг `--no-console`

Полностью отключает console smoke. Recon работает только через статический парсинг файлов:

```
/fr-security-review:security-project --no-console
```

`recon_confidence.ceiling` принудительно понижается до `medium` (некоторые секции остаются на статической эвристике). Это намеренно — чтобы воркеры не строили выводы на полном инвентаре, которого нет.

`--no-console` не защищает от уязвимости в самом PHP metadata extractor (хоть он и не require'ит код), и от расширенных read-only утилит. Если репо реально hostile — добавь sandbox.

### Вариант 2 — sandbox через firejail (Linux)

Идея: запустить Claude Code в песочнице без сети, с read-write доступом только к директории проекта. Конкретные флаги firejail зависят от версии и дистрибутива — отправная точка:

```bash
firejail --private="/path/to/project" --net=none claude code
```

Адаптируй опции под свой стенд (см. `firejail --help` и `man firejail`). Для строгих сценариев Docker предсказуемее.

### Вариант 3 — sandbox через Docker

Минимальный Dockerfile:

```dockerfile
FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git python3 php-cli && rm -rf /var/lib/apt/lists/*
RUN npm install -g @anthropic-ai/claude-code
WORKDIR /workspace
```

Запуск с прокинутым review-root для сохранения артефактов и `--review-root` для явного пути:

```bash
docker run --rm -it \
  -v "$(pwd):/workspace:ro" \
  -v "$(pwd)/security-review-docker:/review:rw" \
  -e ANTHROPIC_API_KEY \
  claude-sandbox \
  claude /fr-security-review:security-project --review-root=/review --no-console
```

`--review-root` обязателен для override label-based пути; внутри контейнера cwd read-only, а review-root — read-write на хосте.

## Project-specific exclusions

Помимо встроенных безопасных дефолтов (`vendor/`, `var/cache/`, `var/log/`, `node_modules/`, `storage/framework/cache/`, `storage/logs/`, `bootstrap/cache/`, `public/build/`, `.git/`), которые PHP-extractor пропускает *до* парсинга, можно исключить дополнительные директории:

- **`<project_root>/CLAUDE.md`** — рекомендуемый способ для повторяющихся проектных условий. Оркестратор перед запуском recon читает CLAUDE.md и автоматически извлекает path-prefix'ы из секции `## Code review exclusions` (или эквивалентной). Не парсится regex'ом — Claude разбирает её естественно. Рекомендуемый формат:

  ```markdown
  ## Code review exclusions
  Не анализировать в security-ревью:
  - legacy/                — устаревший код, будет удалён в Q4
  - src/ThirdParty/        — vendored-код, не наш контракт
  - generated/             — autogenerated, ревью не нужно
  ```

- **`--exclude=<csv>`** — флаг команды для разовых исключений:

  ```
  /fr-security-review:security-project --exclude=legacy,src/ThirdParty
  ```

Оба источника объединяются с встроенным `DEFAULT_EXCLUDE` (не заменяют его). Перед запуском recon оркестратор выводит итоговый список — пользователь видит, что не будет проанализировано. Применённые проектные exclude'ы записываются в `frontmatter.warnings` итогового `<review_root>/CONTEXT.md` как `exclude_paths_user: <list>` для аудита.

**Когда добавлять exclude:** auto-generated код, vendored mirrors, legacy-код перед удалением, директории с фикстурами тестов, в которых заведомо есть «уязвимости» для проверки. Не добавляй директории, которые хочешь анализировать — это снижает recall security-ревью.

**Per-file size cap.** Файлы крупнее 2 MiB (например, `vimeo/psalm/dictionaries/CallMap_*.php`) extractor пропускает с предупреждением в stderr. Это страховка от OOM, даже если файл попадает в анализируемое поддерево.

## Self-introspection и параллельные прогоны

Без `--label` команды делают self-introspection и выбирают label из словаря: `claude | codex | gemini | deepseek | qwen | other-<short>`. Review-root становится `security-review-<label>/` — параллельные прогоны разных моделей на одном проекте не конфликтуют.

**Известное ограничение:** open-weight fine-tunes (Qwen/DeepSeek) могут ошибочно идентифицировать себя как Claude. Для CI/Docker — передавай `--label` явно.

## Версия и совместимость

Текущая мажорная версия — 3.x. Полный changelog — в [CHANGELOG.md](CHANGELOG.md).

- `schema_version: 2` для `<review_root>/CONTEXT.md`. Старые v1-артефакты (`<project_root>/SECURITY_CONTEXT.md`) не читаются — slash-команды детектируют их и выводят предупреждение.
- Multi-stack monorepos — out of scope. Один основной стек на проект.

## Принципы

- **Никогда не коммитить артефакты ревью.** Локальный `<review_root>/.gitignore` уже игнорирует всё содержимое. Закоммитить можно через `git add -f` явно.
- **Recon-агент — single writer на CONTEXT.md.** Никакие воркеры, slash-команды, MCP не должны его перезаписывать.
- **Воркер failure ≠ abort всего ревью.** Продолжаем с оставшимися волнами.

## Лицензия

Elastic License 2.0. Полный текст — в корне репозитория ([LICENSE](../LICENSE)).

Кратко: свободное использование (в том числе в коммерческих и проприетарных проектах) разрешено. Запрещено: предоставление плагина третьим лицам как hosted/managed service, обход лицензионных механизмов, удаление copyright/attribution.
