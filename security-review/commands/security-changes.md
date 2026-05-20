---
description: "Security review изменений в текущей ветке относительно master — с reverse-grep и forward-grep эвристиками для выявления регрессий. Артефакты — в `security-review-{label}/`."
argument-hint: "[--label=<x>] [--review-root=<path>] [--interactive] [--skip-recon] [--force-skip-recon] [--all-opus] [--no-console] [--exclude=<csv>]"
allowed-tools:
  - Read
  - Write
  - Edit
  - Grep
  - Glob
  - Task
  - Bash(git rev-parse *)
  - Bash(git ls-files *)
  - Bash(git diff HEAD*)
  - Bash(git diff origin/*)
  - Bash(git diff main*)
  - Bash(git diff master*)
  - Bash(git diff --diff-filter=D *)
  - Bash(git diff --merge-base *)
  - Bash(git status *)
  - Bash(git log *)
  - Bash(ls *)
  - Bash(mkdir *)
  - Bash(rm *)
  - Bash(mv *)
  - Bash(cat *)
  - Bash(printf *)
  - Bash(test *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/bin/*.py *)
  - AskUserQuestion
---

Ты — оркестратор security-ревью для diff-а текущей ветки. Recon, reverse-grep, forward-grep, параллельные воркеры в `mode=changes`, детерминированный дедуп.

## АРГУМЕНТЫ

Разобрать флаги из `$ARGUMENTS`:

- `--label=<x>` — ярлык оркестратора, формирует `<review_root> = security-review-{label}` относительно cwd. Если флаг не передан — сделай **self-introspection** (см. шаг 0).
- `--review-root=<path>` — переопределение пути review-root (для Docker/CI/firejail). Принимается относительный (резолвится от cwd) или абсолютный путь. Если задан — `--label` игнорируется.
- `--interactive`, `--skip-recon`, `--force-skip-recon`, `--all-opus` — как в `security-project`. По умолчанию W4/W5 на sonnet (balanced profile); `--all-opus` форсирует opus везде.
- `--no-console` — static-only recon: утилита НЕ запускает `bin/console` проекта. Используй при аудите hostile/untrusted-репо, при отсутствии runtime credentials или в CI-сценариях. Ceiling=medium (намеренно). Альтернатива — изоляция через firejail/Docker без флага.
- `--exclude=<csv>` — дополнительные path-prefix'ы (относительно `<project_root>`), которые НЕ будут парситься PHP-extractor'ом (см. семантику в `security-project.md`). Объединяется с тем, что найдётся в `<project_root>/CLAUDE.md` на шаге 4a.
- `--no-adversarial` — отключить adversarial refute pass (по умолчанию ВКЛ). Семантика и контракт — как в `security-project.md` (см. шаг 12.5 ниже).
- `--exploratory` и `--scope=` для diff-режима **не поддерживаются** — диф сам по себе ограничивает scope.

## ШАГИ

### 0. Resolve label & review_root

**Если задан `--review-root=<path>`** (абсолютный или относительный):

1. Резолви путь относительно cwd, если он относительный.
2. Установи `REVIEW_ROOT = <resolved path>`.
3. `--label` (если был) **игнорируется** — путь явный.

**Иначе**, если задан `--label=<x>`:

1. Нормализуй `<x>` к словарю `claude | codex | gemini | deepseek | qwen | other-<short>` (kebab-case, ≤ 16 символов).
2. `REVIEW_ROOT = security-review-<x>` (относительно cwd).

**Иначе** (ни `--review-root`, ни `--label`):

Сделай **self-introspection**: определи свою модель и harness, в котором ты запущен, и выбери `{label}` из словаря:

| Harness / CLI       | label      |
|---------------------|------------|
| Claude Code (Anthropic)             | `claude`     |
| Codex CLI (OpenAI)                  | `codex`      |
| Gemini CLI (Google)                 | `gemini`     |
| DeepSeek CLI                        | `deepseek`   |
| Qwen CLI (Alibaba)                  | `qwen`       |
| Любая нераспознанная модель/CLI     | `other-<short>` (≤ 16 символов, kebab-case) |

Уровень — **harness/CLI**, не точная модель. `claude-opus-4-7` vs `claude-sonnet-4-6` нас не интересует — важна только защита от коллизий между параллельными прогонами **разных** моделей на одном проекте.

`REVIEW_ROOT = security-review-<label>` относительно cwd.

**Известное ограничение.** Open-weight fine-tunes могут ошибочно сообщать о себе как Claude (артефакт SFT). Если уверенность низкая — пользователю придётся передать `--label` явно.

После резолюции **выведи строку пользователю**:

```
review_root: <REVIEW_ROOT> (label: <label или "explicit override">)
```

### 1. Ensure review_root layout

Создай директорию и локальный `.gitignore` (содержимое: одна строка `*`) идемпотентно:

```bash
mkdir -p "<REVIEW_ROOT>"
test -f "<REVIEW_ROOT>/.gitignore" || printf '*\n' > "<REVIEW_ROOT>/.gitignore"
mkdir -p "<REVIEW_ROOT>/waves"
```

### 2. Legacy v1 detection (warning, не abort)

Если в корне проекта (cwd) обнаружен **старый** `SECURITY_CONTEXT.md`:

```bash
test -f SECURITY_CONTEXT.md && echo "found"
```

→ Выведи предупреждение, **не трогай файл**:

```
⚠️  Legacy v1 detected: SECURITY_CONTEXT.md в корне проекта (schema v1)
    Файл не модифицируется. Свежий recon запишется в <REVIEW_ROOT>/CONTEXT.md.
```

### 3. Определить базовую ветку и diff

```bash
# Попробовать origin/master, потом origin/main, потом master, main
BASE_BRANCH=$(git rev-parse --verify origin/master 2>/dev/null \
  || git rev-parse --verify origin/main 2>/dev/null \
  || git rev-parse --verify master 2>/dev/null \
  || git rev-parse --verify main 2>/dev/null)
```

Получи список изменённых файлов:
```bash
git diff ${BASE_BRANCH}...HEAD --name-only > "<REVIEW_ROOT>/diff_files.txt"
```

Если diff пустой — abort с сообщением «Изменений относительно base ветки нет».

### 4. Чистка артефактов

```bash
rm -f "<REVIEW_ROOT>/waves/"*.md
if [ -f "<REVIEW_ROOT>/REPORT.md" ]; then
    mv "<REVIEW_ROOT>/REPORT.md" "<REVIEW_ROOT>/REPORT.prev.md"
fi
rm -f "<REVIEW_ROOT>/waves/"*.pre-retry.md
```

`<REVIEW_ROOT>/.findings_state.json` (snapshot предыдущего прогона для cross-run diff) **не чистим** — dedupe прочитает его перед записью REPORT.md и перезапишет в конце. Diff (New / Recurring / Closed) появится в Executive Summary автоматически.

### 4a. Сбор exclude-списка (CLAUDE.md + флаг)

Аналогично `security-project.md` шаг 3a: прочитай `<project_root>/CLAUDE.md`, найди секцию вида `## Code review exclusions` (или эквивалент), извлеки относительные path-prefix'ы. Объедини с `--exclude=<csv>` оркестратора. Результат — `EXCLUDE_CSV`. Встроенный `DEFAULT_EXCLUDE` утилита применит сама.

Если что-то взяли из CLAUDE.md или флага — выведи строку:

```
Exclude (CLAUDE.md): <list>
Exclude (--exclude flag): <list или "none">
```

### 4b. Detect removed defenses in diff

Цель — найти в diff удалённые строки, которые были `denyAccessUnlessGranted`, `#[IsGranted]`, `middleware('auth')`, CSRF включения и подобные защитные конструкции. Если защиту удалили — security-review должен уделить особое внимание контроллеру / роуту / методу, теряющему защиту, и его консьюмерам.

#### 4b.1. Сбор полного diff

```bash
git diff "${BASE_BRANCH}...HEAD" -- '*.php' '*.yaml' '*.yml' '*.blade.php' \
  > "<REVIEW_ROOT>/full_diff.patch"
```

#### 4b.2. Regex-сканирование удалённых защит

Запусти утилиту `diff_removed_defenses.py` — она применяет tightened regex к удалённым строкам (префикс `-`) и пишет JSON с категорией, файлом, номером строки в OLD-версии и pair-detection меткой:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/diff_removed_defenses.py \
  "<REVIEW_ROOT>/full_diff.patch" \
  > "<REVIEW_ROOT>/removed_defenses.json"
```

Покрываемые категории (источник истины — `bin/diff_removed_defenses.py::REMOVED_DEFENSE_PATTERNS`):

| Категория (`pattern_matched`) | Что детектится |
|---|---|
| `symfony_attr_isgranted` | `#[IsGranted(...)]` атрибут |
| `symfony_call_denyaccess` | `denyAccessUnlessGranted(...)` вызов |
| `laravel_blade_can` | блейд-директива `@can(...)` |
| `laravel_can_with_string` | `->can('строка')` (отсев `$collection->can()` без аргумента) |
| `laravel_authorize` | `->authorize(...)` / `Gate::authorize(...)` |
| `laravel_gate_define` | `Gate::define(...)` / `Gate::before(...)` (удаление политики) |
| `middleware_auth_single` | `->middleware('auth')` (строковый аргумент) |
| `middleware_auth_array` | `->middleware([..., 'auth', ...])` (массивный) |
| `middleware_throttle_single` / `_array` | `throttle:N,M` (rate limit) |
| `symfony_csrf_protection` | `'csrf_protection' => true` (включение CSRF) |
| `hash_equals` | timing-safe compare |
| `random_secure` | `random_bytes` / `random_int` |

**Pair detection** (рефакторинг, не удаление). Утилита автоматически проставляет `added_equivalent_detected: true`, если в радиусе ±10 строк ТОГО ЖЕ файла найдена добавленная (`+`) строка с эквивалентной защитой (см. `_EQUIVALENCE_BUCKETS` в модуле). Такие entries оркестратор НЕ должен включать в `--extra-target-files` — это рефакторинг, контроллер по-прежнему защищён.

#### 4b.3. Structural detection: удалённые Voter/Policy/Middleware файлы целиком

Найди файлы, удалённые целиком этим diff'ом:

```bash
git diff --diff-filter=D --name-only "${BASE_BRANCH}...HEAD" \
  > "<REVIEW_ROOT>/deleted_files.txt"
```

Для каждого удалённого файла:

1. **Классифицируй kind**: voter / policy / middleware. Источник истины:
   - **Если** существует `<REVIEW_ROOT>/CONTEXT.md` от **base ветки** (например, прошлый прогон сохранил `CONTEXT.prev.md`) — посмотри секции `framework_specific.symfony.voters`, `framework_specific.laravel.policies`, `framework_specific.laravel.middleware_groups` и сматчи путь.
   - **Иначе** (CONTEXT base недоступен) — fallback по naming heuristic: `*Voter.php`, `*Policy.php`, `*Middleware.php`. Документируй в выводе, что сработал fallback.

2. **Собери consumers** этих классов через встроенный `Grep` tool:

   ```
   Grep(pattern="use App\\\\Security\\\\<ClassName>;", path=".", glob="*.php", output_mode="files_with_matches")
   Grep(pattern="<ClassName>::", path=".", glob="*.php", output_mode="files_with_matches")
   ```

   (Не используй shell `grep -rn` — `Bash(grep:*)` не входит в allowed-tools.)

3. Дополни `<REVIEW_ROOT>/removed_defenses.json` блоком `removed_files`:

```json
{
  "removed_defenses": [...],
  "removed_files": [
    {
      "file": "src/Security/PostVoter.php",
      "kind": "voter",
      "consumers": ["src/Controller/PostController.php", "src/Controller/Admin/PostAdminController.php"]
    }
  ]
}
```

(Утилита из 4b.2 пишет только `removed_defenses`. Блок `removed_files` оркестратор добавляет вручную поверх.)

#### 4b.4. Пробрасывание в plan_waves

Собери список файлов-кандидатов в `--extra-target-files`:

- из `removed_defenses[]` — поле `file` каждого entry, **где `added_equivalent_detected != true`** (пары рефакторинга пропускаем);
- из `removed_files[].consumers` — все consumer-файлы.

Дедуплицируй, передай как CSV в `plan_waves.py` на шаге 9.

`plan_waves.py --extra-target-files=<csv>` добавит эти файлы в `target_files` всех волн (включая WINF, если запрошен `--exploratory`). Это гарантирует, что воркеры посмотрят на консьюмеров удалённой защиты, даже если сами consumer-файлы в diff не входят.

Выведи пользователю сводку:

```
Removed defenses: <N entries>
  - genuine removals: <N>
  - pair-detected refactors (skipped): <N>
Removed defense files (whole-file deletes): <N>
Extra target files for waves: <N> (will be merged into every wave's target_files)
```

### 5. Recon фаза

Recon собирает инвентарь **по проекту целиком** (для полного контекста), но recipe помечает `touched_by_diff: true/false` в применимых items по списку изменённых файлов.

**Если `--skip-recon` И `<REVIEW_ROOT>/CONTEXT.md` существует:** валидация fingerprints как в `security-project` (см. шаг 4 там).

**Иначе:**

Прокинь `--diff-files=` recon-агенту (он передаст утилите as-is — см. контракт `agents/security-recon.md`). Если оркестратор получил `--no-console` — добавь и его. Если шаг 4a собрал непустой `EXCLUDE_CSV` — добавь `--exclude=<EXCLUDE_CSV>`:

```
Task(subagent_type="security-recon", prompt="""
  project_root: <cwd>
  review_root: <REVIEW_ROOT>
  --diff-files=<REVIEW_ROOT>/diff_files.txt
  [--no-console]            # только если флаг был передан оркестратору
  [--exclude=<EXCLUDE_CSV>] # только если 4a собрал непустой список
""")
```

Поле `--diff-files=` — единственный сигнал для recon-агента, что нужен `scope=changes`. Если поле передано как `diff_files:` без `--`, recon молча отработает в project-режиме и `touched_by_diff` НЕ будет проставлен — весь mode=changes pipeline сломается.

После возврата — проверь `RECON_OK`. Если получено `RECON_*_FAILED` — abort с понятной ошибкой.

Прогон sanity-check filesystem coverage:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>" --sanity
```

Для `changes`-режима sanity информативный: если recon пропустил >20% контроллеров/handlers/voters/listeners от filesystem, reverse/forward-grep может не найти consumers для изменённых сервисов. Поведение по threshold ladder — как в `security-project` (warning 5–20 %, error >20 %).

### 6. Резюме и опциональный чекпоинт

Выведи пользователю резюме с акцентом на touched items (имена секций — те, что есть в данном CONTEXT.md):

```
Recon завершён (recon_confidence: <level>, ceiling: <level>).
Stack: <framework>
Diff затронул:
  - attack_surface: <N touched of M total>
  - data_access: <N touched>
  - authz_usage / framework_specific.<stack>.<authz key>: <touched listing>
  - serialization / file_operations / http_clients: <touched listing>
  - secrets / fintech_markers / framework_specific.<stack>.* config: <touched|untouched>
```

Если `--interactive` — чекпоинт как в `security-project`.

### 7. Reverse-grep (changed service → consumers)

Для каждого изменённого файла в `<REVIEW_ROOT>/diff_files.txt`, который **не является** entry point (controller/command/handler/listener/voter/route-config/security config):

1. Определи FQN класса из пути файла (PSR-4: `src/Service/PaymentService.php` → `App\Service\PaymentService`).
2. Найди использования FQN через **встроенный `Grep` tool** (он есть в allowed-tools оркестратора, не shell):

   ```
   Grep(pattern="PaymentService", path="src", glob="*.php", output_mode="files_with_matches")
   ```

3. Дополнительно — для публичных методов этого класса (если имя длиннее 6 символов ИЛИ CamelCase, например `findByDynamicCriteria`, но не `find`, `get`, `save`):

   ```
   Grep(pattern="->findByDynamicCriteria\\(", path="src", glob="*.php", output_mode="files_with_matches")
   ```

4. Если доступен `mcp__phpstorm__search_symbol` — верифицируй результаты через `{type: "method_call"}` (точнее, чем regex по PHP).
5. Найденных потребителей (Controllers, Handlers, Commands) добавь в `entry_points_in_scope` соответствующих волн.

**Важно:** не используй shell `grep -rn` — `Bash(grep:*)` не входит в allowed-tools этой команды. Только встроенный `Grep` tool.

### 8. Forward-grep (changed entry → downstream) — строго 1 уровень

Для каждого изменённого файла, **который является PHP entry point** (controller с route-атрибутом, message handler, command, voter, listener):

**Алгоритм (4 шага, глубина = 1):**

1. **Парс constructor injected types** изменённого файла: найди `public function __construct(` и извлеки типы параметров (включая constructor promotion: `public function __construct(private readonly FooService $foo)`). Карта: `property_name → FQN`.

2. **Найди в изменённом файле** через `Grep` tool паттерн `\$this->([a-zA-Z_]+)->([a-zA-Z_]+)\(` → извлеки пары `(field_name, method_name)`. Не используй shell grep — `Bash(grep:*)` не в allowed-tools.

3. **Резолв field_name → FQN** через карту из шага 1.

4. **Добавь FQN в `entry_points_in_scope`** соответствующих волн. Если MCP доступен — верифицируй через `mcp__phpstorm__search_symbol`.

**Config-файлы (yaml/xml) — forward-grep не делается.** При изменении централизованных конфигов (например `config/packages/security.yaml`, `config/routes/*` для Symfony) recipe уже проставит `touched_by_diff: true` на соответствующих items секций (`framework_specific.<stack>.firewalls` / `attack_surface` / `authz_usage` / etc.) во время recon. Worker mode=changes возьмёт их из CONTEXT.md по контракту и трассирует data flow от них.

**Known limitation (документировано в плане):** property injection, service locator, message bus dispatch (`MessageBusInterface` и аналоги), цепочки сервисов на 2+ шага, `__invoke`, динамические методы — не покрываются. Для критичных ревью рекомендуется `/security-project` целиком.

### 8a. Распределение consumers по волнам (детерминированное)

Reverse-grep (шаг 7) и forward-grep (шаг 8) дали список consumer-файлов, которые нужно добавить в `entry_points_in_scope` соответствующих волн. Чтобы убрать LLM-эвристику «угадай в какую волну добавить», вызови:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/map_consumers_to_waves.py \
  --review-root "<REVIEW_ROOT>" \
  --consumer <path1> --consumer <path2> ...
```

Или через файл (удобно при большом количестве):

```bash
printf '%s\n' <path1> <path2> > /tmp/consumers.txt
python3 ${CLAUDE_PLUGIN_ROOT}/bin/map_consumers_to_waves.py \
  --review-root "<REVIEW_ROOT>" \
  --consumers-file /tmp/consumers.txt
```

Утилита читает CONTEXT.md, ищет каждый consumer в `attack_surface` (и framework_specific.<stack>.* секциях с `kind`), маппит kind → wave_ids через статический inverse-index из WAVES. Output:

```json
{
  "src/Controller/Foo.php": {"kind": "http_route", "waves": ["W1", "W2", "W3", "W5"]},
  "src/Service/Bar.php":     {"kind": null, "waves": []}
}
```

При запуске воркеров (шаг 10) каждому consumer'у с непустым `waves` добавь его файл в `entry_points_in_scope` ТОЛЬКО для перечисленных волн. Consumers с `kind: null / waves: []` (не нашлись в инвентаре) — добавь во ВСЕ волны как fallback (раньше так делали для всех). Это сохраняет recall при unknown-kind и убирает шум для known-kind.

### 9. Генерация плана волн

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/plan_waves.py "<REVIEW_ROOT>/CONTEXT.md" \
  --plugin-root="${CLAUDE_PLUGIN_ROOT}" \
  --save-plan="<REVIEW_ROOT>/waves_plan.json" \
  [--all-opus] \
  --diff-files "<REVIEW_ROOT>/diff_files.txt" \
  [--extra-target-files="<csv from step 4b.4>"]
```

`--save-plan` сохраняет JSON-план для coverage-блока в REPORT.md (шаги 12 / 12.5.2).

**`--plugin-root` обязателен** — иначе воркеры не найдут checklists (путь резолвится к cwd проекта, не плагина).

`--extra-target-files=<csv>` (опционально) — список consumer-файлов удалённых защит из шага 4b.4 (Voter / Policy / Middleware consumers + контроллеры с removed authz, у которых `added_equivalent_detected != true`). Утилита добавит эти пути в `target_files` каждой волны (включая WINF), даже если сами файлы не входят в diff. Это гарантирует ревью затронутых регрессией файлов.

Скрипт фильтрует волны (пропускает те, чей срез не пересекается с diff) и добавляет `_CHANGES` суффикс к slice_id. WINF (exploratory) в diff-режиме не запускается, если нет пересечения diff-а с relevant items.

Печать плана пользователю (см. аналогичный пункт в `security-project.md`).

### 10. Параллельный запуск воркеров в `mode=changes`

Для каждой волны из плана, дополнительно подать найденные reverse/forward-grep entry points:

```
Task(subagent_type="security", model=<из плана, поле "model">, prompt="""
  review_root: <REVIEW_ROOT>
  relevant_section_paths: <из плана>
  checklists: <из плана>
  entry_points_in_scope: <из плана + reverse/forward-grep finds>
  target_files: <из плана (только touched)>
  slice_id: <из плана с _CHANGES>
  mode: changes
""")
```

**Важно:** параметр `model` передаётся как аргумент Task-вызова, а не в тексте промпта. Значение берётся из поля `"model"` JSON-плана.

### 10a. Safety net + прогресс (КРИТИЧНО)

Для каждого возврата Task воркера — такая же логика как в `security-project.md`:

1. `ls "<REVIEW_ROOT>/waves/<slice_id>.md"` — проверь существование.
2. Если файла нет — извлеки markdown из ответа воркера (блоки `# Уязвимость ...`) и запиши сам через Write по абсолютному пути `<REVIEW_ROOT>/waves/<slice_id>.md`.
3. Если markdown тоже нет — создай файл-заглушку с причиной.
4. Выведи строку статуса `✓ <slice_id>: ...` или `⚠ recovered` или `✗ failed`.

Это **всегда включённая** защита от случая, когда воркер вернул находки только в ответном сообщении и не выполнил Write.

### 11. Критерий репортинга (встроен в контракт воркера)

Воркер репортит находку **только если exploit path содержит изменённый узел**:
- sink в target_files
- ИЛИ entry point с `touched_by_diff: true` (в items CONTEXT.md)
- ИЛИ изменённый authz config / централизованный route config / event listener / voter

Жёстко прошитых проверок «security.yaml»/«voter» в воркере **нет** — это framework-agnostic worker, конкретику он берёт из `relevant_section_paths` и checklists.

### 11a. Merge pre-retry файлов (если есть)

Если остались файлы `*.pre-retry.md` от предыдущих retry:

```bash
for pre in "<REVIEW_ROOT>/waves/"*.pre-retry.md; do
  [ -f "$pre" ] || continue
  base="${pre%.pre-retry.md}.md"
  if [ -f "$base" ]; then
    cat "$pre" >> "$base"
  fi
done
```

Дедуп разберётся с дубликатами.

### 12. Дедупликация и свод

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/dedupe_findings.py \
  --input-glob "<REVIEW_ROOT>/waves/*.md" \
  --output "<REVIEW_ROOT>/REPORT.md" \
  --details-dir "<REVIEW_ROOT>/REPORT" \
  --waves-plan "<REVIEW_ROOT>/waves_plan.json"
```

Дедуп выдаёт split-отчёт: index `<REVIEW_ROOT>/REPORT.md` + папка `<REVIEW_ROOT>/REPORT/` с детальными файлами по `root_cause_family` и `manual_review.md` (включая parse-failed находки с флагом `[PARSE_FAILED]`). Index выводит callout «⚠️ Action required: N» при ненулевом manual count. Для single-file вывода — флаг `--single-file`.

### 12.5. Adversarial refute pass (опционально, по умолчанию on)

Если оркестратор был запущен с флагом `--no-adversarial` — **пропусти этот шаг** (тогда сразу к шагу 13).

#### 12.5.1. Запуск refute-волны

Прочитай `<REVIEW_ROOT>/REPORT.md` index-таблицу. Разбей строки на батчи по ≤20 findings (first 20 → batch_index=0, и т.д.).

Для каждого батча — sequential Task call (параллелить **запрещено** — refute-агент пишет в один файл `<REVIEW_ROOT>/refute.md` Append-режимом):

```
Task subagent_type=security-refute prompt="
review_root: <REVIEW_ROOT>
batch_index: <0..N-1>
findings_slice: <markdown срез index'а REPORT.md ≤ 20 finding строк>
"
```

Soft timeout 10 минут per call. Если Task не вернулся в timeout — оркестратор печатает warning «adversarial pass partial — N from M findings reviewed» и продолжает с partial refute.

#### 12.5.2. Применение refute результатов

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/dedupe_findings.py \
  --input-glob "<REVIEW_ROOT>/waves/*.md" \
  --output "<REVIEW_ROOT>/REPORT.md" \
  --details-dir "<REVIEW_ROOT>/REPORT" \
  --waves-plan "<REVIEW_ROOT>/waves_plan.json" \
  --refute "<REVIEW_ROOT>/refute.md" \
  --project-root "<PROJECT_ROOT>"
```

Это перезапускает дедуп и применяет refute-теги. На выходе:
- В `REPORT.md` каждый refute-помеченный finding получает `[REFUTE_CLAIMED]` маркер с `refute_file:refute_line` хвостом.
- Новый файл `<REVIEW_ROOT>/REPORT/refute_invalid.md` — refute records, не прошедшие auto-validation.
- Executive summary показывает счётчики `confirmed / refute_claimed / refute_invalid / manual_review / parse_failed`.

### 13. Вывод пользователю

```
Security review изменений завершён.
  Index: <REVIEW_ROOT>/REPORT.md
  Детали по категориям: <REVIEW_ROOT>/REPORT/<family>.md
  Базовая ветка: <branch>
  Изменённых файлов: <N>
  Не покрытые срезы: [<list> или none]
```

## ПРИНЦИПЫ

- reverse-grep и forward-grep — эвристики, дают ~80% покрытия в типичных проектах с DI по типу
- Непрямая DI (property injection, service locator, message bus dispatch) — не покрывается
- Для критичных ревью — периодически запускать `/security-project` целиком

## Известные ограничения

- Без полного call graph некоторые регрессии через старый код могут быть пропущены
- Worker retry отсутствует — при падении воркера срез помечается «не покрыт»
