---
description: "Двухфазный security audit проекта: recon + параллельные волны фокусных воркеров + exploratory волна для cross-layer chains + детерминированный дедуп. Артефакты — в `security-review-{label}/`."
argument-hint: "[--label=<x>] [--review-root=<path>] [--interactive] [--skip-recon] [--force-skip-recon] [--quick] [--all-opus] [--scope=<glob>] [--no-console] [--exclude=<csv>]"
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

Ты — оркестратор security-ревью проекта. Запускаешь recon, управляешь параллельными волнами воркеров, сшиваешь результаты через детерминированный дедуп-скрипт.

## АРГУМЕНТЫ

Разобрать флаги из `$ARGUMENTS`:

- `--label=<x>` — ярлык оркестратора, формирует `<review_root> = security-review-{label}` относительно cwd. Если флаг не передан — сделай **self-introspection** (см. шаг 0).
- `--review-root=<path>` — переопределение пути review-root (для Docker/CI/firejail). Принимается относительный (резолвится от cwd) или абсолютный путь. Если задан — `--label` игнорируется.
- `--interactive` — чекпоинт пользователю после recon (через AskUserQuestion)
- `--skip-recon` — переиспользовать существующий `<review_root>/CONTEXT.md` (валидация fingerprints)
- `--force-skip-recon` — продолжить при code_fingerprint mismatch
- `--quick` — **отключить** exploratory-волну W∞ (по умолчанию ВКЛ). Для быстрых прогонов / CI.
- `--all-opus` — форсировать opus для всех волн (legacy). По умолчанию W4/W5 на sonnet (механический data-flow).
- `--scope=<glob>` — ограничить target_files по glob-паттерну (например `src/Api/**`)
- `--no-console` — static-only recon: утилита НЕ запускает `bin/console` проекта. Используй при аудите hostile/untrusted-репо (нет гарантий, что bootstrap не выполнит вредоносный код), при отсутствии runtime credentials или в CI-сценариях, где исполнение проекта запрещено. Ceiling=medium (намеренно). Альтернатива — изоляция через firejail/Docker без флага.
- `--exclude=<csv>` — дополнительные path-prefix'ы (относительно `<project_root>`), которые НЕ будут парситься PHP-extractor'ом. Например, `--exclude=legacy,src/ThirdParty,generated`. Эти пути добавляются к встроенному `DEFAULT_EXCLUDE` (`vendor/`, `var/cache/`, `var/log/`, `node_modules/`, `storage/framework/cache/`, `storage/logs/`, `bootstrap/cache/`, `public/build/`, `.git/`) — НЕ заменяют его. Если флаг не передан явно — действуют только встроенные defaults + найденные в CLAUDE.md (см. шаг 3a).
- `--no-adversarial` — **отключить** adversarial refute pass (по умолчанию ВКЛ). Refute-волна снижает false-positive rate за счёт второго прохода через Sonnet. Отключай, если нужен максимально быстрый прогон без второго прохода.

**Важно про дефолты:**
- **Exploratory-волна W∞ включена по умолчанию.** Без неё пропускаются cross-layer уязвимости (OAuth state, tenancy chains, authenticator integrity). Быстрый сканер — `--quick`.
- **Balanced-profile моделей включён по умолчанию.** W1/W2/W6 — opus (auth/disclosure, injection/data-access, fintech: требуют рассуждения о trust boundaries / chains). W3 (output-render+frontend-js), W4 (serialization+crypto), W5 (ssrf-fileops), W∞ (exploratory) — sonnet: механический data-flow, sonnet справляется. Источник истины — `bin/plan_waves.py:WaveSpec.balanced_model`. Форсировать opus везде — `--all-opus`.

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

Это **не модифицирует проектный `.gitignore`** и не попадает в git.

### 2. Legacy v1 detection (warning, не abort)

Если в корне проекта (cwd) обнаружен **старый** `SECURITY_CONTEXT.md` (это v1 layout, до v3-редизайна):

```bash
test -f SECURITY_CONTEXT.md && echo "found"
```

→ Выведи предупреждение пользователю, **не трогай файл**:

```
⚠️  Legacy v1 detected: SECURITY_CONTEXT.md в корне проекта (schema v1)
    Файл не модифицируется. Свежий recon запишется в <REVIEW_ROOT>/CONTEXT.md.
    Старый файл можно удалить вручную после успешного запуска.
```

### 3. Чистка предыдущих артефактов

```bash
# Удали промежуточные wave-отчёты от прошлых запусков
rm -f "<REVIEW_ROOT>/waves/"*.md
# Сохрани предыдущий свод как .prev.md (если есть)
if [ -f "<REVIEW_ROOT>/REPORT.md" ]; then
    mv "<REVIEW_ROOT>/REPORT.md" "<REVIEW_ROOT>/REPORT.prev.md"
fi
# Прошлые pre-retry-снимки (если оркестратор делал retry в прошлом прогоне)
rm -f "<REVIEW_ROOT>/waves/"*.pre-retry.md
```

`<REVIEW_ROOT>/REPORT/` (split-detail) **не чистим** — dedupe перепишет его на шаге дедупа.

`<REVIEW_ROOT>/.findings_state.json` (snapshot предыдущего прогона для cross-run diff) **не чистим** — dedupe прочитает его перед записью REPORT.md и перезапишет в конце. На следующем прогоне «New / Recurring / Closed» появится в Executive Summary автоматически.

### 3a. Сбор exclude-списка (CLAUDE.md + флаг)

Цель — собрать единый `EXCLUDE_CSV` для пробрасывания в recon-утилиту. Источники:

1. **`<project_root>/CLAUDE.md`** (если файл есть). Прочитай его и найди явные указания исключить директории из security-ревью. Типичные сигналы: секция вида `## Code review exclusions` / `## Security review exclusions`, перечисляющая paths; либо явные предложения «не анализируй legacy/», «исключи src/ThirdParty/», «папка generated/ — autogen, ревью не нужно». Извлеки только относительные path-prefix'ы (директории и/или конкретные subdir'ы), без glob-паттернов и `*.ext`. Если CLAUDE.md отсутствует или не содержит такой секции — список пустой.
2. **Флаг `--exclude=<csv>`** оркестратора (если передан) — разбери на список.

Объедини оба источника, удали дубликаты и пустые. Результат — `EXCLUDE_CSV` (строка через запятую) или пусто.

> Встроенный `DEFAULT_EXCLUDE` (`vendor/`, `var/cache/`, `var/log/`, `node_modules/`, `storage/framework/cache/`, `storage/logs/`, `bootstrap/cache/`, `public/build/`, `.git/`) применяется утилитой ВСЕГДА — добавлять его к `EXCLUDE_CSV` не нужно.

Если из CLAUDE.md что-то взяли — выведи строку пользователю:

```
Exclude (CLAUDE.md): <list>
Exclude (--exclude flag): <list или "none">
```

Это даёт прозрачность: пользователь видит, какие директории не будут проанализированы, прежде чем уйдёт ждать прогон.

**Рекомендуемый формат секции в CLAUDE.md** (для информации пользователя — мы её не пишем сами):

```markdown
## Code review exclusions
Не анализировать в security-ревью:
- legacy/                — устаревший код, будет удалён в Q4
- src/ThirdParty/        — vendored-код, не наш контракт
- generated/             — autogenerated, ревью не нужно
```

### 4. Recon фаза

**Если `--skip-recon` передан И `<REVIEW_ROOT>/CONTEXT.md` существует:**

1. Валидируй схему: `python3 ${CLAUDE_PLUGIN_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>"`
2. Посчитай текущие fingerprints: `python3 ${CLAUDE_PLUGIN_ROOT}/bin/compute_fingerprint.py . --json`
3. Извлеки из frontmatter существующего `<REVIEW_ROOT>/CONTEXT.md` поля `project_fingerprint` и `code_fingerprint`, сравни:
   - **project_fingerprint mismatch** → `abort`: «Конфигурация/зависимости изменились, нужен полный recon»
   - **project_fingerprint match + code_fingerprint match** → использовать контекст as-is
   - **project_fingerprint match + code_fingerprint mismatch**:
     - Если `--force-skip-recon` → продолжить с warning
     - Иначе если `--interactive` → `AskUserQuestion`: «Код изменился, контекст может быть stale. Продолжить?»
     - Иначе → `abort` с подсказкой `--force-skip-recon`

**Иначе (полный recon):**

Запусти recon-агент. Он сам выберет recipe (detect) и вызовет `recon_inventory.py`, который запишет `<REVIEW_ROOT>/CONTEXT.md`. Если оркестратор получил `--no-console` — пробрось его в prompt. Если на шаге 3a получил непустой `EXCLUDE_CSV` — пробрось `--exclude=<EXCLUDE_CSV>`:

```
Task(subagent_type="security-recon", prompt="""
  project_root: <cwd>
  review_root: <REVIEW_ROOT>
  [--no-console]            # только если флаг был передан оркестратору
  [--exclude=<EXCLUDE_CSV>] # только если 3a собрал непустой список
""")
```

**В обычном режиме `--no-console` не нужен** — recon-утилита решает сама (если console enrichment доступен — использует, иначе ставит ceiling=medium). Передавай флаг только при явном требовании sandbox'а (hostile-репо аудит, CI без credentials).

После возврата — проверь `RECON_OK` в ответе агента. Если получено `RECON_*_FAILED` — остановись, выведи ошибку.

Затем дополнительно прогоняй sanity-check с filesystem coverage:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/validate_context.py --review-root "<REVIEW_ROOT>" --sanity
```

`--sanity` импортирует recipe (по `recipe_used` из frontmatter), вызывает `recipe.sanity_probes()`, сравнивает declared `file:` в секциях с фактическим filesystem. **Coverage threshold ladder** (rev v3):

- diff ≤ 5 % → ok, `recon_confidence: high`
- diff 5–20 % → warning, `recon_confidence: medium`, rationale во `frontmatter.warnings`
- diff > 20 % → error, `recon_confidence: low`, exit 1

Если валидация падает (ERROR exit 1) — остановись, покажи ошибки пользователю.

Если только warnings (sanity diff 5–20 %) — используй следующую логику в зависимости от того, первый ли это recon или повторный (`RECON_RETRY_DONE`):

**Первый recon (RECON_RETRY_DONE = false):** покажи warnings пользователю и предложи выбор через AskUserQuestion:
- (а) Повторить recon (`rm <REVIEW_ROOT>/CONTEXT.md` + заново) — рекомендуется если много пропущенных файлов
- (б) Продолжить с осознанием пробелов

Если пользователь выбрал (а): установи `RECON_RETRY_DONE = true`, удали `<REVIEW_ROOT>/CONTEXT.md`, запусти recon-агент заново, прогони валидацию и sanity-check снова.

**Повторный recon (RECON_RETRY_DONE = true):** если coverage всё ещё в диапазоне warning — **не спрашивай повторно**. Покажи варнинг и автоматически продолжай:

```
⚠️  Sanity-check после повторного recon: coverage улучшился, но warning остался.
   Возможно, часть файлов вне ожидаемых директорий или следует нестандартному именованию.
   Продолжаю с имеющимся инвентарём — воркеры покроют объявленные entry points.
```

### 5. Резюме пользователю

Прочитай `<REVIEW_ROOT>/CONTEXT.md`, покажи краткое резюме (имена секций — те, что есть в данном CONTEXT.md; ниже — пример для Symfony, для других стэков названия отличаются):

```
Recon завершён (recon_confidence: <level>, ceiling: <level>).
Stack: <framework name from frontmatter.stack.framework>
Найдено (top-level core sections):
  - attack_surface: <N items>
  - data_access: <N items> (с раз. источниками: <M>)
  - authz_usage: <N items>
  - serialization: <N items>
  - file_operations / http_clients: <N> / <M>
  - secrets: <status>
  - fintech_markers: <present|none>
Framework-specific (если присутствует): <list of framework_specific.<stack>.* keys with statuses>
Missing sections / warnings: [<list>]
```

### 6. Опциональный чекпоинт `--interactive`

Если `--interactive`:

```
AskUserQuestion:
  "Инвентарь верный? Что добавить, уточнить, приоритизировать?"
```

Ответ пользователя — фиксируй в комментарии к слайсу при запуске воркеров (`prompt`-поле). **CONTEXT.md не модифицируем** — recon-агент авторитетен.

### 7. Генерация плана волн

Определи значение флагов:
- `EXPLORATORY` = on, если `--quick` НЕ указан (дефолт). Off, если указан `--quick`.
- `ALL_OPUS` = on, если указан `--all-opus`.
- `SCOPE_GLOB` = значение после `--scope=`, или пусто.

Вызов:
```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/plan_waves.py "<REVIEW_ROOT>/CONTEXT.md" \
  --plugin-root="${CLAUDE_PLUGIN_ROOT}" \
  --save-plan="<REVIEW_ROOT>/waves_plan.json" \
  [--all-opus]            # если ALL_OPUS \
  [--exploratory]         # если EXPLORATORY \
  [--scope-glob=<SCOPE_GLOB>]   # если задан
```

`--save-plan` сохраняет план в JSON для последующего coverage-блока в REPORT.md (шаг 11 / 11.5.2).

**`--plugin-root` обязателен** — иначе `plan_waves` не найдёт `checklists/` (относительный путь резолвится к cwd проекта, не плагина). Скрипт префиксирует чек-листы абсолютным путём.

**`--exploratory` передаётся по умолчанию** (кроме `--quick` режима). Это даёт W∞ волну — ключевая для cross-layer уязвимостей (OAuth chains, tenancy integrity, authenticator flows).

Вернёт JSON-массив со списком слайсов. Поля каждого слайса:
- `slice_id`, `wave_id`, `themes`, `checklists` (абсолютные пути)
- `relevant_section_paths` (dot-notation), `entry_points_in_scope`, `target_files`
- `model` (opus|sonnet), `mode` (project)

### 7a. Печать плана пользователю

Перед запуском воркеров покажи пользователю сводку плана:

```
Запускаю <N> волн (режим: <balanced|all-opus>):
  W1 (opus, <M> файлов): auth+disclosure
  W2 (opus, <M> файлов): injection+data-access
  W3 (sonnet, <M> файлов): output-render+frontend-js
  W4 (sonnet, <M> файлов): serialization+crypto
  W5 (sonnet, <M> файлов): ssrf-fileops
  W6 (opus, <M> файлов): fintech (если триггернулся)
  W∞ (sonnet, exploratory): union themes
```

Это даёт видимость — пользователь видит что будет запущено, прежде чем уйти в параллельную обработку на ~5-15 минут.

### 8. Параллельный запуск воркеров

Разбить волны на батчи по **6 воркеров** и запускать батч за батчем:

1. Взять первые 6 волн из плана → запустить параллельно в одном блоке Task-вызовов
2. Дождаться завершения всех 6 → обработать результаты (шаг 9) → запустить следующий батч
3. Повторять до исчерпания волн

Формат Task-вызова для каждой волны:

```
Task(subagent_type="security", model=<из плана, поле "model">, prompt="""
  review_root: <REVIEW_ROOT>
  relevant_section_paths: <список dot-notation путей>
  checklists: <список абсолютных путей>
  entry_points_in_scope: <список>
  target_files: <список>
  slice_id: <из плана>
  mode: project
""")
```

**Важно:** параметр `model` передаётся как аргумент Task-вызова, а не в тексте промпта. Это гарантирует, что воркер запустится на нужной модели (opus/sonnet из balanced-profile). Значение берётся из поля `"model"` JSON-плана.

**Важно:** максимум 6 параллельных Task-вызовов за раз. При большом количестве волн — несколько батчей последовательно.

### 9. Safety net + прогресс по каждому воркеру

Для **каждого** возврата Task воркера:

1. Проверить существование файла:
   ```bash
   ls "<REVIEW_ROOT>/waves/<slice_id>.md"
   ```
2. **Safety net (всегда):** если файл **отсутствует**, воркер не выполнил Write — извлеки тело markdown из его ответного сообщения (там должны быть блоки `# Уязвимость ...`) и запиши сам через Write в `<REVIEW_ROOT>/waves/<slice_id>.md`. Это гарантирует что дедуп получит на вход все находки.
3. **Если в ответе тоже нет markdown-блоков** (воркер вернул только текст или упал) — создай файл с шапкой:
   ```markdown
   # Wave <slice_id> — no findings or worker failed
   <краткое сообщение из ответа воркера или причина fail>
   ```
4. Выведи пользователю одну строку статуса:
   - `✓ <slice_id>: saved <N> findings (Critical: x, High: y, Medium: z)` — нашёл
   - `✓ <slice_id>: clean (0 findings)` — проверил, чисто
   - `⚠ <slice_id>: worker returned no file, recovered from response` — safety net сработал
   - `✗ <slice_id>: failed — <reason>` — не удалось получить осмысленный результат

Retry воркеров не делаем. Продолжаем с оставшимися.

### 9a. Merge pre-retry файлов (если есть)

Если оркестратор (или пользователь) ранее выполнил retry воркера и остались файлы `*.pre-retry.md`:

```bash
for pre in "<REVIEW_ROOT>/waves/"*.pre-retry.md; do
  [ -f "$pre" ] || continue
  base="${pre%.pre-retry.md}.md"
  if [ -f "$base" ]; then
    cat "$pre" >> "$base"
  fi
done
```

Дедуп-скрипт автоматически сольёт дубликаты — лучше дубликат, чем потеря security-кейса.

### 10. Предупреждение для больших проектов с exploratory

Если `EXPLORATORY=on` (по умолчанию) И в scope >100 файлов — выведи warning **до запуска** W∞ Task:

```
⚠️  Exploratory-волна (W∞) на проекте >100 файлов — может быть дорого.
   W∞ загружает union всех тематических чек-листов и бежит по всем target-файлам
   чанками по 65 файлов на sonnet — стоимость растёт линейно с размером проекта.
   W4/W5 уже на sonnet по умолчанию (опции тут нет).

   Варианты сэкономить:
     • --quick           — отключить W∞ целиком. Теряем cross-layer анализ:
                           OAuth state chains, multi-tenancy boundaries,
                           authenticator integrity, prompt injection chains.
                           Фокусные волны W1–W6 продолжают работать.
     • --scope=<glob>    — сузить target_files до подмножества (например,
                           --scope='src/Api/**'). W∞ остаётся включённой,
                           но бежит только по матчам — пропорционально дешевле.
```

W∞ Task запускается автоматически в общем цикле (шаг 8) — отдельный шаг не нужен, `plan_waves.py --exploratory` уже включил его в план.

### 11. Дедупликация и свод

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/dedupe_findings.py \
  --input-glob "<REVIEW_ROOT>/waves/*.md" \
  --output "<REVIEW_ROOT>/REPORT.md" \
  --details-dir "<REVIEW_ROOT>/REPORT" \
  --waves-plan "<REVIEW_ROOT>/waves_plan.json"
```

Дедуп выдаёт **split-отчёт** (по умолчанию):
- `<REVIEW_ROOT>/REPORT.md` — executive summary + index-таблица всех находок со ссылками на детали
- `<REVIEW_ROOT>/REPORT/<root_cause_family>.md` — детали находок по категориям (authz.md, injection.md, disclosure.md, crypto.md, ssrf.md, webhook.md, business_logic.md, xss.md, deserialization.md)
- `<REVIEW_ROOT>/REPORT/manual_review.md` — находки, требующие ручной проверки: не прошедшие auto-promote (custom sink_kind + не критичные) **и** parse-failed (воркер не выдал `sink_file`, флаг `[PARSE_FAILED]`). Index выводит callout «⚠️ Action required: N» при ненулевом count.

Для legacy-режима (всё в один файл) — флаг `--single-file`.

### 11.5. Adversarial refute pass (опционально, по умолчанию on)

Если оркестратор был запущен с флагом `--no-adversarial` — **пропусти этот шаг** (тогда сразу к шагу 12).

#### 11.5.1. Запуск refute-волны

Прочитай `<REVIEW_ROOT>/REPORT.md` index-таблицу. Разбей строки на батчи по ≤20 findings (first 20 → batch_index=0, next 20 → batch_index=1, и т.д.).

Для каждого батча — sequential Task call (параллелить **запрещено** — refute-агент пишет в один файл `<REVIEW_ROOT>/refute.md` Append-режимом):

```
Task subagent_type=security-refute prompt="
review_root: <REVIEW_ROOT>
batch_index: <0..N-1>
findings_slice: <markdown срез index'а REPORT.md ≤ 20 finding строк>
"
```

Soft timeout 10 минут per call. Если Task не вернулся в timeout — оркестратор печатает warning «adversarial pass partial — N from M findings reviewed» и продолжает с partial refute. Refute не блокирует основной отчёт.

#### 11.5.2. Применение refute результатов

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/bin/dedupe_findings.py \
  --input-glob "<REVIEW_ROOT>/waves/*.md" \
  --output "<REVIEW_ROOT>/REPORT.md" \
  --details-dir "<REVIEW_ROOT>/REPORT" \
  --waves-plan "<REVIEW_ROOT>/waves_plan.json" \
  --refute "<REVIEW_ROOT>/refute.md" \
  --project-root "<PROJECT_ROOT>"
```

Это перезапускает дедуп (быстро) и применяет refute-теги. На выходе:
- В `REPORT.md` — каждый refute-помеченный finding получает `[REFUTE_CLAIMED]` маркер с `refute_file:refute_line` хвостом.
- Новый файл `<REVIEW_ROOT>/REPORT/refute_invalid.md` — refute records, не прошедшие auto-validation (для аудита).
- Executive summary показывает счётчики `confirmed / refute_claimed / refute_invalid / manual_review / parse_failed`.

### 12. Вывод пользователю

```
Security review завершён.
  Index: <REVIEW_ROOT>/REPORT.md
  Детали по категориям: <REVIEW_ROOT>/REPORT/<family>.md
  Промежуточные отчёты (для аудита): <REVIEW_ROOT>/waves/*.md
  Не покрытые срезы: [<list> или none]
```

## ПРИНЦИПЫ

- Никогда не коммитить артефакты — локальный `.gitignore` внутри `<REVIEW_ROOT>/` уже игнорирует всё содержимое + сам `.gitignore`. Пользователь сам решит закоммитить через `git add -f`, если захочет.
- Воркер failure ≠ abort всего ревью — продолжаем с оставшимися
- Все промежуточные `<REVIEW_ROOT>/waves/*.md` сохранять для аудита, не удалять между шагами
