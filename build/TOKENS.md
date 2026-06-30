# Token inventory — harness-coupled spans in the Claude artifacts

This is the formal inventory the build's partitioner (`extract.py`) and registry
(`tokens.py`) are built against. It covers the five authoritative artifacts:

```
commands/security-project.md   commands/security-changes.md
agents/security.md   agents/security-recon.md   agents/security-refute.md
```

Counts below are verified by grep over those files. Recognizer code keys its
category names to `extract.CAT_*`; this doc and `tokens.REGISTRY` must stay in
sync (the registry-coverage test enforces that every category is classified).

## Tiers

- **ACTIVE_CANONICAL** — abstracted now, rendered from a canonical form (must
  reproduce the original for Claude). The only tier exercising a non-identity
  renderer; the FakeAdapter divergence test proves the seam is real.
- **ACTIVE_PARSED** — attributes captured now (so Phase 2/3 renderers aren't
  blocked) but echoed for Claude.
- **DEFERRED** — inventoried as harness-coupled, intentionally not abstracted in
  Phase 1; allow-listed in the no-leak scan.

## Categories (8)

| # | Category | Tier | Count | Where / notes |
|---|----------|------|-------|---------------|
| 1 | `CORE_ROOT` (`${CLAUDE_PLUGIN_ROOT}`) | ACTIVE_CANONICAL | **25** = 21 body/fence + 4 frontmatter | project 11 (2 fm + 9), changes 11 (2 fm + 9), recon 3. Body roles: 19 `path_prefix` + 2 `flag_value` (`--plugin-root="…"`, project:363 / changes:450). Body fence: 17 `triple_fence` + 4 `inline_code` (project:230/261/262, changes:315). Frontmatter ones are `glob_permission`, captured as a `cmd_frontmatter` attr, not separately tagged. |
| 2 | `args_injection` (`$ARGUMENTS`) | ACTIVE_PARSED | 2 | project:33, changes:38. The `## ARGUMENTS` heading (no `$`) is **not** tagged. |
| 3 | `cmd_frontmatter` | ACTIVE_PARSED (opaque echo) | 2 | leading YAML of both commands. Attrs: `description`, `argument-hint`, `allowed-tools` (incl. its 2 CORE_ROOT globs + the `Task` / `AskUserQuestion` entries). |
| 4 | `agent_frontmatter` | ACTIVE_PARSED (opaque echo) | 3 | leading YAML of the 3 agents. Attrs: `name`, `description`, `model` (security=opus, recon/refute=sonnet). Cleanest Phase-2 mapping (named-agent → skill/prompt). |
| 5 | `task_block` | ACTIVE_PARSED (echo) | 6 directives | project 276/409/515, changes 333/472/547. Two syntaxes: **paren** `Task(subagent_type="…", [model=…,] prompt="""…""")` (4) and **bare** `Task subagent_type=… prompt="…"` (2). Attrs: `syntax_variant`, `subagent_type`, `model` (raw + `is_template`), `prompt_body`, `fence_context`, `is_directive`. Prose `Task(...)` mentions (project:122 / changes:126) are **not** tagged. |
| 6 | `auq` (`AskUserQuestion`) | ACTIVE_PARSED (echo) | 6 body | project 38/242/268/308 + labeled-block 347; changes 317. (Frontmatter entries project:26 / changes:31 are subsumed by `cmd_frontmatter`.) Attrs: `occurrence_kind` ∈ {prose-mention (5), labeled-block (1)}. Choices→flags + non-interactive fallbacks live in `PROSE_COUPLING.md`. |
| 7 | `mcp_ref` (`mcp__phpstorm__*`) | ACTIVE_PARSED (echo) | 5 | changes 393/410; security 34/88/176. All framed as optional ("if available"). Attr: `tool`, `optional=true`. |
| 8 | `deferred_tools` (bare `Read`/`Write`/`Grep` …, `Grep(pattern=…)`) | DEFERRED | n/a | Double as English words → tagging risks false positives. Passthrough as neutral; allow-listed in the no-leak scan. Phase 2 decides their codex/opencode handling. |

## Deliberately-NEUTRAL (negative guards)

These look token-ish but are harness-agnostic or load-bearing prose; `extract`
must never tag them (guarded by tests):

- `${BASE_BRANCH}` — ordinary shell var (changes:176/215/253).
- `<REVIEW_ROOT>`, `<PROJECT_ROOT>`, `<from plan, field "model">`, `mode:` literals.
- the 32-entry review-root blacklist (asserted verbatim by `test_slash_commands.py`).

## Out of scope for Phase 1

Bare tool names and structured tool-calls are deferred. Frontmatter is echoed
opaque (not re-serialized). Codex/OpenCode renderers are not implemented; their
adapters raise `NotImplementedError`.

**Nested tokens inside Task bodies.** A point token (e.g. `${CLAUDE_PLUGIN_ROOT}`)
that ever appears *inside* a `prompt="""…"""` body is subsumed into the
`task_block` and echoed as part of the block for all harnesses — it loses its own
canonical seam. None exist in the current artifacts (so this is latent), but
Phase 2 must re-scan captured `prompt_body` for nested tokens before rendering a
non-Claude harness.
