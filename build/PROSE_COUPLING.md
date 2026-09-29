# Prose-coupling register

The artifacts are **LLM prompts**, so harness-specificity is not confined to the
token inventory (`TOKENS.md`) — it is partly dissolved into narrative prose that
a Codex renderer must *rewrite*, not merely re-tokenize. This register
names those spans so the section-fold derivation (Phase 2B) knows exactly which
`### N` sections to replace with adapter-authored prose.

Each entry has a stable `id`, a `file:` anchor, the `section_anchor` (the slug of
the heading whose section it couples — informational; the template key is the
section's own computed anchor), a `pinned:` literal (a verbatim substring that
must still exist in the artifact — a tripwire enforced by
`tests/test_prose_coupling.py`), the `harness_semantic` it carries, the
`codex_action` a derived artifact applies, and the `non_interactive_fallback`
(Codex have no `AskUserQuestion` analog, so every interactive checkpoint
needs a no-human path).

**Coupling is PIN-DRIVEN (Phase 2B, AD-2B2):** a section is coupled iff its span
contains ≥1 pin below. `task_block` and `labeled-block AskUserQuestion` tokens do
NOT auto-couple — they are *completeness guards* that must fall inside a pinned
section, else the build errors. A bare `AskUserQuestion` *prose-mention* (e.g.
the `--interactive` bullet in the command's `## ARGUMENTS`) is token-rendered to a
neutral phrase, never coupling its section.

All entries stay **ECHO** for Claude; nothing here is auto-parsed into
`Segment.attrs`. A multi-pin section (project `### 8`) still maps to exactly
ONE template, keyed by `(artifact_basename, section_anchor)`.

```yaml
# ---- commands/security-project.md ----
- id: console-runner
  file: commands/security-project.md
  section_anchor: "3b-resolve-console-runner-environment-aware"
  pinned: "Build ≤4 options from the probe's `suggestions`"
  harness_semantic: "Interactive choice of console runner for a containerized project, boot-tested via --console-preflight."
  codex_action: "Resolve from `--console-cmd=` / `--no-console`; no prompt."
  non_interactive_fallback: "Console required and not booting (exit 3) -> stop with reason + exact flags (--console-cmd=<tpl> / --no-console, or FR_SECURITY_CONSOLE_CMD)."

- id: recon-dispatch
  file: commands/security-project.md
  section_anchor: "4-recon-phase"
  pinned: "subagent_type="security-recon""
  harness_semantic: "In-process Task(security-recon) dispatch (1x)."
  codex_action: "Launch 1 external `codex exec` (recon role); preserve the recon_inventory.py / validate_context.py logic interwoven in this section."
  non_interactive_fallback: "Always run recon; no human gate."

- id: inventory-checkpoint
  file: commands/security-project.md
  section_anchor: "6-optional-interactive-checkpoint"
  pinned: "Is the inventory correct"
  harness_semantic: "Optional post-recon human review of the inventory (only under --interactive)."
  codex_action: "Skip unless an explicit interactive mode is wired."
  non_interactive_fallback: "Skip the checkpoint entirely; recon agent is authoritative."

- id: worker-fanout
  file: commands/security-project.md
  section_anchor: "8-parallel-worker-launch"
  pinned: "maximum 6 parallel Task calls at once"
  harness_semantic: "In-process Task fan-out, batches of <=6 workers."
  codex_action: "Launch <=6 external `codex exec -m <tier>` processes via the dispatcher, one per wave (no in-process Task primitive)."
  non_interactive_fallback: "Bounded concurrency 6; no human input needed."

- id: worker-model-arg
  file: commands/security-project.md
  section_anchor: "8-parallel-worker-launch"
  pinned: "the `model` parameter is passed as a Task call argument"
  harness_semantic: "Per-wave model tiering via the Task call's model= argument."
  codex_action: "Pass `-m <tier>` per external process from the resolved tier map."
  non_interactive_fallback: "Use persisted/CLI model map; strict error if unresolved."

- id: write-safety-net
  file: commands/security-project.md
  section_anchor: "9-safety-net-progress-per-worker"
  pinned: "the worker did not perform a Write"
  harness_semantic: "Orchestrator recovers a worker's findings from its response message if waves/<slice_id>.md is missing."
  codex_action: "Recover from the dispatcher's captured stdout when the wave file is missing (partial safety net)."
  non_interactive_fallback: "If unrecoverable, record a coverage gap for that wave; do not block the report."
```

## ADR pointer

See `ADR-0001-artifacts-are-prompts.md`: later renderers rewrite prose, not only
tokens — and in-process `Task` fan-out has **no** Codex prose
equivalent, so it requires an external dispatcher/wrapper, not a paragraph
rewrite. This register is the inventory of exactly those rewrites; the
section-fold build (Phase 2B) consumes it as the sole coupling driver.
