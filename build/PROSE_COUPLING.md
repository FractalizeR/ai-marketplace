# Prose-coupling register

The artifacts are **LLM prompts**, so harness-specificity is not confined to the
token inventory (`TOKENS.md`) — it is partly dissolved into narrative prose that
a Codex/OpenCode renderer must *rewrite*, not merely re-tokenize. This register
names those spans so the section-fold derivation (Phase 2B) knows exactly which
`### N` sections to replace with adapter-authored prose.

Each entry has a stable `id`, a `file:` anchor, the `section_anchor` (the slug of
the heading whose section it couples — informational; the template key is the
section's own computed anchor), a `pinned:` literal (a verbatim substring that
must still exist in the artifact — a tripwire enforced by
`tests/test_prose_coupling.py`), the `harness_semantic` it carries, the
`codex_action` a derived artifact applies, and the `non_interactive_fallback`
(Codex/OpenCode have no `AskUserQuestion` analog, so every interactive checkpoint
needs a no-human path).

**Coupling is PIN-DRIVEN (Phase 2B, AD-2B2):** a section is coupled iff its span
contains ≥1 pin below. `task_block` and `labeled-block AskUserQuestion` tokens do
NOT auto-couple — they are *completeness guards* that must fall inside a pinned
section, else the build errors. A bare `AskUserQuestion` *prose-mention* (e.g.
`security-project.md:38`, describing `--interactive`) is token-rendered to a
neutral phrase, never coupling its section.

All entries stay **ECHO** for Claude; nothing here is auto-parsed into
`Segment.attrs`. Multi-pin sections (project `### 4`, `### 8`) still map to exactly
ONE template, keyed by `(artifact_basename, section_anchor)`.

```yaml
# ---- commands/security-project.md ----
- id: console-runner
  file: commands/security-project.md
  section_anchor: "3b-resolve-console-runner-environment-aware"
  pinned: "Build ≤4 options from the probe's `suggestions`"
  harness_semantic: "Interactive choice of console runner for a containerized project."
  codex_action: "Resolve from `--console-cmd=` / `--no-console`; no prompt."
  non_interactive_fallback: "Containerized + unresolved -> record console_gap (ceiling=medium), proceed static-only."

- id: recon-dispatch
  file: commands/security-project.md
  section_anchor: "4-recon-phase"
  pinned: "subagent_type="security-recon""
  harness_semantic: "In-process Task(security-recon) dispatch (1x)."
  codex_action: "Launch 1 external `opencode run` (recon role); preserve the recon_inventory.py / validate_context.py / skip-recon fingerprint logic interwoven in this section."
  non_interactive_fallback: "Always run recon; no human gate."

- id: recon-quality
  file: commands/security-project.md
  section_anchor: "4-recon-phase"
  pinned: "offer a choice via AskUserQuestion"
  harness_semantic: "On a sanity diff of 5-20%, ask whether to repeat recon or continue."
  codex_action: "No prompt; honor `--interactive` only where supported."
  non_interactive_fallback: "Continue with awareness of gaps (option b); recon_confidence: medium; no auto-retry."

- id: recon-skip-mismatch
  file: commands/security-project.md
  section_anchor: "4-recon-phase"
  pinned: "Code changed, context may be stale"
  harness_semantic: "Optional interactive confirm when --skip-recon reuses a stale CONTEXT.md."
  codex_action: "No prompt; honor explicit flags."
  non_interactive_fallback: "Proceed with the reused context; note potential staleness."

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
  codex_action: "Launch <=6 external `opencode run -m <tier>` processes via the dispatcher, one per wave (no in-process Task primitive)."
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

- id: refute-no-parallelism
  file: commands/security-project.md
  section_anchor: "11-5-1-launching-the-refute-wave"
  pinned: "parallelism is **forbidden**"
  harness_semantic: "Refute pass is sequential (single refute.md writer)."
  codex_action: "Sequential `opencode run` per <=20-finding batch; never parallel."
  non_interactive_fallback: "Same: sequential, single writer."

# ---- commands/security-changes.md (changes-specific pins, NOT mirrored verbatim) ----
- id: console-runner-changes
  file: commands/security-changes.md
  section_anchor: "4c-resolve-console-runner-environment-aware"
  pinned: "decide HOW to run the project console"
  harness_semantic: "Interactive console-runner choice (changes mode)."
  codex_action: "Resolve from `--console-cmd=` / `--no-console`; no prompt."
  non_interactive_fallback: "Containerized + unresolved -> console_gap; proceed static-only."

- id: recon-dispatch-changes
  file: commands/security-changes.md
  section_anchor: "5-recon-phase"
  pinned: "subagent_type="security-recon""
  harness_semantic: "In-process Task(security-recon) dispatch, changes mode (no sanity AUQ here)."
  codex_action: "Launch 1 external `opencode run` (recon role); preserve the interwoven Python invocations."
  non_interactive_fallback: "Always run recon; no human gate."

- id: checkpoint-changes
  file: commands/security-changes.md
  section_anchor: "6-summary-and-optional-checkpoint"
  pinned: "checkpoint as in"
  harness_semantic: "Print summary + optional interactive checkpoint (delegated to security-project in prose)."
  codex_action: "Carry the summary print; resolve the security-project xref; non-interactive checkpoint fallback."
  non_interactive_fallback: "Skip the checkpoint; print the summary and proceed."

- id: worker-fanout-changes
  file: commands/security-changes.md
  section_anchor: "10-parallel-worker-launch-in-mode-changes"
  pinned: "subagent_type="security""
  harness_semantic: "In-process Task fan-out (changes mode), <=6 workers, per-wave model."
  codex_action: "Launch <=6 external `opencode run -m <tier>` via the dispatcher, one per wave."
  non_interactive_fallback: "Bounded concurrency 6; persisted/CLI model map."

- id: write-safety-net-changes
  file: commands/security-changes.md
  section_anchor: "10a-safety-net-progress-critical"
  pinned: "did not execute Write"
  harness_semantic: "Recover worker findings from the response message if the wave file is missing."
  codex_action: "Recover from the dispatcher's captured stdout; else record a coverage gap."
  non_interactive_fallback: "Unrecoverable -> coverage gap; do not block the report."

- id: refute-changes
  file: commands/security-changes.md
  section_anchor: "12-5-1-launching-the-refute-wave"
  pinned: "subagent_type=security-refute"
  harness_semantic: "Sequential refute pass (single refute.md writer), changes mode."
  codex_action: "Sequential `opencode run` per <=20-finding batch; never parallel."
  non_interactive_fallback: "Same: sequential, single writer."
```

## ADR pointer

See `ADR-0001-artifacts-are-prompts.md`: later renderers rewrite prose, not only
tokens — and in-process `Task` fan-out has **no** Codex/OpenCode prose
equivalent, so it requires an external dispatcher/wrapper, not a paragraph
rewrite. This register is the inventory of exactly those rewrites; the
section-fold build (Phase 2B) consumes it as the sole coupling driver.
