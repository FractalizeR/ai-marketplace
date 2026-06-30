# Prose-coupling register

The artifacts are **LLM prompts**, so harness-specificity is not confined to the
token inventory (`TOKENS.md`) — it is partly dissolved into narrative prose that
a Codex/OpenCode renderer must *rewrite*, not merely re-tokenize. This register
names those spans so Phase 2 doesn't discover them late.

Each entry has a stable `id`, a `file:`/`pinned:` anchor (a literal substring
that must still exist in the artifact — a tripwire enforced by
`tests/test_prose_coupling.py`), the `harness_semantic` it carries, the
`codex_action` a derived artifact applies, and the `non_interactive_fallback`
(Codex/OpenCode have no `AskUserQuestion` analog, so every interactive checkpoint
needs a no-human path).

All entries stay **ECHO** for Claude in Phase 1; nothing here is auto-parsed into
`Segment.attrs`. The data is captured once, here.

```yaml
- id: parallel-task-fanout
  file: commands/security-project.md
  pinned: "maximum 6 parallel Task calls at once"
  harness_semantic: "In-process Task fan-out, batches of <=6 workers."
  codex_action: "Launch <=6 external `codex exec -m <tier>` processes, one per wave (no in-process Task primitive)."
  non_interactive_fallback: "Bounded concurrency 6; no human input needed."

- id: model-passed-as-task-arg
  file: commands/security-project.md
  pinned: "the `model` parameter is passed as a Task call argument"
  harness_semantic: "Per-wave model tiering via the Task call's model= argument."
  codex_action: "Pass `-m <tier>` per external process from the resolved tier map (Codex named agents inherit parent model; tiering must be external)."
  non_interactive_fallback: "Use persisted/CLI model map; strict error if unresolved."

- id: write-safety-net
  file: commands/security-project.md
  pinned: "the worker did not perform a Write"
  harness_semantic: "Orchestrator recovers a worker's findings from its response message if waves/<slice_id>.md is missing."
  codex_action: "Recover from `codex exec -o <capture>` JSON when the wave file is missing (partial safety net)."
  non_interactive_fallback: "If unrecoverable, record a coverage gap for that wave; do not block the report."

- id: refute-no-parallelism
  file: commands/security-project.md
  pinned: "parallelism is **forbidden**"
  harness_semantic: "Refute pass is sequential (single refute.md writer)."
  codex_action: "Sequential `codex exec` per <=20-finding batch; never parallel."
  non_interactive_fallback: "Same: sequential, single writer."

- id: auq-console-runner
  file: commands/security-project.md
  pinned: "Build ≤4 options from the probe's `suggestions`"
  harness_semantic: "Interactive choice of console runner for a containerized project."
  codex_action: "Resolve from `--console-cmd=` / `--no-console`; no prompt."
  non_interactive_fallback: "Containerized + unresolved -> record console_gap (ceiling=medium), proceed static-only."

- id: auq-recon-quality
  file: commands/security-project.md
  pinned: "offer a choice via AskUserQuestion"
  harness_semantic: "On a sanity diff of 5-20%, ask whether to repeat recon or continue."
  codex_action: "No prompt; honor `--interactive` only where supported."
  non_interactive_fallback: "Continue with awareness of gaps (option b); recon_confidence: medium; no auto-retry."

- id: auq-inventory-checkpoint
  file: commands/security-project.md
  pinned: "Is the inventory correct? What to add, refine, prioritize?"
  harness_semantic: "Optional post-recon human review of the inventory (only under --interactive)."
  codex_action: "Skip unless an explicit interactive mode is wired."
  non_interactive_fallback: "Skip the checkpoint entirely; recon agent is authoritative."
```

## ADR pointer

See `ADR-0001-artifacts-are-prompts.md`: later renderers rewrite prose, not only
tokens — and in-process `Task` fan-out has **no** Codex/OpenCode prose
equivalent, so it requires an external dispatcher/wrapper, not a paragraph
rewrite. This register is the inventory of exactly those rewrites.
