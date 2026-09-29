# ADR-0001 — Artifacts are prompts; renderers rewrite prose, not only tokens

Status: accepted (Phase 1 of the multi-environment build). Consequences 1–3 and the
implementation are superseded by the 5.0 amendment below; the core decision stands.

## Context

The five authoritative artifacts (`commands/*.md`, `agents/*.md`) are not data
files — they are **natural-language instructions to an LLM orchestrator**. The
multi-environment build derives Codex artifacts from this
Claude-authoritative prose through a harness-neutral IR.

It is tempting to model harness-specificity as a finite set of *tokens*
(`${CLAUDE_PLUGIN_ROOT}`, `Task(...)`, `AskUserQuestion`, frontmatter) and treat
everything else as portable prose to echo verbatim. That assumption is wrong.

## Decision

Harness-specificity is **also dissolved into narrative prose**. Examples that
would emit *broken* instructions if echoed verbatim into a Codex
artifact:

- "launch in parallel in one block of Task calls", "maximum 6 parallel Task calls".
- "the `model` parameter is passed as a Task call argument".
- the Write-safety-net protocol ("the worker did not perform a Write — … write
  it yourself via Write").
- every `AskUserQuestion` checkpoint, whose choices and fallbacks are described
  in prose, not encoded.

Crucially, **in-process `Task` fan-out has no Codex prose equivalent.**
`codex exec` is external-process dispatch with
no in-conversation Task primitive and no interactive-question primitive. A
working derived artifact therefore requires an external **dispatcher/wrapper**
and rewritten paragraphs — not a token swap.

Consequences:

1. Phase 1 produces **two** inventories: the token inventory (`TOKENS.md`) and
   the structured prose-coupling register (`PROSE_COUPLING.md`).
2. The register's entries are echoed for Claude but carry the `codex_action` +
   `non_interactive_fallback` a later renderer needs. A tripwire test asserts the
   pinned literals still exist, so prose drift is caught.
3. The byte-preserving partitioner's round-trip identity proves we won't corrupt
   the authoritative files; it does **not** prove portability. Portability is the
   job of Phases 2/3, guided by this register.

## Alternatives rejected

- *Token-only model* — would silently echo harness-coupled prose into derived
  artifacts. Rejected: it under-models the actual rewrite surface.
- *Template-with-placeholders source* — forces immediate YAML/heredoc
  re-serialization against byte-coupled tests. Rejected in favor of the
  byte-preserving partitioner (see the Phase-1 plan, AD-P1).

## Amendment (5.0) — one section layer; template presence is the coupling register

### Context

Codex is now the only derived harness, and the command surface shrank to one
orchestrator (`security-project`) plus two agents. The two-layer IR (a
byte-preserving token partition *and* a section partition, joined by a pin
register) had two consumers left:

- the Claude byte-identity gate, which rebuilt the Claude files from themselves.
  The Claude files are the build's *input*, so the gate could never catch a wrong
  Claude file — it only proved the partitioner was lossless (already asserted on
  every Codex build) — and `--harness=claude --mode=write` could rewrite the
  authoritative files;
- the Codex derivation, which used the token layer only to find Task extents,
  frontmatter attributes, and the labeled/prose `AskUserQuestion` split.

### Decision

1. **One layer.** An artifact is split into sections at headings outside the
   frontmatter, fenced blocks and `Task` directives; concatenation == source is
   asserted. `build/derive.py` renders each section; `build/sections.py` splits.
2. **A section is templated iff `harness/codex/sections/<artifact>/<anchor>.md`
   exists.** The template directory *is* the coupling register;
   `PROSE_COUPLING.md` (pins) and `TOKENS.md` (token inventory) are deleted.
3. **Other sections** get frontmatter handling (command → Codex skill block with
   `name` + `description`; agent → stripped) and a token substitution chain
   (`${CLAUDE_PLUGIN_ROOT}` → `${FR_SECURITY_CORE_ROOT}`; `$ARGUMENTS`, prose
   `AskUserQuestion`, `mcp__…` → neutral phrases; the orchestrator file ref is
   stripped, agent read-follow refs are kept).
4. **The output no-leak gate replaces the completeness guards.** A `Task`
   directive and a labeled `AskUserQuestion:` block are deliberately *not*
   substituted, so one outside a templated section reaches the output and fails
   `gates.check_codex_output`. *Amended in 5.0.0:* the leak gate cannot see a
   deleted template for a section that holds neither token (3b, 9), so
   `derive.REQUIRED_TEMPLATES` lists every templated anchor and the check fails
   when one is missing or a template directory names no artifact.
5. **Stale-template detector (replaces the pin tripwire).** Each template's first
   line is `<!-- source-sha256: <hex> -->`, the sha256 of the Claude section it was
   authored against; it is never emitted. Any change to that Claude section fails
   the build until the template is reviewed and
   `python3 build/build.py --mode=refresh-hashes` records the new hash. A template
   whose anchor names no section (a renamed heading) also fails the build.
6. The Claude byte-identity path (`--harness=claude`, the Claude/Fake/Stub
   adapters, round-trip and harness-isolation tests, the claude step in the
   pre-commit hook and `make check`) is removed.

The Codex bundle built before and after this change was byte-identical
(`diff -r` empty).

### Consequences

- Readiness for a *third* derived harness is given up: its renderer would have to
  reintroduce whatever it shares with Codex.
- A pin located one literal; the hash covers the whole section, so it fires on any
  edit, including cosmetic ones. The cost is one reviewed `refresh-hashes` run.
- Newly harness-coupled prose that contains no leak token is still caught only by
  review (true of the pin design as well).

### Templated sections as of 5.0 (why each is rewritten)

| `security-project` section | Claude semantics | Codex rewrite | No-human path |
|---|---|---|---|
| `3b-resolve-console-runner-environment-aware` | interactive choice of console runner, boot-tested via `--console-preflight` | resolve from `--console-cmd=` / `--no-console` / `FR_SECURITY_CONSOLE_CMD`; no prompt | console required and not booting → stop with the reason and the exact flags |
| `4-recon-phase` | in-process `Task(security-recon)` | one external `codex exec` that reads and follows `agents/security-recon.md` | always run recon |
| `6-optional-interactive-checkpoint` | post-recon `AskUserQuestion` review of the inventory | skipped | recon is authoritative |
| `8-parallel-worker-launch` | ≤6 parallel `Task` calls, `model=` per wave | ≤6 external `codex exec -m <tier>` processes via the dispatcher | bounded concurrency; tiers from `<REVIEW_ROOT>/.model_map.json` |
| `9-safety-net-progress-per-worker` | recover findings from a worker's response message when it did not Write | recover from the dispatcher's captured stdout | unrecoverable → coverage gap, report still produced |
