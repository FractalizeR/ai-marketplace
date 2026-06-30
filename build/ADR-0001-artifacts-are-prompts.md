# ADR-0001 — Artifacts are prompts; renderers rewrite prose, not only tokens

Status: accepted (Phase 1 of the multi-environment build).

## Context

The five authoritative artifacts (`commands/*.md`, `agents/*.md`) are not data
files — they are **natural-language instructions to an LLM orchestrator**. The
multi-environment build derives Codex/OpenCode artifacts from this
Claude-authoritative prose through a harness-neutral IR.

It is tempting to model harness-specificity as a finite set of *tokens*
(`${CLAUDE_PLUGIN_ROOT}`, `Task(...)`, `AskUserQuestion`, frontmatter) and treat
everything else as portable prose to echo verbatim. That assumption is wrong.

## Decision

Harness-specificity is **also dissolved into narrative prose**. Examples that
would emit *broken* instructions if echoed verbatim into a Codex/OpenCode
artifact:

- "launch in parallel in one block of Task calls", "maximum 6 parallel Task calls".
- "the `model` parameter is passed as a Task call argument".
- the Write-safety-net protocol ("the worker did not perform a Write — … write
  it yourself via Write").
- every `AskUserQuestion` checkpoint, whose choices and fallbacks are described
  in prose, not encoded.

Crucially, **in-process `Task` fan-out has no Codex/OpenCode prose equivalent.**
Codex `codex exec` and OpenCode `opencode run` are external-process dispatch with
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
