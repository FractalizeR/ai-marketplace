# Multi-environment guide

`fr-security-review` is primarily a Claude Code plugin, but the **same audit
engine** also runs on **Codex CLI**. This guide is the big picture — what it is,
how it is built, how to install and run it on Codex, and the operational gotchas.
For the exact install steps see
[`harness/codex/INSTALL.md`](../harness/codex/INSTALL.md); this document does not
duplicate them.

- **Users** — start at [Overview](#overview) → [Install and run](#install-and-run)
  → [Operating notes](#operating-notes--gotchas).
- **Contributors** — [Concepts](#concepts) and [How it is built](#how-it-is-built).

---

## Overview

One engine, two harnesses:

| | Claude Code | Codex CLI |
|---|---|---|
| Entry point | slash commands | a **skill** |
| Distribution | marketplace (GitHub) | self-hosted marketplace bundle |
| Worker fan-out | native `Task(model=…)` | `codex exec -m <tier>` processes |
| Source of truth | **authoritative prose** | derived from Claude |

The Claude command/agent prose under `security-review/{commands,agents}/` is the
**single source of truth**. The Codex artifacts are *derived* from it
by an in-repo build (`build/`), so there is no parallel implementation to drift.
A byte-identity gate proves the Claude artifacts are unchanged by the build; the
derived harness gets structural gates instead (see [How it is built](#how-it-is-built)).

The portable engine — the recon/plan/dedupe Python under `security-review/bin/`,
the PHP metadata sandbox, and the `checklists/` — is **identical everywhere**. On
Codex it is copied into the bundle's `core/` directory, which
operators reference through the `FR_SECURITY_CORE_ROOT` environment variable.

---

## Concepts

### External-process fan-out

On Claude, waves fan out as native `Task` subagents. Codex has no
named-agent mechanism, so each wave is dispatched as an **independent OS
process** — one `codex exec` per slice, ≤6 concurrent. This is the one architectural difference
that matters operationally; everything downstream is identical.

The unifying glue is the **worker→file contract**: every worker, on every
harness, writes its findings to `<review_root>/waves/<slice_id>.md`. `recon`,
`plan_waves`, and `dedupe_findings` are pure Python and byte-for-byte the same
everywhere. The dispatcher lives at
[`security-review/bin/shared/dispatch.py`](../security-review/bin/shared/dispatch.py).

### Model tiering

Waves are tiered into `{high, fast}` — trust-boundary waves run on `high`,
mechanical data-flow waves on `fast`. On Claude these map to `opus`/`sonnet`
statically. On Codex the concrete model IDs are **resolved at run time**
by [`security-review/bin/shared/model_resolver.py`](../security-review/bin/shared/model_resolver.py):

1. **discover** — `codex debug models`;
2. **propose** — rank the discovered models by capability signals (fast-first);
3. **confirm** — accept the proposal, or override with
   `--models high=<id>,fast=<id>`;
4. **persist** — write `<review_root>/.model_map.json`, reused on re-runs unless
   `--remodel`.

It is non-interactive by default and never silently picks a model for a tier it
can't resolve — it fails loudly. Auto-proposal is best-effort; the operator
override is the safety net (a real run once saw Codex auto-pick a review-only
model for `high` — corrected with `--models`).

### Offline / permission posture

The auditor is **static and offline** — it never needs the network. Codex has no
permission file; the posture rests on the `codex exec` sandbox: workers run
`-s workspace-write` (write only their worktree + `--add-dir <review_root>`),
approval defaults to `never` headless, and `workspace-write` disables network by
default.

**Residual risk:** run audits only against code you trust — recon may execute the
project's own console (`bin/console`) for enrichment. Pass `--no-console` for a
hostile repo and consider a sandbox.

The run boot-tests the resolved console up front and **stops** if a console is
required but doesn't boot, unless `--console-cmd=<tpl>`, `FR_SECURITY_CONSOLE_CMD`,
or `--no-console` is set.

---

## Install and run

Two paths: `make` convenience wrappers (recommended), or the manual steps in the
Codex INSTALL guide. **Claude** needs neither — it installs from the
GitHub marketplace (`claude /plugin install fr-security-review@fractalizer-marketplace`).

The Codex bundle is built into `dist/` (gitignored), so **each machine
builds its own** — clone the repo, then:

```bash
make install-codex        # build dist/codex + register a self-hosted marketplace + install the plugin
make install-launchers    # put the `frsr` launcher on PATH (default ~/.local/bin)
make check                # full local validation gate
make help                 # list every target
```

All install targets are **idempotent** — re-run to update. Codex re-runs bump the
plugin cachebuster (a local marketplace can't be `marketplace upgrade`d).

### The `frsr` launcher

`make install-launchers` bakes this repo's path into `scripts/frsr` and installs
it, so you can run an audit from **any directory**:

```bash
frsr project  --harness codex                        # prints the prepared command; add --go to run
frsr changes  --harness codex -- --no-console        # extra flags after --
```

It exports `FR_SECURITY_CORE_ROOT`, resolves the model tiers, and invokes the harness. Options:
`--review-root`, `--project-root`, `--models high=…,fast=…`, `--no-resolve`,
`--dry-run`, and `-- <extra>` passthrough to the orchestrator.

**Why Codex only prints by default:** the headless full-autonomy path runs the
orchestrator *unsandboxed* (`--dangerously-bypass-approvals-and-sandbox`) so it
can spawn worker processes — the workers it launches stay sandboxed and offline.
`frsr` will not invoke that flag implicitly; pass `--go` to execute.

### Manual path

If you'd rather not use `make`/`frsr`, the [Codex INSTALL guide](../harness/codex/INSTALL.md)
walks every step (build → register → export `FR_SECURITY_CORE_ROOT` → resolve
models → run → permissions).

---

## Operating notes / gotchas

- **Prefer `frsr` over a global `FR_SECURITY_CORE_ROOT`.** `frsr` sets the right
  value per session; if you run manually, export it in the session where you run
  the audit.
- **Codex caches installed plugins by version.** After a rebuild, Codex won't pick
  up changes without a cachebuster bump + reinstall — `make install-codex` does
  this automatically. `FR_SECURITY_CORE_ROOT` should point at the built
  `dist/codex/plugins/fr-security-review/core` (stable across cachebuster bumps).
- **`--review-root` is output-only.** Both orchestrators reject a value that looks
  like a source tree (a past incident clobbered a `src/.gitignore`). Point it at a
  fresh `security-review-*` directory.
- **Verify the offline posture before a hostile-repo audit.** Confirm your
  `workspace-write` sandbox disables network (`curl` inside a worker should fail
  to resolve).

---

## How it is built

For contributors. The build derives the Codex artifacts from the
Claude-authoritative prose and gates them; it is dev-only tooling under `build/`
and is **not shipped inside the plugin**.

- **Two IR layers over the same text.** `build/extract.py` partitions an artifact
  into typed token `Segment`s (the Claude token fold, byte-identical);
  `build/sections.py` splits the same text into `### N` sections for the
  section-fold the Codex build walks. Both stay byte-faithful.
- **Coupling is pin-driven.** A section is *coupled* (needs harness-specific
  rewriting, not just re-tokenizing) iff it carries a
  [`build/PROSE_COUPLING.md`](../build/PROSE_COUPLING.md) pin. Coupled sections are
  replaced by authored templates under `harness/<h>/sections/<artifact>/<anchor>.md`;
  neutral sections are token-rendered by the harness adapter (`build/adapters.py`).
- **Anti-drift gate.** `build/build.py --harness=claude --mode=check` rebuilds the
  Claude artifacts in memory and diffs against on-disk — it **must** be
  byte-identical (exit 0). The derived harnesses have no byte oracle, so they get
  structural gates instead (`build/gates.py`: no Claude-token leaks, correct
  frontmatter shape, dispatch-template invariants, determinism). Both run in
  `make check` and in the `.githooks/pre-commit` hook.
- **Bundling.** `build/build.py --harness=codex --mode=write --out=dist/codex` copies
  the engine into `core/`, renders the derived skills/agents, drops the authored
  static configs (`adapter.json`, `.codex-plugin/plugin.json` + marketplace), and
  swaps the bundle in atomically.

See [`build/ADR-0001-artifacts-are-prompts.md`](../build/ADR-0001-artifacts-are-prompts.md)
for why *prose*, not only tokens, is the rewrite surface,
[`build/TOKENS.md`](../build/TOKENS.md) for the token inventory, and the
`CLAUDE.md` "Multi-environment build" sections for the phase-by-phase design.

### One naming subtlety

There are two things spelled `CORE_ROOT`, and they are different:

- the **token category** `CORE_ROOT` (internal to the build; renders to Claude's
  `${CLAUDE_PLUGIN_ROOT}`) — unchanged, internal;
- the **exported shell variable** `FR_SECURITY_CORE_ROOT` — what an operator
  exports on Codex to point at the bundled engine.

The lowercase `{core_root}` / `--core-root` / `core_root=` dispatch API is a third,
separate thing (the dispatcher's `str.format` placeholder and CLI flag). Keep them
distinct when editing the build.

---

## Troubleshooting

- **A worker hangs forever (Codex).** Fixed: `codex exec` reads extra prompt input
  from stdin, so a fanned-out worker inheriting a non-EOF stdin would block. The
  dispatcher now feeds workers `stdin=DEVNULL`. If you see this, rebuild the bundle
  so `core/bin/shared/dispatch.py` carries the fix.
- **Recon fails with a literal `<HIGH_TIER>` / `-m <HIGH_TIER>`.** The recon/refute
  role templates use `<…>` slots the orchestrator must substitute *before* calling
  `dispatch.py` (which only expands `{…}` placeholders). Inline every `<…>` slot.
- **A dispatched `--flag` is eaten as the harness CLI's own option.** Recon inputs
  are passed as flag-free `key=value` (e.g. `console_mode=off`) precisely to avoid
  this; the agent maps them to `recon_inventory.py` flags. Keep dispatched inputs
  flag-free.
- **Model auto-pick chose the wrong `high`.** Override with
  `frsr … --models high=<id>,fast=<id>` (or `model_resolver.py --models …`), then
  it persists to `.model_map.json`.
- **`FR_SECURITY_CORE_ROOT` is empty / paths break.** You did not export it. Use `frsr`, or export it in the session where you run the audit.
