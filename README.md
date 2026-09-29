# ai-marketplace

Marketplace of plugins for Claude Code and compatible AI agents.

## Available plugins

| Plugin | Purpose |
| --- | --- |
| [`fr-security-review`](./security-review/) | Framework-aware static-first security audit for PHP/Symfony/Laravel: recon, focused worker waves, deterministic deduplication. |
| [`fr-audit-triage`](./audit-triage/) | Turns a `fr-security-review` `findings.json` into deduplicated, code-verified units of work grouped by fix pattern, plus a triage bucket for leads and a structured verdict channel back into the audit. Claude Code only — not part of the Codex build. It is also the audit's false-positive filter. |

## Installing the marketplace in Claude Code

```bash
claude /plugin marketplace add github:FractalizeR/ai-marketplace
```

After that, plugins from the marketplace become available for installation:

```bash
claude /plugin install fr-security-review@fractalizer-marketplace
```

## Codex CLI

`fr-security-review` also runs on **Codex CLI**. The Codex skill and worker files are *derived* from the Claude-authoritative prose by an in-repo build and bundled into a self-contained, installable package. Fan-out uses external `codex exec` processes instead of native subagents, so per-wave model tiering still works.

Quick install from a clone of this repo (idempotent; re-run to update):

```bash
make install-codex      # build + register a self-hosted Codex marketplace + install the plugin
make help               # list all targets (build-codex, check, test-*)
```

`make install-launchers` additionally puts an `frsr` command on your `PATH` (default `~/.local/bin`) so you can run an audit from any directory — it sets `FR_SECURITY_CORE_ROOT`, saves the model tiers (on a `--go` run), and invokes Codex:

```bash
frsr project --models high=<id>,fast=<id>           # prints the prepared command; add --go to run
frsr project --models high=<id>,fast=<id> -- --quick --no-console   # orchestrator flags go after --
```

`--models` (comma-separated, spaces around `,` and `=` are tolerated; list the ids with `codex debug models`) is required until a `--go` run has saved the tier map for that review directory; later runs may drop it. The bundle lands in `dist/` (gitignored), so each machine builds its own. The installer prints the `FR_SECURITY_CORE_ROOT` export for the session where you run an audit without `frsr` — do **not** put it in your shell rc globally.

The [multi-environment guide](./docs/multi-environment.md) is the big picture — architecture, model tiering, the offline posture, and troubleshooting. The exact install steps, model setup, and permissions are in [`harness/codex/INSTALL.md`](./harness/codex/INSTALL.md).

## License

All plugins in this marketplace are distributed under the [Elastic License 2.0](./LICENSE).

**In short:** free use is permitted, including in commercial and proprietary projects. Prohibited: providing the plugin to third parties as a hosted/managed service, circumventing license mechanisms, removing copyright/attribution.

Some checklist content is adapted from third-party projects under their own licenses — see [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).

## Development

A pre-commit hook validates the marketplace via `claude plugin validate .`. After cloning, set up the hook once:

```bash
git config core.hooksPath .githooks
```
