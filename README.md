# ai-marketplace

Marketplace of plugins for Claude Code and compatible AI agents.

## Available plugins

| Plugin | Purpose |
| --- | --- |
| [`fr-security-review`](./security-review/) | Framework-aware static-first security audit for PHP/Symfony/Laravel: recon, focused worker waves, deterministic deduplication. |

## Installing the marketplace in Claude Code

```bash
claude /plugin marketplace add github:FractalizeR/ai-marketplace
```

After that, plugins from the marketplace become available for installation:

```bash
claude /plugin install fr-security-review@fractalizer-marketplace
```

## Other harnesses (Codex CLI / OpenCode)

`fr-security-review` also runs on **Codex CLI** and **OpenCode**. The same audit engine is *derived* from the Claude-authoritative prose by an in-repo build (the Claude artifacts stay byte-for-byte identical), then bundled into a self-contained, installable package. Fan-out on these harnesses uses external `codex exec` / `opencode run` processes instead of native subagents, so per-wave model tiering still works.

Quick install from a clone of this repo (idempotent; re-run to update):

```bash
make install-codex      # build + register a self-hosted Codex marketplace + install the plugin
make install-opencode   # build + drop commands/agents into ~/.config/opencode (OPENCODE_SCOPE=project for per-project)
make help               # list all targets (build-*, check, test-*)
```

The bundles land in `dist/` (gitignored), so each machine builds its own. Each installer then prints the `CORE_ROOT` (and, for OpenCode, `OPENCODE_CONFIG`) export you set in the session where you run an audit — these are per-harness and must **not** go in your shell rc globally. For the full manual steps, model setup, and the permission/offline posture, see:

- Codex CLI — [`harness/codex/INSTALL.md`](./harness/codex/INSTALL.md)
- OpenCode — [`harness/opencode/INSTALL.md`](./harness/opencode/INSTALL.md)

## License

All plugins in this marketplace are distributed under the [Elastic License 2.0](./LICENSE).

**In short:** free use is permitted, including in commercial and proprietary projects. Prohibited: providing the plugin to third parties as a hosted/managed service, circumventing license mechanisms, removing copyright/attribution.

## Development

A pre-commit hook validates the marketplace via `claude plugin validate .`. After cloning, set up the hook once:

```bash
git config core.hooksPath .githooks
```
