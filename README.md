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

## License

All plugins in this marketplace are distributed under the [Elastic License 2.0](./LICENSE).

**In short:** free use is permitted, including in commercial and proprietary projects. Prohibited: providing the plugin to third parties as a hosted/managed service, circumventing license mechanisms, removing copyright/attribution.

## Development

A pre-commit hook validates the marketplace via `claude plugin validate .`. After cloning, set up the hook once:

```bash
git config core.hooksPath .githooks
```
