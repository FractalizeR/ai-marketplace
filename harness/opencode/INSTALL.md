# Installing `fr-security-review` on OpenCode

Verified against **OpenCode 1.17.10**. This bundle is *derived* from the
Claude-authoritative command/agent prose — do not hand-edit files under
`dist/opencode/`; re-run the build instead (see the repo's `build/`).

## 1. Build the bundle

From the repo root:

```bash
python3 build/build.py --harness=opencode --mode=write --out=dist/opencode
```

This emits a self-contained tree:

```
dist/opencode/
  core/                 # the portable engine (= $CORE_ROOT)
    bin/  checklists/
  commands/             # entrypoints: /security-project, /security-changes
    security-project.md
    security-changes.md
  agents/               # workers dispatched via `opencode run --agent <name>`
    security.md  security-recon.md  security-refute.md
  opencode.json         # scoped permissions
  adapter.json          # build metadata (not read by OpenCode at runtime)
  INSTALL.md            # this file
```

## 2. Place the artifacts where OpenCode reads them

OpenCode discovers commands and agents from `.opencode/commands/` and
`.opencode/agents/` (per-project) or `~/.config/opencode/{commands,agents}/`
(global). Copy them into whichever scope you want:

```bash
# per-project (run inside the target project)
mkdir -p .opencode/commands .opencode/agents
cp path/to/dist/opencode/commands/* .opencode/commands/
cp path/to/dist/opencode/agents/*   .opencode/agents/
```

The `agents/*.md` filenames become the agent names (`security`,
`security-recon`, `security-refute`) that the dispatcher targets with
`--agent`. The `commands/*.md` filenames become the slash commands
(`/security-project`, `/security-changes`).

## 3. Point OpenCode at the permission config

`opencode.json` must sit where OpenCode's config resolution finds it — either
the **project root** where you launch `opencode`, or exported explicitly:

```bash
export OPENCODE_CONFIG=path/to/dist/opencode/opencode.json
```

(The `OPENCODE_CONFIG` env var is a separate precedence layer from the
`.opencode/` directories — set one or the other, not necessarily both.)

## 4. Export `CORE_ROOT`

The derived prose references the portable engine as `${CORE_ROOT}`. OpenCode
does **not** substitute this the way Claude substitutes `${CLAUDE_PLUGIN_ROOT}` —
it is a plain shell variable that the orchestrator's bash steps expand, and it
propagates to every `opencode run` worker the dispatcher launches. Export it to
the absolute path of the bundle's `core/` directory:

```bash
export CORE_ROOT=/abs/path/to/dist/opencode/core
# on the same machine you just built on:
#   export CORE_ROOT=$(pwd)/dist/opencode/core
echo "$CORE_ROOT"   # verify — if empty, every ${CORE_ROOT}/bin/... path breaks
```

## 5. Resolve models

The wave dispatcher tiers workers into `{high, fast}` (trust-boundary waves on
`high`, mechanical data-flow waves on `fast`). Discover and pin the tier map:

```bash
opencode models                                  # inspect what your providers expose
python3 "$CORE_ROOT/bin/shared/model_resolver.py" \
  --discovery-cmd "opencode models" \
  --review-root security-review-opencode
```

This writes `<review_root>/.model_map.json`, reused on re-runs (pass
`--remodel` to re-resolve). It is non-interactive by default; add
`--interactive` to confirm/override the proposed tiers at a stdin checkpoint.

## 6. Run an audit

Invoke the command in OpenCode (TUI `/security-project`, or headless):

```bash
opencode run --command security-project "project_root=. review_root=security-review-opencode"
```

The orchestrator runs recon → wave planning → external-process fan-out (one
`opencode run --agent security -m <tier>` per slice, ≤6 concurrent) → dedupe,
writing artifacts under `security-review-opencode/`.

## Permissions & residual risk

`opencode.json` ships a deliberately scoped posture:

- `task: "deny"` — encodes the architecture decision (AD4): OpenCode's
  in-process subagent fan-out is unreliable (deadlocks), so fan-out is done with
  independent `opencode run` OS-processes, never the `task` tool.
- `webfetch: "deny"`, `websearch: "deny"` — the methodology is static and
  offline; a security auditor has no reason to reach the network.
- `external_directory: "allow"`, `bash: "allow"`, `read`/`edit: "allow"` — the
  pipeline reads `$CORE_ROOT`, `project_root`, and `review_root`, which normally
  live **outside** the OpenCode worktree, and writes wave files across them; it
  also runs `python3`/`php`/`opencode`. These paths are only known at runtime,
  so they cannot be pattern-scoped in a static config, and a headless
  `opencode run` cannot answer an `ask` prompt. **Residual:** these three are
  broad. Run the audit only against code you trust, in a trusted environment;
  recon may execute the project's own console (`bin/console`) for enrichment.
  For a hostile-repo audit pass `--no-console` and consider a sandbox.
