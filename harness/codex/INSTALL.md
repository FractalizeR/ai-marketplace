# Installing `fr-security-review` on Codex CLI

Verified against **codex-cli 0.135.0**. This bundle is *derived* from the
Claude-authoritative command/agent prose — do not hand-edit files under
`dist/codex/`; re-run the build instead (see the repo's `build/`).

Distribution is **self-hosted** (a local/team marketplace you host yourself); there
is no OpenAI store submission.

## Quick path

From the repo root, `make install-codex` runs steps 1–2 (and, on re-runs, bumps the
cachebuster per §6) in one idempotent command, then prints the `CORE_ROOT` export:

```bash
make install-codex
```

Steps 3–5 (export `CORE_ROOT`, resolve models, run) still happen in the session where
you run the audit. The manual walkthrough below explains each step.

## 1. Build the bundle

From the repo root:

```bash
python3 build/build.py --harness=codex --mode=write --out=dist/codex
```

This emits a self-contained **marketplace root**:

```
dist/codex/                                   # = the dir you register with codex
  .fr-codex-bundle                            # generated-bundle sentinel (do not commit)
  .agents/plugins/marketplace.json            # marketplace: fractalizer-marketplace
  plugins/fr-security-review/
    .codex-plugin/plugin.json                 # plugin manifest
    skills/security-project/SKILL.md          # orchestrator skills
    skills/security-changes/SKILL.md
    core/                                     # = $CORE_ROOT
      bin/  checklists/
      agents/security.md  agents/security-recon.md  agents/security-refute.md
    adapter.json                              # build metadata (not read by Codex at runtime)
    INSTALL.md                                # this file
```

## 2. Register the marketplace and install the plugin

`dist/codex/` is the marketplace **root** (it carries `.agents/plugins/marketplace.json`,
and each entry's `source.path` is relative to this root). Register it, then install:

```bash
codex plugin marketplace add /abs/path/to/dist/codex
codex plugin add fr-security-review@fractalizer-marketplace
```

If you re-run `codex plugin marketplace add` for a root you already registered,
first check what is registered and reconcile rather than assuming a clean re-add:

```bash
codex plugin marketplace list
```

After installing, start a **new Codex thread** so the plugin's skills and tools are
picked up.

## 3. Export `CORE_ROOT`

The derived prose references the portable engine as `${CORE_ROOT}`. Codex does not
substitute this — it is a plain shell variable the orchestrator's bash steps expand,
and it propagates to every `codex exec` worker the dispatcher launches. Export it to
the absolute path of the installed plugin's `core/` directory:

```bash
export CORE_ROOT=/abs/path/to/dist/codex/plugins/fr-security-review/core
echo "$CORE_ROOT"   # verify — if empty, every ${CORE_ROOT}/bin/... path breaks
```

The worker read-follow files live at `$CORE_ROOT/agents/{security,security-recon,security-refute}.md`.

## 4. Resolve models

The wave dispatcher tiers workers into `{high, fast}` (trust-boundary waves on
`high`, mechanical data-flow waves on `fast`). Discover and pin the tier map:

```bash
codex debug models                               # inspect what your account exposes
python3 "$CORE_ROOT/bin/shared/model_resolver.py" \
  --discovery-cmd "codex debug models" \
  --review-root security-review-codex
```

This writes `<review_root>/.model_map.json`, reused on re-runs (pass `--remodel`
to re-resolve). It is non-interactive by default; add `--interactive` to confirm or
override the proposed tiers at a stdin checkpoint.

## 5. Run an audit

Start a Codex session (or `codex exec`) and invoke the orchestrator skill
(`security-project` or `security-changes`). The skill runs recon → wave planning →
external-process fan-out (one `codex exec -m <tier>` per slice, ≤6 concurrent) →
dedupe, writing artifacts under the review root you choose. Recon and each worker run
as independent `codex exec` processes that **read and follow** the bundled
`$CORE_ROOT/agents/<role>.md` file — Codex has no named agents, so role prose is
delivered as a file, not a `--agent` handle.

## 6. Updating during local development

The build is byte-deterministic, so rebuilding `dist/codex/` does **not** by itself
make an already-installed Codex plugin pick up changes. To iterate, bump the plugin
manifest's Codex cachebuster suffix **in place inside the already-registered bundle**
and reinstall from the same marketplace name. `dist/codex/` is gitignored, so dirtying
its `plugin.json` never touches the committed authored source (`harness/codex/plugin.json`
stays a clean semver — the next `--mode=write` regenerates the dist copy):

```bash
# bump the cachebuster on the SAME path you registered in step 2
python3 ~/.codex/skills/.system/plugin-creator/scripts/update_plugin_cachebuster.py \
  /abs/path/to/dist/codex/plugins/fr-security-review
codex plugin add fr-security-review@fractalizer-marketplace
```

Do **not** bump the cachebuster on a separate copy: `codex plugin add
<plugin>@<marketplace>` reinstalls from whatever path the marketplace name was bound
to at `codex plugin marketplace add` time (step 2), so a bump on any other path is a
no-op. Then start a new thread to test the updated plugin.

## Permissions & offline posture

Codex has no `opencode.json`-style permission file. The security posture rests on the
`codex exec` sandbox the dispatcher uses:

- **`-s workspace-write`** — workers may write only their worktree plus the explicit
  `--add-dir <review_root>` (the review root lies **outside** `project_root` in a
  composite repo, so `workspace-write` would otherwise deny the wave-file write).
- **Approval defaults to `never`** headless — no interactive prompt to hang on.
- **No network** — `codex exec` under `workspace-write` has no `webfetch`/`websearch`
  surface and network access is disabled by default; the methodology is static and
  offline, matching the OpenCode sibling's `webfetch/websearch: deny` promise. Verify
  this default in your Codex config before a hostile-repo audit.
- **Read scope of `$CORE_ROOT`** — each worker must *read* `${CORE_ROOT}/agents/*.md`,
  `${CORE_ROOT}/bin/*.py`, and the checklists, which live **outside** `project_root`
  and `review_root`. If your Codex `workspace-write` sandbox restricts reads to the
  workspace + `--add-dir` roots (rather than allowing full-disk read), add
  `--add-dir "${CORE_ROOT}"` to each dispatch template so workers can open the engine.
  On a default 0.135.0 install reads are unrestricted, but confirm this before the
  first fan-out (it is the first thing the live smoke checks).

**Residual:** run the audit only against code you trust, in a trusted environment;
recon may execute the project's own console (`bin/console`) for enrichment. For a
hostile-repo audit pass `--no-console` and consider a sandbox.
