# fr-audit-triage

Turns a `fr-security-review` audit's `findings.json` into deduplicated, code-verified units of work grouped by fix pattern — with a triage bucket for leads (`needs_validation`) and non-actionable observations (`hardening`), full traceability in `INDEX.md`, and an optional, structured verdict hand-back into the audit's own cross-run memory.

## Status

**`bin/` implemented; not yet run live end to end by the orchestrator prompt.** `bin/parse_findings.py` (load/coverage/bundle) and `bin/build_index.py` (INDEX.md + the verdict hand-back) are implemented, stdlib-only, and covered by their own `unittest` suite under `bin/tests/` — including a run against a REAL `findings.json` produced by `fr-security-review`'s own `dedupe_findings.py` CLI, and a real round-trip through that CLI's `--verdicts-in`. What's still open: an actual `/fr-audit-triage:triage-findings` run driven by Claude Code itself (Phases 2/4/6 are LLM judgment work — grouping, verification, adversarial review — that only a live orchestrator run exercises, not a unit test).

## Claude Code only

Unlike `fr-security-review`, this plugin is **not** part of the multi-environment build (`build/`). It relies on native parallel `Task` subagents (Phase 4 batch verification, Phase 6 independent review) and on ad-hoc MCP tracker tools, neither of which the Codex/OpenCode derivation currently supports. The build tooling under repo-top `build/` knows about exactly the five `fr-security-review` artifacts; adding this plugin to it is a separate, later piece of work, not something this package does.

## Prerequisite

An audit run from `fr-security-review` that produced `<review_root>/findings.json` (the schema-versioned, machine-readable export — present from the point `fr-security-review` started shipping it; older audit runs need to be redone). This plugin reads that file via `json.load` — never by regexing `REPORT.md`/`REPORT/*.md` — and refuses noisily on a missing or mismatched `schema_version` rather than guessing a different shape.

## Usage

```
/fr-audit-triage:triage-findings [label|path]
```

Same label convention as `fr-security-review`: a bare label (`claude`, `codex`, …) resolves to `security-review-<label>/`, and the output lands in the matching `security-tickets-<label>/` so runs against different audit engines don't collide. A full path is used as-is.

## Configuration

Copy [`.audit-triage.example.json`](./.audit-triage.example.json) to `<project_root>/.audit-triage.json` and add it to the project's `.gitignore` — it names your tracker queue and internal conventions, which this plugin deliberately ships no defaults for. If the file (or a field in it) is missing, the command asks instead of guessing. Leave `tracker.tool_prefix`/`tracker.cli_command` empty to run file-only: unit files and `INDEX.md` are still produced in full, but no tracker reads/writes are attempted.

The config's `trust_model` block answers a short mini-interview once per project (are internal calls trusted, does the ingress own `X-Forwarded-For`, is debug mode on in prod, is `.env` deploy-generated) — the answers pre-calibrate severity downgrades and are recorded as `condition_keys` instead of free text, which is what makes the calibration reproducible across runs and across audit engines. `condition_keys` is the same closed 7-value enum `fr-security-review` defines in `security-review/checklists/_meta.md`; the two plugins must be kept in sync the same way the audit plugin's own `sink_kind`/`root_cause_family` enums are (see that project's `CLAUDE.md`).

## Output layout

```
security-tickets-<label>/
  .gitignore              # content: *, written on first run (never touches the project .gitignore)
  <severity>-NN-<slug>.md # tracker-ready units of work
  INDEX.md                # traceability: finding -> unit, per-location verification status, severity history
  .work/
    parsed.json             # Phase 1: parse_findings.py's persisted Record list + findings_json_sha256
    grouping.json           # Phase 2: {unit_id: [record_id, ...]}, written by the orchestrator
    bundles/<unit>.md       # Phase 3: parse_findings.py's per-unit bundle (constituent finding bodies)
    verify/<unit>.json      # structured, non-free-text verification metadata per unit
    verdicts.json           # --verdicts-in payload for fr-security-review, see below
    TRACKER_DEDUP.md        # only when tracker filing was actually run
```

`security-tickets-*/` and `.work/` describe real vulnerabilities in a real codebase — the command protects them the same way `fr-security-review` protects its own `<review_root>`: a local `.gitignore = *` plus `git ls-files`/`git check-ignore` checks (see `commands/triage-findings.md` Phase 0.3, mirroring `security-review/commands/security-project.md` step 0.5/1).

## The verdict hand-back

`fr-security-review`'s `dedupe_findings.py --verdicts-in=<path>` accepts a fail-closed feedback file so a triage verdict (false-positive / reaffirmed) is remembered across audit re-runs instead of re-litigated every time. This plugin cannot invoke that script itself — it has no path into the audit plugin's own `${CLAUDE_PLUGIN_ROOT}` — so it only **produces** `.work/verdicts.json` in the accepted shape (`schema_version`, `findings_json_sha256`, and a `verdicts[]` list of `{sink_hash, verdict, source, condition_keys?, refute_file?, refute_line?}` — structural fields only, no free text) and prints the command for the user to run against their `fr-security-review` install. There is deliberately no reverse dependency: the audit plugin knows nothing about this one.

## License

Elastic License 2.0, same as the rest of this marketplace — see the root [`LICENSE`](../LICENSE) and [`README.md`](../README.md#license).
