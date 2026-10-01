# Changelog

All notable changes to this plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.2.0] — 2026-10-01

### Added

- **`hardening` notes that carry a precondition are flagged.** A `hardening` record whose `condition_keys` include `needs_trusted_integration_compromise`, `internal_network_only`, `admin_only`, `deployment_control_not_in_source` or any `other:` key contradicts its own verdict: a precondition means someone is affected once it holds. Dedupe now adds `[HARDENING_WITH_PRECONDITION]` to the record's `flags` in `findings.json` (additive, `schema_version` stays 1), explains it under the record (in REPORT.md, or in the per-family detail file for a note attached to a finding), and counts such notes in the summary. The verdict itself is not changed — the flag is a pointer for the operator; `fr-audit-triage` shows it in its bundle manifest and INDEX.md but does not act on it yet. The flag fires on every `other:` key, wider than the worker rule, because a worker invents an `other:` key precisely to rename a precondition.

## [5.1.2] — 2026-10-01

### Fixed

- **A precondition no longer passes for "no victim".** Workers kept filing real findings as `hardening` by recasting the trust assumption ("the repository models a single principal") or by tagging the note with a precondition key. The worker prompt now states that a shared credential does not merge its distinct callers into one principal, that changing a resource another caller created (its lifetime, attribution or ownership) affects that resource, and that `hardening` never carries `needs_trusted_integration_compromise`, `internal_network_only`, `admin_only`, `deployment_control_not_in_source` or an `other:` key naming such a precondition — admin and integration credentials leak too, so such a finding is `confirmed` with the key, or `needs_validation`. The admin-endpoint `hardening` example no longer carries `admin_only`, and `checklists/_meta.md` no longer says severity separates `confirmed` from `hardening`.

## [5.1.1] — 2026-09-29

### Fixed

- **Workers no longer file real findings as `hardening`.** The worker prompt said "Severity ≥ MEDIUM separates `confirmed` from `hardening`", which read as "low impact → `hardening`" and contradicted the bucket's definition (no victim at all). It now states that a real finding with a victim is at least Medium, and that "no principal or resource is affected" may not rest on a trust assumption about who holds a credential or reaches an interface (that is a `condition_keys` precondition, or `needs_validation`), nor on the project's own documents calling the behavior accepted. This matters because `fr-audit-triage` never turns a `hardening` note into a work unit: a misfiled real finding is lost downstream.

## [5.1.0] — 2026-09-29

### Every report says what produced it

#### Added

- **Run snapshot.** Wave planning writes `<review_root>/run_info.json` (`plan_waves.py --save-run-info`, new module `bin/run_info.py`): plugin version, harness (`claude` / `codex`, plus the Codex bundle version), orchestrator model, the model of each tier and the waves planned on it, and on Codex the reasoning effort and `model` from `config.toml`. On Claude the tiers are recorded as the `opus` / `sonnet` aliases the harness resolves; the orchestrator id comes from `--orchestrator-model` when the orchestrator knows its exact id, else `unknown`. On Codex the tier ids come from `.model_map.json` and the orchestrator id from `frsr`.
- **`## Run` in REPORT.md and a top-level `run` block in `findings.json`**, read from the snapshot. `findings.json` stays `schema_version` 1 (the key is additive). Dedupe never re-derives the snapshot, so re-running it after triage from another 5.1+ plugin tree keeps the attribution and the bytes of `findings.json`. A review root without a snapshot (or with an unreadable one, with a warning) reports `Run metadata: not recorded`; the first 5.1 dedupe over a pre-5.1 review root therefore adds `run` and changes the bytes once, which a triage bound to the old `findings.json` sees as stale.
- **The Codex build stamps `core/build_info.json`** (harness, engine version, bundle version); the snapshot tells the harness from it, never from the presence of `.model_map.json`.
- **`frsr` prints both tiers and the reasoning effort in effect**, and warns (without stopping) when the high tier differs from `model` in the Codex `config.toml` (`$CODEX_HOME` or `~/.codex`; a selected `profile` overrides the top level). The config is read with `tomllib`; on Python < 3.11 (e.g. macOS `/usr/bin/python3`) both values are `unknown` and nothing is compared. It exports `FR_SECURITY_ORCHESTRATOR_MODEL` for the snapshot.

#### Changed

- `model_resolver.py --describe` also reports the `fast` id.
- `## Estimated cost` (priced on Anthropic tiers) is omitted for a Codex run.

## [5.0.0] — 2026-09-29

### Fewer mechanisms: one audit mode, one derived harness, no self-refute; recon gaps become a wave instead of a stop

A simplification release. Mechanisms without a proven payoff are removed, false-positive filtering moves to `fr-audit-triage`, and a recon that could not collect or interpret something no longer stops the run — the uncovered files get their own review wave instead.

#### Removed

- **The diff-only audit mode.** The `/fr-security-review:security-changes` command, its Codex skill and section templates, the changes-mode rules in the worker and recon agents, `plan_waves.py --diff-files` / `--extra-target-files`, `recon_inventory.py --diff-files`, the per-item `touched_by_diff` key, and the diff-only helpers `diff_removed_defenses.py` / `map_consumers_to_waves.py`. Run `/fr-security-review:security-project` (optionally with `--scope=<glob>`) instead.
- **Recon reuse.** `--skip-recon` / `--force-skip-recon`, the `project_fingerprint` / `code_fingerprint` frontmatter keys and the `scope` key. Every run does a fresh recon.
- **Legacy v1 detection.** The orchestrator no longer probes for `SECURITY_CONTEXT.md`, and `validate_context.py` drops its v1 section map.
- **The adversarial refute pass.** The `security-refute` agent, the orchestrator's refute step, `--no-adversarial`, `dedupe_findings.py --refute` (now an argparse error), `refute.md`, the `[REFUTE_CLAIMED]` flag and the refute summary block in REPORT.md. The verdict channel `--verdicts-in` and the remembered-verdict journal stay; its wire keys `refute_file` / `refute_line` keep their names.
- **The cross-run New / Recurring / Closed diff.** REPORT.md loses its `Diff vs previous run` block, `REPORT.prev.md` is no longer kept, and `.findings_state.json` no longer stores the finding snapshot, `baseline` or `run_id`. A repeated render over the same waves is now byte-identical.
- **The OpenCode harness.** `build.py --harness=opencode`, `make build-opencode` / `install-opencode`, `scripts/install-opencode.sh`, `harness/opencode/` and the OpenCode bundle. Codex is the only derived harness.
- **The static Symfony config parser.** Without a `debug:config` tree, recon no longer reads `security` / `framework` / `twig` values out of yaml (see Changed for what it does instead).
- **`config/bundles.php` alias gating.** The console is asked for every config alias; see Fixed.
- **php/xml env-conditional detection.** Env-conditional blocks in php and xml config no longer set the prod/dev override flags; the files stay evidence. yaml `when@<env>` blocks and `config/packages/{dev,prod}/` keep flagging.
- **The `languages` checklist layer** (it had no files). The resolver is now four layers: `core → stacks → addons → integrations`.
- **Model discovery and auto-proposal** in `bin/shared/model_resolver.py` (`--discovery-cmd`, `--interactive`, `--remodel`), the `provenance` field of `.model_map.json`, and `model_discovery_cmd` / `tier_defaults` / the model gate in the Codex `adapter.json`.
- **The unused `recover_capture` hook** of `bin/shared/dispatch.py` and its refute role; `recon` is the only dispatched role.

#### Changed

- **Sanity warns instead of stopping.** `validate_context.py --sanity` exits non-zero only for a structurally invalid CONTEXT.md. Coverage gaps, extractor failures, uninterpreted config and list sections left in `pending_enrichment` are `WARNING:` lines plus records in `<review_root>/recon_gaps.json`, written by the new `--gaps-out` flag (`schema_version: 1`; empty `items` when there is nothing). Sections without a sanity probe fall back to the recipe's new `SOURCE_ROOTS` glob (the whole project for generic PHP, so code outside `src/` / `app/` reaches the gap list too). A `coverage` record carries `declared` (filesystem matches the inventory lists), `found` (filesystem matches) and `missing_pct` (missing / found). The orchestrator's repeat-recon prompt is gone; the recon agent gets one attempt to fix hallucinated paths.
- **New always-on `WGAP` wave.** `plan_waves.py --recon-gaps` (default: `recon_gaps.json` next to CONTEXT.md) turns the gap files into `WGAP_PART<n>` slices on opus: they survive `--quick`, honour `--scope`, skip files another slice already carries and are capped at 150 files. A worker on a `WGAP_` slice reads `recon_gaps.json` first. No gap records → no WGAP slices.
- **`## Coverage Gaps` shows what was and was not routed to review.** `dedupe_findings.py` reads `recon_gaps.json` and, with `--waves-plan`, splits each entry's files into routed to review (in some slice's `target_files`, WGAP or a focused wave; whether that slice ran is not checked) and NOT routed (cut by the cap, `--scope` or the vendor/tests filter). Without a plan the line says the review status is unknown; `fr-audit-triage`'s re-render command now passes `--waves-plan` as well.
- **`--no-console` means config is not interpreted.** Recon interprets framework config only through the booted console. Without a tree the config sections come back `partial` (`auth_layer` stays `pending_enrichment`) with the reason `config_uninterpreted: <alias>: <no_console|console_failed|console_unsupported|tree_mismatch|env_mismatch>`, and their files are routed to the focused waves (the security config to W1), which read the config directly; WGAP gets only gap files no other slice carries. `console_unsupported` means a console that boots but is older than Symfony 6.3, which rejects `debug:config --format=json`; recon also adds a `console_unsupported:` warning naming the console's version. The route → firewall / `access_control` mapping is no longer precomputed in that case. The tree-vs-file mismatch check is kept for `security` only; `twig.yaml` is evidence only when it sets `autoescape`, so a default project keeps an `ok` `twig_overrides`; `.env` is listed in `secrets.source_files` only when it exists; `secrets.password_hasher` is `unknown` without a tree.
- **`plan_waves` routes the `source_files` of `pending_enrichment` scalar sections**, so an `auth_layer` the recon agent never enriched still puts the security config into W1. `unknown` sections are not routed: a probed list section's filesystem matches reach WGAP through `recon_gaps.json`, a scalar `unknown` section's `source_files` reach no worker.
- **False-positive filtering is handed to `fr-audit-triage` 0.4.0.** The final output points to `/fr-audit-triage:triage-findings` on `findings.json`. The triage verifier gains Principle 14 — the grounds that can never close a finding (no caller, admin-only source without cross-tenant analysis, a validator without bypass analysis, defense-in-depth reasoning) and the ones that can (a cited in-code control or an enforced config/deployment restriction) — and `build_index` rejects a cited evidence line that is a comment.
- **The "Previously rejected" note names the verdict source** next to the evidence `file:line`.
- **Codex model tiers come only from `--models high=<id>,fast=<id>`** (both required). The map is saved to `.model_map.json` and reused; with neither, the run stops with a `codex debug models` hint. Model ids are not validated. A map a pre-5.0 build wrote (it carries a `provenance` key, whatever its value: 4.x recorded `cli` even for a map with one auto-proposed tier) is ignored with a message, so `--models` is needed again. `model_resolver.py` gains side-effect-free `--check --models <spec>` and `--describe --review-root <dir>` modes.
- **`frsr`:** `--help` / `-h` works anywhere before `--` and has no side effects; every argument is validated before anything is written or run — including `--review-root`, refused like the orchestrator's step 0.3 (the project root or any ancestor of it, a non-directory, a path inside the project not named `security-review*`, a source-tree name such as `src`) — and the model map is saved only with `--go`. The `project` subcommand is optional. Unknown options before `--` are an error — orchestrator flags go after it (`frsr project -- --quick`). `frsr changes` and `--harness opencode` fail with an explanation.
- **`exclude_paths_user` frontmatter list.** Recon records the user's excludes as a structured list, which sanity uses to keep excluded files out of `recon_gaps.json`; the human-readable warning line stays.
- **`recon_confidence` is display-only.** Its level is no longer cross-checked against the ceiling or coverage.
- **Codex build: one section layer.** Each Claude artifact is split into sections; a section is replaced iff `harness/codex/sections/<artifact>/<anchor>.md` exists, the rest get frontmatter handling and token substitution, and a leak gate on the output plus a list of required templates (`derive.REQUIRED_TEMPLATES`; a missing one, or a template directory naming no artifact, fails the check) replace the completeness guards. The leak gate also catches `Task( subagent_type=` spacing and `Agent(subagent_type=`. Each template carries a `source-sha256` header of the Claude section it was written against; a changed section fails the check until the template is reviewed and `python3 build/build.py --mode=refresh-hashes` records the new hash. The Claude byte-identity gate (`--harness=claude`), the token partitioner, `PROSE_COUPLING.md` and `TOKENS.md` are gone. The derivation refactor itself changed no bundle byte.
- **Laravel's class extractor runs once per inventory** instead of twice.

#### Fixed

- **A project whose `config/bundles.php` is not a plain literal map (e.g. an empty stub with a custom kernel registering the bundles) no longer loses its console config.** `debug:config` was skipped for every alias; it is now asked for all of them, and a failure warning is suppressed only when the alias has no config evidence at all.
- **Laravel extractor failures are visible.** A timed-out or crashed class extractor left `attack_surface`, `data_access`, `policies`, `service_providers`, `form_requests` and `routes_authz_matrix` as `ok` with a short list; they now go `partial` (`routes_authz_matrix` only when it lists anything: with no route files it stays `none`) with `extractor_failed: class: <cause>`, and sanity reports the cause as it does for Symfony.
- **`--verdicts-in` rejects evidence it cannot locate:** the `nohash00` sink hash, absolute or `..` evidence paths, and an evidence line that is missing, blank or whitespace-only (its hash would never change, so the rejection would never lift).
- **`console_unsupported` fires on a real Symfony < 6.3 console.** The old check matched the last stderr line, but Symfony prints the command synopsis after an input error; recon now reads the console's `--version` once when `debug:config --format=json` fails and treats `< 6.3` as unsupported (the option-error sentence still counts when it survives). A newer console failing for another reason stays `console_failed`.
- **`frsr` and the orchestrator refuse a `--review-root` that contains the project** (`--project-root=api --review-root=.` would have written every artifact over the monorepo root). `frsr` now validates `--models` and reads the saved map through the bundled resolver, so its verdict cannot drift from the resolver's (unknown or duplicate `--models` keys are rejected in the preview, and a pre-5.0 map is reported as such).
- **The recon agent passes `--project-root` to its sanity call**, so composite repositories no longer skip the coverage check.
- **Remembered rejections survive in composite repositories.** The orchestrator passes `--project-root` to dedupe; without it dedupe re-checked the evidence against cwd and silently dropped them, and it now warns when the flag is missing and remembered rejections cite code.
- **A Codex wave recovered by the orchestrator's safety net no longer marks the report INCOMPLETE:** dedupe drops a dispatch gap whose wave file exists and parses.
- **A corrupt `.findings_state.json` is no longer silently replaced:** dedupe warns and moves it aside to `.findings_state.json.corrupt` before writing a fresh journal.
- **The Codex `adapter.json` no longer advertises interactive gates** (`interactive_gates: []`, `checkpoint_binding: null`): the headless harness stops instead of asking.
- **`--all-opus` documentation** names the waves it promotes (W4 / W5 / W∞); W3 stays on sonnet.

#### Migration

- **Old review directories stay readable.** A `.findings_state.json` with a schema other than 2 is read as an empty verdict journal with a stderr warning (an unparseable one is moved aside to `.findings_state.json.corrupt`); the remembered verdicts must be fed again via `--verdicts-in`. Schema-2 state files drop their old `findings` / `baseline` / `run_id` keys on the next write.
- **An old CONTEXT.md with fingerprints or `scope` still validates** — extra frontmatter keys are allowed; the next run rewrites it anyway.
- **Removed orchestrator flags are warned and ignored:** `--no-adversarial`, `--skip-recon` and `--force-skip-recon` print a `was removed in 5.0.0 and is ignored` warning and the run continues.
- **Codex:** reinstall the plugin (`make install-codex`, which bumps the cachebuster), pass `--models high=<id>,fast=<id>` on the first `--go` run for each review root (a `.model_map.json` written by 4.x is ignored with a message), and move orchestrator flags after `--` (`frsr project -- --quick`).
- **Diff-only audits:** use `/fr-security-review:security-project`, narrowed with `--scope=<glob>` if needed.
- **False-positive filtering:** run `/fr-audit-triage:triage-findings` on `findings.json` and feed its verdicts back with `dedupe_findings.py --verdicts-in=<path>`.

## [4.5.0] — 2026-09-29

### Recon reads what Symfony actually loaded, not just `config/packages/*.yaml`

Trigger: a project with `security.php` / `framework.php` / `easy_security.php` config had those files silently ignored by every previous release — recon's config readers hardcoded a single canonical YAML filename per alias, so a project that split or wrote its config any other way read as having no security/trust/messenger/twig config at all.

#### Changed

- **Console preflight at the start of every run.** The orchestrator now resolves the console runner and boot-tests it (`recon_inventory.py --console-preflight`) before recon depends on it, instead of discovering a broken console partway through. **Behaviour change:** when the console is required and doesn't boot, a non-interactive run now **stops** with the reason and the exact fix-it flags, instead of proceeding with degraded static-only coverage. CI must pass `--console-cmd=<tpl>` or `--no-console` explicitly, or export `FR_SECURITY_CONSOLE_CMD`.
- **Symfony `security` / `framework` / `messenger` / `twig` config is read via `debug:config --format=json`** (Symfony ≥ 6.3) when the console boots — the processed, merged config tree, regardless of file name, format (yaml/php/xml), or how the config is split across files. Static YAML parsing (today's single-file `config/packages/<alias>.yaml` assumption) is now only the `--no-console` fallback. Multi-file, php/xml, or prod-environment-only config that the fallback can't interpret no longer disappears: it routes into `auth_layer`'s `pending_enrichment` for the recon agent to read and enrich, or leaves the affected `recon_bags` section `partial` with the evidence files still routed to workers via `source_files`.
- **The console is asked per extension alias actually registered, from `config/bundles.php`.** `security` / `framework` / `twig` are only queried when their owning bundle (`SecurityBundle`, `FrameworkBundle`, `TwigBundle`) appears in a plain literal `return [Bundle::class => [...], ...];` map, so a bundle genuinely absent from that map produces no probe-failure noise. When `bundles.php` is missing or isn't a plain literal map (`array_merge`, `require`, bundles added from `Kernel::registerBundles()`, …), every alias is still asked, quietly. Static evidence-scanning (`find_config_evidence`) never gates the console query itself, only which files `source_files` routes to workers — a config form the scan misses (MicroKernel inline config, a bundle's `prependExtensionConfig`) still reaches `debug:config`.
- **Two new recon warnings, alongside the existing `config_env_<env>_only`:** `config_source_files_not_located: <alias>` — the console's tree has content but no on-disk config file could be matched, so nothing could be routed to workers via `source_files`; `config_env_dev_overrides: <alias>` — dev-only overrides exist and shape what a dev-mode console reports.
- **Secrets are never copied out of config into CONTEXT.md.** Both the console and static views redact secret-looking keys (password, DSN, private/client secrets, …) unless the value is a literal `%env(...)%`; `--resolve-env` is never passed to `debug:config`.
- **`secrets.data.candidates[].snippet` values are now masked** (`<redacted:N>`, N = the masked length): a recognizable vendor-key prefix (`sk_live_`, `AKIA`, `ghp_`, `xoxb-`, …) stays visible ahead of the masked span so the recon agent can still tell what kind of credential it is, and the whole userinfo of a DSN-shaped URL is masked. A key only triggers masking when it *ends* in a secret word, so a lookalike option name (`password_parameter`, `csrf_token_id`) never matches in the first place; the two cases that do match but aren't credentials (`access_token`, `csrf_token` — Symfony option names) are explicitly kept visible. `%env(...)%` / `%param%` indirections and unquoted code expressions stay visible regardless; a placeholder (`changeme…`, `<...>`, `xxx…`) is visible only when it is the *whole* value, not merely a substring of it. The enrichment hint tells the agent the masking exists, so it reads the file at `line` instead of judging a redacted snippet as-is.
- **`routes_authz_matrix` marks what it couldn't interpret.** An item whose access control could not be determined now carries `access_control_interpreted: false` instead of being silently dropped or reported as unprotected — unknown is no longer indistinguishable from missing. This fires when the console's tree doesn't reflect what the located config files declare (an env mismatch it can't reconcile, or a form the tree doesn't expose) — `auth_layer` also goes `pending_enrichment` and the affected `recon_bags` section goes `partial` in that case. It's distinct from a tree that still returns content despite a recorded env gap (e.g. dev-only overrides picked up by a dev-mode console): that stays `partial` with the gap as `reason`, but the interpreted values are kept as-is and the matrix is **not** blanked.
- **Emitted config shape changed for `firewalls` / `trusted_config` / `messenger_transports` / `twig_overrides` in CONTEXT.md, on both the console path and the `--no-console` yaml path** (the old flattening parser is retired, not just supplemented on the console side): firewall factory nodes (`form_login`, `remember_me`, `login_throttling`, …) now render as presence (`form_login: "true"`) instead of their children being flattened into sibling keys; a fixed set of security-meaningful nested leaves still render explicitly as `<node>__<leaf>` (e.g. `login_throttling__max_attempts`); `auth_layer.kind` is derived from the parsed config structure, not a text regex, so it no longer matches inside comments; `unknown`/`none` reasons are now specific (e.g. `no <alias> config in scanned config/**`); `trusted_config` may now read `none` in cases that previously read `unknown`. **Console-only:** firewall keys additionally elide values equal to the SecurityBundle default — the yaml path still emits every value it read, since a hand-written file rarely spells out the full option list the way the processed tree does.
- **`config/reference.php` (Symfony ≥ 7.4's auto-generated IDE reference — array-shape docs for every registered extension) is no longer treated as config evidence or a secrets-scan candidate.** It names every alias and option without configuring anything, so it used to look like evidence for any alias and got grepped for secrets it can't contain. Detected by exact path plus the generated-file header, so a hand-written `config/reference.php` still counts.
- **An empty `trusted_proxies` / `trusted_hosts` / `trusted_headers` (`[]`, `''`, `~`) now reads as not configured (`trusted_config: none`) on the `--no-console` yaml path too**, instead of `ok` with the opaque `(list)` marker — matching what the console tree path already reported for an empty/default-valued list.
- **Console enrichment no longer runs `debug:event-dispatcher`, `debug:messenger`, or `list`.** Their output was never consumed, and on Symfony 8 the first two reject `--format` — a failure that surfaced as a warning and dragged `recon_confidence` down to medium on every console-enabled run for no functional reason. `sources_used` no longer carries `console:debug_event_dispatcher` / `console:debug_messenger` / `console:list`; console enrichment now issues exactly `debug:router` (attack surface) and `debug:config` (config introspection).
- **Sanity probes ignore abstract class bases for every class-inventory coverage probe**, not only the ones with a `kind_filter` — fixes a false `declared N of M` abort on projects (e.g. EasyAdmin) with a project-local abstract CRUD/command/listener base. `data_access` is deliberately excluded: an abstract Repository is still a legitimate data-access surface.
- **`jwt_generic_detect`, `oauth_oidc_detect`, `auth0_detect`** now accept `.php`/`.xml` config files for the same basename, not only `.yaml`/`.yml`.
- **`project_fingerprint` now covers `config/services.php`, `config/services/*.php`, and the env subdirectories of `config/packages` and `config/routes`.** A project that has any of these newly-globbed files will see its existing CONTEXT.md's fingerprint mismatch once: `--skip-recon` asks for a full recon on the first run after upgrading, then is stable again.

#### Fixed

- **Hidden directories (`.cache/`, `bin/.phpunit/`, IDE dotfolders, …) are never walked by the extractor or the recipe's own file scans.** Reproduced on a real EasyAdmin project: a PHPStan result cache and phpunit-bridge PHPUnit copies added ~30k extra PHP files in front of the extractor, timing out every kind before it reached `src/` — `http_route_admin` read 0 of 52 CRUD controllers, with CLI commands, repositories, and listeners equally missing. Pruning is a single always-on rule (basename starts with `.`), independent of `--exclude`/`EXCLUDE_PATHS`, applied in the PHP extractor's walk, the Symfony recipe's own `_list_php_files` / `_list_config_files` / entity listing, `find_config_evidence`'s `config/**` scan, and the sanity coverage glob. The extractor follows symlinks (a `src -> .build/src` source root is walked), and the hidden-directory rule judges the *walked* name, not the link's target, so a symlinked root isn't itself pruned just because its target path has a dot-segment; a visited-realpath set stops it walking any directory twice (a link cycle, `a -> .`), and every directory is checked against the same project-root escape guard already used for files.
- **An extractor call failure no longer reads as `status: ok` with silently-missing items — and is now loud, not just `partial`.** `attack_surface`, `data_access`, `voters`, `forms`, `serializer_groups`, `doctrine_listeners`, `routes_authz_matrix`, and the EasyAdmin/Sonata CRUD bags now turn `partial` with an `extractor_failed: <kind>: <warning>` reason when their underlying `--kind=` call times out, exits non-zero, or returns bad JSON — previously `attack_surface`/`data_access` stayed `ok` with an under-populated item list, and the rest read `unknown` with no indication *why*, inviting the recon agent to invent a cause. `partial` skips the sanity coverage-diff ratio, but `validate_context.py --sanity` now ERRORs on the failure directly (`sanity[extractor]: <section> not collected — extractor_failed: <kind>: <warning>`), and `recon_confidence.level` drops to `low` — this is surfaced, not swallowed. Within one recon run, the *first* extractor timeout latches: every later `--kind=` call is skipped without spawning (`skipped after earlier timeout`), so a slow/huge project pays for one timeout total, not one per kind.
- **Extractor timeout raised 60s → 180s**, overridable per-run via `FR_SECURITY_EXTRACTOR_TIMEOUT` (seconds). 60s was tuned against a much smaller corpus than the hidden-directory fix now exposes as normal — even correctly excluded, a large project's directory tree costs real wall-clock to enumerate on a loaded machine.

## [4.4.1] — 2026-09-23

### A finding's checklist path no longer carries the auditing machine's install prefix

### Fixed

- **`findings.json`'s `discovered_via`, finding bodies in `REPORT/<root_cause_family>.md`, standalone `## Needs validation` / `## Hardening notes` entries in `REPORT.md`, and `REPORT.md`'s `## Checklist coverage` no longer leak the plugin install path.** A checklist path is only meaningful from its `checklists/` anchor onward, but all four places carried it as the worker or the wave plan wrote it — including the absolute prefix of wherever the plugin happened to be installed. This showed up whenever the wave plan consulted for `## Checklist coverage` was built by a different install than the one rendering the report: the absolute path didn't match either install's root, so it was left untouched. The same normalization now also fixes the per-checklist finding counts in that section, which silently read zero for every checklist under the same mismatch.
- **A standalone `## Needs validation` / `## Hardening notes` entry now shows "Previously rejected" when its `sink_hash` carries an active rejection**, as a confirmed finding already did — including one bound to a finding without a hash match. `--verdicts-in` and refute store rejections for those hashes too, but the report never showed them, so a settled lead read as open on every re-run.

## [4.4.0] — 2026-09-23

### Recon survives the configs it did not model; bucket records find their finding

Six defects surfaced by a live control run, none of them introduced by the verdict-bucket work they were found alongside. Four of them ended an audit or silently narrowed what a worker was told; two made a report say something that was not true.

### Changed

- **A verdict-bucket record binds to a confirmed finding by sink, not by quoted text.** `needs_validation` / `hardening` records were bound only when their `sink_hash` matched, and `sink_hash` is computed from the worker's `sink_snippet` — so two workers quoting one sink slightly differently produced a finding plus a separate bucket row for the same place. Binding now falls back to `dedupe()`'s own merge keys, so a record binds exactly when `dedupe()` would have merged it had it been `confirmed`; a record bound that way carries `[ATTACHED_WITHOUT_HASH]` and REPORT.md says the binding was by location rather than by text. `findings.json` keeps its shape and `schema_version` — `matched_to` is now best-effort and the flag carries the stricter reading.

### Fixed

- **`access_control` parsing no longer aborts the whole audit.** The flow-mapping splitter in `bin/recon/recipes/symfony.py` counted brackets but not quotes, so a quoted CIDR list (`ips: '127.0.0.0/8,::1,10.0.0.0/8'`) was cut into fragments and `::1` became an empty key — which `bin/recon/yaml_emit.py` rejects, failing recon and with it the run. Quote handling is now shared by every layer that scans this text: comma splitting, brace nesting in a multi-line `- { … }` rule (a quoted `}` used to end the rule early and drop it), and escaped quotes inside double-quoted scalars.
- **One unmodelled YAML construct no longer costs the whole recon.** Rules parsed out of `security.yaml` are filtered against the CONTEXT.md emitter's key contract before they reach it, so a merge key (`<<: *common`) or any other construct the line parser does not model costs that key and a warning instead of the entire inventory.
- **YAML anchors and aliases in `access_control`.** A leading `&name` is stripped from the value instead of being carried into CONTEXT.md, and a whole-value `*name` alias resolves to its anchor's scalar. Resolution is positional — only anchors defined above the alias are eligible — so a name redefined later in the file cannot widen an address range a worker reads. Anchors on mapping / sequence / block-scalar nodes are not collected, and an unresolved alias stays literal rather than becoming a wrong value.
- **`.claude/` is excluded from the extractor walk.** A coding agent's git worktree parked under `.claude/worktrees/` was read as a second copy of the project tree, doubling every inventory counter and tripping the recon sanity gate. The Python and PHP copies of `DEFAULT_EXCLUDE` are now checked against each other by a test rather than by a comment.
- **`## Diff vs previous run` no longer diffs a run against itself.** The dedupe pass that follows adversarial refute (and any other re-render over the same wave files) reported every finding as recurring, because it compared against the snapshot the run's own first pass had just written. A run is now identified by its wave files, and a pass over the same ones inherits the baseline of the first instead of rotating it. `.findings_state.json` gains `baseline` and `run_id` as additive keys — the schema version deliberately does not move, so a rollback to an earlier build still reads the file and keeps the accumulated `resolutions` journal.
- **`console_gap_reason` distinguishes an operator's choice from an unresolved runner.** The Codex orchestrator templates passed `--no-console` when a containerized project supplied no `--console-cmd`, so the recorded reason read as `console_disabled_by_flag` although no flag had been passed; they now pass no flag, as the OpenCode templates already did, and the utility records `env_runner_unknown: containerized project …`. REPORT.md additionally spells the flag reason out in prose.

## [4.3.0] — 2026-09-21

### Verdict buckets, `findings.json`, cross-run memory

Workers no longer report only exploitable vulnerabilities. Each wave file now carries three verdicts — `confirmed` (the existing severity/confidence-gated finding), `needs_validation` (a traced path blocked on a fact outside the repo, e.g. "is this endpoint actually internet-facing"), and `hardening` (a traced observation with no affected principal or resource). Neither bucket carries severity or confidence; recall-first philosophy is unchanged. A `<!-- wave_format: 2 -->` marker as the first non-empty line of a wave file signals the new format; older wave files without it still parse under the legacy rules.

#### Added

- **`needs_validation` / `hardening` verdicts** in the worker contract (`agents/security.md`) and the wave-file parser (`bin/dedupe/parser.py`). Bucket records that share a `sink_hash` with a `confirmed` finding render as an annotation on it; unmatched records render in their own `## Needs validation` / `## Hardening notes` sections, index-`REPORT.md`-only.
- **`<review_root>/findings.json`** — a `schema_version`-gated public inter-plugin contract (`bin/dedupe/export.py`) listing every constituent finding across all three verdicts, including findings absorbed into a `MergedFinding.merged_from` group. No field varies run-to-run for unchanged inputs.
- **Cross-run verdict memory.** `<review_root>/.findings_state.json` moves to schema 2: alongside the existing New/Recurring/Closed snapshot, it now persists a `sink_hash → Resolution` map (adversarial-refute and `--verdicts-in` verdicts) as a read-modify-write merge, so a previously rejected finding is annotated "Previously rejected" instead of re-litigated on every run (a `reaffirmed` resolution cancels a prior rejection for the same `sink_hash` and renders nothing). The mark is invalidated by re-hashing the cited evidence location's normalized content, not its path — if the referenced protection code changes, the mark silently drops.
- **`dedupe_findings.py --verdicts-in=<path>`** — folds externally-produced verdicts (e.g. from a ticket-triage plugin) into remembered resolutions. Fail-closed: validated by content hash against the review root's pre-existing `findings.json`; any schema violation, unknown field, unknown `sink_hash`, duplicate, or stale hash aborts the whole run before any output is written. Requires cross-run state (incompatible with `--no-state`).
- Adversarial refute only ever considers `confirmed` findings — `needs_validation` and `hardening` are excluded from the refute slice the orchestrators build, since refute looks for blocking code in the repo and `needs_validation` is, by definition, blocked on a fact outside it.

#### Fixed

- **`bin/dedupe/parser.py` snippet truncation on `# TODO`.** `_extract_snippet_block` stopped a block scalar early on any line matching `^#+\s`, so a `sink_snippet` containing a `# TODO` PHP comment at column 0 was silently truncated — and `sink_hash`, computed from the truncated snippet, diverged from the same finding reported without the comment. Fixed; regression-tested.

## [4.2.0] — 2026-07-03

### Multi-environment support

The same audit engine now runs on **Codex CLI** and **OpenCode** in addition to Claude Code. The Claude behaviour is byte-for-byte unchanged; the secondary harnesses are **derived** from the Claude-authoritative command/agent prose by a build, so there is a single source of truth and no parallel implementation to drift. See [`harness/codex/INSTALL.md`](../harness/codex/INSTALL.md) and [`harness/opencode/INSTALL.md`](../harness/opencode/INSTALL.md) for install and model-setup on each harness.

On Claude, fan-out stays native `Task(model=…)` in batches of ≤6. On Codex/OpenCode the same waves fan out as external `codex exec -m <model>` / `opencode run -m <model>` processes (one per slice, ≤6 concurrent), because neither harness supports reliable in-process subagents. The worker→file contract (`<review_root>/waves/<slice_id>.md`) and the recon/plan/dedupe Python are identical everywhere.

#### Added

- **`bin/shared/` runtime helpers** (stdlib-only, ships with the plugin; Claude does not use them — they are the foundation the Codex/OpenCode derivations invoke as staged stage-commands).
  - **`model_resolver.py`** — model resolution as `discover → propose → confirm → persist` a `{high, fast}` tier map. Discovery is harness-shape-sniffed (`codex debug models` JSON vs `opencode models` lines); proposal ranks by capability signals (fast-first); the chosen map persists to `<review_root>/.model_map.json` and is reused on re-run unless `--remodel`. Non-interactive by default; `--models=high=<id>,fast=<id>` bypass; an unresolved tier fails loudly instead of silently picking. The Claude path returns the static `{high: opus, fast: sonnet}` and never persists.
  - **`dispatch.py`** — bounded external-process wave dispatcher (≤6 concurrent) plus a single-process `dispatch_role` for recon/refute. Planned wave files are deleted before fan-out, so a stale prior-run file plus a crashed worker is still counted as a gap (`timeout` / `crash` / `missing_write` distinguished). `--allow-gaps` writes `dispatch_gaps.json` and marks the run degraded instead of aborting the whole fan-out on one failed worker.
  - **`contracts.py`** — typed seams (`Roots`, `RunResult`, the runner/builder callables, typed exceptions). Subprocess is the single injected seam, so tests never spawn a real `codex` / `opencode`.
- **`dedupe_findings.py --dispatch-gaps=<path>`** — folds wave-dispatch gaps into REPORT.md's `## Coverage Gaps` (alongside the existing `console_gap`) and surfaces a prominent **INCOMPLETE** marker. With recorded gaps but zero wave files it renders a minimal INCOMPLETE report instead of erroring out.

#### Changed

- **`agents/security-recon.md` input contract** documents the harness-neutral `key=value` → `recon_inventory.py` flag mapping (e.g. `console_mode=off` → `--no-console`). The Codex/OpenCode recon dispatch passes flag-free `key=value` inputs to avoid a leading-`--` collision with the worker CLI's own option parsing; the agent is now the single documented source of that mapping.

#### Fixed

- **`bin/shared/dispatch.py` feeds workers EOF stdin** (`stdin=DEVNULL`). `codex exec` reads additional prompt input from stdin, so a fanned-out worker that inherited a non-EOF orchestrator stdin would block forever. Harness-neutral (a non-interactive worker must never read stdin); OpenCode is unaffected.

## [4.1.0] — 2026-05-23

### Environment-aware console enrichment

Recon no longer blindly runs `bin/console` on the host. It probes the project's execution environment first and, when the project runs inside a container (where host execution distorts the environment), asks the user how to run the console instead of silently degrading.

#### Added

- **`--console-cmd=<template>`** flag on `/security-project` and `/security-changes` (and `recon_inventory.py`). An explicit command for running the project console, e.g. `--console-cmd="docker compose exec -T php php bin/console"`. Supports a `{args}` placeholder for Makefile-style passthrough (`make console CMD={args}`); otherwise the subcommand is appended.
- **`bin/recon/environment.py`** — a standalone, stdlib-only environment probe (`--probe`). Detects containerization signals (`docker-compose.y*ml`, `Dockerfile`, `.ddev`, `.lando.yml`, `laravel/sail`, `.devcontainer`), host PHP presence/version, the PHP service in a compose file, and Makefile console targets (with their recipe body, for transparency). Emits ready-to-confirm runner suggestions. Never executes project code.
- **`environment` frontmatter block in CONTEXT.md** — records `containerized`, `container_signals`, `host_php_present`, `host_php_version`, `console_mode` (`host|container|custom|disabled`), `console_gap`, and `console_gap_reason`. Optional and backward-compatible (pre-4.x contexts still validate).
- **`## Coverage Gaps` section in REPORT.md** — when console enrichment did not run (containerized + no `--console-cmd`, or `--no-console`), `dedupe_findings.py` surfaces the gap at the top of the report so the reduced coverage is visible, not buried in the inventory.
- **Orchestrator "resolve console runner" step** (project step 3b / changes step 4c) — probes the environment and, when ambiguous, asks via `AskUserQuestion` with a **show + confirm** trust model: the container command is built deterministically in Python and shown verbatim; Makefile targets are shown with their recipe body; nothing repo-derived is auto-executed without the user's choice.
- **`CONSOLE_ENTRYPOINT` recipe contract attribute** — `["php","bin/console"]` for Symfony, `None` for Laravel/generic (console N/A; no coverage gap reported).

#### Changed

- **`sandbox.ConsoleRunner` abstraction.** `try_console_smoke` / `run_console_command` now take a `ConsoleRunner` (host / container / custom / disabled) instead of hard-coding `["php", bin/console]` on the host, and pick higher timeouts for container/custom modes. Console execution is now stack- and location-agnostic.
- **Containerization is the dominant gate.** A containerized project's console is never run on the host automatically — recon resolves a runner (interactively or via `--console-cmd`) or records a loud `console_gap` (ceiling=medium). In non-interactive/CI runs nothing blocks: the gap is recorded and surfaced.

### Composite repository support

Adds first-class support for monorepos where `composer.json` / framework configs live in a subdirectory below `cwd` and CLAUDE.md is shared at the monorepo root.

### Added

- **`--project-root=<path>`** flag on `/security-project` and `/security-changes`. Defaults to `cwd`. When set, all paths in recon, worker file resolution, CLAUDE.md exclusions, sanity coverage, refute normalization, and git operations resolve against this value. Required for composite repos (monorepo + PHP subproject).
- **Dual CLAUDE.md read.** Exclusions are merged from both `<cwd>/CLAUDE.md` and `<PROJECT_ROOT>/CLAUDE.md` when these differ. All paths in either file are interpreted as `PROJECT_ROOT`-relative; entries that don't resolve under `PROJECT_ROOT` are skipped with a user warning.
- **Worker `project_root` parameter.** `Task(security, ...)` now passes `project_root: <PROJECT_ROOT>` so workers prepend it when calling `Read` / `Grep` / `Glob` / `mcp__phpstorm__*` on project files. Without this, workers silently miss files in composite repos. Output paths in findings (`sink_file:sink_line`) remain `PROJECT_ROOT`-relative for dedup parser compatibility.

### Changed

- **`--review-root` is now strictly an output-directory flag.** Step 0.3 in both orchestrators rejects values that look like a source tree (basename in a blacklist of `src`, `app`, `lib`, `vendor`, `node_modules`, `public`, `templates`, `views`, `database`, `migrations`, `seeders`, `scripts`, `routes`, `build`, `dist`, `target`, `out`, `coverage`, `.next`, `.nuxt`, `__pycache__`, etc.), and values that equal or are a non-`security-review-`-prefixed subpath of `<PROJECT_ROOT>`. Past incident: `--review-root=src` clobbered the user's `src/.gitignore` with `*`. The guard also pre-checks that the resolved path is not an existing non-directory.
- **Absolute-path invariant.** After Step 0, all references to `<REVIEW_ROOT>` and `<PROJECT_ROOT>` in subsequent bash, `Task(...)`, and helper utility calls MUST use the resolved absolute paths. Past incident: `validate_context.py` received an absolute path while a later `ls` received a relative one, producing `ls: src/CONTEXT.md: No such file or directory` on a file that actually existed.
- **`validate_context.py --sanity` now receives `--project-root`** from the orchestrator. Removes the `WARNING: project_root not specified and could not be inferred — sanity coverage skipped` that fired on composite repos (where `parent(review_root)` had no `composer.json` / `package.json`).
- **`/security-changes` git operations** all use `git -C "<PROJECT_ROOT>"`. Without this, in a monorepo with `cwd != PROJECT_ROOT`, `git diff` would return paths relative to the monorepo root, which recon then could not match against `<PROJECT_ROOT>`-relative file globs (`touched_by_diff` would never set, the mode=changes contract would break silently). `Bash(git -C *)` added to `allowed-tools`. Step 0.2 verifies `PROJECT_ROOT` is a git repo before continuing.
- **Legacy v1 (`SECURITY_CONTEXT.md`) detection** probes both `<cwd>` and `<PROJECT_ROOT>`. Previous form only probed `cwd` and would silently miss legacy files in composite repos.

## [4.0.0] — 2026-05-21

### Five-layer checklist resolver and integrations layer

Major architectural release. The checklist resolver moves from a flat two-level scheme (`core/` + `frameworks/`) to a five-layer chain that scales to multiple languages, sub-framework addons, and vendor / capability integrations. First content lands in the new `addons/` and `integrations/` layers.

### Added

- **Resolution chain.** Five layers, less specific to more specific: `core/` → `languages/{lang}/` → `stacks/{stack}/` → `stacks/{stack}/addons/{addon}/` → `integrations/{integration}/`. Precedence on conflict: integration > addon > stack > language > core. Integrations apply even when stack is `none` / `unknown`. New `ResolutionContext` dataclass with normalized addons/integrations.
- **Symfony addons.**
  - `stacks/symfony/addons/easyadmin/` and `.../sonata/` extracted from inline stack-checklist sections into dedicated addon files. Recipe-driven recall via `recon_bags.addon.easyadmin.crud_controllers` and `recon_bags.addon.sonata.admin_classes`.
  - `stacks/symfony/addons/api-platform/` — REST and GraphQL coverage: `_detect.md`, `auth.md`, `data-access.md`, `output-render.md`, `disclosure.md`. New `recon_bags.addon.api-platform.resources` schema slot (PHP sandbox extractor deferred; placeholder bag).
- **Integrations layer (12 directories total).**
  - Generic capabilities: `jwt-generic`, `oauth-oidc`.
  - Identity providers: `auth0`, `aws-cognito`, `okta`, `keycloak`, `firebase-auth`. Provider detection auto-includes generic JWT and OAuth/OIDC layers via `PROVIDER_IMPLIES_INTEGRATIONS`.
  - Vendor / capability integrations: `stripe` (fintech), `aws-secrets-manager` (crypto), `vault` (crypto), `saml` (auth), `webauthn-passkeys` (auth).
- **New core theme `security-headers.md`** covering CSP, frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS, COOP/COEP/CORP. Added as third theme of W3.
- **`## Trusted patterns (do NOT flag)`** convention (Anthropic `claude-code-security-review` precedent) — negative filter for safe-by-construction idioms. Seeded in `core/{auth, output-render, injection}.md` (CSPRNG primitives, default-escape templating, parameterized ORM queries).
- **Confidence caps** — new upper-bound rules complementing existing floors. `redirect_open` and `ssrf` capped at confidence 5 when only the URL path is attacker-controlled (host/scheme/port hardcoded). `race_condition` floor `≥ 8` only for TOCTOU on concrete state mutation; read-side cache races capped at 4.
- **`sink_kind` enum** extended from 30 to 41 values:
  - Security headers: `csp_missing`, `csp_unsafe_inline`, `clickjacking_unprotected`, `hsts_missing`, `mime_sniff_unprotected`.
  - JWT / OAuth: `jwks_spoof`, `oidc_misconfig`, `tls_validation_bypass`.
  - Injection sub-kinds: `ldap_injection`, `xpath_injection`, `nosql_injection`.
- **`root_cause_family` enum** extended with `clickjacking`.
- **Detection recipes** (10 new under `bin/recon/recipes/`): `easyadmin_detect.py`, `sonata_detect.py`, `api_platform_detect.py`, `jwt_generic_detect.py`, `oauth_oidc_detect.py`, `auth0_detect.py`, `aws_cognito_detect.py`, `okta_detect.py`, `keycloak_detect.py`, `firebase_auth_detect.py`, `stripe_detect.py`, `aws_secrets_manager_detect.py`, `vault_detect.py`, `saml_detect.py`, `webauthn_passkeys_detect.py`. Composer + env + bounded source-scan probes with vendor-skip and symlink containment.
- **`stack.addons` and `stack.integrations`** populated automatically in CONTEXT.md frontmatter from detection results; consumed by the resolver to load the corresponding checklist layers.
- 1024 unit/regression tests (+238 since 3.4.0).

### Changed

- **BREAKING.** Directory `checklists/frameworks/` renamed to `checklists/stacks/` (history preserved via `git mv`).
- **BREAKING.** `resolve_checklists(themes, stack, plugin_root)` signature changed to `resolve_checklists(themes, ctx: ResolutionContext, plugin_root)`. Callers must construct a `ResolutionContext` and read `stack.framework` from the frontmatter dict.
- **BREAKING.** CONTEXT.md bag namespace renamed: `framework_specific.{stack}.*` → `recon_bags.{kind}.{name}.*` where `kind ∈ {stack, addon, integration}`. Three-level shape replaces the previous two-level shape. ~240 references updated across code, tests, checklists, and worker prompts.
- **`_meta.md`** rewritten for the five-layer model with new diagrams, resolution chain, layer conventions, integration-anchor exception, disambiguation rows for the new sink_kinds, and the documented `## Trusted patterns` convention.
- **YAML subset emitter/parser** widened to accept kebab-case dict keys (needed for `recon_bags.addon["api-platform"].resources`). Leading-hyphen still rejected.
- **GraphQL detection** (`graphql_detect.py`) recognizes both `api-platform/core` (v3) and `api-platform/symfony` (v4).
- **`available_recipes()`** filters `*_detect.py` so addon/integration probes are not auto-loaded as stack recipes.
- **EasyAdmin and Sonata bag-collectors** moved into dedicated modules; backward-compat re-exports from `symfony.py` removed (no in-repo callers).
- **Symfony recipe `_empty_skeleton`** degraded path now runs composer-based addon and integration probes when `project_root` is available — addon / integration detection survives extractor failure.

### Fixed

- **`plan_waves.lookup_kind_for_file`** walked the bag at two levels after the namespace rename and silently returned `None` for every file. The masking unit test used the old two-level fixture shape. Fixed to walk three levels; new test exercises the addon namespace.
- **JWT and OAuth content** migrated from `core/auth.md` and `core/crypto.md` into `integrations/{jwt-generic,oauth-oidc}/`. Defense-in-depth `oauth_state_missing` floor retained in `core/auth.md` for projects that use custom OAuth without a detected SDK.
- **`#[ApiResource]` / GraphQL** sections previously embedded in `stacks/symfony/{auth, data-access, output-render}.md` moved into `stacks/symfony/addons/api-platform/` with the api-platform parts; overblog/webonyx-specific bullets remain in stack files. Section titles updated and breadcrumbs added.

### Composer-name accuracy

Two rounds of triple review (Stages 5 and 7) caught fictional composer package names in detector tables. Every package name in identity-provider and vendor-integration detectors is now packagist-verified against `https://repo.packagist.org/p2/...`. AWS Cognito, Okta, Auth0, Keycloak, Stripe, Vault, WebAuthn, and SAML lists were corrected. Worker tests that previously passed tautologically (using the same fake names as the detectors) now use real names.

### Notes

- **Provider integrations imply generic layers.** Detection of `auth0` / `aws-cognito` / `okta` / `keycloak` automatically activates `jwt-generic` and `oauth-oidc` layers. `firebase-auth` activates `jwt-generic` only (Firebase uses JWT but not standard OAuth/OIDC).
- **Stage 7 integrations are intentionally orthogonal** — `stripe`, `aws-secrets-manager`, `vault`, `saml`, `webauthn-passkeys` do NOT pull in `jwt-generic` or `oauth-oidc` (different protocol surfaces).
- **PHP sandbox extractor for `api-platform.resources` and JWT/OAuth call sites is deferred.** The bag is populated only with a placeholder status (`status: unknown` with a reason); content extraction lands in a follow-up release.
- **Reserved for future stages**: `languages/{php,python,node,go}/`, `stacks/{django,fastapi,express,nestjs}/`, additional providers (Azure AD B2C, Clerk, Supabase Auth), LLM-security integrations (prompt injection, output handling), compliance integrations (GDPR / HIPAA / PCI).

### Migration from 3.x

Internal-only refactor — no external consumers of the plugin format. Projects that use 3.4.0 CONTEXT.md fixtures need to:

1. Rename top-level `framework_specific:` → `recon_bags:` and restructure as `recon_bags.{kind}.{name}.<bag_key>` (kind ∈ `stack`, `addon`, `integration`).
2. Move EasyAdmin / Sonata bag entries from `framework_specific.symfony.easyadmin_crud_controllers` / `.sonata_admin_classes` to `recon_bags.addon.easyadmin.crud_controllers` / `recon_bags.addon.sonata.admin_classes`. Keep `admin_authz_coverage` under `recon_bags.stack.symfony.*` (cross-addon synthesis).
3. Add optional `stack.addons: [...]` and `stack.integrations: [...]` lists to the frontmatter; they're populated automatically by recon and consumed by the resolver to load the new layers.

## [3.4.0] — 2026-05-20

### Initial public release

First public release. Version 3.4.0 inherits the version number from a private predecessor for numbering continuity.

**What is included:**

- Slash commands `/fr-security-review:security-project` and `/fr-security-review:security-changes` for PHP projects.
- Recipe-driven recon with support for Symfony, Laravel, and generic PHP. Schema v2 (`<review_root>/CONTEXT.md` with frontmatter and closed shape specs).
- 6 focused worker waves: W1 auth/disclosure, W2 injection/data-access, W3 output-render, W4 serialization/crypto, W5 ssrf+fileops, W6 fintech + W∞ exploratory (cross-layer chains).
- Adversarial pass (second-pass refute) and the option to disable it via `--no-adversarial`.
- Detection: GraphQL (lighthouse, rebing-laravel, api-platform, webonyx), EasyAdmin, Sonata, Octane, messenger transports, sensitive columns.
- Detection regression: "removed-defense" — detection of removed validators/sanitizers in `/security-changes`.
- Deterministic deduplication (`dedupe_findings.py`) with split report `REPORT.md` + `REPORT/<root_cause_family>.md`.
- 767 unit/regression tests for recon, dedupe, and e2e pipeline (stdlib only, no third-party Python deps).
- Sandbox modes: `--no-console`, firejail, Docker.
- Project-level exclude via `<project_root>/CLAUDE.md` and `--exclude=<csv>`.

**License:** Elastic License 2.0.
