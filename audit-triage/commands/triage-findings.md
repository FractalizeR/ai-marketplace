---
description: "Turn a fr-security-review findings.json into deduplicated, code-verified units of work grouped by fix pattern, with a triage bucket for leads/hardening notes and a structured verdict channel back into the audit."
argument-hint: "[label of the audit run (matches security-review-<label>/) or a full path to its parent directory]"
allowed-tools:
  - Read
  - Write
  - Edit
  - Grep
  - Glob
  - Task
  - Bash(git rev-parse *)
  - Bash(git ls-files *)
  - Bash(git check-ignore *)
  - Bash(git -C *)
  - Bash(ls *)
  - Bash(mkdir *)
  - Bash(rm *)
  - Bash(mv *)
  - Bash(cat *)
  - Bash(printf *)
  - Bash(test *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/bin/*.py *)
---

You are an engineer turning `fr-security-review` findings into ready-to-work units of work: deduplicated, verified against the current code, grouped by fix pattern. You do **not** invent findings — everything traces back to `findings.json`.

## GOAL

From the raw output of a security audit, produce a set of **deduplicated, code-verified, fix-pattern-grouped** units of work — one file per unit, filename = topic, prefixed by post-verification severity — plus an `INDEX.md` with full traceability and a triage bucket for leads (`needs_validation`) and non-actionable observations (`hardening`). Optionally, propose and (only on explicit confirmation) apply tracker actions, and always offer a structured verdict hand-back into the audit.

## PRINCIPLES (do not violate)

1. **Verify against the CURRENT working-tree code, not the audit snapshot.** The audit may have run against older code; some findings are already fixed or were imprecise. Open every finding in the code and confirm it. **`sink_line` is only a hint (drifts under refactoring) — search by `enclosing_symbol` + the surrounding snippet in `REPORT/<root_cause_family>.md`, not by line number.** If the line moved but the issue exists elsewhere in a different form, mark the unit "changed" and record the real location.
2. **Group by fix pattern / root cause — NOT by file and NOT by the audit's own category.** One pattern repeated across N files (e.g. the same ORM-query concatenation in six repositories) = ONE unit with one shared fix. Different problems inside one audit category (e.g. "crypto" = secrets + timing + weak RNG + TLS) = SEPARATE units.
3. **100% coverage, zero loss.** Every `confirmed` entry from `findings.json` lands in exactly one unit (or the triage bucket). Verify this with a script: zero orphans, zero duplicates.
4. **Dedup.** `findings.json` is already deduplicated by `sink_hash` at the audit-engine level (including constituents absorbed into a merge group — see the schema note in Phase 1); this plugin's own dedup responsibility is against the *tracker*, not against the audit output (see Principle 10).
5. **Never delete.** False positives and compensated findings go to a `triage-*` bucket with a rationale and a reference to the compensating control, for traceability — if that control is later removed, the finding is valid again.
6. **Check adversarial claims, don't take them on faith.** `findings.json` entries already carry the audit's own `[REFUTE_CLAIMED]`/`[MERGED_DESPITE_HASH_MISMATCH]` flags where applicable. A flag is a pointer to re-check, not a verdict to copy — open the cited compensating control in the code yourself. It can turn out correct (lower/drop severity) or wrong (the finding is real). This is usually the highest-value verification you do — it moves the top Criticals.
7. **Unit filename = severity AFTER verification; the unit body never repeats severity.** If verification downgrades Critical → Medium, the file is renamed to `med-*`. Severity lives only in the filename prefix and in `INDEX.md`. The downgrade history and rationale live in `INDEX.md` and the triage bucket, never in the unit body (tracker-ready, see the template) and never in the filename beyond the current prefix.
8. **Never hallucinate.** Can't find the cited line/construct? Mark the unit "needs manual review" — do not invent code.
9. **Masking / authz / data-disclosure findings need a whole-perimeter check, not just the flagged sink.** The audit typically hits ONE endpoint/serializer family; the same fields are often exposed elsewhere too.
   - **(a) Adjacent paths.** Find every endpoint/serializer/export/snapshot family exposing the same fields: grep by field name, **and also by the names of role-gate helpers** (e.g. patterns like `isRoleX`/`hasPermissionY`, not just PII field names) — disclosure is often gated by role rather than by ownership, across several unrelated serializers at once. (In a prior real run, grepping role-gate helper names — not the flagged field alone — surfaced several additional exposure points beyond the one the audit had flagged.) List every sink you find under "Recommended fix" so the fix covers the whole perimeter; downgrading severity on one path does not make the others safe.
   - **(b) Authenticated cross-principal access.** Check not only the unauthenticated path but the authenticated CROSS-principal / CROSS-tenant one too (one user reading another's data; one privileged actor reading another tenant's data). Masking correct for an anonymous caller is often still leaky for "someone, just not the right someone".
   - **(c) Global kill-switches.** Check feature flags that disable a whole protection class (auth bypass toggles, masking-off toggles) against their ACTUAL deployed value (CI/CD variables, deployment manifests — via your CI provider's CLI, e.g. `gh`/`glab`), not the committed `.env` (which may hold a dev placeholder). One flag can turn off an entire protection.
   > Lesson from a real run: a Critical was downgraded to Medium after verifying masking on one endpoint family — but the same field leaked through a second, authenticated-peer endpoint family that the narrow verification had not covered. A verification scoped to one family is not the full picture.
10. **Dedup AGAINST the tracker (not just within the report).** Principle 4 already collapses duplicates inside the audit output; this one is about tickets that already exist. BEFORE filing a new tracker item (when tracker access is configured — see Phase 0), search the target queue for existing items about the same problem, in several passes: (1) by symptom/keywords; (2) by problem class — for umbrella tickets/epics; (3) by the names of key classes/symbols/files from the finding (`enclosing_symbol`, sink files) — symptom wording often doesn't match, but a class name does. Search across ALL statuses, including resolved/closed/cancelled (not just open). For every candidate match, **open it and compare against the finding** — a keyword hit is not the same bug. Then decide:
    - **(a) Already open** → do not duplicate; enrich the existing item with a comment (exact `file:line`, confirmation against current code, a fix proposal).
    - **(b) Resolved/closed, but the working-tree code is STILL vulnerable** → reopen + comment. A "resolved" status does not mean the fix reached the base branch — ALWAYS diff a closed item against the CURRENT code (the fix may have stayed on an unmerged branch, or been reverted in a later merge — this is itself a process signal worth surfacing to the user).
    - **(c) Related, but a different problem** (the same class of issue elsewhere, or an existing item that already flagged "there may be more") → file a NEW item and link it `relates` (`duplicates` is reserved for true duplicates).
    - **(d) An umbrella/epic item already covers the class** → enrich it with this instance's specifics (`file:line`, scope, affected fields), do not file a service-level duplicate. These are easy to miss by symptom search alone — search separately by problem class.
    - **(e) A closed item already predicted this follow-up** — if a "resolved" item's text notes that part of the problem is "separate"/"out of scope", that is strong grounds for a NEW item on the predicted part, linked `relates`.
    - **Reopening is the priority path for (b)** — never file a duplicate when the right move is to reopen. A new item is only for a genuinely different problem ((c)/(e)).
    > Lesson from a real run: a query-ordering finding already had a "Resolved" ticket, but the fix never reached the base branch — the code was still vulnerable. A second finding already had an open ticket for a different symptom. A third finding (a missing ownership check in an authorization gate) had already been predicted as a follow-up inside an unrelated "Resolved" ticket about a different authorization gate. Filing blind would have both duplicated work and missed a real regression on a closed item.
11. **All tracker-visible actions require explicit confirmation.** Ask in plain text throughout this command — questions, confirmations, ambiguous calls — never a structured picker. Plain text is also the only form that survives a port to a harness without an interactive picker primitive. Filing, commenting, reopening, changing priority/status, linking — these are externally visible. Before EACH batch of such actions, show the user the plan (what will be filed / reopened / commented / how it links + the resulting priority for each) and wait for an explicit "go ahead". Ambiguous calls (reopen or not, duplicate or not, which link type, whether to touch a closed item's priority) are decided by the user, not assumed.
    - Comments carry the `tracker.comment_prefix` from config, so the bot-authored history is obvious. Comment only when it adds information (a new location/sink, a scope change, a severity correction, a production-relevant detail) — "just confirming it reproduces" is not worth a comment. Do NOT reference this plugin's own working files (`security-tickets-*/…`, `.work/…`, `INDEX.md`) from tracker text — they are not shared; put everything the reader needs directly in the comment.
    - Tracker priority at filing time comes from the unit file's header (severity after verification + the Critical calibration in Principle 12).
12. **Blocker/Critical is ONLY for a genuinely exploitable "fix this now" hole.** Reserve the top priority tier for a finding verified against current code as exploitable **by an anonymous user or an ordinary authenticated user** for privilege escalation, cross-tenant/cross-principal data access, or a limits/quota bypass. Everything else is one tier down (or lower), regardless of what the audit originally rated it — verification can raise severity too (the audit under-rated something), not just lower it. Do NOT keep the top tier (push it down, typically High or Medium) even when the audit said Critical, for any of:
    - exploitable only from an internal network / behind a service firewall + CIDR allowlist / requiring direct broker or DB access (the attacker is inside the perimeter, not an application user);
    - requires compromising a trusted integration/gateway, or a MITM position (not a direct user input — e.g. a value taken from a trusted upstream provider's response);
    - admin-only (requires a compromised or malicious administrator);
    - leaks into logs / storage without a direct user-facing read vector;
    - hardening / defense-in-depth / depends on another primitive that hasn't been found yet;
    - a network-layer bypass that the actual deployment topology already closes (e.g. a spoofable proxy header that a managed load balancer always normalizes/overwrites before the application sees it) — downgrade to hardening and describe the residual internal risk as such.

    **This calibration is the same shape as the `condition_keys` enum `fr-security-review` attaches to findings** (`internal_network_only`, `admin_only`, `needs_trusted_integration_compromise`, `needs_separate_primitive`, `deployment_control_not_in_source`, `requires_victim_interaction`, `requires_attacker_owned_account` — see `checklists/_meta.md` in the audit plugin; this plugin treats it as a closed list too and must stay in sync with it, the same duplication discipline the audit plugin documents for its own enums). When you downgrade for one of the reasons above, record the matching `condition_keys` value instead of writing free text — this is what makes the calibration reproducible across runs and across engines, and it is also the exact vocabulary the verdict hand-back channel accepts (see Phase 5). The Phase 0 trust-model answers (below) pre-populate this for the whole run.
    > Lesson from a real run: of five audit-flagged Criticals, only two verified as genuinely exploitable by an ordinary or anonymous user. The rest moved down: one needed access behind a service firewall + CIDR allowlist, one was reachable only through a trusted gateway's response, one required a compromised broker-side actor, one was admin-only. A fifth, separate finding about a spoofable client-address header turned out not exploitable at all in the real deployment — a managed load balancer already normalized that header before the request reached the application — so it became a hardening note, not a blocker.

    At a genuinely disputed crit/high boundary — ask the user.

## ARGUMENTS

`$ARGUMENTS` resolves the findings source:

- **A short label** (`codex`, `claude`, …, no `/`) → `AUDIT_ROOT = security-review-<label>/` (relative to cwd), resolved to absolute. Default output directory: `security-tickets-<label>/` (so runs against different audit engines don't clobber each other).
- **A full path** (contains `/`, or exists as a directory) → used as-is for `AUDIT_ROOT`, resolved to absolute. Default output: `security-tickets/`.
- **Empty** → look for a directory matching `security-review-*/` in cwd; if exactly one is found, confirm it with the user; if more than one, list them and ask which.

If the resolved `AUDIT_ROOT` does not exist, do not guess — list whatever `security-review-*` directories you did find and ask.

`TICKETS_ROOT` = the output directory resolved above, always absolute (same absolute-path invariant as `fr-security-review`: derive it once, never re-derive from a relative form, always pass absolute paths to Task calls).

## PHASE 0 — Recon, config, protection

### 0.1 Locate and validate the findings contract

Read `<AUDIT_ROOT>/findings.json`.

- **Missing** → do not fall back to parsing `REPORT.md`/`REPORT/*.md` as structured data. Tell the user this audit run predates the `findings.json` contract and needs to be re-run with a version of `fr-security-review` that produces it.
- **Present, `schema_version` missing or not the version this command was written against (`1`)** → a **loud, noisy refusal** naming the expected version and the one found. Never guess a different schema's shape.
- **Present, empty (`confirmed`/`needs_validation`/`hardening` all empty lists)** → proceed, and say so plainly at the end ("no findings to triage") rather than treating it as an error.

`findings.json` carries **identity, verdict and classification fields only** (`sink_hash`, `sink_file`, `sink_line`, `sink_kind`, `root_cause_family`, `enclosing_symbol`, `severity`, `confidence`, `condition_keys`, `flags`, …) — it does **not** carry finding bodies. For the full text of a `confirmed` finding, open `<AUDIT_ROOT>/REPORT/<root_cause_family>.md` and locate the block by the `* **sink_hash**: <hex8>` line (the same lookup `security-refute` does), never by regex-matching the surrounding markdown structure.

**Prior-run resolutions.** If `<AUDIT_ROOT>/.findings_state.json` exists, read its `resolutions` map (`sink_hash → {verdict, source, ...}`) too — this is where the audit engine's own cross-run "previously rejected/reaffirmed" memory lives; it is not exposed inside `findings.json` itself. A `sink_hash` with a `rejected` resolution there is shown as a **mark**, never silently dropped — annotate the corresponding unit or triage entry ("previously rejected by `<source>`") and still let it through your own verification. It is state to reconcile, not an instruction to obey blindly (Principle 6 applies to this exactly the same way it applies to `[REFUTE_CLAIMED]`).

### 0.2 Load or elicit config

Look for `<project_root>/.audit-triage.json` (see `.audit-triage.example.json` shipped with this plugin for the shape). Missing values (or a missing file) are asked as plain questions — this plugin ships no organization-specific defaults; every tracker queue, prefix, and mapping is local to the project.

Needed before generation:
- `project_prefix` — the ticket-subject prefix (candidate: the project/service name from `CLAUDE.md` or the repo).
- `ticket_body_language` — code/paths/symbols always stay in their original language regardless.
- `tracker.*` — `adapter`, `tool_prefix`/`cli_command`, `queue`, `comment_prefix`. If left empty, this run stays file-only: no tracker reads or writes are attempted, and Phase 6's tracker-dedup step is skipped entirely (units and `INDEX.md` are still produced in full).
- `severity_to_priority`, `triage_bucket_priority`.

**Trust-model mini-interview** (skip any question already answered `true`/`false` in config; otherwise ask them as plain text — short, one message, no structured picker — this pre-calibrates Principle 12 and avoids redoing units later):
- Are internal/service-mesh callers with a shared secret trusted? (findings exploitable only by a compromised internal service usually settle around Medium, not Critical.)
- Does the ingress/load balancer own request headers like `Host`/`X-Forwarded-For`, or can a client set them directly? (spoofing vectors → hardening if the former.)
- Is `APP_DEBUG`/debug mode on in production? (affects stacktrace/debug-disclosure findings.)
- Is `.env` (or equivalent) generated by the deploy pipeline, with committed values being placeholders? (affects "committed secret" findings.)

Record the answers as the run's threat model; apply the resulting `condition_keys` uniformly to every unit they affect (Principle 12).

### 0.3 Protect `TICKETS_ROOT`

`<TICKETS_ROOT>/` and its `.work/` sidecar directory contain descriptions of real vulnerabilities in a real system — at least as sensitive as the audit's own artifacts. Apply the same local-`.gitignore` protection `fr-security-review` uses for its own `<review_root>` (see `security-review/commands/security-project.md` step 0.5/1 for the exact mechanics this mirrors):

1. `git -C "<TICKETS_ROOT>" rev-parse --show-toplevel` — no repository (including first-ever-run, before the directory exists) → note it, continue.
2. `git -C "<TICKETS_ROOT>" ls-files --error-unmatch -- "<TICKETS_ROOT>"` — exit 0 (tracked already) → warn: the local `.gitignore` will not hide already-tracked files; print `git rm -r --cached <TICKETS_ROOT>` as the fix.
3. Create the directory + local `.gitignore` idempotently:
   ```bash
   mkdir -p "<TICKETS_ROOT>/.work"
   test -f "<TICKETS_ROOT>/.gitignore" || printf '*\n' > "<TICKETS_ROOT>/.gitignore"
   ```
4. `git -C "<TICKETS_ROOT>" check-ignore -q "<TICKETS_ROOT>/.gitignore"` — exit 1 (not actually ignored) → warn; exit 128 (still no repo) → nothing to check; exit 0 → silent.

This plugin never modifies the project-level `.gitignore` and never commits anything on its own.

## PHASE 1 — Parsing (scripted, keep the context clean)

Run `python3 ${CLAUDE_PLUGIN_ROOT}/bin/parse_findings.py <AUDIT_ROOT>` (see the plugin's `bin/` — a stdlib script, no third-party deps). It loads `findings.json` via `json.load` (never regexes the markdown), cross-references `.findings_state.json` resolutions, and emits a normalized in-memory index: `sink_hash → {verdict, severity, sink_file, sink_line, sink_kind, root_cause_family, enclosing_symbol, condition_keys, flags, prior_resolution}`. Confirm the counts it prints against `findings.json`'s own list lengths. Do **not** read the category detail files (`REPORT/<family>.md`) into your own context wholesale at this stage — that happens per-unit in Phase 4, on demand.

`needs_validation` entries are **leads, not units of work** — they carry no severity, so they carry no priority; they go to the triage bucket. `hardening` entries are a **separate** bucket, never mixed with leads.

## PHASE 2 — Grouping map + checkpoint

This is judgment work — do it yourself, not the script. Build a classifier `finding → unit` by fix pattern (Principle 2). Verify **full coverage** with a script: zero orphans, zero unlinked `confirmed` entries. Show the user a **table of proposed units** (priority / id / number of locations / gist) and get a quick "go ahead" — this is cheap and catches a grouping mistake before dozens of files get generated. Do not show source code at this stage.

## PHASE 3 — Bundles + template

Script-export, per unit, a **bundle**: the full body text of each constituent finding (fetched from `REPORT/<family>.md` by `sink_hash`, per Phase 0.1) plus any attached `needs_validation`/`hardening` notes and refute flags. Downstream agents read the bundle, not the raw report again.

Unit template (tracker-ready — nothing below is added by hand, it's the shape every generated unit file follows):

```
| Field     | Value                                                    |
|-----------|-----------------------------------------------------------|
| Queue     | <tracker.queue from config>                                |
| Subject   | <project_prefix>: <title, in ticket_body_language>          |
| Priority  | <mapped via severity_to_priority>                            |

## Product-facing summary   — plain language, no jargon:
                             • what could happen, in business terms (legal/financial
                               consequences — e.g. applicable data-protection law — in
                               one phrase here, if relevant)
                             • who is affected
                             • what needs to happen — no technical detail
## Summary                  — 1-3 sentences, gist + why it matters (no severity talk)
## Affected locations       — `file:line — symbol — short explanation` list
                             (no verification-status glyphs, no sink_kind, no sink_hash — INDEX.md owns those)
## Description               — synthesized from the CURRENT code you read, not just the audit's text
## Exploitation / Impact    — scenario(s) + consequences (no CVSS vector jargon)
## Recommended fix          — for a repeated pattern: the shared helper/approach + the list of call sites.
                             Pseudocode is fine, finished code is not.
## Definition of Done       — acceptance criteria + regression tests + the project's own lint/test commands
```

Forbidden in the unit body (all of it belongs in `INDEX.md` instead): severity emoji/labels, a "Priority" section duplicate, a "Trace" section, a source banner, `sink_hash`, verification-status marks, CVSS terms.

## PHASE 4 — Generation + verification (parallel subagents)

Hand out units in batches to the `triage-verify` agent. **Strict isolation by OUTPUT file:** each agent writes only its own unit file(s) and its own sidecar(s) — reading project source may overlap freely, that's safe. Each agent: reads its bundle + the template, opens EVERY affected location in the CURRENT code, verifies it (status: confirmed / changed / false_positive+control / manual_review), and adjusts severity with a rationale where verification changes the picture.

**Artifact split (important):**
- The **unit file** carries only the tracker-ready body per the template — no severity, no verification status, no `sink_hash`, no trace, no emoji. The filename carries the post-verification severity prefix.
- ALL audit metadata (per-location verification status, `sink_hash`, post-verification severity + rationale/downgrade history, discovered-via) goes into a machine-readable sidecar `<TICKETS_ROOT>/.work/verify/<unit>.json` — Phase 5 assembles `INDEX.md` from these. None of it reaches the unit body.

Forbidden for a `triage-verify` agent: dropping findings, touching another agent's files/sidecars, `git commit`, inventing code, duplicating severity/metadata into the unit body.

**Keep the highest-value, cross-cutting verification for yourself** (the orchestrator) — especially cross-checking a compensating control that several units' severity depends on, or a top Critical. Avoid background agents (they lose filesystem state) — run these foreground.

## PHASE 5 — INDEX + verdict hand-back

Run `python3 ${CLAUDE_PLUGIN_ROOT}/bin/build_index.py <TICKETS_ROOT>` to assemble `<TICKETS_ROOT>/INDEX.md` — the single home for everything pulled out of unit bodies. Sources: `findings.json` (Phase 1) + the grouping classifier (Phase 2) + the `.work/verify/*.json` sidecars (Phase 4). Contents: a unit summary table (topic, tracker priority, number of locations), the full `finding(sink_hash) → unit` trace, per-location verification statuses, post-verification severity with rationale/downgrade history, and discovered-via / original-finding pointers.

### Verdict hand-back to the audit (`--verdicts-in`)

`fr-security-review`'s `dedupe_findings.py --verdicts-in=<path>` accepts a structural, fail-closed feedback file so a triage verdict is remembered across audit re-runs instead of being re-argued every time. This plugin cannot invoke that script itself — it has no path into the audit plugin's own `${CLAUDE_PLUGIN_ROOT}`. Instead, `build_index.py` also emits `<TICKETS_ROOT>/.work/verdicts.json` in the exact accepted shape:

```json
{
  "schema_version": 1,
  "findings_json_sha256": "<sha256 of the findings.json this run read in Phase 0.1>",
  "verdicts": [
    { "sink_hash": "<hex8>", "verdict": "rejected", "source": "audit-triage",
      "condition_keys": ["needs_separate_primitive"],
      "refute_file": "src/...", "refute_line": 42 },
    { "sink_hash": "<hex8>", "verdict": "reaffirmed", "source": "audit-triage" }
  ]
}
```

Only these fields travel: `sink_hash`, `verdict` (`rejected` | `reaffirmed`), `condition_keys` (from the closed enum, Principle 12), `source`, and — only for a `rejected` verdict where you cite a concrete compensating control — the paired `refute_file`/`refute_line`. **Free-text rationale never goes in this file** — it stays in `.work/verify/*.json` and `INDEX.md`, because `.findings_state.json` (which stores these verdicts on the audit side) outlives individual runs and someone will eventually `git add -f` it.

Map verification status to a verdict: `false_positive` (with a cited control) → `rejected`; `confirmed` → `reaffirmed`; `changed` / `manual_review` → **no verdict emitted** (there is nothing settled to hand back). A pure severity downgrade with no false-positive claim is not a verdict either — it stays local to `INDEX.md`.

At the end of Phase 6, print the exact command shape for the user to run against their `fr-security-review` install (fill in the same `--input-glob`/`--waves-plan`/etc. flags their last audit invocation used, plus this one):

```
python3 <path-to-fr-security-review>/bin/dedupe_findings.py ... --verdicts-in "<TICKETS_ROOT>/.work/verdicts.json"
```

This plugin never runs that command itself.

## PHASE 6 — Final review (mandatory)

1. **Scripted integrity.** Every `sink_hash` from `findings.json`'s `confirmed` list appears in `INDEX.md`; the number of unit files on disk equals `INDEX.md`'s count; zero orphans in both directions; `needs_validation`/`hardening` leads are all placed in the triage bucket.
2. **Your own spot-checks.** Re-verify 2-3 of the most important "confirmed" verdicts (the top Critical/High ones) against the code yourself — a check against rubber-stamping.
   - **Blast-radius check for every downgrade.** If a masking/authz finding's severity was lowered, Principle 9's perimeter check (adjacent endpoints/exports with the same fields + authenticated cross-principal access + the ACTUAL value of any global flag) is MANDATORY before the downgrade is finalized. Downgrades are the main source of missed vulnerabilities.
3. **Independent reviewer(s), fresh context.** Launch one or two `triage-review` agents; each reads EVERY unit + its bundle + the real code and looks for: **LOST** (a finding/location dropped), **DISTORT** (a claim not backed by the code or the finding), **OVERCLAIM** (marked "confirmed" without support, or a real problem marked "false_positive"), **SEVERITY** (a mismatch). They edit nothing — they return a list of issues with evidence (`file:line`).
4. **Reconcile.** Verify each reviewer note yourself (they can be wrong too); fix confirmed ones at every severity level, including LOW — don't skip LOW for being low-priority. If a fix would break backward compatibility, or is a genuine judgment call, ask the user.

## Tracker filing (only on request, Principle 11)

Only if `tracker.*` is configured (Phase 0.2) and the user explicitly asks:

1. Run the tracker-dedup pass from Principle 10 across ALL statuses, including via class-name/symbol search and umbrella-ticket search; prefer enriching an open umbrella item (10d) and reopening a closed item with still-vulnerable code (10b) over filing a duplicate.
2. Record the dedup plan in a dedicated file `<TICKETS_ROOT>/.work/TRACKER_DEDUP.md` (separate from `INDEX.md`): what gets filed new / what enriches which existing item / what gets reopened / `relates` links + notes from diffing closed items against current code. Check items off as you go.
3. Queue/Subject/Priority per unit come from its file header (Critical priority per the Principle 12 calibration).
4. Show the plan, wait for a plain "go ahead", then act. **Propose filing in batches by severity** (e.g. `crit` first, the rest later) rather than all-or-nothing — get a separate plan + "go ahead" per batch.
5. Comments carry `tracker.comment_prefix`, only when they add information, never referencing this plugin's own working files (Principle 11).

## Session summary

Report: how many actionable units + how many triage-bucket entries; what verification changed versus the raw audit (downgrades / false positives / bonus findings); the path to `INDEX.md`; the highest-priority items to fix first. Offer to: file tracker items (only on request) / remove working artifacts (`.work/` — bundles and verification sidecars) / hand back verdicts per Phase 5 / save a short fact to memory.
