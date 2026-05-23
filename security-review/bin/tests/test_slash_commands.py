"""Contract tests for slash commands (security-project / security-changes).

Slash commands are markdown files; the harness (Claude Code / Codex CLI / etc.)
executes the prompt instructions inside them. We can't unit-test the LLM
behavior, but we can lint the markdown to ensure the contracts haven't drifted:

- both commands document `--label=<x>` and `--review-root=<path>` flags
- self-introspection vocabulary `claude | codex | gemini | deepseek | qwen | other-`
- `--review-root` overrides `--label`
- review-root layout: directory + `.gitignore` (`*`)
- legacy v1 detection: warn, don't touch
- review-root paths plumbed through recon-agent, plan_waves, worker, dedupe
- worker uses `<REVIEW_ROOT>/waves/<slice_id>.md` (not legacy SECURITY_REVIEW_RESULTS_*)
- security-project supports `--quick` / `--scope=` / exploratory; security-changes does not

Functional behavior of `recon_inventory.py --review-root` (S6 DoD #8 a/c/d --
review_root creation, idempotency, absolute path override) is covered in
test_recon_inventory.py (CreateContext / UserGitignorePreserved / etc.).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = THIS_DIR.parent.parent
COMMANDS = PLUGIN_ROOT / "commands"
PROJECT_CMD = COMMANDS / "security-project.md"
CHANGES_CMD = COMMANDS / "security-changes.md"


def _load(path: Path) -> str:
    assert path.is_file(), f"missing: {path}"
    return path.read_text(encoding="utf-8")


class CommonContract(unittest.TestCase):
    """Both commands must declare label resolution + review-root layout."""

    def setUp(self) -> None:
        self.project = _load(PROJECT_CMD)
        self.changes = _load(CHANGES_CMD)

    def _both(self):
        return [("security-project.md", self.project), ("security-changes.md", self.changes)]

    def test_argument_hint_lists_label_and_review_root(self) -> None:
        # YAML frontmatter `argument-hint:` must mention all three path-related
        # flags so the harness surfaces them in `/help` / completion.
        for name, text in self._both():
            with self.subTest(cmd=name):
                m = re.search(r'^argument-hint:\s*"(.+)"\s*$', text, re.MULTILINE)
                self.assertIsNotNone(m, f"{name}: no argument-hint frontmatter")
                hint = m.group(1)
                self.assertIn("--label=", hint, f"{name}: argument-hint missing --label=")
                self.assertIn("--review-root=", hint, f"{name}: argument-hint missing --review-root=")
                self.assertIn("--project-root=", hint,
                              f"{name}: argument-hint missing --project-root=")

    def test_self_introspection_vocabulary(self) -> None:
        # When --label is not provided, the orchestrator-LLM must self-introspect
        # against a fixed vocabulary. The exact dictionary string must appear so
        # the contract is unambiguous.
        vocab = "claude | codex | gemini | deepseek | qwen | other-"
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertIn(vocab, text, f"{name}: missing label vocabulary")
                self.assertIn("self-introspection", text.lower(),
                              f"{name}: missing self-introspection wording")

    def test_review_root_overrides_label(self) -> None:
        # Prose contract: --review-root overrides --label (Docker/CI escape hatch).
        for name, text in self._both():
            with self.subTest(cmd=name):
                lower = text.lower()
                self.assertIn("--review-root", text, f"{name}: missing --review-root")
                self.assertTrue(
                    "--label` (if any) is **ignored**" in text
                    or "--label ignored" in lower,
                    f"{name}: --review-root must explicitly override --label",
                )

    def test_review_root_layout_ensure(self) -> None:
        # Both commands must instruct: mkdir <REVIEW_ROOT>, write .gitignore=`*`,
        # mkdir <REVIEW_ROOT>/waves. Idempotent (test guard before write).
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertIn('mkdir -p "<REVIEW_ROOT>"', text,
                              f"{name}: missing mkdir review_root step")
                self.assertIn('mkdir -p "<REVIEW_ROOT>/waves"', text,
                              f"{name}: missing mkdir waves step")
                # .gitignore guard pattern: `test -f ... || printf '*\n' > ...`
                self.assertRegex(
                    text,
                    r'test -f "<REVIEW_ROOT>/\.gitignore"\s*\|\|\s*printf [\'"]\*\\n[\'"] > "<REVIEW_ROOT>/\.gitignore"',
                    f"{name}: missing idempotent .gitignore creation",
                )

    def test_legacy_v1_detection_warn_only(self) -> None:
        # Old SECURITY_CONTEXT.md must trigger a warning, not abort or rm.
        # In composite repos the file may live at <cwd> or at <PROJECT_ROOT>,
        # so both locations must be probed.
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertIn("Legacy v1 detected", text, f"{name}: missing legacy v1 banner")
                self.assertIn('test -f "<cwd>/SECURITY_CONTEXT.md"', text,
                              f"{name}: missing v1 probe at <cwd>")
                self.assertIn('test -f "<PROJECT_ROOT>/SECURITY_CONTEXT.md"', text,
                              f"{name}: missing v1 probe at <PROJECT_ROOT>"
                              " (composite repos)")
                # Must NOT remove or rename the legacy file.
                self.assertNotRegex(
                    text,
                    r"rm\s+-f?\s+.*SECURITY_CONTEXT\.md",
                    f"{name}: legacy v1 file must not be deleted automatically",
                )
                self.assertNotRegex(
                    text,
                    r"mv\s+.*SECURITY_CONTEXT\.md",
                    f"{name}: legacy v1 file must not be moved automatically",
                )

    def test_recon_agent_called_with_review_root(self) -> None:
        # Task(security-recon, ...) must include review_root + project_root,
        # both as <REVIEW_ROOT>/<PROJECT_ROOT> placeholders (NOT raw <cwd>).
        # <cwd> would be ambiguous in composite repos where --project-root
        # differs from cwd.
        for name, text in self._both():
            with self.subTest(cmd=name):
                m = re.search(
                    r'Task\(subagent_type="security-recon"[^)]+?\)',
                    text,
                    re.DOTALL,
                )
                self.assertIsNotNone(m, f"{name}: no security-recon Task block")
                block = m.group(0)
                self.assertIn("review_root: <REVIEW_ROOT>", block,
                              f"{name}: security-recon Task missing review_root")
                self.assertIn("project_root: <PROJECT_ROOT>", block,
                              f"{name}: security-recon Task must pass project_root: <PROJECT_ROOT>")
                self.assertNotIn("project_root: <cwd>", block,
                                 f"{name}: security-recon Task uses literal <cwd> "
                                 "instead of <PROJECT_ROOT> — breaks composite repos")

    def test_validate_context_uses_review_root_and_project_root(self) -> None:
        # validate_context.py must be called with --review-root (never the
        # legacy positional path) AND --project-root (otherwise the sanity
        # coverage fallback prints `WARNING: project_root not specified ...`
        # and skips coverage on composite repos where parent(review_root)
        # has no composer.json/package.json).
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertRegex(
                    text,
                    r'validate_context\.py --review-root "<REVIEW_ROOT>" --sanity --project-root "<PROJECT_ROOT>"',
                    f"{name}: validate_context.py --sanity must pass "
                    "both --review-root and --project-root",
                )
                self.assertNotIn("validate_context.py SECURITY_CONTEXT.md", text,
                                 f"{name}: legacy positional context path leaked")

    def test_project_root_flag_documented(self) -> None:
        # --project-root must be documented in ARGUMENTS so users know it
        # exists; otherwise composite repos (CLAUDE.md at top, PHP in
        # subdir) cannot be audited correctly.
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertRegex(
                    text,
                    r'`--project-root=<path>`',
                    f"{name}: --project-root flag must be documented in ARGUMENTS",
                )

    # Canonical blacklist of basenames that --review-root must reject. This
    # must match the list in the Step 0.3 prose of both commands exactly. If
    # you add a name to the prose, add it here too.
    REVIEW_ROOT_BLACKLIST = (
        "src", "app", "lib", "source", "tests", "test", "spec",
        "vendor", "node_modules", "public", "web", "bin", "config",
        "assets", "resources", "var", "storage",
        "templates", "views", "database", "migrations", "seeders",
        "scripts", "routes",
        "build", "dist", "target", "out", "coverage",
        ".next", ".nuxt", "__pycache__",
    )

    def test_review_root_misuse_guard(self) -> None:
        # Step 0 must abort if --review-root resolves to a source-tree dir
        # (src/, app/, lib/, ...). Past incident: client passed
        # `--review-root=src`, recon wrote CONTEXT.md INTO their source tree
        # and clobbered src/.gitignore with '*'. The guard prevents this.
        #
        # All canonical blacklist names must appear in the prose so the
        # orchestrator-LLM has a concrete check. Removing a name silently
        # would weaken the guard — this test catches that.
        for name, text in self._both():
            with self.subTest(cmd=name):
                for entry in self.REVIEW_ROOT_BLACKLIST:
                    # Names appear as backtick-quoted tokens in the prose,
                    # e.g. `src`, `node_modules`, `.next`.
                    self.assertIn(
                        f"`{entry}`",
                        text,
                        f"{name}: blacklist missing `{entry}` "
                        "(must match Step 0.3 source-tree dictionary)",
                    )
                # And an explicit error message pointing the user away.
                self.assertIn("looks like a project source directory", text,
                              f"{name}: misuse guard error message wording missing")
                # File-vs-directory pre-check (M2 guard).
                self.assertIn("non-directory", text,
                              f"{name}: missing pre-check that REVIEW_ROOT "
                              "is not an existing non-directory")

    def test_absolute_path_invariant(self) -> None:
        # Step 0 must require absolute paths for REVIEW_ROOT and PROJECT_ROOT
        # for all subsequent steps. Past incident: validate_context.py was
        # invoked with absolute path, but later ls was invoked with the
        # relative original flag value, leading to "ls: src/CONTEXT.md:
        # No such file or directory" on a path that actually existed.
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertRegex(
                    text,
                    r"MUST use the resolved absolute paths",
                    f"{name}: missing absolute-path invariant for review_root/project_root",
                )

    def test_plan_waves_reads_context_md(self) -> None:
        # plan_waves consumes <REVIEW_ROOT>/CONTEXT.md, with absolute --plugin-root.
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertIn(
                    'plan_waves.py "<REVIEW_ROOT>/CONTEXT.md"',
                    text,
                    f"{name}: plan_waves must read <REVIEW_ROOT>/CONTEXT.md",
                )
                self.assertIn('--plugin-root="${CLAUDE_PLUGIN_ROOT}"', text,
                              f"{name}: --plugin-root must be passed")

    def test_worker_writes_into_waves_dir(self) -> None:
        # The orchestrator must instruct workers to write to
        # <REVIEW_ROOT>/waves/<slice_id>.md (not the legacy
        # SECURITY_REVIEW_RESULTS_<slice_id>.md in cwd).
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertIn('"<REVIEW_ROOT>/waves/<slice_id>.md"', text,
                              f"{name}: workers must target <REVIEW_ROOT>/waves/<slice_id>.md")
                # Legacy path must not appear in any role.
                self.assertNotIn("SECURITY_REVIEW_RESULTS_<slice_id>.md", text,
                                 f"{name}: legacy SECURITY_REVIEW_RESULTS_<slice_id>.md leaked")

    def test_dedupe_outputs_into_review_root(self) -> None:
        # Dedupe must consume waves/*.md and emit REPORT.md + REPORT/ inside review_root.
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertIn(
                    '--input-glob "<REVIEW_ROOT>/waves/*.md"',
                    text,
                    f"{name}: dedupe input-glob wrong",
                )
                self.assertIn(
                    '--output "<REVIEW_ROOT>/REPORT.md"',
                    text,
                    f"{name}: dedupe --output wrong",
                )
                self.assertIn(
                    '--details-dir "<REVIEW_ROOT>/REPORT"',
                    text,
                    f"{name}: dedupe --details-dir wrong",
                )

    def test_worker_task_carries_review_root(self) -> None:
        # Each Task(security, ...) call must pass review_root + project_root +
        # relevant_section_paths (dot-notation, not the v1
        # relevant_section_ids). project_root is required so the worker can
        # resolve target_files / entry_points_in_scope / paths inside
        # CONTEXT.md in composite repos (cwd != PROJECT_ROOT) — without it,
        # Read silently resolves against cwd and misses the right file.
        for name, text in self._both():
            with self.subTest(cmd=name):
                m = re.search(
                    r'Task\(subagent_type="security",[^)]+?\)',
                    text,
                    re.DOTALL,
                )
                self.assertIsNotNone(m, f"{name}: no security worker Task block")
                block = m.group(0)
                self.assertIn("review_root: <REVIEW_ROOT>", block,
                              f"{name}: worker Task missing review_root")
                self.assertIn("project_root: <PROJECT_ROOT>", block,
                              f"{name}: worker Task missing project_root — "
                              "breaks file resolution in composite repos")
                self.assertIn("relevant_section_paths:", block,
                              f"{name}: worker Task must pass relevant_section_paths")
                self.assertNotIn("relevant_section_ids:", block,
                                 f"{name}: legacy relevant_section_ids leaked into worker Task")
                self.assertNotIn("context_file:", block,
                                 f"{name}: legacy context_file leaked into worker Task")


class ProjectOnly(unittest.TestCase):
    def setUp(self) -> None:
        self.text = _load(PROJECT_CMD)

    def test_supports_quick_and_scope(self) -> None:
        self.assertIn("--quick", self.text)
        self.assertIn("--scope=<glob>", self.text)
        self.assertIn("--scope-glob", self.text, "plan_waves invocation must pass --scope-glob")

    def test_exploratory_default_on(self) -> None:
        self.assertIn("Exploratory wave W∞ is enabled by default", self.text)

    def test_no_console_flag_exposed_and_conditional(self) -> None:
        # Orchestrator exposes --no-console for hostile-repo audits; in the
        # default flow step 3b resolves the console runner (host or asks) and
        # neither flag is needed.
        self.assertIn("--no-console", self.text)
        self.assertIn("In normal mode neither flag is needed", self.text)
        self.assertIn("CONSOLE_CMD resolved in step 3b", self.text)

    def test_worker_mode_project(self) -> None:
        # security-project must run workers in mode=project. Catches a refactor
        # that accidentally swaps the literal with mode: changes.
        self.assertIn("mode: project", self.text)
        self.assertNotIn("mode: changes", self.text)

    def test_balanced_profile_matches_plan_waves(self) -> None:
        # Balanced model assignment in prose must match WaveSpec.balanced_model
        # in bin/plan_waves.py: W1/W2/W6 → opus; W3/W4/W5/W∞ → sonnet.
        self.assertIn("W1/W2/W6 — opus", self.text)
        self.assertIn("W∞ (exploratory) — sonnet", self.text)


class ChangesOnly(unittest.TestCase):
    def setUp(self) -> None:
        self.text = _load(CHANGES_CMD)

    def test_diff_files_in_review_root(self) -> None:
        # diff list must live inside <REVIEW_ROOT>/ to keep cwd clean and
        # automatically expire with the run.
        self.assertIn('"<REVIEW_ROOT>/diff_files.txt"', self.text)
        # The legacy /tmp/security_diff_files.txt path must be gone.
        self.assertNotIn("/tmp/security_diff_files.txt", self.text)

    def test_plan_waves_passes_diff_files(self) -> None:
        self.assertIn('--diff-files "<REVIEW_ROOT>/diff_files.txt"', self.text)

    def test_recon_task_uses_diff_files_flag(self) -> None:
        # Recon-agent input contract (see agents/security-recon.md) takes
        # `--diff-files=<path>` flag-style — NOT a `diff_files:` yaml-style key.
        # Mismatch → recon silently runs in project mode, touched_by_diff is not
        # propagated, and the entire mode=changes invariant breaks.
        m = re.search(
            r'Task\(subagent_type="security-recon"[^)]+?\)',
            self.text,
            re.DOTALL,
        )
        self.assertIsNotNone(m, "no security-recon Task block in changes command")
        block = m.group(0)
        self.assertIn(
            "--diff-files=<REVIEW_ROOT>/diff_files.txt",
            block,
            "recon Task must pass --diff-files= as flag-style (recon-agent contract)",
        )
        self.assertNotRegex(
            block,
            r"^\s*diff_files:\s",
            "yaml-style `diff_files:` key in recon Task — recon-agent expects --diff-files=",
        )

    def test_changes_mode_disclaims_exploratory_and_scope(self) -> None:
        self.assertIn("`--exploratory` and `--scope=` for diff mode are **not supported**",
                      self.text)

    def test_reverse_and_forward_grep_present(self) -> None:
        self.assertIn("Reverse-grep", self.text)
        self.assertIn("Forward-grep", self.text)

    def test_git_ops_target_project_root(self) -> None:
        # In composite repos cwd may differ from <PROJECT_ROOT>; all git
        # operations must use `git -C "<PROJECT_ROOT>"` so they read the
        # audited project's repo (not the monorepo wrapper). Bare `git diff`
        # / `git rev-parse` would silently read the wrong repo.
        git_lines = [
            line for line in self.text.splitlines()
            if re.match(r'^\s*git\s+(diff|rev-parse|log|status|ls-files)\b', line)
        ]
        bad = [line for line in git_lines if "-C " not in line]
        self.assertFalse(
            bad,
            "security-changes git commands missing `-C \"<PROJECT_ROOT>\"`:\n  "
            + "\n  ".join(bad),
        )
        # The allowed-tools list must permit `Bash(git -C *)` since every
        # invocation now uses it.
        self.assertIn("Bash(git -C *)", self.text,
                      "allowed-tools must permit `Bash(git -C *)`")

    def test_grep_uses_orchestrator_tool_not_shell(self) -> None:
        # `Bash(grep:*)` is NOT in allowed-tools — the orchestrator must use the
        # built-in `Grep` tool, not shell `grep -rn`. A bash grep snippet would
        # be silently blocked by the harness in real runs.
        self.assertNotRegex(
            self.text,
            r"```bash\s*\n\s*grep\s+-",
            "shell `grep -...` snippet present, but Bash(grep:*) is not allowed",
        )
        # Positive: at least one Grep(...) tool invocation must be documented
        # in reverse/forward-grep sections.
        self.assertIn(
            'Grep(pattern=',
            self.text,
            "reverse/forward-grep must use the built-in Grep tool",
        )

    def test_worker_mode_changes(self) -> None:
        self.assertIn("mode: changes", self.text)


class WorkerAgentContract(unittest.TestCase):
    """The security worker agent must mirror the slash-command contract."""

    AGENT = PLUGIN_ROOT / "agents" / "security.md"

    def setUp(self) -> None:
        self.text = _load(self.AGENT)

    def test_no_tools_block_in_frontmatter(self) -> None:
        # Wave 1-A (3.4.0): `tools:` allowlist removed from sub-agent
        # frontmatter — worker inherits the parent (slash-command) tool-set.
        # Permission gating lives at the harness layer in
        # `commands/security-{project,changes}.md` `allowed-tools:` blocks,
        # not duplicated in the agent. See NEXT_RELEASE_PLAN.md §1.1, Principle 2.
        self.assertNotRegex(
            self.text,
            r"(?m)^tools:\s*$",
            "agents/security.md must NOT declare its own tools: block "
            "(Wave 1-A: worker inherits tools from parent orchestrator)",
        )
        # Legacy `Bash(php bin/console debug:*)` must not reappear by accident.
        self.assertNotIn("Bash(php bin/console debug:*)", self.text)

    def test_diff_reconstruction_forbidden_textually(self) -> None:
        # After Wave 1-A the worker inherits tools from the parent slash command,
        # which legitimately needs `Bash(git diff …)` to compute diff_files.
        # The "do not regrep diff yourself" guard therefore cannot live as a
        # tool-allowlist exclusion any more — it lives as an explicit textual
        # contract in the agent prompt. This test enforces that the textual
        # guard is preserved on every edit.
        self.assertIn("Do not grep the diff manually", self.text)
        self.assertIn("touched_by_diff", self.text)
        # No legacy CLI snippet teaching the worker to compute the file list itself.
        self.assertNotIn("git diff origin/main...HEAD --name-only", self.text)

    def test_input_contract_uses_review_root_and_section_paths(self) -> None:
        self.assertIn("review_root", self.text)
        self.assertIn("relevant_section_paths", self.text)
        self.assertNotIn("relevant_section_ids", self.text)
        # No legacy context_file pointer.
        self.assertNotRegex(self.text, r"(?m)^\s*-\s*`context_file`")

    def test_input_contract_documents_project_root(self) -> None:
        # Worker must accept project_root and explain how to resolve paths
        # relative to it (vs cwd) — otherwise composite repos break silently.
        self.assertRegex(self.text, r"`project_root`",
                         "worker INPUT CONTRACT must list project_root")
        # Concrete how-to: prepend project_root when calling Read.
        self.assertRegex(self.text, r"PATH RESOLUTION",
                         "worker must have a PATH RESOLUTION section")
        # Negative: must explain that emitted finding paths stay project_root-relative
        # (sink_file format depends on this for dedup parser).
        self.assertIn("keep them `project_root`-relative", self.text,
                      "worker must NOT prepend project_root to finding sink_file")

    def test_output_target_is_waves_dir(self) -> None:
        self.assertIn("<review_root>/waves/<slice_id>.md", self.text)
        self.assertNotIn("SECURITY_REVIEW_RESULTS_<slice_id>.md", self.text)

    def test_changes_mode_uses_touched_by_diff(self) -> None:
        # Worker must rely on touched_by_diff (recipe-authoritative), not regrep diff itself.
        self.assertIn("touched_by_diff", self.text)
        self.assertNotIn("git diff origin/main...HEAD --name-only", self.text)

    def test_recon_bags_reading_documented(self) -> None:
        # Worker must know how to resolve recon_bags.{kind}.{name}.* via dot-notation.
        self.assertIn("recon_bags", self.text)
        self.assertIn("dot-notation", self.text.lower())

    def test_mcp_phpstorm_documented_as_conditional(self) -> None:
        self.assertIn("tool_versions.mcp_phpstorm", self.text)


class ConsoleRunnerResolution(unittest.TestCase):
    """Both commands must document the environment-aware console resolution."""

    def setUp(self) -> None:
        self.project = _load(PROJECT_CMD)
        self.changes = _load(CHANGES_CMD)

    def _both(self):
        return [("security-project.md", self.project), ("security-changes.md", self.changes)]

    def test_console_cmd_in_argument_hint(self) -> None:
        for name, text in self._both():
            with self.subTest(cmd=name):
                m = re.search(r'^argument-hint:\s*"(.+)"\s*$', text, re.MULTILINE)
                self.assertIsNotNone(m, f"{name}: no argument-hint")
                self.assertIn("--console-cmd=", m.group(1),
                              f"{name}: argument-hint missing --console-cmd=")

    def test_console_cmd_documented_in_arguments(self) -> None:
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertIn("--console-cmd=<template>", text,
                              f"{name}: --console-cmd not documented in ARGUMENTS")

    def test_resolve_console_step_present(self) -> None:
        # The pre-recon step that probes the environment and (when ambiguous)
        # asks the user how to run the console.
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertIn("environment.py", text,
                              f"{name}: missing environment.py probe invocation")
                self.assertIn("--console-entrypoint", text,
                              f"{name}: missing --console-entrypoint")
                self.assertIn("AskUserQuestion", text,
                              f"{name}: console resolution must ask via AskUserQuestion")

    def test_show_and_confirm_trust_model(self) -> None:
        # Never auto-run a repo-derived command: Makefile recipe body must be
        # shown for confirmation.
        for name, text in self._both():
            with self.subTest(cmd=name):
                low = text.lower()
                self.assertIn("docker compose exec -t", low,
                              f"{name}: container runner command not documented")
                self.assertTrue(
                    "recipe body" in low or "detail" in low,
                    f"{name}: Makefile recipe body (transparency) not mentioned",
                )

    def test_recon_task_forwards_console_decision(self) -> None:
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertIn("--console-cmd=<tpl>", text,
                              f"{name}: recon Task block does not forward --console-cmd")

    def test_non_interactive_records_gap_not_block(self) -> None:
        # CI must not block on AskUserQuestion; the gap is recorded instead.
        for name, text in self._both():
            with self.subTest(cmd=name):
                low = text.lower()
                self.assertIn("console_gap", low, f"{name}: console_gap not mentioned")


if __name__ == "__main__":
    unittest.main()
