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
        # YAML frontmatter `argument-hint:` must mention both flags so the harness
        # surfaces them in `/help` / completion.
        for name, text in self._both():
            with self.subTest(cmd=name):
                m = re.search(r'^argument-hint:\s*"(.+)"\s*$', text, re.MULTILINE)
                self.assertIsNotNone(m, f"{name}: no argument-hint frontmatter")
                hint = m.group(1)
                self.assertIn("--label=", hint, f"{name}: argument-hint missing --label=")
                self.assertIn("--review-root=", hint, f"{name}: argument-hint missing --review-root=")

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
        # Old SECURITY_CONTEXT.md in cwd must trigger warning, not abort or rm.
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertIn("Legacy v1 detected", text, f"{name}: missing legacy v1 banner")
                self.assertIn("test -f SECURITY_CONTEXT.md", text,
                              f"{name}: missing v1 file probe")
                # Must NOT remove or rename the legacy file.
                self.assertNotRegex(
                    text,
                    r"rm\s+-f?\s+SECURITY_CONTEXT\.md",
                    f"{name}: legacy v1 file must not be deleted automatically",
                )
                self.assertNotRegex(
                    text,
                    r"mv\s+SECURITY_CONTEXT\.md",
                    f"{name}: legacy v1 file must not be moved automatically",
                )

    def test_recon_agent_called_with_review_root(self) -> None:
        # Task(security-recon, ...) must include review_root in its prompt.
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
                self.assertIn("project_root:", block,
                              f"{name}: security-recon Task missing project_root")

    def test_validate_context_uses_review_root(self) -> None:
        # validate_context.py must be called with --review-root, never with the
        # legacy positional path.
        for name, text in self._both():
            with self.subTest(cmd=name):
                self.assertRegex(
                    text,
                    r'validate_context\.py --review-root "<REVIEW_ROOT>"',
                    f"{name}: validate_context.py must use --review-root",
                )
                self.assertNotIn("validate_context.py SECURITY_CONTEXT.md", text,
                                 f"{name}: legacy positional context path leaked")

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
        # Each Task(security, ...) call must pass review_root + relevant_section_paths
        # (dot-notation, not the v1 relevant_section_ids).
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
        # Orchestrator exposes --no-console for hostile-repo audits but only
        # forwards it when the user explicitly passed it — recipe decides
        # console enrichment in the default flow.
        self.assertIn("--no-console", self.text)
        self.assertIn("In normal mode `--no-console` is not needed", self.text)
        self.assertIn("only if the flag was passed to the orchestrator", self.text)

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


if __name__ == "__main__":
    unittest.main()
