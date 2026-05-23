"""Tests for environment-aware console runner resolution (Phase C).

Two layers:
1. Unit tests for the pure decision functions in recon_inventory:
   `decide_console_runner` (the precedence matrix) and `_environment_block`
   (console_gap logic).
2. CLI integration tests: the `environment` frontmatter block emitted by a real
   `recon_inventory.py` run across host / containerized / --console-cmd /
   --no-console / generic-recipe scenarios.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
RECON = BIN_DIR / "recon_inventory.py"
FIX_MIN = THIS_DIR / "fixtures" / "symfony_minimal"
FIX_GEN = THIS_DIR / "fixtures" / "generic_php"

sys.path.insert(0, str(BIN_DIR))
import recon_inventory as ri  # noqa: E402
from recon.environment import EnvProbe  # noqa: E402
from validate_context import parse_yaml_subset, FRONTMATTER_RE  # noqa: E402


def _probe(*, containerized=False, signals=None, host_php=True, version="8.3.0") -> EnvProbe:
    return EnvProbe(
        containerized=containerized,
        container_signals=list(signals or []),
        host_php_present=host_php,
        host_php_version=version if host_php else None,
        suggested_php_service="php" if containerized else None,
        suggestions=[],
        reason="test",
    )


SYM_ENTRY = ["php", "bin/console"]


# ---------------------------------------------------------------------------
# decide_console_runner — precedence matrix.
# ---------------------------------------------------------------------------


class DecideConsoleRunner(unittest.TestCase):
    def setUp(self):
        self.cwd = Path("/tmp/project")

    def test_no_entrypoint_is_not_supported(self):
        r = ri.decide_console_runner(
            _probe(), no_console=False, console_cmd=None, entrypoint=None, cwd=self.cwd
        )
        self.assertEqual(r.mode, "disabled")
        self.assertEqual(r.disabled_reason, "console_not_supported_by_recipe")

    def test_no_console_flag_disables_even_when_host_ok(self):
        r = ri.decide_console_runner(
            _probe(host_php=True), no_console=True, console_cmd=None,
            entrypoint=SYM_ENTRY, cwd=self.cwd,
        )
        self.assertEqual(r.mode, "disabled")
        self.assertEqual(r.disabled_reason, "console_disabled_by_flag")

    def test_no_console_flag_beats_console_cmd(self):
        # --no-console wins over --console-cmd (explicit "off" is dominant).
        r = ri.decide_console_runner(
            _probe(), no_console=True, console_cmd="docker compose exec php php bin/console",
            entrypoint=SYM_ENTRY, cwd=self.cwd,
        )
        self.assertEqual(r.mode, "disabled")
        self.assertEqual(r.disabled_reason, "console_disabled_by_flag")

    def test_console_cmd_yields_custom(self):
        tpl = "docker compose exec -T php php bin/console"
        r = ri.decide_console_runner(
            _probe(containerized=True, signals=["docker-compose.yml"]),
            no_console=False, console_cmd=tpl, entrypoint=SYM_ENTRY, cwd=self.cwd,
        )
        self.assertEqual(r.mode, "custom")
        self.assertEqual(r.cmd_template, tpl)

    def test_console_cmd_beats_containerized(self):
        r = ri.decide_console_runner(
            _probe(containerized=True, signals=["docker-compose.yml"]),
            no_console=False, console_cmd="make console CMD={args}",
            entrypoint=SYM_ENTRY, cwd=self.cwd,
        )
        self.assertEqual(r.mode, "custom")

    def test_containerized_disables_with_env_runner_unknown(self):
        r = ri.decide_console_runner(
            _probe(containerized=True, signals=["docker-compose.yml", "Dockerfile"]),
            no_console=False, console_cmd=None, entrypoint=SYM_ENTRY, cwd=self.cwd,
        )
        self.assertEqual(r.mode, "disabled")
        self.assertTrue(r.disabled_reason.startswith("env_runner_unknown"))
        # Surfaces the detected signals so the operator knows why.
        self.assertIn("docker-compose.yml", r.disabled_reason)

    def test_host_php_present_yields_host_runner(self):
        r = ri.decide_console_runner(
            _probe(containerized=False, host_php=True),
            no_console=False, console_cmd=None, entrypoint=SYM_ENTRY, cwd=self.cwd,
        )
        self.assertEqual(r.mode, "host")
        self.assertEqual(r.cmd_template, "php bin/console")

    def test_no_php_no_container_disables(self):
        r = ri.decide_console_runner(
            _probe(containerized=False, host_php=False),
            no_console=False, console_cmd=None, entrypoint=SYM_ENTRY, cwd=self.cwd,
        )
        self.assertEqual(r.mode, "disabled")
        self.assertTrue(r.disabled_reason.startswith("env_runner_unknown"))
        self.assertIn("php not on host PATH", r.disabled_reason)

    def test_host_entrypoint_is_shell_joined(self):
        # An entrypoint with a space-bearing token must be shell-quoted.
        r = ri.decide_console_runner(
            _probe(host_php=True), no_console=False, console_cmd=None,
            entrypoint=["php", "artisan tinker"], cwd=self.cwd,
        )
        self.assertEqual(r.mode, "host")
        self.assertEqual(r.cmd_template, "php 'artisan tinker'")

    def test_malformed_console_cmd_yields_disabled(self):
        # MINOR-2: an unbalanced quote in --console-cmd must not crash recon —
        # it degrades to a disabled runner with a clear reason.
        r = ri.decide_console_runner(
            _probe(), no_console=False, console_cmd='make console CMD="unclosed',
            entrypoint=SYM_ENTRY, cwd=self.cwd,
        )
        self.assertEqual(r.mode, "disabled")
        self.assertTrue(r.disabled_reason.startswith("invalid_console_cmd"))

    def test_console_cmd_with_args_placeholder_is_valid(self):
        # A well-formed {args} template passes validation and yields custom.
        r = ri.decide_console_runner(
            _probe(), no_console=False, console_cmd="make console CMD={args}",
            entrypoint=SYM_ENTRY, cwd=self.cwd,
        )
        self.assertEqual(r.mode, "custom")
        self.assertEqual(r.cmd_template, "make console CMD={args}")


# ---------------------------------------------------------------------------
# _environment_block — console_gap logic.
# ---------------------------------------------------------------------------


class EnvironmentBlock(unittest.TestCase):
    def setUp(self):
        self.cwd = Path("/tmp/project")

    def test_env_runner_unknown_is_a_gap(self):
        probe = _probe(containerized=True, signals=["docker-compose.yml"])
        runner = ri.decide_console_runner(
            probe, no_console=False, console_cmd=None, entrypoint=SYM_ENTRY, cwd=self.cwd
        )
        block = ri._environment_block(probe, runner, SYM_ENTRY, console_used=False)
        self.assertTrue(block["console_gap"])
        self.assertEqual(block["console_mode"], "disabled")
        self.assertTrue(block["console_gap_reason"].startswith("env_runner_unknown"))
        self.assertEqual(block["container_signals"], ["docker-compose.yml"])
        self.assertTrue(block["containerized"])

    def test_no_console_flag_is_a_gap(self):
        probe = _probe()
        runner = ri.decide_console_runner(
            probe, no_console=True, console_cmd=None, entrypoint=SYM_ENTRY, cwd=self.cwd
        )
        block = ri._environment_block(probe, runner, SYM_ENTRY, console_used=False)
        self.assertTrue(block["console_gap"])
        self.assertEqual(block["console_gap_reason"], "console_disabled_by_flag")

    def test_not_supported_is_not_a_gap(self):
        probe = _probe()
        runner = ri.decide_console_runner(
            probe, no_console=False, console_cmd=None, entrypoint=None, cwd=self.cwd
        )
        block = ri._environment_block(probe, runner, None, console_used=False)
        self.assertFalse(block["console_gap"])
        self.assertIsNone(block["console_gap_reason"])
        self.assertEqual(block["console_mode"], "disabled")

    def test_host_mode_that_ran_is_not_a_gap(self):
        probe = _probe(host_php=True)
        runner = ri.decide_console_runner(
            probe, no_console=False, console_cmd=None, entrypoint=SYM_ENTRY, cwd=self.cwd
        )
        block = ri._environment_block(probe, runner, SYM_ENTRY, console_used=True)
        self.assertEqual(block["console_mode"], "host")
        self.assertFalse(block["console_gap"])
        self.assertIsNone(block["console_gap_reason"])
        self.assertEqual(block["host_php_version"], "8.3.0")

    def test_host_runner_smoke_failure_is_a_gap(self):
        # MAJOR-1 regression: a host runner was resolved but the console did NOT
        # actually run (smoke failed) → still a coverage gap, not silent.
        probe = _probe(host_php=True)
        runner = ri.decide_console_runner(
            probe, no_console=False, console_cmd=None, entrypoint=SYM_ENTRY, cwd=self.cwd
        )
        self.assertEqual(runner.mode, "host")
        block = ri._environment_block(probe, runner, SYM_ENTRY, console_used=False)
        self.assertTrue(block["console_gap"])
        self.assertEqual(block["console_mode"], "host")
        self.assertTrue(block["console_gap_reason"].startswith("console_runtime_failed"))

    def test_custom_mode_that_ran_is_not_a_gap(self):
        probe = _probe(containerized=True, signals=["docker-compose.yml"])
        runner = ri.decide_console_runner(
            probe, no_console=False, console_cmd="docker compose exec -T php php bin/console",
            entrypoint=SYM_ENTRY, cwd=self.cwd,
        )
        block = ri._environment_block(probe, runner, SYM_ENTRY, console_used=True)
        self.assertEqual(block["console_mode"], "custom")
        self.assertFalse(block["console_gap"])

    def test_block_has_no_signals_key_when_empty(self):
        probe = _probe(containerized=False, signals=[])
        runner = ri.decide_console_runner(
            probe, no_console=False, console_cmd=None, entrypoint=SYM_ENTRY, cwd=self.cwd
        )
        block = ri._environment_block(probe, runner, SYM_ENTRY, console_used=True)
        self.assertNotIn("container_signals", block)


# ---------------------------------------------------------------------------
# CLI integration — the `environment` frontmatter block end to end.
# ---------------------------------------------------------------------------


def _run_cli(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(RECON), *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _read_fm(review_root: Path) -> dict:
    text = (review_root / "CONTEXT.md").read_text(encoding="utf-8")
    m = FRONTMATTER_RE.match(text)
    assert m, f"no frontmatter in {review_root}/CONTEXT.md"
    return parse_yaml_subset(m.group(1))


def _make_containerized_symfony(root: Path) -> None:
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "console").write_text("#!/usr/bin/env php\n<?php\n")
    (root / "docker-compose.yml").write_text(
        "services:\n  php:\n    image: php:8.4-fpm\n  db:\n    image: mysql:8\n"
    )
    (root / "composer.json").write_text('{"require": {"symfony/framework-bundle": "^7.0"}}')


class EnvironmentBlockCLI(unittest.TestCase):
    def test_block_present_with_required_keys(self):
        with tempfile.TemporaryDirectory() as td:
            rr = Path(td) / "r"
            proc = _run_cli(str(FIX_MIN), "--recipe", "symfony", "--review-root", str(rr),
                            "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            env = _read_fm(rr)["environment"]
            for k in ("containerized", "host_php_present", "host_php_version",
                      "console_mode", "console_gap", "console_gap_reason"):
                self.assertIn(k, env)
            self.assertFalse(env["containerized"])
            self.assertEqual(env["console_mode"], "disabled")
            self.assertEqual(env["console_gap_reason"], "console_disabled_by_flag")

    def test_containerized_project_disables_with_gap(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            rr = Path(td) / "r"
            proc = _run_cli(str(proj), "--recipe", "symfony", "--review-root", str(rr))
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            fm = _read_fm(rr)
            env = fm["environment"]
            self.assertTrue(env["containerized"])
            self.assertEqual(env["console_mode"], "disabled")
            self.assertTrue(env["console_gap"])
            self.assertIn("docker-compose.yml", env["container_signals"])
            # Loud coverage-gap warning surfaced in frontmatter.warnings.
            gap_warnings = [w for w in fm["warnings"] if w.startswith("coverage_gap:")]
            self.assertEqual(len(gap_warnings), 1, msg=fm["warnings"])
            self.assertIn("env_runner_unknown", gap_warnings[0])

    def test_console_cmd_that_runs_has_no_gap(self):
        # A custom runner whose console actually executes (smoke rc=0) → no gap.
        # `true` ignores its args and exits 0, so `true list` smokes clean.
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            rr = Path(td) / "r"
            proc = _run_cli(str(proj), "--recipe", "symfony", "--review-root", str(rr),
                            "--console-cmd", "true")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            fm = _read_fm(rr)
            self.assertEqual(fm["environment"]["console_mode"], "custom")
            self.assertFalse(fm["environment"]["console_gap"], msg=fm["environment"])
            self.assertEqual([w for w in fm["warnings"] if w.startswith("coverage_gap:")], [])

    def test_console_cmd_runtime_failure_is_a_gap(self):
        # MAJOR-1 (end to end): a custom runner that FAILS at runtime (`false`
        # exits 1) enriches nothing → console_gap recorded even though a runner
        # was resolved (mode=custom, not disabled).
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            rr = Path(td) / "r"
            proc = _run_cli(str(proj), "--recipe", "symfony", "--review-root", str(rr),
                            "--console-cmd", "false")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            env = _read_fm(rr)["environment"]
            self.assertEqual(env["console_mode"], "custom")
            self.assertTrue(env["console_gap"], msg=env)
            self.assertTrue(env["console_gap_reason"].startswith("console_runtime_failed"))

    def test_malformed_console_cmd_does_not_crash(self):
        # MINOR-2 (end to end): an unbalanced quote in --console-cmd must not
        # crash recon — it degrades to a disabled runner + recorded gap.
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            rr = Path(td) / "r"
            proc = _run_cli(str(proj), "--recipe", "symfony", "--review-root", str(rr),
                            "--console-cmd", 'make console CMD="unclosed')
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            env = _read_fm(rr)["environment"]
            self.assertEqual(env["console_mode"], "disabled")
            self.assertTrue(env["console_gap"])
            self.assertTrue(env["console_gap_reason"].startswith("invalid_console_cmd"))

    def test_no_console_does_not_emit_loud_gap_warning(self):
        # --no-console is the user's explicit choice: console_gap is recorded in
        # the environment block, but the recipe must NOT add a noisy
        # `coverage_gap:` warning (the `console_disabled_by_flag` warning covers it).
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _make_containerized_symfony(proj)
            rr = Path(td) / "r"
            proc = _run_cli(str(proj), "--recipe", "symfony", "--review-root", str(rr),
                            "--no-console")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            fm = _read_fm(rr)
            self.assertTrue(fm["environment"]["console_gap"])
            self.assertEqual([w for w in fm["warnings"] if w.startswith("coverage_gap:")], [])
            self.assertIn("console_disabled_by_flag", fm["warnings"])

    def test_generic_recipe_has_no_console_gap(self):
        with tempfile.TemporaryDirectory() as td:
            rr = Path(td) / "r"
            proc = _run_cli(str(FIX_GEN), "--recipe", "generic_php", "--review-root", str(rr))
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            env = _read_fm(rr)["environment"]
            self.assertEqual(env["console_mode"], "disabled")
            self.assertFalse(env["console_gap"])
            self.assertIsNone(env["console_gap_reason"])


if __name__ == "__main__":
    unittest.main()
