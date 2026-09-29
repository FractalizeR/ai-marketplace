"""Tests for bin/run_info.py (run snapshot: build, harness, models per tier)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BIN = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BIN))

import run_info as ri  # noqa: E402

PLAN = [
    {"slice_id": "W1_PART1", "wave_id": "W1", "model": "opus"},
    {"slice_id": "W1_PART2", "wave_id": "W1", "model": "opus"},
    {"slice_id": "W3_PART1", "wave_id": "W3", "model": "sonnet"},
    {"slice_id": "WINF_PART1", "wave_id": "WINF", "model": "sonnet"},
    {"slice_id": "WX_PART1", "wave_id": "WX"},
]


_NEEDS_TOMLLIB = unittest.skipIf(ri.tomllib is None, "reading config.toml needs tomllib (Python >= 3.11)")


class _Dirs(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        base = Path(self._td.name)
        self.plugin = base / "plugin"
        self.review = base / "review"
        self.home = base / "codex_home"
        for d in (self.plugin, self.review, self.home):
            d.mkdir()
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        os.environ.pop(ri.ORCHESTRATOR_ENV, None)
        self.addCleanup(env.stop)

    def tearDown(self):
        self._td.cleanup()

    def claude_tree(self, version="9.1.0"):
        (self.plugin / "plugin.json").write_text(json.dumps({"version": version}))

    def codex_tree(self):
        (self.plugin / ri.BUILD_INFO_NAME).write_text(json.dumps(
            {"harness": "codex", "plugin_version": "9.1.0", "bundle_version": "0.9.0"}))

    def model_map(self, data):
        (self.review / ".model_map.json").write_text(json.dumps(data))

    def config(self, text):
        (self.home / "config.toml").write_text(text)

    def collect(self, orchestrator=None, plan=PLAN):
        return ri.collect(plugin_root=self.plugin, review_root=self.review, plan=plan,
                          orchestrator_model=orchestrator, home=self.home)


class ClaudeTreeTests(_Dirs):
    def test_labels_version_and_self_reported_orchestrator(self):
        self.claude_tree()
        info = self.collect(orchestrator="model-o")
        self.assertEqual(info.harness, "claude")
        self.assertEqual(info.plugin_version, "9.1.0")
        self.assertEqual((info.high, info.fast), ("opus", "sonnet"))
        self.assertEqual((info.orchestrator, info.orchestrator_source), ("model-o", "self-reported"))
        self.assertEqual(info.reasoning_effort, ri.UNKNOWN)

    def test_foreign_codex_map_in_review_root_is_ignored(self):
        self.claude_tree()
        self.model_map({"high": "codex-big", "fast": "codex-small"})
        info = self.collect()
        self.assertEqual((info.high, info.fast), ("opus", "sonnet"))
        self.assertEqual(info.orchestrator, ri.UNKNOWN)

    def test_tier_waves_from_plan(self):
        self.claude_tree()
        info = self.collect()
        self.assertEqual(info.tier_waves, {"high": ["W1"], "fast": ["W3", "WINF"]})

    def test_all_opus_layout(self):
        self.claude_tree()
        plan = [{"wave_id": "W4", "model": "opus"}, {"wave_id": "W3", "model": "sonnet"}]
        self.assertEqual(self.collect(plan=plan).tier_waves, {"high": ["W4"], "fast": ["W3"]})

    def test_no_manifest_no_stamp_is_unknown(self):
        info = self.collect()
        self.assertEqual((info.harness, info.plugin_version), (ri.UNKNOWN, ri.UNKNOWN))


class CodexTreeTests(_Dirs):
    @_NEEDS_TOMLLIB
    def test_map_ids_orchestrator_from_frsr_and_config(self):
        self.codex_tree()
        self.model_map({"high": "big", "fast": "small"})
        self.config('model = "big"\nmodel_reasoning_effort = "high"\n')
        with mock.patch.dict(os.environ, {ri.ORCHESTRATOR_ENV: "big"}):
            info = self.collect(orchestrator="ignored")
        self.assertEqual(info.harness, "codex")
        self.assertEqual((info.plugin_version, info.bundle_version), ("9.1.0", "0.9.0"))
        self.assertEqual((info.high, info.fast), ("big", "small"))
        self.assertEqual((info.orchestrator, info.orchestrator_source), ("big", "frsr"))
        self.assertEqual((info.reasoning_effort, info.config_model), ("high", "big"))

    def test_self_reported_orchestrator_without_frsr(self):
        self.codex_tree()
        info = self.collect(orchestrator="thread-model")
        self.assertEqual((info.orchestrator, info.orchestrator_source), ("thread-model", "self-reported"))

    def test_missing_or_pre_5_map_gives_unknown_tiers(self):
        self.codex_tree()
        self.assertEqual((self.collect().high, self.collect().fast), (ri.UNKNOWN, ri.UNKNOWN))
        self.model_map({"high": "a", "fast": "b", "provenance": "cli"})
        self.assertEqual(self.collect().high, ri.UNKNOWN)


@_NEEDS_TOMLLIB
class CodexConfigTests(_Dirs):
    def read(self):
        return ri.read_codex_config(self.home)

    def test_top_level(self):
        self.config('# c\nmodel = "m1" # trailing\nmodel_reasoning_effort = \'low\'\n[tools]\nmodel = "nope"\n')
        cfg = self.read()
        self.assertEqual((cfg["model"], cfg["model_reasoning_effort"]), ("m1", "low"))

    def test_profile_overrides_top_level(self):
        self.config('model = "m1"\nmodel_reasoning_effort = "low"\nprofile = "deep"\n'
                    '[profiles.deep]\nmodel_reasoning_effort = "high"\n'
                    '[profiles."other"]\nmodel = "m3"\n')
        cfg = self.read()
        self.assertEqual((cfg["model"], cfg["model_reasoning_effort"]), ("m1", "high"))

    def test_missing_or_garbage(self):
        self.assertEqual(self.read()["model"], None)
        self.config("this is = not [toml\n\x00")
        self.assertEqual(self.read()["model"], None)

    def test_non_string_values_of_other_keys_are_fine(self):
        self.config('approvals = true\nretries = 3\nmodel = "m1"\n[tools]\nweb = false\n')
        self.assertEqual(self.read()["model"], "m1")


class NoTomllibTests(_Dirs):
    def test_without_tomllib_config_is_unknown(self):
        """No hand-rolled TOML: on Python < 3.11 the values are unknown, never guessed."""
        self.config('model = "m1"\nmodel_reasoning_effort = "high"\n')
        with mock.patch.object(ri, "tomllib", None):
            cfg = ri.read_codex_config(self.home)
        self.assertEqual((cfg["model"], cfg["model_reasoning_effort"]), (None, None))


class PersistenceTests(_Dirs):
    def test_save_load_roundtrip_is_stable(self):
        self.claude_tree()
        info = self.collect(orchestrator="o")
        path = ri.save(info, self.review / ri.RUN_INFO_NAME)
        first = path.read_bytes()
        self.assertEqual(ri.load(path), info)
        ri.save(ri.load(path), path)
        self.assertEqual(path.read_bytes(), first)
        self.assertEqual([p.name for p in self.review.iterdir()], [ri.RUN_INFO_NAME])

    def test_load_missing_or_corrupt(self):
        self.assertIsNone(ri.load(self.review / "nope.json"))
        (self.review / "bad.json").write_text("{")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertIsNone(ri.load(self.review / "bad.json"))
        self.assertIn("WARNING", err.getvalue())

    def test_load_misshaped_is_none_with_a_warning(self):
        for data in ({"tier_waves": ["W1"]}, {"tier_waves": []}, {"models": "big"},
                     {"models": []}, {"harness": {"a": 1}}, {"bundle_version": 3},
                     {"tier_waves": {"high": "W1"}}, {"tier_waves": {"high": [1]}}, ["x"]):
            (self.review / "odd.json").write_text(json.dumps(data))
            with self.subTest(data=data), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertIsNone(ri.load(self.review / "odd.json"))
                self.assertIn("WARNING", err.getvalue())

    def test_load_deeply_nested_garbage_is_none(self):
        (self.review / "deep.json").write_text("[" * 200000)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(ri.load(self.review / "deep.json"))

    def test_unknown_harness_with_planned_waves_still_counts_as_recorded(self):
        info = self.collect()
        self.assertEqual(info.harness, ri.UNKNOWN)
        self.assertTrue(info.is_recorded())
        self.assertFalse(ri.RunInfo().is_recorded())


class CliTests(_Dirs):
    def test_codex_config_cli_on_system_python(self):
        """frsr runs whatever python3 is on PATH; macOS /usr/bin/python3 is 3.9
        (no tomllib → unknown, not an error)."""
        self.config('model = "m1"\n')
        pythons = [sys.executable] + [p for p in ("/usr/bin/python3",) if shutil.which(p)]
        for py in pythons:
            out = subprocess.run(
                [py, str(BIN / "run_info.py"), "--codex-config"],
                capture_output=True, text=True, env={**os.environ, "CODEX_HOME": str(self.home)},
            )
            self.assertEqual(out.returncode, 0, f"{py}: {out.stderr}")
            has_tomllib = subprocess.run([py, "-c", "import tomllib"], capture_output=True).returncode == 0
            self.assertEqual(json.loads(out.stdout)["model"], "m1" if has_tomllib else None, py)


if __name__ == "__main__":
    unittest.main()
