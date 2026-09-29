"""Tests for shared/model_resolver.py (operator-supplied {high, fast} tier map)."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.contracts import ResolverError  # noqa: E402
from shared import model_resolver as mr  # noqa: E402


class PersistTests(unittest.TestCase):
    def test_persist_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            tm = mr.TierMap(high="big", fast="small")
            path = mr.persist(tm, Path(d) / "review")
            self.assertTrue(path.is_file())
            self.assertEqual(mr.load_persisted(Path(d) / "review"), tm)

    def test_file_shape_is_exactly_high_and_fast(self):
        with tempfile.TemporaryDirectory() as d:
            path = mr.persist(mr.TierMap(high="a", fast="b"), Path(d))
            self.assertEqual(json.loads(path.read_text()), {"high": "a", "fast": "b"})

    def test_load_missing_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(mr.load_persisted(Path(d)))

    def test_load_corrupt_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".model_map.json").write_text("{not json")
            self.assertIsNone(mr.load_persisted(Path(d)))

    def test_load_incomplete_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".model_map.json").write_text('{"high": "a"}')
            self.assertIsNone(mr.load_persisted(Path(d)))
            (Path(d) / ".model_map.json").write_text('{"high": "a", "fast": ""}')
            self.assertIsNone(mr.load_persisted(Path(d)))

    def test_any_provenance_key_marks_a_pre_5_0_map_and_is_ignored(self):
        # 4.x recorded "cli" for a map with one guessed tier and "persisted" after
        # any re-run, so the value says nothing about who chose the ids.
        for prov in ("cli", "proposed", "collapsed", "persisted"):
            with self.subTest(provenance=prov), tempfile.TemporaryDirectory() as d:
                (Path(d) / ".model_map.json").write_text(
                    json.dumps({"high": "a", "fast": "b", "provenance": prov}))
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertIsNone(mr.load_persisted(Path(d)))
                self.assertIn("--models", err.getvalue())
                self.assertIn("pre-5.0", err.getvalue())


class InspectTests(unittest.TestCase):
    def _status(self, text=None):
        with tempfile.TemporaryDirectory() as d:
            if text is not None:
                (Path(d) / ".model_map.json").write_text(text)
            return mr.inspect_persisted(Path(d))

    def test_statuses(self):
        self.assertEqual(self._status(), ("absent", None))
        self.assertEqual(self._status('{"high": "a", "fast": "b"}'),
                         ("usable", mr.TierMap("a", "b")))
        self.assertEqual(self._status('{"high": "a", "fast": "b", "provenance": "cli"}'),
                         ("ignored-pre-5.0", None))
        self.assertEqual(self._status('{"high": "a"}'), ("invalid", None))
        self.assertEqual(self._status('not json'), ("invalid", None))

    def test_inspection_prints_nothing(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self._status('{"high": "a", "fast": "b", "provenance": "cli"}')
        self.assertEqual(err.getvalue(), "")


class ParseCliModelsTests(unittest.TestCase):
    def test_both_tiers(self):
        self.assertEqual(mr.parse_cli_models("high=a,fast=b"), mr.TierMap("a", "b"))

    def test_order_and_spaces_tolerated(self):
        self.assertEqual(mr.parse_cli_models(" fast = b , high = a "), mr.TierMap("a", "b"))

    def test_partial_is_rejected(self):
        for spec in ("high=a", "fast=b"):
            with self.assertRaises(ResolverError) as cm:
                mr.parse_cli_models(spec)
            self.assertIn("both tiers", str(cm.exception))

    def test_unknown_key_raises(self):
        with self.assertRaises(ResolverError):
            mr.parse_cli_models("high=a,fast=b,mid=c")

    def test_duplicate_key_raises(self):
        with self.assertRaises(ResolverError):
            mr.parse_cli_models("high=a,high=b,fast=c")

    def test_empty_value_raises(self):
        with self.assertRaises(ResolverError):
            mr.parse_cli_models("high=,fast=b")

    def test_empty_spec_raises(self):
        with self.assertRaises(ResolverError):
            mr.parse_cli_models("")


class ResolveTests(unittest.TestCase):
    def test_models_flag_persists(self):
        with tempfile.TemporaryDirectory() as d:
            tm = mr.resolve(review_root=Path(d) / "r", models="high=a,fast=b")
            self.assertEqual(tm, mr.TierMap("a", "b"))
            self.assertEqual(mr.load_persisted(Path(d) / "r"), tm)

    def test_persisted_reused_without_flag(self):
        with tempfile.TemporaryDirectory() as d:
            mr.persist(mr.TierMap("a", "b"), Path(d))
            self.assertEqual(mr.resolve(review_root=Path(d), models=None), mr.TierMap("a", "b"))

    def test_models_flag_overwrites_persisted(self):
        with tempfile.TemporaryDirectory() as d:
            mr.persist(mr.TierMap("old-h", "old-f"), Path(d))
            mr.resolve(review_root=Path(d), models="high=n1,fast=n2")
            self.assertEqual(mr.load_persisted(Path(d)), mr.TierMap("n1", "n2"))

    def test_nothing_set_raises_with_hint(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ResolverError) as cm:
                mr.resolve(review_root=Path(d), models=None)
            self.assertIn("--models high=<id>,fast=<id>", str(cm.exception))
            self.assertIn("codex debug models", str(cm.exception))

    def test_partial_flag_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ResolverError):
                mr.resolve(review_root=Path(d) / "r", models="high=a")
            self.assertFalse((Path(d) / "r").exists())


class CliTests(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mr.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_models_exit0_prints_map(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out, _ = self._run(["--review-root", d, "--models", "high=a,fast=b"])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out), {"high": "a", "fast": "b"})

    def test_missing_map_exit2_with_hint(self):
        with tempfile.TemporaryDirectory() as d:
            rc, _, err = self._run(["--review-root", d])
            self.assertEqual(rc, 2)
            self.assertIn("--models", err)

    def test_partial_models_exit2(self):
        with tempfile.TemporaryDirectory() as d:
            rc, _, err = self._run(["--review-root", d, "--models", "high=a"])
            self.assertEqual(rc, 2)
            self.assertIn("both tiers", err)

    def test_check_validates_like_parse_cli_models_and_writes_nothing(self):
        rc, out, _ = self._run(["--check", "--models", " high = a , fast = b "])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out), {"high": "a", "fast": "b"})
        for spec in ("high=a,fast=b,mid=c", "high=a,high=z,fast=b", "high=a",
                     "high=,fast=b", ""):
            with self.subTest(spec=spec):
                rc, _, err = self._run(["--check", "--models", spec])
                self.assertEqual(rc, 2)
                self.assertIn("Error:", err)

    def test_check_does_not_touch_review_root(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "r"
            rc, _, _ = self._run(["--check", "--review-root", str(root),
                                  "--models", "high=a,fast=b"])
            self.assertEqual(rc, 0)
            self.assertFalse(root.exists())

    def test_describe_reports_status_and_high(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out, _ = self._run(["--describe", "--review-root", d])
            self.assertEqual((rc, json.loads(out)), (0, {"status": "absent"}))
            (Path(d) / ".model_map.json").write_text('{"high": "a", "fast": "b"}')
            rc, out, err = self._run(["--describe", "--review-root", d])
            self.assertEqual((rc, json.loads(out)), (0, {"status": "usable", "high": "a"}))
            (Path(d) / ".model_map.json").write_text(
                '{"high": "a", "fast": "b", "provenance": "cli"}')
            rc, out, err = self._run(["--describe", "--review-root", d])
            self.assertEqual(json.loads(out), {"status": "ignored-pre-5.0"})
            self.assertEqual(err, "")

    def test_describe_and_check_are_exclusive_and_need_their_inputs(self):
        for argv in (["--describe"], ["--check"], ["--describe", "--check", "--models", "high=a,fast=b"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    mr.main(argv)
                self.assertEqual(cm.exception.code, 2)

    def test_removed_flags_are_argparse_errors(self):
        with tempfile.TemporaryDirectory() as d:
            for flag in ("--discovery-cmd", "--interactive", "--remodel"):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as cm:
                        mr.main(["--review-root", d, flag, "x"] if flag == "--discovery-cmd"
                                else ["--review-root", d, flag])
                self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
