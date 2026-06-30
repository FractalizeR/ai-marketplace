"""Tests for shared/model_resolver.py (Phase 2A).

Subprocess is the single injected seam — every test passes a FAKE runner; no
real `opencode`/`codex` binary is ever invoked.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.contracts import ResolverError, RunResult  # noqa: E402
from shared import model_resolver as mr  # noqa: E402


def make_runner(stdout="", returncode=0, timed_out=False, record=None):
    """Build a fake Runner returning a canned RunResult; records argv calls."""

    def runner(argv, timeout):
        if record is not None:
            record.append((list(argv), timeout))
        return RunResult(
            returncode=None if timed_out else returncode,
            stdout=stdout,
            stderr="",
            timed_out=timed_out,
        )

    return runner


def models(*ids, provider=None, cw=None):
    return [mr.ModelInfo(id=i, raw=i, provider=provider, context_window=cw) for i in ids]


class DiscoveryTests(unittest.TestCase):
    def test_none_cmd_returns_empty(self):
        self.assertEqual(mr.discover_models(None, runner=make_runner()), [])

    def test_codex_json_shape(self):
        payload = json.dumps({"models": [
            {"slug": "o3", "provider": "openai", "context_window": 200000},
            {"slug": "o4-mini", "provider": "openai"},
        ]})
        out = mr.discover_models("codex models", runner=make_runner(stdout=payload))
        self.assertEqual([m.id for m in out], ["o3", "o4-mini"])  # sorted by id
        self.assertEqual(out[0].provider, "openai")
        self.assertEqual(out[0].context_window, 200000)

    def test_opencode_line_shape(self):
        text = "anthropic/claude-opus\nanthropic/claude-haiku\n"
        out = mr.discover_models("opencode models", runner=make_runner(stdout=text))
        # sorted by id
        self.assertEqual([m.id for m in out],
                         ["anthropic/claude-haiku", "anthropic/claude-opus"])
        self.assertEqual(out[0].provider, "anthropic")

    def test_shlex_split_not_shell(self):
        rec: list = []
        mr.discover_models("codex models --json", runner=make_runner(stdout="{\"models\": [{\"slug\": \"a\"}]}", record=rec))
        self.assertEqual(rec[0][0], ["codex", "models", "--json"])

    def test_unparseable_raises(self):
        with self.assertRaises(ResolverError):
            mr.discover_models("x", runner=make_runner(stdout="   "))

    def test_nonzero_exit_raises(self):
        with self.assertRaises(ResolverError):
            mr.discover_models("x", runner=make_runner(returncode=1, stdout="anthropic/x"))

    def test_normalize_applied(self):
        out = mr.discover_models(
            "x", runner=make_runner(stdout="A\nB\n"),
            normalize=lambda r: r.strip().lower(),
        )
        self.assertEqual([m.id for m in out], ["a", "b"])

    def test_parser_reads_input(self):
        # Mutating the synthetic input flips the output (proves the parser reads it).
        out1 = mr.discover_models("x", runner=make_runner(stdout="p/one\n"))
        out2 = mr.discover_models("x", runner=make_runner(stdout="p/two\n"))
        self.assertNotEqual([m.id for m in out1], [m.id for m in out2])


class ProposeTests(unittest.TestCase):
    def test_collapse_on_one(self):
        tm = mr.propose_tier_map(models("solo"), None)
        self.assertEqual(tm.high, "solo")
        self.assertEqual(tm.fast, "solo")
        self.assertEqual(tm.provenance, "collapsed")

    def test_error_on_zero(self):
        with self.assertRaises(ResolverError):
            mr.propose_tier_map([], None)

    def test_pattern_ranking(self):
        tm = mr.propose_tier_map(models("opus", "haiku"), None)
        self.assertEqual(tm.high, "opus")
        self.assertEqual(tm.fast, "haiku")

    def test_fast_first_precedence_pro_lite(self):
        # "pro-lite" matches both 'pro' (high) and 'lite' (fast); fast wins.
        ms = models("pro-lite", "reasoner")
        tm = mr.propose_tier_map(ms, None)
        self.assertEqual(tm.fast, "pro-lite")
        self.assertEqual(tm.high, "reasoner")

    def test_tiebreak_context_window_desc(self):
        ms = [
            mr.ModelInfo(id="opus-a", raw="opus-a", provider="z", context_window=100),
            mr.ModelInfo(id="opus-b", raw="opus-b", provider="a", context_window=900),
        ]
        tm = mr.propose_tier_map(ms + models("haiku"), None)
        self.assertEqual(tm.high, "opus-b")  # larger context window wins

    def test_per_tier_defaults_present(self):
        ms = models("opus", "haiku", "sonnet")
        tm = mr.propose_tier_map(ms, {"high": "sonnet", "fast": "haiku"})
        self.assertEqual(tm.high, "sonnet")
        self.assertEqual(tm.fast, "haiku")

    def test_per_tier_defaults_absent_falls_back_to_pattern(self):
        ms = models("opus", "haiku")
        tm = mr.propose_tier_map(ms, {"high": "ghost"})  # ghost not present
        self.assertEqual(tm.high, "opus")  # pattern fallback


class ConfirmTests(unittest.TestCase):
    def test_proposed_passthrough(self):
        prop = mr.TierMap(high="opus", fast="haiku", provenance="proposed")
        out = mr.confirm_tier_map(prop, discovered_ids={"opus", "haiku"})
        self.assertEqual((out.high, out.fast), ("opus", "haiku"))

    def test_cli_override_priority(self):
        prop = mr.TierMap(high="opus", fast="haiku", provenance="proposed")
        out = mr.confirm_tier_map(
            prop, discovered_ids={"opus", "haiku", "sonnet"},
            cli_overrides={"high": "sonnet"},
        )
        self.assertEqual(out.high, "sonnet")
        self.assertEqual(out.provenance, "cli")

    def test_cli_unknown_id_raises_with_list(self):
        prop = mr.TierMap(high="opus", fast="haiku", provenance="proposed")
        with self.assertRaises(ResolverError) as ctx:
            mr.confirm_tier_map(
                prop, discovered_ids={"opus", "haiku"},
                cli_overrides={"high": "ghost"},
            )
        self.assertIsNotNone(ctx.exception.available)
        self.assertIn("opus", ctx.exception.available)

    def test_persisted_priority_over_proposed(self):
        prop = mr.TierMap(high="opus", fast="haiku", provenance="proposed")
        persisted = mr.TierMap(high="o3", fast="o4-mini", provenance="persisted")
        out = mr.confirm_tier_map(
            prop, discovered_ids={"o3", "o4-mini", "opus", "haiku"},
            persisted=persisted,
        )
        self.assertEqual((out.high, out.fast), ("o3", "o4-mini"))

    def test_persisted_stale_non_interactive_raises(self):
        prop = mr.TierMap(high="opus", fast="haiku", provenance="proposed")
        persisted = mr.TierMap(high="gone", fast="haiku", provenance="persisted")
        with self.assertRaises(ResolverError):
            mr.confirm_tier_map(
                prop, discovered_ids={"opus", "haiku"}, persisted=persisted,
            )

    def test_non_interactive_with_checkpoint_is_usage_error(self):
        prop = mr.TierMap(high="opus", fast="haiku", provenance="proposed")
        with self.assertRaises(ResolverError):
            mr.confirm_tier_map(
                prop, discovered_ids={"opus", "haiku"},
                checkpoint=lambda p, m: p, non_interactive=True,
            )


class PersistTests(unittest.TestCase):
    def test_persist_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            rr = Path(d)
            tm = mr.TierMap(high="opus", fast="haiku", provenance="proposed")
            path = mr.persist(tm, rr)
            self.assertTrue(path.is_file())
            loaded = mr.load_persisted(rr)
            self.assertEqual((loaded.high, loaded.fast), ("opus", "haiku"))

    def test_as_dict_exact_keys(self):
        tm = mr.TierMap(high="o", fast="h", provenance="cli")
        self.assertEqual(set(tm.as_dict().keys()), {"high", "fast", "provenance"})

    def test_load_missing_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(mr.load_persisted(Path(d)))

    def test_load_corrupt_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".model_map.json").write_text("{not json", encoding="utf-8")
            self.assertIsNone(mr.load_persisted(Path(d)))


class ParseCliModelsTests(unittest.TestCase):
    def test_both_tiers(self):
        self.assertEqual(mr.parse_cli_models("high=a,fast=b"), {"high": "a", "fast": "b"})

    def test_partial_single_tier(self):
        self.assertEqual(mr.parse_cli_models("high=a"), {"high": "a"})

    def test_unknown_key_raises(self):
        with self.assertRaises(ResolverError):
            mr.parse_cli_models("mid=a")

    def test_duplicate_key_raises(self):
        with self.assertRaises(ResolverError):
            mr.parse_cli_models("high=a,high=b")

    def test_empty_value_raises(self):
        with self.assertRaises(ResolverError):
            mr.parse_cli_models("high=")

    def test_empty_spec_raises(self):
        with self.assertRaises(ResolverError):
            mr.parse_cli_models("")


class ResolveTests(unittest.TestCase):
    def test_claude_static_passthrough(self):
        with tempfile.TemporaryDirectory() as d:
            tm = mr.resolve(
                discovery_cmd=None, tier_defaults=None, review_root=Path(d),
                runner=make_runner(),
            )
            self.assertEqual((tm.high, tm.fast), ("opus", "sonnet"))
            # Claude path does NOT persist.
            self.assertIsNone(mr.load_persisted(Path(d)))

    def test_claude_static_with_cli_overrides(self):
        with tempfile.TemporaryDirectory() as d:
            tm = mr.resolve(
                discovery_cmd=None, tier_defaults=None, review_root=Path(d),
                runner=make_runner(), cli_overrides={"fast": "haiku"},
            )
            self.assertEqual((tm.high, tm.fast), ("opus", "haiku"))

    def test_discovery_path_persists(self):
        with tempfile.TemporaryDirectory() as d:
            tm = mr.resolve(
                discovery_cmd="opencode models", tier_defaults=None,
                review_root=Path(d),
                runner=make_runner(stdout="p/opus\np/haiku\n"),
            )
            self.assertEqual(tm.high, "p/opus")
            self.assertEqual(tm.fast, "p/haiku")
            self.assertIsNotNone(mr.load_persisted(Path(d)))

    def test_persisted_reuse(self):
        with tempfile.TemporaryDirectory() as d:
            mr.persist(mr.TierMap(high="p/opus", fast="p/haiku", provenance="persisted"), Path(d))
            tm = mr.resolve(
                discovery_cmd="opencode models", tier_defaults=None,
                review_root=Path(d),
                runner=make_runner(stdout="p/opus\np/haiku\np/sonnet\n"),
            )
            # persisted ids still discovered → reused.
            self.assertEqual((tm.high, tm.fast), ("p/opus", "p/haiku"))

    def test_remodel_ignores_persisted(self):
        with tempfile.TemporaryDirectory() as d:
            mr.persist(mr.TierMap(high="old", fast="old2", provenance="persisted"), Path(d))
            tm = mr.resolve(
                discovery_cmd="opencode models", tier_defaults=None,
                review_root=Path(d), remodel=True,
                runner=make_runner(stdout="p/opus\np/haiku\n"),
            )
            self.assertEqual(tm.high, "p/opus")

    def test_em2_non_interactive_stale_raises(self):
        with tempfile.TemporaryDirectory() as d:
            mr.persist(mr.TierMap(high="gone", fast="p/haiku", provenance="persisted"), Path(d))
            with self.assertRaises(ResolverError):
                mr.resolve(
                    discovery_cmd="opencode models", tier_defaults=None,
                    review_root=Path(d),
                    runner=make_runner(stdout="p/opus\np/haiku\n"),
                )

    def test_em2_interactive_resolves_via_checkpoint(self):
        # Stale persisted + interactive: confirm hands the freshly-discovered
        # models to the checkpoint (resolve owns discovery), which picks a valid
        # fresh map. The checkpoint is consulted and the result is the fresh map.
        seen = {"models": None}

        def checkpoint(proposed, ms):
            seen["models"] = [m.id for m in ms]
            return proposed  # operator accepts the freshly proposed map

        with tempfile.TemporaryDirectory() as d:
            mr.persist(mr.TierMap(high="gone", fast="p/haiku", provenance="persisted"), Path(d))
            tm = mr.resolve(
                discovery_cmd="opencode models", tier_defaults=None,
                review_root=Path(d), non_interactive=False, checkpoint=checkpoint,
                runner=make_runner(stdout="p/opus\np/haiku\n"),
            )
            self.assertEqual(tm.high, "p/opus")
            # checkpoint received ModelInfo list (not bare ids), per AD-2A5.
            self.assertEqual(seen["models"], ["p/haiku", "p/opus"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self._old_stdout = sys.stdout
        sys.stdout = io.StringIO()

    def tearDown(self):
        sys.stdout = self._old_stdout

    def test_claude_exit0(self):
        with tempfile.TemporaryDirectory() as d:
            rc = mr.main(["--review-root", d], runner=make_runner())
            self.assertEqual(rc, 0)

    def test_bad_models_exit2(self):
        with tempfile.TemporaryDirectory() as d:
            rc = mr.main(["--review-root", d, "--models", "mid=x"], runner=make_runner())
            self.assertEqual(rc, 2)

    def test_discovery_unknown_models_exit2_lists_available(self):
        with tempfile.TemporaryDirectory() as d:
            err = io.StringIO()
            old = sys.stderr
            sys.stderr = err
            try:
                rc = mr.main(
                    ["--review-root", d, "--discovery-cmd", "opencode models",
                     "--models", "high=ghost"],
                    runner=make_runner(stdout="p/opus\np/haiku\n"),
                )
            finally:
                sys.stderr = old
            self.assertEqual(rc, 2)
            self.assertIn("Available ids", err.getvalue())

    def test_interactive_stdin_checkpoint(self):
        with tempfile.TemporaryDirectory() as d:
            stdin = io.StringIO("\n")  # accept proposed
            rc = mr.main(
                ["--review-root", d, "--discovery-cmd", "opencode models",
                 "--interactive"],
                runner=make_runner(stdout="p/opus\np/haiku\n"),
                stdin=stdin,
            )
            self.assertEqual(rc, 0)


class RegressionFixTests(unittest.TestCase):
    """Post-code-review hardening (M2 resolve guard, L1 collapsed provenance,
    L7 malformed JSON, H1 spawn failure)."""

    def test_resolve_non_interactive_with_checkpoint_raises(self):
        # The usage error must fire at resolve() level, not be silently dropped (M2).
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ResolverError):
                mr.resolve(
                    discovery_cmd="opencode models",
                    tier_defaults=None,
                    review_root=Path(d),
                    runner=make_runner(stdout="p/opus\np/haiku\n"),
                    non_interactive=True,
                    checkpoint=lambda proposed, models: proposed,
                )

    def test_resolve_single_model_collapsed_provenance(self):
        # One discovered model → both tiers collapse; provenance survives confirm (L1).
        with tempfile.TemporaryDirectory() as d:
            tm = mr.resolve(
                discovery_cmd="opencode models",
                tier_defaults=None,
                review_root=Path(d),
                runner=make_runner(stdout="p/only-model\n"),
                non_interactive=True,
            )
            self.assertEqual(tm.high, tm.fast)
            self.assertEqual(tm.provenance, "collapsed")
            persisted = mr.load_persisted(Path(d))
            self.assertEqual(persisted.provenance, "collapsed")

    def test_malformed_json_discovery_raises(self):
        # JSON-looking output that fails to parse must NOT be line-parsed into
        # garbage models (L7).
        with self.assertRaises(ResolverError):
            mr.discover_models(
                "codex models", runner=make_runner(stdout='{"models": [bad json')
            )

    def test_default_runner_spawn_failure_returns_nonzero(self):
        # Missing discovery binary → non-zero RunResult, not a raised OSError (H1).
        result = mr.default_runner(["definitely-missing-bin-xyz-2a"], None)
        self.assertFalse(result.timed_out)
        self.assertNotIn(result.returncode, (0, None))


if __name__ == "__main__":
    unittest.main()
