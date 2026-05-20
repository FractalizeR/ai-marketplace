"""Cost-estimate module — slice-id parsing, model lookup, render block."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent))

from dedupe.cost import (  # noqa: E402
    COST_PER_PART_USD,
    CostEstimate,
    _wave_id_from_slice,
    estimate_cost,
    render_cost_block,
)


class WaveIdParse(unittest.TestCase):
    def test_w1_part1(self):
        self.assertEqual(_wave_id_from_slice("W1_PART1"), "W1")

    def test_w12_part5(self):
        self.assertEqual(_wave_id_from_slice("W12_PART5"), "W12")

    def test_winf_part1(self):
        self.assertEqual(_wave_id_from_slice("WINF_PART1"), "WINF")

    def test_changes_suffix(self):
        self.assertEqual(_wave_id_from_slice("W2_PART3_CHANGES"), "W2")
        self.assertEqual(_wave_id_from_slice("WINF_PART1_CHANGES"), "WINF")

    def test_unknown_pattern_returns_none(self):
        for name in ("W1part1", "wave_1", "PART1_W1", "RANDOM_FILENAME", "W"):
            with self.subTest(name=name):
                self.assertIsNone(_wave_id_from_slice(name))


class EstimateCostBehaviour(unittest.TestCase):
    def test_returns_none_on_empty_input(self):
        self.assertIsNone(estimate_cost([], {"W1": "opus"}))

    def test_sums_per_model_costs(self):
        # 2 opus parts (W1) + 3 sonnet parts (W3) = 2*0.30 + 3*0.06 = 0.78
        paths = [
            Path("W1_PART1.md"), Path("W1_PART2.md"),
            Path("W3_PART1.md"), Path("W3_PART2.md"), Path("W3_PART3.md"),
        ]
        waves = {"W1": "opus", "W3": "sonnet"}
        cost = estimate_cost(paths, waves)
        self.assertAlmostEqual(cost.total_usd, 0.78, places=2)
        self.assertEqual(cost.parts_per_model, {"opus": 2, "sonnet": 3})
        self.assertEqual(cost.parts_per_wave, {"W1": 2, "W3": 3})
        self.assertEqual(cost.unrecognized_slices, [])

    def test_unmapped_wave_falls_into_unrecognized(self):
        # Wave id that plan_waves doesn't know about → unrecognized.
        paths = [Path("W99_PART1.md")]
        cost = estimate_cost(paths, {})
        self.assertEqual(cost.total_usd, 0.0)
        self.assertEqual(cost.parts_per_model, {})
        self.assertEqual(cost.unrecognized_slices, ["W99_PART1"])

    def test_unparseable_filename_falls_into_unrecognized(self):
        paths = [Path("garbage_filename.md")]
        cost = estimate_cost(paths, {"W1": "opus"})
        self.assertEqual(cost.unrecognized_slices, ["garbage_filename"])

    def test_unknown_model_string_falls_into_unrecognized(self):
        # plan_waves gave a model name not in COST_PER_PART_USD (e.g. someone
        # introduces a new tier). The slice still counts as unrecognized rather
        # than crashing.
        paths = [Path("W1_PART1.md")]
        cost = estimate_cost(paths, {"W1": "claude-future"})
        self.assertEqual(cost.unrecognized_slices, ["W1_PART1"])
        self.assertEqual(cost.total_usd, 0.0)

    def test_total_parts_property(self):
        paths = [Path("W1_PART1.md"), Path("RANDOM.md")]
        cost = estimate_cost(paths, {"W1": "opus"})
        self.assertEqual(cost.total_parts, 2)


class RenderBlock(unittest.TestCase):
    def test_no_block_when_cost_is_none(self):
        self.assertEqual(render_cost_block(None), [])

    def test_no_block_when_only_unrecognized(self):
        cost = CostEstimate(
            total_usd=0.0, parts_per_model={}, parts_per_wave={},
            unrecognized_slices=["RANDOM_PART1"],
        )
        # Block is suppressed: showing $0 cost with non-zero parts is misleading.
        self.assertEqual(render_cost_block(cost), [])

    def test_block_lists_total_models_waves_and_constants(self):
        cost = CostEstimate(
            total_usd=0.78,
            parts_per_model={"opus": 2, "sonnet": 3},
            parts_per_wave={"W1": 2, "W3": 3},
            unrecognized_slices=[],
        )
        rendered = "\n".join(render_cost_block(cost))
        self.assertIn("## Estimated cost", rendered)
        self.assertIn("~$0.78", rendered)
        self.assertIn("2 opus", rendered)
        self.assertIn("3 sonnet", rendered)
        self.assertIn("W1=2", rendered)
        self.assertIn("W3=3", rendered)
        # Calibration constants are mentioned for transparency.
        self.assertIn("opus≈$0.30", rendered)

    def test_unmapped_slices_listed_truncated(self):
        cost = CostEstimate(
            total_usd=0.30,
            parts_per_model={"opus": 1},
            parts_per_wave={"W1": 1},
            unrecognized_slices=[f"BROKEN{i}" for i in range(8)],
        )
        rendered = "\n".join(render_cost_block(cost))
        self.assertIn("Unmapped slices (8):", rendered)
        # Truncation hint is present on >5 unmapped items.
        self.assertIn("…", rendered)

    def test_calibration_constants_match_module_dict(self):
        """Block mentions opus, sonnet, haiku — make sure module's dict has them.
        If a future bump adds a new tier, render_cost_block should be updated too."""
        for tier in ("opus", "sonnet", "haiku"):
            self.assertIn(tier, COST_PER_PART_USD)


if __name__ == "__main__":
    unittest.main()
