"""Rough cost estimate for the security pipeline run.

Walks the input file paths fed into dedupe (their names follow the
`W<N>_PART<M>[_CHANGES].md` convention emitted by `plan_waves.py`), looks up
which model each wave runs by default, multiplies by an empirical per-slice
constant, and renders a `## Estimated cost` block for the executive summary.

Calibration (`COST_PER_PART`) is empirical and **will drift** as Anthropic
pricing or our prompt sizes change. Update it together with model upgrades
(`Opus 4.7 → 4.8` etc.). The block in the report explicitly says «rough
estimate» and lists the constants — readers can spot when numbers go stale.

The estimate uses each wave's `balanced_model` because that is the default
mode for `/security-project`. If the orchestrator overrides to `default_model`
for a single wave, the real cost differs proportionally; the block notes this.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


# Per-slice averages on the review pipeline. Numbers are derived from
# the event-prog baseline (≈80k input + 4k output tokens per wave part with
# prompt-cache hits, large-context model). Update together with pricing or
# prompt size changes.
COST_PER_PART_USD: dict[str, float] = {
    "opus": 0.30,
    "sonnet": 0.06,
    "haiku": 0.015,
}


SLICE_ID_RE = re.compile(r"^(W(?:\d+|INF))_PART\d+(?:_CHANGES)?$")


@dataclass(frozen=True)
class CostEstimate:
    total_usd: float
    parts_per_model: dict[str, int]   # "opus" → 4, "sonnet" → 8
    parts_per_wave: dict[str, int]    # "W1" → 2, "W2" → 1, ...
    unrecognized_slices: list[str] = field(default_factory=list)

    @property
    def total_parts(self) -> int:
        return sum(self.parts_per_model.values()) + len(self.unrecognized_slices)


def _wave_id_from_slice(slice_id: str) -> Optional[str]:
    """`W2_PART3` → `W2`, `WINF_PART1_CHANGES` → `WINF`. None on no match."""
    m = SLICE_ID_RE.match(slice_id)
    return m.group(1) if m else None


def estimate_cost(input_paths: Iterable[Path], waves_by_id: dict[str, str]) -> Optional[CostEstimate]:
    """Compute the estimate.

    `waves_by_id` maps `wave_id → balanced_model_name` (e.g. `{"W1": "opus", "W2": "opus", ...}`).
    Pass `None`-yielding `waves_by_id` and the function still returns a CostEstimate
    with everything counted as `unrecognized_slices` (informative but no $).

    Returns None when there are zero input paths (nothing to estimate).
    """
    paths = list(input_paths)
    if not paths:
        return None

    parts_per_model: dict[str, int] = {}
    parts_per_wave: dict[str, int] = {}
    unrecognized: list[str] = []
    total_usd = 0.0

    for p in paths:
        slice_id = p.stem  # `W1_PART2.md` → `W1_PART2`
        wave_id = _wave_id_from_slice(slice_id)
        if wave_id is None:
            unrecognized.append(slice_id)
            continue
        parts_per_wave[wave_id] = parts_per_wave.get(wave_id, 0) + 1
        model = (waves_by_id.get(wave_id) or "").lower()
        if model not in COST_PER_PART_USD:
            unrecognized.append(slice_id)
            continue
        parts_per_model[model] = parts_per_model.get(model, 0) + 1
        total_usd += COST_PER_PART_USD[model]

    return CostEstimate(
        total_usd=round(total_usd, 2),
        parts_per_model=parts_per_model,
        parts_per_wave=parts_per_wave,
        unrecognized_slices=unrecognized,
    )


def render_cost_block(cost: Optional[CostEstimate]) -> list[str]:
    """Render `## Estimated cost` lines for inclusion in the executive summary.

    Returns [] when `cost is None` (no inputs, fixture invocation, etc.) or
    when every slice was unrecognized (no model was ever resolved → block
    would be misleading)."""
    if cost is None:
        return []
    if cost.total_usd == 0 and not cost.parts_per_model:
        return []

    parts_summary = ", ".join(
        f"{n} {model}" for model, n in sorted(cost.parts_per_model.items())
    )
    waves_summary = ", ".join(
        f"{wid}={n}" for wid, n in sorted(cost.parts_per_wave.items())
    )
    lines = [
        "## Estimated cost",
        "",
        f"- Suggested cost: ~${cost.total_usd:.2f} ({parts_summary} wave parts)",
        f"- Per wave: {waves_summary}",
        "- Rough estimate from per-slice averages "
        + "(opus≈$0.30, sonnet≈$0.06, haiku≈$0.015) — update with pricing changes.",
    ]
    if cost.unrecognized_slices:
        lines.append(
            f"- Unmapped slices ({len(cost.unrecognized_slices)}): "
            + ", ".join(sorted(cost.unrecognized_slices)[:5])
            + ("…" if len(cost.unrecognized_slices) > 5 else "")
        )
    lines.append("")
    return lines
