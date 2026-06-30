"""Typed contracts shared by `model_resolver` and `dispatch` (Phase 2A).

Defines the data carriers (`Roots`, `RunResult`), the typed Callable aliases for
every injected seam (subprocess `Runner`, command builders, capture recovery,
the resolver checkpoint), and the typed exceptions. No implementation logic —
this module is import-only so both helpers (and their tests) share one source of
truth for the seams.

stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Mapping, Sequence

if TYPE_CHECKING:  # avoid an import cycle: model_resolver imports contracts.
    from shared.model_resolver import ModelInfo, TierMap


@dataclass(frozen=True)
class Roots:
    """Explicit roots for a run (composite-repo safe; never assume cwd == root).

    project_root : the PHP project being audited (target_files are relative to it).
    review_root  : where artifacts live (`waves/`, `REPORT.md`, `.model_map.json`).
    core_root    : the plugin core (`bin/`, `checklists/`) — for path-invoking helpers.
    capture_dir  : optional directory for worker stdout captures (None ⇒ no capture).
    """

    project_root: Path
    review_root: Path
    core_root: Path
    capture_dir: Path | None = None


@dataclass(frozen=True)
class RunResult:
    """Result of one external-process invocation through the `Runner` seam.

    returncode is None iff the child timed out (timed_out is then True). A thin
    stdlib wrapper around `subprocess.run` produces this; tests inject fakes.
    """

    returncode: int | None  # None <=> timed_out
    stdout: str
    stderr: str
    timed_out: bool


# (argv, timeout_seconds_or_None) -> RunResult.
# MUST terminate the child process tree before returning on timeout (AD-2A6/E13).
Runner = Callable[[Sequence[str], "float | None"], RunResult]

# (slice, model_id, roots, capture_path_or_None) -> argv.
WaveCommandBuilder = Callable[[Mapping, str, Roots, "Path | None"], Sequence[str]]

# (role, roots) -> argv  (no slice/model — recon/refute carry no per-slice model).
RoleCommandBuilder = Callable[[str, Roots], Sequence[str]]

# (slice_id, roots) -> recovered finding text, or None if nothing to recover.
RecoverCapture = Callable[[str, Roots], "str | None"]

# (proposed_tier_map, discovered_models) -> chosen TierMap.
# Accept-as-is = return the proposed map; raise to abort.
Checkpoint = Callable[["TierMap", "list[ModelInfo]"], "TierMap"]


class DispatchConfigError(Exception):
    """Bad slice label or incompatible dispatch flags (not a raw KeyError)."""

    def __init__(self, slice_id: str, label: str, allowed: Sequence[str]):
        self.slice_id = slice_id
        self.label = label
        self.allowed = list(allowed)
        super().__init__(
            f"slice {slice_id!r}: unknown model label {label!r}; "
            f"allowed: {sorted(self.allowed)}"
        )


class DispatchGapError(Exception):
    """Strict mode: at least one planned wave produced no findings file.

    Carries the list of gap `WaveResult`s (typed as object to avoid importing
    `dispatch` here, which would create an import cycle).
    """

    def __init__(self, gaps: "list"):
        self.gaps = list(gaps)
        slice_ids = [getattr(g, "slice_id", "?") for g in self.gaps]
        super().__init__(
            f"dispatch gaps in strict mode: {len(self.gaps)} wave(s) missing "
            f"findings: {slice_ids}"
        )


class ResolverError(Exception):
    """Discovery/parse/ambiguity/unresolved tier resolution failure.

    Carries the available model ids (when known) so the CLI can print them.
    """

    def __init__(self, message: str, available: "Sequence[str] | None" = None):
        self.available = list(available) if available is not None else None
        super().__init__(message)
