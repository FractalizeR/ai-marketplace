"""Recipe registry.

Recipes are Python modules in `bin/recon/recipes/`. Each defines:
- RECIPE_NAME, LANGUAGE
- FRAMEWORK_SPECIFIC_SCHEMA: dict[str, SectionSpec]
- detect(project_root) -> StackMatch | None
- build_inventory(project_root, diff_files=None, *,
                  plugin_root=None, no_console=False, exclude=None) -> InventoryResult
- sanity_probes() -> list[SanityProbe]

`exclude` (3.1.1+): optional tuple of path prefixes (relative to project_root)
appended to sandbox.DEFAULT_EXCLUDE before invoking the PHP extractor.
Recipes pass this through to every sandbox.run_extractor call so vendored,
generated, or legacy directories are skipped pre-parse rather than post-filter.

Detect uses a per-recipe weighted-signal formula (see docstrings in each
module). The cross-recipe selection contract:
- Each recipe scores on the same project_root.
- Whichever scores ≥ 0.7 wins; ties broken by score.
- Below 0.7, we fall back to the generic-language recipe (e.g. generic_php),
  which has its own simpler "is this PHP at all?" floor.
- Caller can override via --force-recipe=<name>.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType
from typing import Optional

# Order matters: stack-specific recipes are tried before generic fallbacks.
KNOWN_RECIPES: tuple[str, ...] = ("symfony", "laravel", "generic_php")

# Generic-language fallbacks: detect floor for "looks like this language".
GENERIC_FALLBACKS: tuple[str, ...] = ("generic_php",)

# Threshold above which a stack-specific recipe wins.
STACK_DETECT_THRESHOLD: float = 0.7


def load_recipe(name: str) -> ModuleType:
    """Import recipe module by short name. Raises ModuleNotFoundError if absent."""
    return importlib.import_module(f"recon.recipes.{name}")


def available_recipes() -> list[str]:
    """List recipe modules present in this package (excluding the registry)."""
    here = Path(__file__).resolve().parent
    out = []
    for f in sorted(here.glob("*.py")):
        if f.name.startswith("_"):
            continue
        out.append(f.stem)
    return out


def detect_best(project_root: Path) -> Optional[tuple[str, "StackMatch"]]:  # noqa: F821
    """Run detect() on every known recipe; return (recipe_name, match) for the
    highest-confidence match, or None if no recipe matches at all.

    Selection rules:
    - If any stack-specific recipe scores ≥ STACK_DETECT_THRESHOLD, it wins
      (tie: max confidence; further tie: KNOWN_RECIPES order).
    - Otherwise, return the generic fallback if it has any positive signal.
    - Otherwise, None (caller should treat as `framework: unknown`).
    """
    best_stack: Optional[tuple[str, object]] = None
    generic: Optional[tuple[str, object]] = None
    for name in KNOWN_RECIPES:
        try:
            mod = load_recipe(name)
        except ModuleNotFoundError:
            continue
        match = mod.detect(project_root)
        if match is None:
            continue
        if name in GENERIC_FALLBACKS:
            if generic is None or match.confidence > generic[1].confidence:
                generic = (name, match)
            continue
        if match.confidence >= STACK_DETECT_THRESHOLD:
            if best_stack is None or match.confidence > best_stack[1].confidence:
                best_stack = (name, match)
    if best_stack is not None:
        return best_stack
    if generic is not None and generic[1].confidence > 0.0:
        return generic
    return None
