"""Shared helpers for stack recipes and addon detectors.

Lives under `recon.recipes._shared` (leading underscore → skipped by the
recipe-registry's `available_recipes()` glob). Exposes only path-handling
primitives used by both stack recipes (symfony.py, laravel.py) and
addon detectors (easyadmin_detect.py, sonata_detect.py).

Keep this module small: only utilities that have NO knowledge of recon
semantics belong here. Anything stack- or addon-specific stays in its
owning module.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, Optional


# Default vendor-exclude paths for grep / extractor sources (rev 3.5).
# Note: `var/` is symfony-specific (cache+logs). Generic recipe drops it.
EXCLUDE_PATHS: tuple[str, ...] = (
    "vendor/", "var/", "node_modules/", "tests/", "test/", "Tests/", "Test/", "*.min.js",
)


def is_excluded(rel_path: str, exclude: tuple[str, ...]) -> bool:
    """Match `rel_path` against EXCLUDE_PATHS entries (matches validator helper).

    Supports glob entries (with `*`), directory entries (trailing `/`), and
    literal entries. Path prefixes and embedded segments both match.
    """
    rel_with_slash = "/" + rel_path
    for ex in exclude:
        if "*" in ex:
            if fnmatch.fnmatch(rel_path.rsplit("/", 1)[-1], ex):
                return True
            continue
        if ex.endswith("/"):
            if rel_path.startswith(ex) or ("/" + ex) in rel_with_slash:
                return True
        else:
            if rel_path == ex or rel_path.startswith(ex + "/") or ("/" + ex + "/") in rel_with_slash:
                return True
    return False


def to_relative(abs_path: Any, project_root: Path) -> Optional[str]:
    """Convert absolute path → project-relative POSIX path.

    Returns None when `abs_path` is not a string or when the resolved path is
    outside `project_root`. Both sides go through `resolve()` so macOS
    `/var ↔ /private/var` symlink quirks don't cause spurious None.
    """
    if not isinstance(abs_path, str):
        return None
    try:
        return Path(abs_path).resolve().relative_to(project_root.resolve()).as_posix()
    except (ValueError, OSError):
        return None
