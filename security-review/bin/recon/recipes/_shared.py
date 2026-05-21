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


# Provider integrations imply generic layers (semantic invariant: Auth0 IS
# JWT+OAuth, Cognito IS JWT+OAuth, etc.). Forced inclusion ensures workers
# always get the generic checklists alongside provider-specific refinements,
# even when only the provider-narrow signals fired (e.g. composer has
# `auth0/auth0-php` but no other JWT library).
#
# Lives here (in `_shared.py`) because all three stack recipes (symfony.py,
# laravel.py, generic_php.py) and `symfony._empty_skeleton` use it.
PROVIDER_IMPLIES_INTEGRATIONS: dict[str, tuple[str, ...]] = {
    "auth0": ("jwt-generic", "oauth-oidc"),
    "aws-cognito": ("jwt-generic", "oauth-oidc"),
    "okta": ("jwt-generic", "oauth-oidc"),
    "keycloak": ("jwt-generic", "oauth-oidc"),
    # Firebase uses JWT but is not a standard OAuth/OIDC provider — its tokens
    # are Google-signed JWTs verified directly, no OAuth flow.
    "firebase-auth": ("jwt-generic",),
}


def expand_provider_implications(detected: list[str]) -> list[str]:
    """Add implied generic integrations for each detected provider.

    Iterates `PROVIDER_IMPLIES_INTEGRATIONS`: for every provider present in
    `detected`, ensures each implied integration is also present. Order is
    preserved for already-present items, and implied integrations are
    appended in declaration order. De-duplication is left to the caller
    (typically `sorted(set(...))`).
    """
    result = list(detected)
    for provider, implied in PROVIDER_IMPLIES_INTEGRATIONS.items():
        if provider in result:
            for imp in implied:
                if imp not in result:
                    result.append(imp)
    return result


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
