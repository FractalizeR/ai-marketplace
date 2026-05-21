"""Okta provider integration detector (Stage 5).

Exports:
- detect_okta(project_root): True/False from composer dependency probe
  + env / config fallback + PHP source URL probe. Used by every stack
  recipe's `build_inventory` to decide whether to add `"okta"` to
  `frontmatter.stack.integrations` (drives integration-layer checklist
  loading in plan_waves).

Okta is an OIDC-compliant identity-as-a-service vendor; its tokens are JWTs.
The `okta` integration is typically activated ALONGSIDE the generic
`jwt-generic` and `oauth-oidc` integrations — provider rules refine the
generic layer, never replace it (see `_meta.md`, "Five-layer structure").

Signals (any one suffices):

1. composer.json `require`/`require-dev` containing a known Okta package
   (official JWT verifier, official SDK, or community OAuth provider). All
   names below are real, verified on packagist.
2. `.env` referencing `OKTA_DOMAIN` / `OKTA_CLIENT_ID` / `OKTA_CLIENT_SECRET`
   / `OKTA_AUTH_SERVER_ID` / `OKTA_ISSUER`.
3. PHP source under `src/` or `app/` contains an Okta tenant URL substring
   (`.okta.com` or `.oktapreview.com`) — fires when a project hard-codes
   the issuer URL without using the official SDK.

This module deliberately does NOT define RECIPE_NAME / build_inventory /
sanity_probes — `recon.recipes.__init__.available_recipes()` filters out
`*_detect.py` so this won't be tried as a stack recipe.

No bag collector here (Stage 5).
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Composer package names that gate Okta detection. All names verified to
# exist on packagist.
OKTA_PACKAGES: tuple[str, ...] = (
    "okta/jwt-verifier",            # official JWT verifier
    "okta/sdk",                     # official SDK
    "socialiteproviders/okta",      # Laravel Socialite Okta provider
    "foxworth42/oauth2-okta",       # league/oauth2-client Okta provider
)

# Env variable names that strongly imply Okta use.
OKTA_ENV_NAMES: tuple[str, ...] = (
    "OKTA_DOMAIN",
    "OKTA_CLIENT_ID",
    "OKTA_CLIENT_SECRET",
    "OKTA_AUTH_SERVER_ID",
    "OKTA_ISSUER",
)

# Tenant URL substrings. `.okta.com` is the production tenant suffix;
# `.oktapreview.com` is the preview / sandbox suffix.
OKTA_SOURCE_MARKERS: tuple[str, ...] = (
    ".okta.com",
    ".oktapreview.com",
)

_SCAN_ROOTS: tuple[str, ...] = ("src", "app")
_SCAN_MAX_FILES = 500
_SCAN_MAX_BYTES_PER_FILE = 256 * 1024


def _composer_signal(project_root: Path) -> bool:
    composer = project_root / "composer.json"
    if not composer.is_file():
        return False
    try:
        data = json.loads(composer.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    if not isinstance(data, dict):
        return False
    for section in ("require", "require-dev"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for pkg in deps.keys():
            if isinstance(pkg, str) and pkg in OKTA_PACKAGES:
                return True
    return False


def _env_signal(project_root: Path) -> bool:
    for candidate in (".env", ".env.example", ".env.local", ".env.dist"):
        env_file = project_root / candidate
        if not env_file.is_file():
            continue
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name in OKTA_ENV_NAMES:
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
    return False


def _source_signal(project_root: Path) -> bool:
    """True iff a PHP file under src/ or app/ contains an Okta tenant URL.

    Bounded scan — same shape as `aws_cognito_detect._source_signal`.
    Vendor-skip and the cap counter are evaluated using the RESOLVED
    project-relative path, so symlinks pointing into vendor/ cannot smuggle
    vendor markers through the filter, and the cap isn't exhausted by
    vendor-tree files.
    """
    scanned = 0
    project_root_resolved = project_root.resolve()
    for root_name in _SCAN_ROOTS:
        root = project_root / root_name
        if not root.is_dir():
            continue
        for f in root.rglob("*.php"):
            if scanned >= _SCAN_MAX_FILES:
                return False
            try:
                resolved = f.resolve(strict=False)
                try:
                    rel = resolved.relative_to(project_root_resolved)
                except ValueError:
                    continue
                parts = rel.parts
            except (OSError, RuntimeError):
                continue
            if "vendor" in parts or "node_modules" in parts:
                continue
            scanned += 1
            try:
                with f.open("rb") as fh:
                    chunk = fh.read(_SCAN_MAX_BYTES_PER_FILE)
            except (OSError, ValueError):
                continue
            try:
                text = chunk.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                continue
            for marker in OKTA_SOURCE_MARKERS:
                if marker in text:
                    return True
    return False


def detect_okta(project_root: Path) -> bool:
    """Return True iff any Okta signal is present (composer / env / source URL)."""
    if _composer_signal(project_root):
        return True
    if _env_signal(project_root):
        return True
    if _source_signal(project_root):
        return True
    return False
