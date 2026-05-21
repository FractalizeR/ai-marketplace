"""Keycloak provider integration detector (Stage 5).

Exports:
- detect_keycloak(project_root): True/False from composer dependency probe
  + env / config fallback + PHP source URL probe. Used by every stack
  recipe's `build_inventory` to decide whether to add `"keycloak"` to
  `frontmatter.stack.integrations` (drives integration-layer checklist
  loading in plan_waves).

Keycloak is a self-hosted OIDC identity provider that issues JWTs. The
`keycloak` integration is typically activated ALONGSIDE the generic
`jwt-generic` and `oauth-oidc` integrations — provider rules refine the
generic layer, never replace it.

Signals (any one suffices):

1. composer.json `require`/`require-dev` containing a known Keycloak
   integration package (OAuth2 client provider, Laravel/Symfony Keycloak
   bundle/guard, or admin client). All names verified to exist on packagist.
2. `.env` referencing `KEYCLOAK_URL` / `KEYCLOAK_REALM` /
   `KEYCLOAK_CLIENT_ID` / `KEYCLOAK_CLIENT_SECRET`.
3. PHP source under `src/` or `app/` contains BOTH `/realms/` AND
   `/protocol/openid-connect/` substrings (the canonical Keycloak token /
   userinfo / JWKS endpoint shape). The conjunction is the precision
   guardrail — either substring alone is ambiguous (`/realms/` shows up
   in DDD code, `/protocol/openid-connect/` is rare but appears in
   compliance docs); together they uniquely identify a Keycloak server URL.

This module deliberately does NOT define RECIPE_NAME / build_inventory /
sanity_probes — `recon.recipes.__init__.available_recipes()` filters out
`*_detect.py` so this won't be tried as a stack recipe.

No bag collector here (Stage 5).
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Composer package names that gate Keycloak detection. All names verified to
# exist on packagist. Note: `nbgrp/oidc-bundle` is a generic OIDC bundle
# (supports Auth0/Okta/Google/Keycloak), so it lives in `oauth_oidc_detect.py`
# rather than here.
KEYCLOAK_PACKAGES: tuple[str, ...] = (
    "stevenmaguire/oauth2-keycloak",         # league/oauth2-client Keycloak provider
    "robsontenorio/laravel-keycloak-guard",  # Laravel JWT guard for Keycloak
    "vizir/laravel-keycloak-web-guard",      # Laravel web guard for Keycloak
    "socialiteproviders/keycloak",           # Laravel Socialite Keycloak provider
    "mohammad-waleed/keycloak-admin-client", # Keycloak admin REST client
    "fschmtt/keycloak-rest-api-client-php",  # Keycloak REST API client
    "mainick/keycloak-client-bundle",        # Symfony Keycloak client bundle
    "idci/keycloak-security-bundle",         # Symfony Keycloak security bundle
)

# Env variable names that strongly imply Keycloak use.
KEYCLOAK_ENV_NAMES: tuple[str, ...] = (
    "KEYCLOAK_URL",
    "KEYCLOAK_REALM",
    "KEYCLOAK_CLIENT_ID",
    "KEYCLOAK_CLIENT_SECRET",
)

# Conjunctive source markers — BOTH must appear in the same file.
_KEYCLOAK_URL_MARKER_A = "/realms/"
_KEYCLOAK_URL_MARKER_B = "/protocol/openid-connect/"

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
            if isinstance(pkg, str) and pkg in KEYCLOAK_PACKAGES:
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
        for name in KEYCLOAK_ENV_NAMES:
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
    return False


def _source_signal(project_root: Path) -> bool:
    """True iff a PHP file under src/ or app/ contains BOTH Keycloak URL markers.

    The conjunction is the precision floor. Bounded scan — same limits and
    same vendor-skip-via-resolved-path discipline as
    `aws_cognito_detect._source_signal`.
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
            if _KEYCLOAK_URL_MARKER_A in text and _KEYCLOAK_URL_MARKER_B in text:
                return True
    return False


def detect_keycloak(project_root: Path) -> bool:
    """Return True iff any Keycloak signal is present (composer / env / conjunctive URL)."""
    if _composer_signal(project_root):
        return True
    if _env_signal(project_root):
        return True
    if _source_signal(project_root):
        return True
    return False
