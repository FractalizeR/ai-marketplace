"""Auth0 provider integration detector (Stage 5).

Exports:
- detect_auth0(project_root): True/False from composer dependency probe
  + env / config fallback. Used by every stack recipe's `build_inventory` to
  decide whether to add `"auth0"` to `frontmatter.stack.integrations`
  (drives integration-layer checklist loading in plan_waves).

Auth0 is an OIDC-compliant identity-as-a-service vendor; its tokens are JWTs.
The `auth0` integration is therefore typically activated ALONGSIDE the generic
`jwt-generic` and `oauth-oidc` integrations — provider rules refine the
generic layer, never replace it (see `_meta.md`, "Five-layer structure").

Signals (any one suffices):

1. composer.json `require`/`require-dev` containing a known Auth0 package
   (official SDK, Symfony bundle, Laravel bridge, or JWT bundle). All names
   verified to exist on packagist.
2. `.env` file referencing `AUTH0_DOMAIN` / `AUTH0_CLIENT_ID` /
   `AUTH0_CLIENT_SECRET` / `AUTH0_AUDIENCE` — strong indicator even when the
   project uses a hand-rolled JWKS verifier instead of the SDK.
3. `config/auth0.php` (Laravel) or `config/packages/auth0.yaml` (Symfony).

This module deliberately does NOT define RECIPE_NAME / build_inventory /
sanity_probes — `recon.recipes.__init__.available_recipes()` filters out
`*_detect.py` so this won't be tried as a stack recipe.

No bag collector here (Stage 5): no `recon_bags.integration.auth0.*` yet.
That's deferred; for Stage 5 we only expose `stack.integrations` membership
so worker checklists auto-load.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Composer package names that gate Auth0 detection. All names verified to
# exist on packagist.
AUTH0_PACKAGES: tuple[str, ...] = (
    "auth0/auth0-php",            # official SDK
    "auth0/symfony",              # Symfony bundle
    "auth0/login",                # canonical Laravel bridge
    "auth0/jwt-auth-bundle",      # Symfony JWT bundle
)

# Env variable names that strongly imply Auth0 use.
AUTH0_ENV_NAMES: tuple[str, ...] = (
    "AUTH0_DOMAIN",
    "AUTH0_CLIENT_ID",
    "AUTH0_CLIENT_SECRET",
    "AUTH0_AUDIENCE",
)


def _composer_signal(project_root: Path) -> bool:
    """True iff composer.json has an Auth0 package."""
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
            if isinstance(pkg, str) and pkg in AUTH0_PACKAGES:
                return True
    return False


def _env_signal(project_root: Path) -> bool:
    """True iff `.env*` references an Auth0 env name."""
    for candidate in (".env", ".env.example", ".env.local", ".env.dist"):
        env_file = project_root / candidate
        if not env_file.is_file():
            continue
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name in AUTH0_ENV_NAMES:
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
    return False


def _config_signal(project_root: Path) -> bool:
    """True iff a known Auth0 config file is present.

    - Laravel: `config/auth0.php` (published via the laravel-auth0 vendor:publish).
    - Symfony: `config/packages/auth0.yaml` (bundle config path).
    """
    if (project_root / "config" / "auth0.php").is_file():
        return True
    if (project_root / "config" / "packages" / "auth0.yaml").is_file():
        return True
    return False


def detect_auth0(project_root: Path) -> bool:
    """Return True iff any Auth0 signal is present.

    Signals are OR-combined (any one is enough). See module docstring for the
    full list. Cheap probe — only reads composer.json + a handful of env/config
    files; never walks the source tree.
    """
    if _composer_signal(project_root):
        return True
    if _env_signal(project_root):
        return True
    if _config_signal(project_root):
        return True
    return False
