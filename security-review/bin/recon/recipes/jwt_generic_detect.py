"""Generic JWT integration detector (Stage 4).

Exports:
- detect_jwt_generic(project_root): True/False from composer dependency probe
  + env / config fallback. Used by every stack recipe's `build_inventory` to
  decide whether to add `"jwt-generic"` to `frontmatter.stack.integrations`
  (drives integration-layer checklist loading in plan_waves).

Integrations are vendor-neutral cross-stack capabilities, orthogonal to the
language/stack axis. `jwt-generic` activates whenever any signal of JSON Web
Token use is present, regardless of which library produces/consumes them.

Signals (any one suffices — broader catch is acceptable here; the checklists
are still vendor-neutral and apply to any JWT user):

1. composer.json `require`/`require-dev` containing a known JWT package,
   or any package matching the broad `*/jwt-*` or `jwt-*/*` wildcard
   (catches `lcobucci/jwt`, `web-token/jwt-framework`, `tymon/jwt-auth`, ...).
2. `.env` file referencing JWT-specific env names (`JWT_SECRET`,
   `JWT_PASSPHRASE`, `JWT_PRIVATE_KEY`) — a project may roll its own JWT
   helper without pulling a library.
3. `config/packages/lexik_jwt_authentication.yaml` (Symfony Lexik bundle).

PASETO (paragonie/paseto) is treated as JWT-adjacent for stage 4 purposes:
the threat model overlaps heavily (claims-bearing token, signing keys) and
the integration checklists apply almost verbatim. Stage 5 may introduce a
dedicated `paseto` integration with refined content.

This module deliberately does NOT define RECIPE_NAME / build_inventory /
sanity_probes — `recon.recipes.__init__.available_recipes()` filters out
`*_detect.py` so this won't be tried as a stack recipe.

No bag collector here (Stage 4): no `recon_bags.integration.jwt-generic.*`
yet. That's deferred; for Stage 4 we only expose `stack.integrations`
membership so worker checklists auto-load.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Composer package names that gate JWT detection. Each tuple entry is matched
# against `require` / `require-dev` exact keys.
JWT_PACKAGES: tuple[str, ...] = (
    # Generic PHP libraries.
    "firebase/php-jwt",
    "lcobucci/jwt",
    "web-token/jwt-framework",
    "paragonie/paseto",
    # Laravel-side wrappers.
    "tymon/jwt-auth",
    "php-open-source-saver/jwt-auth",
    # Symfony bundle.
    "lexik/jwt-authentication-bundle",
)

# Broad wildcard regex for any `vendor/jwt-*`, `jwt-*/package`, or `*-jwt/...`
# package — catches community wrappers and forks (e.g. `mycorp/auth-jwt`).
# Matches on the full `vendor/package` key.
_JWT_PACKAGE_WILDCARD_RE = re.compile(r"(?:^|/)jwt[-_]|[-_]jwt(?:/|$)")

# Env variable names that strongly imply JWT use even without a library
# dependency (a project may roll its own JWT helper).
JWT_ENV_NAMES: tuple[str, ...] = (
    "JWT_SECRET",
    "JWT_PASSPHRASE",
    "JWT_PRIVATE_KEY",
    "JWT_PUBLIC_KEY",
)


def _composer_signal(project_root: Path) -> bool:
    """True iff composer.json has a JWT package (exact match or wildcard)."""
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
            if not isinstance(pkg, str):
                continue
            if pkg in JWT_PACKAGES:
                return True
            if _JWT_PACKAGE_WILDCARD_RE.search(pkg):
                return True
    return False


def _env_signal(project_root: Path) -> bool:
    """True iff `.env` or `.env.example` references a JWT_* env name."""
    for candidate in (".env", ".env.example", ".env.local", ".env.dist"):
        env_file = project_root / candidate
        if not env_file.is_file():
            continue
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name in JWT_ENV_NAMES:
            # Match `JWT_SECRET=...` at line start (after optional whitespace).
            # `export JWT_SECRET=...` is also accepted (some teams export from bashrc-style envs).
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
    return False


def _config_signal(project_root: Path) -> bool:
    """True iff a known JWT bundle config file is present.

    Probes:
    - Symfony Lexik bundle's canonical config path (`config/packages/lexik_jwt_authentication.yaml`).
    - Laravel Tymon-style published config (`config/jwt.php` from `vendor:publish`).
    """
    if (project_root / "config" / "packages" / "lexik_jwt_authentication.yaml").is_file():
        return True
    if (project_root / "config" / "jwt.php").is_file():
        return True
    return False


def detect_jwt_generic(project_root: Path) -> bool:
    """Return True iff any JWT signal is present.

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
