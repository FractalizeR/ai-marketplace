"""AWS Cognito (User Pools) provider integration detector (Stage 5).

Exports:
- detect_aws_cognito(project_root): True/False from a composite of signals
  (specialized composer packages OR Cognito-specific env vars OR Cognito
  service URL / class name in PHP source). Used by every stack recipe's
  `build_inventory` to decide whether to add `"aws-cognito"` to
  `frontmatter.stack.integrations` (drives integration-layer checklist
  loading in plan_waves).

AWS Cognito User Pools issue JWTs that are OIDC-compliant; the `aws-cognito`
integration is typically activated ALONGSIDE the generic `jwt-generic` and
`oauth-oidc` integrations — provider rules refine the generic layer, never
replace it (see `_meta.md`, "Five-layer structure").

Signal design — DIFFERENT from other providers:

The bare composer package `aws/aws-sdk-php` is too broad to use alone — it
ships hundreds of service clients (S3, DynamoDB, SES, …) and is depended on
by countless projects that have nothing to do with Cognito. Therefore the
detector REQUIRES a stronger signal:

1. Specialized composer packages (narrower than the umbrella SDK). All names
   below are real, verified on packagist:
   - `async-aws/cognito-identity-provider` — split-SDK Cognito client.
   - `ellaisys/aws-cognito` — Laravel Cognito guard.
   - `black-bits/laravel-cognito-auth` — Laravel Cognito auth.
   - `pmill/aws-cognito` — generic PHP Cognito helpers.
   - `cakedc/oauth2-cognito` — league/oauth2-client Cognito provider.
   - `socialiteproviders/cognito` — Laravel Socialite Cognito provider.
   - `customergauge/cognito` — another community Cognito client.
2. `.env` referencing Cognito-specific env names:
   - `COGNITO_USER_POOL_ID`, `COGNITO_CLIENT_ID`, `COGNITO_REGION`,
     `AWS_COGNITO_POOL_ID`.
3. PHP source under `src/` or `app/` contains either:
   - the class name substring `CognitoIdentityProviderClient` (canonical
     AWS SDK client class for User Pools), OR
   - the URL substring `cognito-idp.` (canonical service endpoint host).
   Both are unambiguous Cognito markers — the class name has no
   non-Cognito meaning, and the URL host is reserved by AWS.

This module deliberately does NOT define RECIPE_NAME / build_inventory /
sanity_probes — `recon.recipes.__init__.available_recipes()` filters out
`*_detect.py` so this won't be tried as a stack recipe.

No bag collector here (Stage 5): no `recon_bags.integration.aws-cognito.*`
yet. For Stage 5 we only expose `stack.integrations` membership so worker
checklists auto-load.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Specialized composer package names that gate Cognito detection (NOT the
# umbrella `aws/aws-sdk-php`). All names verified to exist on packagist.
AWS_COGNITO_PACKAGES: tuple[str, ...] = (
    "async-aws/cognito-identity-provider",   # split-SDK Cognito client
    "ellaisys/aws-cognito",                  # Laravel Cognito guard
    "black-bits/laravel-cognito-auth",       # Laravel Cognito auth
    "pmill/aws-cognito",                     # generic PHP Cognito helpers
    "cakedc/oauth2-cognito",                 # league/oauth2-client Cognito provider
    "socialiteproviders/cognito",            # Laravel Socialite provider
    "customergauge/cognito",
)

# Env variable names that strongly imply Cognito use.
AWS_COGNITO_ENV_NAMES: tuple[str, ...] = (
    "COGNITO_USER_POOL_ID",
    "COGNITO_CLIENT_ID",
    "COGNITO_REGION",
    "AWS_COGNITO_POOL_ID",
)

# Source markers — substring matches; no regex needed.
AWS_COGNITO_SOURCE_MARKERS: tuple[str, ...] = (
    "CognitoIdentityProviderClient",
    "cognito-idp.",
)

# Source-scan roots and limits. Bounded to keep the probe cheap.
_SCAN_ROOTS: tuple[str, ...] = ("src", "app")
_SCAN_MAX_FILES = 500
_SCAN_MAX_BYTES_PER_FILE = 256 * 1024  # 256 KB — Cognito wiring lives near the top of files


def _composer_signal(project_root: Path) -> bool:
    """True iff composer.json has a specialized Cognito package."""
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
            if isinstance(pkg, str) and pkg in AWS_COGNITO_PACKAGES:
                return True
    return False


def _env_signal(project_root: Path) -> bool:
    """True iff `.env*` references a Cognito env name."""
    for candidate in (".env", ".env.example", ".env.local", ".env.dist"):
        env_file = project_root / candidate
        if not env_file.is_file():
            continue
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name in AWS_COGNITO_ENV_NAMES:
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
    return False


def _source_signal(project_root: Path) -> bool:
    """True iff a PHP file under src/ or app/ contains a Cognito marker.

    Bounded: at most `_SCAN_MAX_FILES` files, at most `_SCAN_MAX_BYTES_PER_FILE`
    bytes read per file. `vendor/` and `node_modules/` are skipped via the
    RESOLVED project-relative path, so symlinks like `src/foo.php →
    ../vendor/foo.php` cannot smuggle vendor code through the filter. Paths
    resolving outside the project root are also skipped.

    The vendor-skip is evaluated BEFORE `scanned += 1`, so projects with
    hundreds of `src/vendor/*.php` files do not exhaust the cap before the
    real `src/Foo.php` is reached.
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
                    # Symlink escaped outside the project root.
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
            for marker in AWS_COGNITO_SOURCE_MARKERS:
                if marker in text:
                    return True
    return False


def detect_aws_cognito(project_root: Path) -> bool:
    """Return True iff any AWS Cognito signal is present.

    Signals are OR-combined (any one is enough). The umbrella `aws/aws-sdk-php`
    package is INTENTIONALLY NOT a signal on its own — see module docstring.
    """
    if _composer_signal(project_root):
        return True
    if _env_signal(project_root):
        return True
    if _source_signal(project_root):
        return True
    return False
