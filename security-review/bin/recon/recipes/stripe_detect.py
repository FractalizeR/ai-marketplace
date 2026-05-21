"""Stripe payments integration detector (Stage 7).

Exports:
- detect_stripe(project_root): True/False from composer dependency probe
  + env / source-marker fallback. Used by every stack recipe's
  `build_inventory` to decide whether to add `"stripe"` to
  `frontmatter.stack.integrations` (drives integration-layer checklist
  loading in plan_waves).

Stripe is a payments provider — its integration patterns (webhook signature
verification, idempotency, amount-in-cents arithmetic, Connect tenancy) are
orthogonal to the JWT / OAuth axis. `stripe` does NOT imply jwt-generic /
oauth-oidc (see `_shared.PROVIDER_IMPLIES_INTEGRATIONS`).

Signals (any one suffices):

1. composer.json `require`/`require-dev` containing a known Stripe package.
   All names verified to exist on packagist.
2. `.env` referencing `STRIPE_KEY`, `STRIPE_SECRET`, `STRIPE_WEBHOOK_SECRET`,
   or `STRIPE_PUBLISHABLE_KEY`.
3. PHP source under `src/` or `app/` containing the substring
   `api.stripe.com` (canonical service endpoint host).

This module deliberately does NOT define RECIPE_NAME / build_inventory /
sanity_probes — `recon.recipes.__init__.available_recipes()` filters out
`*_detect.py` so this won't be tried as a stack recipe.

No bag collector here (Stage 7): no `recon_bags.integration.stripe.*` yet.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Composer package names that gate Stripe detection. All names verified to
# exist on packagist.
STRIPE_PACKAGES: tuple[str, ...] = (
    "stripe/stripe-php",            # official SDK
    "laravel/cashier",              # Cashier (Stripe) — official Laravel bridge
    "omnipay/stripe",               # Omnipay payment-gateway adapter
)

# Env variable names that strongly imply Stripe use.
STRIPE_ENV_NAMES: tuple[str, ...] = (
    "STRIPE_KEY",
    "STRIPE_SECRET",
    "STRIPE_WEBHOOK_SECRET",
    "STRIPE_PUBLISHABLE_KEY",
)

# Source markers — substring matches; no regex needed.
STRIPE_SOURCE_MARKERS: tuple[str, ...] = (
    "api.stripe.com",
)

# Source-scan roots and limits. Bounded to keep the probe cheap.
_SCAN_ROOTS: tuple[str, ...] = ("src", "app")
_SCAN_MAX_FILES = 500
_SCAN_MAX_BYTES_PER_FILE = 256 * 1024  # 256 KB


def _composer_signal(project_root: Path) -> bool:
    """True iff composer.json has a known Stripe package."""
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
            if isinstance(pkg, str) and pkg in STRIPE_PACKAGES:
                return True
    return False


def _env_signal(project_root: Path) -> bool:
    """True iff `.env*` references a Stripe env name."""
    for candidate in (".env", ".env.example", ".env.local", ".env.dist"):
        env_file = project_root / candidate
        try:
            if not env_file.is_file():
                continue
        except OSError:
            continue
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name in STRIPE_ENV_NAMES:
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
    return False


def _source_signal(project_root: Path) -> bool:
    """True iff a PHP file under src/ or app/ contains a Stripe marker.

    Bounded: at most `_SCAN_MAX_FILES` files, at most `_SCAN_MAX_BYTES_PER_FILE`
    bytes read per file. `vendor/` and `node_modules/` are skipped via the
    RESOLVED project-relative path, so symlinks like
    `src/foo.php → ../vendor/foo.php` cannot smuggle vendor code through the
    filter. Paths resolving outside the project root are also skipped.

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
            for marker in STRIPE_SOURCE_MARKERS:
                if marker in text:
                    return True
    return False


def detect_stripe(project_root: Path) -> bool:
    """Return True iff any Stripe signal is present.

    Signals are OR-combined (any one is enough). See module docstring for the
    full list.
    """
    if _composer_signal(project_root):
        return True
    if _env_signal(project_root):
        return True
    if _source_signal(project_root):
        return True
    return False
