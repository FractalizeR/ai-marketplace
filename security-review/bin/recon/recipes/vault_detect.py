"""HashiCorp Vault integration detector (Stage 7).

Exports:
- detect_vault(project_root): True/False from composer dependency probe
  + env / source-marker fallback. Used by every stack recipe's
  `build_inventory` to decide whether to add `"vault"` to
  `frontmatter.stack.integrations`.

HashiCorp Vault is a secrets-management server — its integration patterns
(token rotation, TLS verification, dynamic-secret leases, path policies)
are orthogonal to the JWT / OAuth axis. `vault` does NOT imply
jwt-generic / oauth-oidc.

Signals (any one suffices):

1. composer.json `require`/`require-dev` containing a known Vault PHP
   client. All names verified to exist on packagist.
2. `.env` referencing `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, or
   `VAULT_AUTH_METHOD`.
3. PHP source under `src/` or `app/` containing either:
   - the substring `/v1/secret/` (the canonical Vault KV v1 API path), OR
   - the substring `/v1/secret/data/` (the KV v2 path — dominant since Vault
     0.10 in 2018).
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Composer package names that gate Vault detection. All names verified to
# exist on packagist; community libraries dominate the PHP Vault landscape.
VAULT_PACKAGES: tuple[str, ...] = (
    "csharpru/vault-php",            # most popular community Vault client
    "mittwald/vault-php",            # alternative community Vault client
    "jippi/vault-php-sdk",           # Jippi Vault PHP SDK
    "violuke/vault-php-sdk",         # community Vault SDK fork
)

# Env variable names that strongly imply Vault use.
VAULT_ENV_NAMES: tuple[str, ...] = (
    "VAULT_ADDR",
    "VAULT_TOKEN",
    "VAULT_NAMESPACE",
    "VAULT_AUTH_METHOD",
)

# Source markers — substring matches; no regex needed.
VAULT_SOURCE_MARKERS: tuple[str, ...] = (
    "/v1/secret/",          # canonical KV v1 path
    "/v1/secret/data/",     # KV v2 path — dominant deployment shape since Vault 0.10 (2018)
)

# Source-scan roots and limits.
_SCAN_ROOTS: tuple[str, ...] = ("src", "app")
_SCAN_MAX_FILES = 500
_SCAN_MAX_BYTES_PER_FILE = 256 * 1024


def _composer_signal(project_root: Path) -> bool:
    """True iff composer.json has a known Vault package."""
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
            if isinstance(pkg, str) and pkg in VAULT_PACKAGES:
                return True
    return False


def _env_signal(project_root: Path) -> bool:
    """True iff `.env*` references a Vault env name."""
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
        for name in VAULT_ENV_NAMES:
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
    return False


def _source_signal(project_root: Path) -> bool:
    """True iff a PHP file under src/ or app/ contains a Vault marker.

    Bounded with vendor-skip; see `aws_cognito_detect._source_signal` for
    the full rationale (vendor markers smuggled via symlinks must not fire
    and the cap must not be exhausted by vendor files).
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
            for marker in VAULT_SOURCE_MARKERS:
                if marker in text:
                    return True
    return False


def detect_vault(project_root: Path) -> bool:
    """Return True iff any HashiCorp Vault signal is present.

    Signals are OR-combined (any one is enough).
    """
    if _composer_signal(project_root):
        return True
    if _env_signal(project_root):
        return True
    if _source_signal(project_root):
        return True
    return False
