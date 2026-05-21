"""AWS Secrets Manager integration detector (Stage 7).

Exports:
- detect_aws_secrets_manager(project_root): True/False from a composite of
  signals. The umbrella `aws/aws-sdk-php` package is too broad to use alone
  (it ships hundreds of service clients), so detection REQUIRES either a
  Secrets-Manager-specific env var, a Secrets-Manager source marker, OR a
  source marker COMBINED with the umbrella SDK in composer.json.

AWS Secrets Manager is a key/secret management service — its integration
patterns (rotation, KMS encryption, IAM permissions, never logging the
retrieved value) are orthogonal to the JWT / OAuth axis. The integration
does NOT imply jwt-generic / oauth-oidc.

Signals (any one suffices):

1. `.env` referencing an `AWS_SECRETS_MANAGER_*` variable (rare but
   unambiguous when present).
2. PHP source under `src/` or `app/` containing either:
   - the class name `SecretsManagerClient` (canonical AWS SDK client class),
     which fires regardless of composer.json content, OR
   - the URL substring `secretsmanager.` AND the project depends on
     `aws/aws-sdk-php` in composer.json — the host alone is too narrow to
     be a strong signal without the SDK present.

Composer detection reads `composer.json` only (consistent with the rest of
the codebase). `composer.lock` is intentionally not consulted: it would
fire for transitive deps that the application doesn't actually use.

This module deliberately does NOT define RECIPE_NAME / build_inventory /
sanity_probes — `recon.recipes.__init__.available_recipes()` filters out
`*_detect.py` so this won't be tried as a stack recipe.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Env variable names that strongly imply Secrets Manager use. Rare in
# practice — most projects use generic `AWS_REGION` + IAM role + boto config.
# Kept as a signal for projects that have configured an explicit
# Secrets-Manager wrapper layer.
AWS_SECRETS_MANAGER_ENV_NAMES: tuple[str, ...] = (
    "AWS_SECRETS_MANAGER_REGION",
    "AWS_SECRETS_MANAGER_ARN",
    "AWS_SECRETS_MANAGER_SECRET_ID",
)

# Strong source markers — these fire on their own.
AWS_SECRETS_MANAGER_STRONG_MARKERS: tuple[str, ...] = (
    "SecretsManagerClient",
)

# Weak source marker — only fires when corroborated by `aws/aws-sdk-php` in
# composer.json (the umbrella SDK confirms intent).
AWS_SECRETS_MANAGER_WEAK_MARKERS: tuple[str, ...] = (
    "secretsmanager.",
)

# Source-scan roots and limits.
_SCAN_ROOTS: tuple[str, ...] = ("src", "app")
_SCAN_MAX_FILES = 500
_SCAN_MAX_BYTES_PER_FILE = 256 * 1024


def _has_aws_sdk(project_root: Path) -> bool:
    """True iff composer.json declares `aws/aws-sdk-php`.

    Checked in both `require` and `require-dev`. composer.lock is not
    consulted (see module docstring).
    """
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
        if "aws/aws-sdk-php" in deps:
            return True
    return False


def _env_signal(project_root: Path) -> bool:
    """True iff `.env*` references a Secrets-Manager-specific env name."""
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
        for name in AWS_SECRETS_MANAGER_ENV_NAMES:
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
    return False


def _source_signal(project_root: Path, has_sdk: bool) -> bool:
    """True iff a PHP file contains a Secrets-Manager marker.

    Strong markers (e.g. `SecretsManagerClient` class name) fire on their own.
    Weak markers (e.g. `secretsmanager.` host substring) require corroboration
    via `aws/aws-sdk-php` in composer (passed in as `has_sdk`).

    Bounded: at most `_SCAN_MAX_FILES` files, `_SCAN_MAX_BYTES_PER_FILE` bytes
    per file. Vendor / node_modules / outside-root paths skipped via resolved
    project-relative path.
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
            for marker in AWS_SECRETS_MANAGER_STRONG_MARKERS:
                if marker in text:
                    return True
            if has_sdk:
                for marker in AWS_SECRETS_MANAGER_WEAK_MARKERS:
                    if marker in text:
                        return True
    return False


def detect_aws_secrets_manager(project_root: Path) -> bool:
    """Return True iff any AWS Secrets Manager signal is present.

    The umbrella `aws/aws-sdk-php` package is INTENTIONALLY NOT a signal on
    its own — see module docstring.
    """
    if _env_signal(project_root):
        return True
    has_sdk = _has_aws_sdk(project_root)
    if _source_signal(project_root, has_sdk):
        return True
    return False
