"""WebAuthn / FIDO2 / Passkeys integration detector (Stage 7).

Exports:
- detect_webauthn_passkeys(project_root): True/False from composer
  dependency probe + env / source-marker fallback. Used by every stack
  recipe's `build_inventory` to decide whether to add `"webauthn-passkeys"`
  to `frontmatter.stack.integrations`.

WebAuthn is a public-key-based authentication standard (passwordless /
phishing-resistant). Its integration patterns (origin validation, RP ID
binding, challenge replay, counter check, attestation policy, allowCredentials
enumeration) are orthogonal to the OAuth axis. `webauthn-passkeys` does NOT
imply jwt-generic / oauth-oidc.

Signals (any one suffices):

1. composer.json `require`/`require-dev` containing a known WebAuthn PHP
   library. All names verified to exist on packagist.
2. `.env` referencing `WEBAUTHN_RP_ID` or `WEBAUTHN_RP_NAME`.
3. PHP source under `src/` or `app/` containing either:
   - `Webauthn\\PublicKeyCredentialOptions` (lowercase `a` — PSR-4 namespace
     of `web-auth/webauthn-lib`), OR
   - `lbuchs\\WebAuthn\\WebAuthn` (entry-point class of `lbuchs/webauthn`).

Out of scope (Stage 7 simplicity): JS-side `navigator.credentials` scanning.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Composer package names that gate WebAuthn detection. All names verified to
# exist on packagist.
WEBAUTHN_PACKAGES: tuple[str, ...] = (
    "web-auth/webauthn-lib",              # core WebAuthn library
    "web-auth/webauthn-symfony-bundle",   # Symfony bundle
    "web-auth/webauthn-framework",        # umbrella package shipping the lib + ancillaries
    "lbuchs/webauthn",                    # community PHP WebAuthn library
)

# Env variable names that strongly imply WebAuthn use.
WEBAUTHN_ENV_NAMES: tuple[str, ...] = (
    "WEBAUTHN_RP_ID",
    "WEBAUTHN_RP_NAME",
)

# Source markers — substring matches; no regex needed. Two case-correct
# entry points:
# - `Webauthn\` (lowercase `a`) is the PSR-4 namespace of `web-auth/webauthn-lib`
#   — this is the dominant library, so case matters.
# - `lbuchs\WebAuthn\WebAuthn` is the entry-point class of `lbuchs/webauthn`.
WEBAUTHN_SOURCE_MARKERS: tuple[str, ...] = (
    "Webauthn\\PublicKeyCredentialOptions",   # web-auth/webauthn-lib (lowercase 'a')
    "lbuchs\\WebAuthn\\WebAuthn",              # lbuchs/webauthn entry-point class
)

# Source-scan roots and limits.
_SCAN_ROOTS: tuple[str, ...] = ("src", "app")
_SCAN_MAX_FILES = 500
_SCAN_MAX_BYTES_PER_FILE = 256 * 1024


def _composer_signal(project_root: Path) -> bool:
    """True iff composer.json has a known WebAuthn package."""
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
            if isinstance(pkg, str) and pkg in WEBAUTHN_PACKAGES:
                return True
    return False


def _env_signal(project_root: Path) -> bool:
    """True iff `.env*` references a WebAuthn env name."""
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
        for name in WEBAUTHN_ENV_NAMES:
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
    return False


def _source_signal(project_root: Path) -> bool:
    """True iff a PHP file under src/ or app/ contains a WebAuthn marker.

    Bounded with vendor-skip; see `aws_cognito_detect._source_signal` for
    the full rationale.
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
            for marker in WEBAUTHN_SOURCE_MARKERS:
                if marker in text:
                    return True
    return False


def detect_webauthn_passkeys(project_root: Path) -> bool:
    """Return True iff any WebAuthn / FIDO2 / Passkeys signal is present.

    Signals are OR-combined (any one is enough).
    """
    if _composer_signal(project_root):
        return True
    if _env_signal(project_root):
        return True
    if _source_signal(project_root):
        return True
    return False
