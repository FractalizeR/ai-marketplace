"""SAML federation integration detector (Stage 7).

Exports:
- detect_saml(project_root): True/False from composer dependency probe
  + env / config-file fallback. Used by every stack recipe's
  `build_inventory` to decide whether to add `"saml"` to
  `frontmatter.stack.integrations`.

SAML 2.0 is a SSO federation protocol — its integration patterns (signature
wrapping, assertion replay, NameID confusion, recipient validation, XXE)
are orthogonal to the JWT / OAuth axis. `saml` does NOT imply
jwt-generic / oauth-oidc.

Signals (any one suffices):

1. composer.json `require`/`require-dev` containing a known SAML PHP
   library. All names verified to exist on packagist.
2. `.env` referencing `SAML_IDP_METADATA_URL`, `SAML_IDP_ENTITY_ID`, or
   `SAML_SP_ENTITY_ID`.
3. A metadata XML file (`metadata.xml` or `idp_metadata.xml`) present in
   the repository root or in `config/`, AND containing the SAML OASIS
   namespace substring `urn:oasis:names:tc:SAML` within its first 2 KB.
   The namespace check disambiguates from unrelated `metadata.xml` files
   (Apache, Maven, NuGet, Composer descriptors).
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Composer package names that gate SAML detection. All names verified to
# exist on packagist.
SAML_PACKAGES: tuple[str, ...] = (
    "onelogin/php-saml",                  # OneLogin's PHP SAML toolkit
    "simplesamlphp/saml2",                # SimpleSAMLphp's SAML2 library
    "simplesamlphp/simplesamlphp",        # SimpleSAMLphp full IdP/SP
    "hslavich/oneloginsaml-bundle",       # legacy Symfony bundle (abandoned but still seen in old projects)
    "nbgrp/onelogin-saml-bundle",         # active fork — canonical since 2022
    "aacotroneo/laravel-saml2",           # original Laravel SAML2 bridge (abandoned)
    "24slides/laravel-saml2",             # active fork of aacotroneo/laravel-saml2
)

# Env variable names that strongly imply SAML use.
SAML_ENV_NAMES: tuple[str, ...] = (
    "SAML_IDP_METADATA_URL",
    "SAML_IDP_ENTITY_ID",
    "SAML_SP_ENTITY_ID",
)

# Canonical metadata-file drop sites.
SAML_METADATA_FILENAMES: tuple[str, ...] = (
    "metadata.xml",
    "idp_metadata.xml",
)

# Substring that must appear in the first chunk of a candidate metadata file
# for the metadata signal to fire. SAML 2.0 metadata XML always references
# the OASIS SAML namespace family (`urn:oasis:names:tc:SAML:2.0:metadata` /
# `:assertion`). Tightening on this substring disambiguates from unrelated
# `metadata.xml` files (Apache, Maven, NuGet, Composer descriptors, etc.)
# that share the filename.
SAML_METADATA_NAMESPACE_MARKER: str = "urn:oasis:names:tc:SAML"
SAML_METADATA_PROBE_BYTES: int = 2048


def _composer_signal(project_root: Path) -> bool:
    """True iff composer.json has a known SAML package."""
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
            if isinstance(pkg, str) and pkg in SAML_PACKAGES:
                return True
    return False


def _env_signal(project_root: Path) -> bool:
    """True iff `.env*` references a SAML env name."""
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
        for name in SAML_ENV_NAMES:
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
    return False


def _metadata_signal(project_root: Path) -> bool:
    """True iff a canonical SAML metadata XML file is present AND contains
    the SAML OASIS namespace marker.

    Bounded: only checks the repository root and `config/` directory.
    Doesn't walk the source tree. The filename alone is too broad (collides
    with Apache, Maven, NuGet, Composer descriptors), so we read the first
    `SAML_METADATA_PROBE_BYTES` bytes and require the substring
    `urn:oasis:names:tc:SAML` to be present.
    """
    for parent in (project_root, project_root / "config"):
        try:
            if not parent.is_dir():
                continue
        except OSError:
            continue
        for fname in SAML_METADATA_FILENAMES:
            candidate = parent / fname
            try:
                if not candidate.is_file():
                    continue
            except OSError:
                continue
            try:
                with candidate.open("rb") as fh:
                    chunk = fh.read(SAML_METADATA_PROBE_BYTES)
            except (OSError, ValueError):
                continue
            try:
                text = chunk.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                continue
            if SAML_METADATA_NAMESPACE_MARKER in text:
                return True
    return False


def detect_saml(project_root: Path) -> bool:
    """Return True iff any SAML signal is present.

    Signals are OR-combined (any one is enough).
    """
    if _composer_signal(project_root):
        return True
    if _env_signal(project_root):
        return True
    if _metadata_signal(project_root):
        return True
    return False
