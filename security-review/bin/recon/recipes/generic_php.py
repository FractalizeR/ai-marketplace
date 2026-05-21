"""generic_php recipe — fallback when no stack-specific recipe scores ≥ 0.7.

Used for projects with composer.json / *.php files but no recognizable
framework markers (Slim, Phalcon, raw PSR-15, custom MVC).

S1 stub: detect logic + minimal sanity probes + skeleton build_inventory.
Real fleshing-out is deferred (out of S1 scope).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from recon.types import (
    InventoryResult,
    SectionPayload,
    SectionSpec,
    SanityProbe,
    StackMatch,
)
from recon.recipes._shared import expand_provider_implications
from recon.recipes.jwt_generic_detect import detect_jwt_generic
from recon.recipes.oauth_oidc_detect import detect_oauth_oidc
from recon.recipes.auth0_detect import detect_auth0
from recon.recipes.aws_cognito_detect import detect_aws_cognito
from recon.recipes.okta_detect import detect_okta
from recon.recipes.keycloak_detect import detect_keycloak
from recon.recipes.firebase_auth_detect import detect_firebase_auth
from recon.recipes.stripe_detect import detect_stripe
from recon.recipes.aws_secrets_manager_detect import detect_aws_secrets_manager
from recon.recipes.vault_detect import detect_vault
from recon.recipes.saml_detect import detect_saml
from recon.recipes.webauthn_passkeys_detect import detect_webauthn_passkeys

RECIPE_NAME = "generic_php"
LANGUAGE = "php"

# No stack-specific bag for generic recipe.
RECON_BAGS_SCHEMA: dict[str, dict[str, dict[str, SectionSpec]]] = {}

# Note: NO `var/` excluded here — generic projects may use var/ for sources.
EXCLUDE_PATHS: tuple[str, ...] = (
    "vendor/", "node_modules/", "tests/", "test/", "Tests/", "Test/", "*.min.js",
)


# ---------------------------------------------------------------------------
# Detect: floor for "looks like a PHP project at all".
# ---------------------------------------------------------------------------


def detect(project_root: Path) -> Optional[StackMatch]:
    """Return a baseline confidence based on PHP signals.

    - composer.json present → 0.5
    - any *.php file (top 2 levels) → +0.3 (capped at 0.8)
    - both → 0.8
    Returns None if neither signal triggers.

    Caller (recipes registry) treats this as a fallback: stack-specific
    recipes win above 0.7; generic_php is consulted only when no stack
    scores ≥ 0.7.
    """
    score = 0.0
    evidence = []

    if (project_root / "composer.json").is_file():
        score += 0.5
        evidence.append("composer.json")

    if _has_php_file(project_root):
        score += 0.3
        evidence.append("*.php files")

    if score == 0.0:
        return None
    return StackMatch(name="generic_php", confidence=score, evidence=evidence)


def _has_php_file(project_root: Path, max_depth: int = 3) -> bool:
    """Cheap check: are there *.php files within max_depth levels?"""
    if not project_root.is_dir():
        return False
    try:
        # Top-level scan first (cheap).
        for entry in project_root.iterdir():
            if entry.is_file() and entry.suffix == ".php":
                return True
        # Then bounded recursion.
        for entry in project_root.rglob("*.php"):
            if "vendor" in entry.parts or "node_modules" in entry.parts:
                continue
            return True
    except (OSError, PermissionError):
        return False
    return False


def sanity_probes() -> list[SanityProbe]:
    return [
        SanityProbe(
            section_path="data_access",
            glob_patterns=["src/**/*Repository.php", "app/**/*Repository.php"],
            label="Repository classes",
        ),
    ]


CORE_SECTION_IDS = (
    "attack_surface", "data_access", "auth_layer", "authz_usage",
    "output_renderers", "serialization", "file_operations", "http_clients",
    "secrets", "fintech_markers", "frontend_assets",
)


def build_inventory(
    project_root: Path,
    diff_files: Optional[set[str]] = None,
    *,
    plugin_root: Optional[Path] = None,
    no_console: bool = False,
    exclude: Optional[tuple[str, ...]] = None,
) -> InventoryResult:
    """STUB — emits skeleton with all sections in pending_enrichment.

    Real population for generic_php is out of S2 scope; the kwargs
    `plugin_root` / `no_console` / `exclude` are accepted to keep the
    contract uniform across recipes.
    """
    del plugin_root, no_console, exclude  # unused in stub
    scalar_core = {"auth_layer", "secrets"}
    core: dict[str, SectionPayload] = {}
    for sid in CORE_SECTION_IDS:
        is_scalar = sid in scalar_core
        core[sid] = SectionPayload(
            status="pending_enrichment",
            enrichment_hint=f"S1 stub: {sid} not yet collected for generic_php.",
            items=None if is_scalar else [],
            data=None,
            source_files=[] if is_scalar else None,
        )
    # Integration detection (Stage 4): vendor-neutral cross-stack capabilities.
    # composer.json alone is enough signal for plain-PHP projects — they may
    # use firebase/php-jwt or league/oauth2-client without any framework.
    detected_integrations: list[str] = []
    if detect_jwt_generic(project_root):
        detected_integrations.append("jwt-generic")
    if detect_oauth_oidc(project_root):
        detected_integrations.append("oauth-oidc")
    # Provider integrations (Stage 5) — these refine the generic layers.
    if detect_auth0(project_root):
        detected_integrations.append("auth0")
    if detect_aws_cognito(project_root):
        detected_integrations.append("aws-cognito")
    if detect_okta(project_root):
        detected_integrations.append("okta")
    if detect_keycloak(project_root):
        detected_integrations.append("keycloak")
    if detect_firebase_auth(project_root):
        detected_integrations.append("firebase-auth")
    # Stage 7 integrations: payments / secret stores / SAML / WebAuthn.
    # These do NOT imply jwt-generic / oauth-oidc.
    if detect_stripe(project_root):
        detected_integrations.append("stripe")
    if detect_aws_secrets_manager(project_root):
        detected_integrations.append("aws-secrets-manager")
    if detect_vault(project_root):
        detected_integrations.append("vault")
    if detect_saml(project_root):
        detected_integrations.append("saml")
    if detect_webauthn_passkeys(project_root):
        detected_integrations.append("webauthn-passkeys")
    # A provider integration always IMPLIES the generic layers it refines.
    # See `_shared.PROVIDER_IMPLIES_INTEGRATIONS`.
    detected_integrations = expand_provider_implications(detected_integrations)
    detected_integrations = sorted(set(detected_integrations))

    return InventoryResult(
        status="partial",
        core=core,
        recon_bags={},
        sources_used=["recipe_stub:generic_php"],
        warnings=["s1_stub_recipe: generic_php build_inventory returns skeleton only"],
        detected_integrations=detected_integrations,
    )
