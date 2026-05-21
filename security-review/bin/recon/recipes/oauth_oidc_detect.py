"""Generic OAuth 2.0 / OpenID Connect integration detector (Stage 4).

Exports:
- detect_oauth_oidc(project_root): True/False from composer dependency probe
  + env / config fallback. Used by every stack recipe's `build_inventory` to
  decide whether to add `"oauth-oidc"` to `frontmatter.stack.integrations`
  (drives integration-layer checklist loading in plan_waves).

Integrations are vendor-neutral cross-stack capabilities, orthogonal to the
language/stack axis. `oauth-oidc` activates whenever any signal of OAuth 2.0
or OpenID Connect client/server flow use is present, regardless of which
library implements it.

Signals (any one suffices):

1. composer.json `require`/`require-dev` containing a known OAuth/OIDC
   package, or any package matching the broad wildcards `*/oauth2-*`,
   `oauth-*/*`, `*/openid-connect-*`, `*/oidc-*`.
2. `.env` file referencing `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` (or
   the underscored OIDC equivalents) — common when teams use a custom OAuth
   client without a library.
3. `config/packages/knpu_oauth2_client.yaml` (Symfony KnpUOAuth2ClientBundle).
4. Laravel Socialite `redirect=` patterns in `config/services.php`.

Provider-specific integrations (auth0, aws-cognito, okta, keycloak,
firebase-auth) will land in Stage 5 and EXTEND this generic integration —
the checklists in `integrations/oauth-oidc/` always apply when any provider
integration is active.

This module deliberately does NOT define RECIPE_NAME / build_inventory /
sanity_probes — `recon.recipes.__init__.available_recipes()` filters out
`*_detect.py` so this won't be tried as a stack recipe.

No bag collector here (Stage 4): no `recon_bags.integration.oauth-oidc.*`
yet. That's deferred; for Stage 4 we only expose `stack.integrations`
membership so worker checklists auto-load.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Composer package names that gate OAuth/OIDC detection.
OAUTH_OIDC_PACKAGES: tuple[str, ...] = (
    # Generic PHP OAuth libraries.
    "league/oauth2-client",
    "league/oauth2-server",
    "bshaffer/oauth2-server-php",
    "hybridauth/hybridauth",
    # Symfony OAuth2 client bundles.
    "knpuniversity/oauth2-client-bundle",
    "omines/oauth2-client-bundle",
    # Generic Symfony OIDC bundle (supports any provider — Auth0, Okta,
    # Google, Keycloak, …). Belongs here, NOT in `keycloak_detect.py`.
    "nbgrp/oidc-bundle",
    # Laravel.
    "laravel/socialite",
    "laravel/passport",
)

# Wildcard patterns matching `vendor/package` substrings. Each tuple entry is
# tried in order; matched against the full `vendor/package` string.
#
# Design note: these wildcards are deliberately broad-catch (`*/oauth2-*` also
# matches arbitrary helpers like `acme/oauth2-utils-helpers`). False positives
# are acceptable here — the resolver only lazily loads the integration
# checklist when a bag-emit actually happens, and Stage 5 will narrow signal
# via provider-specific integrations. Recall on legit OAuth packages matters
# more at this stage than precision.
_OAUTH_OIDC_WILDCARD_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"/oauth2-"),           # `*/oauth2-*` providers (league, omines spread)
    re.compile(r"^oauth2?-"),          # vendor starts `oauth-` OR `oauth2-`
    re.compile(r"^oidc-"),             # vendor starts `oidc-`
    re.compile(r"/openid-connect-"),   # `*/openid-connect-*`
    re.compile(r"/oidc-"),             # `*/oidc-*`
)

# Env variable names that strongly imply OAuth use even without a library
# dependency. The OAUTH_*/OIDC_* prefixes are conventional.
OAUTH_OIDC_ENV_NAMES: tuple[str, ...] = (
    "OAUTH_CLIENT_ID",
    "OAUTH_CLIENT_SECRET",
    "OIDC_CLIENT_ID",
    "OIDC_CLIENT_SECRET",
    "OIDC_ISSUER",
)


def _composer_signal(project_root: Path) -> bool:
    """True iff composer.json has an OAuth/OIDC package (exact match or wildcard)."""
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
            if pkg in OAUTH_OIDC_PACKAGES:
                return True
            for pat in _OAUTH_OIDC_WILDCARD_RES:
                if pat.search(pkg):
                    return True
    return False


def _env_signal(project_root: Path) -> bool:
    """True iff `.env*` references an OAuth/OIDC env name."""
    for candidate in (".env", ".env.example", ".env.local", ".env.dist"):
        env_file = project_root / candidate
        if not env_file.is_file():
            continue
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name in OAUTH_OIDC_ENV_NAMES:
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
    return False


def _config_signal(project_root: Path) -> bool:
    """True iff a known OAuth/OIDC config file is present.

    - Symfony: `config/packages/knpu_oauth2_client.yaml` (KnpUOAuth2ClientBundle).
    - Laravel: `config/services.php` matching the canonical Socialite shape.

    The bare `'redirect' =>` key alone is ambiguous (Mailgun, Twilio, internal
    callbacks all use it). Tighter signals required:
      (a) `redirect` value is sourced from env() / getenv() / $_ENV / $_SERVER,
          which is the canonical Socialite scaffold pattern; OR
      (b) the same file declares `client_id`, `client_secret`, and `redirect`
          together — the full Socialite provider block.
    """
    if (project_root / "config" / "packages" / "knpu_oauth2_client.yaml").is_file():
        return True
    services = project_root / "config" / "services.php"
    if services.is_file():
        try:
            text = services.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        # (a) env-based redirect URL — canonical Socialite scaffold.
        if re.search(
            r"['\"]redirect['\"]\s*=>\s*(?:env\(|getenv\(|\$_ENV\[|\$_SERVER\[)",
            text,
        ):
            return True
        # (b) `client_id` + `client_secret` + `redirect` all present.
        if (
            re.search(r"['\"]client_id['\"]\s*=>", text)
            and re.search(r"['\"]client_secret['\"]\s*=>", text)
            and re.search(r"['\"]redirect['\"]\s*=>", text)
        ):
            return True
    return False


def detect_oauth_oidc(project_root: Path) -> bool:
    """Return True iff any OAuth 2.0 / OpenID Connect signal is present.

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
