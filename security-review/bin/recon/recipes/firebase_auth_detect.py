"""Firebase Authentication provider integration detector (Stage 5).

Exports:
- detect_firebase_auth(project_root): True/False from composer dependency
  probe + env fallback + service-account JSON filename glob. Used by every
  stack recipe's `build_inventory` to decide whether to add `"firebase-auth"`
  to `frontmatter.stack.integrations` (drives integration-layer checklist
  loading in plan_waves).

Firebase Authentication issues ID tokens that are OIDC-style JWTs signed by
Google. The `firebase-auth` integration is typically activated ALONGSIDE the
generic `jwt-generic` and `oauth-oidc` integrations — provider rules refine
the generic layer, never replace it.

Signals (any one suffices):

1. composer.json `require`/`require-dev` containing a known Firebase Admin
   SDK / bundle (kreait's family is the canonical PHP entry point).
2. `.env` referencing `FIREBASE_PROJECT_ID` / `FIREBASE_CREDENTIALS` /
   `FIREBASE_CREDENTIALS_PATH`. The generic `GOOGLE_APPLICATION_CREDENTIALS`
   ALSO fires, but only when corroborated by a Firebase-specific hint in
   the same env file (any case-insensitive match of `firebase`) — bare
   GAC is too broad (any Google SDK uses it).
3. A service-account JSON file containing the substring
   `firebase-adminsdk-<key-id>.json` is present in the repository root or
   in `config/`. The Firebase console actually downloads service accounts
   as `{project-id}-firebase-adminsdk-{key-id}.json` (e.g.
   `myproject-firebase-adminsdk-fbsvc-abc123.json`), so we match the
   `firebase-adminsdk-…` substring anywhere in the filename rather than
   requiring it at the start.

This module deliberately does NOT define RECIPE_NAME / build_inventory /
sanity_probes — `recon.recipes.__init__.available_recipes()` filters out
`*_detect.py` so this won't be tried as a stack recipe.

No bag collector here (Stage 5).
"""

from __future__ import annotations

import json
import re
from pathlib import Path


# Composer package names that gate Firebase Auth detection.
FIREBASE_AUTH_PACKAGES: tuple[str, ...] = (
    "kreait/firebase-php",        # core PHP Admin SDK
    "kreait/firebase-bundle",     # Symfony bundle
    "kreait/laravel-firebase",    # Laravel bridge
)

# Env variable names that strongly imply Firebase Auth use, FIRE ON THEIR
# OWN. The generic `GOOGLE_APPLICATION_CREDENTIALS` is deliberately NOT in
# this list — it is the standard location used by ANY Google Cloud SDK
# (Cloud Storage, BigQuery, …) and bare-bones detection on it alone would
# trigger Firebase checklists on every Google-SDK consumer. Instead, GAC is
# accepted only when corroborated by a Firebase-specific hint in the same
# env file (see `_env_signal`).
FIREBASE_AUTH_ENV_NAMES: tuple[str, ...] = (
    "FIREBASE_PROJECT_ID",
    "FIREBASE_CREDENTIALS",
    "FIREBASE_CREDENTIALS_PATH",
)

# Service-account JSON filename pattern. Firebase console downloads service
# accounts as `{project-id}-firebase-adminsdk-{key-id}.json` (e.g.
# `myproject-firebase-adminsdk-fbsvc-abc123.json`), so we match the
# `firebase-adminsdk-…` substring anywhere in the filename rather than
# requiring it at the start.
_FIREBASE_SA_RE = re.compile(r"firebase-adminsdk-[\w-]+\.json$")


def _composer_signal(project_root: Path) -> bool:
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
            if isinstance(pkg, str) and pkg in FIREBASE_AUTH_PACKAGES:
                return True
    return False


def _env_signal(project_root: Path) -> bool:
    """True iff `.env*` carries a Firebase-Auth env signal.

    Firebase-specific names (`FIREBASE_PROJECT_ID`, `FIREBASE_CREDENTIALS`,
    `FIREBASE_CREDENTIALS_PATH`) fire on their own.

    The generic `GOOGLE_APPLICATION_CREDENTIALS` is broad — any Google SDK
    uses it — so it fires ONLY when corroborated by a Firebase-specific
    hint in the same env file (the substring `firebase`, case-insensitive,
    in a key, value, or comment).
    """
    for candidate in (".env", ".env.example", ".env.local", ".env.dist"):
        env_file = project_root / candidate
        if not env_file.is_file():
            continue
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Firebase-specific env names fire on their own.
        for name in FIREBASE_AUTH_ENV_NAMES:
            if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(name)}\s*=", text):
                return True
        # GOOGLE_APPLICATION_CREDENTIALS — require a Firebase hint in the
        # same file.
        has_gac = bool(re.search(
            r"(?m)^\s*(?:export\s+)?GOOGLE_APPLICATION_CREDENTIALS\s*=", text,
        ))
        has_firebase_hint = bool(re.search(r"(?i)firebase", text))
        if has_gac and has_firebase_hint:
            return True
    return False


def _service_account_signal(project_root: Path) -> bool:
    """True iff a `firebase-adminsdk-*.json` file exists in repo root or `config/`.

    Bounded: only the two known canonical drop sites are checked (no rglob);
    if a project hides the service account under `secrets/` we accept the
    false negative for cheapness — the env-name signal usually covers that.
    """
    for parent in (project_root, project_root / "config"):
        if not parent.is_dir():
            continue
        try:
            for entry in parent.iterdir():
                # `is_file()` raises OSError on broken symlinks on some
                # filesystems — defensively swallow and skip.
                try:
                    if not entry.is_file():
                        continue
                except OSError:
                    continue
                if _FIREBASE_SA_RE.search(entry.name):
                    return True
        except (OSError, PermissionError):
            continue
    return False


def detect_firebase_auth(project_root: Path) -> bool:
    """Return True iff any Firebase Auth signal is present."""
    if _composer_signal(project_root):
        return True
    if _env_signal(project_root):
        return True
    if _service_account_signal(project_root):
        return True
    return False
