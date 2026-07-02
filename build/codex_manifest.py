"""Stdlib mirror of the Codex ``validate_plugin.py`` manifest contract (3B-pkg).

The authoritative validator ships with the local ``plugin-creator`` skill and
imports PyYAML — a non-stdlib dependency the repo forbids in build tooling. This
module re-implements the *shape* checks (plugin manifest + marketplace entry +
skill frontmatter) in pure stdlib so the build can gate the authored/derived
Codex configs with no third-party import.

Fidelity is pinned two ways: unit tests mirror each of the validator's rules
(``test_codex_manifest``), and a durable skip-if-unavailable test runs the REAL
``validate_plugin.py`` against the emitted bundle when PyYAML is present
(``test_codex_pkg``). The oracle covers ONLY the plugin manifest + skills — the
validator never reads a marketplace file — so the marketplace half is anchored by
a golden-shape test instead.

Skill-frontmatter shape is NOT mirrored here: the derived ``skills/*/SKILL.md`` are
gated by ``gates.check_codex_output(is_skill=True)`` (the wired build gate) and
pinned by the real-validator oracle; a second copy here would only drift.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Ported verbatim from validate_plugin.py so semver acceptance cannot drift.
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\."
    r"(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
HEX_COLOR_RE = re.compile(r"^#[0-9A-F]{6}$", re.IGNORECASE)
TODO_MARKER = "[TODO:"

ALLOWED_MANIFEST_KEYS = frozenset({
    "id", "name", "version", "description", "skills", "apps", "mcpServers",
    "interface", "author", "homepage", "repository", "license", "keywords",
})
ALLOWED_AUTHOR_KEYS = frozenset({"name", "email", "url"})
ALLOWED_INTERFACE_KEYS = frozenset({
    "displayName", "shortDescription", "longDescription", "developerName",
    "category", "capabilities", "websiteURL", "privacyPolicyURL",
    "termsOfServiceURL", "brandColor", "composerIcon", "logo", "screenshots",
    "defaultPrompt", "default_prompt",
})
REQUIRED_INTERFACE_STRINGS = (
    "displayName", "shortDescription", "longDescription", "developerName", "category",
)

# Marketplace enums (from create_basic_plugin.py) + the name form it validates.
INSTALL_POLICIES = frozenset({"NOT_AVAILABLE", "AVAILABLE", "INSTALLED_BY_DEFAULT"})
AUTH_POLICIES = frozenset({"ON_INSTALL", "ON_USE"})
_MARKETPLACE_NAME_RE = re.compile(r"[A-Za-z0-9_-]+")


# --- small shared helpers ----------------------------------------------------
def _is_nonempty_str(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _https_ok(value) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def normalize_contract_path(raw_path) -> str | None:
    """Mirror validate_plugin.normalize_contract_path: reject absolute, strip a
    trailing slash. Returns the normalized posix path or None."""
    if not isinstance(raw_path, str):
        return None
    from pathlib import PurePosixPath
    p = PurePosixPath(raw_path)
    if p.is_absolute():
        return None
    normalized = p.as_posix().rstrip("/")
    return normalized or None


def _asset_path_safe(raw_path) -> bool:
    """Mirror validate_plugin.validate_asset_path's archive-containment rule
    (filesystem-free legs): non-empty relative posix path, no absolute root and no
    ``''``/``.``/``..`` component (the ``../evil.png`` escape). The 'file exists'
    leg is left to the real validator / oracle — it needs the archive root."""
    from pathlib import PurePosixPath
    if not isinstance(raw_path, str) or not raw_path.strip():
        return False
    candidate = PurePosixPath(raw_path.replace("\\", "/"))
    if candidate.is_absolute() or any(p in {"", ".", ".."} for p in candidate.parts):
        return False
    return True


def reject_todo(value, path: str = "$") -> list[str]:
    """Recursive ``[TODO:`` scan over str/list/dict (mirror)."""
    out: list[str] = []
    if isinstance(value, str):
        if TODO_MARKER in value:
            out.append(f"{path} still contains a `[TODO: ...]` placeholder")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            out += reject_todo(item, f"{path}[{i}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            out += reject_todo(item, f"{path}.{key}")
    return out


# --- plugin manifest ---------------------------------------------------------
def validate_plugin_manifest(data) -> list[str]:
    """Return violations (empty = ok) for a ``.codex-plugin/plugin.json`` dict."""
    if not isinstance(data, dict):
        return ["plugin.json must contain a JSON object"]
    problems: list[str] = list(reject_todo(data))

    for key in sorted(set(data) - ALLOWED_MANIFEST_KEYS):
        problems.append(f"plugin.json field `{key}` is not accepted")

    if data.get("id") is not None and not _is_nonempty_str(data.get("id")):
        problems.append("plugin.json field `id` must be a non-empty string")
    if not _is_nonempty_str(data.get("name")):
        problems.append("plugin.json field `name` must be a non-empty string")
    version = data.get("version")
    if not _is_nonempty_str(version):
        problems.append("plugin.json field `version` must be a non-empty string")
    elif SEMVER_RE.fullmatch(version) is None:
        problems.append("plugin.json field `version` must be strict semver")
    if not _is_nonempty_str(data.get("description")):
        problems.append("plugin.json field `description` must be a non-empty string")

    problems += _validate_author(data.get("author"))
    problems += _validate_skills_field(data.get("skills"))
    problems += _validate_contract_field(data, "apps", ".app.json")
    problems += _validate_contract_field(data, "mcpServers", ".mcp.json")
    problems += _validate_interface(data.get("interface"))
    return problems


def _validate_contract_field(data: dict, key: str, expected: str) -> list[str]:
    """Mirror validate_optional_contract_path: an optional ``key`` must normalize
    to ``expected`` (e.g. ``apps`` → ``.app.json``). The companion-file shape check
    is left to the real validator; this is the string-only leg the fast gate needs."""
    value = data.get(key)
    if value is None:
        return []
    if normalize_contract_path(value) != expected:
        return [f"plugin.json field `{key}` must resolve to `{expected}`"]
    return []


def _validate_author(author) -> list[str]:
    if not isinstance(author, dict):
        return ["plugin.json field `author` must be an object"]
    out: list[str] = []
    for key in sorted(set(author) - ALLOWED_AUTHOR_KEYS):
        out.append(f"plugin.json field `author.{key}` is not accepted")
    if not _is_nonempty_str(author.get("name")):
        out.append("plugin.json field `author.name` must be a non-empty string")
    if author.get("email") is not None and not _is_nonempty_str(author.get("email")):
        out.append("plugin.json field `author.email` must be a non-empty string")
    if author.get("url") is not None and not _https_ok(author.get("url")):
        out.append("plugin.json field `author.url` must be an absolute `https://` URL")
    return out


def _validate_skills_field(skills) -> list[str]:
    if skills is None:
        return []
    if normalize_contract_path(skills) != "skills":
        return ["plugin.json field `skills` must resolve to `skills`"]
    return []


def _validate_interface(interface) -> list[str]:
    if not isinstance(interface, dict):
        return ["plugin.json field `interface` must be an object"]
    out: list[str] = []
    for key in sorted(set(interface) - ALLOWED_INTERFACE_KEYS):
        out.append(f"plugin.json field `interface.{key}` is not accepted")
    for field in REQUIRED_INTERFACE_STRINGS:
        if not _is_nonempty_str(interface.get(field)):
            out.append(f"plugin.json field `interface.{field}` must be a non-empty string")
    if "defaultPrompt" not in interface and "default_prompt" not in interface:
        out.append("plugin.json field `interface.defaultPrompt` or "
                   "`interface.default_prompt` is required")
    caps = interface.get("capabilities")
    if not isinstance(caps, list) or not all(_is_nonempty_str(v) for v in caps):
        out.append("plugin.json field `interface.capabilities` must be an array of strings")
    for field in ("websiteURL", "privacyPolicyURL", "termsOfServiceURL"):
        if interface.get(field) is not None and not _https_ok(interface.get(field)):
            out.append(f"plugin.json field `interface.{field}` must be an absolute `https://` URL")
    brand = interface.get("brandColor")
    if brand is not None and (not isinstance(brand, str) or HEX_COLOR_RE.fullmatch(brand) is None):
        out.append("plugin.json field `interface.brandColor` must use `#RRGGBB`")
    for field in ("composerIcon", "logo"):
        val = interface.get(field)
        if val is not None and not _asset_path_safe(val):
            out.append(f"plugin.json field `interface.{field}` must be a relative "
                       "path inside the plugin archive")
    shots = interface.get("screenshots")
    if shots is not None:
        if not isinstance(shots, list):
            out.append("plugin.json field `interface.screenshots` must be an array")
        else:
            for i, s in enumerate(shots):
                if not _asset_path_safe(s):
                    out.append(f"plugin.json field `interface.screenshots[{i}]` must be "
                               "a relative path inside the plugin archive")
    return out


# --- marketplace -------------------------------------------------------------
def validate_marketplace(data, *, plugin_name: str) -> list[str]:
    """Return violations for a ``.agents/plugins/marketplace.json`` dict, given
    the plugin it must register. No runnable oracle exists (validate_plugin.py
    never reads a marketplace file), so this mirrors create_basic_plugin.py +
    plugin-json-spec.md."""
    if not isinstance(data, dict):
        return ["marketplace.json must contain a JSON object"]
    problems: list[str] = []
    name = data.get("name")
    if not _is_nonempty_str(name):
        problems.append("marketplace.json field `name` must be a non-empty string")
    elif _MARKETPLACE_NAME_RE.fullmatch(name) is None:
        problems.append("marketplace.json field `name` may only contain letters, "
                        "digits, `_`, and `-`")
    iface = data.get("interface")
    if iface is not None and not isinstance(iface, dict):
        problems.append("marketplace.json field `interface` must be an object")
    plugins = data.get("plugins")
    if not isinstance(plugins, list):
        return problems + ["marketplace.json field `plugins` must be an array"]

    entry = next((e for e in plugins
                  if isinstance(e, dict) and e.get("name") == plugin_name), None)
    if entry is None:
        return problems + [f"marketplace.json has no entry for plugin `{plugin_name}`"]
    problems += _validate_marketplace_entry(entry, plugin_name)
    return problems


def _validate_marketplace_entry(entry: dict, plugin_name: str) -> list[str]:
    out: list[str] = []
    source = entry.get("source")
    if not isinstance(source, dict):
        out.append("marketplace entry `source` must be an object")
    else:
        if source.get("source") != "local":
            out.append("marketplace entry `source.source` must be 'local'")
        expected = f"./plugins/{plugin_name}"
        if source.get("path") != expected:
            out.append(f"marketplace entry `source.path` must be '{expected}'")
    policy = entry.get("policy")
    if not isinstance(policy, dict):
        out.append("marketplace entry `policy` must be an object")
    else:
        if policy.get("installation") not in INSTALL_POLICIES:
            out.append(f"marketplace entry `policy.installation` must be one of "
                       f"{sorted(INSTALL_POLICIES)}")
        if policy.get("authentication") not in AUTH_POLICIES:
            out.append(f"marketplace entry `policy.authentication` must be one of "
                       f"{sorted(AUTH_POLICIES)}")
    if not _is_nonempty_str(entry.get("category")):
        out.append("marketplace entry `category` must be a non-empty string")
    return out


# Skill-frontmatter validation is NOT mirrored here: the derived `skills/*/SKILL.md`
# are gated by `gates.check_codex_output(is_skill=True)` (non-empty name+description,
# closed leading block) and pinned by the real-validator oracle. Duplicating it here
# would be a third, drift-prone copy of the same rule (see the 3B code review).
