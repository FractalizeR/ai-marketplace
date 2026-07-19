"""Symfony recipe — full inventory collector (S2).

Static-first architecture (rev 3.3):
- Primary source for routes / forms / voters / serializer-groups / class metadata
  is `extract_php_metadata.php` (lexical, no PHP execution).
- Console enrichment (`bin/console debug:router|debug:event-dispatcher|
  debug:messenger|list`) is **optional** and merged on top of the static set.
  Disabled with `no_console=True`. On hostile / read-only repositories
  console must stay off — it boots Symfony Kernel = arbitrary code execution.

build_inventory pipeline:
1. attack_surface  — http routes (+ admin), CLI commands, messenger handlers, event listeners.
2. data_access     — repositories (extends ServiceEntityRepository or *Repository.php).
3. auth_layer      — abstract: kind/provider/mfa from security.yaml.
4. authz_usage     — call sites of denyAccessUnlessGranted / #[IsGranted] / #[Security] / etc.
5. output_renderers — twig templates + per-controller render calls.
6. serialization / file_operations / http_clients — grep with EXCLUDE_PATHS.
7. secrets         — pending_enrichment with bounded regex candidates.
8. fintech_markers — composer deps + entity decimal columns.
9. frontend_assets — JS bundles / Stimulus / importmap.
10. recon_bags.stack.symfony.*: voters, forms, serializer_groups, twig_overrides,
    doctrine_listeners, firewalls, trusted_config (framework.yaml request trust
    boundary), messenger_transports.
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Any, Optional

from recon.types import (
    InventoryResult,
    SectionPayload,
    SectionSpec,
    SanityProbe,
    StackMatch,
)
from recon.graphql_detect import detect_graphql


RECIPE_NAME = "symfony"
LANGUAGE = "php"

# Console entrypoint for environment-aware enrichment (the subcommand args are
# appended by the recon utility / sandbox.build_console_argv). The recon
# utility combines this with bin/recon/environment.py to construct a
# `sandbox.ConsoleRunner` — on the host, inside a container (docker compose
# exec), or via a user-supplied `--console-cmd`. `None` on a recipe means the
# recipe has no console enrichment and the whole console-applicability
# machinery is N/A (e.g. laravel/generic_php today).
CONSOLE_ENTRYPOINT: list[str] = ["php", "bin/console"]


# ---------------------------------------------------------------------------
# Schema bag — 3-level shape: {kind: {name: {bag_key: SectionSpec}}}.
# Mirrors the runtime emit structure produced by build_inventory().
# ---------------------------------------------------------------------------

RECON_BAGS_SCHEMA: dict[str, dict[str, dict[str, SectionSpec]]] = {
    "stack": {
        "symfony": {
            "voters": SectionSpec(
                shape="list",
                item_keys=frozenset({"class", "file", "attributes", "subjects", "line"}),
            ),
            "forms": SectionSpec(
                shape="list",
                item_keys=frozenset({
                    "class", "file", "line", "data_class", "csrf_protection", "allow_extra_fields",
                }),
            ),
            "serializer_groups": SectionSpec(
                shape="list",
                item_keys=frozenset({"class", "member", "kind", "groups", "file", "line"}),
            ),
            "twig_overrides": SectionSpec(
                shape="scalar",
                data_keys=frozenset({"autoescape_default", "raw_filter_count", "raw_filter_locations"}),
            ),
            "doctrine_listeners": SectionSpec(
                shape="list",
                item_keys=frozenset({"listener", "type", "events", "file", "line"}),
            ),
            "firewalls": SectionSpec(
                shape="scalar",
                data_keys=frozenset({"firewalls", "access_control"}),
            ),
            # Request trust boundary from config/packages/framework.yaml —
            # trusted_proxies/hosts/headers govern the effective client IP/host
            # derived from X-Forwarded-* (spoofing → IP-authz / host-injection).
            # required=False: not every project configures it, and pre-4.x
            # CONTEXT.md without the bag must still validate.
            "trusted_config": SectionSpec(
                shape="scalar",
                data_keys=frozenset({"trusted_proxies", "trusted_hosts", "trusted_headers"}),
                required=False,
            ),
            "messenger_transports": SectionSpec(
                shape="scalar",
                data_keys=frozenset({"transports"}),
            ),
            "admin_authz_coverage": SectionSpec(
                shape="scalar",
                data_keys=frozenset({
                    "crud_controllers_with_voter",
                    "crud_controllers_without_voter",
                    "voters_inspected",
                }),
                required=False,
            ),
            "graphql_layer": SectionSpec(
                shape="scalar",
                data_keys=frozenset({"library_name", "schema_files", "resolvers_dir"}),
                required=False,
            ),
            # Wave 2-D (3.4.0): per-route effective authz fingerprint.
            # `effective_middleware` is kept as an empty list for cross-stack shape
            # parity with Laravel — Symfony has no middleware concept.
            # `authz_evidence` is an array (not a single requires_role) to allow
            # multiple sources (#[IsGranted], denyAccessUnlessGranted, access_control,
            # voter wiring) to coexist per-route — workers diff this against admin
            # routes to detect missing protection.
            "routes_authz_matrix": SectionSpec(
                shape="list",
                item_keys=frozenset({
                    "route_name", "file", "line", "methods", "path",
                    "effective_middleware", "matched_access_control", "firewall",
                    "csrf_protection", "authz_evidence",
                }),
                required=False,
            ),
            # Wave 2-D (3.4.0): Doctrine entity columns whose property name matches
            # a sensitive-name regex (token/password/secret/etc). `encryption_status`
            # collapses Doctrine column type + #[Encrypted] attribute into a tri-state
            # (encrypted / plaintext / unknown). Workers use this to flag PII/secret
            # leakage without re-parsing every entity.
            "sensitive_columns": SectionSpec(
                shape="list",
                item_keys=frozenset({
                    "entity_class", "file", "field_name", "column_type",
                    "name_pattern_matched", "encryption_status", "encryption_evidence",
                }),
                required=False,
            ),
        },
    },
    "addon": {
        "easyadmin": {
            "crud_controllers": SectionSpec(
                shape="list",
                item_keys=frozenset({
                    "class", "file", "line", "entity_fqcn",
                    "configure_fields", "configure_actions", "page_titles",
                    "unresolved_fields",
                }),
                required=False,
            ),
        },
        "sonata": {
            "admin_classes": SectionSpec(
                shape="list",
                item_keys=frozenset({
                    "class", "file", "line", "entity_fqcn",
                    "form_fields", "unresolved_fields",
                }),
                required=False,
            ),
        },
        # Kebab-case `api-platform` matches the composer package name and the
        # Stage 0 addon naming convention. Item shape mirrors the planned
        # extractor output documented in `addons/api-platform/_detect.md`;
        # until the extractor lands the bag is emitted as `status=unknown`.
        "api-platform": {
            "resources": SectionSpec(
                shape="list",
                item_keys=frozenset({
                    "class", "file", "line",
                    "operations", "graphql_enabled",
                }),
                required=False,
            ),
        },
    },
}


# Default vendor-exclude paths for grep-based sources (rev 3.5).
# Sourced from `recon.recipes._shared` so addon detectors (easyadmin_detect,
# sonata_detect) share the same exclusion list without circular imports.
# Note: `var/` is symfony-specific (cache+logs). Generic recipe drops it.
from recon.recipes._shared import (  # noqa: E402  (re-export)
    EXCLUDE_PATHS,
    expand_provider_implications,
    is_excluded as _shared_is_excluded,
    to_relative as _shared_to_relative,
)
from recon.recipes.easyadmin_detect import (  # noqa: E402
    collect_easyadmin_crud_controllers,
    detect_easyadmin,
)
from recon.recipes.sonata_detect import (  # noqa: E402
    collect_sonata_admin_classes,
    detect_sonata,
)
from recon.recipes.api_platform_detect import (  # noqa: E402
    collect_api_platform_resources,
    detect_api_platform,
)
from recon.recipes.jwt_generic_detect import detect_jwt_generic  # noqa: E402
from recon.recipes.oauth_oidc_detect import detect_oauth_oidc  # noqa: E402
from recon.recipes.auth0_detect import detect_auth0  # noqa: E402
from recon.recipes.aws_cognito_detect import detect_aws_cognito  # noqa: E402
from recon.recipes.okta_detect import detect_okta  # noqa: E402
from recon.recipes.keycloak_detect import detect_keycloak  # noqa: E402
from recon.recipes.firebase_auth_detect import detect_firebase_auth  # noqa: E402
from recon.recipes.stripe_detect import detect_stripe  # noqa: E402
from recon.recipes.aws_secrets_manager_detect import detect_aws_secrets_manager  # noqa: E402
from recon.recipes.vault_detect import detect_vault  # noqa: E402
from recon.recipes.saml_detect import detect_saml  # noqa: E402
from recon.recipes.webauthn_passkeys_detect import detect_webauthn_passkeys  # noqa: E402


# Source-tree roots scanned for PHP. `templates/`, `config/`, `public/` are
# scanned separately when needed; only `src/` and `app/` carry user-authored code.
PHP_SCAN_ROOTS: tuple[str, ...] = ("src", "app")


# Console probes: per rev 3.4 F-E.1 each command is independent — failure of
# one does not skip the others.
CONSOLE_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("debug_router", ("debug:router", "--format=json")),
    ("debug_event_dispatcher", ("debug:event-dispatcher", "--format=json")),
    ("debug_messenger", ("debug:messenger", "--format=json")),
    ("list", ("list", "--format=json")),
)


# ---------------------------------------------------------------------------
# Detect: weighted signals.
# ---------------------------------------------------------------------------

# rev 3.5 G-Conf.1 — Symfony detect formula.
SIGNAL_WEIGHTS = {
    "framework_bundle_dep": 0.4,  # composer.json: symfony/framework-bundle in require
    "symfony_lock":         0.2,  # symfony.lock file
    "bin_console":          0.2,  # bin/console exists
    "config_bundles_php":   0.2,  # config/bundles.php exists
}


def detect(project_root: Path) -> Optional[StackMatch]:
    """Score Symfony likelihood. Returns StackMatch or None.

    Threshold for use as stack recipe: ≥ 0.7 (enforced by recipes registry).
    Below threshold, registry falls back to generic_php.
    """
    score = 0.0
    evidence = []
    version: Optional[str] = None

    composer = project_root / "composer.json"
    if composer.is_file():
        try:
            data = json.loads(composer.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = None
        if isinstance(data, dict):
            for section in ("require", "require-dev"):
                deps = data.get(section)
                if not isinstance(deps, dict):
                    continue
                if "symfony/framework-bundle" in deps:
                    score += SIGNAL_WEIGHTS["framework_bundle_dep"]
                    evidence.append(f"composer.json: {section}.symfony/framework-bundle")
                    raw_ver = deps["symfony/framework-bundle"]
                    if isinstance(raw_ver, str):
                        version = raw_ver
                    break

    if (project_root / "symfony.lock").is_file():
        score += SIGNAL_WEIGHTS["symfony_lock"]
        evidence.append("symfony.lock")

    if (project_root / "bin" / "console").is_file():
        score += SIGNAL_WEIGHTS["bin_console"]
        evidence.append("bin/console")

    if (project_root / "config" / "bundles.php").is_file():
        score += SIGNAL_WEIGHTS["config_bundles_php"]
        evidence.append("config/bundles.php")

    if score == 0.0:
        return None
    return StackMatch(name="symfony", version=version, confidence=score, evidence=evidence)


# ---------------------------------------------------------------------------
# Sanity probes: globs vs declared inventory.
# ---------------------------------------------------------------------------


def sanity_probes() -> list[SanityProbe]:
    return [
        SanityProbe(
            section_path="attack_surface",
            glob_patterns=["src/**/*Controller.php", "app/**/*Controller.php"],
            label="HTTP controllers",
            # Controllers are inventoried under two sibling kinds: plain
            # `http_route` (attribute routes) and `http_route_admin` (EasyAdmin
            # CRUD/Dashboard controllers, whose entry points are CRUD actions,
            # not #[Route]). Filtering on `http_route` alone would flag every
            # EasyAdmin controller as a coverage gap though it is fully declared.
            kind_filter=("http_route", "http_route_admin"),
        ),
        SanityProbe(
            section_path="attack_surface",
            glob_patterns=["src/**/*Command.php", "app/**/*Command.php"],
            label="CLI commands",
            kind_filter="cli_command",
            # Glob alone over-matches: DDD/CQRS Command DTOs and Messenger
            # message classes also end in *Command.php. Narrow to files that
            # actually reference Symfony Console — by FQN of the base class
            # OR by AsCommand attribute (FQN or short form after `use`).
            content_filter=(
                r"Symfony\\Component\\Console\\Command\\Command"
                r"|Symfony\\Component\\Console\\Attribute\\AsCommand"
                r"|#\[\s*AsCommand\b"
            ),
        ),
        SanityProbe(
            section_path="data_access",
            glob_patterns=["src/**/*Repository.php", "app/**/*Repository.php"],
            label="Doctrine repositories",
        ),
        SanityProbe(
            section_path="recon_bags.stack.symfony.voters",
            glob_patterns=["src/**/*Voter*.php", "app/**/*Voter*.php"],
            label="Security voters",
        ),
        SanityProbe(
            section_path="attack_surface",
            glob_patterns=["src/**/*Listener.php", "src/**/*Subscriber.php",
                           "app/**/*Listener.php", "app/**/*Subscriber.php"],
            label="Event listeners/subscribers",
            kind_filter="event_listener",
            # `*Listener.php` / `*Subscriber.php` also match Doctrine ORM
            # listeners (#[AsDoctrineListener] / #[AsEntityListener]) and
            # Messenger handlers (#[AsMessageHandler]) — none of which are
            # kernel event listeners. Narrow `found` to the two markers the
            # collector actually classifies as event_listener so those files
            # do not read as coverage gaps. (A kernel.event_listener registered
            # only via a services.yaml tag carries neither marker in its PHP
            # source and is intentionally out of this glob's reach.)
            # The EventSubscriberInterface branch is anchored to an `implements`
            # list (bounded by the class-body `{`) so a mere `use …\
            # EventSubscriberInterface;` import or a comment mention does not
            # inflate `found`; `[^{]*` still spans a multi-interface list.
            content_filter=r"#\[\s*AsEventListener\b|implements[^{]*\bEventSubscriberInterface\b",
        ),
        SanityProbe(
            section_path="recon_bags.addon.easyadmin.crud_controllers",
            glob_patterns=["src/**/*CrudController.php", "app/**/*CrudController.php"],
            label="EasyAdmin CRUD controllers",
            content_filter=r"extends\s+AbstractCrudController",
        ),
        SanityProbe(
            section_path="recon_bags.addon.sonata.admin_classes",
            glob_patterns=["src/**/*Admin.php", "app/**/*Admin.php"],
            label="Sonata Admin classes",
            content_filter=r"extends\s+AbstractAdmin",
        ),
        SanityProbe(
            section_path="recon_bags.addon.api-platform.resources",
            glob_patterns=["src/**/*.php", "app/**/*.php"],
            label="API Platform ApiResources",
            content_filter=r"#\[ApiResource",
        ),
        # Wave 2-D (3.4.0): per-route authz fingerprint — same glob universe
        # as the existing http-controller probe (#[Route] attributes are only
        # parsed in *Controller.php files). content_filter narrows to actual
        # #[Route] usage to avoid flagging WebTestCase fixtures or trait files.
        SanityProbe(
            section_path="recon_bags.stack.symfony.routes_authz_matrix",
            glob_patterns=["src/**/*Controller.php", "app/**/*Controller.php"],
            label="symfony.routes_authz_matrix",
            content_filter=r"#\[\s*Route\b",
        ),
        # Wave 2-D (3.4.0): sensitive entity columns. Hallucination-only: the
        # section lists only entities carrying a column whose NAME matches the
        # sensitive-field regex — a semantic subset a filename/text glob cannot
        # reproduce (a whole-file regex also matches the word in an #[ORM\\Table]
        # name or a comment, which the column-name-scoped collector rightly
        # ignores). A coverage ratio over "all entity files" is a category error
        # here, so we verify declared files exist but skip the diff.
        SanityProbe(
            section_path="recon_bags.stack.symfony.sensitive_columns",
            glob_patterns=["src/Entity/**/*.php", "src/**/Entity/*.php",
                           "app/Entity/**/*.php", "app/**/Entity/*.php"],
            label="symfony.sensitive_columns",
            coverage=False,
        ),
    ]


# ---------------------------------------------------------------------------
# Helpers: file scan + grep.
# ---------------------------------------------------------------------------


def _is_excluded(rel_path: str, exclude: tuple[str, ...]) -> bool:
    """Match `rel_path` against EXCLUDE_PATHS entries (matches validator helper).

    Thin wrapper around `recon.recipes._shared.is_excluded` so addon detectors
    (easyadmin_detect, sonata_detect) and this module share one implementation.
    Kept under the original `_is_excluded` name so internal callers don't need
    rewiring.
    """
    return _shared_is_excluded(rel_path, exclude)


def _list_php_files(project_root: Path) -> list[tuple[str, Path]]:
    """Return (rel_path, abs_path) pairs for every *.php in PHP_SCAN_ROOTS,
    skipping anything caught by EXCLUDE_PATHS. Sorted for determinism.

    Symlink containment: `Path.rglob()` follows symlinks by default, so a
    symlink inside `src/` pointing outside `project_root` would otherwise
    bypass path safety. We resolve every candidate and drop anything whose
    resolved path is not under the resolved project root.
    """
    out: list[tuple[str, Path]] = []
    project_resolved = project_root.resolve()
    for root_name in PHP_SCAN_ROOTS:
        root = project_root / root_name
        if not root.is_dir():
            continue
        for f in root.rglob("*.php"):
            if not f.is_file():
                continue
            try:
                resolved = f.resolve()
            except (OSError, RuntimeError):
                continue
            try:
                resolved.relative_to(project_resolved)
            except ValueError:
                # Symlink escape — drop silently (recipe is best-effort).
                continue
            try:
                rel = resolved.relative_to(project_resolved).as_posix()
            except ValueError:
                continue
            if _is_excluded(rel, EXCLUDE_PATHS):
                continue
            out.append((rel, resolved))
    out.sort(key=lambda pair: pair[0])
    return out


def _list_config_yaml_files(project_root: Path) -> list[tuple[str, Path]]:
    """Return (rel_path, abs_path) pairs for *.yaml/*.yml under `config/`.

    Used by secret-candidate scanning to surface yaml-resident credentials
    (Symfony `parameters.*` blocks, embedded API keys in service definitions).
    Mirrors `_list_php_files` symlink-containment logic.
    """
    out: list[tuple[str, Path]] = []
    project_resolved = project_root.resolve()
    root = project_root / "config"
    if not root.is_dir():
        return out
    for ext in ("*.yaml", "*.yml"):
        for f in root.rglob(ext):
            if not f.is_file():
                continue
            try:
                resolved = f.resolve()
            except (OSError, RuntimeError):
                continue
            try:
                rel = resolved.relative_to(project_resolved).as_posix()
            except ValueError:
                continue
            if _is_excluded(rel, EXCLUDE_PATHS):
                continue
            out.append((rel, resolved))
    out.sort(key=lambda pair: pair[0])
    return out


# Maximum file size to read for grep-style scanning (avoids OOM on huge files).
GREP_MAX_BYTES = 1_000_000  # 1 MB


def _read_text_safe(path: Path, max_bytes: int = GREP_MAX_BYTES) -> Optional[str]:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def _grep_files(
    files: list[tuple[str, Path]],
    pattern: re.Pattern[str],
    project_root: Path,
    item_builder,
) -> list[dict]:
    """Apply `pattern` line-by-line to each file in `files`. For every match,
    call `item_builder(rel_path, line_number, line, match) -> dict | None`.
    Returns list of items in deterministic order.
    """
    items: list[dict] = []
    for rel, abs_path in files:
        text = _read_text_safe(abs_path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in pattern.finditer(line):
                item = item_builder(rel, lineno, line, m)
                if item is not None:
                    items.append(item)
    return items


# ---------------------------------------------------------------------------
# Helpers: minimal Symfony YAML parsers (regex/line-based, NOT PyYAML).
# ---------------------------------------------------------------------------


_FLOW_PAIRS_RE = re.compile(r"\{\s*([^}]+?)\s*\}")


def _parse_flow_inline_kv(s: str) -> dict[str, str]:
    """Parse `{ key: value, key2: value2 }` flow-style mapping into dict[str,str].
    Values are kept as raw strings (caller normalizes)."""
    inner = s.strip()
    if not (inner.startswith("{") and inner.endswith("}")):
        return {}
    inner = inner[1:-1].strip()
    out: dict[str, str] = {}
    # Split on commas not inside brackets.
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in inner:
        if ch in "[{(":
            depth += 1
            cur.append(ch)
        elif ch in "]})":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())
    for p in parts:
        if ":" not in p:
            continue
        k, _, v = p.partition(":")
        out[k.strip()] = _strip_yaml_quotes(v.strip())
    return out


def _strip_yaml_quotes(s: str) -> str:
    if len(s) >= 2 and ((s[0] == s[-1] == "'") or (s[0] == s[-1] == '"')):
        return s[1:-1]
    return s


def _yaml_value_at(text: str, top_key: str, sub_key: Optional[str] = None) -> Optional[str]:
    """Extract a scalar value from a Symfony-style YAML.

    Supports two forms:
      - `top_key: value` at column 0.
      - `top_key:` followed by indented `sub_key: value`.
    Returns None if not found. Quote-stripped.
    """
    in_top = False
    top_indent: Optional[int] = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if not in_top:
            m = re.match(rf"^{re.escape(top_key)}\s*:\s*(.*)$", stripped)
            if m and indent == 0:
                tail = m.group(1).strip()
                if sub_key is None:
                    if tail:
                        return _strip_yaml_quotes(tail)
                    in_top = True
                    top_indent = indent
                    continue
                if tail:
                    # `top_key: scalar` but caller wants nested — mismatch.
                    return None
                in_top = True
                top_indent = indent
        else:
            if indent <= (top_indent or 0):
                # Left the block.
                break
            m = re.match(rf"^{re.escape(sub_key)}\s*:\s*(.+)$", stripped)
            if m:
                return _strip_yaml_quotes(m.group(1).strip())
    return None


# ---------------------------------------------------------------------------
# Sub-section collectors.
# ---------------------------------------------------------------------------


_SYMFONY_COMMAND_FQNS = frozenset({
    "Symfony\\Component\\Console\\Command\\Command",
})
_EASYADMIN_CRUD_FQNS = frozenset({
    "EasyCorp\\Bundle\\EasyAdminBundle\\Controller\\AbstractCrudController",
    "EasyCorp\\Bundle\\EasyAdminBundle\\Controller\\AbstractDashboardController",
})
_SONATA_ADMIN_FQNS = frozenset({
    "Sonata\\AdminBundle\\Admin\\AbstractAdmin",
})
_MESSAGE_HANDLER_INTERFACES = frozenset({
    "Symfony\\Component\\Messenger\\Handler\\MessageHandlerInterface",
})
_EVENT_SUBSCRIBER_INTERFACES = frozenset({
    "Symfony\\Component\\EventDispatcher\\EventSubscriberInterface",
})
_AS_COMMAND_FQNS = frozenset({"Symfony\\Component\\Console\\Attribute\\AsCommand"})
_AS_MESSAGE_HANDLER_FQNS = frozenset({"Symfony\\Component\\Messenger\\Attribute\\AsMessageHandler"})
_AS_EVENT_LISTENER_FQNS = frozenset({"Symfony\\Component\\EventDispatcher\\Attribute\\AsEventListener"})


def _classify_kind(cls: dict, namespace_uses: dict[str, str]) -> Optional[str]:
    """Decide entry kind for an attack_surface item from class metadata.
    Returns None when class doesn't match an entry kind.

    FQN-first to avoid colliding with project-local classes named e.g.
    `App\\Domain\\Command` (DDD CQRS pattern). Short-name matching is kept
    for the resolved-attribute case (extractor's #[AsCommand] post-process
    yields short or fully-qualified depending on the use clause).

    Inheritance chains: extractor emits `parent_chain` (transitive list of
    resolved parent FQNs, max 5 hops) so a CLI command defined as
    `App\\Console\\BaseCommand → Symfony\\...\\Command\\Command` is detected
    even though the direct `extends` points at the project base class.
    """
    if cls.get("is_abstract"):
        # Abstract base classes (BaseCrudController, BaseCommand, ...) are
        # never user-reachable — surface only their concrete subclasses.
        return None
    extends = cls.get("extends") or ""
    parent_chain = list(cls.get("parent_chain") or [])
    parent_chain_set = set(parent_chain)
    implements = cls.get("implements") or []
    implements_set = set(implements)
    implements_short = {i.rsplit("\\", 1)[-1] for i in implements}
    attrs = cls.get("attributes") or []
    attr_fqns = {a.get("name") or "" for a in attrs}
    attr_short = {n.rsplit("\\", 1)[-1] for n in attr_fqns}

    # Admin CRUD (EasyAdmin / Sonata) — direct or via project-local base class.
    # FQN-only: a project-local `App\Framework\AbstractAdmin` should not be
    # misclassified as Sonata, and short-name `AbstractCrudController`
    # collisions in unrelated vendors are excluded by construction.
    if extends in _EASYADMIN_CRUD_FQNS or extends in _SONATA_ADMIN_FQNS:
        return "http_route_admin"
    if parent_chain_set & (_EASYADMIN_CRUD_FQNS | _SONATA_ADMIN_FQNS):
        return "http_route_admin"
    # CLI command — require Symfony FQN, not just any class named "Command".
    if extends in _SYMFONY_COMMAND_FQNS:
        return "cli_command"
    if parent_chain_set & _SYMFONY_COMMAND_FQNS:
        return "cli_command"
    if attr_fqns & _AS_COMMAND_FQNS or "AsCommand" in attr_short:
        return "cli_command"
    # Message handler.
    if attr_fqns & _AS_MESSAGE_HANDLER_FQNS or "AsMessageHandler" in attr_short:
        return "message_handler"
    if implements_set & _MESSAGE_HANDLER_INTERFACES or "MessageHandlerInterface" in implements_short:
        return "message_handler"
    # Event listener / subscriber.
    if implements_set & _EVENT_SUBSCRIBER_INTERFACES or "EventSubscriberInterface" in implements_short:
        return "event_listener"
    if attr_fqns & _AS_EVENT_LISTENER_FQNS or "AsEventListener" in attr_short:
        return "event_listener"
    # Method-level #[AsEventListener] (Symfony 6.3+ style: the attribute sits on
    # the handler method, not the class). Such classes carry no class-level
    # AsEventListener and may not implement EventSubscriberInterface (they can
    # even carry an unrelated class-level attribute like #[AsDoctrineListener]),
    # so the class-level checks above miss them. The extractor surfaces the flat
    # set of method-level attribute FQNs as `method_attributes` (the `class`
    # kind output does not carry full `methods`).
    method_attr_fqns = set(cls.get("method_attributes") or [])
    method_attr_short = {n.rsplit("\\", 1)[-1] for n in method_attr_fqns}
    if method_attr_fqns & _AS_EVENT_LISTENER_FQNS or "AsEventListener" in method_attr_short:
        return "event_listener"
    return None


def _attr_named_arg(attr: dict, key: str) -> Optional[str]:
    """Return string value of named arg `key` from extractor attribute dict."""
    args = (attr.get("arguments") or {}).get("named") or {}
    v = args.get(key)
    if not isinstance(v, dict):
        return None
    if v.get("type") == "string":
        return v.get("value")
    return None


def _attr_first_positional(attr: dict) -> Optional[str]:
    args = (attr.get("arguments") or {}).get("positional") or []
    if not args:
        return None
    v = args[0]
    if isinstance(v, dict) and v.get("type") == "string":
        return v.get("value")
    return None


def collect_attack_surface(
    project_root: Path,
    plugin_root: Path,
    diff_files: Optional[set[str]],
    sources_used: list[str],
    warnings: list[str],
    console_runner: "object",
    *,
    exclude: Optional[tuple[str, ...]] = None,
) -> list[dict]:
    """Build attack_surface items.

    `console_runner` is a `sandbox.ConsoleRunner`. Console enrichment runs only
    when its mode is not "disabled"; the runner already encodes WHERE the
    console runs (host / container / custom) — see recon_inventory's
    `decide_console_runner` and bin/recon/environment.py. When the runner is
    disabled because the execution environment could not be resolved
    (`env_runner_unknown:*` — e.g. a containerized project with no
    `--console-cmd`), we emit a LOUD `coverage_gap:` warning so the auditor
    knows dynamic route enumeration was skipped — never a silent degrade.

    Per-command console enrichment failures land in `warnings` (which the
    utility surfaces via frontmatter). Per-section partial-status semantics
    are out of S2 scope; the whole `attack_surface` is `status=ok` even
    when console enrichment partially failed (static-collected items are
    still authoritative for routes/cli/handlers/listeners).
    """
    from recon import sandbox

    items: list[dict] = []

    # 1. http_route (atomic + admin).
    # Extractor now skips DEFAULT_EXCLUDE prefixes (vendor/, var/cache/, ...)
    # before parsing; EXCLUDE_PATHS post-filter remains as a safety net for
    # paths the recipe wants to drop on top (tests/, *.min.js).
    routes_data, route_warn = sandbox.run_extractor(
        plugin_root, project_root, "routes", project_root, exclude=exclude,
    )
    if route_warn:
        warnings.append(route_warn)
    else:
        sources_used.append("extract_php_metadata.php:routes")
        for r in routes_data.get("items", []):
            file_rel = _to_relative(r.get("file"), project_root)
            if file_rel is None or _is_excluded(file_rel, EXCLUDE_PATHS):
                continue
            items.append(_route_item(r, project_root, diff_files, kind="http_route"))

    # 2. classes for cli_command / message_handler / event_listener / http_route_admin.
    classes_data, classes_warn = sandbox.run_extractor(
        plugin_root, project_root, "class", project_root, exclude=exclude,
    )
    fqn_to_file: dict[str, str] = {}
    if classes_warn:
        warnings.append(classes_warn)
    elif classes_data:
        sources_used.append("extract_php_metadata.php:class")
        # fqn → file over ALL classes (pre-classification), so console
        # enrichment can resolve a source file for a debug:router route whose
        # controller is declared without a static #[Route] attribute — the
        # debug:router JSON carries no file. See _enrich_via_console.
        for cls in classes_data.get("items", []):
            _fqn = (cls.get("fqn") or "").strip()
            _frel = _to_relative(cls.get("file"), project_root)
            if _fqn and _frel and not _is_excluded(_frel, EXCLUDE_PATHS):
                fqn_to_file[_fqn] = _frel
        seen_admin_classes: set[str] = set()
        for cls in classes_data.get("items", []):
            kind = _classify_kind(cls, {})
            if kind is None:
                continue
            file_rel = _to_relative(cls.get("file"), project_root)
            if file_rel is None:
                continue
            if _is_excluded(file_rel, EXCLUDE_PATHS):
                continue
            fqn = cls.get("fqn") or ""
            line = cls.get("line") or 0
            handler = fqn
            identifier = fqn
            if kind == "http_route_admin":
                # One admin item per class; route paths come from console
                # enrichment if available (EasyAdmin / Sonata generate them).
                if fqn in seen_admin_classes:
                    continue
                seen_admin_classes.add(fqn)
                items.append({
                    "kind": "http_route_admin",
                    "surface_type": "entry",
                    "identifier": identifier,
                    "handler": handler,
                    "file": file_rel,
                    "methods": [],
                    "guards": [],
                    "source": "extract_php_metadata.php:class",
                    "touched_by_diff": _touched(file_rel, diff_files),
                    "line": line,
                })
                continue
            if kind == "cli_command":
                cmd_name = _extract_cli_command_name(cls) or fqn
                items.append({
                    "kind": "cli_command",
                    "surface_type": "entry",
                    "identifier": cmd_name,
                    "handler": fqn,
                    "file": file_rel,
                    "methods": [],
                    "guards": [],
                    "source": "extract_php_metadata.php:class",
                    "touched_by_diff": _touched(file_rel, diff_files),
                    "line": line,
                })
                continue
            if kind == "message_handler":
                items.append({
                    "kind": "message_handler",
                    "surface_type": "listener",
                    "identifier": fqn,
                    "handler": fqn,
                    "file": file_rel,
                    "methods": [],
                    "guards": [],
                    "source": "extract_php_metadata.php:class",
                    "touched_by_diff": _touched(file_rel, diff_files),
                    "line": line,
                })
                continue
            if kind == "event_listener":
                items.append({
                    "kind": "event_listener",
                    "surface_type": "listener",
                    "identifier": fqn,
                    "handler": fqn,
                    "file": file_rel,
                    "methods": [],
                    "guards": [],
                    "source": "extract_php_metadata.php:class",
                    "touched_by_diff": _touched(file_rel, diff_files),
                    "line": line,
                })

    # 3. console enrichment (optional, environment-aware).
    if getattr(console_runner, "mode", "disabled") != "disabled":
        _enrich_via_console(
            project_root, items, sources_used, warnings, diff_files, console_runner,
            fqn_to_file,
        )
    else:
        reason = getattr(console_runner, "disabled_reason", None) or ""
        if reason.startswith("env_runner_unknown"):
            # LOUD coverage gap — not a silent skip. The execution environment
            # (e.g. a containerized project) could not be resolved, so dynamic
            # route enumeration via bin/console did NOT run.
            warnings.append(
                f"coverage_gap: console_disabled ({reason}) — dynamic route "
                "enumeration NOT performed; static route set may be incomplete"
            )

    return items


def _route_item(
    extractor_item: dict,
    project_root: Path,
    diff_files: Optional[set[str]],
    kind: str,
) -> dict:
    file_rel = _to_relative(extractor_item.get("file"), project_root) or ""
    return {
        "kind": kind,
        "surface_type": "entry",
        "identifier": extractor_item.get("route_name") or extractor_item.get("path") or "",
        "handler": extractor_item.get("controller") or "",
        "file": file_rel,
        "methods": list(extractor_item.get("methods") or []),
        "guards": [],
        "source": "extract_php_metadata.php:routes",
        "touched_by_diff": _touched(file_rel, diff_files),
        "line": extractor_item.get("line") or 0,
    }


def _to_relative(abs_path: Any, project_root: Path) -> Optional[str]:
    """Thin wrapper around `recon.recipes._shared.to_relative`.

    Shared with easyadmin_detect / sonata_detect via `_shared.py` so the three
    modules can't drift on the macOS `/var ↔ /private/var` symlink edge case.
    """
    return _shared_to_relative(abs_path, project_root)


def _touched(file_rel: str, diff_files: Optional[set[str]]) -> bool:
    if diff_files is None:
        return False
    if file_rel in diff_files:
        return True
    # Allow callers to pass diff entries with leading `./`.
    return ("./" + file_rel) in diff_files


def _extract_cli_command_name(cls: dict) -> Optional[str]:
    for a in cls.get("attributes") or []:
        if (a.get("name") or "").rsplit("\\", 1)[-1] == "AsCommand":
            name = _attr_named_arg(a, "name") or _attr_first_positional(a)
            if name:
                return name
    return None


def _enrich_via_console(
    project_root: Path,
    items: list[dict],
    sources_used: list[str],
    warnings: list[str],
    diff_files: Optional[set[str]],
    runner: "object",
    fqn_to_file: Optional[dict[str, str]] = None,
) -> None:
    """Run console probes via `runner` and fold their output into `items`.
    Per-command failures are captured in `warnings`, not raised — degraded
    gracefully.

    SECURITY: caller must have decided that running console is safe and chosen
    the execution environment (`runner.mode != "disabled"`). This DOES boot the
    framework kernel = arbitrary code execution, possibly inside a container.
    """
    from recon import sandbox

    smoke_ok, smoke_warn = sandbox.try_console_smoke(runner)
    if not smoke_ok:
        warnings.append(smoke_warn or "console_smoke_failed: unknown")
        return

    sources_used.append("console:smoke")

    # debug:router for additional routes.
    out, warn = sandbox.run_console_command(runner, ["debug:router", "--format=json"])
    if warn:
        warnings.append(warn)
    elif out is not None:
        try:
            data = json.loads(out)
        except json.JSONDecodeError as e:
            warnings.append(f"console_parse_failed: debug:router: {e}")
        else:
            sources_used.append("console:debug_router")
            seen = {(it.get("identifier"), it.get("handler")) for it in items}
            for name, info in (data.items() if isinstance(data, dict) else []):
                if not isinstance(info, dict):
                    continue
                # Defensive: `defaults` may be present with a `None` value.
                defaults = info.get("defaults") or {}
                controller = (defaults.get("_controller") if isinstance(defaults, dict) else None) \
                    or info.get("controller") or ""
                # Some bundles (e.g. LiipMonitorBundle) register the controller
                # as a `[class, method]` callable array rather than a
                # `Fqn::method` string, so debug:router --format=json emits a
                # list. Normalize to the string form the rest of this path (and
                # the dedup `key`) expects — a list is unhashable and would blow
                # up `seen.add(key)` with `unhashable type: 'list'`.
                if isinstance(controller, list):
                    controller = "::".join(str(p) for p in controller)
                elif not isinstance(controller, str):
                    controller = str(controller) if controller else ""
                identifier = name
                key = (identifier, controller)
                if key in seen:
                    continue
                seen.add(key)
                # Resolve the source file from the controller FQN (debug:router
                # gives `Fqn::method` and no file). Leaves "" when unresolved.
                cls_fqn = controller.split("::", 1)[0].lstrip("\\") if controller else ""
                file_rel = (fqn_to_file or {}).get(cls_fqn, "")
                method_str = info.get("method") or ""
                items.append({
                    "kind": "http_route",
                    "surface_type": "entry",
                    "identifier": identifier,
                    "handler": controller,
                    "file": file_rel,
                    "methods": list(method_str.split("|")) if method_str else [],
                    "guards": [],
                    "source": "console:debug_router",
                    "touched_by_diff": _touched(file_rel, diff_files) if file_rel else False,
                    "line": 0,
                })

    # debug:event-dispatcher / debug:messenger / list — currently we only
    # record the data source; per-item reconciliation is out of S2 scope.
    for label, args in (
        ("console:debug_event_dispatcher", ["debug:event-dispatcher", "--format=json"]),
        ("console:debug_messenger", ["debug:messenger", "--format=json"]),
        ("console:list", ["list", "--format=json"]),
    ):
        out, warn = sandbox.run_console_command(runner, args)
        if warn:
            warnings.append(warn)
        elif out is not None:
            sources_used.append(label)


# ---------------------------------------------------------------------------
# data_access.
# ---------------------------------------------------------------------------


_QUERY_PATTERNS = {
    "raw":     re.compile(r"->getConnection\(\)|->executeQuery\(|->executeStatement\(|->prepare\(|getNativeQuery\("),
    "builder": re.compile(r"->createQueryBuilder\("),
    "orm":     re.compile(r"->createQuery\(|->find\(|->findOneBy\(|->findBy\(|->findAll\("),
}
_DYNAMIC_QUERY_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\s*\.\s*[\"'`]|->andWhere\([^)]*\$|->where\([^)]*\$")


def collect_data_access(
    project_root: Path,
    plugin_root: Path,
    diff_files: Optional[set[str]],
    sources_used: list[str],
    warnings: list[str],
    *,
    exclude: Optional[tuple[str, ...]] = None,
) -> list[dict]:
    """Repository / DAO classes — extends ServiceEntityRepository or matches *Repository.php."""
    from recon import sandbox

    items: list[dict] = []
    classes_data, classes_warn = sandbox.run_extractor(
        plugin_root, project_root, "class", project_root, exclude=exclude,
    )
    if classes_warn:
        warnings.append(classes_warn)
        return items
    sources_used.append("extract_php_metadata.php:class")

    for cls in classes_data.get("items", []):
        file_rel = _to_relative(cls.get("file"), project_root)
        if file_rel is None:
            continue
        if _is_excluded(file_rel, EXCLUDE_PATHS):
            continue
        if not file_rel.endswith("Repository.php"):
            extends = (cls.get("extends") or "")
            if "Repository" not in extends:
                continue
        # Read text once for query-style heuristics.
        text = _read_text_safe(project_root / file_rel) or ""
        styles: list[str] = []
        for label, pat in _QUERY_PATTERNS.items():
            if pat.search(text):
                styles.append(label)
        items.append({
            "kind": "repository",
            "class": cls.get("fqn") or "",
            "file": file_rel,
            "line": cls.get("line") or 0,
            "extends": cls.get("extends") or None,
            "query_styles": styles,
            "has_native_sql": bool(_QUERY_PATTERNS["raw"].search(text)),
            "has_dynamic_query": bool(_DYNAMIC_QUERY_RE.search(text)),
            "source": "extract_php_metadata.php:class",
            "touched_by_diff": _touched(file_rel, diff_files),
        })
    return items


# ---------------------------------------------------------------------------
# auth_layer + recon_bags.stack.symfony.firewalls (parsed from security.yaml).
# ---------------------------------------------------------------------------


def collect_auth_layer_and_firewalls(
    project_root: Path,
    warnings: list[str],
) -> tuple[Optional[SectionPayload], Optional[SectionPayload]]:
    """Parse config/packages/security.yaml. Return (auth_layer, firewalls)."""
    sec_file = project_root / "config" / "packages" / "security.yaml"
    if not sec_file.is_file():
        return (
            SectionPayload(status="unknown", reason="security.yaml not found", source_files=[]),
            SectionPayload(status="unknown", reason="security.yaml not found", source_files=[]),
        )
    text = _read_text_safe(sec_file)
    if text is None:
        return (
            SectionPayload(status="unknown", reason="security.yaml unreadable", source_files=[]),
            SectionPayload(status="unknown", reason="security.yaml unreadable", source_files=[]),
        )
    rel = sec_file.relative_to(project_root).as_posix()

    firewalls = _parse_firewalls(text)
    access_control = _parse_access_control(text)
    has_jwt = bool(re.search(r"jwt|lexik_jwt", text, re.I))
    has_oauth = bool(re.search(r"oauth|knpu/oauth2", text, re.I))
    stateless = any(fw.get("stateless") == "true" for fw in firewalls)
    kind = "oauth" if has_oauth else ("jwt" if has_jwt else ("stateless" if stateless else "session"))
    # provider name = the first key inside `security: -> providers:` (nested).
    provider_name = _first_key_under_nested(text, ("security", "providers")) or "unknown"
    summary = (
        f"{kind.title()} auth via security.yaml; provider={provider_name}; "
        f"firewalls={len(firewalls)}; access_control rules={len(access_control)}"
    )

    auth_layer = SectionPayload(
        status="ok",
        data={
            "kind": kind,
            "provider": provider_name,
            "mfa": False,
            "summary": summary,
        },
        source_files=[rel],
    )
    firewalls_payload_data: dict = {}
    if firewalls:
        firewalls_payload_data["firewalls"] = firewalls
    if access_control:
        firewalls_payload_data["access_control"] = access_control
    if firewalls_payload_data:
        firewalls_payload = SectionPayload(
            status="ok",
            data=firewalls_payload_data,
            source_files=[rel],
        )
    else:
        firewalls_payload = SectionPayload(
            status="none",
            reason="no firewalls or access_control declared",
            source_files=[rel],
        )
    return auth_layer, firewalls_payload


def _framework_setting(text: str, sub_key: str) -> Optional[str]:
    """Value of `framework: -> sub_key:` from framework.yaml.

    Inline scalar (`trusted_proxies: '%env(TRUSTED_PROXIES)%'`) → its
    inline-comment-stripped, quote-stripped string. List form — block
    (`trusted_headers:` then indented `- x-forwarded-for`) or inline flow
    (`['x-forwarded-for']`) — → the marker `"(list)"` (the bag is a hint; the
    worker reads the routed source_file for the exact items). Absent — or a
    bare key with no value and no children — → None.

    Matches only **direct children** of the top-level `framework:` block: a
    same-named key nested under a sub-block (e.g. `framework: http_client:
    trusted_proxies:`) is ignored, so the recorded value is never borrowed from
    an unrelated setting.
    """
    lines = text.splitlines()
    in_fw = False
    child_indent: Optional[int] = None
    for i, raw in enumerate(lines):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if not in_fw:
            if indent == 0 and re.match(r"^framework\s*:\s*$", stripped):
                in_fw = True
            continue
        if indent == 0:
            break  # left the framework: block
        if child_indent is None:
            child_indent = indent  # first direct child fixes the level
        if indent != child_indent:
            continue  # nested deeper than a direct child — not framework.<key>
        m = re.match(rf"^{re.escape(sub_key)}\s*:\s*(.*)$", stripped)
        if not m:
            continue
        tail = _strip_inline_comment(m.group(1).strip()).strip()
        if tail:
            # Inline flow-list → the same "(list)" marker as the block form.
            if tail.startswith("["):
                return "(list)"
            return _strip_yaml_quotes(tail)
        # Empty tail → value lives on following more-indented lines.
        for nxt in lines[i + 1:]:
            nl = nxt.rstrip()
            if not nl.strip() or nl.lstrip().startswith("#"):
                continue
            if (len(nl) - len(nl.lstrip(" "))) <= child_indent:
                break  # nothing indented under the key → treat as unset
            return "(list)"
        return None
    return None


def collect_trusted_config(project_root: Path) -> SectionPayload:
    """Parse config/packages/framework.yaml for the request trust boundary
    (trusted_proxies / trusted_hosts / trusted_headers).

    Scalar bag `recon_bags.stack.symfony.trusted_config`, routed into W1 via
    the `request_trust` concept (plan_waves) so a worker reads framework.yaml.
    Status contract mirrors `firewalls`:
      - file absent/unreadable → `unknown` (bag present in the skeleton, not
        routed; `scalar_source_files` gates routing on status=="ok").
      - ≥1 trusted_* key present → `ok` (data + source_files → routed).
      - file present, no trusted_* key → `none` (safe default, nothing to review).
    See stacks/symfony/auth.md → "Request trust boundary".
    """
    fw_file = project_root / "config" / "packages" / "framework.yaml"
    if not fw_file.is_file():
        return SectionPayload(status="unknown", reason="framework.yaml not found", source_files=[])
    text = _read_text_safe(fw_file)
    if text is None:
        return SectionPayload(status="unknown", reason="framework.yaml unreadable", source_files=[])
    rel = fw_file.relative_to(project_root).as_posix()
    data: dict = {}
    for key in ("trusted_proxies", "trusted_hosts", "trusted_headers"):
        val = _framework_setting(text, key)
        if val is not None:
            data[key] = val
    if data:
        return SectionPayload(status="ok", data=data, source_files=[rel])
    return SectionPayload(
        status="none",
        reason="no trusted_proxies/hosts/headers configured",
        source_files=[rel],
    )


def _first_key_under_nested(text: str, path: tuple[str, ...]) -> Optional[str]:
    """Find the first child key inside a nested-block YAML path.

    Example: path=("security", "providers") on
        security:
            providers:
                app_user_provider:
                    entity: ...
    returns "app_user_provider".

    Indent-relative: works with any consistent step (2 / 4 / 8 spaces).
    Skips comments and blank lines. Returns None on miss.
    """
    if not path:
        return None
    cursor = 0
    parent_indent: Optional[int] = None  # indent of `path[cursor-1]:` line
    expect = path[cursor]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if cursor == 0:
            # Look for top-level key (indent 0, first segment of path).
            if indent == 0 and stripped.startswith(expect + ":"):
                parent_indent = indent
                cursor += 1
                if cursor < len(path):
                    expect = path[cursor]
            continue
        # We are inside a parent block; require indent > parent_indent.
        if indent <= parent_indent:
            return None
        if cursor < len(path):
            # Looking for the next named key in the path.
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:", stripped)
            if m and m.group(1) == expect:
                parent_indent = indent
                cursor += 1
                if cursor < len(path):
                    expect = path[cursor]
            continue
        # Cursor exhausted — first child key under the deepest segment.
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:", stripped)
        if m:
            return m.group(1)
    return None


def _first_key_under(text: str, top_key: str) -> Optional[str]:
    """Backward-compat wrapper: top-level only (path of length 1)."""
    return _first_key_under_nested(text, (top_key,))


def _strip_inline_comment(s: str) -> str:
    """Strip ` # ...` inline comment, but only when `#` is preceded by
    whitespace and lies outside string quotes.

    Whole-line comments are filtered upstream by `raw.lstrip().startswith("#")`,
    so a `#` at position 0 here is part of the value (anchor / literal hash),
    not a comment marker.
    """
    in_quote: Optional[str] = None
    for i, ch in enumerate(s):
        if in_quote is not None:
            if ch == in_quote:
                in_quote = None
            continue
        if ch in "'\"":
            in_quote = ch
            continue
        if ch == "#" and i > 0 and s[i - 1] in " \t":
            return s[:i].rstrip()
    return s


def _enter_nested_block(text: str, path: tuple[str, ...]) -> Optional[tuple[int, int]]:
    """Find a block at `path` (e.g. ("security", "firewalls")) and return
    (start_line_index, parent_indent) — `start_line_index` is the line right
    after the deepest path segment header, `parent_indent` is the indent of
    that header. Returns None if any segment is missing.
    """
    lines = text.splitlines()
    cursor = 0
    parent_indent = -1  # indent of segment[cursor-1] header (-1 = pre-root)
    for i, raw in enumerate(lines):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        # Have we left the block we were searching in?
        if cursor > 0 and indent <= parent_indent:
            return None
        # Match the next path segment.
        if indent == (parent_indent + (0 if cursor == 0 else 1)) or (cursor == 0 and indent == 0) or (cursor > 0 and indent > parent_indent):
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:", stripped)
            if m and m.group(1) == path[cursor]:
                parent_indent = indent
                cursor += 1
                if cursor == len(path):
                    return (i + 1, indent)
    return None


def _parse_firewalls(text: str) -> list[dict[str, str]]:
    """Extract list of firewalls from `security: firewalls:` block.

    Indent-relative: works with 2/4-space (or any consistent) indentation.
    """
    block = _enter_nested_block(text, ("security", "firewalls"))
    if block is None:
        return []
    start_idx, firewalls_indent = block
    lines = text.splitlines()
    out: list[dict[str, str]] = []
    cur_name: Optional[str] = None
    cur: dict[str, str] = {}
    name_indent: Optional[int] = None  # indent of `<firewall_name>:` lines
    for raw in lines[start_idx:]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= firewalls_indent:
            break
        stripped = raw.strip()
        if name_indent is None:
            name_indent = indent
        if indent == name_indent and stripped.endswith(":"):
            if cur_name is not None:
                out.append({"name": cur_name, **cur})
            cur_name = stripped[:-1].strip()
            cur = {}
            continue
        if indent > name_indent and ":" in stripped and cur_name is not None:
            k, _, v = stripped.partition(":")
            v = _strip_inline_comment(v.strip())
            cur[k.strip()] = _strip_yaml_quotes(v)
    if cur_name is not None:
        out.append({"name": cur_name, **cur})
    return out


_ACCESS_CONTROL_FLOW_RE = re.compile(r"^\s*-\s*(\{.*\})\s*$")


def _parse_access_control(text: str) -> list[dict[str, str]]:
    """Extract access_control rules.

    Supports both forms:
      - flow-style single-line:  `- { path: ^/admin, roles: ROLE_ADMIN }`
      - flow-style multi-line:   `- {\n    path: ^/admin,\n    roles: ROLE_ADMIN\n  }`
      - block-style: `- path: ^/admin\n      roles: ROLE_ADMIN`
    Indent-relative.
    """
    block = _enter_nested_block(text, ("security", "access_control"))
    if block is None:
        return []
    start_idx, access_indent = block
    lines = text.splitlines()
    out: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    cur_active = False
    # Accumulator for multi-line flow-style blocks (`- {\n...\n}`).
    flow_buf: list[str] = []
    flow_depth = 0  # brace nesting depth (>0 means inside a flow block)
    for raw in lines[start_idx:]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= access_indent and flow_depth == 0:
            break
        stripped = raw.strip()
        # If we are inside a multi-line flow block, accumulate lines. Strip any
        # inline `# comment` per physical line BEFORE buffering: the lines are
        # later joined with spaces, so an un-stripped trailing comment would
        # swallow the following line (`roles: [...], # or` + `allow_if: ...`
        # -> `# or allow_if`, an invalid key).
        if flow_depth > 0:
            clean = _strip_inline_comment(stripped)
            flow_buf.append(clean)
            flow_depth += clean.count("{") - clean.count("}")
            if flow_depth <= 0:
                # Block closed — join and parse.
                full = " ".join(flow_buf)
                parsed = _parse_flow_inline_kv(full)
                if parsed:
                    out.append(parsed)
                flow_buf = []
                flow_depth = 0
            continue
        # Flow-style entry on a single line: `- { ... }`.
        m = _ACCESS_CONTROL_FLOW_RE.match(raw)
        if m:
            if cur_active:
                out.append(cur)
                cur, cur_active = {}, False
            parsed = _parse_flow_inline_kv(m.group(1))
            if parsed:
                out.append(parsed)
            continue
        # Multi-line flow block starting with `- {` (no closing `}` on same line).
        if stripped.startswith("- {"):
            if cur_active:
                out.append(cur)
                cur, cur_active = {}, False
            tail = _strip_inline_comment(stripped[2:])  # strip leading `- ` + inline comment
            flow_buf = [tail]
            # Count brace depth; `{` opens it, `}` closes it.
            flow_depth = tail.count("{") - tail.count("}")
            if flow_depth <= 0:
                # Edge case: somehow closed on the same line without matching regex.
                parsed = _parse_flow_inline_kv(" ".join(flow_buf))
                if parsed:
                    out.append(parsed)
                flow_buf = []
                flow_depth = 0
            continue
        # Block-style: `- key: value` starts a new rule; subsequent indented
        # `key: value` lines extend the same rule.
        if stripped.startswith("- "):
            if cur_active:
                out.append(cur)
            cur, cur_active = {}, True
            kv = stripped[2:]
            if ":" in kv:
                k, _, v = kv.partition(":")
                cur[k.strip()] = _strip_yaml_quotes(_strip_inline_comment(v.strip()))
            continue
        if cur_active and ":" in stripped:
            k, _, v = stripped.partition(":")
            cur[k.strip()] = _strip_yaml_quotes(_strip_inline_comment(v.strip()))
    if cur_active:
        out.append(cur)
    return out


# ---------------------------------------------------------------------------
# authz_usage.
# ---------------------------------------------------------------------------


_AUTHZ_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("denyAccessUnlessGranted", re.compile(r"->denyAccessUnlessGranted\(\s*([^,)\s]+)")),
    ("isGranted_security",      re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?security->isGranted\(\s*([^,)\s]+)")),
    ("isGranted_authChecker",   re.compile(r"\$(?:auth_?checker|authorizationChecker)->isGranted\(\s*([^,)\s]+)")),
    ("attr_IsGranted",          re.compile(r"#\[\s*(?:[A-Za-z_\\][A-Za-z0-9_\\]*\\)?IsGranted\(\s*([^,)\s]+)")),
    ("attr_Security",           re.compile(r"#\[\s*(?:[A-Za-z_\\][A-Za-z0-9_\\]*\\)?Security\(\s*([^,)\s]+)")),
    ("anno_IsGranted",          re.compile(r"@IsGranted\(\s*([^,)\s]+)")),
    ("anno_Security",           re.compile(r"@Security\(\s*([^,)\s]+)")),
    ("hasAccess",               re.compile(r"->hasAccess\(\s*([^,)\s]+)")),
]


def collect_authz_usage(
    files: list[tuple[str, Path]],
    project_root: Path,
    diff_files: Optional[set[str]],
) -> list[dict]:
    items: list[dict] = []
    for rel, abs_path in files:
        text = _read_text_safe(abs_path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for kind, pattern in _AUTHZ_PATTERNS:
                m = pattern.search(line)
                if m is None:
                    continue
                attribute = m.group(1).strip().rstrip("'\",")
                attribute = attribute.lstrip("'\"")
                in_service = "/Service/" in rel or rel.endswith("Service.php") or "/Manager/" in rel
                items.append({
                    "kind": "authz_in_service" if in_service else kind,
                    "file": rel,
                    "line": lineno,
                    "attribute_or_role": attribute,
                    "source": "extract_php_metadata.php:grep",
                    "touched_by_diff": _touched(rel, diff_files),
                })
                break  # one match per line — avoid double-reporting overlap
    return items


# ---------------------------------------------------------------------------
# output_renderers.
# ---------------------------------------------------------------------------


def collect_output_renderers(
    project_root: Path,
    files: list[tuple[str, Path]],
    diff_files: Optional[set[str]],
) -> list[dict]:
    """Twig templates + controller render() / new JsonResponse / new Response calls."""
    items: list[dict] = []

    # Templates.
    templates_root = project_root / "templates"
    if templates_root.is_dir():
        project_resolved = project_root.resolve()
        for tpl in sorted(templates_root.rglob("*.twig")):
            # Symlink containment + EXCLUDE_PATHS, mirroring _list_php_files.
            try:
                resolved = tpl.resolve()
                rel = resolved.relative_to(project_resolved).as_posix()
            except (ValueError, OSError):
                continue
            if _is_excluded(rel, EXCLUDE_PATHS):
                continue
            autoescape = "on" if rel.endswith(".html.twig") else "na"
            text = _read_text_safe(resolved) or ""
            if re.search(r"\{%\s*autoescape\s+false\s*%\}", text):
                autoescape = "off"
            items.append({
                "kind": "template",
                "file": rel,
                "identifier": rel,
                "autoescape": autoescape,
                "source": "glob:templates",
                "touched_by_diff": _touched(rel, diff_files),
            })

    # Controllers: render / JsonResponse / Response.
    render_re = re.compile(r"->render(?:View)?\(\s*['\"]([^'\"]+)['\"]")
    json_re = re.compile(r"new\s+JsonResponse\(|->json\(")
    html_re = re.compile(r"new\s+Response\(")
    for rel, abs_path in files:
        if "Controller" not in rel:
            continue
        text = _read_text_safe(abs_path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = render_re.search(line)
            if m:
                items.append({
                    "kind": "template_render",
                    "file": rel,
                    "identifier": m.group(1),
                    "autoescape": "na",
                    "source": "extract_php_metadata.php:grep",
                    "touched_by_diff": _touched(rel, diff_files),
                    "line": lineno,
                })
                continue  # don't double-report a single line
            if json_re.search(line):
                items.append({
                    "kind": "json_response",
                    "file": rel,
                    "identifier": f"{rel}:{lineno}",
                    "autoescape": "na",
                    "source": "extract_php_metadata.php:grep",
                    "touched_by_diff": _touched(rel, diff_files),
                    "line": lineno,
                })
                continue
            if html_re.search(line):
                items.append({
                    "kind": "html_response",
                    "file": rel,
                    "identifier": f"{rel}:{lineno}",
                    "autoescape": "na",
                    "source": "extract_php_metadata.php:grep",
                    "touched_by_diff": _touched(rel, diff_files),
                    "line": lineno,
                })
    return items


# ---------------------------------------------------------------------------
# serialization / file_operations / http_clients.
# ---------------------------------------------------------------------------


_SERIALIZATION_RE = re.compile(r"\b(unserialize|jms_serializer|php_serialize)\b")
_FILE_OPS_RE = re.compile(
    r"\b(file_get_contents|file_put_contents|fopen|move_uploaded_file|"
    r"include|include_once|require|require_once|copy|rename)\s*\("
)
_HTTP_CLIENT_RE = re.compile(
    r"\b(HttpClientInterface|GuzzleHttp\\\\Client|Symfony\\\\Contracts\\\\HttpClient|"
    r"curl_init)\b|\b(?:->createClient|HttpClient::create)\("
)


def collect_grep_section(
    files: list[tuple[str, Path]],
    pattern: re.Pattern[str],
    kind_label: str,
    diff_files: Optional[set[str]],
) -> list[dict]:
    items: list[dict] = []
    for rel, abs_path in files:
        text = _read_text_safe(abs_path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = pattern.search(line)
            if m is None:
                continue
            tag = (m.group(1) if m.lastindex else m.group(0)).strip()
            items.append({
                "kind": tag if tag else kind_label,
                "file": rel,
                "line": lineno,
                "has_dynamic_arg": "$" in line[m.end():m.end() + 60],
                "source": "extract_php_metadata.php:grep",
                "touched_by_diff": _touched(rel, diff_files),
            })
    return items


# ---------------------------------------------------------------------------
# secrets (pending_enrichment).
# ---------------------------------------------------------------------------


_SECRET_CRED_REGEXES = [
    (re.compile(r"sk_live_[A-Za-z0-9_-]{8,}"), "stripe_live_key"),
    (re.compile(r"sk_test_[A-Za-z0-9_-]{8,}"), "stripe_test_key"),
    (re.compile(r"AIza[A-Za-z0-9_-]{20,}"), "google_api_key"),
    (re.compile(r"AKIA[A-Z0-9]{16}"), "aws_access_key"),
    (re.compile(r"\bxox[bpoa]-[A-Za-z0-9-]{10,}"), "slack_token"),
]
_SECRET_REGEXES = _SECRET_CRED_REGEXES + [
    (re.compile(r"['\"](?:api_?key|secret|password|token)['\"]\s*=>\s*['\"][^'\"]{8,}['\"]"),
     "key_value_pair"),
]
# YAML scanner uses only credential-prefix patterns; the PHP-arrow `=>` form
# does not occur in yaml. Adding a yaml-style `key: value` pattern would flag
# `secret: '%env(...)%'` and `password_hashers: auto`, so we keep it focused
# on hard tokens — yaml-resident weak/key_value entries surface via worker
# checklists, not the static recipe.
_SECRET_REGEXES_YAML = _SECRET_CRED_REGEXES
_SECRETS_CANDIDATES_CAP = 50


def _scan_secrets_in_files(
    files: list[tuple[str, Path]],
    regexes: list[tuple[re.Pattern[str], str]],
    candidates: list[dict],
) -> bool:
    """Append candidate hits in-place; return True if cap was hit."""
    for rel, abs_path in files:
        if len(candidates) >= _SECRETS_CANDIDATES_CAP:
            return True
        text = _read_text_safe(abs_path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(candidates) >= _SECRETS_CANDIDATES_CAP:
                return True
            for pat, label in regexes:
                m = pat.search(line)
                if m is None:
                    continue
                snippet = line.strip()[:120]
                candidates.append({
                    "file": rel,
                    "line": lineno,
                    "snippet": snippet,
                    "regex_match": label,
                })
                break
    return False


def collect_secrets(
    project_root: Path,
    files: list[tuple[str, Path]],
    warnings: list[str],
) -> SectionPayload:
    candidates: list[dict] = []
    capped = _scan_secrets_in_files(files, _SECRET_REGEXES, candidates)
    if not capped:
        yaml_files = _list_config_yaml_files(project_root)
        capped = _scan_secrets_in_files(yaml_files, _SECRET_REGEXES_YAML, candidates)
    if capped:
        warnings.append(
            f"secrets_candidates_capped: stopped at {_SECRETS_CANDIDATES_CAP} hits "
            "(real audit needs full grep — bounded for LLM enrichment)"
        )

    # app_secret_in_repo / dotenv_committed.
    env_file = project_root / ".env"
    app_secret_in_repo = False
    dotenv_committed = env_file.is_file()
    if env_file.is_file():
        text = _read_text_safe(env_file) or ""
        if re.search(r"^APP_SECRET=.+", text, re.M):
            app_secret_in_repo = True

    sec_yaml = project_root / "config" / "packages" / "security.yaml"
    password_hasher: Optional[str] = None
    if sec_yaml.is_file():
        sec_text = _read_text_safe(sec_yaml) or ""
        password_hasher = _parse_password_hasher(sec_text)

    data = {
        "app_secret_in_repo": app_secret_in_repo,
        "hardcoded_secret_count": len(candidates),
        "candidates": candidates,
        "password_hasher": password_hasher or "unknown",
        "dotenv_committed": dotenv_committed,
    }
    return SectionPayload(
        status="pending_enrichment",
        enrichment_hint=(
            f"Static recipe collected {len(candidates)} candidate hardcoded-secret matches "
            f"(cap={_SECRETS_CANDIDATES_CAP}). Classify each in `candidates`: "
            "is_real_secret yes/no, severity (info/medium/critical), sink_kind. "
            "Promote real secrets into items with status=ok."
        ),
        data=data,
        source_files=[".env", "config/packages/security.yaml"],
    )


# ---------------------------------------------------------------------------
# fintech_markers + frontend_assets.
# ---------------------------------------------------------------------------


def collect_fintech_markers(
    project_root: Path,
    files: list[tuple[str, Path]],
    diff_files: Optional[set[str]],
) -> list[dict]:
    items: list[dict] = []
    composer = project_root / "composer.json"
    if composer.is_file():
        try:
            data = json.loads(composer.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
        deps = {**(data.get("require") or {}), **(data.get("require-dev") or {})}
        for dep in sorted(deps):
            if any(s in dep.lower() for s in ("stripe", "moneyphp", "brick/money", "cashier", "paypal")):
                items.append({
                    "marker": dep,
                    "file": "composer.json",
                    "source": "composer.json",
                    "touched_by_diff": _touched("composer.json", diff_files),
                })
    decimal_re = re.compile(r"#\[\s*ORM\\Column\([^)]*type:\s*['\"](decimal|float|money)['\"]")
    for rel, abs_path in files:
        if "/Entity/" not in rel:
            continue
        text = _read_text_safe(abs_path) or ""
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = decimal_re.search(line)
            if m:
                items.append({
                    "marker": f"orm_column_{m.group(1)}",
                    "file": rel,
                    "entity": Path(rel).stem,
                    "field": "",
                    "source": "extract_php_metadata.php:grep",
                    "touched_by_diff": _touched(rel, diff_files),
                })
    return items


def collect_frontend_assets(
    project_root: Path,
    diff_files: Optional[set[str]],
) -> list[dict]:
    items: list[dict] = []
    importmap = project_root / "importmap.php"
    if importmap.is_file():
        rel = "importmap.php"
        items.append({
            "kind": "importmap",
            "name": "importmap",
            "file": rel,
            "source": "glob:importmap.php",
            "touched_by_diff": _touched(rel, diff_files),
        })
    assets_root = project_root / "assets"
    if assets_root.is_dir():
        for f in sorted(assets_root.rglob("*.js")):
            try:
                rel = f.relative_to(project_root).as_posix()
            except ValueError:
                continue
            if _is_excluded(rel, EXCLUDE_PATHS):
                continue
            kind = "stimulus" if "/controllers/" in rel else "raw_js"
            items.append({
                "kind": kind,
                "name": Path(rel).stem,
                "file": rel,
                "source": "glob:assets",
                "touched_by_diff": _touched(rel, diff_files),
            })
    return items


# ---------------------------------------------------------------------------
# recon_bags.stack.symfony.* collectors.
# ---------------------------------------------------------------------------


def compute_admin_authz_coverage(
    voters_payload: SectionPayload,
    crud_payload: SectionPayload,
    sonata_payload: Optional[SectionPayload] = None,
) -> SectionPayload:
    """Cross-check admin classes (EasyAdmin CRUD + Sonata) against voters.

    Each admin class declares an `entity_fqcn`. A voter is considered to cover
    that entity when its `subjects` list contains the same FQN (exact match —
    sub-class match would require runtime semantics).

    Status semantics:
      * `none`    — no admin classes at all (irrelevant on non-admin projects).
      * `ok`      — every admin class has at least one matching voter.
      * `partial` — at least one admin class has no matching voter (likely
                    `mass_assignment` / privilege-escalation surface).

    Known limitations (per plan §Task 6 edge cases):
      * Voters that match super- or subclasses dynamically are missed.
      * Custom `Security::isGranted()` checks inside controller actions are
        invisible — only the voter layer is inspected.
    """
    crud_items = list(crud_payload.items or [])
    sonata_items = list(sonata_payload.items or []) if sonata_payload else []
    voter_items = list(voters_payload.items or [])

    if not crud_items and not sonata_items:
        return SectionPayload(
            status="none",
            reason="no admin classes (EasyAdmin/Sonata) to evaluate",
            source_files=[],
        )

    voter_subjects: dict[str, set[str]] = {}
    for v in voter_items:
        subjects = {s for s in (v.get("subjects") or []) if isinstance(s, str)}
        cls = v.get("class") or ""
        voter_subjects[cls] = subjects

    with_voter: list[str] = []
    without_voter: list[str] = []
    source_files: set[str] = set()

    for admin in (*crud_items, *sonata_items):
        admin_class = admin.get("class") or ""
        admin_short = admin_class.rsplit("\\", 1)[-1] or admin_class
        admin_file = admin.get("file")
        if isinstance(admin_file, str) and admin_file:
            source_files.add(admin_file)
        entity = admin.get("entity_fqcn")
        if not entity:
            without_voter.append(admin_short)
            continue
        is_wired = any(entity in subjects for subjects in voter_subjects.values())
        (with_voter if is_wired else without_voter).append(admin_short)

    voters_inspected = sorted({
        (cls.rsplit("\\", 1)[-1] or cls) for cls in voter_subjects.keys()
    })
    for v in voter_items:
        f = v.get("file")
        if isinstance(f, str) and f:
            source_files.add(f)

    data = {
        "crud_controllers_with_voter": with_voter,
        "crud_controllers_without_voter": without_voter,
        "voters_inspected": voters_inspected,
    }
    status = "partial" if without_voter else "ok"
    return SectionPayload(
        status=status,
        data=data,
        source_files=sorted(source_files),
    )


# Sonata / EasyAdmin collectors live in sibling addon-detector modules
# (imported at module top alongside other recon.recipes imports).


def collect_voters(
    project_root: Path,
    plugin_root: Path,
    warnings: list[str],
    *,
    exclude: Optional[tuple[str, ...]] = None,
) -> SectionPayload:
    from recon import sandbox

    out, warn = sandbox.run_extractor(
        plugin_root, project_root, "voters", project_root, exclude=exclude,
    )
    if warn:
        warnings.append(warn)
        return SectionPayload(status="unknown", reason=warn)
    items: list[dict] = []
    for v in (out.get("items") or []):
        rel = _to_relative(v.get("file"), project_root)
        if rel is None or _is_excluded(rel, EXCLUDE_PATHS):
            continue
        items.append({
            "class": v.get("class") or "",
            "file": rel,
            "line": v.get("line") or 0,
            "attributes": list(v.get("attributes") or []),
            "subjects": list(v.get("subjects") or []),
        })
    return SectionPayload(status="ok", items=items)


def collect_forms(
    project_root: Path,
    plugin_root: Path,
    warnings: list[str],
    *,
    exclude: Optional[tuple[str, ...]] = None,
) -> SectionPayload:
    from recon import sandbox

    out, warn = sandbox.run_extractor(
        plugin_root, project_root, "forms", project_root, exclude=exclude,
    )
    if warn:
        warnings.append(warn)
        return SectionPayload(status="unknown", reason=warn)
    items: list[dict] = []
    for f in (out.get("items") or []):
        rel = _to_relative(f.get("file"), project_root)
        if rel is None or _is_excluded(rel, EXCLUDE_PATHS):
            continue
        items.append({
            "class": f.get("class") or "",
            "file": rel,
            "line": f.get("line") or 0,
            "data_class": f.get("data_class") or "",
            "csrf_protection": f.get("csrf_protection") if f.get("csrf_protection") is not None else False,
            "allow_extra_fields": f.get("allow_extra_fields") if f.get("allow_extra_fields") is not None else False,
        })
    return SectionPayload(status="ok", items=items)


def collect_serializer_groups(
    project_root: Path,
    plugin_root: Path,
    warnings: list[str],
    *,
    exclude: Optional[tuple[str, ...]] = None,
) -> SectionPayload:
    from recon import sandbox

    out, warn = sandbox.run_extractor(
        plugin_root, project_root, "serializer-groups", project_root, exclude=exclude,
    )
    if warn:
        warnings.append(warn)
        return SectionPayload(status="unknown", reason=warn)
    items: list[dict] = []
    for g in (out.get("items") or []):
        rel = _to_relative(g.get("file"), project_root)
        if rel is None or _is_excluded(rel, EXCLUDE_PATHS):
            continue
        items.append({
            "class": g.get("class") or "",
            "member": g.get("member") or "",
            "kind": g.get("kind") or "property",
            "groups": list(g.get("groups") or []),
            "file": rel,
            "line": g.get("line") or 0,
        })
    return SectionPayload(status="ok", items=items)


def collect_twig_overrides(project_root: Path) -> SectionPayload:
    """twig_overrides scalar — autoescape default + |raw filter usage."""
    twig_yaml = project_root / "config" / "packages" / "twig.yaml"
    autoescape_default = "name"  # Symfony default
    source_files: list[str] = []
    if twig_yaml.is_file():
        source_files.append(twig_yaml.relative_to(project_root).as_posix())
        text = _read_text_safe(twig_yaml) or ""
        v = _yaml_value_at(text, "twig", "autoescape")
        if v is not None:
            autoescape_default = v

    # |raw filter occurrences in templates/. Use \|raw\b to skip false-positive
    # `|raw` substring inside string literals or comments (`{# |raw #}` etc).
    raw_count = 0
    raw_locations: list[str] = []
    raw_re = re.compile(r"\|\s*raw\b")
    templates_root = project_root / "templates"
    if templates_root.is_dir():
        project_resolved = project_root.resolve()
        for tpl in sorted(templates_root.rglob("*.twig")):
            try:
                resolved = tpl.resolve()
                rel = resolved.relative_to(project_resolved).as_posix()
            except (ValueError, OSError):
                continue
            if _is_excluded(rel, EXCLUDE_PATHS):
                continue
            text = _read_text_safe(resolved) or ""
            for lineno, line in enumerate(text.splitlines(), start=1):
                if raw_re.search(line):
                    raw_count += 1
                    if len(raw_locations) < 50:
                        raw_locations.append(f"{rel}:{lineno}")
                        if rel not in source_files:
                            source_files.append(rel)

    return SectionPayload(
        status="ok",
        data={
            "autoescape_default": autoescape_default,
            "raw_filter_count": raw_count,
            "raw_filter_locations": raw_locations,
        },
        source_files=source_files,
    )


def collect_messenger_transports(project_root: Path) -> SectionPayload:
    msg_yaml = project_root / "config" / "packages" / "messenger.yaml"
    if not msg_yaml.is_file():
        return SectionPayload(
            status="none",
            reason="messenger.yaml not present",
            source_files=[],
        )
    text = _read_text_safe(msg_yaml) or ""
    rel = msg_yaml.relative_to(project_root).as_posix()
    transports = _parse_messenger_transports(text)
    if not transports:
        return SectionPayload(
            status="none",
            reason="messenger.yaml present but no transports section parsed",
            source_files=[rel],
        )
    return SectionPayload(
        status="ok",
        data={"transports": transports},
        source_files=[rel],
    )


def _parse_password_hasher(text: str) -> Optional[str]:
    """Find the value of the first child entry under
    `security: password_hashers: <subject>: <value>`.

    Symfony's password_hashers maps subject (FQN/interface) → algorithm
    string ("auto", "bcrypt", ...). We want the algorithm, not the subject.
    """
    block = _enter_nested_block(text, ("security", "password_hashers"))
    if block is None:
        return None
    start_idx, hashers_indent = block
    lines = text.splitlines()
    for raw in lines[start_idx:]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= hashers_indent:
            return None
        stripped = raw.strip()
        if ":" not in stripped:
            continue
        # First entry: scalar form `<subject>: <value>` OR block form
        # `<subject>:` followed by indented `algorithm: ...`.
        _, _, value = stripped.partition(":")
        value = _strip_inline_comment(value.strip())
        if value:
            return _strip_yaml_quotes(value)
        # Block form — return value of `algorithm:` key inside subject block.
        return _read_block_algorithm(lines, start_idx + 1, indent)
    return None


def _read_block_algorithm(lines: list[str], start: int, parent_indent: int) -> Optional[str]:
    for raw in lines[start:]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= parent_indent:
            return None
        stripped = raw.strip()
        if stripped.startswith("algorithm:"):
            _, _, v = stripped.partition(":")
            return _strip_yaml_quotes(_strip_inline_comment(v.strip()))
    return None


def _parse_messenger_transports(text: str) -> list[dict[str, str]]:
    """Extract transports list from `framework: messenger: transports:` block.

    Indent-relative — accepts any consistent indentation step (2 / 4 / 8).
    """
    block = _enter_nested_block(text, ("framework", "messenger", "transports"))
    if block is None:
        return []
    start_idx, transports_indent = block
    lines = text.splitlines()
    transports: list[dict[str, str]] = []
    cur_name: Optional[str] = None
    cur: dict[str, str] = {}
    name_indent: Optional[int] = None  # indent of `<transport_name>:` lines

    for raw in lines[start_idx:]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= transports_indent:
            break
        stripped = raw.strip()
        if name_indent is None:
            name_indent = indent
        if indent == name_indent:
            if cur_name is not None:
                transports.append({"name": cur_name, **cur})
                cur = {}
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", stripped)
            if not m:
                cur_name = None
                continue
            cur_name = m.group(1)
            tail = _strip_inline_comment(m.group(2).strip())
            if tail:
                # name: 'sync://' or name: 'doctrine://default'
                cur["dsn_type"] = _classify_dsn(_strip_yaml_quotes(tail))
                cur["retry_strategy"] = "default"
                transports.append({"name": cur_name, **cur})
                cur_name, cur = None, {}
            continue
        if indent > name_indent and cur_name is not None:
            if stripped.startswith("dsn:"):
                _, _, v = stripped.partition(":")
                v = _strip_inline_comment(v.strip())
                cur["dsn_type"] = _classify_dsn(_strip_yaml_quotes(v))
            elif stripped.startswith("retry_strategy:"):
                cur["retry_strategy"] = "configured"
            elif stripped.startswith("serializer:"):
                _, _, v = stripped.partition(":")
                v = _strip_inline_comment(v.strip())
                if v:
                    cur["serializer"] = _strip_yaml_quotes(v)
    if cur_name is not None:
        transports.append({"name": cur_name, **cur})
    return transports


def _classify_dsn(dsn: str) -> str:
    low = dsn.lower()
    if "%env" in low:
        return "env"
    if low.startswith("doctrine"):
        return "doctrine"
    if low.startswith("amqp") or low.startswith("rabbit"):
        return "amqp"
    if low.startswith("redis"):
        return "redis"
    if low.startswith("sync"):
        return "sync"
    if low.startswith("in-memory"):
        return "in_memory"
    return "other"


def collect_doctrine_listeners(
    project_root: Path,
    plugin_root: Path,
    warnings: list[str],
    *,
    exclude: Optional[tuple[str, ...]] = None,
) -> SectionPayload:
    """Doctrine listeners — class-level #[AsDoctrineListener] + service.yaml tags."""
    from recon import sandbox

    out, warn = sandbox.run_extractor(
        plugin_root, project_root, "class", project_root, exclude=exclude,
    )
    if warn:
        warnings.append(warn)
        return SectionPayload(status="unknown", reason=warn)
    items: list[dict] = []
    for cls in out.get("items", []):
        attrs = cls.get("attributes") or []
        rel = _to_relative(cls.get("file"), project_root)
        if rel is None or _is_excluded(rel, EXCLUDE_PATHS):
            continue
        for a in attrs:
            short = (a.get("name") or "").rsplit("\\", 1)[-1]
            if short != "AsDoctrineListener":
                continue
            event = _attr_named_arg(a, "event") or _attr_first_positional(a) or "unknown"
            items.append({
                "listener": cls.get("fqn") or "",
                "type": "doctrine",
                "events": [event],
                "file": rel,
                "line": cls.get("line") or 0,
            })
    return SectionPayload(status="ok", items=items)


# ---------------------------------------------------------------------------
# Wave 2-D (3.4.0): routes_authz_matrix.
# ---------------------------------------------------------------------------


# Doctrine ORM types that encrypt-at-rest the underlying value. Curated list
# from popular community bundles; extend as new types appear in the wild.
# Matched case-insensitively against the `type:` argument of #[ORM\Column].
ENCRYPTING_DOCTRINE_TYPES: frozenset[str] = frozenset({
    # ambta/doctrine-encrypt-bundle
    "encrypted_string",
    # doctrine/dbal-encrypted-field-types & similar
    "encryptedstring",
    "encrypted_text",
    "encrypted_json",
    "encryptedjson",
    "encryptedbinary",
    "encrypted_binary",
})


# Sensitive property-name regex (case-insensitive). Curated to catch tokens,
# secrets, passwords, API keys, signing keys without flagging normal email/
# username/birthdate fields. Anchored as a substring match: `oldRefreshToken`
# matches `refreshToken`.
_SENSITIVE_FIELD_RE = re.compile(
    r"accessToken|refreshToken|secretKey|apiKey|botToken|clientSecret|password"
    r"|privateKey|webhookSecret|sessionToken|csrfToken|signingKey|hmacKey"
    r"|\bpat\b|\bpwd\b",
    re.IGNORECASE,
)


# `denyAccessUnlessGranted(...)` — first positional arg is the attribute/role.
_DENY_ACCESS_RE = re.compile(
    r"->denyAccessUnlessGranted\(\s*['\"]([^'\"]+)['\"]"
)

# `#[IsGranted('ROLE_X')]` / `#[IsGranted("ROLE_X")]` /
# `#[IsGranted(attribute: 'ROLE_X')]` — capture role string. Optional FQN/
# namespace prefix tolerated. `#[Security("is_granted('X')")]` not handled here:
# the expression form is opaque without a parser; workers handle it from
# core authz_usage section.
_IS_GRANTED_ATTR_RE = re.compile(
    r"#\[\s*(?:[A-Za-z_\\][A-Za-z0-9_\\]*\\)?IsGranted\s*\(\s*"
    r"(?:attribute\s*:\s*)?['\"]([^'\"]+)['\"]"
)
# `#[Route(...)]` attribute presence — used to anchor the attribute block
# preceding a route handler. Matches both single- and multi-line forms.
_ROUTE_ATTR_RE = re.compile(r"#\[\s*(?:[A-Za-z_\\][A-Za-z0-9_\\]*\\)?Route\b")


def _build_routes_authz_matrix(
    project_root: Path,
    plugin_root: Path,
    *,
    exclude: Optional[tuple[str, ...]] = None,
    console_router_data: Optional[dict] = None,
) -> SectionPayload:
    """Per-route effective authz fingerprint.

    Sources merged in this order:
      1. Static parse via extract_php_metadata.php --kind=routes (always tried).
         Yields (route_name, path, methods, controller=Class::method, file, line).
      2. Class metadata (--kind=class) — to find #[IsGranted] on methods and
         denyAccessUnlessGranted() in method bodies.
      3. config/packages/security.yaml — `firewalls:` and `access_control:`
         rules. Each route's effective `firewall` and `matched_access_control`
         is the FIRST rule whose `path:` regex matches the route path.
      4. Optional `console_router_data` (output of debug:router as dict) —
         when supplied, authoritative for path/methods (overrides static parse
         on identifier collision).

    Notes:
      * `effective_middleware` is always [] for Symfony — middleware is a
        Laravel concept; we keep the empty list for cross-stack shape parity.
      * `csrf_protection` is currently `unknown` for non-form controllers
        (Symfony has no per-route CSRF declaration; protection comes via Form
        types). Worker can refine via Form linkage.
      * `authz_evidence` is an array (possibly empty) — empty array means no
        protection found at any layer (drives high-severity findings).
    """
    from recon import sandbox

    sources: list[str] = []

    # 1. Static routes from extractor.
    routes_data, route_warn = sandbox.run_extractor(
        plugin_root, project_root, "routes", project_root, exclude=exclude,
    )
    static_routes: list[dict] = []
    if route_warn or routes_data is None:
        # Without the extractor we can't enumerate routes — return unknown.
        return SectionPayload(
            status="unknown",
            reason=route_warn or "extractor returned no data",
            source_files=[],
        )
    sources.append("extract_php_metadata.php:routes")
    for r in routes_data.get("items", []):
        rel = _to_relative(r.get("file"), project_root)
        if rel is None or _is_excluded(rel, EXCLUDE_PATHS):
            continue
        static_routes.append({
            "route_name": r.get("route_name") or "",
            "file": rel,
            "line": r.get("line") or 0,
            "methods": list(r.get("methods") or []),
            "path": r.get("path") or "",
            "controller": r.get("controller") or "",
        })

    # 2. Per-route authz, derived from each route's file/line via lightweight
    #    line scanning. The PHP extractor's `--kind=class` does not currently
    #    surface methods/attributes (only class-level metadata), so we
    #    re-scan controller files directly: for each route item we look
    #    at the attribute block immediately preceding the method line for
    #    `#[IsGranted(...)]`, and we collect `denyAccessUnlessGranted(...)`
    #    calls per-file (file-scoped, not method-scoped — see note below).
    method_authz: dict[tuple[str, int], list[dict]] = {}  # (file, route_line) -> evidence
    deny_calls_by_file: dict[str, list[tuple[int, str]]] = {}
    file_text_cache: dict[str, list[str]] = {}

    def _file_lines(file_rel: str) -> Optional[list[str]]:
        if file_rel in file_text_cache:
            return file_text_cache[file_rel]
        text = _read_text_safe(project_root / file_rel)
        if text is None:
            return None
        lines = text.splitlines()
        file_text_cache[file_rel] = lines
        return lines

    # Window size: how many lines back from the route declaration we scan
    # for IsGranted attributes. 20 covers typical multi-attribute method
    # heads; bigger window risks picking up attributes from the previous
    # method.
    ATTR_LOOKBACK = 20

    for r in static_routes:
        file_rel = r["file"]
        route_line = r["line"]
        lines = _file_lines(file_rel)
        if lines is None:
            continue
        start = max(0, route_line - ATTR_LOOKBACK - 1)
        # Cut at the previous `}` (end of previous method body) to keep the
        # scan inside the current method head.
        prev_end = -1
        for idx in range(route_line - 2, start - 1, -1):
            if idx < 0 or idx >= len(lines):
                continue
            if lines[idx].strip() == "}":
                prev_end = idx
                break
        attr_block = "\n".join(lines[max(start, prev_end + 1):route_line])
        for m in _IS_GRANTED_ATTR_RE.finditer(attr_block):
            role = m.group(1)
            method_authz.setdefault((file_rel, route_line), []).append({
                "source": "route_attribute",
                "file": file_rel,
                "line": route_line,
                "roles": [role],
                # `IsGranted` raises AccessDeniedException on failure → hard_deny.
                "strength": "hard_deny",
            })

    # denyAccessUnlessGranted across each controller file — file-scoped, not
    # method-scoped. We can't pinpoint to a method without parsing bodies,
    # so any deny call in a controller file is attached to every route in
    # that same file. This over-attaches in multi-action controllers but
    # never under-reports — workers reconcile during deep analysis.
    seen_files: set[str] = {r["file"] for r in static_routes}
    for file_rel in sorted(seen_files):
        lines = _file_lines(file_rel)
        if lines is None:
            continue
        calls: list[tuple[int, str]] = []
        for lineno, line in enumerate(lines, start=1):
            m = _DENY_ACCESS_RE.search(line)
            if m:
                calls.append((lineno, m.group(1)))
        if calls:
            deny_calls_by_file[file_rel] = calls

    # 3. security.yaml: firewalls + access_control.
    sec_yaml = project_root / "config" / "packages" / "security.yaml"
    firewalls: list[dict[str, str]] = []
    access_control: list[dict[str, str]] = []
    if sec_yaml.is_file():
        text = _read_text_safe(sec_yaml) or ""
        if text:
            firewalls = _parse_firewalls(text)
            access_control = _parse_access_control(text)
            sources.append("config/packages/security.yaml")

    def _match_firewall(route_path: str) -> Optional[str]:
        for fw in firewalls:
            pattern = fw.get("pattern")
            name = fw.get("name")
            if not pattern or not name:
                continue
            try:
                if re.search(pattern, route_path):
                    return name
            except re.error:
                continue
        return None

    def _match_access_control(route_path: str) -> Optional[dict[str, str]]:
        for rule in access_control:
            pattern = rule.get("path")
            if not pattern:
                continue
            try:
                if re.search(pattern, route_path):
                    return rule
            except re.error:
                continue
        return None

    # 4. Optional console_router_data — overlay on identifier match.
    console_overlay: dict[str, dict] = {}
    if isinstance(console_router_data, dict):
        for name, info in console_router_data.items():
            if not isinstance(info, dict):
                continue
            defaults = info.get("defaults") or {}
            controller = (
                defaults.get("_controller") if isinstance(defaults, dict) else None
            ) or info.get("controller") or ""
            method_str = info.get("method") or info.get("methods") or ""
            methods: list[str]
            if isinstance(method_str, list):
                methods = [str(x) for x in method_str]
            elif isinstance(method_str, str):
                methods = [m for m in method_str.split("|") if m]
            else:
                methods = []
            console_overlay[name] = {
                "path": info.get("path") or "",
                "methods": methods,
                "controller": controller,
            }
        if console_overlay:
            sources.append("console:debug_router")

    # Build per-route items.
    items: list[dict] = []
    src_files: set[str] = set()
    if sec_yaml.is_file():
        try:
            src_files.add(sec_yaml.relative_to(project_root).as_posix())
        except ValueError:
            pass

    for r in static_routes:
        route_name = r["route_name"]
        path = r["path"]
        methods = r["methods"]
        controller = r["controller"]
        # console overlay (if route_name matches).
        if route_name and route_name in console_overlay:
            ov = console_overlay[route_name]
            path = ov["path"] or path
            methods = ov["methods"] or methods
            controller = ov["controller"] or controller

        ac_rule = _match_access_control(path) if path else None
        fw_name = _match_firewall(path) if path else None

        evidence: list[dict] = []
        # Per-method evidence keyed by (file, line) of the route.
        ev_key = (r["file"], r["line"])
        if ev_key in method_authz:
            evidence.extend(method_authz[ev_key])
        # Body-level deny calls — attached to every route in the file (see note above).
        deny_for_file = deny_calls_by_file.get(r["file"])
        if deny_for_file:
            for lineno, role in deny_for_file:
                evidence.append({
                    "source": "method_call",
                    "file": r["file"],
                    "line": lineno,
                    "roles": [role],
                    "strength": "hard_deny",
                })
        # access_control rule evidence.
        if ac_rule:
            roles_raw = ac_rule.get("roles", "")
            roles = (
                [s.strip() for s in roles_raw.strip("[]").split(",") if s.strip()]
                if roles_raw else []
            )
            evidence.append({
                "source": "access_control",
                "file": "config/packages/security.yaml",
                "line": 0,  # access_control rules don't carry line info from our parser
                "roles": roles,
                # access_control denies the request when role check fails → hard_deny.
                "strength": "hard_deny",
            })

        src_files.add(r["file"])

        items.append({
            "route_name": route_name,
            "file": r["file"],
            "line": r["line"],
            "methods": methods,
            "path": path,
            # Symfony has no middleware concept — empty list for shape parity.
            "effective_middleware": [],
            "matched_access_control": (ac_rule.get("path") if ac_rule else None),
            "firewall": fw_name,
            "csrf_protection": "unknown",
            "authz_evidence": evidence,
        })

    if not items:
        return SectionPayload(
            status="none",
            reason="no #[Route]-annotated controller methods found",
            source_files=sorted(src_files),
        )
    return SectionPayload(
        status="ok",
        items=items,
        source_files=sorted(src_files),
    )


# ---------------------------------------------------------------------------
# Wave 2-D (3.4.0): sensitive_columns.
# ---------------------------------------------------------------------------


# Property declaration on a class member after one or more attribute lines.
# Captures the property name; we anchor on `private|protected|public` so we
# don't pick up local variables or method args.
_PROPERTY_RE = re.compile(
    r"^\s*(?:public|protected|private)\s+(?:readonly\s+)?(?:[\w\\?|]+\s+)?\$([A-Za-z_][A-Za-z0-9_]*)\s*"
)
# Single #[ORM\Column(...)] attribute line — capture the inner argument list.
_ORM_COLUMN_RE = re.compile(r"#\[\s*ORM\\Column\s*\(([^\]]*?)\)\s*\]")
# Standalone #[Encrypted] attribute on the same property.
_ENCRYPTED_ATTR_RE = re.compile(r"#\[\s*Encrypted(?:\([^\]]*\))?\s*\]")
# `type: 'foo'` or `type: "foo"` (or `type:foo`) — first occurrence inside Column args.
_COLUMN_TYPE_RE = re.compile(r"\btype\s*:\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")


def _scan_entity_file(file_rel: str, text: str) -> list[dict]:
    """Yield sensitive-column items from one Entity PHP file.

    We walk the file line-by-line, accumulate attribute lines until we hit a
    property declaration, then decide whether to emit. This is robust against
    multi-line `#[ORM\\Column(\n    type: 'string',\n    nullable: false,\n)]`
    constructs (joined into a single buffered string).
    """
    items: list[dict] = []

    # Find FQN of the class in the file (first non-abstract class).
    namespace_match = re.search(r"^\s*namespace\s+([A-Za-z_\\][A-Za-z0-9_\\]*)\s*;",
                                text, re.MULTILINE)
    namespace = namespace_match.group(1) if namespace_match else ""
    class_match = re.search(
        r"^\s*(?:final\s+|abstract\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)",
        text, re.MULTILINE,
    )
    if not class_match:
        return items
    class_short = class_match.group(1)
    entity_class = f"{namespace}\\{class_short}" if namespace else class_short

    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        # Check if this line starts an attribute block (#[...).
        if "#[" in line:
            # Buffer attribute lines (may span multiple physical lines).
            buf = line
            buf_start_lineno = i + 1
            j = i
            # Continue accumulating until balanced brackets — count `[` vs `]`.
            open_count = buf.count("[") - buf.count("]")
            while open_count > 0 and j + 1 < n:
                j += 1
                buf += "\n" + lines[j]
                open_count = buf.count("[") - buf.count("]")
            # Look ahead for more attributes / property decl on subsequent lines.
            # Collect contiguous attribute block + the declaring line.
            block = buf
            block_start = i + 1
            k = j + 1
            decl_lineno: Optional[int] = None
            decl_line: Optional[str] = None
            while k < n:
                cur = lines[k]
                stripped = cur.strip()
                if not stripped:
                    k += 1
                    continue
                if stripped.startswith("#["):
                    # Another attribute — buffer it too (multi-line aware).
                    sub_buf = cur
                    open_count = sub_buf.count("[") - sub_buf.count("]")
                    sub_end = k
                    while open_count > 0 and sub_end + 1 < n:
                        sub_end += 1
                        sub_buf += "\n" + lines[sub_end]
                        open_count = sub_buf.count("[") - sub_buf.count("]")
                    block += "\n" + sub_buf
                    k = sub_end + 1
                    continue
                # Non-attribute line — must be the property declaration (or stop).
                m = _PROPERTY_RE.match(cur)
                if m:
                    decl_lineno = k + 1
                    decl_line = cur
                    field_name = m.group(1)
                    # Now decide whether this property is sensitive.
                    name_match = _SENSITIVE_FIELD_RE.search(field_name)
                    column_match = _ORM_COLUMN_RE.search(block)
                    if name_match and column_match:
                        col_args = column_match.group(1)
                        type_match = _COLUMN_TYPE_RE.search(col_args)
                        column_type = (
                            type_match.group(1) if type_match else "string"
                        )
                        column_type_lower = column_type.lower()
                        has_encrypted_attr = bool(
                            _ENCRYPTED_ATTR_RE.search(block)
                        )
                        encryption_evidence: list[dict] = []
                        encryption_status: str
                        if column_type_lower in ENCRYPTING_DOCTRINE_TYPES:
                            encryption_status = "encrypted"
                            encryption_evidence.append({
                                "kind": "doctrine_type_whitelist",
                                "identifier": column_type,
                                "file": file_rel,
                                "line": block_start,
                            })
                        elif has_encrypted_attr:
                            encryption_status = "encrypted"
                            encryption_evidence.append({
                                "kind": "column_attribute",
                                "identifier": "Encrypted",
                                "file": file_rel,
                                "line": block_start,
                            })
                        elif column_type_lower in {
                            "string", "text", "json", "simple_array", "binary", "blob",
                        }:
                            encryption_status = "plaintext"
                        else:
                            encryption_status = "unknown"
                        items.append({
                            "entity_class": entity_class,
                            "file": file_rel,
                            "field_name": field_name,
                            "column_type": column_type,
                            "name_pattern_matched": _SENSITIVE_FIELD_RE.pattern,
                            "encryption_status": encryption_status,
                            "encryption_evidence": encryption_evidence,
                        })
                # Whether or not we emitted, advance past the decl line.
                i = k + 1
                break
            else:
                # Ran off the end without finding decl line.
                i = k
                continue
            if decl_lineno is None:
                # No property decl found — skip block.
                i = k
            continue
        i += 1
    return items


def _list_entity_files(project_root: Path) -> list[tuple[str, Path]]:
    """Find PHP files under any Entity/ folder inside src/ (or app/)."""
    out: list[tuple[str, Path]] = []
    project_resolved = project_root.resolve()
    for root_name in PHP_SCAN_ROOTS:
        root = project_root / root_name
        if not root.is_dir():
            continue
        for f in root.rglob("*.php"):
            if not f.is_file():
                continue
            try:
                resolved = f.resolve()
                rel = resolved.relative_to(project_resolved).as_posix()
            except (OSError, ValueError, RuntimeError):
                continue
            if _is_excluded(rel, EXCLUDE_PATHS):
                continue
            # Match either /Entity/<file>.php or anywhere under */Entity/*.
            if "/Entity/" not in ("/" + rel) and not rel.startswith(f"{root_name}/Entity/"):
                continue
            out.append((rel, resolved))
    out.sort(key=lambda pair: pair[0])
    return out


def _build_sensitive_columns(project_root: Path) -> SectionPayload:
    """Doctrine entity columns whose property name matches a sensitive regex.

    Pure static parse — no PHP extractor required (we use line-based regex
    directly because the existing extractor doesn't surface property-level
    #[ORM\\Column] attributes today).
    """
    files = _list_entity_files(project_root)
    if not files:
        return SectionPayload(
            status="none",
            reason="no Entity/ directory found under src/ or app/",
            source_files=[],
        )

    items: list[dict] = []
    src_files: set[str] = set()
    for rel, abs_path in files:
        text = _read_text_safe(abs_path)
        if text is None:
            continue
        new = _scan_entity_file(rel, text)
        if new:
            items.extend(new)
            src_files.add(rel)

    if not items:
        return SectionPayload(
            status="none",
            reason="no Doctrine columns matched sensitive-field regex",
            source_files=sorted(src_files) or [f for f, _ in files],
        )
    return SectionPayload(
        status="ok",
        items=items,
        source_files=sorted(src_files),
    )


# ---------------------------------------------------------------------------
# Top-level build_inventory.
# ---------------------------------------------------------------------------


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
    console_runner: "object" = None,
    exclude: Optional[tuple[str, ...]] = None,
) -> InventoryResult:
    """Full Symfony inventory (rev 3.7).

    Required kwargs in real runs:
      plugin_root — to invoke extract_php_metadata.php (needed for nearly
                    every section that scans PHP).
      console_runner — a `sandbox.ConsoleRunner` deciding WHERE/whether console
                    enrichment runs (host / container / custom / disabled). The
                    recon utility builds it via `decide_console_runner` from an
                    environment probe + `--console-cmd` / `--no-console`. When
                    None (direct callers / back-compat) it is derived from
                    `no_console`: disabled when True, else a host runner using
                    CONSOLE_ENTRYPOINT.
      no_console — back-compat boolean kept for direct callers; superseded by
                    `console_runner` when the latter is provided.
      exclude    — extra path prefixes (relative to project_root) appended
                   to sandbox.DEFAULT_EXCLUDE for the PHP extractor. Use it
                   to skip project-specific directories (legacy/, generated/,
                   third-party mirrors) sourced from CLAUDE.md.

    When `plugin_root` is None we return an empty-but-valid skeleton
    (all sections `unknown` with reason). This keeps unit tests that
    don't have the extractor available green; real CLI always supplies it.
    """
    sources_used: list[str] = []
    warnings: list[str] = []
    errors: list[str] = []
    missing_sections: list[str] = []

    if plugin_root is None:
        return _empty_skeleton(
            "plugin_root not provided; recipe requires extractor",
            project_root=project_root,
        )

    if console_runner is None:
        # Direct callers / back-compat: derive a runner from `no_console`.
        from recon import sandbox
        console_runner = (
            sandbox.disabled_runner("console_disabled_by_flag", project_root)
            if no_console
            else sandbox.host_runner(shlex.join(CONSOLE_ENTRYPOINT), project_root)
        )

    files = _list_php_files(project_root)

    # 1. attack_surface.
    # `console_disabled_by_flag` is appended by the utility (cmd_inventory),
    # not the recipe, so we don't emit it here to avoid duplication.
    attack_items = collect_attack_surface(
        project_root, plugin_root, diff_files, sources_used, warnings, console_runner,
        exclude=exclude,
    )

    # 2. data_access.
    data_items = collect_data_access(
        project_root, plugin_root, diff_files, sources_used, warnings,
        exclude=exclude,
    )

    # 3. auth_layer + firewalls.
    auth_payload, firewalls_payload = collect_auth_layer_and_firewalls(project_root, warnings)

    # 4. authz_usage.
    authz_items = collect_authz_usage(files, project_root, diff_files)

    # 5. output_renderers.
    renderers_items = collect_output_renderers(project_root, files, diff_files)

    # 6. serialization / file_operations / http_clients.
    serialization_items = collect_grep_section(files, _SERIALIZATION_RE, "serialization", diff_files)
    file_ops_items = collect_grep_section(files, _FILE_OPS_RE, "file_op", diff_files)
    http_client_items = collect_grep_section(files, _HTTP_CLIENT_RE, "http_client", diff_files)

    # 7. secrets.
    secrets_payload = collect_secrets(project_root, files, warnings)

    # 8. fintech_markers + frontend_assets.
    fintech_items = collect_fintech_markers(project_root, files, diff_files)
    frontend_items = collect_frontend_assets(project_root, diff_files)

    # 9. recon_bags.stack.symfony.*.
    voters_payload = collect_voters(project_root, plugin_root, warnings, exclude=exclude)
    forms_payload = collect_forms(project_root, plugin_root, warnings, exclude=exclude)
    sg_payload = collect_serializer_groups(project_root, plugin_root, warnings, exclude=exclude)
    twig_payload = collect_twig_overrides(project_root)
    trusted_config_payload = collect_trusted_config(project_root)
    msg_payload = collect_messenger_transports(project_root)
    listeners_payload = collect_doctrine_listeners(project_root, plugin_root, warnings, exclude=exclude)
    easyadmin_crud_payload = collect_easyadmin_crud_controllers(
        project_root, plugin_root, warnings, exclude=exclude,
    )
    sonata_admin_payload = collect_sonata_admin_classes(
        project_root, plugin_root, warnings, exclude=exclude,
    )
    api_platform_resources_payload = collect_api_platform_resources(
        project_root, plugin_root, warnings, exclude=exclude,
    )

    core: dict[str, SectionPayload] = {
        "attack_surface": SectionPayload(status="ok", items=attack_items),
        "data_access": SectionPayload(status="ok", items=data_items),
        "auth_layer": auth_payload,
        "authz_usage": SectionPayload(status="ok", items=authz_items),
        "output_renderers": SectionPayload(status="ok", items=renderers_items),
        "serialization": SectionPayload(status="ok", items=serialization_items),
        "file_operations": SectionPayload(status="ok", items=file_ops_items),
        "http_clients": SectionPayload(status="ok", items=http_client_items),
        "secrets": secrets_payload,
        "fintech_markers": SectionPayload(status="ok", items=fintech_items),
        "frontend_assets": SectionPayload(status="ok", items=frontend_items),
    }

    admin_authz_payload = compute_admin_authz_coverage(
        voters_payload, easyadmin_crud_payload, sonata_admin_payload,
    )

    # Wave 2-D (3.4.0) — per-route authz matrix + sensitive Doctrine columns.
    # `console_router_data=None` — current pipeline collapses console output
    # inline in `_enrich_via_console`; threading the dict through is out of
    # scope for Wave 2-D (Wave 2.5 sync-step may rewire this once console
    # output becomes a first-class object). Static parse alone is sufficient
    # for #[Route] attributes (extractor's --kind=routes covers them).
    routes_authz_payload = _build_routes_authz_matrix(
        project_root, plugin_root, exclude=exclude, console_router_data=None,
    )
    sensitive_columns_payload = _build_sensitive_columns(project_root)

    stack_symfony: dict[str, SectionPayload] = {
        "voters": voters_payload,
        "forms": forms_payload,
        "serializer_groups": sg_payload,
        "twig_overrides": twig_payload,
        "doctrine_listeners": listeners_payload,
        "firewalls": firewalls_payload,
        "trusted_config": trusted_config_payload,
        "messenger_transports": msg_payload,
        "admin_authz_coverage": admin_authz_payload,
        "routes_authz_matrix": routes_authz_payload,
        "sensitive_columns": sensitive_columns_payload,
    }
    addon_easyadmin: dict[str, SectionPayload] = {
        "crud_controllers": easyadmin_crud_payload,
    }
    addon_sonata: dict[str, SectionPayload] = {
        "admin_classes": sonata_admin_payload,
    }
    addon_api_platform: dict[str, SectionPayload] = {
        "resources": api_platform_resources_payload,
    }

    # Optional graphql_layer — present only when a known PHP GraphQL library
    # is in composer.json (api-platform/core, webonyx/graphql-php).
    gql = detect_graphql(project_root)
    if gql is not None:
        stack_symfony["graphql_layer"] = SectionPayload(
            status="ok",
            data=gql,
            source_files=["composer.json"],
        )

    recon_bags: dict[str, dict[str, dict[str, SectionPayload]]] = {
        "stack": {"symfony": stack_symfony},
        "addon": {
            "easyadmin": addon_easyadmin,
            "sonata": addon_sonata,
            "api-platform": addon_api_platform,
        },
    }

    # Addon detection (composer-level) feeds `frontmatter.stack.addons`. We
    # use a positive composer-dep probe (cheaper than walking the bag payload):
    # an addon is "present" iff its package is in require/require-dev.
    # `status: none` from the heavy collector is NOT a signal — a project can
    # legitimately depend on EasyAdmin and define zero CRUD controllers yet,
    # and we still want addon-layer checklists loaded for follow-up review.
    detected_addons: list[str] = []
    if detect_easyadmin(project_root):
        detected_addons.append("easyadmin")
    if detect_sonata(project_root):
        detected_addons.append("sonata")
    if detect_api_platform(project_root):
        detected_addons.append("api-platform")
    detected_addons.sort()

    # Integration detection (Stage 4): vendor-neutral cross-stack capabilities.
    # Orthogonal to addons — `jwt-generic` and `oauth-oidc` apply even on a
    # generic-PHP stack. Cheap composer + env + config probes (no source walk).
    detected_integrations: list[str] = []
    if detect_jwt_generic(project_root):
        detected_integrations.append("jwt-generic")
    if detect_oauth_oidc(project_root):
        detected_integrations.append("oauth-oidc")
    # Provider integrations (Stage 5) refine the generic jwt-generic /
    # oauth-oidc layers; multiple providers can co-exist (rare but legal).
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
    # Stage 7 integrations: payments / secret stores / SAML federation /
    # WebAuthn. These do NOT imply the generic jwt-generic / oauth-oidc
    # layers — they have their own threat surfaces (HMAC webhook sigs,
    # XML-DSig, public-key auth, Vault tokens) orthogonal to the JWT axis.
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
    # A provider integration always IMPLIES the generic layers it refines
    # (Auth0 IS JWT+OAuth, Cognito IS JWT+OAuth, …). Force-include so the
    # worker resolver always loads `integrations/jwt-generic/` and
    # `integrations/oauth-oidc/` alongside the provider-specific files even
    # when only the provider-narrow signals fired (e.g. composer has
    # `auth0/auth0-php` but no generic JWT library). See
    # `_shared.PROVIDER_IMPLIES_INTEGRATIONS`.
    detected_integrations = expand_provider_implications(detected_integrations)
    detected_integrations = sorted(set(detected_integrations))

    # Compute overall status — flatten payloads across kinds.
    all_bag_payloads: list[SectionPayload] = []
    for names in recon_bags.values():
        for bag in names.values():
            all_bag_payloads.extend(bag.values())
    any_unknown = any(p.status == "unknown" for p in core.values()) or any(
        p.status == "unknown" for p in all_bag_payloads
    )
    if any_unknown or warnings:
        status = "partial"
    else:
        status = "ok"

    for sid, payload in core.items():
        if payload.status == "unknown":
            missing_sections.append(sid)

    return InventoryResult(
        status=status,
        core=core,
        recon_bags=recon_bags,
        sources_used=sources_used,
        warnings=warnings,
        errors=errors,
        missing_sections=missing_sections,
        detected_addons=detected_addons,
        detected_integrations=detected_integrations,
    )


def _empty_skeleton(
    reason: str, project_root: Optional[Path] = None,
) -> InventoryResult:
    """Fall-back: emit `unknown` for every section so validator produces a
    medium-confidence CONTEXT.md instead of failing the schema.

    When `project_root` is provided we still run the cheap composer-based
    addon/integration probes (they don't need the PHP extractor), so the
    degraded path still produces accurate `detected_addons` /
    `detected_integrations`. When `project_root` is None we leave both lists
    empty (legacy behavior).
    """
    core: dict[str, SectionPayload] = {}
    scalar_core = {"auth_layer", "secrets"}
    for sid in CORE_SECTION_IDS:
        is_scalar = sid in scalar_core
        core[sid] = SectionPayload(
            status="unknown",
            reason=reason,
            source_files=[] if is_scalar else None,
        )
    fs: dict[str, dict[str, dict[str, SectionPayload]]] = {}
    for kind, names in RECON_BAGS_SCHEMA.items():
        per_kind: dict[str, dict[str, SectionPayload]] = {}
        for name, bag_keys in names.items():
            per_name: dict[str, SectionPayload] = {}
            for key, spec in bag_keys.items():
                is_scalar = spec.shape == "scalar"
                per_name[key] = SectionPayload(
                    status="unknown",
                    reason=reason,
                    source_files=[] if is_scalar else None,
                )
            per_kind[name] = per_name
        fs[kind] = per_kind

    detected_addons: list[str] = []
    detected_integrations: list[str] = []
    if project_root is not None:
        # Composer-based probes work without the PHP extractor.
        if detect_easyadmin(project_root):
            detected_addons.append("easyadmin")
        if detect_sonata(project_root):
            detected_addons.append("sonata")
        if detect_api_platform(project_root):
            detected_addons.append("api-platform")
        detected_addons.sort()
        if detect_jwt_generic(project_root):
            detected_integrations.append("jwt-generic")
        if detect_oauth_oidc(project_root):
            detected_integrations.append("oauth-oidc")
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
        # See note in `build_inventory`: provider integrations always imply
        # their generic layers (jwt-generic, oauth-oidc).
        detected_integrations = expand_provider_implications(detected_integrations)
        detected_integrations = sorted(set(detected_integrations))

    return InventoryResult(
        status="partial",
        core=core,
        recon_bags=fs,
        sources_used=[],
        warnings=[reason],
        errors=[],
        missing_sections=list(CORE_SECTION_IDS),
        detected_addons=detected_addons,
        detected_integrations=detected_integrations,
    )
