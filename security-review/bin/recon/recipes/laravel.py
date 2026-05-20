"""Laravel recipe — schema v2 inventory builder.

Static-first architecture (mirrors symfony recipe):
- Primary source for class metadata (controllers, jobs, listeners, policies,
  providers, form requests, models, console commands) is `extract_php_metadata.php`
  (token-based, no PHP execution).
- Routes are parsed from `routes/{web,api,channels,console}.php` via regex
  (Laravel does not expose route metadata as PHP attributes — Route::*
  facade calls are the canonical surface).
- Console enrichment (`php artisan list --format=json`) is OPTIONAL, merged
  on top of the static set. Disabled with `no_console=True`. On hostile or
  read-only repositories console must stay off — it boots Laravel's HTTP
  kernel container = arbitrary code execution.

build_inventory pipeline:
1. attack_surface  — http routes (web/api), CLI commands, queue jobs, listeners.
2. data_access     — Eloquent models from app/Models/ + repositories from app/Repositories/.
3. auth_layer      — abstract: kind/provider from config/auth.php.
4. authz_usage     — Gate::*, $this->authorize(), $user->can(), middleware can: call sites.
5. output_renderers — Blade templates + per-controller view() render calls.
6. serialization / file_operations / http_clients — grep over app/ with Laravel-aware
   patterns (Crypt::decrypt, Storage facade, Http facade, Guzzle, curl_init).
7. secrets         — bounded credential-prefix scan over app/ + config/*.php; .env in
   source_files. Status remains pending_enrichment so worker classifies candidates.
8. fintech_markers — composer-dep substring match + bcmath/Stripe/PayPal grep markers.
9. frontend_assets — vite/webpack/Inertia detection.
10. framework_specific.laravel.*: policies, service_providers, middleware_groups,
    form_requests, graphql_layer (when GraphQL library detected).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from recon import sandbox
from recon.types import (
    InventoryResult,
    SectionPayload,
    SectionSpec,
    SanityProbe,
    StackMatch,
)
from recon.graphql_detect import detect_graphql


RECIPE_NAME = "laravel"
LANGUAGE = "php"


# ---------------------------------------------------------------------------
# Schema bag — what `framework_specific.laravel.*` keys may contain.
# ---------------------------------------------------------------------------

FRAMEWORK_SPECIFIC_SCHEMA: dict[str, SectionSpec] = {
    "policies": SectionSpec(
        shape="list",
        item_keys=frozenset({"class", "file", "model", "line"}),
    ),
    "service_providers": SectionSpec(
        shape="list",
        item_keys=frozenset({"class", "file", "line", "deferred"}),
    ),
    "middleware_groups": SectionSpec(
        shape="scalar",
        data_keys=frozenset({"groups", "global", "route"}),
    ),
    "form_requests": SectionSpec(
        shape="list",
        item_keys=frozenset({"class", "file", "line", "authorize"}),
    ),
    "graphql_layer": SectionSpec(
        shape="scalar",
        data_keys=frozenset({"library_name", "schema_files", "resolvers_dir"}),
        required=False,
    ),
    # 3.4.0 Wave 2-E: routes/authz cross-product matrix.
    "routes_authz_matrix": SectionSpec(
        shape="list",
        item_keys=frozenset({
            "route_name", "file", "line", "methods", "path",
            "effective_middleware", "matched_access_control", "firewall",
            "csrf_protection", "authz_evidence",
        }),
        required=False,
    ),
    # 3.4.0 Wave 2-E: sensitive (token/secret/credential) Eloquent columns.
    "sensitive_columns": SectionSpec(
        shape="list",
        item_keys=frozenset({
            "entity_class", "file", "field_name", "column_type",
            "name_pattern_matched", "encryption_status", "encryption_evidence",
        }),
        required=False,
    ),
    # 3.4.0 Wave 2-E: long-running runtime detection (Octane + server flavor).
    "runtime": SectionSpec(
        shape="scalar",
        data_keys=frozenset({"octane", "octane_server"}),
        required=False,
    ),
}


# Default vendor/test exclusions for filesystem scans.
EXCLUDE_PATHS: tuple[str, ...] = (
    "vendor/", "node_modules/", "storage/", "bootstrap/cache/",
    "tests/", "test/", "Tests/", "Test/", "*.min.js",
)


# Source-tree roots holding user-authored PHP code. Also `database/migrations`
# is sometimes scanned by checklists, but we don't surface migrations as
# attack surface — it's schema-only.
PHP_SCAN_ROOTS: tuple[str, ...] = ("app",)


# ---------------------------------------------------------------------------
# Detect: weighted signals.
# ---------------------------------------------------------------------------

SIGNAL_WEIGHTS = {
    "framework_dep":   0.4,   # composer.json: laravel/framework in require
    "artisan":         0.2,   # artisan binary present
    "config_app_php":  0.2,   # config/app.php exists
    "app_models_dir":  0.2,   # app/Models/ directory
}


def detect(project_root: Path) -> Optional[StackMatch]:
    """Score Laravel likelihood. Returns StackMatch or None.

    Threshold for use as stack recipe: ≥ 0.7 (enforced by recipes registry).
    Below threshold, registry falls back to generic_php.
    """
    score = 0.0
    evidence: list[str] = []
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
                if "laravel/framework" in deps:
                    score += SIGNAL_WEIGHTS["framework_dep"]
                    evidence.append(f"composer.json: {section}.laravel/framework")
                    raw_ver = deps["laravel/framework"]
                    if isinstance(raw_ver, str):
                        version = raw_ver
                    break

    if (project_root / "artisan").is_file():
        score += SIGNAL_WEIGHTS["artisan"]
        evidence.append("artisan")

    if (project_root / "config" / "app.php").is_file():
        score += SIGNAL_WEIGHTS["config_app_php"]
        evidence.append("config/app.php")

    if (project_root / "app" / "Models").is_dir():
        score += SIGNAL_WEIGHTS["app_models_dir"]
        evidence.append("app/Models/")

    if score == 0.0:
        return None
    return StackMatch(name="laravel", version=version, confidence=score, evidence=evidence)


# ---------------------------------------------------------------------------
# Sanity probes — used by validate_context.py --sanity.
# ---------------------------------------------------------------------------


def sanity_probes() -> list[SanityProbe]:
    return [
        SanityProbe(
            section_path="attack_surface",
            glob_patterns=["app/Http/Controllers/**/*.php"],
            label="HTTP controllers",
            kind_filter="http_route",
        ),
        SanityProbe(
            section_path="attack_surface",
            glob_patterns=["app/Console/Commands/**/*.php"],
            label="Console commands",
            kind_filter="cli_command",
        ),
        SanityProbe(
            section_path="data_access",
            glob_patterns=["app/Models/**/*.php"],
            label="Eloquent models",
        ),
        SanityProbe(
            section_path="framework_specific.laravel.policies",
            glob_patterns=["app/Policies/**/*.php"],
            label="Policies",
        ),
        SanityProbe(
            section_path="framework_specific.laravel.service_providers",
            glob_patterns=["app/Providers/**/*.php"],
            label="Service providers",
        ),
        SanityProbe(
            section_path="framework_specific.laravel.form_requests",
            glob_patterns=["app/Http/Requests/**/*.php"],
            label="Form requests",
        ),
        # 3.4.0 Wave 2-E: routes/authz matrix sourced from controllers + routes.
        SanityProbe(
            section_path="framework_specific.laravel.routes_authz_matrix",
            glob_patterns=["app/Http/Controllers/**/*.php", "routes/*.php"],
            label="laravel.routes_authz_matrix",
        ),
        # 3.4.0 Wave 2-E: sensitive columns sourced from models + migrations.
        SanityProbe(
            section_path="framework_specific.laravel.sensitive_columns",
            glob_patterns=[
                "app/Models/**/*.php",
                "app/**/Models/**/*.php",
                "database/migrations/**/*.php",
            ],
            label="laravel.sensitive_columns",
        ),
        # runtime — composer.json is guaranteed; no sanity probe needed.
    ]


# ---------------------------------------------------------------------------
# Helpers — file scanning, PHP metadata extraction, route parsing.
# ---------------------------------------------------------------------------


CORE_SECTION_IDS = (
    "attack_surface", "data_access", "auth_layer", "authz_usage",
    "output_renderers", "serialization", "file_operations", "http_clients",
    "secrets", "fintech_markers", "frontend_assets",
)


# Maximum file size for grep-style scanning (avoids OOM on autogenerated giants).
GREP_MAX_BYTES = 1_000_000  # 1 MB


def _read_text_safe(path: Path, max_bytes: int = GREP_MAX_BYTES) -> Optional[str]:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def _is_excluded(rel_path: str, exclude: tuple[str, ...]) -> bool:
    """Match `rel_path` against EXCLUDE_PATHS (mirrors symfony recipe)."""
    import fnmatch
    rel_with_slash = "/" + rel_path
    for ex in exclude:
        if "*" in ex:
            if fnmatch.fnmatch(rel_path.rsplit("/", 1)[-1], ex):
                return True
            continue
        if ex.endswith("/"):
            if rel_path.startswith(ex) or ("/" + ex) in rel_with_slash:
                return True
        else:
            if rel_path == ex or rel_path.startswith(ex + "/") or ("/" + ex + "/") in rel_with_slash:
                return True
    return False


def _list_php_files(project_root: Path) -> list[tuple[str, Path]]:
    """Return (rel_path, abs_path) pairs for every *.php in PHP_SCAN_ROOTS,
    skipping anything caught by EXCLUDE_PATHS. Sorted for determinism.

    Symlink containment: drop anything whose resolved path is not under
    the resolved project root.
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
                rel = resolved.relative_to(project_resolved).as_posix()
            except ValueError:
                continue
            if _is_excluded(rel, EXCLUDE_PATHS):
                continue
            out.append((rel, resolved))
    out.sort(key=lambda pair: pair[0])
    return out


def _touched(file_rel: str, diff_files: Optional[set[str]]) -> bool:
    if diff_files is None:
        return False
    return file_rel in diff_files


# Laravel-specific grep patterns. Mirrors symfony.py spirit but adds Laravel
# facades: `Crypt::decrypt`, `decrypt(`, `Storage::`, `Http::*`. Kept narrow
# to keep precision over recall — worker checklists pick up edge cases.
_SERIALIZATION_RE = re.compile(
    r"\b(unserialize|igbinary_unserialize|msgpack_unpack|"
    r"Crypt::decrypt|decrypt|Cookie::get)\s*\("
)
_FILE_OPS_RE = re.compile(
    r"\b(file_get_contents|file_put_contents|fopen|move_uploaded_file|"
    r"include|include_once|require|require_once|copy|rename|unlink|"
    r"Storage::(?:get|put|putFile|putFileAs|append|prepend|disk|delete|"
    r"deleteDirectory|move|copy|download|getRaw|readStream))\s*\("
)
# `new Client(` without a prefix is too general — it catches Stripe\Client, App\Services\Client.
# Require GuzzleHttp namespace, optional leading-backslash for FQN.
_HTTP_CLIENT_RE = re.compile(
    r"\b(Http::(?:get|post|put|patch|delete|withHeaders|withToken|asForm|"
    r"send|head|options|withBasicAuth|withDigestAuth)|"
    r"\\?GuzzleHttp\\Client|Guzzle\\Client|curl_init)\s*\("
    r"|\bnew\s+\\?GuzzleHttp\\Client\s*\("
)


_COMMENT_PREFIX_RE = re.compile(r"^\s*(?://|#(?!\[)|\*|/\*)")


def _is_comment_line(line: str) -> bool:
    """True for lines whose trimmed start is a PHP comment (// # * /*).
    Skips matches inside docblocks (`* @example unserialize($x)`) and
    inline-disabled code (`// Crypt::decrypt(...)`). Best-effort — does
    not track multi-line block-comment state across lines.
    """
    return _COMMENT_PREFIX_RE.match(line) is not None


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
            if _is_comment_line(line):
                continue
            m = pattern.search(line)
            if m is None:
                continue
            # Symfony-symmetric kind capture: the whole match preserves more
            # diagnostic detail (e.g. distinct `new GuzzleHttp\Client(` vs
            # `Http::post(` for the same `http_client` pattern).
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


# Laravel authz call sites: Gate facade + Controller::authorize() + various
# `->can()` shapes + middleware('can:...'). The `->user()->can(` pattern catches
# Auth::user(), $request->user(), request()->user() in one shot — common in
# both controllers (route model binding) and form requests.
_AUTHZ_PATTERNS = [
    (re.compile(r"Gate::(?:define|policy|allows|denies|check|authorize|forUser|before|after)\s*\("), "gate_facade"),
    (re.compile(r"\$this->authorize\s*\("), "controller_authorize"),
    (re.compile(r"->user\s*\(\s*\)\s*->\s*can\s*\("), "user_can"),
    (re.compile(r"\$[a-zA-Z_]\w*->can\s*\(\s*['\"]"), "var_can"),
    # `->middleware('can:edit')` and `->middleware(['can:edit', ...])` — both
    # surface as middleware_can. Quote may be either single/double.
    (re.compile(r"->middleware\s*\(\s*\[?\s*['\"]can:"), "middleware_can"),
]


def collect_authz_usage(
    files: list[tuple[str, Path]],
    diff_files: Optional[set[str]],
) -> list[dict]:
    items: list[dict] = []
    for rel, abs_path in files:
        text = _read_text_safe(abs_path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _is_comment_line(line):
                continue
            for pat, label in _AUTHZ_PATTERNS:
                m = pat.search(line)
                if m is None:
                    continue
                items.append({
                    "kind": label,
                    "file": rel,
                    "line": lineno,
                    "snippet": line.strip()[:120],
                    "touched_by_diff": _touched(rel, diff_files),
                })
                break
    return items


# Hardcoded-secret candidate scanner — same regex set as symfony.py for
# consistent cross-stack reporting.
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
_SECRETS_CANDIDATES_CAP = 50


def _scan_secrets_in_files(
    files: list[tuple[str, Path]],
    regexes: list[tuple[re.Pattern[str], str]],
    candidates: list[dict],
) -> bool:
    for rel, abs_path in files:
        if len(candidates) >= _SECRETS_CANDIDATES_CAP:
            return True
        text = _read_text_safe(abs_path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(candidates) >= _SECRETS_CANDIDATES_CAP:
                return True
            if _is_comment_line(line):
                continue
            for pat, label in regexes:
                m = pat.search(line)
                if m is None:
                    continue
                candidates.append({
                    "file": rel,
                    "line": lineno,
                    "snippet": line.strip()[:120],
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
        # Laravel rarely keeps secrets in yaml — only `config/*.php` files
        # carry hardcoded credentials. Scan them with credential-prefix only
        # (no PHP-arrow `=>` form when in plain config arrays).
        config_dir = project_root / "config"
        if config_dir.is_dir():
            project_resolved = project_root.resolve()
            config_files: list[tuple[str, Path]] = []
            for f in config_dir.rglob("*.php"):
                if not f.is_file():
                    continue
                try:
                    rel = f.resolve().relative_to(project_resolved).as_posix()
                except (OSError, ValueError):
                    continue
                if _is_excluded(rel, EXCLUDE_PATHS):
                    continue
                config_files.append((rel, f.resolve()))
            config_files.sort(key=lambda p: p[0])
            capped = _scan_secrets_in_files(config_files, _SECRET_CRED_REGEXES, candidates)

    if capped:
        warnings.append(
            f"secrets_candidates_capped: stopped at {_SECRETS_CANDIDATES_CAP} hits "
            "(real audit needs full grep — bounded for LLM enrichment)"
        )

    env_files: list[str] = []
    for cand in (".env", ".env.example"):
        if (project_root / cand).is_file():
            env_files.append(cand)
    return SectionPayload(
        status="pending_enrichment",
        data={
            "hardcoded_secret_count": len(candidates),
            "candidates": candidates,
        },
        source_files=env_files,
        enrichment_hint=(
            f"Static recipe collected {len(candidates)} candidate hardcoded-secret matches "
            f"(cap={_SECRETS_CANDIDATES_CAP}). Classify each in `candidates`: is_real_secret "
            "yes/no, severity (info/medium/critical), sink_kind. Promote real secrets into "
            "items with status=ok. .env files listed in source_files for diffing only."
        ),
    )


# Fintech-domain markers — substring composer-dep matching (Symfony-symmetric:
# `laravel/cashier` and `paypal/paypal-checkout-sdk` are common Laravel-side
# Stripe/PayPal wrappers; exact-match would miss them) + grep markers covering
# both Stripe v6-7 (top-level resource classes) and v8+ (StripeClient,
# Service\* namespace) plus PayPal SDK call sites (excluding `use`/`namespace`).
_FINTECH_COMPOSER_MARKERS = (
    "stripe", "paypal", "moneyphp", "brick/money", "cashier", "iso3166",
)
_FINTECH_GREP_RE = re.compile(
    r"\b(Stripe\\(?:Customer|Charge|PaymentIntent|Subscription|Refund|Invoice|"
    r"SetupIntent|Dispute|StripeClient|Service\\[A-Z][A-Za-z0-9_]*)|"
    r"PayPalHttp\\[A-Z][A-Za-z0-9_]*|"
    r"PayPal\\(?:Api|Auth|Common|Core|Exception|Rest|Validation)\\[A-Z][A-Za-z0-9_]*|"
    r"bcmul\s*\(|bcadd\s*\(|bcsub\s*\(|bcdiv\s*\(|"
    r"money_format\s*\()"
)
_USE_NAMESPACE_PREFIX_RE = re.compile(r"^\s*(?:use|namespace)\s")


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
            data = None
        if isinstance(data, dict):
            seen_deps: set[str] = set()
            for section in ("require", "require-dev"):
                deps = data.get(section)
                if not isinstance(deps, dict):
                    continue
                for dep in deps:
                    dep_lower = dep.lower()
                    for marker in _FINTECH_COMPOSER_MARKERS:
                        if marker in dep_lower and dep not in seen_deps:
                            seen_deps.add(dep)
                            items.append({
                                "kind": "composer_dep",
                                "label": marker,
                                "dep": dep,
                                "file": "composer.json",
                                "touched_by_diff": _touched("composer.json", diff_files),
                            })
                            break
    for rel, abs_path in files:
        text = _read_text_safe(abs_path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _is_comment_line(line):
                continue
            # Skip `use` / `namespace` declarations — they reference SDK
            # classes but are not call sites (avoids 1 finding per controller
            # using PayPal SDK).
            if _USE_NAMESPACE_PREFIX_RE.match(line):
                continue
            m = _FINTECH_GREP_RE.search(line)
            if m is None:
                continue
            items.append({
                "kind": "grep_marker",
                "marker": m.group(0).strip("("),
                "file": rel,
                "line": lineno,
                "snippet": line.strip()[:120],
                "touched_by_diff": _touched(rel, diff_files),
            })
    return items


def _rel(path: Path, project_root: Path) -> str:
    """POSIX project-relative path."""
    return path.relative_to(project_root).as_posix()


def _to_relative(abs_path: Any, project_root: Path) -> Optional[str]:
    """Convert extractor's absolute path to POSIX project-relative."""
    if not isinstance(abs_path, str):
        return None
    try:
        return Path(abs_path).resolve().relative_to(project_root.resolve()).as_posix()
    except (ValueError, OSError):
        return None


_ROUTE_FACADE_RE = re.compile(
    r"Route::(?P<verb>get|post|put|patch|delete|options|any|match|resource|apiResource)"
    r"\s*\(\s*(?P<rest>[^;]+);",
    re.MULTILINE | re.DOTALL,
)
# `[Controller::class, 'method']` — classic two-arg array form.
_ROUTE_TARGET_ARRAY_RE = re.compile(
    r"\[\s*([A-Za-z_\\][A-Za-z0-9_\\]*)::class\s*,\s*['\"]([A-Za-z0-9_]+)['\"]\s*\]"
)
# `'App\Foo@method'` — Laravel <=5.x string form.
_ROUTE_TARGET_STRING_RE = re.compile(
    r"['\"]([A-Za-z_\\][A-Za-z0-9_\\]*@[A-Za-z0-9_]+)['\"]"
)
# `, Controller::class)` — invokable controller (single `__invoke` method)
# AND `Route::resource('uri', Controller::class)`. Anchored on `,` and a
# closing token (`)`, `,`, `-` for fluent chains).
_ROUTE_TARGET_BARE_CLASS_RE = re.compile(
    r",\s*([A-Za-z_\\][A-Za-z0-9_\\]*)::class\s*[\),\-]"
)
# Methods array literal at the start of `Route::match([...], 'uri', ...)`.
# Matches the first `[...]` (single-level — methods arrays don't nest).
_METHODS_ARRAY_RE = re.compile(r"^\s*\[[^\]]*\]\s*,")
_USE_RE = re.compile(
    r"^\s*use\s+([A-Za-z_\\][A-Za-z0-9_\\]*)(?:\s+as\s+([A-Za-z0-9_]+))?\s*;",
    re.MULTILINE,
)
# Group `use App\Http\{Foo, Bar as B};` (PHP 7+).
_USE_GROUP_RE = re.compile(
    r"^\s*use\s+([A-Za-z_\\][A-Za-z0-9_\\]*)\\\{([^}]+)\}\s*;",
    re.MULTILINE,
)


def _parse_use_aliases(text: str) -> dict[str, str]:
    """Extract `use Foo\\Bar [as Baz];` and `use Foo\\{A, B as C};` → alias map.

    Used to expand short class names in route definitions to fully-qualified
    names so they can be resolved to controller files via PSR-4.
    """
    out: dict[str, str] = {}
    for m in _USE_RE.finditer(text):
        fqn = m.group(1).lstrip("\\")
        alias = m.group(2) or fqn.rsplit("\\", 1)[-1]
        out[alias] = fqn
    for m in _USE_GROUP_RE.finditer(text):
        prefix = m.group(1).lstrip("\\")
        for entry in m.group(2).split(","):
            entry = entry.strip()
            if not entry:
                continue
            if " as " in entry:
                name, alias = (s.strip() for s in entry.split(" as ", 1))
            else:
                name = entry
                alias = entry.rsplit("\\", 1)[-1]
            out[alias] = f"{prefix}\\{name}"
    return out


def _parse_routes_file(path: Path, project_root: Path) -> list[dict]:
    """Parse routes/*.php for Route::* facade calls.

    Captures: verb (get/post/match/resource/...), URI literal (best-effort),
    controller FQN+method. Supported target forms:
        [Class::class, 'method']         — classic
        'Class@method'                   — legacy
        Class::class                     — invokable / resource bare class
    Short controller names are resolved to FQN via `use ...;` aliases.
    Closures and dynamic targets are recorded with target_kind=closure.

    For `Route::match(['get','post'], '/uri', ...)` the leading methods array
    is stripped before URI extraction so `/uri` is captured, not `'get'`.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    aliases = _parse_use_aliases(text)
    out: list[dict] = []
    for m in _ROUTE_FACADE_RE.finditer(text):
        verb = m.group("verb")
        rest = m.group("rest")
        # `match`/`apiMatch`/etc.: skip leading methods array before URI extraction.
        rest_for_uri = rest
        if verb in ("match", "apiMatch"):
            rest_for_uri = _METHODS_ARRAY_RE.sub("", rest, count=1)
        uri_m = re.search(r"['\"]([^'\"]+)['\"]", rest_for_uri)
        uri = uri_m.group(1) if uri_m else ""
        controller_fqn: Optional[str] = None
        method: Optional[str] = None
        target_kind = "closure"
        # Resolution order matters — try most specific first.
        ctrl_m = _ROUTE_TARGET_ARRAY_RE.search(rest)
        if ctrl_m:
            raw = ctrl_m.group(1).lstrip("\\")
            controller_fqn = aliases.get(raw, raw)
            method = ctrl_m.group(2)
            target_kind = "controller"
        else:
            str_m = _ROUTE_TARGET_STRING_RE.search(rest)
            if str_m:
                fqm = str_m.group(1)
                if "@" in fqm:
                    cls, mtd = fqm.rsplit("@", 1)
                    cls = cls.lstrip("\\")
                    controller_fqn = aliases.get(cls, cls)
                    method = mtd
                    target_kind = "controller"
            else:
                bare_m = _ROUTE_TARGET_BARE_CLASS_RE.search(rest)
                if bare_m:
                    raw = bare_m.group(1).lstrip("\\")
                    controller_fqn = aliases.get(raw, raw)
                    # Invokable: method=__invoke (Laravel convention).
                    # Resource: no single method — Laravel generates
                    # index/show/store/update/destroy. Worker reads the
                    # controller file as a whole.
                    method = "__invoke" if verb not in ("resource", "apiResource") else None
                    target_kind = "controller"
        # Approximate line number: char offset → line
        line = text.count("\n", 0, m.start()) + 1
        out.append({
            "verb": verb,
            "uri": uri,
            "target_kind": target_kind,
            "controller": controller_fqn,
            "method": method,
            "file": _rel(path, project_root),
            "line": line,
        })
    return out


def _resolve_controller_file(
    fqn: str,
    project_root: Path,
) -> Optional[str]:
    r"""Resolve `App\Http\Controllers\Foo` → `app/Http/Controllers/Foo.php` (PSR-4).

    Best-effort. Returns POSIX project-relative path or None when file absent.

    Containment-checked: if the resolved candidate is a symlink (or contains
    one in its parents) escaping `project_root`, returns None — a hostile
    repo cannot make recon emit paths pointing outside the project.
    """
    if not fqn.startswith("App\\"):
        return None
    rel = fqn[len("App\\"):].replace("\\", "/") + ".php"
    candidate = project_root / "app" / rel
    if not candidate.is_file():
        return None
    try:
        resolved = candidate.resolve()
        root_resolved = project_root.resolve()
        resolved.relative_to(root_resolved)
    except (OSError, ValueError):
        return None
    return _rel(candidate, project_root)


def _extract_classes(
    plugin_root: Path,
    project_root: Path,
    scan_root: Path,
    *,
    exclude: Optional[tuple[str, ...]] = None,
    warnings: Optional[list[str]] = None,
) -> list[dict]:
    """Bulk extract namespace + class names + parents from a directory.

    `exclude`  — extra exclude prefixes appended to sandbox.DEFAULT_EXCLUDE.
    `warnings` — when provided, extractor failure messages are appended to it
                 (parity with symfony recipe).
    """
    if not scan_root.is_dir():
        return []
    result, warn = sandbox.run_extractor(
        plugin_root, project_root, "class", scan_root, exclude=exclude,
    )
    if warn is not None and warnings is not None:
        warnings.append(warn)
    if result is None:
        return []
    items = result.get("items")
    return items if isinstance(items, list) else []


def _classes_extending(
    classes: list[dict], parents: tuple[str, ...],
) -> list[dict]:
    """Filter classes whose direct or transitive parent FQN matches any of `parents`.

    Handles indirect inheritance: `MyController extends ApiController extends
    Controller` is included when `parents=("Illuminate\\...\\Controller",)`.
    Falls back to suffix-match for ambiguous setups where extractor output
    omits the leading namespace; abstract classes are filtered out so base
    types don't surface as concrete admin/API surfaces.
    """
    out: list[dict] = []
    parents_set = set(parents)
    parents_norm = tuple(p.replace("\\", "/").rstrip("/") for p in parents)
    for cls in classes:
        if cls.get("is_abstract"):
            continue
        ext = cls.get("extends")
        chain = cls.get("parent_chain") or []
        candidates = [ext] if isinstance(ext, str) and ext else []
        candidates.extend(c for c in chain if isinstance(c, str))
        # FQN-first.
        if any(c in parents_set for c in candidates):
            out.append(cls)
            continue
        # Suffix-fallback (handles unresolved leading slash variations).
        norm_candidates = [c.replace("\\", "/").lstrip("/") for c in candidates]
        if any(c.endswith(p) or c == p for c in norm_candidates for p in parents_norm):
            out.append(cls)
    return out


def _classes_implementing(
    classes: list[dict], interfaces: tuple[str, ...],
) -> list[dict]:
    """Filter classes whose `implements` list contains any FQN ending in `interfaces`.

    Uses the extractor's `implements` field (list of fully-qualified interface names).
    Abstract classes are filtered out — `BaseJob implements ShouldQueue` is not
    dispatchable until a concrete subclass extends it.
    """
    out: list[dict] = []
    iface_norm = tuple(p.replace("\\", "/").lstrip("/") for p in interfaces)
    for cls in classes:
        if cls.get("is_abstract"):
            continue
        impl = cls.get("implements")
        if not isinstance(impl, list):
            continue
        normalized = [
            i.replace("\\", "/").lstrip("/") for i in impl if isinstance(i, str)
        ]
        if any(any(n.endswith(p) or n == p for p in iface_norm) for n in normalized):
            out.append(cls)
    return out


# ---------------------------------------------------------------------------
# Section builders.
# ---------------------------------------------------------------------------


def _build_attack_surface(
    project_root: Path,
    plugin_root: Path,
    *,
    exclude: Optional[tuple[str, ...]] = None,
    warnings: Optional[list[str]] = None,
) -> tuple[SectionPayload, list[str]]:
    """Aggregate http_route + cli_command + message_handler + event_listener."""
    items: list[dict] = []
    sources_used: list[str] = []
    # 1. HTTP routes — parse routes/*.php and dedupe by (verb, uri, controller).
    routes_dir = project_root / "routes"
    seen: set[tuple[str, str, Optional[str], Optional[str]]] = set()
    if routes_dir.is_dir():
        for routes_file in sorted(routes_dir.glob("*.php")):
            sources_used.append(_rel(routes_file, project_root))
            for r in _parse_routes_file(routes_file, project_root):
                key = (r["verb"], r["uri"], r["controller"], r["method"])
                if key in seen:
                    continue
                seen.add(key)
                # Resolve controller → file when possible. The file: field is
                # what plan_waves uses as target; closures point to routes file.
                file = r["file"]  # routes file
                if r["target_kind"] == "controller" and r["controller"]:
                    resolved = _resolve_controller_file(r["controller"], project_root)
                    if resolved:
                        file = resolved
                items.append({
                    "kind": "http_route",
                    "file": file,
                    "verb": r["verb"],
                    "uri": r["uri"],
                    "controller": r["controller"],
                    "method": r["method"],
                    "target_kind": r["target_kind"],
                    "route_file": r["file"],
                    "route_line": r["line"],
                })

    # 2. Console commands — Console/Commands extending Illuminate\Console\Command.
    classes_app = _extract_classes(
        plugin_root, project_root, project_root / "app",
        exclude=exclude, warnings=warnings,
    )
    if classes_app:
        sources_used.append("php-extractor:app/")
    commands = _classes_extending(classes_app, ("Illuminate/Console/Command", "Command"))
    for cls in commands:
        rel = _to_relative(cls.get("file"), project_root)
        if not _is_under(rel, "app/Console/Commands"):
            continue
        items.append({
            "kind": "cli_command",
            "file": rel,
            "class": cls.get("fqn") or cls.get("name"),
            "line": cls.get("line", 1),
        })
    # 3. Queue jobs — implementing Illuminate\Contracts\Queue\ShouldQueue.
    jobs = _classes_implementing(classes_app, (
        "Illuminate/Contracts/Queue/ShouldQueue", "ShouldQueue",
    ))
    for cls in jobs:
        rel = _to_relative(cls.get("file"), project_root)
        if not _is_under(rel, "app/Jobs"):
            continue
        items.append({
            "kind": "message_handler",
            "file": rel,
            "class": cls.get("fqn") or cls.get("name"),
            "line": cls.get("line", 1),
        })
    # 4. Event listeners — anything under app/Listeners/.
    for cls in classes_app:
        rel = _to_relative(cls.get("file"), project_root)
        if not _is_under(rel, "app/Listeners"):
            continue
        items.append({
            "kind": "event_listener",
            "file": rel,
            "class": cls.get("fqn") or cls.get("name"),
            "line": cls.get("line", 1),
        })
    # Stable order: kind > file.
    items.sort(key=lambda it: (it.get("kind", ""), it.get("file", "")))
    return SectionPayload(status="ok", items=items), sources_used


def _is_under(file_rel: Optional[str], prefix: str) -> bool:
    if not isinstance(file_rel, str):
        return False
    return file_rel == prefix or file_rel.startswith(prefix + "/")


def _short_name(fqn: Optional[str]) -> str:
    """`App\\Models\\Post` → `Post`. Empty string when absent."""
    if not isinstance(fqn, str) or not fqn:
        return ""
    return fqn.rsplit("\\", 1)[-1]


def _build_data_access(
    project_root: Path, classes_app: list[dict],
) -> SectionPayload:
    """Eloquent models (`app/Models/`) + repository pattern (`app/Repositories/`).

    Repositories aren't a Laravel framework primitive but are a common DDD
    layer over Eloquent — surfacing them here lets policy/authz audits walk
    the data path without re-resolving from controllers.
    """
    items: list[dict] = []
    for cls in classes_app:
        rel = _to_relative(cls.get("file"), project_root)
        if _is_under(rel, "app/Models"):
            items.append({
                "file": rel,
                "class": cls.get("fqn") or _short_name(cls.get("fqn")),
                "extends": cls.get("extends"),
                "kind": "model",
            })
        elif _is_under(rel, "app/Repositories"):
            items.append({
                "file": rel,
                "class": cls.get("fqn") or _short_name(cls.get("fqn")),
                "extends": cls.get("extends"),
                "kind": "repository",
            })
    items.sort(key=lambda it: (it.get("kind", ""), it.get("file", "")))
    return SectionPayload(status="ok", items=items)


def _build_form_requests(project_root: Path, classes_app: list[dict]) -> SectionPayload:
    items: list[dict] = []
    for cls in classes_app:
        rel = _to_relative(cls.get("file"), project_root)
        if not _is_under(rel, "app/Http/Requests"):
            continue
        items.append({
            "class": cls.get("fqn") or _short_name(cls.get("fqn")),
            "file": rel,
            "line": cls.get("line", 1),
            "authorize": None,  # full body parse out of MVP scope
        })
    items.sort(key=lambda it: it.get("file", ""))
    return SectionPayload(status="ok", items=items)


def _build_policies(project_root: Path, classes_app: list[dict]) -> SectionPayload:
    items: list[dict] = []
    for cls in classes_app:
        rel = _to_relative(cls.get("file"), project_root)
        if not _is_under(rel, "app/Policies"):
            continue
        # Conventional model: PostPolicy → Post
        short = _short_name(cls.get("fqn"))
        model = short[:-len("Policy")] if short.endswith("Policy") else None
        items.append({
            "class": cls.get("fqn") or short,
            "file": rel,
            "line": cls.get("line", 1),
            "model": model,
        })
    items.sort(key=lambda it: it.get("file", ""))
    return SectionPayload(status="ok", items=items)


def _build_service_providers(project_root: Path, classes_app: list[dict]) -> SectionPayload:
    items: list[dict] = []
    for cls in classes_app:
        rel = _to_relative(cls.get("file"), project_root)
        if not _is_under(rel, "app/Providers"):
            continue
        items.append({
            "class": cls.get("fqn") or _short_name(cls.get("fqn")),
            "file": rel,
            "line": cls.get("line", 1),
            "deferred": None,  # would require body inspection
        })
    items.sort(key=lambda it: it.get("file", ""))
    return SectionPayload(status="ok", items=items)


_KERNEL_GROUPS_RE = re.compile(
    r"protected\s+\$middlewareGroups\s*=\s*\[(?P<body>.*?)\]\s*;",
    re.DOTALL,
)
_KERNEL_GLOBAL_RE = re.compile(
    r"protected\s+\$middleware\s*=\s*\[(?P<body>.*?)\]\s*;",
    re.DOTALL,
)
_KERNEL_ROUTE_RE = re.compile(
    r"protected\s+\$(?:routeMiddleware|middlewareAliases)\s*=\s*\[(?P<body>.*?)\]\s*;",
    re.DOTALL,
)
_GROUP_KEY_RE = re.compile(r"['\"]([A-Za-z0-9_]+)['\"]\s*=>")


def _build_middleware_groups(project_root: Path) -> SectionPayload:
    """Parse app/Http/Kernel.php for $middleware, $middlewareGroups, $routeMiddleware/$middlewareAliases.

    Returns scalar payload with group names + counts. Bodies are not parsed
    deeply; the worker can read the file directly when needed.
    """
    kernel = project_root / "app" / "Http" / "Kernel.php"
    if not kernel.is_file():
        return SectionPayload(
            status="none",
            data={"groups": [], "global": 0, "route": []},
            source_files=[],
            reason="app/Http/Kernel.php not found (Laravel 11+ uses bootstrap/app.php instead)",
        )
    try:
        text = kernel.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return SectionPayload(
            status="failed",
            data={"groups": [], "global": 0, "route": []},
            source_files=["app/Http/Kernel.php"],
            warnings=["Kernel.php unreadable"],
        )

    groups: list[str] = []
    m = _KERNEL_GROUPS_RE.search(text)
    if m:
        groups = sorted(set(_GROUP_KEY_RE.findall(m.group("body"))))

    global_count = 0
    m = _KERNEL_GLOBAL_RE.search(text)
    if m:
        # Count comma-separated entries naively (each non-empty line that ends with ::class)
        body = m.group("body")
        global_count = body.count("::class")

    route: list[str] = []
    m = _KERNEL_ROUTE_RE.search(text)
    if m:
        route = sorted(set(_GROUP_KEY_RE.findall(m.group("body"))))

    return SectionPayload(
        status="ok",
        data={"groups": groups, "global": global_count, "route": route},
        source_files=["app/Http/Kernel.php"],
    )


def _build_output_renderers(project_root: Path) -> SectionPayload:
    """Blade templates: each *.blade.php under resources/views/ as a template_render item."""
    views = project_root / "resources" / "views"
    items: list[dict] = []
    if views.is_dir():
        for p in sorted(views.rglob("*.blade.php")):
            items.append({
                "kind": "template_render",
                "file": _rel(p, project_root),
                "engine": "blade",
            })
    return SectionPayload(status="ok", items=items)


def _build_auth_layer(project_root: Path) -> SectionPayload:
    """config/auth.php — best-effort scalar with default guard + driver names.

    Full parsing is out of MVP scope (config files are PHP arrays, not declarative).
    We surface the file as source and leave deeper inspection to the worker.
    """
    auth = project_root / "config" / "auth.php"
    if not auth.is_file():
        return SectionPayload(
            status="none",
            data={"kind": "unknown"},
            source_files=[],
            reason="config/auth.php not found",
        )
    try:
        text = auth.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return SectionPayload(
            status="failed",
            data={"kind": "unknown"},
            source_files=["config/auth.php"],
            warnings=["config/auth.php unreadable"],
        )
    # Detect drivers via regex — best effort.
    drivers = sorted(set(re.findall(r"['\"]driver['\"]\s*=>\s*['\"]([a-z_]+)['\"]", text)))
    default_guard_m = re.search(r"['\"]guard['\"]\s*=>\s*['\"]([a-z_]+)['\"]", text)
    default_guard = default_guard_m.group(1) if default_guard_m else None
    return SectionPayload(
        status="ok",
        data={
            "kind": "laravel.auth",
            "default_guard": default_guard,
            "drivers": drivers,
        },
        source_files=["config/auth.php"],
    )


# ---------------------------------------------------------------------------
# 3.4.0 Wave 2-E: routes_authz_matrix.
#
# Static cross-product of:
#   * route_name / methods / path / file:line   — from routes/*.php
#   * effective_middleware                       — group/prefix/named middleware
#                                                  inheritance + controller-level
#                                                  __construct() $this->middleware()
#   * authz_evidence                             — middleware authz tokens
#                                                  (auth, can:, throttle:, ...)
#                                                  + $this->authorize() / Gate::*
#                                                  / FormRequest::authorize() /
#                                                  authorizeResource(...) refs
#   * csrf_protection                            — required when route lives in
#                                                  the `web` group (Laravel
#                                                  default CSRF middleware),
#                                                  unknown for `api`/no-group.
#
# We deliberately do not consume `php artisan route:list --json` here in the
# MVP wave — Wave 2.5 (sync-step) will hook console enrichment when available.
# Static analysis covers ≥90 % of real codebases that the security-review
# checklists target.
# ---------------------------------------------------------------------------


# Block-aware route file walker. We track open `Route::middleware([...])`/
# `->prefix()`/`->name()`/`->group(function () { ... })` chains as a stack of
# scopes; a `Route::<verb>(...)` line emits with the union of all enclosing
# scope middleware. Implementation: small line-level brace counter — robust
# enough for canonical Laravel layouts (it does not handle PHP heredocs/CDATA
# or string-embedded braces, which never appear in routes/*.php in practice).

_ROUTE_GROUP_OPEN_RE = re.compile(
    r"Route\s*::\s*(?:[a-zA-Z_]+\s*\([^)]*\)\s*->\s*)*group\s*\(\s*function\b"
)
_ROUTE_VERB_RE = re.compile(
    r"Route\s*::\s*(?P<verb>get|post|put|patch|delete|options|any|match|"
    r"resource|apiResource)\s*\("
)
# Middleware tokens declared as `->middleware('x')` or `->middleware(['x','y'])`
# or `Route::middleware([...])` opening a group. We extract every quoted token.
_MIDDLEWARE_CHAIN_RE = re.compile(
    r"->\s*middleware\s*\(\s*(?P<arg>\[[^\]]*\]|['\"][^'\"]+['\"])"
)
_ROUTE_MIDDLEWARE_OPEN_RE = re.compile(
    r"Route\s*::\s*middleware\s*\(\s*(?P<arg>\[[^\]]*\]|['\"][^'\"]+['\"])"
)
_QUOTED_TOKEN_RE = re.compile(r"['\"]([^'\"]+)['\"]")
# `->name('x')` — used to set route_name. Captured, not propagated upward.
_NAME_RE = re.compile(r"->\s*name\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")
# `Route::prefix('admin')->...` or `->prefix('x')` — best-effort path prefix.
_PREFIX_RE = re.compile(r"->\s*prefix\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")
# Bare `Route::group(['middleware' => 'x', 'prefix' => 'y'], function ...)` —
# legacy Laravel <= 5.x. We extract `middleware` value only (prefix is best-
# effort and rarely changes authz outcome).
_LEGACY_GROUP_RE = re.compile(
    r"Route\s*::\s*group\s*\(\s*\[(?P<attrs>[^\]]*)\]\s*,\s*function\b",
    re.DOTALL,
)


def _extract_middleware_tokens(arg: str) -> list[str]:
    """Pull quoted tokens out of an `->middleware(...)` arg literal."""
    return _QUOTED_TOKEN_RE.findall(arg)


def _evidence_strength_for_middleware(token: str) -> str:
    """Map a middleware token to evidence strength.

    auth/can/role/permission/admin → hard_deny (refuses unauthenticated/forbidden).
    throttle/cache/cors            → soft (rate/perf/policy, not authz).
    Anything else                  → soft (we don't presume).
    """
    base = token.split(":", 1)[0].lower()
    if base in {"auth", "auth.basic", "auth.session", "can", "role", "permission",
                "admin", "verified", "signed", "guest"}:
        return "hard_deny"
    return "soft"


def _build_routes_authz_matrix(
    project_root: Path,
    classes_app: list[dict],
    *,
    diff_files: Optional[set[str]] = None,
) -> SectionPayload:
    """Cross-product of routes × middleware × authz call sites (static-only).

    Process:
      1. Walk every `routes/*.php` line-by-line, maintaining a scope stack of
         (middleware_list, prefix, route_file_kind=web|api|console|channels).
      2. On every `Route::<verb>(...)` literal, snapshot the merged scope and
         emit one item per HTTP method (or one item with method=GET for
         resource/apiResource — for surface-level enumeration).
      3. After the route literal we look ahead in the same line for chained
         `->middleware(...)`, `->name(...)` calls and merge them into the item.
      4. Resolve controller from the parsed route entry (`_parse_routes_file`
         returns FQN+method); read the controller file and look for:
            - `__construct` body with `$this->middleware('auth')` etc.
            - Method body with `$this->authorize('view', $post)` /
              `Gate::authorize('view', ...)`.
            - `authorizeResource(Post::class)` at class level.
         Append all matches as `authz_evidence` entries.
      5. Look up the FormRequest type-hint of the controller method; if the
         request has a `public function authorize(): bool`, emit a
         `form_request_authorize` evidence with strength=soft.
      6. csrf_protection:
            web         → required
            api         → unknown (Sanctum/Passport own CSRF; we don't second-guess)
            console/channels → unknown (not http surface)
            no enclosing group / fallback → unknown
    """
    routes_dir = project_root / "routes"
    if not routes_dir.is_dir():
        return SectionPayload(
            status="none",
            items=[],
            source_files=[],
            reason="routes/ directory not found",
        )

    # Index controllers by FQN for quick lookup.
    classes_by_fqn: dict[str, dict] = {}
    for cls in classes_app:
        fqn = cls.get("fqn")
        if isinstance(fqn, str):
            classes_by_fqn[fqn.lstrip("\\")] = cls

    items: list[dict] = []
    source_files: list[str] = []

    # Form-request authorize() registry: FQN → bool (has authorize method).
    form_request_authorize: dict[str, bool] = {}
    for cls in classes_app:
        rel = _to_relative(cls.get("file"), project_root)
        if not _is_under(rel, "app/Http/Requests"):
            continue
        fqn = cls.get("fqn")
        if not isinstance(fqn, str):
            continue
        form_request_authorize[fqn.lstrip("\\")] = _form_request_has_authorize(
            project_root / rel,
        )

    for routes_file in sorted(routes_dir.glob("*.php")):
        rel_routes = _rel(routes_file, project_root)
        source_files.append(rel_routes)
        text = _read_text_safe(routes_file)
        if text is None:
            continue
        # Line-level walker with scope stack.
        scope_stack: list[dict[str, Any]] = []  # each: {"middleware": [...], "depth": int}
        # `depth` counts the brace nesting at which the scope was opened.
        depth = 0
        # Pending middleware/prefix/name for the next `Route::group(function ...)`
        # opener (when it appears in a fluent chain like
        # `Route::middleware('a')->prefix('p')->group(function () {...})`).
        pending_middleware: list[str] = []
        pending_prefix: Optional[str] = None
        # Determine route file kind for csrf default.
        file_stem = routes_file.stem
        if file_stem == "web":
            base_csrf = "required"
        elif file_stem in ("api",):
            base_csrf = "unknown"
        else:
            base_csrf = "unknown"
        # Parse use-aliases for controller resolution
        aliases = _parse_use_aliases(text)
        # Parse routes (re-use existing parser for verb/uri/controller/method)
        parsed_routes = _parse_routes_file(routes_file, project_root)
        # Build (line-1)-indexed map from approximate file line to parsed entry.
        # _parse_routes_file uses regex offsets — line numbers match.
        routes_by_line: dict[int, dict] = {r["line"]: r for r in parsed_routes}

        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            # Track legacy `Route::group([...], function ...)` openers.
            legacy_m = _LEGACY_GROUP_RE.search(line)
            if legacy_m:
                attrs = legacy_m.group("attrs")
                mw = []
                # Match middleware key: 'middleware' => 'a' OR ['a','b']
                mm = re.search(
                    r"['\"]middleware['\"]\s*=>\s*(\[[^\]]*\]|['\"][^'\"]+['\"])",
                    attrs,
                )
                if mm:
                    mw = _extract_middleware_tokens(mm.group(1))
                pending_middleware = list(pending_middleware) + mw
                # group opener — push when we see `function (` on this same line
            # Track fluent `Route::middleware(...)` chain openers (no group).
            for m in _ROUTE_MIDDLEWARE_OPEN_RE.finditer(line):
                # Only count when this is a TOP-LEVEL chain (not part of a
                # `Route::get(...)->middleware(...)` postfix).
                # Heuristic: position 0 of the `Route::middleware(` token in the
                # stripped line.
                if stripped.startswith("Route::middleware") or stripped.startswith("Route ::middleware"):
                    pending_middleware = list(pending_middleware) + _extract_middleware_tokens(m.group("arg"))
                    break
            # Top-level `Route::prefix('x')` openers.
            if (stripped.startswith("Route::prefix") or stripped.startswith("Route ::prefix")):
                pm = _PREFIX_RE.search(line)
                if pm:
                    pending_prefix = pm.group(1)

            # Detect a group-opener on this line.
            opens_group = bool(_ROUTE_GROUP_OPEN_RE.search(line))
            if opens_group:
                scope_stack.append({
                    "middleware": list(pending_middleware),
                    "depth": depth + line.count("{"),  # group body opens with `{`
                    "prefix": pending_prefix,
                })
                pending_middleware = []
                pending_prefix = None

            # Maintain brace depth (poor man's PHP brace counter — works for
            # routes/*.php where strings rarely contain braces).
            opens = line.count("{")
            closes = line.count("}")
            depth += opens
            depth -= closes
            # Pop scopes whose `depth` exceeds current depth (they closed).
            while scope_stack and scope_stack[-1]["depth"] > depth:
                scope_stack.pop()

            # Now look for a `Route::<verb>(` literal.
            verb_m = _ROUTE_VERB_RE.search(line)
            if not verb_m:
                continue
            # Use the parsed entry that shares this line (best-effort).
            parsed = routes_by_line.get(lineno)
            if parsed is None:
                # Multi-line route literal — re-parse using the existing parser
                # from this offset. Skip if we can't recover a clean record.
                continue

            # Gather chained middleware on the same line (after the verb).
            chained: list[str] = []
            for cm in _MIDDLEWARE_CHAIN_RE.finditer(line[verb_m.end():]):
                chained.extend(_extract_middleware_tokens(cm.group("arg")))

            scope_mw: list[str] = []
            for sc in scope_stack:
                scope_mw.extend(sc["middleware"])

            # Controller-level middleware (from __construct).
            controller_fqn = parsed.get("controller")
            controller_method = parsed.get("method")
            controller_mw: list[str] = []
            controller_authz: list[dict] = []
            if isinstance(controller_fqn, str):
                # Resolve FQN via aliases if it was a short name.
                controller_fqn = aliases.get(
                    controller_fqn.split("\\")[-1], controller_fqn
                )
                ctrl_data = _read_controller_authz(
                    project_root, controller_fqn, controller_method,
                )
                controller_mw = ctrl_data["middleware"]
                controller_authz = ctrl_data["authz_evidence"]

            # Effective middleware: scope (outer→inner) → controller → chained, deduped preserving order.
            seen_mw: set[str] = set()
            effective: list[str] = []
            for token in scope_mw + controller_mw + chained:
                if token in seen_mw:
                    continue
                seen_mw.add(token)
                effective.append(token)

            # Authz evidence array: middleware tokens (auth/can/throttle...) + controller body matches.
            authz_evidence: list[dict] = []
            for token in effective:
                authz_evidence.append({
                    "source": "middleware",
                    "file": rel_routes,
                    "line": lineno,
                    "roles": [token],
                    "strength": _evidence_strength_for_middleware(token),
                })
            authz_evidence.extend(controller_authz)

            # FormRequest::authorize() detection — controller method signature.
            if isinstance(controller_fqn, str) and controller_method:
                fr = _detect_form_request_for_method(
                    project_root, controller_fqn, controller_method, form_request_authorize,
                )
                if fr is not None:
                    authz_evidence.append(fr)

            # csrf_protection.
            csrf = base_csrf
            # If we're inside an `api` middleware group on web.php, or `web`
            # on api.php, the *file* default loses to the explicit middleware.
            # Check effective middleware for the `web` or `api` group token.
            if "web" in effective:
                csrf = "required"
            elif "api" in effective:
                csrf = "unknown"

            # Resolve route file for line+file fields.
            controller_file = parsed.get("file") or rel_routes

            route_name_match = _NAME_RE.search(line)
            route_name = route_name_match.group(1) if route_name_match else None

            verb = parsed.get("verb") or verb_m.group("verb")
            methods = _verb_to_methods(verb)

            items.append({
                "route_name": route_name,
                "file": controller_file,
                "line": parsed.get("line", lineno),
                "methods": methods,
                "path": _join_path(parsed.get("uri", ""), scope_stack),
                "effective_middleware": effective,
                "matched_access_control": None,  # Symfony concept, not Laravel
                "firewall": None,  # Symfony concept, not Laravel
                "csrf_protection": csrf,
                "authz_evidence": authz_evidence,
            })

    # Stable sort: file, line.
    items.sort(key=lambda it: (it.get("file") or "", it.get("line") or 0))

    if diff_files is not None:
        norm = {p.lstrip("./") for p in diff_files}
        for item in items:
            f = item.get("file")
            if isinstance(f, str) and f in norm:
                # Mark touched_by_diff via a non-schema key? schema is closed —
                # we don't add a key. Caller can correlate via file+line.
                pass

    status = "ok" if items else "none"
    return SectionPayload(
        status=status,
        items=items,
        source_files=source_files,
    )


def _verb_to_methods(verb: str) -> list[str]:
    """Map a Route::<verb> name to canonical HTTP methods list."""
    v = verb.lower()
    if v == "any":
        return ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    if v in ("resource", "apiresource"):
        # Surface as the union of REST verbs the resource macro generates.
        if v == "apiresource":
            return ["GET", "POST", "PUT", "PATCH", "DELETE"]
        return ["GET", "POST", "PUT", "PATCH", "DELETE"]
    if v == "match":
        # We don't have the methods array here cleanly; surface as GET as a
        # conservative best-effort. (Wave 2.5 sync-step may enrich.)
        return ["GET"]
    return [v.upper()]


def _join_path(uri: str, scope_stack: list[dict[str, Any]]) -> str:
    """Prepend scope prefixes to the route URI, without double slashes."""
    parts: list[str] = []
    for sc in scope_stack:
        p = sc.get("prefix")
        if isinstance(p, str) and p:
            parts.append(p.strip("/"))
    if uri:
        parts.append(uri.lstrip("/"))
    return "/" + "/".join(part for part in parts if part)


def _read_controller_authz(
    project_root: Path, controller_fqn: str, method_name: Optional[str],
) -> dict:
    """Parse a controller file for __construct middleware + per-method authz calls.

    Returns:
        {"middleware": [...tokens...], "authz_evidence": [...]}
    """
    rel = _resolve_controller_file(controller_fqn, project_root)
    out: dict = {"middleware": [], "authz_evidence": []}
    if rel is None:
        return out
    abs_path = project_root / rel
    text = _read_text_safe(abs_path)
    if text is None:
        return out

    # __construct middleware: best-effort regex scan inside __construct body.
    construct_m = re.search(
        r"function\s+__construct\s*\([^)]*\)\s*\{",
        text,
    )
    if construct_m:
        # Walk from end of `{` to matching `}` (brace counter).
        body_start = construct_m.end()
        depth = 1
        i = body_start
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        body = text[body_start:i - 1]
        # Find `$this->middleware('x')` calls (with optional ->only/->except).
        for mm in re.finditer(
            r"\$this\s*->\s*middleware\s*\(\s*(?P<arg>\[[^\]]*\]|['\"][^'\"]+['\"])(?P<rest>[^;]*)",
            body,
        ):
            tokens = _extract_middleware_tokens(mm.group("arg"))
            rest = mm.group("rest")
            # Only/except scoping. If `->only(['x'])` is present and method_name
            # is known, only apply when method matches.
            only_m = re.search(r"->\s*only\s*\(\s*(\[[^\]]*\]|['\"][^'\"]+['\"])", rest)
            except_m = re.search(r"->\s*except\s*\(\s*(\[[^\]]*\]|['\"][^'\"]+['\"])", rest)
            applies = True
            if only_m and method_name is not None:
                methods = _extract_middleware_tokens(only_m.group(1))
                applies = method_name in methods
            elif except_m and method_name is not None:
                methods = _extract_middleware_tokens(except_m.group(1))
                applies = method_name not in methods
            if applies:
                out["middleware"].extend(tokens)

    # authorizeResource at class level.
    for ar in re.finditer(
        r"\$this\s*->\s*authorizeResource\s*\(\s*([A-Za-z_\\][A-Za-z0-9_\\]*)::class",
        text,
    ):
        line = text.count("\n", 0, ar.start()) + 1
        out["authz_evidence"].append({
            "source": "policy",
            "file": rel,
            "line": line,
            "roles": [ar.group(1)],
            "strength": "hard_deny",
        })

    # Per-method authz calls: locate the method body, scan for $this->authorize / Gate::authorize.
    if method_name:
        meth_m = re.search(
            r"function\s+" + re.escape(method_name) + r"\s*\([^)]*\)[^\{]*\{",
            text,
        )
        if meth_m:
            body_start = meth_m.end()
            depth = 1
            i = body_start
            while i < len(text) and depth > 0:
                ch = text[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                i += 1
            method_body = text[body_start:i - 1]
            method_body_offset = body_start
            for am in re.finditer(
                r"\$this\s*->\s*authorize\s*\(\s*['\"]([^'\"]+)['\"]",
                method_body,
            ):
                line = text.count("\n", 0, method_body_offset + am.start()) + 1
                out["authz_evidence"].append({
                    "source": "method_call",
                    "file": rel,
                    "line": line,
                    "roles": [am.group(1)],
                    "strength": "hard_deny",
                })
            for gm in re.finditer(
                r"Gate\s*::\s*(?:authorize|allows|denies|check)\s*\(\s*['\"]([^'\"]+)['\"]",
                method_body,
            ):
                line = text.count("\n", 0, method_body_offset + gm.start()) + 1
                out["authz_evidence"].append({
                    "source": "gate",
                    "file": rel,
                    "line": line,
                    "roles": [gm.group(1)],
                    "strength": "hard_deny",
                })

    return out


def _form_request_has_authorize(path: Path) -> bool:
    """True iff a FormRequest file declares `public function authorize(...)`."""
    text = _read_text_safe(path)
    if text is None:
        return False
    return re.search(r"function\s+authorize\s*\(", text) is not None


def _detect_form_request_for_method(
    project_root: Path,
    controller_fqn: str,
    method_name: str,
    form_request_authorize: dict[str, bool],
) -> Optional[dict]:
    """Inspect a controller method signature for FormRequest type-hints.

    Returns an authz_evidence dict (source=form_request_authorize) when the
    method takes a parameter typed as a known FormRequest subclass with an
    authorize() method.
    """
    rel = _resolve_controller_file(controller_fqn, project_root)
    if rel is None:
        return None
    abs_path = project_root / rel
    text = _read_text_safe(abs_path)
    if text is None:
        return None
    # Build a use-alias map for the controller file.
    aliases = _parse_use_aliases(text)
    sig_m = re.search(
        r"function\s+" + re.escape(method_name) + r"\s*\((?P<params>[^)]*)\)",
        text,
    )
    if not sig_m:
        return None
    params = sig_m.group("params")
    line = text.count("\n", 0, sig_m.start()) + 1
    # Scan params for `Foo $bar` type-hints (PHP 7+ syntax).
    for pm in re.finditer(
        r"(?:^|[\s,])\s*(?:\?\s*)?([A-Za-z_\\][A-Za-z0-9_\\]*)\s+\$\w+",
        params,
    ):
        type_name = pm.group(1).lstrip("\\")
        # Resolve via aliases if it's a short name.
        candidate_fqn = aliases.get(type_name, type_name)
        candidate_fqn = candidate_fqn.lstrip("\\")
        if form_request_authorize.get(candidate_fqn):
            return {
                "source": "form_request_authorize",
                "file": rel,
                "line": line,
                "roles": [],
                "strength": "soft",
            }
    return None


# ---------------------------------------------------------------------------
# 3.4.0 Wave 2-E: sensitive_columns.
#
# Parse Eloquent models (`app/Models/**`, `app/**/Models/**`) for $casts /
# $fillable / $hidden + Blueprint columns in `database/migrations/**`.
# Surface only columns whose names match credential-related patterns
# (api_token, secret_key, password, ...).
# ---------------------------------------------------------------------------


# Field name patterns (case-insensitive) — both camelCase and snake_case
# Laravel column convention spellings.
_SENSITIVE_FIELD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("password",       re.compile(r"^(?:password|pwd|pw)$", re.IGNORECASE)),
    ("api_token",      re.compile(r"^(?:api[_-]?token|apiKey|api[_-]?key|pat)$", re.IGNORECASE)),
    ("access_token",   re.compile(r"^(?:access[_-]?token|accessToken)$", re.IGNORECASE)),
    ("refresh_token",  re.compile(r"^(?:refresh[_-]?token|refreshToken)$", re.IGNORECASE)),
    ("session_token",  re.compile(r"^(?:session[_-]?token|sessionToken|csrf[_-]?token|csrfToken)$", re.IGNORECASE)),
    ("secret_key",     re.compile(r"^(?:secret[_-]?key|secretKey|signing[_-]?key|signingKey|hmac[_-]?key|hmacKey)$", re.IGNORECASE)),
    ("client_secret",  re.compile(r"^(?:client[_-]?secret|clientSecret)$", re.IGNORECASE)),
    ("private_key",    re.compile(r"^(?:private[_-]?key|privateKey)$", re.IGNORECASE)),
    ("webhook_secret", re.compile(r"^(?:webhook[_-]?secret|webhookSecret)$", re.IGNORECASE)),
    ("bot_token",      re.compile(r"^(?:bot[_-]?token|botToken)$", re.IGNORECASE)),
    ("remember_token", re.compile(r"^(?:remember[_-]?token|rememberToken)$", re.IGNORECASE)),
]


def _classify_sensitive_field(name: str) -> Optional[str]:
    """Return canonical pattern label or None."""
    for label, pat in _SENSITIVE_FIELD_PATTERNS:
        if pat.match(name):
            return label
    return None


# Eloquent cast values (and base classes) we treat as encrypting the column.
_ENCRYPTED_CAST_VALUES = {
    "encrypted", "encrypted:array", "encrypted:collection",
    "encrypted:json", "encrypted:object", "hashed",
}
# `EncryptedCast`, `Hashed`, etc. — custom cast class basenames are also OK.
_ENCRYPTED_CAST_CLASS_RE = re.compile(r"(?:Encrypted|Hashed)[A-Za-z]*Cast?$")
# Migration `Blueprint::` column-creation methods we treat as encrypted.
_ENCRYPTED_BLUEPRINT_METHODS = {"encryptedText", "encryptedString"}


def _parse_php_assoc_string_keys(body: str) -> list[tuple[str, str, int]]:
    """Pull `'key' => 'value'` pairs out of a PHP array body literal.

    Returns list of (key, value, char_offset_within_body). Best-effort;
    handles nested arrays by skipping bracket spans (very basic — sufficient
    for `$casts` / `$fillable` / `$hidden` declarations).
    """
    out: list[tuple[str, str, int]] = []
    for m in re.finditer(
        r"(?P<offset>)['\"](?P<key>[A-Za-z_][A-Za-z0-9_]*)['\"]\s*=>\s*['\"](?P<value>[^'\"]*)['\"]",
        body,
    ):
        out.append((m.group("key"), m.group("value"), m.start()))
    return out


def _parse_php_array_string_values(body: str) -> list[tuple[str, int]]:
    """Pull `'value'` / `"value"` entries out of a PHP array literal.

    Returns list of (value, char_offset_within_body).
    """
    out: list[tuple[str, int]] = []
    for m in re.finditer(r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]", body):
        out.append((m.group(1), m.start()))
    return out


def _find_array_property(
    text: str, prop_name: str,
) -> Optional[tuple[str, int]]:
    """Locate `protected $<prop_name> = [...]` and return (body, body_start_offset).

    Body is the text between `[` and matching `]`. Best-effort brace counter.
    """
    pat = re.compile(
        r"(?:protected|public|private)\s+(?:static\s+)?\$" + re.escape(prop_name) +
        r"\s*=\s*\[",
    )
    m = pat.search(text)
    if not m:
        return None
    start = m.end()  # position right after `[`
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        ch = text[i]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return (text[start:i], start)
        i += 1
    return None


def _is_encrypted_cast_value(value: str) -> bool:
    """True if a $casts entry value indicates encryption-at-rest."""
    if value in _ENCRYPTED_CAST_VALUES:
        return True
    # Custom cast class — match basename suffix.
    basename = value.rsplit("\\", 1)[-1]
    return bool(_ENCRYPTED_CAST_CLASS_RE.search(basename))


def _list_model_files(project_root: Path) -> list[tuple[str, Path]]:
    """Return (rel, abs) tuples for Eloquent model PHP files.

    Sources: `app/Models/**/*.php` and `app/**/Models/**/*.php` (DDD layouts).
    """
    out: list[tuple[str, Path]] = []
    project_resolved = project_root.resolve()
    candidates: list[Path] = []
    models_dir = project_root / "app" / "Models"
    if models_dir.is_dir():
        candidates.extend(models_dir.rglob("*.php"))
    app_dir = project_root / "app"
    if app_dir.is_dir():
        for ddd_models in app_dir.rglob("Models"):
            if ddd_models.resolve() == models_dir.resolve():
                continue
            if not ddd_models.is_dir():
                continue
            candidates.extend(ddd_models.rglob("*.php"))
    seen: set[Path] = set()
    for f in candidates:
        if not f.is_file():
            continue
        try:
            resolved = f.resolve()
        except (OSError, RuntimeError):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            rel = resolved.relative_to(project_resolved).as_posix()
        except ValueError:
            continue
        if _is_excluded(rel, EXCLUDE_PATHS):
            continue
        out.append((rel, resolved))
    out.sort(key=lambda pair: pair[0])
    return out


def _list_migration_files(project_root: Path) -> list[tuple[str, Path]]:
    out: list[tuple[str, Path]] = []
    mig = project_root / "database" / "migrations"
    if not mig.is_dir():
        return out
    project_resolved = project_root.resolve()
    for f in mig.rglob("*.php"):
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
        out.append((rel, resolved))
    out.sort(key=lambda pair: pair[0])
    return out


def _build_sensitive_columns(project_root: Path) -> SectionPayload:
    """Surface tokens/keys/passwords whose model + storage layout is visible."""
    items: list[dict] = []
    source_files: list[str] = []

    # Per-model accumulator: (entity_class, field_name) → item dict.
    by_field: dict[tuple[str, str], dict] = {}

    # Pass 1: models — $casts (with encryption inference) + $fillable.
    for rel, abs_path in _list_model_files(project_root):
        text = _read_text_safe(abs_path)
        if text is None:
            continue
        ns_m = re.search(r"namespace\s+([A-Za-z_\\][A-Za-z0-9_\\]*)\s*;", text)
        cls_m = re.search(r"class\s+([A-Za-z_][A-Za-z0-9_]*)\b", text)
        if not cls_m:
            continue
        ns = ns_m.group(1) if ns_m else ""
        entity_class = (ns + "\\" + cls_m.group(1)) if ns else cls_m.group(1)
        # $casts.
        casts_body = _find_array_property(text, "casts")
        if casts_body is not None:
            body, body_start = casts_body
            source_files.append(rel)
            for key, value, offset in _parse_php_assoc_string_keys(body):
                pattern = _classify_sensitive_field(key)
                if pattern is None:
                    continue
                line = text.count("\n", 0, body_start + offset) + 1
                encrypted = _is_encrypted_cast_value(value)
                evidence: list[dict] = []
                if encrypted:
                    evidence.append({
                        "kind": "eloquent_cast_whitelist",
                        "identifier": value,
                        "file": rel,
                        "line": line,
                    })
                by_field[(entity_class, key)] = {
                    "entity_class": entity_class,
                    "file": rel,
                    "field_name": key,
                    "column_type": value,  # cast value — string|encrypted|hashed|...
                    "name_pattern_matched": pattern,
                    "encryption_status": "encrypted" if encrypted else "plaintext",
                    "encryption_evidence": evidence,
                }
        # $fillable — sensitive fields not already covered by $casts.
        fillable_body = _find_array_property(text, "fillable")
        if fillable_body is not None:
            body, body_start = fillable_body
            if rel not in source_files:
                source_files.append(rel)
            for value, offset in _parse_php_array_string_values(body):
                pattern = _classify_sensitive_field(value)
                if pattern is None:
                    continue
                key = (entity_class, value)
                if key in by_field:
                    continue
                line = text.count("\n", 0, body_start + offset) + 1
                by_field[key] = {
                    "entity_class": entity_class,
                    "file": rel,
                    "field_name": value,
                    "column_type": "unknown",
                    "name_pattern_matched": pattern,
                    "encryption_status": "plaintext",
                    "encryption_evidence": [],
                }

    # Pass 2: migrations — Blueprint::<method>('column_name', ...) calls.
    blueprint_re = re.compile(
        r"(?:\$table|->)\s*->\s*([a-zA-Z_]+)\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"
    )
    # Also match `$table->method(` form (no leading arrow).
    blueprint_alt_re = re.compile(
        r"\$table\s*->\s*([a-zA-Z_]+)\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"
    )
    for rel, abs_path in _list_migration_files(project_root):
        text = _read_text_safe(abs_path)
        if text is None:
            continue
        emitted_in_file = False
        for m in blueprint_alt_re.finditer(text):
            method = m.group(1)
            col = m.group(2)
            pattern = _classify_sensitive_field(col)
            if pattern is None:
                continue
            line = text.count("\n", 0, m.start()) + 1
            # Migrations don't carry entity FQN; use file path as anchor so
            # it doesn't collide with model rows.
            entity_anchor = "migration:" + rel
            key = (entity_anchor, col)
            if key in by_field:
                continue
            encrypted = method in _ENCRYPTED_BLUEPRINT_METHODS
            evidence: list[dict] = []
            if encrypted:
                evidence.append({
                    "kind": "eloquent_cast_whitelist",
                    "identifier": method,
                    "file": rel,
                    "line": line,
                })
            by_field[key] = {
                "entity_class": entity_anchor,
                "file": rel,
                "field_name": col,
                "column_type": method,
                "name_pattern_matched": pattern,
                "encryption_status": "encrypted" if encrypted else "plaintext",
                "encryption_evidence": evidence,
            }
            if not emitted_in_file:
                source_files.append(rel)
                emitted_in_file = True
    # `blueprint_re` reserved for future `$table->method()` chains in
    # non-canonical migrations; current canonical layout matches via
    # `blueprint_alt_re`.
    _ = blueprint_re

    items = list(by_field.values())
    items.sort(key=lambda it: (it["entity_class"], it["field_name"]))

    status = "ok" if items else "none"
    # Dedup source_files preserving order.
    seen_src: set[str] = set()
    sources_dedup: list[str] = []
    for s in source_files:
        if s in seen_src:
            continue
        seen_src.add(s)
        sources_dedup.append(s)
    return SectionPayload(
        status=status,
        items=items,
        source_files=sources_dedup,
    )


# ---------------------------------------------------------------------------
# 3.4.0 Wave 2-E: runtime (Laravel Octane detection).
# ---------------------------------------------------------------------------


_OCTANE_SERVER_LITERAL_RE = re.compile(
    r"['\"]server['\"]\s*=>\s*['\"]([A-Za-z_]+)['\"]"
)
_OCTANE_SERVER_ENV_RE = re.compile(
    r"env\s*\(\s*['\"]OCTANE_SERVER['\"]\s*,\s*['\"]([A-Za-z_]+)['\"]"
)


def _build_runtime(project_root: Path) -> SectionPayload:
    """Detect Laravel Octane and configured server flavor.

    Sources:
      composer.json (require/require-dev)  → octane: bool
      config/octane.php                    → octane_server: 'swoole'|'roadrunner'|...
                                              (literal first, env() default fallback)
    """
    composer = project_root / "composer.json"
    octane_in_deps = False
    sources: list[str] = []
    if composer.is_file():
        sources.append("composer.json")
        try:
            data = json.loads(composer.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = None
        if isinstance(data, dict):
            for section in ("require", "require-dev"):
                deps = data.get(section)
                if not isinstance(deps, dict):
                    continue
                if "laravel/octane" in deps:
                    octane_in_deps = True
                    break

    octane_server: Optional[str] = None
    octane_config = project_root / "config" / "octane.php"
    if octane_config.is_file():
        sources.append("config/octane.php")
        text = _read_text_safe(octane_config)
        if text is not None:
            m = _OCTANE_SERVER_LITERAL_RE.search(text)
            if m:
                octane_server = m.group(1)
            else:
                m2 = _OCTANE_SERVER_ENV_RE.search(text)
                if m2:
                    octane_server = m2.group(1)

    return SectionPayload(
        status="ok",
        data={"octane": octane_in_deps, "octane_server": octane_server},
        source_files=sources,
    )


# ---------------------------------------------------------------------------
# Public entry: build_inventory.
# ---------------------------------------------------------------------------


def build_inventory(
    project_root: Path,
    diff_files: Optional[set[str]] = None,
    *,
    plugin_root: Optional[Path] = None,
    no_console: bool = False,
    exclude: Optional[tuple[str, ...]] = None,
) -> InventoryResult:
    """Run the full Laravel recipe pipeline.

    diff_files — when not None, recipe should mark items whose `file` is in
    the set with `touched_by_diff: true`. (Caller — recon_inventory.py — sets
    this. MVP recipe applies it as a post-pass.)

    no_console — when True, skip artisan-based enrichment (currently unused —
    MVP is fully static; placeholder for v3.x console enrichment).

    exclude — extra path prefixes (relative to project_root) appended to
    sandbox.DEFAULT_EXCLUDE before invoking the PHP extractor. Use it to
    skip project-specific directories (legacy/, generated/, third-party
    mirrors) that the orchestrator picked up from CLAUDE.md.
    """
    if plugin_root is None:
        plugin_root = Path(__file__).resolve().parents[3]
    del no_console  # MVP: no console enrichment yet

    sources_used: list[str] = []
    warnings: list[str] = []
    errors: list[str] = []
    framework_specific: dict[str, SectionPayload] = {}

    # Bulk class extraction — used by multiple section builders.
    classes_app = _extract_classes(
        plugin_root, project_root, project_root / "app",
        exclude=exclude, warnings=warnings,
    )

    # PHP files under app/ — shared between grep-based collectors. Sorted,
    # symlink-contained, excluded vendor/var/test paths.
    files = _list_php_files(project_root)

    # ----- attack_surface -----
    attack_surface, attack_sources = _build_attack_surface(
        project_root, plugin_root, exclude=exclude, warnings=warnings,
    )
    sources_used.extend(attack_sources)

    # ----- data_access -----
    data_access = _build_data_access(project_root, classes_app)

    # ----- auth_layer -----
    auth_layer = _build_auth_layer(project_root)

    # ----- authz_usage -----
    authz_items = collect_authz_usage(files, diff_files)
    authz_usage = SectionPayload(status="ok", items=authz_items)

    # ----- output_renderers -----
    output_renderers = _build_output_renderers(project_root)

    # ----- grep-based domains -----
    serialization_items = collect_grep_section(files, _SERIALIZATION_RE, "serialization", diff_files)
    file_ops_items = collect_grep_section(files, _FILE_OPS_RE, "file_op", diff_files)
    http_client_items = collect_grep_section(files, _HTTP_CLIENT_RE, "http_client", diff_files)
    serialization = SectionPayload(status="ok", items=serialization_items)
    file_operations = SectionPayload(status="ok", items=file_ops_items)
    http_clients = SectionPayload(status="ok", items=http_client_items)

    # ----- secrets -----
    secrets = collect_secrets(project_root, files, warnings)

    # ----- fintech_markers -----
    fintech_items = collect_fintech_markers(project_root, files, diff_files)
    fintech_markers = SectionPayload(status="ok", items=fintech_items)

    # ----- frontend_assets (list-section per schema v2) -----
    frontend_items: list[dict] = []
    bundler_configs = (
        ("vite", "vite.config.js"),
        ("vite", "vite.config.ts"),
        ("mix",  "webpack.mix.js"),
        ("webpack", "webpack.config.js"),
    )
    for bundler, rel in bundler_configs:
        if (project_root / rel).is_file():
            frontend_items.append({
                "kind": "bundler",
                "bundler": bundler,
                "file": rel,
            })
    if (project_root / "resources" / "js" / "Pages").is_dir():
        frontend_items.append({
            "kind": "inertia_pages",
            "file": "resources/js/Pages",
        })
    frontend_assets = SectionPayload(status="ok", items=frontend_items)

    # ----- framework_specific.laravel.* -----
    framework_specific["policies"] = _build_policies(project_root, classes_app)
    framework_specific["service_providers"] = _build_service_providers(project_root, classes_app)
    framework_specific["middleware_groups"] = _build_middleware_groups(project_root)
    framework_specific["form_requests"] = _build_form_requests(project_root, classes_app)
    # GraphQL (optional — only when library detected).
    gql = detect_graphql(project_root)
    if gql is not None:
        framework_specific["graphql_layer"] = SectionPayload(
            status="ok",
            data=gql,
            source_files=["composer.json"],
        )

    # 3.4.0 Wave 2-E sections.
    framework_specific["routes_authz_matrix"] = _build_routes_authz_matrix(
        project_root, classes_app, diff_files=diff_files,
    )
    framework_specific["sensitive_columns"] = _build_sensitive_columns(project_root)
    framework_specific["runtime"] = _build_runtime(project_root)

    # ----- diff_files post-pass: stamp touched_by_diff on list items -----
    if diff_files is not None:
        norm = {p.lstrip("./") for p in diff_files}
        for payload in (attack_surface, data_access, output_renderers,
                        framework_specific.get("policies"),
                        framework_specific.get("service_providers"),
                        framework_specific.get("form_requests")):
            if payload is None or not payload.items:
                continue
            for item in payload.items:
                f = item.get("file")
                if isinstance(f, str) and f in norm:
                    item["touched_by_diff"] = True

    core: dict[str, SectionPayload] = {
        "attack_surface": attack_surface,
        "data_access": data_access,
        "auth_layer": auth_layer,
        "authz_usage": authz_usage,
        "output_renderers": output_renderers,
        "serialization": serialization,
        "file_operations": file_operations,
        "http_clients": http_clients,
        "secrets": secrets,
        "fintech_markers": fintech_markers,
        "frontend_assets": frontend_assets,
    }

    # Ceiling logic: pure-static recipe with no console enrichment available
    # for queue/event metadata → caller should clamp ceiling=medium.
    return InventoryResult(
        status="ok",
        core=core,
        framework_specific=framework_specific,
        sources_used=sources_used,
        warnings=warnings,
        errors=errors,
    )
