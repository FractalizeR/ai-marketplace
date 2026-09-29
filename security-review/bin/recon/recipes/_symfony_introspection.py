"""Framework self-introspection helpers for the Symfony recipe.

Subject: what the running Symfony app reports about its own configuration via
its console (`ConsoleSession`), plus where on disk that configuration lives
when the console cannot be trusted or is disabled (`find_config_evidence`).

Underscore-prefixed module: `recon.recipes.available_recipes()` skips it —
this is not a stack recipe, it has no `RECIPE_NAME` / `build_inventory` /
`detect`. `symfony.py` is the only caller. Kept dependency-free of
`symfony.py` on purpose (that module will import from here, not the reverse).

No `--resolve-env` is ever passed to the console: plain `%param%` values ARE
resolved by Symfony regardless, so both console output and free-text stderr
pass through the redaction helpers below before reaching `warnings` / the
caller-built views.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from recon.recipes._shared import has_hidden_dir_segment


# ---------------------------------------------------------------------------
# Secret redaction — shared by ConsoleSession's warnings here and by the
# normalized config views the Symfony recipe builds from `extension_config()`.
# ---------------------------------------------------------------------------

# Explicit key list (not a substring regex): matched as the full key or a
# `.`-suffix (e.g. "database.password"). Keeps `access_token`,
# `csrf_token_id`, `password_parameter`, `token_provider` untouched even
# though they contain "token"/"password" as a substring.
SECRET_KEYS: tuple[str, ...] = (
    "secret",
    "password",
    "passphrase",
    "api_key",
    "private_key",
    "client_secret",
    "dsn",
    "signature_properties",
)

REDACTED = "<redacted>"

_ENV_PLACEHOLDER_RE = re.compile(r"^%env\([^)]*\)%$")


def _is_secret_key(key: str, *, separators: tuple[str, ...] = (".",)) -> bool:
    """Full-key match, or a match after one of `separators` (e.g. the `.`
    that joins tree paths like `database.password`). `redact_stderr_secrets`
    below additionally accepts `_` (env-var style: `MAILER_PASSWORD`) — kept
    out of the default so structured-view redaction (`redact_secret_value`)
    stays strict and never touches `password_parameter` / `access_token`.
    """
    key_lower = key.strip().lower()
    if not key_lower:
        return False
    if key_lower in SECRET_KEYS:
        return True
    for sep in separators:
        if any(key_lower.endswith(sep + k) for k in SECRET_KEYS):
            return True
    return False


def redact_secret_value(key: str, value):
    """Redact `value` if `key` matches the secret-key list.

    Never redacts an empty value, a boolean, or the literal `%env(...)%`
    placeholder — there is nothing to leak in those.
    """
    if not _is_secret_key(key):
        return value
    if value is None or value == "" or isinstance(value, bool):
        return value
    if isinstance(value, str) and _ENV_PLACEHOLDER_RE.match(value.strip()):
        return value
    return REDACTED


# Free-text variant for console stderr, which is unstructured prose, not a
# key/value tree. Pattern-based on purpose: `key: value`, `key=value`,
# `key => value`, JSON `"key":"value"`, quoted multi-word values, and URL
# userinfo (`scheme://user:pass@`, `redis://:pass@`, `slack://TOKEN@`).
#
# The key group is anchored to the SECRET_KEYS words themselves (optionally
# prefixed by `<word>.` / `<word>_`, e.g. `MAILER_PASSWORD`), not "any
# identifier" — a generic `[\w.-]+` key would misparse adjacent prose like
# "connection failed: password: hunter2" (the first colon's greedy value
# swallows "password:" before it gets a chance to be matched as its own key).
_SECRET_WORDS_ALT = "|".join(re.escape(k) for k in SECRET_KEYS)
_KV_RE = re.compile(
    rf"(?i)(?<![\w.-])(?P<key>(?:[\w-]+[._])?(?:{_SECRET_WORDS_ALT}))(?P<kq>[\"']?)"
    r"(?P<sep>\s*(?:=>|[:=])\s*)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;&}\]]+)"
)
# The whole userinfo is masked: notifier / mailer DSNs carry the secret as a
# bare token (`slack://TOKEN@`) or in the user half (`mailgun+api://KEY:DOMAIN@`).
_URL_USERINFO_RE = re.compile(r"(?i)(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<userinfo>[^@/\s'\"]+)@")


def redact_stderr_secrets(text: Optional[str]) -> Optional[str]:
    """Redact secret-shaped substrings from raw console stderr / a warning.

    Applied to every warning `ConsoleSession` appends and to the console
    preflight `reason`, so a credential echoed by a Symfony boot error never
    lands in CONTEXT.md or a CI log. A value already masked (`<redacted…>`)
    or a literal `%env(...)%` placeholder is left as is.
    """
    if not text:
        return text

    def _url_sub(m: re.Match) -> str:
        if "%env(" in m.group("userinfo") or m.group("userinfo").startswith("<redacted"):
            return m.group(0)
        return f"{m.group('scheme')}{REDACTED}@"

    def _kv_sub(m: re.Match) -> str:
        key, value = m.group("key"), m.group("value")
        if not _is_secret_key(key, separators=(".", "_")):
            return m.group(0)
        quote = value[0] if value[:1] in ("'", '"') and len(value) >= 2 else ""
        inner = value[1:-1] if quote else value
        if not inner or inner.startswith("<redacted") or _ENV_PLACEHOLDER_RE.match(inner):
            return m.group(0)
        return f"{key}{m.group('kq')}{m.group('sep')}{quote}{REDACTED}{quote}"

    out = _URL_USERINFO_RE.sub(_url_sub, text)
    return _KV_RE.sub(_kv_sub, out)


# ---------------------------------------------------------------------------
# ConsoleSession — lazy single smoke + cached extension_config()/kernel_environment().
# ---------------------------------------------------------------------------


class ConsoleSession:
    """One per `build_inventory` run; owned/created by the Symfony recipe.

    `ok` runs `sandbox.try_console_smoke` lazily on first access and memoizes
    the result — at most one smoke probe per session, regardless of how many
    methods below are called. On success it appends `console:smoke` to
    `sources_used` once; on failure it appends the (redacted) smoke warning
    and every subsequent call on this session returns `None` without
    spawning any further subprocess.
    """

    def __init__(self, runner, sources_used: list[str], warnings: list[str]):
        self._runner = runner
        self._sources_used = sources_used
        self._warnings = warnings
        self._smoke_done = False
        self._smoke_ok = False
        self._config_cache: dict[str, Optional[dict]] = {}
        self._debug_config_recorded = False
        self.json_unsupported = False
        self._version_read = False
        self._version: Optional[str] = None
        self._version_too_old = False
        self._env_done = False
        self._env: Optional[str] = None

    def _warn(self, quiet: bool, message: str) -> None:
        if not quiet:
            self._warnings.append(message)

    @property
    def ok(self) -> bool:
        if not self._smoke_done:
            self._smoke_done = True
            from recon import sandbox

            smoke_ok, smoke_warn = sandbox.try_console_smoke(self._runner)
            self._smoke_ok = smoke_ok
            if smoke_ok:
                self._sources_used.append("console:smoke")
            else:
                self._warnings.append(
                    redact_stderr_secrets(smoke_warn) or "console_smoke_failed: unknown"
                )
        return self._smoke_ok

    def extension_config(self, alias: str, *, quiet: bool = False) -> Optional[dict]:
        """`debug:config <alias> --format=json` → the processed config tree.

        Cached per alias. Requires Symfony >= 6.3 (older versions reject
        `--format=json` on this command); rejection, an unregistered alias,
        and any other failure all surface the same way: `None` + a warning
        (`run_console_command` already folds them into one failure shape).
        Never passes `--resolve-env`. `quiet` suppresses the failure warning —
        for an alias with no config anywhere in the project, where "not
        registered" is an expected answer, not a problem.
        """
        if alias in self._config_cache:
            return self._config_cache[alias]
        if not self.ok:
            self._config_cache[alias] = None
            return None

        from recon import sandbox

        out, warn = sandbox.run_console_command(
            self._runner, ["debug:config", alias, "--format=json"],
        )
        if warn:
            self._warn(quiet, redact_stderr_secrets(warn))
            self._check_json_unsupported(warn)
            self._config_cache[alias] = None
            return None
        if out is None:
            self._config_cache[alias] = None
            return None
        try:
            parsed = json.loads(out)
        except json.JSONDecodeError as e:
            self._warn(quiet, f"console_parse_failed: debug:config {alias}: {e}")
            self._config_cache[alias] = None
            return None
        if not isinstance(parsed, dict):
            self._warn(quiet, 
                f"console_parse_failed: debug:config {alias}: unexpected JSON shape"
            )
            self._config_cache[alias] = None
            return None
        # `debug:config <alias>` wraps the tree under the alias key
        # (`{"<alias>": {...}}`); unwrap so callers get the processed tree
        # directly. Falls back to the raw parsed dict if some Symfony version
        # emits it unwrapped.
        inner = parsed.get(alias)
        tree = inner if isinstance(inner, dict) else parsed
        if not self._debug_config_recorded:
            self._sources_used.append("console:debug_config")
            self._debug_config_recorded = True
        self._config_cache[alias] = tree
        return tree

    def _check_json_unsupported(self, warn: str) -> None:
        """After a failed `debug:config --format=json`, decide whether the console
        is simply too old (Symfony < 6.3) and say so once, naming the version.

        The version, not the failure text, is the signal: Symfony prints the
        command synopsis after an input error and `run_console_command` keeps only
        the last stderr line, so the "option does not exist" sentence is usually
        gone. The sentence still counts when it does survive.
        """
        if self.json_unsupported:
            return
        if not self._version_read:
            self._version_read = True
            from recon import sandbox

            out, _ = sandbox.run_console_command(self._runner, ["--version"])
            match = re.search(r"Symfony\s+(\d+)\.(\d+)(?:\.\d+)?", out or "")
            if match:
                self._version = match.group(0).split(None, 1)[1]
                self._version_too_old = (int(match.group(1)), int(match.group(2))) < (6, 3)
        sentence = "option does not exist" in warn.lower()
        if not (self._version_too_old or sentence):
            return
        self.json_unsupported = True
        self._warnings.append(
            f"console_unsupported: debug:config --format=json needs Symfony >= 6.3 "
            f"(console reports {self._version or 'unknown version'}); "
            f"config is left uninterpreted"
        )

    def kernel_environment(self) -> Optional[str]:
        """`debug:container --parameter=kernel.environment --format=json`.

        Queried once per session (each call boots the kernel); a failure is
        cached too, so it warns once.
        """
        if not self._env_done:
            self._env_done = True
            self._env = self._query_kernel_environment()
        return self._env

    def _query_kernel_environment(self) -> Optional[str]:
        if not self.ok:
            return None

        from recon import sandbox

        out, warn = sandbox.run_console_command(
            self._runner,
            ["debug:container", "--parameter=kernel.environment", "--format=json"],
        )
        if warn:
            self._warnings.append(redact_stderr_secrets(warn))
            return None
        if out is None:
            return None
        raw = out.strip()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            # Defensive: some versions print the bare value, not JSON, for a
            # single --parameter query.
            return raw.strip('"') or None
        if isinstance(parsed, str):
            return parsed
        if isinstance(parsed, dict):
            val = parsed.get("kernel.environment")
            if isinstance(val, str):
                return val
        return None

    def run(self, args: list[str]) -> Optional[str]:
        """Passthrough over `sandbox.run_console_command` for existing callers
        (e.g. `debug:router`). Gated on `ok` like every other method here.
        """
        if not self.ok:
            return None

        from recon import sandbox

        out, warn = sandbox.run_console_command(self._runner, args)
        if warn:
            self._warnings.append(redact_stderr_secrets(warn))
            return None
        return out


# ---------------------------------------------------------------------------
# Per-section subtree keys: which keys make a file evidence for a section.
# ---------------------------------------------------------------------------

# security: auth_layer / firewalls / password_hasher / routes_authz_matrix.
SECURITY_SUBTREE_KEYS: tuple[str, ...] = ("firewalls", "access_control", "providers", "password_hashers")
# framework: trusted_config.
TRUSTED_SUBTREE_KEYS: tuple[str, ...] = ("trusted_proxies", "trusted_hosts", "trusted_headers")
# framework: messenger_transports.
MESSENGER_SUBTREE_KEYS: tuple[str, ...] = ("messenger",)
# twig: twig_overrides. Only a file that sets `autoescape` is evidence: a
# default Flex `twig.yaml` never does (and TwigBundle 8 no longer accepts it),
# and without a console tree it would otherwise turn nearly every project
# `partial` for a setting that is at its default.
TWIG_SUBTREE_KEYS: tuple[str, ...] = ("autoescape",)


# ---------------------------------------------------------------------------
# find_config_evidence — static discovery of "where might this alias live".
# ---------------------------------------------------------------------------


@dataclass
class Evidence:
    files: list[str]
    prod_override: bool
    # Set by `config/packages/dev/**` and yaml `when@dev`; those files stay
    # out of `files` (not production posture) but shape a console tree read in
    # the dev env.
    dev_override: bool = False
    # `config/packages/dev/**` files that are evidence on their own — the
    # source when the console reads the dev env and nothing else configures it.
    dev_files: list[str] = field(default_factory=list)


@dataclass
class _FileEvidence:
    found: bool = False
    prod: bool = False
    dev: bool = False


_CONFIG_EXTENSIONS = (".yaml", ".yml", ".php", ".xml")

# Symfony >= 7.4 writes `config/reference.php`: array-shape docs for every
# registered extension, for IDEs only — never loaded as configuration, yet it
# names every alias and option. Matched by exact path AND its generated header,
# so a hand-written file that happens to use the name still counts.
_GENERATED_REFERENCE_PATH = "reference.php"
_GENERATED_REFERENCE_MARKER = "This file is auto-generated"


def is_generated_config_reference(rel_from_config: str, text: Optional[str]) -> bool:
    """`rel_from_config` is relative to `config/` (posix)."""
    return (
        rel_from_config == _GENERATED_REFERENCE_PATH
        and text is not None
        and _GENERATED_REFERENCE_MARKER in text[:1024]
    )


# Files larger than this are not read (avoids OOM on huge / generated files).
READ_MAX_BYTES = 1_000_000


def read_text_safe(path: Path, max_bytes: int = READ_MAX_BYTES) -> Optional[str]:
    """Text of `path`, or None when unreadable or larger than `max_bytes`.
    Shared with the Symfony recipe so both read config under one rule."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None



# --- YAML heuristic -----------------------------------------------------

_TOP_KEY_RE = re.compile(r"^([A-Za-z0-9_@.-]+)\s*:\s*(.*)$")


def _block_end(lines: list[str], start: int, header_indent: int) -> int:
    """First index >= start whose (non-blank, non-comment) indent is <=
    `header_indent` — i.e. one past the end of the block opened at that
    indent. Blank lines and comments never close a block on their own.
    """
    i = start
    while i < len(lines):
        raw = lines[i]
        if not raw.strip() or raw.lstrip().startswith("#"):
            i += 1
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent <= header_indent:
            return i
        i += 1
    return len(lines)


def _contains_any_key_line(lines: list[str], start: int, end: int, keys: tuple[str, ...]) -> bool:
    if not keys:
        return True
    block_text = "\n".join(lines[start:end])
    return any(re.search(rf"^\s*{re.escape(k)}\s*:", block_text, re.MULTILINE) for k in keys)


def _find_alias_block(
    lines: list[str], start: int, end: int, alias: str
) -> Optional[tuple[int, int]]:
    """Within lines[start:end], find a `<alias>:` key line and return the
    (content_start, content_end) range of its nested block, capped at `end`.
    """
    key_re = re.compile(rf"^(\s*){re.escape(alias)}\s*:\s*(.*)$")
    for i in range(start, end):
        raw = lines[i]
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = key_re.match(raw)
        if m:
            indent = len(m.group(1))
            content_start = i + 1
            content_end = min(_block_end(lines, content_start, indent), end)
            return content_start, content_end
    return None


def _yaml_evidence(text: str, alias: str, subtree_keys: tuple[str, ...]) -> _FileEvidence:
    """A yaml file is evidence iff a top-level `<alias>:` block (unconditional,
    or nested one level inside a top-level `when@<env>:` block) contains at
    least one of `subtree_keys`. `when@test` blocks are ignored; a `when@dev`
    block only sets `dev`; a `when@prod` block counts and sets `prod`.
    Directory-based env detection (`config/packages/<env>/**`) is the
    caller's job (filename rule, not content).
    """
    lines = text.splitlines()
    n = len(lines)
    res = _FileEvidence()
    i = 0
    while i < n:
        raw = lines[i]
        if not raw.strip() or raw.lstrip().startswith("#"):
            i += 1
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent != 0:
            i += 1
            continue
        m = _TOP_KEY_RE.match(raw.strip())
        if not m:
            i += 1
            continue
        key = m.group(1)
        block_start = i + 1
        block_end = _block_end(lines, block_start, 0)
        if key.startswith("when@"):
            env = key[len("when@"):]
            if env != "test":
                sub = _find_alias_block(lines, block_start, block_end, alias)
                if sub is not None:
                    c_start, c_end = sub
                    if _contains_any_key_line(lines, c_start, c_end, subtree_keys):
                        if env == "dev":
                            res.dev = True
                        else:
                            res.found = True
                            res.prod = res.prod or env == "prod"
        elif key == alias:
            if _contains_any_key_line(lines, block_start, block_end, subtree_keys):
                res.found = True
        i = block_end
    return res


# --- PHP heuristic --------------------------------------------------------

_PHP_BUILDER_BY_ALIAS = {
    "security": "SecurityConfig",
    "framework": "FrameworkConfig",
    "twig": "TwigConfig",
}


def _snake_to_camel(key: str) -> str:
    parts = key.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _singularize(word: str) -> str:
    """Cheap heuristic singularizer for ConfigBuilder prototyped-node methods.

    Symfony's `ConfigBuilderGenerator` names a prototyped array's adder after
    the *singular* (`firewalls:` -> `->firewall()`, `providers:` ->
    `->provider()`, `password_hashers:` -> `->passwordHasher()`,
    `trusted_proxies` has no prototyped form and stays plural
    (`->trustedProxies()`) — this only changes words that end in a plain "s"
    or "ies"; anything else (e.g. `accessControl`, `messenger`) is unaffected.
    """
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def _php_alias_call_re(alias: str) -> re.Pattern:
    a = re.escape(alias)
    return re.compile(
        rf"(?:->extension|loadFromExtension|prependExtensionConfig)\(\s*['\"]{a}['\"]"
    )


def _php_evidence(text: str, alias: str, subtree_keys: tuple[str, ...]) -> _FileEvidence:
    """Alias declared via its ConfigBuilder class name, `->extension('<alias>'`,
    `loadFromExtension('<alias>'`, `prependExtensionConfig('<alias>'`, or a raw
    `'<alias>' =>` key in an array-shaped config (`return [...]`,
    `App::config(...)`, a `'when@<env>'` entry) — not a service argument that
    merely contains the key. Subtree key present as a builder method call —
    camelCase or its ConfigBuilder singular (prototyped-node methods are
    singular, e.g. `->firewall('main')` for the `firewalls` key) — or an array
    key (snake_case or camelCase). An env-conditional block sets no env flag:
    only yaml `when@<env>` and the `packages/{dev,prod}/` directories do.
    """
    builder = _PHP_BUILDER_BY_ALIAS.get(alias)
    a = re.escape(alias)
    array_config = re.search(r"App::config\(|\breturn\s*\[|['\"]when@\w+['\"]\s*=>", text)
    alias_present = (
        bool(builder and re.search(rf"\b{re.escape(builder)}\b", text))
        or bool(_php_alias_call_re(alias).search(text))
        or bool(array_config and re.search(rf"['\"]{a}['\"]\s*=>", text))
    )
    if not alias_present:
        return _FileEvidence()
    found = not subtree_keys
    for key in subtree_keys:
        camel = _snake_to_camel(key)
        method_names = {camel, _singularize(camel)}
        if any(re.search(rf"\b{re.escape(m)}\s*\(", text) for m in method_names) or re.search(
            rf"['\"](?:{re.escape(key)}|{re.escape(camel)})['\"]\s*=>", text
        ):
            found = True
            break
    if not found:
        return _FileEvidence()
    return _FileEvidence(found=True)


# --- XML heuristic ---------------------------------------------------------

# Special cases where Symfony's XML schema names an element/attribute
# differently from a plain kebab-case of the yaml key. `{alias}` is
# substituted with the (escaped) alias at lookup time. Anything not listed
# here falls back to the generic kebab-element / bare-element / kebab-attribute
# guesses in `_xml_evidence`.
_XML_SUBTREE_MATCHERS: dict[str, tuple[str, ...]] = {
    "firewalls": (r"<(?:{alias}:)?firewall\b",),
    "access_control": (r"<(?:{alias}:)?rule\b",),
    "providers": (r"<(?:{alias}:)?provider\b",),
    "password_hashers": (r"<(?:{alias}:)?password-hasher\b",),
    "trusted_proxies": (r"\btrusted-proxies\s*=",),
    "trusted_hosts": (r"\btrusted-hosts\s*=",),
    "trusted_headers": (r"\btrusted-headers\s*=",),
    "autoescape": (r"\bautoescape\s*=",),
}


def _xml_subtree_patterns(alias: str, key: str) -> list[str]:
    special = _XML_SUBTREE_MATCHERS.get(key)
    if special:
        return [p.format(alias=re.escape(alias)) for p in special]
    kebab = key.replace("_", "-")
    return [
        rf"<{re.escape(alias)}:{re.escape(kebab)}\b",
        rf"<{re.escape(key)}\b",
        rf"\b{re.escape(kebab)}\s*=",
    ]


# XML schema namespace per extension alias (FrameworkBundle's is `symfony`).
_XML_SCHEMA_BY_ALIAS = {"framework": "symfony"}


def _xml_evidence(text: str, alias: str, subtree_keys: tuple[str, ...]) -> _FileEvidence:
    """Alias via its schema namespace — prefixed (`xmlns:<alias>="…/dic/<alias>"`)
    or default (`xmlns="…/dic/<alias>"`, the docs style with bare `<config>`) —
    or a `<<alias>:config` element; subtree key present per
    `_xml_subtree_patterns` (most SecurityBundle nodes are named differently
    from their yaml key — `<firewall>`, `<provider>`, `<password-hasher>`,
    `<rule>` for access_control; FrameworkBundle's trusted_* and twig's
    autoescape are attributes on `<config>`, not elements). A
    `<when env="…">` element sets no env flag.
    """
    schema = re.escape(_XML_SCHEMA_BY_ALIAS.get(alias, alias))
    alias_present = bool(
        re.search(rf"xmlns(?::{re.escape(alias)})?\s*=\s*[\"']https?://symfony\.com/schema/dic/{schema}[\"']", text)
        or re.search(rf"<{re.escape(alias)}:config\b", text)
    )
    if not alias_present:
        return _FileEvidence()
    found = not subtree_keys or any(
        re.search(p, text) for key in subtree_keys for p in _xml_subtree_patterns(alias, key)
    )
    if not found:
        return _FileEvidence()
    return _FileEvidence(found=True)


def find_config_evidence(project_root: Path, alias: str, subtree_keys: tuple[str, ...]) -> Evidence:
    """Scan `config/**/*.{yaml,yml,php,xml}` for files that declare `alias`
    AND mention at least one of `subtree_keys` inside it (empty
    `subtree_keys` ⇒ declaring `alias` is enough). Paths are
    project_root-relative, sorted, posix.

    `config/packages/test/**` is skipped entirely (by filename).
    `config/packages/dev/**` files and yaml `when@dev` blocks never enter
    `files` but set `dev_override`. `config/packages/prod/**` files and
    yaml `when@prod` blocks set `prod_override`; php/xml env conditionals are
    not recognised.
    """
    config_root = project_root / "config"
    if not config_root.is_dir():
        return Evidence(files=[], prod_override=False)

    try:
        project_resolved = project_root.resolve()
    except OSError:
        project_resolved = project_root

    matched: set[str] = set()
    dev_matched: set[str] = set()
    prod_override = False
    dev_override = False
    for path in sorted(config_root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in _CONFIG_EXTENSIONS:
            continue
        try:
            rel_from_config = path.relative_to(config_root).as_posix()
        except ValueError:
            continue
        if has_hidden_dir_segment(rel_from_config):
            continue
        parts = rel_from_config.split("/")
        env_dir = parts[1] if len(parts) >= 2 and parts[0] == "packages" else None
        if env_dir == "test":
            continue

        text = read_text_safe(path)
        if text is None or is_generated_config_reference(rel_from_config, text):
            continue

        if suffix in (".yaml", ".yml"):
            ev = _yaml_evidence(text, alias, subtree_keys)
        elif suffix == ".php":
            ev = _php_evidence(text, alias, subtree_keys)
        else:
            ev = _xml_evidence(text, alias, subtree_keys)

        if not (ev.found or ev.dev):
            continue
        try:
            rel = path.resolve().relative_to(project_resolved).as_posix()
        except (ValueError, OSError):
            rel = path.relative_to(project_root).as_posix()
        if env_dir == "dev":
            dev_override = True
            if ev.found:
                dev_matched.add(rel)
            continue
        dev_override = dev_override or ev.dev
        if not ev.found:
            continue
        matched.add(rel)
        if ev.prod or env_dir == "prod":
            prod_override = True

    return Evidence(
        files=sorted(matched), prod_override=prod_override, dev_override=dev_override,
        dev_files=sorted(dev_matched),
    )
