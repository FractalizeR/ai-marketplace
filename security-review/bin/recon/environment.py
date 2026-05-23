"""Static probe of a project's execution environment for console enrichment.

This module inspects a project tree (filesystem markers + composer.json +
Makefile + compose files) and the host (`php` on PATH) to decide HOW a
project's console (`php bin/console`, `php artisan`, ...) would best be run:
on the host, inside a docker-compose service, or via a Makefile target.

It produces FACTS (`EnvProbe`) plus ready-to-use command SUGGESTIONS
(`RunnerSuggestion`). It NEVER executes the project and NEVER raises on bad
input: every filesystem / subprocess access is wrapped, degrading to safe
defaults. The orchestrator consumes the suggestions (e.g. to drive an
AskUserQuestion) and a downstream sandbox builds the final argv from a
`cmd_template`.

`cmd_template` is the full shell command up to and including the entrypoint.
The sandbox (`sandbox.build_console_argv`) appends the console subcommand+flags
using this exact rule:
  - template contains literal "{args}" -> replace it with
    shlex.quote(" ".join(console_args)) (the space-joined args as ONE
    shell-quoted token), then shlex.split the whole string;
  - else -> shlex.split(template) then append console args as separate tokens.
So a host template is just the joined entrypoint ("php bin/console"); a
container template is "docker compose exec -T <service> php bin/console"; a
Makefile template that passes args via a make variable is
"make <target> CMD={args}" (the whole subcommand collapses into the CMD value).

This module is recipe-agnostic; the caller passes `console_entrypoint`
(e.g. ["php", "bin/console"]). Without it, facts are still gathered but no
runnable host/container suggestion can be built.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

PHP_VERSION_TIMEOUT_SECONDS = 5

# Compose filenames probed in order; the first existing one is scanned.
COMPOSE_FILENAMES: tuple[str, ...] = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)

# Makefile filenames probed in order; the first existing one is parsed.
MAKEFILE_FILENAMES: tuple[str, ...] = ("Makefile", "makefile", "GNUmakefile")

# Service-name keywords that strongly imply a PHP service (heuristic 1).
_PHP_SERVICE_NAME_RE = re.compile(r"php|fpm", re.IGNORECASE)

# Generic application service names (heuristic 3).
_GENERIC_APP_NAMES: frozenset[str] = frozenset(
    {"app", "web", "symfony", "laravel", "application"}
)

# Strings whose presence in a Makefile recipe body marks it as a console target.
_CONSOLE_BODY_MARKERS: tuple[str, ...] = (
    "bin/console",
    "artisan",
    "docker compose exec",
    "docker-compose exec",
)

# Make-variable names that look like an argument passthrough (case-insensitive).
_ARG_PASSTHROUGH_VARS: frozenset[str] = frozenset({"cmd", "args", "command", "c"})

# Parses `PHP X.Y.Z` (with optional extra build metadata) from `php --version`.
_PHP_VERSION_RE = re.compile(r"^PHP\s+(\d+\.\d+\.\d+)")

# A make-variable reference: $(NAME) or ${NAME}.
_MAKE_VAR_RE = re.compile(r"\$[({]\s*([A-Za-z_][A-Za-z0-9_]*)\s*[)}]")

# A Makefile target line: `name:` but NOT `name :=` (an assignment).
_MAKE_TARGET_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._/-]*)\s*:(?!=)")


# ---------------------------------------------------------------------------
# Dataclasses.
# ---------------------------------------------------------------------------


@dataclass
class RunnerSuggestion:
    """One concrete way to run the project's console.

    `mode`         one of "host" | "container" | "makefile".
    `cmd_template` full command template INCLUDING the entrypoint; may contain
                   the literal "{args}" placeholder (see module docstring).
    `label`        short human label for an AskUserQuestion option.
    `source`       provenance: "host" | "docker-compose:<service>" |
                   "makefile:<target>".
    `detail`       (makefile only) the parsed recipe body, for transparency,
                   plus an optional note when the target can't take enrichment
                   subcommands.
    """

    mode: str
    cmd_template: str
    label: str
    source: str
    detail: Optional[str] = None


@dataclass
class EnvProbe:
    """Facts gathered about the execution environment + ranked suggestions."""

    containerized: bool
    container_signals: list[str] = field(default_factory=list)
    host_php_present: bool = False
    host_php_version: Optional[str] = None
    suggested_php_service: Optional[str] = None
    suggestions: list[RunnerSuggestion] = field(default_factory=list)
    reason: str = ""


# Internal helper carrying parsed compose-service facts.
@dataclass
class _ComposeService:
    name: str
    image: Optional[str] = None
    has_build: bool = False


# Internal helper carrying parsed Makefile console-target facts.
@dataclass
class _MakeConsoleTarget:
    target: str
    body: str
    arg_var: Optional[str]  # passthrough make-variable name, if any


# ---------------------------------------------------------------------------
# Host PHP detection.
# ---------------------------------------------------------------------------


def _detect_host_php() -> tuple[bool, Optional[str]]:
    """Return (present, version). Never raises.

    `present` is whether `php` is on PATH. `version` parses the first line of
    `php --version` (`PHP X.Y.Z`) into "X.Y.Z"; any failure yields None.
    """
    try:
        present = shutil.which("php") is not None
    except Exception:
        return False, None
    if not present:
        return False, None
    version: Optional[str] = None
    try:
        proc = subprocess.run(
            ["php", "--version"],
            capture_output=True,
            text=True,
            timeout=PHP_VERSION_TIMEOUT_SECONDS,
        )
        first_line = (proc.stdout or "").strip().splitlines()
        if first_line:
            m = _PHP_VERSION_RE.match(first_line[0].strip())
            if m:
                version = m.group(1)
    except Exception:
        version = None
    return True, version


# ---------------------------------------------------------------------------
# Container signal detection.
# ---------------------------------------------------------------------------


def _detect_container_signals(project_root: Path) -> list[str]:
    """Collect ordered, deduped container signal tokens. Never raises."""
    signals: list[str] = []

    def _add(token: str) -> None:
        if token not in signals:
            signals.append(token)

    # Compose files (record by filename).
    for name in COMPOSE_FILENAMES:
        try:
            if (project_root / name).is_file():
                _add(name)
        except Exception:
            continue

    # Dockerfile.
    try:
        if (project_root / "Dockerfile").is_file():
            _add("Dockerfile")
    except Exception:
        pass

    # ddev (directory or its config file).
    try:
        ddev_dir = project_root / ".ddev"
        if ddev_dir.is_dir() or (ddev_dir / "config.yaml").is_file():
            _add(".ddev")
    except Exception:
        pass

    # Lando.
    try:
        if (project_root / ".lando.yml").is_file():
            _add(".lando.yml")
    except Exception:
        pass

    # Devcontainer (directory or root file).
    try:
        if (project_root / ".devcontainer").is_dir() or (
            project_root / ".devcontainer.json"
        ).is_file():
            _add(".devcontainer")
    except Exception:
        pass

    # Laravel Sail (composer dependency).
    try:
        if _composer_requires(project_root, "laravel/sail"):
            _add("laravel/sail")
    except Exception:
        pass

    return signals


def _composer_requires(project_root: Path, package: str) -> bool:
    """True iff composer.json lists `package` in require / require-dev.

    Tolerant: malformed / missing composer.json -> False, never raises.
    """
    try:
        raw = (project_root / "composer.json").read_text(
            encoding="utf-8", errors="replace"
        )
    except Exception:
        return False
    try:
        data = json.loads(raw)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    for key in ("require", "require-dev"):
        section = data.get(key)
        if isinstance(section, dict) and package in section:
            return True
    return False


# ---------------------------------------------------------------------------
# Compose service extraction (tolerant scanner — NOT a YAML parser).
# ---------------------------------------------------------------------------


def _first_existing(project_root: Path, names: tuple[str, ...]) -> Optional[Path]:
    """Return the first existing file among `names` under project_root."""
    for name in names:
        try:
            p = project_root / name
            if p.is_file():
                return p
        except Exception:
            continue
    return None


def _leading_indent(line: str) -> int:
    """Count leading spaces (tabs counted as one space each). Tolerant."""
    count = 0
    for ch in line:
        if ch == " " or ch == "\t":
            count += 1
        else:
            break
    return count


def _parse_compose_services(compose_path: Path) -> list[_ComposeService]:
    """Best-effort scan of a compose file's top-level `services:` map.

    Indentation-based, deliberately NOT a strict YAML parser: real compose
    files carry nested maps/lists/anchors that a strict parser would choke on.
    We only need service names plus optional `image:` and presence of `build:`.
    Anything unparseable is ignored. Never raises.
    """
    try:
        text = compose_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    lines = text.splitlines()
    services: list[_ComposeService] = []

    # Phase 1: locate the top-level (indent 0) `services:` line.
    services_idx: Optional[int] = None
    for i, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if _leading_indent(line) == 0 and re.match(r"services\s*:", line.strip()):
            services_idx = i
            break
    if services_idx is None:
        return []

    # Phase 2: gather lines belonging to the services block (until next indent-0).
    block: list[str] = []
    for line in lines[services_idx + 1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            block.append(line)
            continue
        if _leading_indent(line) == 0:
            break  # next top-level key ends the services block.
        block.append(line)

    # Phase 3: determine the child indentation (first non-blank line's indent).
    child_indent: Optional[int] = None
    for line in block:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        child_indent = _leading_indent(line)
        break
    if child_indent is None:
        return []

    # Phase 4: collect service keys at child_indent; capture image/build inside.
    current: Optional[_ComposeService] = None
    for line in block:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = _leading_indent(line)
        stripped = line.strip()
        if indent == child_indent:
            # A service key looks like `name:` (optionally `name: {inline}`).
            # Require an alphanumeric first char: a name starting with `-`
            # would be parsed by `docker compose exec` as a flag.
            m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*:", stripped)
            if m:
                current = _ComposeService(name=m.group(1))
                services.append(current)
            else:
                current = None  # list item / scalar at this indent — not a service.
        elif indent > child_indent and current is not None:
            # Inside a service block: look for image:/build: keys.
            im = re.match(r"image\s*:\s*(.+)$", stripped)
            if im:
                val = im.group(1).strip().strip("'\"")
                if val:
                    current.image = val
                continue
            if re.match(r"build\s*:", stripped):
                current.has_build = True
        # indent < child_indent inside the block shouldn't happen; ignore.

    return services


def _pick_php_service(services: list[_ComposeService]) -> Optional[str]:
    """Heuristic, first match wins. Returns a service name or None."""
    if not services:
        return None
    # (1) name matches /php|fpm/i.
    for svc in services:
        if _PHP_SERVICE_NAME_RE.search(svc.name):
            return svc.name
    # (2) image contains "php".
    for svc in services:
        if svc.image and "php" in svc.image.lower():
            return svc.name
    # (3) name in generic app names.
    for svc in services:
        if svc.name.lower() in _GENERIC_APP_NAMES:
            return svc.name
    # (4) has a build: key.
    for svc in services:
        if svc.has_build:
            return svc.name
    # (5) first service.
    return services[0].name


# ---------------------------------------------------------------------------
# Makefile console-target parsing.
# ---------------------------------------------------------------------------


def _parse_make_console_targets(makefile_path: Path) -> list[_MakeConsoleTarget]:
    """Parse console-running targets from a Makefile. Never raises.

    A target line matches `^name:` (not `name:=`). Its recipe body is the run
    of subsequent TAB-indented lines (stopping at the first non-tab, non-blank
    line). A target is a console target iff its body references one of the
    known console markers. The passthrough make-variable (CMD/ARGS/...) is
    detected for arg forwarding.
    """
    try:
        text = makefile_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    lines = text.splitlines()
    targets: list[_MakeConsoleTarget] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = _MAKE_TARGET_RE.match(line)
        if not m:
            i += 1
            continue
        target_name = m.group(1)
        # Collect the recipe body: subsequent TAB-prefixed lines.
        body_lines: list[str] = []
        j = i + 1
        while j < n:
            bl = lines[j]
            if bl.startswith("\t"):
                body_lines.append(bl[1:])  # strip the leading recipe TAB.
                j += 1
                continue
            if bl.strip() == "":
                # Blank line ends the recipe body (standard make behavior).
                break
            # Non-tab, non-blank line: end of this recipe.
            break
        body = "\n".join(body_lines)
        if body_lines and _body_is_console(body):
            arg_var = _find_passthrough_var(body)
            targets.append(
                _MakeConsoleTarget(target=target_name, body=body, arg_var=arg_var)
            )
        i = j if j > i else i + 1
    return targets


def _body_is_console(body: str) -> bool:
    """True iff a recipe body references a console runner."""
    lowered = body.lower()
    for marker in _CONSOLE_BODY_MARKERS:
        if marker in lowered:
            return True
    # `exec ` near `console` — heuristic for a docker-style exec into console.
    if "console" in lowered and "exec " in lowered:
        return True
    return False


def _find_passthrough_var(body: str) -> Optional[str]:
    """Return the actual name of the first arg-passthrough make-variable, or None.

    Matches $(NAME) / ${NAME} where NAME (case-insensitive) is one of
    CMD / ARGS / COMMAND / C. Returns the variable name as written in the body.
    """
    for m in _MAKE_VAR_RE.finditer(body):
        name = m.group(1)
        if name.lower() in _ARG_PASSTHROUGH_VARS:
            return name
    return None


# ---------------------------------------------------------------------------
# Suggestion building.
# ---------------------------------------------------------------------------


def _build_host_suggestion(
    entrypoint_str: str, php_version: Optional[str]
) -> RunnerSuggestion:
    ver = php_version if php_version else "?"
    return RunnerSuggestion(
        mode="host",
        cmd_template=entrypoint_str,
        label=f"Run on host (php {ver})",
        source="host",
    )


def _build_container_suggestions(
    services: list[_ComposeService],
    suggested: str,
    entrypoint_str: str,
) -> list[RunnerSuggestion]:
    """Suggested service first, then bounded alternatives (one per other service)."""
    out: list[RunnerSuggestion] = []
    ordered = [suggested] + [s.name for s in services if s.name != suggested]
    for name in ordered:
        cmd = f"docker compose exec -T {name} {entrypoint_str}"
        out.append(
            RunnerSuggestion(
                mode="container",
                cmd_template=cmd,
                label=f"docker compose exec -T {name}",
                source=f"docker-compose:{name}",
            )
        )
    return out


def _build_makefile_suggestions(
    make_targets: list[_MakeConsoleTarget],
) -> list[RunnerSuggestion]:
    out: list[RunnerSuggestion] = []
    for mt in make_targets:
        if mt.arg_var:
            cmd = f"make {mt.target} {mt.arg_var}={{args}}"
            detail = mt.body
        else:
            cmd = f"make {mt.target}"
            detail = (
                f"{mt.body}\n"
                "[note] no argument-passthrough variable detected; this target "
                "may not accept enrichment subcommands."
            )
        out.append(
            RunnerSuggestion(
                mode="makefile",
                cmd_template=cmd,
                label=f"make {mt.target}",
                source=f"makefile:{mt.target}",
                detail=detail,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Public entry point.
# ---------------------------------------------------------------------------


def probe_environment(
    project_root: Path,
    *,
    console_entrypoint: Optional[list[str]] = None,
) -> EnvProbe:
    """Statically probe `project_root` for how to run its console.

    Best-effort: never raises. Without `console_entrypoint`, facts are still
    gathered but host/container suggestions cannot be built (only Makefile
    suggestions, which embed their own command).
    """
    try:
        project_root = Path(project_root)
    except Exception:
        # Degenerate input — return an empty, safe probe.
        return EnvProbe(
            containerized=False,
            reason="invalid project_root; nothing probed",
        )

    container_signals = _detect_container_signals(project_root)
    containerized = bool(container_signals)
    host_php_present, host_php_version = _detect_host_php()

    # Compose service extraction (only if a compose file exists).
    compose_path = _first_existing(project_root, COMPOSE_FILENAMES)
    services: list[_ComposeService] = []
    suggested_service: Optional[str] = None
    if compose_path is not None:
        services = _parse_compose_services(compose_path)
        suggested_service = _pick_php_service(services)

    # Makefile console targets.
    makefile_path = _first_existing(project_root, MAKEFILE_FILENAMES)
    make_targets: list[_MakeConsoleTarget] = []
    if makefile_path is not None:
        make_targets = _parse_make_console_targets(makefile_path)

    # Entrypoint string (only when provided).
    entrypoint_str: Optional[str] = None
    if console_entrypoint:
        try:
            entrypoint_str = shlex.join(console_entrypoint)
        except Exception:
            entrypoint_str = None

    # Build the three suggestion groups (subject to buildability).
    host_sug: list[RunnerSuggestion] = []
    if host_php_present and entrypoint_str is not None:
        host_sug = [_build_host_suggestion(entrypoint_str, host_php_version)]

    container_sug: list[RunnerSuggestion] = []
    if compose_path is not None and suggested_service is not None and entrypoint_str is not None:
        container_sug = _build_container_suggestions(
            services, suggested_service, entrypoint_str
        )

    makefile_sug = _build_makefile_suggestions(make_targets)

    # Ordering: containerized -> [container, makefile, host]; else [host, makefile, container].
    if containerized:
        suggestions = [*container_sug, *makefile_sug, *host_sug]
    else:
        suggestions = [*host_sug, *makefile_sug, *container_sug]

    reason = _build_reason(
        containerized=containerized,
        container_signals=container_signals,
        suggested_service=suggested_service,
        host_php_present=host_php_present,
        host_php_version=host_php_version,
        make_targets=make_targets,
        compose_present=compose_path is not None,
    )

    return EnvProbe(
        containerized=containerized,
        container_signals=container_signals,
        host_php_present=host_php_present,
        host_php_version=host_php_version,
        suggested_php_service=suggested_service,
        suggestions=suggestions,
        reason=reason,
    )


def _build_reason(
    *,
    containerized: bool,
    container_signals: list[str],
    suggested_service: Optional[str],
    host_php_present: bool,
    host_php_version: Optional[str],
    make_targets: list[_MakeConsoleTarget],
    compose_present: bool,
) -> str:
    """Compose a concise human-readable summary of the findings."""
    parts: list[str] = []
    if containerized:
        parts.append(f"containerized ({', '.join(container_signals)})")
    else:
        parts.append("no container signals")
    if compose_present:
        if suggested_service:
            parts.append(f"suggested php service '{suggested_service}'")
        else:
            parts.append("compose present but no service identified")
    if make_targets:
        names = ", ".join(mt.target for mt in make_targets)
        parts.append(f"makefile console target(s): {names}")
    if host_php_present:
        if host_php_version:
            parts.append(f"host php {host_php_version} present")
        else:
            parts.append("host php present (version unknown)")
    else:
        parts.append("host php absent")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    """Standalone probe CLI. Prints JSON to stdout and always exits 0.

    The probe is best-effort; even on unexpected internal failure we emit a
    valid JSON object and return 0 (never a non-zero status).
    """
    parser = argparse.ArgumentParser(
        description="Statically probe how to run a project's console "
        "(host / container / makefile).",
    )
    parser.add_argument(
        "project_root",
        type=str,
        help="Path to the project root to probe.",
    )
    parser.add_argument(
        "--console-entrypoint",
        type=str,
        default="php bin/console",
        help="Console entrypoint, shlex-split into argv "
        "(default: 'php bin/console'). Pass an empty string to omit it.",
    )
    args = parser.parse_args(argv)

    try:
        raw_entry = args.console_entrypoint
        entrypoint = shlex.split(raw_entry) if raw_entry.strip() else None
    except Exception:
        entrypoint = None

    try:
        probe = probe_environment(
            Path(args.project_root), console_entrypoint=entrypoint
        )
    except Exception as exc:  # defensive: probe should never raise, but be safe.
        print(
            json.dumps(
                {
                    "containerized": False,
                    "container_signals": [],
                    "host_php_present": False,
                    "host_php_version": None,
                    "suggested_php_service": None,
                    "suggestions": [],
                    "reason": f"probe failed: {exc}",
                },
                indent=2,
            )
        )
        return 0

    print(json.dumps(dataclasses.asdict(probe), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
