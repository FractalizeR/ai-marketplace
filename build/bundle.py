"""Bundle the portable engine + authored runtime configs into an OpenCode dist tree.

An OpenCode artifact is not just the derived command/agent prose — workers must
read ``bin/`` + ``checklists/`` with no out-of-worktree hop, so the build copies
the engine once into ``<out>/core/`` (= ``${CORE_ROOT}``) and drops the authored
runtime configs (``opencode.json`` / ``adapter.json`` / ``INSTALL.md``) beside it.

Deterministic and idempotent: a filtered, sorted walk copies byte-identical
content across runs (``shutil.copy2`` carries source mtimes, so a ``diff -r`` of
two builds is empty). Test fixtures (``tests/``) and bytecode caches
(``__pycache__``) are excluded at any depth — the former is dead weight at
runtime, the latter is non-deterministic.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from gates import check_dispatch_template

# Filtered out of the runtime engine at any depth.
_EXCLUDE_DIRS = frozenset({"tests", "__pycache__"})
# Individual junk files that would otherwise cause cross-machine non-determinism.
_EXCLUDE_NAMES = frozenset({".DS_Store"})
_EXCLUDE_SUFFIXES = frozenset({".pyc", ".pyo"})
# The authored runtime configs, copied verbatim beside core/.
STATIC_CONFIGS = ("opencode.json", "adapter.json", "INSTALL.md")
# A dedicated sentinel written into every emitted bundle; a directory carrying it
# is a prior bundle (safe to replace under --out). It must be a name that CANNOT
# occur in the authored source tree — `adapter.json` would falsely mark
# `harness/opencode/` (a git-tracked source dir) as a clobber-safe bundle.
BUNDLE_MARKER = ".fr-opencode-bundle"

_ADAPTER_REQUIRED = frozenset({
    "entrypoint_kind", "fanout", "worker_invocation", "core_root",
    "model_discovery_cmd", "tier_defaults", "interactive_gates",
    "checkpoint_binding", "permission_config", "manifest_template",
    "marketplace_target",
})
# Concrete permission keys the OpenCode config must pin (a mistyped key would fail
# open silently at runtime, so assert the specific keys, not just "parses").
_PERM_REQUIRED = ("external_directory", "bash", "task", "webfetch", "websearch")
# Security-posture values that must hold, not just be present: no in-process
# fan-out (AD4) and no network egress (offline auditor, as INSTALL.md promises).
_PERM_MUST_DENY = ("task", "webfetch", "websearch")


def _iter_bundled_files(src_root: Path):
    """Yield (abs_path, rel_path) for every runtime file under ``src_root``,
    sorted, excluding test fixtures / bytecode caches / junk files at any depth.

    Note: ``rglob`` + ``is_file()`` follows symlinks; the engine tree carries none
    today, so a symlinked file would be copied as a plain file (harmless), and a
    symlinked dir cycle would be surfaced by ``rglob`` rather than silently looped."""
    for path in sorted(src_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(src_root)
        if any(part in _EXCLUDE_DIRS for part in rel.parts):
            continue
        if path.name in _EXCLUDE_NAMES or path.suffix in _EXCLUDE_SUFFIXES:
            continue
        yield path, rel


def bundle_core(out_root: Path, *, plugin_root: Path) -> list[Path]:
    """Copy ``bin/`` (minus tests/__pycache__) + ``checklists/`` into
    ``<out_root>/core/``. Returns the sorted list of written destination paths."""
    core = out_root / "core"
    written: list[Path] = []
    for sub in ("bin", "checklists"):
        src = plugin_root / sub
        if not src.is_dir():
            raise FileNotFoundError(f"cannot bundle: missing {src}")
        for path, rel in _iter_bundled_files(src):
            dest = core / sub / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            written.append(dest)
    return sorted(written)


def copy_static_configs(out_root: Path, *, harness_root: Path) -> list[Path]:
    """Copy the authored runtime configs into ``<out_root>``. Returns written paths."""
    out_root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name in STATIC_CONFIGS:
        src = harness_root / name
        if not src.is_file():
            raise FileNotFoundError(f"missing authored config: {src}")
        dest = out_root / name
        shutil.copy2(src, dest)
        written.append(dest)
    return sorted(written)


def validate_static_configs(harness_root: Path) -> list[str]:
    """Return violations (empty = ok) for the authored OpenCode configs.

    Called in both ``--mode=check`` (against the in-git authored files) and before
    ``--mode=write`` (fail-closed — never materialize a bundle with a broken config).
    """
    problems: list[str] = []
    problems += _validate_adapter(harness_root / "adapter.json")
    problems += _validate_opencode_perms(harness_root / "opencode.json")
    return problems


def _validate_adapter(path: Path) -> list[str]:
    data = _load_json(path)
    if isinstance(data, str):
        return [data]
    if not isinstance(data, dict):
        return [f"{path.name} is not a JSON object"]
    problems: list[str] = []
    missing = _ADAPTER_REQUIRED - data.keys()
    if missing:
        problems.append(f"{path.name} missing keys: {sorted(missing)}")
    if data.get("entrypoint_kind") != "command":
        problems.append(f"{path.name} entrypoint_kind must be 'command'")
    if data.get("fanout") != "external_process":
        problems.append(f"{path.name} fanout must be 'external_process'")
    # worker_invocation must pass the same *structural* dispatch check the section
    # templates do (opencode run + --agent + -m). This is a structural guard only —
    # it does not assert field-for-field parity with the templates (adapter.json is
    # descriptive metadata, "not read by OpenCode at runtime" per INSTALL.md).
    problems += [f"{path.name} worker_invocation: {v}"
                 for v in check_dispatch_template(str(data.get("worker_invocation", "")))]
    return problems


def _validate_opencode_perms(path: Path) -> list[str]:
    cfg = _load_json(path)
    if isinstance(cfg, str):
        return [cfg]
    if not isinstance(cfg, dict):
        return [f"{path.name} is not a JSON object"]
    perm = cfg.get("permission")
    if not isinstance(perm, dict):
        return [f"{path.name} missing object `permission` block"]
    problems: list[str] = []
    for key in _PERM_REQUIRED:
        if key not in perm:
            problems.append(f"{path.name} permission missing key: {key!r}")
    # Values, not just presence: a stray `webfetch: "allow"` would silently break
    # the offline posture INSTALL.md guarantees, so pin the deny-trio explicitly.
    for key in _PERM_MUST_DENY:
        if key in perm and perm.get(key) != "deny":
            problems.append(f"{path.name} permission.{key} must be 'deny', got "
                            f"{perm.get(key)!r}")
    return problems


def _load_json(path: Path):
    """Parse JSON at ``path``; return the value, or an error string on failure."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return f"{path.name} unreadable/invalid: {exc}"
