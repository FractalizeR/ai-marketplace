#!/usr/bin/env python3
"""Run snapshot — which build, harness and models produced an audit.

Written once, at wave planning (`plan_waves.py --save-run-info`), to
`<review_root>/run_info.json`; dedupe only reads it. It must not be derived at
dedupe time: after triage the user re-runs `dedupe_findings.py --verdicts-in`,
for a Codex audit usually from the Claude plugin tree, and a later
`frsr --models` may rewrite `.model_map.json` — either would re-attribute the
run and change the bytes of findings.json that triage is bound to.

Harness and version come from the Codex build stamp `<core>/build_info.json`;
without it the tree is the Claude plugin and the version is `plugin.json`'s.
The harness is never inferred from `.model_map.json`: a Claude run in a
directory Codex used before would claim the Codex models.

CLI (for launchers):
    python3 run_info.py --codex-config
    stdout = {"path", "model", "model_reasoning_effort"} of the Codex
    config.toml ($CODEX_HOME or ~/.codex), values null when unknown.

stdlib only; stays importable on Python 3.9 (frsr runs whatever python3 is on
PATH, and macOS ships 3.9 without tomllib — the config then reads as unknown).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shared.model_resolver import LABEL_TO_TIER, inspect_persisted  # noqa: E402

RUN_INFO_NAME = "run_info.json"
BUILD_INFO_NAME = "build_info.json"
UNKNOWN = "unknown"

# Set by frsr, which starts the Codex orchestrator with `-m <high>`.
ORCHESTRATOR_ENV = "FR_SECURITY_ORCHESTRATOR_MODEL"

# Claude Code resolves these aliases to concrete ids; the plugin never sees them.
CLAUDE_TIER_LABELS = {tier: label for label, tier in LABEL_TO_TIER.items()}


@dataclass(frozen=True)
class RunInfo:
    plugin_version: str = UNKNOWN
    harness: str = UNKNOWN
    bundle_version: str | None = None
    orchestrator: str = UNKNOWN
    orchestrator_source: str = UNKNOWN  # frsr | self-reported | unknown
    high: str = UNKNOWN
    fast: str = UNKNOWN
    reasoning_effort: str = UNKNOWN
    config_model: str | None = None
    tier_waves: dict = field(default_factory=dict)

    def is_recorded(self) -> bool:
        return self.harness != UNKNOWN or self.plugin_version != UNKNOWN or bool(self.tier_waves)

    def as_dict(self) -> dict:
        return {
            "plugin_version": self.plugin_version,
            "harness": self.harness,
            "bundle_version": self.bundle_version,
            "models": {
                "orchestrator": self.orchestrator,
                "orchestrator_source": self.orchestrator_source,
                "high": self.high,
                "fast": self.fast,
            },
            "reasoning_effort": self.reasoning_effort,
            "config_model": self.config_model,
            "tier_waves": {t: sorted(w) for t, w in sorted(self.tier_waves.items())},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RunInfo":
        """Raises ValueError on a wrong shape (`load` turns it into None)."""
        models = d.get("models", {})
        tier_waves = d.get("tier_waves", {})
        if not isinstance(models, dict) or not isinstance(tier_waves, dict):
            raise ValueError("`models` and `tier_waves` must be objects")
        for key, waves in tier_waves.items():
            if not isinstance(waves, list) or not all(isinstance(w, str) for w in waves):
                raise ValueError(f"`tier_waves.{key}` must be a list of strings")

        def text(src: dict, key: str, *, optional: bool = False):
            value = src.get(key)
            if value is None:
                return None if optional else UNKNOWN
            if not isinstance(value, str):
                raise ValueError(f"`{key}` must be a string")
            return value or (None if optional else UNKNOWN)

        return cls(
            plugin_version=text(d, "plugin_version"),
            harness=text(d, "harness"),
            bundle_version=text(d, "bundle_version", optional=True),
            orchestrator=text(models, "orchestrator"),
            orchestrator_source=text(models, "orchestrator_source"),
            high=text(models, "high"),
            fast=text(models, "fast"),
            reasoning_effort=text(d, "reasoning_effort"),
            config_model=text(d, "config_model", optional=True),
            tier_waves={t: list(w) for t, w in tier_waves.items()},
        )

def _read_json(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None


# ---------------------------------------------------------------------------
# Codex config.toml — only the two keys we report, via tomllib. Without it
# (Python < 3.11, e.g. macOS /usr/bin/python3) both are unknown: a hand-rolled
# TOML subset misreads valid configs, and a wrong effort is worse than none.
# ---------------------------------------------------------------------------

try:
    import tomllib
except ImportError:  # pragma: no cover - depends on the interpreter
    tomllib = None


def codex_home() -> Path:
    env = os.environ.get("CODEX_HOME")
    return Path(env) if env else Path.home() / ".codex"


def read_codex_config(home: Path) -> dict:
    """`model` / `model_reasoning_effort` in effect; a `profile = "x"` selects
    `[profiles.x]`, whose keys override the top-level ones. Unknown → None."""
    path = Path(home) / "config.toml"
    out = {"path": str(path), "model": None, "model_reasoning_effort": None}
    if tomllib is None:
        return out
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return out
    effective = {k: data.get(k) for k in ("model", "model_reasoning_effort")}
    profile = data.get("profile")
    profiles = data.get("profiles")
    if isinstance(profile, str) and isinstance(profiles, dict) and isinstance(profiles.get(profile), dict):
        effective.update({k: v for k, v in profiles[profile].items() if k in effective})
    for key, value in effective.items():
        out[key] = value if isinstance(value, str) and value else None
    return out


# ---------------------------------------------------------------------------
# Snapshot.
# ---------------------------------------------------------------------------


def tier_waves_from_plan(plan: list[dict] | None) -> dict:
    out: dict[str, set[str]] = {}
    for entry in plan or []:
        if not isinstance(entry, dict):
            continue
        tier = LABEL_TO_TIER.get(entry.get("model"))
        wave = entry.get("wave_id")
        if tier and isinstance(wave, str) and wave:
            out.setdefault(tier, set()).add(wave)
    return {t: sorted(w) for t, w in out.items()}


def collect(
    *,
    plugin_root: Path,
    review_root: Path,
    plan: list[dict] | None,
    orchestrator_model: str | None,
    home: Path | None = None,
) -> RunInfo:
    plugin_root = Path(plugin_root)
    tier_waves = tier_waves_from_plan(plan)
    stamp = _read_json(plugin_root / BUILD_INFO_NAME)
    if isinstance(stamp, dict) and stamp.get("harness") == "codex":
        status, tier_map = inspect_persisted(Path(review_root))
        high = tier_map.high if status == "usable" else UNKNOWN
        fast = tier_map.fast if status == "usable" else UNKNOWN
        via_frsr = os.environ.get(ORCHESTRATOR_ENV)
        if via_frsr:
            orchestrator, source = via_frsr, "frsr"
        elif orchestrator_model:
            orchestrator, source = orchestrator_model, "self-reported"
        else:
            orchestrator, source = UNKNOWN, UNKNOWN
        cfg = read_codex_config(home if home is not None else codex_home())
        return RunInfo(
            plugin_version=str(stamp.get("plugin_version") or UNKNOWN),
            harness="codex",
            bundle_version=stamp.get("bundle_version"),
            orchestrator=orchestrator,
            orchestrator_source=source,
            high=high,
            fast=fast,
            reasoning_effort=cfg["model_reasoning_effort"] or UNKNOWN,
            config_model=cfg["model"],
            tier_waves=tier_waves,
        )
    manifest = _read_json(plugin_root / "plugin.json")
    if isinstance(manifest, dict) and manifest.get("version"):
        return RunInfo(
            plugin_version=str(manifest["version"]),
            harness="claude",
            orchestrator=orchestrator_model or UNKNOWN,
            orchestrator_source="self-reported" if orchestrator_model else UNKNOWN,
            high=CLAUDE_TIER_LABELS["high"],
            fast=CLAUDE_TIER_LABELS["fast"],
            tier_waves=tier_waves,
        )
    return RunInfo(tier_waves=tier_waves)


def save(info: RunInfo, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(info.as_dict(), indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".run_info.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def load(path: Path) -> RunInfo | None:
    """The snapshot at `path`; None when missing, or — with a warning, since the
    report must still be written — unparseable or mis-shaped."""
    path = Path(path)
    if not path.is_file():
        return None
    data = _read_json(path)
    try:
        if not isinstance(data, dict):
            raise ValueError("not a JSON object")
        return RunInfo.from_dict(data)
    except ValueError as exc:
        print(f"run_info: WARNING: ignoring {path}: {exc}", file=sys.stderr)
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run snapshot helpers")
    parser.add_argument("--codex-config", action="store_true",
                        help="print the model / reasoning effort in effect in the Codex config.toml")
    args = parser.parse_args(argv)
    if not args.codex_config:
        parser.error("nothing to do (pass --codex-config)")
    print(json.dumps(read_codex_config(codex_home()), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
