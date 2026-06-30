#!/usr/bin/env python3
"""AD7 model resolver — discover -> propose -> confirm -> persist a tier map.

A `TierMap` is a `{high, fast}` pair of concrete model ids that downstream
`dispatch` looks up via `LABEL_TO_TIER` (plan_waves emits `opus|sonnet` labels).

Harness specifics enter as PARAMETERS, never imports (AD-2A3): `discovery_cmd`,
a `normalize` callable, `tier_defaults`. The Claude path uses no discovery at all
(static {high: opus, fast: sonnet}). OpenCode/Codex pass a discovery command whose
output is shape-sniffed (JSON list vs newline list). Subprocess is the single
injected seam — the `runner` callable (AD-2A2); tests never spawn a real CLI.

CLI:
    python3 <core_root>/bin/shared/model_resolver.py --discovery-cmd <c>
        [--tier-defaults high=<id>,fast=<id>] --review-root P
        [--models high=<id>,fast=<id>] [--remodel] [--interactive]
    stdout = resolved TierMap JSON + persisted path.
    exit 0 ok / 2 ResolverError (prints available ids).

stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

# Engine invocation convention: bin/ is NOT a package. Put `.../bin` on sys.path
# so `from shared.contracts import ...` resolves (mirrors dedupe_findings.py).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.contracts import ResolverError, Runner, RunResult  # noqa: E402

LABEL_TO_TIER = {"opus": "high", "sonnet": "fast"}
TIERS = ("high", "fast")

# Per-tier name-pattern ranking. FAST patterns are tried first so a model like
# "pro-lite" lands in `fast` (lite wins over pro) — see propose_tier_map.
_FAST_PATTERNS = ("flash", "mini", "lite", "haiku", "small")
_HIGH_PATTERNS = ("reasoner", "pro", "opus", "max", "large")

_PROVENANCE_RANK = {"cli": 3, "persisted": 2, "proposed": 1, "collapsed": 0}

# A model-discovery command should answer fast; never hang forever (L6).
DISCOVERY_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# Data carriers.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelInfo:
    """One discovered model. `id` is the normalized identifier dispatch uses."""

    id: str
    raw: str
    provider: str | None
    context_window: int | None


@dataclass(frozen=True)
class TierMap:
    """Resolved {high, fast} model ids plus a provenance tag.

    provenance ∈ {"cli", "persisted", "proposed", "collapsed"}. For a composite
    map (e.g. high from persisted, fast from proposed) the highest-priority
    contributing source wins (cli > persisted > proposed > collapsed).
    """

    high: str
    fast: str
    provenance: str

    def as_dict(self) -> dict:
        return {"high": self.high, "fast": self.fast, "provenance": self.provenance}

    @classmethod
    def from_dict(cls, d: dict) -> "TierMap":
        return cls(
            high=d["high"],
            fast=d["fast"],
            provenance=d.get("provenance", "persisted"),
        )


def _combine_provenance(*sources: str) -> str:
    """Highest-priority source wins (DeepSeek #14)."""
    return max(sources, key=lambda s: _PROVENANCE_RANK.get(s, -1))


# ---------------------------------------------------------------------------
# Default normalize.
# ---------------------------------------------------------------------------


def default_normalize(raw: str) -> str:
    """Identity-ish normalize: strip whitespace. Harnesses inject their own."""
    return raw.strip()


# ---------------------------------------------------------------------------
# Subprocess seam — default runner.
# ---------------------------------------------------------------------------


def default_runner(argv, timeout):  # pragma: no cover - thin stdlib wrapper
    """Thin `subprocess.run` wrapper producing a `RunResult`.

    Tests NEVER use this — they inject a fake runner. On timeout the stdlib
    terminates the direct child (and, with start_new_session, we make a process
    group so the tree can be reaped); returncode None signals timed_out.
    """
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return RunResult(
            returncode=None,
            stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
            stderr=exc.stderr or "" if isinstance(exc.stderr, str) else "",
            timed_out=True,
        )
    except OSError as exc:
        # Spawn failure → non-zero RunResult so discover_models raises a
        # ResolverError (not a bare OSError) on a missing discovery binary (H1).
        return RunResult(returncode=127, stdout="", stderr=str(exc), timed_out=False)
    return RunResult(
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        timed_out=False,
    )


# ---------------------------------------------------------------------------
# Discovery.
# ---------------------------------------------------------------------------


def _parse_json_models(data, normalize) -> list[ModelInfo] | None:
    """codex shape: {"models": [{"slug": ..., "provider": ..., ...}, ...]} or a
    bare list of such objects. Returns None if the shape does not match."""
    if isinstance(data, dict):
        items = data.get("models")
    elif isinstance(data, list):
        items = data
    else:
        return None
    if not isinstance(items, list):
        return None
    out: list[ModelInfo] = []
    for it in items:
        if not isinstance(it, dict):
            return None
        raw = it.get("slug") or it.get("id") or it.get("name")
        if not isinstance(raw, str) or not raw.strip():
            continue
        provider = it.get("provider")
        cw = it.get("context_window") or it.get("context_length")
        out.append(
            ModelInfo(
                id=normalize(raw),
                raw=raw,
                provider=provider if isinstance(provider, str) else None,
                context_window=cw if isinstance(cw, int) else None,
            )
        )
    return out


def _parse_line_models(text: str, normalize) -> list[ModelInfo]:
    """opencode shape: newline-separated `provider/model` lines."""
    out: list[ModelInfo] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw:
            continue
        provider = raw.split("/", 1)[0] if "/" in raw else None
        out.append(
            ModelInfo(id=normalize(raw), raw=raw, provider=provider, context_window=None)
        )
    return out


def discover_models(
    discovery_cmd: str | None,
    *,
    runner: Runner,
    normalize=default_normalize,
) -> list[ModelInfo]:
    """Run the discovery command and parse its output into `ModelInfo`s.

    None ⇒ [] (the Claude path discovers nothing). The command is split with
    `shlex.split` (never shell=True). Shape-sniff: try JSON (codex), else parse
    newline list (opencode). Neither parses → ResolverError. Output is sorted by
    id for determinism.
    """
    if discovery_cmd is None:
        return []
    argv = shlex.split(discovery_cmd)
    if not argv:
        raise ResolverError(f"empty discovery command: {discovery_cmd!r}")
    result = runner(argv, DISCOVERY_TIMEOUT)
    if result.timed_out or result.returncode not in (0, None):
        raise ResolverError(
            f"discovery command failed (rc={result.returncode}, "
            f"timed_out={result.timed_out}): {discovery_cmd!r}"
        )
    text = result.stdout or ""
    models: list[ModelInfo] | None = None
    stripped = text.strip()
    looks_like_json = stripped[:1] in ("{", "[")
    if stripped:
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = None
        if data is not None:
            models = _parse_json_models(data, normalize)
        elif looks_like_json:
            # Malformed JSON must NOT silently fall back to line-parsing the raw
            # braces into garbage ModelInfos (L7) — fail loudly instead.
            raise ResolverError(
                f"discovery output looks like JSON but did not parse: "
                f"{stripped[:200]!r}"
            )
    if models is None and not looks_like_json:
        models = _parse_line_models(text, normalize)
    if not models:
        raise ResolverError(
            f"discovery produced no models (output did not parse as JSON or "
            f"newline list): {stripped[:200]!r}"
        )
    return sorted(models, key=lambda m: m.id)


# ---------------------------------------------------------------------------
# Proposal.
# ---------------------------------------------------------------------------


def _rank_for_tier(models: list[ModelInfo], tier: str) -> ModelInfo:
    """Pick the best model for a tier by name pattern, FAST-first precedence.

    For each model compute whether it matches a fast or high pattern. fast-first
    means a model matching a fast pattern is treated as fast even if it also
    matches a high pattern ("pro-lite"). Tiebreak: context_window desc, then
    provider asc, then id asc.
    """
    def classify(m: ModelInfo) -> str | None:
        low = m.id.lower()
        for pat in _FAST_PATTERNS:
            if pat in low:
                return "fast"
        for pat in _HIGH_PATTERNS:
            if pat in low:
                return "high"
        return None

    matching = [m for m in models if classify(m) == tier]
    pool = matching or list(models)
    return sorted(
        pool,
        key=lambda m: (
            -(m.context_window or 0),
            m.provider or "",
            m.id,
        ),
    )[0]


def propose_tier_map(models: list[ModelInfo], tier_defaults: dict | None) -> TierMap:
    """Propose a {high, fast} map from discovered models.

    Per-tier independently: use tier_defaults[tier] if it is present in the
    discovered set; else rank by name pattern. 1 model → collapse both tiers
    (provenance="collapsed"); 0 → ResolverError.
    """
    if not models:
        raise ResolverError("no models to propose from", available=[])
    ids = {m.id for m in models}
    if len(models) == 1:
        only = models[0].id
        return TierMap(high=only, fast=only, provenance="collapsed")

    defaults = tier_defaults or {}
    chosen: dict[str, str] = {}
    for tier in TIERS:
        want = defaults.get(tier)
        if want and want in ids:
            chosen[tier] = want
        else:
            chosen[tier] = _rank_for_tier(models, tier).id
    return TierMap(high=chosen["high"], fast=chosen["fast"], provenance="proposed")


# ---------------------------------------------------------------------------
# Confirmation (pure validation/selection over the PASSED discovered ids).
# ---------------------------------------------------------------------------


def confirm_tier_map(
    proposed: TierMap,
    *,
    discovered_ids,
    persisted: TierMap | None = None,
    cli_overrides: dict | None = None,
    checkpoint=None,
    non_interactive: bool = True,
) -> TierMap:
    """Validate/select a tier map over the PASSED discovered_ids. Does NOT
    re-discover (the E-M2 re-discover loop is owned by resolve()).

    Priority per tier: cli > persisted > proposed. Every chosen id must be in
    discovered_ids, else ResolverError(available=...). Non-interactive: any
    unresolved (persisted/proposed/cli id absent from discovered) → ResolverError.
    Interactive: delegate to checkpoint(proposed, discovered_models).
    """
    if non_interactive and checkpoint is not None:
        raise ResolverError(
            "non_interactive=True is incompatible with a checkpoint callable"
        )
    discovered = set(discovered_ids)
    cli = cli_overrides or {}

    # Per-tier source selection with priority cli > persisted > proposed.
    selected: dict[str, str] = {}
    sources: dict[str, str] = {}
    for tier in TIERS:
        if tier in cli and cli[tier]:
            selected[tier] = cli[tier]
            sources[tier] = "cli"
        elif persisted is not None:
            selected[tier] = getattr(persisted, tier)
            sources[tier] = "persisted"
        else:
            selected[tier] = getattr(proposed, tier)
            sources[tier] = "proposed"

    unresolved = {t: v for t, v in selected.items() if v not in discovered}
    if unresolved:
        if non_interactive:
            raise ResolverError(
                f"unresolved tier id(s) not in discovered set: {unresolved}",
                available=sorted(discovered),
            )
        # Interactive: hand the proposed map + discovered models to the operator.
        if checkpoint is None:
            raise ResolverError(
                "interactive mode but no checkpoint supplied to confirm_tier_map",
                available=sorted(discovered),
            )
        # checkpoint receives ModelInfo list — caller (resolve) supplies it via a
        # closure; here discovered_ids may already be ModelInfo. Normalize below.
        chosen = checkpoint(proposed, list(discovered_ids))
        for tier in TIERS:
            if getattr(chosen, tier) not in discovered:
                raise ResolverError(
                    f"checkpoint returned id for {tier} not in discovered set: "
                    f"{getattr(chosen, tier)!r}",
                    available=sorted(discovered),
                )
        return chosen

    return TierMap(
        high=selected["high"],
        fast=selected["fast"],
        provenance=_combine_provenance(*sources.values()),
    )


# ---------------------------------------------------------------------------
# Persistence.
# ---------------------------------------------------------------------------


def _model_map_path(review_root: Path) -> Path:
    return Path(review_root) / ".model_map.json"


def persist(tier_map: TierMap, review_root: Path) -> Path:
    """Atomically write <review_root>/.model_map.json. Returns the path."""
    review_root = Path(review_root)
    review_root.mkdir(parents=True, exist_ok=True)
    out = _model_map_path(review_root)
    text = json.dumps(tier_map.as_dict(), indent=2, sort_keys=True) + "\n"
    fd, tmp_path = tempfile.mkstemp(prefix=".model_map.", suffix=".tmp", dir=str(review_root))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp_path, out)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return out


def load_persisted(review_root: Path) -> TierMap | None:
    """Load <review_root>/.model_map.json. Missing/corrupt → None."""
    path = _model_map_path(Path(review_root))
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "high" not in data or "fast" not in data:
            return None
        return TierMap.from_dict(data)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CLI override parsing.
# ---------------------------------------------------------------------------


def parse_cli_models(spec: str) -> dict:
    """Parse "high=<id>,fast=<id>" → {"high": ..., "fast": ...}.

    Allowed keys: high|fast only. Unknown key / duplicate key / empty value →
    ResolverError. A single tier is allowed (partial override).
    """
    out: dict[str, str] = {}
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ResolverError(f"malformed --models entry (need key=value): {part!r}")
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key not in TIERS:
            raise ResolverError(f"unknown --models key {key!r}; allowed: {list(TIERS)}")
        if key in out:
            raise ResolverError(f"duplicate --models key {key!r}")
        if not value:
            raise ResolverError(f"empty value for --models key {key!r}")
        out[key] = value
    if not out:
        raise ResolverError(f"no tiers parsed from --models {spec!r}")
    return out


# ---------------------------------------------------------------------------
# Orchestration — owner of the E-M2 re-discover loop.
# ---------------------------------------------------------------------------


def resolve(
    *,
    discovery_cmd: str | None,
    tier_defaults: dict | None,
    review_root: Path,
    runner: Runner,
    normalize=default_normalize,
    cli_overrides: dict | None = None,
    non_interactive: bool = True,
    remodel: bool = False,
    checkpoint=None,
) -> TierMap:
    """Full resolution. Owner of discovery + the E-M2 (stale persisted) retry.

    Claude path (discovery_cmd is None): static {high: opus, fast: sonnet}, with
    cli_overrides applied over it; no persist.
    Else: load persisted (unless --remodel), discover, propose, confirm. On a
    stale-persisted unresolved interactively → re-discover + re-confirm. On
    non-interactive unresolved → ResolverError suggesting --remodel. persist().
    """
    # AD-2A5 usage error: a checkpoint is meaningless in non-interactive mode.
    # confirm_tier_map asserts this too, but resolve must not silently drop it (M2).
    if non_interactive and checkpoint is not None:
        raise ResolverError(
            "non_interactive=True is incompatible with a checkpoint callable"
        )
    if discovery_cmd is None:
        base = {"high": "opus", "fast": "sonnet"}
        cli = cli_overrides or {}
        high = cli.get("high") or base["high"]
        fast = cli.get("fast") or base["fast"]
        provenance = "cli" if cli else "proposed"
        return TierMap(high=high, fast=fast, provenance=provenance)

    persisted = None if remodel else load_persisted(review_root)
    models = discover_models(discovery_cmd, runner=runner, normalize=normalize)
    discovered_ids = [m.id for m in models]
    proposed = propose_tier_map(models, tier_defaults)

    # When interactive, the checkpoint wants ModelInfo objects, so wrap to pass
    # `models` (not bare ids) through confirm via a closure.
    def _checkpoint_adapter(prop, _ids):
        return checkpoint(prop, models)

    try:
        result = confirm_tier_map(
            proposed,
            discovered_ids=discovered_ids,
            persisted=persisted,
            cli_overrides=cli_overrides,
            checkpoint=_checkpoint_adapter if (not non_interactive and checkpoint) else None,
            non_interactive=non_interactive,
        )
    except ResolverError:
        if non_interactive:
            raise ResolverError(
                "could not resolve tier map non-interactively (persisted entry "
                "may be stale). Re-run with --remodel to rediscover, or pass "
                "--models high=<id>,fast=<id>.",
                available=discovered_ids,
            )
        # Interactive: rediscover fresh and re-confirm without the stale persisted.
        models = discover_models(discovery_cmd, runner=runner, normalize=normalize)
        discovered_ids = [m.id for m in models]
        proposed = propose_tier_map(models, tier_defaults)

        def _checkpoint_adapter2(prop, _ids):
            return checkpoint(prop, models)

        result = confirm_tier_map(
            proposed,
            discovered_ids=discovered_ids,
            persisted=None,
            cli_overrides=cli_overrides,
            checkpoint=_checkpoint_adapter2 if checkpoint else None,
            non_interactive=False,
        )

    # Preserve the "collapsed" provenance when a single-model proposal survived
    # confirm unchanged (confirm re-derives provenance from sources and loses it
    # otherwise — L1 / DeepSeek #14).
    if (
        proposed.provenance == "collapsed"
        and result.high == proposed.high
        and result.fast == proposed.fast
    ):
        result = replace(result, provenance="collapsed")

    persist(result, review_root)
    return result


# ---------------------------------------------------------------------------
# Interactive stdin/stdout checkpoint (CLI --interactive).
# ---------------------------------------------------------------------------


def _stdin_checkpoint(stdin=None, stdout=None):
    """Build a Checkpoint that reads tier ids from a text dialog on stdin.

    The operator is shown the proposed map + discovered models and may accept
    (blank line) or type "high=<id>,fast=<id>". Raises to abort (EOF).
    """
    src = stdin if stdin is not None else sys.stdin
    out = stdout if stdout is not None else sys.stdout

    def checkpoint(proposed: TierMap, models):
        print("Discovered models:", file=out)
        for m in models:
            cw = f" ({m.context_window})" if m.context_window else ""
            print(f"  - {m.id}{cw}", file=out)
        print(
            f"Proposed: high={proposed.high} fast={proposed.fast}", file=out
        )
        print(
            "Accept (blank line) or override 'high=<id>,fast=<id>':", file=out
        )
        line = src.readline()
        if line == "":
            raise ResolverError("checkpoint aborted (EOF on stdin)")
        line = line.strip()
        if not line:
            return TierMap(high=proposed.high, fast=proposed.fast, provenance="proposed")
        overrides = parse_cli_models(line)
        return TierMap(
            high=overrides.get("high", proposed.high),
            fast=overrides.get("fast", proposed.fast),
            provenance="cli",
        )

    return checkpoint


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None, *, runner: Runner | None = None, stdin=None) -> int:
    parser = argparse.ArgumentParser(description="Resolve a {high, fast} model tier map")
    parser.add_argument("--discovery-cmd", default=None,
                        help="Discovery command (shlex-split). Omit for the Claude static map.")
    parser.add_argument("--tier-defaults", default=None,
                        help="Preferred ids per tier: high=<id>,fast=<id>")
    parser.add_argument("--review-root", type=Path, required=True,
                        help="Where to persist .model_map.json")
    parser.add_argument("--models", default=None,
                        help="CLI override ids: high=<id>,fast=<id> (partial allowed)")
    parser.add_argument("--remodel", action="store_true",
                        help="Ignore any persisted map and rediscover")
    parser.add_argument("--interactive", action="store_true",
                        help="Bind a stdin/stdout text checkpoint (default: non-interactive)")
    args = parser.parse_args(argv)

    run = runner if runner is not None else default_runner

    try:
        cli_overrides = parse_cli_models(args.models) if args.models else None
        tier_defaults = parse_cli_models(args.tier_defaults) if args.tier_defaults else None
        checkpoint = _stdin_checkpoint(stdin=stdin) if args.interactive else None
        tier_map = resolve(
            discovery_cmd=args.discovery_cmd,
            tier_defaults=tier_defaults,
            review_root=args.review_root,
            runner=run,
            cli_overrides=cli_overrides,
            non_interactive=not args.interactive,
            remodel=args.remodel,
            checkpoint=checkpoint,
        )
    except ResolverError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if exc.available is not None:
            print(f"Available ids: {exc.available}", file=sys.stderr)
        return 2

    # Only the discovery path persists; never claim a leftover file on the Claude
    # static path (L2).
    out = dict(tier_map.as_dict())
    if args.discovery_cmd is not None:
        persisted_path = _model_map_path(Path(args.review_root))
        if persisted_path.is_file():
            out["persisted"] = str(persisted_path)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
