#!/usr/bin/env python3
"""Model tier map — the operator names a `{high, fast}` pair once, it is persisted.

plan_waves emits `opus|sonnet` labels; `dispatch` maps them to concrete ids via
`LABEL_TO_TIER` and the `.model_map.json` written here. No discovery and no
guessing: a bad guess (both tiers on one weak model) only shows up hours later
as crashed waves, so the ids are always supplied by the operator.

Source of the map, in precedence order:
  1. `--models high=<id>,fast=<id>` (both tiers required) — overwrites the file;
  2. an existing valid `<review_root>/.model_map.json` (re-run / resume);
  3. otherwise exit 2.

CLI:
    python3 <core_root>/bin/shared/model_resolver.py --review-root P
        [--models high=<id>,fast=<id>]
    stdout = the resolved map as JSON. exit 0 ok / 2 ResolverError.

Side-effect-free modes (for launchers): `--check --models SPEC` validates the spec
exactly as a real run would; `--describe --review-root P` prints
`{"status": ..., "high": ..., "fast": ...}` for the saved map.

stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

# Engine invocation convention: bin/ is NOT a package. Put `.../bin` on sys.path
# so `from shared.contracts import ...` resolves (mirrors dedupe_findings.py).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.contracts import ResolverError  # noqa: E402

LABEL_TO_TIER = {"opus": "high", "sonnet": "fast"}
TIERS = ("high", "fast")

MISSING_MODELS_HINT = (
    "model tiers are not set; pass --models high=<id>,fast=<id> "
    "(list the available ids with `codex debug models`)"
)


@dataclass(frozen=True)
class TierMap:
    """Concrete model ids for the two tiers."""

    high: str
    fast: str

    def as_dict(self) -> dict:
        return {"high": self.high, "fast": self.fast}

    @classmethod
    def from_dict(cls, d: dict) -> "TierMap":
        return cls(high=d["high"], fast=d["fast"])


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
    """Load <review_root>/.model_map.json. Missing/corrupt/incomplete → None."""
    return load_tier_map_file(_model_map_path(Path(review_root)))


def inspect_tier_map_file(path: Path) -> tuple[str, TierMap | None]:
    """Side-effect-free status of a tier-map file: `(status, map)`.

    Statuses: `usable`, `absent`, `invalid` (corrupt or a tier missing) and
    `ignored-pre-5.0`. Only pre-5.0 builds wrote a `provenance` key, and its
    value never said reliably who chose the ids (a 4.x `cli` map could hold an
    auto-proposed tier, a re-run rewrote it as `persisted`), so the key alone
    marks the map as untrusted.
    """
    path = Path(path)
    if not path.is_file():
        return "absent", None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "invalid", None
    if not isinstance(data, dict):
        return "invalid", None
    if not all(isinstance(data.get(t), str) and data[t] for t in TIERS):
        return "invalid", None
    if "provenance" in data:
        return "ignored-pre-5.0", None
    return "usable", TierMap.from_dict(data)


def inspect_persisted(review_root: Path) -> tuple[str, TierMap | None]:
    return inspect_tier_map_file(_model_map_path(Path(review_root)))


def load_tier_map_file(path: Path) -> TierMap | None:
    """The trusted tier map at any path, else None (with a message when ignored)."""
    status, tier_map = inspect_tier_map_file(path)
    if status == "ignored-pre-5.0":
        print(
            f"model_resolver: ignoring {path}: written by a pre-5.0 build "
            f"(it carries a `provenance` key); pass --models high=<id>,fast=<id> "
            f"to replace it",
            file=sys.stderr,
        )
    return tier_map


def parse_cli_models(spec: str) -> TierMap:
    """Parse "high=<id>,fast=<id>". Both tiers are required, no duplicates."""
    out: dict[str, str] = {}
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ResolverError(f"malformed --models entry (need key=value): {part!r}")
        key, value = (x.strip() for x in part.split("=", 1))
        if key not in TIERS:
            raise ResolverError(f"unknown --models key {key!r}; allowed: {list(TIERS)}")
        if key in out:
            raise ResolverError(f"duplicate --models key {key!r}")
        if not value:
            raise ResolverError(f"empty value for --models key {key!r}")
        out[key] = value
    missing = [t for t in TIERS if t not in out]
    if missing:
        raise ResolverError(
            f"--models needs both tiers (high=<id>,fast=<id>); missing: {missing}"
        )
    return TierMap.from_dict(out)


def resolve(*, review_root: Path, models: str | None) -> TierMap:
    """`--models` wins and is persisted; else the persisted map; else error."""
    if models:
        tier_map = parse_cli_models(models)
        persist(tier_map, review_root)
        return tier_map
    persisted = load_persisted(review_root)
    if persisted is None:
        raise ResolverError(MISSING_MODELS_HINT)
    return persisted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve the {high, fast} model tier map")
    parser.add_argument("--review-root", type=Path, default=None,
                        help="Where .model_map.json lives")
    parser.add_argument("--models", default=None,
                        help="high=<id>,fast=<id> (both required); overwrites the saved map")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
                      help="only validate --models exactly as a real run would; writes nothing")
    mode.add_argument("--describe", action="store_true",
                      help="only report the saved map's status for --review-root "
                           "(usable | absent | invalid | ignored-pre-5.0) and its tier ids")
    args = parser.parse_args(argv)

    if args.check:
        if args.models is None:
            parser.error("--check needs --models")
        try:
            tier_map = parse_cli_models(args.models)
        except ResolverError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(tier_map.as_dict(), indent=2, sort_keys=True))
        return 0
    if args.review_root is None:
        parser.error("--review-root is required")
    if args.describe:
        status, tier_map = inspect_persisted(args.review_root)
        report = {"status": status}
        if tier_map is not None:
            report["high"] = tier_map.high
            report["fast"] = tier_map.fast
        print(json.dumps(report, sort_keys=True))
        return 0

    try:
        tier_map = resolve(review_root=args.review_root, models=args.models)
    except ResolverError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(tier_map.as_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
