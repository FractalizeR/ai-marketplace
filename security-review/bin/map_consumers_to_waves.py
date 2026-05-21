#!/usr/bin/env python3
"""Map consumer file paths to wave IDs deterministically.

Used by `/fr-security-review:security-changes` after reverse-grep:
the orchestrator collects consumer files (entry points referencing changed
services), then asks this CLI for the corresponding wave assignment instead
of guessing heuristically.

Resolution per consumer file:
1. Look up the file in CONTEXT.md `attack_surface` (and recon_bags
   sub-sections that carry items with `kind`). The first match wins.
2. Map the resolved `kind` to wave_ids via `plan_waves.consumer_kinds_to_waves()`.
3. Files not present in any indexed section, or whose `kind` is not covered
   by any wave's `relevant_kinds`, return an empty `waves` list.

Output (JSON to stdout):

    {
      "src/Controller/Foo.php": {"kind": "http_route", "waves": ["W1", "W2", "W3", "W5"]},
      "src/Repository/Bar.php": {"kind": null, "waves": []}
    }

stdlib only. No external dependencies.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as standalone script: bin/ on sys.path so `import plan_waves`
# resolves to the local module.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from plan_waves import (  # noqa: E402
    consumer_kinds_to_waves,
    lookup_kind_for_file,
    parse_context,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Map consumer file paths to wave IDs (deterministic).",
    )
    parser.add_argument(
        "--review-root", type=Path, required=True,
        help="Review root with CONTEXT.md.",
    )
    parser.add_argument(
        "--consumer", action="append", default=[],
        help="Consumer file path (repeatable). Project-relative.",
    )
    parser.add_argument(
        "--consumers-file", type=Path, default=None,
        help="File listing consumer paths, one per line.",
    )
    args = parser.parse_args(argv)

    consumers: list[str] = list(args.consumer)
    if args.consumers_file:
        try:
            for ln in args.consumers_file.read_text(encoding="utf-8").splitlines():
                ln = ln.strip()
                if ln:
                    consumers.append(ln)
        except OSError as exc:
            print(f"Error reading --consumers-file: {exc}", file=sys.stderr)
            return 2

    if not consumers:
        print("Error: no consumers provided (--consumer or --consumers-file)", file=sys.stderr)
        return 2

    context_path = args.review_root / "CONTEXT.md"
    try:
        ctx = parse_context(context_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    inverse_index = consumer_kinds_to_waves()
    out: dict[str, dict[str, object]] = {}
    seen: set[str] = set()
    for raw in consumers:
        if raw in seen:
            continue
        seen.add(raw)
        kind = lookup_kind_for_file(raw, ctx)
        waves = inverse_index.get(kind, []) if kind else []
        out[raw] = {"kind": kind, "waves": waves}

    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
