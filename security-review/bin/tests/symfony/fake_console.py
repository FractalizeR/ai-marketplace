"""Stand-in for `bin/console` in recon tests (used via `--console-cmd`).

Usage: fake_console.py <case> [<env>] <console args...>

Serves `debug:config <alias> --format=json` from
`fixtures/symfony_debug_config/<case>.<alias>.json` (trees captured from a real
Symfony skeleton), answers the smoke / enrichment probes with empty JSON and
`debug:container --parameter=kernel.environment` with <env> (default `dev`).
An alias of a registered bundle without a captured tree answers `{alias: {}}`.
Refuses `--resolve-env`: the recipe must never ask for resolved env values.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

DEBUG_CONFIG_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "symfony_debug_config"
REGISTERED_ALIASES = ("framework", "security", "twig")


def main(argv: list[str]) -> int:
    case, rest = argv[0], argv[1:]
    env = "dev"
    if rest and rest[0].startswith("env="):
        env, rest = rest[0][len("env="):], rest[1:]
    if "--resolve-env" in rest:
        print("fake_console: --resolve-env is forbidden", file=sys.stderr)
        return 2
    cmd = rest[0] if rest else "list"
    if cmd == "debug:config":
        alias = rest[1]
        path = DEBUG_CONFIG_DIR / f"{case}.{alias}.json"
        if not path.is_file():
            if alias in REGISTERED_ALIASES:
                # A registered bundle with no captured tree: defaults only.
                print(json.dumps({alias: {}}))
                return 0
            print(f'There is no extension able to load the configuration for "{alias}".', file=sys.stderr)
            return 1
        sys.stdout.write(path.read_text(encoding="utf-8"))
        return 0
    if cmd == "debug:container" and "--parameter=kernel.environment" in rest:
        print(json.dumps({"kernel.environment": env}))
        return 0
    print("{}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
