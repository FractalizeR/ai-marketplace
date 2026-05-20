"""PHP GraphQL detection layer (recipe-agnostic).

Surfaced by recipes (Symfony, Laravel) as `framework_specific.<stack>.graphql_layer`
when a known PHP GraphQL library is present in `composer.json`.

Supported libraries (composer package → `library_name` value):
    nuwave/lighthouse             → "lighthouse"      (Laravel, schema-first)
    rebing/graphql-laravel        → "rebing-laravel"  (Laravel, code-first)
    api-platform/core             → "api-platform"    (Symfony, GraphQL bundle)
    webonyx/graphql-php           → "webonyx"         (low-level, no conventions)

Resolution order: stack-specific frameworks first (lighthouse / rebing /
api-platform), webonyx as a final fallback when no framework wraps it.
This keeps the layer informative — a Lighthouse project also has webonyx
transitively, but the lighthouse signal is more actionable for security review.

Returned shape (dict, scalar-section payload):
    {
        "library_name": str,             # one of the values above
        "schema_files": list[str],       # POSIX project-relative paths
        "resolvers_dir": list[str],      # POSIX project-relative directory paths
    }

`schema_files` and `resolvers_dir` are populated by convention; an empty list
means the library does not enforce a path convention or the convention dirs
do not exist in this project. Worker is expected to do manual review for
empty-list cases.

stdlib only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

# Library name → composer package name. Order = detection priority.
_LIBRARY_PACKAGES: tuple[tuple[str, str], ...] = (
    ("lighthouse", "nuwave/lighthouse"),
    ("rebing-laravel", "rebing/graphql-laravel"),
    ("api-platform", "api-platform/core"),
    ("webonyx", "webonyx/graphql-php"),
)


# Convention file/dir candidates per library (project-relative POSIX).
# Recipes consume these and emit only the ones that actually exist on disk.
_CONVENTIONS: dict[str, dict[str, tuple[str, ...]]] = {
    "lighthouse": {
        "schema_files": (
            "graphql/schema.graphql",
            "graphql/main.graphql",
        ),
        "resolvers_dir": (
            "app/GraphQL/Queries",
            "app/GraphQL/Mutations",
            "app/GraphQL/Types",
            "app/GraphQL/Subscriptions",
            "app/GraphQL/Directives",
        ),
    },
    "rebing-laravel": {
        "schema_files": (),
        "resolvers_dir": (
            "app/GraphQL/Type",
            "app/GraphQL/Query",
            "app/GraphQL/Mutation",
            "app/GraphQL/Types",
            "app/GraphQL/Queries",
            "app/GraphQL/Mutations",
        ),
    },
    "api-platform": {
        "schema_files": (),
        "resolvers_dir": (
            "src/GraphQl/Resolver",
            "src/GraphQl/Type",
            "src/Resolver",
        ),
    },
    "webonyx": {
        # No conventional layout: low-level library used by frameworks above
        # and ad-hoc projects. Worker must manually identify schema files.
        "schema_files": (),
        "resolvers_dir": (),
    },
}


_COMPOSER_MAX_BYTES = 5 * 1024 * 1024  # 5 MB — well above any sane composer.json


def detect_graphql(project_root: Path) -> Optional[dict]:
    """Detect a PHP GraphQL library; return scalar-section payload or None.

    Returned dict can be passed straight into a SectionPayload.data field
    (with status="ok" and source_files=["composer.json"] in the recipe).
    """
    composer = project_root / "composer.json"
    if not composer.is_file():
        return None
    try:
        if composer.stat().st_size > _COMPOSER_MAX_BYTES:
            return None
        data = json.loads(composer.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None

    deps: set[str] = set()
    for section in ("require", "require-dev"):
        block = data.get(section)
        if isinstance(block, dict):
            deps.update(block.keys())

    library_name: Optional[str] = None
    for name, package in _LIBRARY_PACKAGES:
        if package in deps:
            library_name = name
            break
    if library_name is None:
        return None

    convs = _CONVENTIONS[library_name]

    schema_files: list[str] = []
    for rel in convs["schema_files"]:
        if (project_root / rel).is_file():
            schema_files.append(rel)

    resolvers_dir: list[str] = []
    for rel in convs["resolvers_dir"]:
        if (project_root / rel).is_dir():
            resolvers_dir.append(rel)

    return {
        "library_name": library_name,
        "schema_files": schema_files,
        "resolvers_dir": resolvers_dir,
    }
