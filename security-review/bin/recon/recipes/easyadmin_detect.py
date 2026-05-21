"""EasyAdmin addon detector — moved out of `symfony.py` (Stage 1).

Exports:
- detect_easyadmin(project_root): True/False from composer dependency probe.
  Used by `symfony.build_inventory` to decide whether to add `"easyadmin"`
  to `frontmatter.stack.addons` (drives addon-layer checklist loading).
- collect_easyadmin_crud_controllers(...): the real bag collector. Returns a
  SectionPayload describing all `extends AbstractCrudController` subclasses
  (entity_fqcn, configure_fields, configure_actions, page_titles).

The PHP-side enumeration runs through `recon.sandbox.run_extractor` with
the `easyadmin-crud` extractor. We re-export from the recipes namespace so
imports from `recon.recipes.easyadmin_detect` stay stable.

This module deliberately does NOT define RECIPE_NAME / build_inventory /
sanity_probes — `recon.recipes.__init__.available_recipes()` filters out
`*_detect.py` so this won't be tried as a stack recipe.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from recon.recipes._shared import EXCLUDE_PATHS, is_excluded, to_relative
from recon.types import SectionPayload


# Composer package name that gates EasyAdmin detection.
EASYADMIN_PACKAGE = "easycorp/easyadmin-bundle"


def detect_easyadmin(project_root: Path) -> bool:
    """Return True iff `easycorp/easyadmin-bundle` is in composer.json require*.

    Cheap composer probe — doesn't parse PHP, doesn't list CRUD classes.
    Stack recipe calls this to decide whether to declare `easyadmin` as a
    stack addon (drives addon-layer checklist resolution in plan_waves).
    Heavier enumeration (CRUD class list, fields) lives in
    `collect_easyadmin_crud_controllers`.
    """
    composer = project_root / "composer.json"
    if not composer.is_file():
        return False
    try:
        data = json.loads(composer.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    if not isinstance(data, dict):
        return False
    for section in ("require", "require-dev"):
        deps = data.get(section)
        if isinstance(deps, dict) and EASYADMIN_PACKAGE in deps:
            return True
    return False


def collect_easyadmin_crud_controllers(
    project_root: Path,
    plugin_root: Path,
    warnings: list[str],
    *,
    exclude: Optional[tuple[str, ...]] = None,
) -> SectionPayload:
    """EasyAdmin CRUD controllers — entity_fqcn + configure_fields/actions/titles.

    Returns `none` (not `unknown`) when no CRUD controllers are present — that's
    a normal state for non-admin projects, not a recipe failure.

    Sets `status=partial` if any controller has `unresolved_fields=true` so the
    worker knows the field set is best-effort (parent::configureFields delegate).
    """
    from recon import sandbox

    out, warn = sandbox.run_extractor(
        plugin_root, project_root, "easyadmin-crud", project_root, exclude=exclude,
    )
    if warn:
        warnings.append(warn)
        return SectionPayload(status="unknown", reason=warn)
    items: list[dict] = []
    has_unresolved = False
    for it in (out.get("items") or []):
        rel = to_relative(it.get("file"), project_root)
        if rel is None or is_excluded(rel, EXCLUDE_PATHS):
            continue
        unresolved = bool(it.get("unresolved_fields"))
        if unresolved:
            has_unresolved = True
        # YAML emitter rejects `{}` (Empty dict value at key — use null instead),
        # so an absent configureCrud method becomes `page_titles: null` in CONTEXT.md.
        page_titles_raw = it.get("page_titles") or {}
        page_titles_val = dict(page_titles_raw) if page_titles_raw else None
        items.append({
            "class": it.get("class") or "",
            "file": rel,
            "line": it.get("line") or 0,
            "entity_fqcn": it.get("entity_fqcn") or None,
            "configure_fields": list(it.get("configure_fields") or []),
            "configure_actions": dict(it.get("configure_actions") or {"disabled": []}),
            "page_titles": page_titles_val,
            "unresolved_fields": unresolved,
        })
    if not items:
        return SectionPayload(status="none", reason="no AbstractCrudController subclasses found")
    if has_unresolved:
        return SectionPayload(
            status="partial",
            items=items,
            reason="at least one CRUD controller delegates configureFields() to parent",
        )
    return SectionPayload(status="ok", items=items)
