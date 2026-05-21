"""Sonata AdminBundle addon detector — moved out of `symfony.py` (Stage 1).

Exports:
- detect_sonata(project_root): True/False from composer dependency probe.
  Used by `symfony.build_inventory` to decide whether to add `"sonata"`
  to `frontmatter.stack.addons` (drives addon-layer checklist loading).
- collect_sonata_admin_classes(...): the real bag collector. Returns a
  SectionPayload describing all `extends AbstractAdmin` subclasses
  (entity_fqcn, form_fields).

The PHP-side enumeration runs through `recon.sandbox.run_extractor` with
the `sonata-admin` extractor.

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


# Composer package name that gates Sonata detection.
SONATA_PACKAGE = "sonata-project/admin-bundle"


def detect_sonata(project_root: Path) -> bool:
    """Return True iff `sonata-project/admin-bundle` is in composer.json require*.

    Cheap composer probe — doesn't parse PHP, doesn't list admin classes.
    Stack recipe calls this to decide whether to declare `sonata` as a
    stack addon (drives addon-layer checklist resolution in plan_waves).
    Heavier enumeration (admin class list, form_fields) lives in
    `collect_sonata_admin_classes`.
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
        if isinstance(deps, dict) and SONATA_PACKAGE in deps:
            return True
    return False


def collect_sonata_admin_classes(
    project_root: Path,
    plugin_root: Path,
    warnings: list[str],
    *,
    exclude: Optional[tuple[str, ...]] = None,
) -> SectionPayload:
    """Sonata AdminBundle admin classes — entity_fqcn + form_fields.

    Returns `none` (not `unknown`) when no admin classes are present — that's
    a normal state for non-Sonata projects, not a recipe failure.
    """
    from recon import sandbox

    out, warn = sandbox.run_extractor(
        plugin_root, project_root, "sonata-admin", project_root, exclude=exclude,
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
        items.append({
            "class": it.get("class") or "",
            "file": rel,
            "line": it.get("line") or 0,
            "entity_fqcn": it.get("entity_fqcn") or None,
            "form_fields": list(it.get("form_fields") or []),
            "unresolved_fields": unresolved,
        })
    if not items:
        return SectionPayload(status="none", reason="no AbstractAdmin subclasses found")
    if has_unresolved:
        return SectionPayload(
            status="partial",
            items=items,
            reason="at least one admin class delegates configureFormFields() to parent",
        )
    return SectionPayload(status="ok", items=items)
