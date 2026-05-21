# EasyAdmin addon — detection

This file describes how the recon agent detects an EasyAdmin installation on top of Symfony and activates checklists from `stacks/symfony/addons/easyadmin/`. It is not a checklist — there are no vulnerability items.

## EasyAdmin signals (by `composer.json`)

`bin/recon/recipes/easyadmin_detect.py::detect_easyadmin()` marks the project as using EasyAdmin if `composer.json` contains `easycorp/easyadmin-bundle` in `require` or `require-dev`. The probe is intentionally lightweight (composer only, no PHP parse) so addon-layer checklists are loaded even before the heavier CRUD enumeration runs.

On a hit, the recon agent writes into `<review_root>/CONTEXT.md`:

```yaml
stack:
  framework: symfony
  addons:
    - easyadmin
```

`plan_waves.resolve_checklists(...)` then appends, for each wave theme, the file `stacks/symfony/addons/easyadmin/{theme}.md`, if present.

## What lands in the `recon_bags.addon.easyadmin` bag

The recipe fills (or marks `status: unknown`/`none` with reason) the key `crud_controllers` — collected by `recon_bags.addon.easyadmin.crud_controllers`. Each item carries: `class`, `file`, `line`, `entity_fqcn`, `configure_fields[]` (field name + type + modifiers), `configure_actions`, `page_titles`, `unresolved_fields` (true when configureFields() delegates to a parent the static parser cannot resolve).

See `bin/recon/recipes/symfony.py::RECON_BAGS_SCHEMA["addon"]["easyadmin"]` for the exact shape.

Detection of `extends AbstractCrudController` classes is the second-stage check inside `collect_easyadmin_crud_controllers` — it runs the PHP extractor (`easyadmin-crud` kind) and produces `status: none` when zero subclasses are found. A project may legitimately depend on the bundle and have zero CRUD controllers; addon-layer checklists still load (composer-level detection is the gate).
