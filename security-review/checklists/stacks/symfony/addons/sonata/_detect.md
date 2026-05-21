# Sonata AdminBundle addon — detection

This file describes how the recon agent detects a Sonata installation on top of Symfony and activates checklists from `stacks/symfony/addons/sonata/`. It is not a checklist — there are no vulnerability items.

## Sonata signals (by `composer.json`)

`bin/recon/recipes/sonata_detect.py::detect_sonata()` marks the project as using Sonata if `composer.json` contains `sonata-project/admin-bundle` in `require` or `require-dev`. The probe is intentionally lightweight (composer only, no PHP parse) so addon-layer checklists are loaded even before the heavier admin enumeration runs.

On a hit, the recon agent writes into `<review_root>/CONTEXT.md`:

```yaml
stack:
  framework: symfony
  addons:
    - sonata
```

`plan_waves.resolve_checklists(...)` then appends, for each wave theme, the file `stacks/symfony/addons/sonata/{theme}.md`, if present.

## What lands in the `recon_bags.addon.sonata` bag

The recipe fills (or marks `status: unknown`/`none` with reason) the key `admin_classes` — collected by `recon_bags.addon.sonata.admin_classes`. Each item carries: `class`, `file`, `line`, `entity_fqcn`, `form_fields[]` (array of field names from `$form->add('name', ...)`), `unresolved_fields` (true when configureFormFields() delegates to a parent the static parser cannot resolve).

See `bin/recon/recipes/symfony.py::RECON_BAGS_SCHEMA["addon"]["sonata"]` for the exact shape.

Detection of `extends AbstractAdmin` classes is the second-stage check inside `collect_sonata_admin_classes` — it runs the PHP extractor (`sonata-admin` kind) and produces `status: none` when zero subclasses are found. A project may legitimately depend on the bundle and have zero admin classes; addon-layer checklists still load (composer-level detection is the gate).
