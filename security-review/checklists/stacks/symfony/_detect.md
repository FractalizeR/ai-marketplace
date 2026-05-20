# Symfony stack — detection

This file describes how `recipes/symfony` detects a Symfony project and activates checklists from `stacks/symfony/`. It is not a checklist itself — there are no vulnerability items.

## Symfony project signals (by `composer.json` and file structure)

`bin/recon/recipes/symfony.py::detect()` marks the project as Symfony if one of the conditions holds: `composer.json` contains `symfony/framework-bundle` (or `symfony/runtime` plus any `symfony/*-bundle`) in `require`/`require-dev`; `symfony.lock` (Symfony Flex marker) is present at the project root; both `bin/console` and `config/bundles.php` exist.

On a hit, the recon agent writes into `<review_root>/CONTEXT.md`:

```yaml
stack:
  framework: symfony
  framework_version: <major>.<minor>   # from composer.lock or composer show
  detector: composer.json+symfony.lock
```

`plan_waves.resolve_checklists(themes, ctx, plugin_root)` (where `ctx.stack == "symfony"`) then adds to each theme the file `stacks/symfony/{theme}.md`, if it exists.

## What lands in the `framework_specific.symfony` bag

The recipe fills in (or marks `status: unknown` with reason) the keys: `voters` (classes `extends Voter`/`extends VoterInterface` and their attributes); `forms` (classes `extends AbstractType` with `data_class`, `csrf_protection`, `allow_extra_fields`); `serializer_groups` (classes with `#[Groups]` attributes; JMS XML/YAML — known limitation of static parsing); `twig_overrides` (global `autoescape` settings and counter of `|raw` filter usages); `doctrine_listeners` (kernel/doctrine event subscribers); `firewalls` (`config/packages/security.yaml`: firewalls + access_control rules); `messenger_transports` (`config/packages/messenger.yaml` or `framework.yaml`: transports + retry strategy).

See `bin/recon/recipes/symfony.py::FRAMEWORK_SPECIFIC_SCHEMA` for the exact shape.

## What "framework: none/unknown" means

`none` — generic PHP project without a framework. `stacks/symfony/*.md` are not loaded. Worker operates only with core checklists.

`unknown` — detect did not fire (possibly non-standard installation). The recon agent writes `recon_confidence: low`, plan_waves does not activate framework sections.
