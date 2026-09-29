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

## What lands in the `recon_bags.stack.symfony` bag

The recipe fills in (or marks `status: unknown` / `partial` with reason) the keys: `voters` (classes `extends Voter`/`extends VoterInterface` and their attributes); `forms` (classes `extends AbstractType` with `data_class`, `csrf_protection`, `allow_extra_fields`); `serializer_groups` (classes with `#[Groups]` attributes; JMS XML/YAML — known limitation of static parsing); `twig_overrides` (global `autoescape` settings and counter of `|raw` filter usages); `doctrine_listeners` (kernel/doctrine event subscribers); `firewalls` (security config — `config/packages/security.{yaml,php,xml}`, possibly split across files; read via `debug:config` when the project console boots: firewalls + access_control rules. Without a console the recipe does not parse the files — the section is `partial` with a `config_uninterpreted:` reason and the files in `source_files`); `messenger_transports` (framework config — `config/packages/messenger.{yaml,php,xml}` or `framework.{yaml,php,xml}`: transports + retry strategy).

See `bin/recon/recipes/symfony.py::RECON_BAGS_SCHEMA` for the exact shape.

## What "framework: none/unknown" means

`none` — generic PHP project without a framework. `stacks/symfony/*.md` are not loaded. Worker operates only with core checklists.

`unknown` — detect did not fire (possibly non-standard installation). `stack.framework` does not name this stack, so `stacks/symfony/*.md` are not loaded either. (`recon_confidence` in the frontmatter is shown to the user only; nothing reads it.)
