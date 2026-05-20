# Symfony stack — detection

Этот файл описывает, как `recipes/symfony` детектирует Symfony-проект и активирует чек-листы из `frameworks/symfony/`. Сам по себе чек-листом не является — пунктов с уязвимостями нет.

## Признаки Symfony-проекта (по `composer.json` и файловой структуре)

`bin/recon/recipes/symfony.py::detect()` отмечает проект как Symfony, если выполняется одно из условий: `composer.json` содержит `symfony/framework-bundle` (или `symfony/runtime` плюс любой `symfony/*-bundle`) в `require`/`require-dev`; в корне проекта присутствует `symfony.lock` (Symfony Flex marker); существуют одновременно `bin/console` и `config/bundles.php`.

При срабатывании recon-агент пишет в `<review_root>/CONTEXT.md`:

```yaml
stack:
  framework: symfony
  framework_version: <major>.<minor>   # из composer.lock или composer show
  detector: composer.json+symfony.lock
```

`plan_waves.resolve_checklists(themes, stack="symfony", plugin_root)` тогда добавляет к каждой теме файл `frameworks/symfony/{theme}.md`, если он существует.

## Что попадает в `framework_specific.symfony` bag

Recipe заполняет (или помечает `status: unknown` с reason) ключи: `voters` (классы `extends Voter`/`extends VoterInterface` и их атрибуты); `forms` (классы `extends AbstractType` с `data_class`, `csrf_protection`, `allow_extra_fields`); `serializer_groups` (классы с `#[Groups]` атрибутами; JMS XML/YAML — known limitation static-парсинга); `twig_overrides` (глобальные `autoescape` настройки и счётчик `|raw` filter usages); `doctrine_listeners` (kernel/doctrine event subscribers); `firewalls` (`config/packages/security.yaml`: firewalls + access_control rules); `messenger_transports` (`config/packages/messenger.yaml` или `framework.yaml`: transports + retry strategy).

См. `bin/recon/recipes/symfony.py::FRAMEWORK_SPECIFIC_SCHEMA` для точного shape.

## Что значит «framework: none/unknown»

`none` — generic-PHP проект без фреймворка. `frameworks/symfony/*.md` не подгружаются. Worker работает только с core checklists.

`unknown` — detect не сработал (возможно, нестандартная установка). recon-агент пишет `recon_confidence: low`, plan_waves не активирует framework-секции.
