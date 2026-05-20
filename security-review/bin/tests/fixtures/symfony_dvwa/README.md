# symfony_dvwa — Damn Vulnerable Symfony fixture

> **Не запускать.** Это намеренно сломанный код, существующий ровно для проверки recall плагина.

## Зачем

Без known-vulnerable fixture невозможно отличить случай «recipe пропустил injection-релевантные файлы» от «у проекта действительно нет SQLi», и нельзя замерить numeric recall плагина.

`symfony_dvwa` фиксирует **15 разнотипных уязвимостей** на Symfony 7 + EasyAdmin, охватывающих все 6 фокусных волн (W1 auth/disclosure, W2 injection/data-access, W3 xss/SSTI, W4 deserialization/crypto, W5 ssrf-fileops, W6 — здесь не задействована, fintech_markers есть только из Order entity для inventory recall).

## Состав

```
src/
  Entity/{User,Post,Order}.php           # entities + поля под уязвимости
  Repository/{User,Post,Order}Repository.php
  Controller/
    ApiController.php                    # DVWA-02, DVWA-07
    AuthController.php                   # DVWA-06, DVWA-08
    FileController.php                   # DVWA-05
    PostController.php                   # рендер шаблона DVWA-03
    SearchController.php                 # DVWA-04
    UserController.php                   # DVWA-13
    Admin/
      DashboardController.php
      UserCrudController.php             # DVWA-11, DVWA-12
      OrderCrudController.php            # control case (wired через OrderVoter)
  Form/UserType.php                      # DVWA-08, DVWA-09
  Security/Voter/OrderVoter.php          # demo-voter (только Order wired)
  Service/PaymentClient.php              # дин. base_url для http_clients recall
config/
  packages/{security,twig,messenger}.yaml  # DVWA-03 (autoescape), DVWA-07 (php_serialize), DVWA-14, DVWA-15
  services.yaml                            # DVWA-10 (hardcoded secret в yaml)
templates/post/show.html.twig            # DVWA-03 sink
golden_findings.yaml                     # 15 expected findings с sink_kind / wave
```

## Как пользоваться

### Inventory recall (автоматизировано)

`bin/tests/test_dvwa_inventory_recall.py` — unit-тест, прогоняет `recon_inventory.py --recipe symfony --no-console` на fixture и проверяет, что:

- `attack_surface` содержит ровно ожидаемое число http_route / http_route_admin items;
- `data_access` содержит все 3 repositories;
- `serialization` ловит `unserialize($_COOKIE)` (DVWA-07);
- `file_operations` ловит `file_get_contents` (DVWA-05);
- `http_clients` ловит `HttpClientInterface` / `HttpClient::create` (DVWA-services pivot);
- `framework_specific.symfony.forms` содержит `UserType` с `csrf_protection: false`, `allow_extra_fields: true` (DVWA-08, DVWA-09);
- `framework_specific.symfony.easyadmin_crud_controllers` содержит User + Order CrudController'ы;
- `framework_specific.symfony.admin_authz_coverage.crud_controllers_without_voter` включает `UserCrudController` (DVWA-12 trigger).

### Worker recall (manual)

LLM-воркер прогоняется ручным `/security-project` или эквивалентным CLI на этом fixture. После прогона:

1. Открыть финальный `<review_root>/REPORT.md` (или split-files в `REPORT/`).
2. Для каждого finding'а из `golden_findings.yaml` проверить, есть ли ему соответствие в отчёте (по `file:line` ± 5 строк + матчинг `sink_kind` / эквивалент).
3. Записать matched / missed / extra:
   ```
   precision = matched / (matched + extra)
   recall    = matched / 15
   ```
4. Цель v3.3.0 baseline: **precision ≥ 0.9, recall ≥ 0.85**.

Отчёт о ручном прогоне сохранять как `<review_root>/RECALL_<sha>.md` рядом с REPORT.md. См. CHANGELOG.md release notes для актуального baseline.

## Известные ограничения fixture'а

- **DVWA-15 (missing_authz конфиг-уровня):** анкер в `security.yaml`, не в коде; recipe выдаёт `auth_layer.summary` корректно, но конкретное несоответствие `^/admin → ROLE_USER` ловит уже воркер по чек-листу `frameworks/symfony/auth.md`.
- **Двойные анкеры:** DVWA-14 (plaintext_password) — два анкера, в `security.yaml` (хешер) и `User::setPassword` (отсутствие хеширования). Воркер должен зарепортить ОДИН finding с обоими; дедуп должен это поддержать (sink_hash на каноничном файле).

## Не путать с

- `symfony_minimal/` — clean-baseline, без vulns (для smoke-tests recipe).
- `symfony_admin/` — minimal admin fixture для проверки `kind: http_route_admin` и базового easyadmin_crud_controllers (2 контроллера, без vulns в смысле «нашли в worker'е»).
- `symfony_hostile_console/` — `composer.json` с post-install hook, для теста sandbox-policy `--no-console`.

`symfony_dvwa/` дополняет их: реалистичный профиль уязвимостей вместо точечной фикстурки.
