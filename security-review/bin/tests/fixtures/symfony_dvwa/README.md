# symfony_dvwa -- Damn Vulnerable Symfony fixture

> **Do not run.** This is intentionally broken code that exists solely to verify plugin recall.

## Purpose

Without a known-vulnerable fixture it is impossible to distinguish "the recipe missed injection-relevant files" from "the project really has no SQLi", and there is no way to measure numeric plugin recall.

`symfony_dvwa` pins **15 heterogeneous vulnerabilities** on Symfony 7 + EasyAdmin, covering all 6 focal waves (W1 auth/disclosure, W2 injection/data-access, W3 xss/SSTI, W4 deserialization/crypto, W5 ssrf-fileops, W6 -- not exercised here, fintech_markers come only from the Order entity for inventory recall).

## Layout

```
src/
  Entity/{User,Post,Order}.php           # entities + fields for vulnerabilities
  Repository/{User,Post,Order}Repository.php
  Controller/
    ApiController.php                    # DVWA-02, DVWA-07
    AuthController.php                   # DVWA-06, DVWA-08
    FileController.php                   # DVWA-05
    PostController.php                   # template render DVWA-03
    SearchController.php                 # DVWA-04
    UserController.php                   # DVWA-13
    Admin/
      DashboardController.php
      UserCrudController.php             # DVWA-11, DVWA-12
      OrderCrudController.php            # control case (wired via OrderVoter)
  Form/UserType.php                      # DVWA-08, DVWA-09
  Security/Voter/OrderVoter.php          # demo voter (only Order wired)
  Service/PaymentClient.php              # dynamic base_url for http_clients recall
config/
  packages/{security,twig,messenger}.yaml  # DVWA-03 (autoescape), DVWA-07 (php_serialize), DVWA-14, DVWA-15
  services.yaml                            # DVWA-10 (hardcoded secret in yaml)
templates/post/show.html.twig            # DVWA-03 sink
golden_findings.yaml                     # 15 expected findings with sink_kind / wave
```

## How to use

### Inventory recall (automated)

`bin/tests/test_dvwa_inventory_recall.py` -- unit test, runs `recon_inventory.py --recipe symfony --no-console` on the fixture and verifies that:

- `attack_surface` contains exactly the expected number of http_route / http_route_admin items;
- `data_access` contains all 3 repositories;
- `serialization` catches `unserialize($_COOKIE)` (DVWA-07);
- `file_operations` catches `file_get_contents` (DVWA-05);
- `http_clients` catches `HttpClientInterface` / `HttpClient::create` (DVWA-services pivot);
- `framework_specific.symfony.forms` contains `UserType` with `csrf_protection: false`, `allow_extra_fields: true` (DVWA-08, DVWA-09);
- `framework_specific.symfony.easyadmin_crud_controllers` contains the User + Order CrudControllers;
- `framework_specific.symfony.admin_authz_coverage.crud_controllers_without_voter` includes `UserCrudController` (DVWA-12 trigger).

### Worker recall (manual)

The LLM worker is driven manually via `/security-project` or an equivalent CLI on this fixture. After the run:

1. Open the final `<review_root>/REPORT.md` (or split-files in `REPORT/`).
2. For each finding in `golden_findings.yaml`, check whether the report has a counterpart (by `file:line` +- 5 lines + matching `sink_kind` / equivalent).
3. Record matched / missed / extra:
   ```
   precision = matched / (matched + extra)
   recall    = matched / 15
   ```
4. v3.3.0 baseline target: **precision >= 0.9, recall >= 0.85**.

Save the manual-run report as `<review_root>/RECALL_<sha>.md` next to REPORT.md. See CHANGELOG.md release notes for the current baseline.

## Known fixture limitations

- **DVWA-15 (missing_authz at config level):** anchor is in `security.yaml`, not in code; the recipe emits `auth_layer.summary` correctly, but the specific `^/admin -> ROLE_USER` mismatch is caught by the worker against the `frameworks/symfony/auth.md` checklist.
- **Dual anchors:** DVWA-14 (plaintext_password) -- two anchors, in `security.yaml` (hasher) and `User::setPassword` (no hashing). The worker must report ONE finding spanning both; dedupe must support this (sink_hash on the canonical file).

## Not to be confused with

- `symfony_minimal/` -- clean baseline, no vulns (for recipe smoke tests).
- `symfony_admin/` -- minimal admin fixture for checking `kind: http_route_admin` and basic easyadmin_crud_controllers (2 controllers, no vulns in the "found by the worker" sense).
- `symfony_hostile_console/` -- `composer.json` with a post-install hook, for testing the sandbox policy `--no-console`.

`symfony_dvwa/` complements them: a realistic vulnerability profile instead of a pinpoint fixture.
