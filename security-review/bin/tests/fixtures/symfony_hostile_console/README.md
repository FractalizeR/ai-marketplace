# symfony_hostile_console

Hostile fixture for **R10/R7 sandbox tests** in fr-security-review v3.

**Do not run** `composer install`, `composer update`, or `bin/console` against this
fixture outside the sandbox under test — the composer post-* hooks and
`HostileService::__construct` deliberately write a marker file at
`.snitch/pwned` to simulate attacker-controlled side effects on probe.

S1+ tests assert that running the recipe pipeline against this fixture
**must not** produce `.snitch/pwned`, regardless of whether `--no-console` is set.
