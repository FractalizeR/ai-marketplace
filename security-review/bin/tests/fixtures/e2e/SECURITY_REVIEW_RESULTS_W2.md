# Уязвимость 1: [sql_injection]: `src/Repo.php:42`

* **Severity**: Critical
* **Confidence**: 10/10
* **Категория**: sql_injection_via_sort_param
* **sink_kind**: dql_concat
* **root_cause_family**: injection
* **enclosing_symbol**: Repo::findByName
* **sink_snippet**: |
    $dql = "SELECT u FROM User u WHERE u.name = " . $name;
* **Описание**: SQL injection в Repo::findByName (same as W1 but different severity; quotes differ → hash mismatch).
* **Сценарий эксплуатации**: exfiltrate all users
* **Потенциальное влияние**: full DB read
* **Рекомендация**: parametrize
* **Discovered via**: checklist:injection.md

# Уязвимость 2: [plaintext_token_variant]: `src/Token.php:33`

* **Severity**: High
* **Confidence**: 8/10
* **Категория**: plaintext_storage_variant
* **sink_kind**: other:secret-plaintext-storage
* **root_cause_family**: crypto
* **enclosing_symbol**: Token
* **sink_snippet**: |
    different snippet here
* **Описание**: same vuln, different classification (tests cross-sink + normalizer).
* **Сценарий эксплуатации**: DB dump
* **Потенциальное влияние**: token theft
* **Рекомендация**: encrypt
* **Discovered via**: checklist:crypto.md

# Уязвимость 3: [low_confidence_custom]: `src/Misc.php:10`

* **Severity**: Medium
* **Confidence**: 6/10
* **Категория**: speculative_custom_sink
* **sink_kind**: other:some-weird-pattern
* **root_cause_family**: business_logic
* **enclosing_symbol**: Misc::speculate
* **sink_snippet**: |
    $x = rand();
* **Описание**: custom sink low confidence — goes to manual review.
* **Сценарий эксплуатации**: n/a
* **Потенциальное влияние**: unclear
* **Рекомендация**: review
* **Discovered via**: checklist:other.md
