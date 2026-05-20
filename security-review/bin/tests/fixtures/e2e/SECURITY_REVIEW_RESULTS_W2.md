# Vulnerability 1: [sql_injection]: `src/Repo.php:42`

* **Severity**: Critical
* **Confidence**: 10/10
* **Category**: sql_injection_via_sort_param
* **sink_kind**: dql_concat
* **root_cause_family**: injection
* **enclosing_symbol**: Repo::findByName
* **sink_snippet**: |
    $dql = "SELECT u FROM User u WHERE u.name = " . $name;
* **Description**: SQL injection in Repo::findByName (same as W1 but different severity; quotes differ -> hash mismatch).
* **Exploitation scenario**: exfiltrate all users
* **Impact**: full DB read
* **Recommendation**: parametrize
* **Discovered via**: checklist:injection.md

# Vulnerability 2: [plaintext_token_variant]: `src/Token.php:33`

* **Severity**: High
* **Confidence**: 8/10
* **Category**: plaintext_storage_variant
* **sink_kind**: other:secret-plaintext-storage
* **root_cause_family**: crypto
* **enclosing_symbol**: Token
* **sink_snippet**: |
    different snippet here
* **Description**: same vuln, different classification (tests cross-sink + normalizer).
* **Exploitation scenario**: DB dump
* **Impact**: token theft
* **Recommendation**: encrypt
* **Discovered via**: checklist:crypto.md

# Vulnerability 3: [low_confidence_custom]: `src/Misc.php:10`

* **Severity**: Medium
* **Confidence**: 6/10
* **Category**: speculative_custom_sink
* **sink_kind**: other:some-weird-pattern
* **root_cause_family**: business_logic
* **enclosing_symbol**: Misc::speculate
* **sink_snippet**: |
    $x = rand();
* **Description**: custom sink low confidence -- goes to manual review.
* **Exploitation scenario**: n/a
* **Impact**: unclear
* **Recommendation**: review
* **Discovered via**: checklist:other.md
