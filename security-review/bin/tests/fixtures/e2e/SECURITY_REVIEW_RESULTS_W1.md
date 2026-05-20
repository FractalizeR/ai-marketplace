# Vulnerability 1: [sql_injection]: `src/Repo.php:42`

* **Severity**: Medium
* **Confidence**: 5/10
* **Category**: sql_injection_dql
* **sink_kind**: dql_concat
* **root_cause_family**: injection
* **enclosing_symbol**: App\Crm\Repo::findByName
* **sink_snippet**: |
    $dql = 'SELECT u FROM User u WHERE u.name = ' . $name;
* **Description**: DQL concatenation without parameterization.
* **Exploitation scenario**: $name = "x' OR 1=1 --"
* **Impact**: arbitrary DB read
* **Recommendation**: use setParameter
* **Discovered via**: checklist:injection.md

# Vulnerability 2: [plaintext_token]: `src/Token.php:33`

* **Severity**: High
* **Confidence**: 9/10
* **Category**: plaintext_secrets_at_rest
* **sink_kind**: other:plaintext_token_at_rest
* **root_cause_family**: crypto
* **enclosing_symbol**: App\Crm\Common\Token
* **sink_snippet**: |
    #[ORM\Column(type: 'string')]
    public string $accessToken;
* **Description**: OAuth tokens stored plaintext.
* **Exploitation scenario**: DB dump -> all tokens exposed
* **Impact**: token theft
* **Recommendation**: field encryption
* **Discovered via**: checklist:crypto.md

# Vulnerability 3: [malformed]: ``

* **Severity**: High
* **Confidence**: 9/10
* **Category**: should_be_rejected
* **sink_kind**: missing_authz
* **root_cause_family**: authz
* **enclosing_symbol**: unknown
* **sink_snippet**: (no snippet)
* **Description**: malformed -- empty sink_file
* **Discovered via**: checklist:auth.md
