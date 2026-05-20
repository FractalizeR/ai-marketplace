# Уязвимость 1: [sql_injection]: `src/Repo.php:42`

* **Severity**: Medium
* **Confidence**: 5/10
* **Категория**: sql_injection_dql
* **sink_kind**: dql_concat
* **root_cause_family**: injection
* **enclosing_symbol**: App\Crm\Repo::findByName
* **sink_snippet**: |
    $dql = 'SELECT u FROM User u WHERE u.name = ' . $name;
* **Описание**: DQL concatenation без параметризации.
* **Сценарий эксплуатации**: $name = "x' OR 1=1 --"
* **Потенциальное влияние**: arbitrary DB read
* **Рекомендация**: использовать setParameter
* **Discovered via**: checklist:injection.md

# Уязвимость 2: [plaintext_token]: `src/Token.php:33`

* **Severity**: High
* **Confidence**: 9/10
* **Категория**: plaintext_secrets_at_rest
* **sink_kind**: other:plaintext_token_at_rest
* **root_cause_family**: crypto
* **enclosing_symbol**: App\Crm\Common\Token
* **sink_snippet**: |
    #[ORM\Column(type: 'string')]
    public string $accessToken;
* **Описание**: OAuth tokens stored plaintext.
* **Сценарий эксплуатации**: DB dump → all tokens exposed
* **Потенциальное влияние**: token theft
* **Рекомендация**: field encryption
* **Discovered via**: checklist:crypto.md

# Уязвимость 3: [malformed]: ``

* **Severity**: High
* **Confidence**: 9/10
* **Категория**: should_be_rejected
* **sink_kind**: missing_authz
* **root_cause_family**: authz
* **enclosing_symbol**: unknown
* **sink_snippet**: (no snippet)
* **Описание**: malformed — empty sink_file
* **Discovered via**: checklist:auth.md
