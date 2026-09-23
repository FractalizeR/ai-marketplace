<!-- wave_format: 2 -->

# Vulnerability 1: [ssrf_via_webhook]: `src/Example/PaymentController.php:88`

* **Severity**: High
* **Confidence**: 9/10
* **Category**: ssrf_via_webhook_url
* **sink_kind**: ssrf
* **root_cause_family**: ssrf
* **enclosing_symbol**: Example\PaymentController::charge
* **sink_snippet**: |
    $response = $client->request('GET', $url);
* **Description**: Outbound HTTP request built from an unvalidated webhook URL.
* **Exploitation scenario**: attacker-controlled webhook_url reaches an internal-only endpoint
* **Impact**: SSRF against internal services
* **Recommendation**: allow-list destination hosts
* **Discovered via**: checklist:ssrf.md

# Needs validation 1: `src/Example/PaymentController.php:91`

* **sink_kind**: ssrf
* **root_cause_family**: ssrf
* **enclosing_symbol**: Example\PaymentController::charge
* **sink_snippet**: |
    $client->request('GET', $webhookUrl, ['timeout' => 5]);
* **claimed_root_cause**: Same SSRF sink as Vulnerability 1, but this worker could not confirm whether `$webhookUrl` is attacker-controlled at this exact call site (different snippet text -> different sink_hash; the two must bind by location, not by hash).
* **trace**: PaymentController::charge -> $webhookUrl -> HTTP client GET.
* **blockers**:
    - could not confirm the upstream caller passes an attacker-controlled URL into this specific call
* **validation_plan_local**: trace webhookUrl provenance through the queue consumer that invokes charge().
* **Discovered via**: checklist:ssrf.md

# Needs validation 2: `src/Example/ReportExporter.php:40`

* **sink_kind**: path_traversal
* **root_cause_family**: injection
* **enclosing_symbol**: Example\ReportExporter::export
* **sink_snippet**: |
    $path = $baseDir . '/' . $request->query->get('name');
* **claimed_root_cause**: Unvalidated filename from the query string concatenated into a filesystem path.
* **trace**: ReportExporter::export -> $request->query->get('name') -> file path build.
* **blockers**:
    - could not confirm baseDir is applied as a strict prefix check downstream
* **validation_plan_local**: trace the file read call for a realpath/prefix check.
* **Discovered via**: checklist:injection.md

# Needs validation 3: `src/Example/ReportExporter.php:40`

* **sink_kind**: ssrf
* **root_cause_family**: ssrf
* **enclosing_symbol**: Example\ReportExporter::export
* **sink_snippet**: |
    $path = $baseDir . '/' . $request->query->get('name');
* **claimed_root_cause**: Same call site, reported by a different checklist pass as a possible SSRF sink (the filename mistaken for a remote fetch target) -- identical snippet, disagreeing sink_kind.
* **trace**: ReportExporter::export -> $request->query->get('name') -> possibly passed to a remote fetch elsewhere.
* **blockers**:
    - two checklist passes disagree on sink_kind for this exact snippet; needs a human call
* **validation_plan_local**: confirm whether $path (or a value derived from it) is ever passed to an HTTP client instead of a local filesystem call.
* **Discovered via**: checklist:ssrf.md
