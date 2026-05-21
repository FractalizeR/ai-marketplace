# SSRF / HTTP Client / File operations / Uploads

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `ssrf` — outgoing request to a user-controlled URL (host/protocol)
- `redirect_open` — open redirect via user input
- `path_traversal` — file ops with an unchecked path
- `file_include_dynamic` — `include`/`require` with a user-controlled path (cross-ref `injection.md`)

## Confidence floor rules

- **`redirect_open` cap — path-only control**: when only the URL **path** is attacker-controlled (host/scheme/port hardcoded in code), the redirect cannot leave the application → max confidence 5.
  - **Cap engages on** (capped to ≤5, dropped under the ≥8 gate): `header("Location: /profile/" . $userId)`, `return redirect("/orders/" . $id)` — host implicit-same-origin.
  - **Cap does NOT engage on** (still reported as `redirect_open`): `header("Location: " . $_GET['next'])` where `$_GET['next']` may be a full URL.
- **`ssrf` cap — path-only control**: when only the URL **path** is attacker-controlled (host/scheme hardcoded in code), real SSRF is not possible → max confidence 5. Exception (cap does NOT engage): a hardcoded host that itself fronts internal admin APIs / cloud metadata / `/_profiler` / unix-socket gateways, where the user-controlled path crosses into a new internal surface — that *is* SSRF (see "Do NOT automatically exclude" in `agents/security.md`).
  - **Cap engages on** (capped to ≤5, dropped under the ≥8 gate): `$client->get("https://api.example.com/users/" . $userId)`, `file_get_contents("https://internal-api/items/{$id}")` — host fully hardcoded, path is the only user-controlled segment and does not cross into a sensitive internal surface.
  - **Cap does NOT engage on** (still reported as `ssrf`): `$client->get($_GET['url'])`, `curl_init($request->input('endpoint'))` where the attacker controls scheme+host; or `$client->get("http://169.254.169.254/" . $userPath)` / `$client->get("http://localhost/_profiler/" . $token)` where the hardcoded host already fronts a sensitive internal surface.

## SSRF via HTTP Client

- HTTP client of any framework with a user-controlled URL argument (`request($method, $userUrl)`)
- Guzzle with a user-controlled base URI
- `file_get_contents($url)` where `$url` is user input (reads through the HTTP wrapper)
- `curl_init($url)` with a user URL
- Missing whitelist of hosts / schemes (`http`/`https` only, block `file://`, `gopher://`, `dict://`)
- Missing block of private IPs: `127.0.0.1`, `169.254.169.254` (AWS metadata), `10.0.0.0/8`, `192.168.0.0/16`
- DNS rebinding: host check before resolve, but actual resolution happens later — use IP resolution and re-check
- TOCTOU between validation (admin form / `SafeUrl` constraint when saved to DB) and use (HTTP request in the worker) — if the URL is stored between T1 and T2, the attacker can flip the DNS record to a private IP in this window (classic DNS rebinding with TTL ≤ 30s). Especially typical for Symfony Messenger pipelines: admin form → DB → async consumer → `httpClient->request($url, ...)`. Fix: revalidate the URL before the HTTP request, or `RequestOptions::RESOLVE` (Guzzle) / `'resolve' =>` (Symfony HttpClient) with the IP resolved at validation time, or an egress firewall at the network layer

## SSRF via webhooks / callbacks

- User-configurable webhook URL without a whitelist → SSRF to internal services
- OAuth callback URL not validated against registered redirects
- Image/PDF generators (wkhtmltopdf, Puppeteer) that accept a user URL — SSRF + potentially RCE via the browser

## Open redirects

- `return $this->redirect($request->...->get('next'))` without a whitelist
- Redirect response with a user URL after login / action — phishing vector
- Protocol-relative URLs `//evil.com` — bypass a naive `startswith('/')` check
- URL without scheme validation (`javascript:...`, `data:...`)

## File operations — path traversal

- `file_get_contents($userPath)` without `realpath()` + whitelist of the base directory
- `fopen($userPath, ...)` with user input
- `readfile($userPath)` for download — directly allows `../../../etc/passwd`
- `basename()` is insufficient — it returns the last segment, but a user can supply `../sensitive/file`
- Sanitization only against `..` via `str_replace`, without accounting for URL encoding (`%2e%2e%2f`)
- `realpath()` is used, but a base whitelist is not applied

## File uploads

- Missing MIME check by content (`finfo_file`) — relying on `$_FILES['file']['type']` (client-controlled)
- Saving the file with the original name without sanitization → `../../../attack.php`
- Missing extension check against a whitelist
- Upload into a web-accessible directory → executable PHP/PHAR files
- Missing size limit (`upload_max_filesize`, application-level)
- ZIP bombs / decompression without limits
- Polyglot files (GIF+PHP) — MIME magic matches, but the content is dangerous
- Framework-level `UploadedFile::move()` with a user-controlled `$name`

## File inclusion

- `include($userPath . '.php')` — LFI, see `injection.md`
- Template loaders with a user-controlled path
- Local PHAR files with metadata — `file_exists()` on a phar URL triggers unserialize of metadata

## Download endpoints

- `/download?file=...` without authz (see also `auth.md` IDOR)
- `Content-Disposition` with a user-controlled filename — possibility to inject CRLF / path traversal into the header
- MIME sniffing prevention: missing `X-Content-Type-Options: nosniff`

## Export / CSV injection

- User data in CSV exports without prefix escaping: cells starting with `=`, `+`, `-`, `@` can execute when opened in Excel/LibreOffice
- Export to SVG with user content → XSS when the file is opened in a browser
