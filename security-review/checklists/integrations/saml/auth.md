# Authentication / Authorization (SAML federation)

> This checklist extends `core/auth.md` for projects that use SAML 2.0 for SSO federation. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Confidence floor rules

- **XML Signature Wrapping (XSW) detected**: SAML response with multiple `<Subject>` / `<Assertion>` elements where only one is signed → `other:saml_signature_wrap` **confidence ≥ 9**. CVE-2017-11427 (OneLogin SAML toolkit family, applies to the PHP variant) is the canonical historical reference for this class. Worker patterns: more than one `Subject` element in the parsed document, signed `Assertion` carrying an inner `Subject` that the validator returns instead of the outer attacker-controlled one.
- **`LIBXML_NOENT` set when parsing SAML response** (`simplexml_load_string($xml, …, LIBXML_NOENT)`) → `xxe` **confidence ≥ 9**. Cross-ref `core/injection.md` (where the `xxe` sink_kind is defined). Even with signature verification, XXE in the IdP-supplied XML reads server-side files / exfiltrates via DNS during parse.
- **Validator accepts SHA-1 signatures** without an enterprise policy waiver → `weak_hash` confidence ≥ 8. SHA-1 is considered collision-broken; SAML's typical signing context is malleable enough to make this exploitable in practice for sophisticated attackers.

## XML Signature Wrapping (XSW)

SAML responses carry XML-DSig signatures. XSW attacks rearrange the document so the verified signature covers one subtree while the validator reads identity from a different (attacker-controlled) subtree. CVE-2017-11427 (OneLogin SAML toolkit family, applies to the PHP variant) is the canonical historical instance.

Common variants:
- **XSW1/2**: signed assertion is duplicated; the validator returns the unsigned outer assertion's `<Subject>` while signature validation succeeded on the inner one.
- **XSW3/4**: attacker-controlled `<Assertion>` wraps the original signed assertion; the validator descends into the wrong assertion.
- **XSW7/8**: payload moved into `<Extensions>` or `<Object>` — atypical XML locations that the validator may still parse.

Defenses to look for:
- Validator returns the `Reference` URI'd subtree (XPath-anchored to the signature) — NOT a "first matching element" of the SAML response.
- Library actively maintained — newer `saml-toolkits/php-saml` v4+ (and the `onelogin/php-saml` alias) ship signature-validation hardening; pre-3.x versions had documented XSW issues. Worker should still confirm via a concrete code path, not version alone.
- Counting check on `<Assertion>` / `<Subject>` elements before validation; reject documents with > 1.

Sink: `other:saml_signature_wrap` (or `oidc_misconfig` as nearest enum match if `other:` is undesirable for the project).

## IdP metadata trust

- **Metadata fetched at runtime over plain HTTP**: an attacker on the network replaces the metadata, installs an attacker-controlled signing key, signs assertions on a victim user's behalf. Sink: `oidc_misconfig` (no SAML-specific enum value; closest match).
- **Metadata fetched over HTTPS but `validateSignature: false`**: even HTTPS-fetched metadata should be cryptographically pinned (signed by a metadata-signing key, or pinned to a fingerprint). Without pinning, a TLS-MitM (compromised CA, captive-portal) achieves the same. Sink: `tls_validation_bypass` (closer to `core/crypto.md`) or `oidc_misconfig`.
- **Metadata file checked into repo and never refreshed**: certificate rotation on the IdP side will cause "auth broken" outages, then someone disables signature validation as a quick fix. Architecture-level finding.

## NameID confusion

SAML `NameID` is the IdP's user identifier. Its format (e.g. `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `…:persistent`, `…:emailAddress`) controls its semantic.

- **`NameID` used as primary key without `Issuer` qualifier**: if the application federates multiple IdPs and uses bare `NameID` as the user lookup, an attacker controlling IdP B who can create a user with the same NameID as victim's IdP-A entry takes over the victim's account. Always key on `(Issuer, NameID)` or `(Issuer, NameID, SPNameQualifier)`. Sink: `missing_authz`.
- **`emailAddress` NameID treated as verified email**: IdP B may issue `emailAddress` NameIDs without verifying ownership. Cross-ref `core/auth.md` (account-takeover via email-trust).
- **`transient` NameID stored as if `persistent`**: transient NameIDs CHANGE between sessions; using them as primary key breaks login on the second session.

## Assertion replay (`Conditions/NotOnOrAfter`)

SAML assertions carry validity windows in `Conditions/NotBefore` and `Conditions/NotOnOrAfter`. Bearer assertions can be replayed within that window if the SP doesn't track usage.

- **`NotOnOrAfter` not enforced**: code that doesn't reject expired assertions accepts ancient assertions indefinitely. Look for the validator's clock-skew tolerance — typical is ±5 minutes; widening to hours is a smell.
- **Assertion ID (`ID` attribute) not tracked**: even within the validity window, the same assertion should be usable only once. SP should maintain a short-lived cache of assertion IDs. Sink: `other:saml_assertion_replay` (SAML-specific; do not conflate with `webhook_replay`, which is HMAC-signed-webhook-specific).

## Recipient and audience validation

`SubjectConfirmation/SubjectConfirmationData` carries `Recipient` (typically the SP's ACS URL) and `Conditions/AudienceRestriction/Audience` carries the SP's entity ID. Both are anti-cross-site / anti-cross-SP defenses.

- **`AudienceRestriction` not validated**: assertion forged for SP A is accepted by SP B (cross-SP confusion). Sink: `oidc_misconfig`.
- **`Recipient` not validated against the ACS URL**: assertion intercepted at SP A's ACS replayed against SP B's ACS — same as above for transport.
- **`InResponseTo` not enforced** for SP-initiated flows: response not bound to a previous AuthnRequest → CSRF on the auth flow (semantically analogous to OAuth `state`, but SAML-specific). Sink: `other:saml_inresponseto_missing`.

## XML External Entity (XXE) in SAML parsing

SAML responses are XML; the parser is configured at construction time.

- **`simplexml_load_string` / `DOMDocument::loadXML` with `LIBXML_NOENT`**: see Confidence floor rules. Even modern PHP doesn't default to this — but legacy code that "fixed entity references" by enabling NOENT created the vector.
- **External DTDs allowed**: `LIBXML_DTDLOAD | LIBXML_DTDATTR` — same vector, modern PHP defaults disable. Look for explicit option-passing on the parser.
- **`libxml_disable_entity_loader(false)` global toggle**: any earlier code in the request can flip it; defense-in-depth requires asserting the disabled state inside SAML parsing.

## Algorithm and key handling

- **Signing algorithm SHA-1 accepted**: see Confidence floor rules. SHA-1 in XML-DSig: `http://www.w3.org/2000/09/xmldsig#rsa-sha1`. Modern: `…rsa-sha256` / `…rsa-sha512`.
- **Validator pinned to a single certificate that's been rotated** vs IdP that signs with new key: causes outage → temptation to disable validation. Architecture-level.
- **Encrypted assertion key not validated for size / algorithm**: RSA-1.5 key transport (`http://www.w3.org/2001/04/xmlenc#rsa-1_5`) is vulnerable to Bleichenbacher attacks. Prefer RSA-OAEP. Cross-ref `core/crypto.md`.

## Logout (SLO)

SAML Single Logout uses `LogoutRequest` / `LogoutResponse` — signed messages.

- **LogoutRequest signature not validated**: attacker invalidates a victim's session by sending a forged LogoutRequest → denial of service on individual sessions.
- **`NameID` in LogoutRequest used to terminate sessions by user identifier** without cross-checking session ownership: a logout intended for one IdP's session terminates all sessions for that NameID across all IdPs.

## Worker search patterns

- `OneLogin\\Saml2` / `SAML2\\` / `Hslavich\\OneloginSamlBundle` / `Nbgrp\\OneloginSamlBundle` namespaces in code — entry points for response processing.
- `loadXML\(` / `simplexml_load_string\(` near SAML response handling — XXE surface; check second argument flags.
- `LIBXML_NOENT` / `LIBXML_DTDLOAD` literals — see Confidence floor rules.
- `auth->getNameId\(` / `auth->getNameIdFormat\(` — NameID consumer; check that callers also check Issuer.
- `<ds:SignatureMethod` with `Algorithm.*sha1` in pinned metadata or sample responses — weak hash.
- `validateSignature\s*=>\s*false` / `wantAssertionsSigned\s*=>\s*false` — toggle-off patterns to inspect.
