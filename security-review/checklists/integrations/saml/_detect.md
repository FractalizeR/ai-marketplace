# SAML federation integration — detection

This file describes how the recon agent detects SAML 2.0 use and activates checklists from `integrations/saml/`. It is not a checklist — there are no vulnerability items.

## SAML signals (composer + env + metadata file)

`bin/recon/recipes/saml_detect.py::detect_saml()` marks the project as using SAML if ANY of:

1. `composer.json` `require` / `require-dev` contains (all names verified on packagist):
   - `onelogin/php-saml` — OneLogin's PHP SAML toolkit.
   - `simplesamlphp/saml2` — SimpleSAMLphp's SAML2 library.
   - `simplesamlphp/simplesamlphp` — SimpleSAMLphp full IdP/SP.
   - `hslavich/oneloginsaml-bundle` — legacy Symfony bundle for OneLogin php-saml (abandoned but still found in older projects).
   - `nbgrp/onelogin-saml-bundle` — active fork; canonical Symfony bundle since 2022.
   - `aacotroneo/laravel-saml2` — original Laravel SAML2 bridge (abandoned).
   - `24slides/laravel-saml2` — active fork of `aacotroneo/laravel-saml2`.
2. `.env` / `.env.example` / `.env.local` / `.env.dist` declares any of `SAML_IDP_METADATA_URL`, `SAML_IDP_ENTITY_ID`, `SAML_SP_ENTITY_ID`.
3. A metadata XML file (`metadata.xml` or `idp_metadata.xml`) is present in the repository root or in `config/` AND contains the SAML OASIS namespace marker `urn:oasis:names:tc:SAML` within the first 2 KB. The namespace check disambiguates from unrelated `metadata.xml` files (Apache, Maven, NuGet, Composer descriptors).

The probe is intentionally lightweight (composer + env + filesystem checks only). On a hit, the recon agent adds `saml` to `stack.integrations` in `CONTEXT.md`; `plan_waves.resolve_checklists(...)` then loads `integrations/saml/{theme}.md`.

Note: `saml` does NOT imply `jwt-generic` / `oauth-oidc` — SAML uses XML signatures (XML-DSig) for assertion authenticity, not JWTs, and its protocol surface (XML signature wrapping, recipient validation, XXE) is distinct from OAuth/OIDC.

Canonical docs: [https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf).
