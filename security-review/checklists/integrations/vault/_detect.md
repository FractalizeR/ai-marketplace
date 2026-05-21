# HashiCorp Vault integration — detection

This file describes how the recon agent detects HashiCorp Vault use and activates checklists from `integrations/vault/`. It is not a checklist — there are no vulnerability items.

## Vault signals (composer + env + source)

`bin/recon/recipes/vault_detect.py::detect_vault()` marks the project as using Vault if ANY of:

1. `composer.json` `require` / `require-dev` contains (all names verified on packagist):
   - `csharpru/vault-php` — most popular community Vault client.
   - `mittwald/vault-php` — alternative community Vault client.
   - `jippi/vault-php-sdk` — Jippi Vault PHP SDK.
   - `violuke/vault-php-sdk` — community Vault SDK fork.
2. `.env` / `.env.example` / `.env.local` / `.env.dist` declares any of `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_AUTH_METHOD`.
3. PHP source under `src/` or `app/` contains the substring `/v1/secret/` (canonical Vault KV v1 API path) OR `/v1/secret/data/` (KV v2 path — dominant deployment shape since Vault 0.10 in 2018).

The probe is intentionally lightweight (composer + env + bounded source scan with vendor-skip). On a hit, the recon agent adds `vault` to `stack.integrations` in `CONTEXT.md`; `plan_waves.resolve_checklists(...)` then loads `integrations/vault/{theme}.md`.

Note: `vault` does NOT imply `jwt-generic` / `oauth-oidc` — even though Vault can issue JWT-shaped tokens via its auth methods, the integration's security surface is Vault's own client-server protocol (TLS, token leases, policies), not standard JWT verification.

Canonical docs: [https://developer.hashicorp.com/vault/docs](https://developer.hashicorp.com/vault/docs).
