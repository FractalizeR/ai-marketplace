# AWS Secrets Manager integration — detection

This file describes how the recon agent detects AWS Secrets Manager use and activates checklists from `integrations/aws-secrets-manager/`. It is not a checklist — there are no vulnerability items.

## AWS Secrets Manager signals (env + source, with SDK gate)

`bin/recon/recipes/aws_secrets_manager_detect.py::detect_aws_secrets_manager()` marks the project as using Secrets Manager if ANY of:

1. `.env` / `.env.example` / `.env.local` / `.env.dist` declares any of `AWS_SECRETS_MANAGER_REGION`, `AWS_SECRETS_MANAGER_ARN`, `AWS_SECRETS_MANAGER_SECRET_ID`.
2. PHP source under `src/` or `app/` contains the class name `SecretsManagerClient` (canonical AWS SDK client). Fires on its own — no SDK corroboration required.
3. PHP source contains the URL substring `secretsmanager.` AND `composer.json` declares `aws/aws-sdk-php` in `require`/`require-dev`. The host alone is too narrow a signal without the umbrella SDK present.

Why the SDK gate matters: the umbrella `aws/aws-sdk-php` package ships hundreds of service clients (S3, DynamoDB, SES, …) and is depended on by countless projects unrelated to Secrets Manager. Composer alone is therefore NOT a signal — there is no "specialized" Secrets Manager package on packagist analogous to `async-aws/cognito-identity-provider`.

On a hit, the recon agent adds `aws-secrets-manager` to `stack.integrations` in `CONTEXT.md`; `plan_waves.resolve_checklists(...)` then loads `integrations/aws-secrets-manager/{theme}.md`.

Note: `aws-secrets-manager` does NOT imply `jwt-generic` / `oauth-oidc` — it's a key/secret store, not an identity provider.

Canonical docs: [https://docs.aws.amazon.com/secretsmanager/](https://docs.aws.amazon.com/secretsmanager/).
