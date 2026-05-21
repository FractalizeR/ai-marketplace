# AWS Cognito (User Pools) integration — detection

This file describes how the recon agent detects AWS Cognito User Pool use and activates checklists from `integrations/aws-cognito/`. It is not a checklist — there are no vulnerability items.

## Cognito signals (composer + env + source)

`bin/recon/recipes/aws_cognito_detect.py::detect_aws_cognito()` marks the project as using Cognito if ANY of:

1. `composer.json` contains a SPECIALIZED Cognito package (NOT the umbrella `aws/aws-sdk-php`). All names below are real, verified on packagist:
   - `async-aws/cognito-identity-provider` — split-SDK Cognito client.
   - `ellaisys/aws-cognito` — Laravel Cognito guard.
   - `black-bits/laravel-cognito-auth` — Laravel Cognito auth.
   - `pmill/aws-cognito` — generic PHP Cognito helpers.
   - `cakedc/oauth2-cognito` — league/oauth2-client Cognito provider.
   - `socialiteproviders/cognito` — Laravel Socialite Cognito provider.
   - `customergauge/cognito` — another community Cognito client.
2. `.env` references `COGNITO_USER_POOL_ID`, `COGNITO_CLIENT_ID`, `COGNITO_REGION`, or `AWS_COGNITO_POOL_ID`.
3. PHP source under `src/` or `app/` contains either:
   - the class name substring `CognitoIdentityProviderClient` (canonical AWS SDK client class for User Pools), OR
   - the URL substring `cognito-idp.` (canonical service endpoint host).

The bare composer dependency `aws/aws-sdk-php` is INTENTIONALLY NOT a signal — it ships dozens of unrelated service clients (S3, DynamoDB, SES, …) and is depended on by countless non-IAM projects. A stronger signal is required.

The probe is bounded: at most 500 PHP files, 256 KB read per file; never walks the `vendor/` tree.

On a hit, the recon agent adds `aws-cognito` to `stack.integrations` in `CONTEXT.md`; `plan_waves.resolve_checklists(...)` then loads `integrations/aws-cognito/{theme}.md` after the generic `integrations/jwt-generic/` and `integrations/oauth-oidc/` layers, with the provider rules winning on conflict.

Canonical docs: [https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html).
