# Changelog

All notable changes to this plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.4.0] — 2026-05-20

### Initial public release

First public release. Version 3.4.0 inherits the version number from a private predecessor for numbering continuity.

**Что входит:**

- Slash-команды `/fr-security-review:security-project` и `/fr-security-review:security-changes` для PHP-проектов.
- Recipe-driven recon с поддержкой Symfony, Laravel и generic PHP. Schema v2 (`<review_root>/CONTEXT.md` с frontmatter и закрытыми shape-спеками).
- 6 фокусных волн воркеров: W1 auth/disclosure, W2 injection/data-access, W3 output-render, W4 serialization/crypto, W5 ssrf+fileops, W6 fintech + W∞ exploratory (cross-layer chains).
- Adversarial pass (refute второго прохода) и его отключение через `--no-adversarial`.
- Detection: GraphQL (lighthouse, rebing-laravel, api-platform, webonyx), EasyAdmin, Sonata, Octane, messenger transports, sensitive columns.
- Detection regression: «removed-defense» — обнаружение удалённых валидаторов/санитайзеров в `/security-changes`.
- Детерминированная дедупликация (`dedupe_findings.py`) с split-отчётом `REPORT.md` + `REPORT/<root_cause_family>.md`.
- 767 unit/regression-тестов на recon, dedupe и e2e pipeline (stdlib only, без third-party Python deps).
- Sandbox-режимы: `--no-console`, firejail, Docker.
- Project-level exclude через `<project_root>/CLAUDE.md` и `--exclude=<csv>`.

**Лицензия:** Elastic License 2.0.
