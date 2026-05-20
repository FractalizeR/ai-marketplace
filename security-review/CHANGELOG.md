# Changelog

All notable changes to this plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.4.0] — 2026-05-20

### Initial public release

First public release. Version 3.4.0 inherits the version number from a private predecessor for numbering continuity.

**What is included:**

- Slash commands `/fr-security-review:security-project` and `/fr-security-review:security-changes` for PHP projects.
- Recipe-driven recon with support for Symfony, Laravel, and generic PHP. Schema v2 (`<review_root>/CONTEXT.md` with frontmatter and closed shape specs).
- 6 focused worker waves: W1 auth/disclosure, W2 injection/data-access, W3 output-render, W4 serialization/crypto, W5 ssrf+fileops, W6 fintech + W∞ exploratory (cross-layer chains).
- Adversarial pass (second-pass refute) and the option to disable it via `--no-adversarial`.
- Detection: GraphQL (lighthouse, rebing-laravel, api-platform, webonyx), EasyAdmin, Sonata, Octane, messenger transports, sensitive columns.
- Detection regression: "removed-defense" — detection of removed validators/sanitizers in `/security-changes`.
- Deterministic deduplication (`dedupe_findings.py`) with split report `REPORT.md` + `REPORT/<root_cause_family>.md`.
- 767 unit/regression tests for recon, dedupe, and e2e pipeline (stdlib only, no third-party Python deps).
- Sandbox modes: `--no-console`, firejail, Docker.
- Project-level exclude via `<project_root>/CLAUDE.md` and `--exclude=<csv>`.

**License:** Elastic License 2.0.
