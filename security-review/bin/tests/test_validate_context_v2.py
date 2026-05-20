"""Tests for validate_context.py — schema v2.

Covers:
  - Frontmatter validation (required keys, schema_version, recon_confidence shapes).
  - Core sections v2 (shape, status, required-presence).
  - framework_specific bag validation against recipe FRAMEWORK_SPECIFIC_SCHEMA.
  - Recipe-driven sanity probes (coverage diff ladder, hallucination check).
  - Ceiling enforcement (level cannot exceed ceiling).
  - CLI: --review-root contract.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
BIN_DIR = THIS_DIR.parent
sys.path.insert(0, str(BIN_DIR))

import validate_context as vc  # noqa: E402

FIX_MIN = THIS_DIR / "fixtures" / "symfony_minimal"
RECON = BIN_DIR / "recon_inventory.py"
VALIDATE = BIN_DIR / "validate_context.py"


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def write_context(review_root: Path, frontmatter: str, body: str) -> Path:
    review_root.mkdir(parents=True, exist_ok=True)
    p = review_root / "CONTEXT.md"
    p.write_text(f"---\n{frontmatter.strip()}\n---\n{body}", encoding="utf-8")
    return p


VALID_FRONTMATTER_V2 = """
schema_version: 2
generated_at: "2026-05-05T12:00:00Z"
git_rev: "abc123"
project_fingerprint: "p1"
code_fingerprint: "c1"
scope: "project"
stack:
  language: php
  framework: symfony
  framework_version: "7.0"
  detected_via: composer.json
recipe_used: symfony
tool_versions:
  symfony: "7.0"
  doctrine: "3.0"
  mcp_phpstorm: unavailable
sources_used:
  - "extract_php_metadata.php"
missing_sections: []
recon_confidence:
  level: medium
  ceiling: medium
warnings:
  - "console_disabled_by_flag"
errors: []
"""


def all_core_sections_pending() -> str:
    body = ""
    for sid, (shape, _) in vc.CORE_SECTIONS_V2.items():
        body += (
            f"## {sid.replace('_', ' ').title()}\n"
            f"<!-- section_id: {sid} -->\n\n"
            "```yaml\n"
            "status: pending_enrichment\n"
            f"enrichment_hint: \"S1 stub: {sid}\"\n"
            f"{'items: []' if shape == 'list' else 'source_files: []'}\n"
            "```\n\n"
        )
    return body


# ---------------------------------------------------------------------------
# Frontmatter v2.
# ---------------------------------------------------------------------------


class FrontmatterV2(unittest.TestCase):
    def test_minimal_valid_passes(self):
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertTrue(res.ok(), msg=f"errors: {res.errors}")

    def test_v1_schema_rejected_with_clear_message(self):
        fm = "schema_version: 1\n"
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, "")
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("schema_version must be 2" in e for e in res.errors))

    def test_missing_required_key(self):
        fm = VALID_FRONTMATTER_V2.replace("git_rev:", "_skip:")  # remove git_rev
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("git_rev" in e for e in res.errors))

    def test_recon_confidence_string_form_accepted(self):
        fm = VALID_FRONTMATTER_V2.replace(
            "recon_confidence:\n  level: medium\n  ceiling: medium",
            "recon_confidence: medium",
        )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertTrue(res.ok(), msg=f"errors: {res.errors}")

    def test_recon_confidence_invalid_string(self):
        fm = VALID_FRONTMATTER_V2.replace(
            "recon_confidence:\n  level: medium\n  ceiling: medium",
            "recon_confidence: bogus",
        )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())

    def test_ceiling_clamps_level(self):
        fm = VALID_FRONTMATTER_V2.replace(
            "recon_confidence:\n  level: medium\n  ceiling: medium",
            "recon_confidence:\n  level: high\n  ceiling: medium",
        )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("ceiling" in e for e in res.errors))

    def test_stack_block_requires_language_and_framework(self):
        fm = VALID_FRONTMATTER_V2.replace(
            "stack:\n  language: php\n  framework: symfony\n  framework_version: \"7.0\"\n  detected_via: composer.json",
            "stack:\n  framework_version: \"7.0\"",
        )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("language" in e or "framework" in e for e in res.errors))


# ---------------------------------------------------------------------------
# Section shapes.
# ---------------------------------------------------------------------------


class CoreSectionsV2(unittest.TestCase):
    def test_missing_required_section_errors(self):
        # Drop attack_surface from body.
        body = ""
        for sid, (shape, _) in vc.CORE_SECTIONS_V2.items():
            if sid == "attack_surface":
                continue
            body += (
                f"## {sid}\n<!-- section_id: {sid} -->\n\n"
                f"```yaml\nstatus: pending_enrichment\nenrichment_hint: \"x\"\n"
                f"{'items: []' if shape == 'list' else 'source_files: []'}\n```\n\n"
            )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, body)
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("attack_surface" in e for e in res.errors))

    def test_status_ok_list_requires_items(self):
        body = (
            "## Attack Surface\n<!-- section_id: attack_surface -->\n\n"
            "```yaml\nstatus: ok\n```\n\n"
        )
        # ... rest valid
        for sid, (shape, _) in vc.CORE_SECTIONS_V2.items():
            if sid == "attack_surface":
                continue
            body += (
                f"## {sid}\n<!-- section_id: {sid} -->\n\n"
                f"```yaml\nstatus: pending_enrichment\nenrichment_hint: \"x\"\n"
                f"{'items: []' if shape == 'list' else 'source_files: []'}\n```\n\n"
            )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, body)
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("requires 'items'" in e for e in res.errors))

    def test_status_pending_requires_enrichment_hint(self):
        body = (
            "## Attack Surface\n<!-- section_id: attack_surface -->\n\n"
            "```yaml\nstatus: pending_enrichment\nitems: []\n```\n\n"
        )
        for sid, (shape, _) in vc.CORE_SECTIONS_V2.items():
            if sid == "attack_surface":
                continue
            body += (
                f"## {sid}\n<!-- section_id: {sid} -->\n\n"
                f"```yaml\nstatus: pending_enrichment\nenrichment_hint: \"x\"\n"
                f"{'items: []' if shape == 'list' else 'source_files: []'}\n```\n\n"
            )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, body)
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("enrichment_hint" in e for e in res.errors))

    def test_status_unknown_requires_reason(self):
        body = (
            "## Attack Surface\n<!-- section_id: attack_surface -->\n\n"
            "```yaml\nstatus: unknown\n```\n\n"
        )
        for sid, (shape, _) in vc.CORE_SECTIONS_V2.items():
            if sid == "attack_surface":
                continue
            body += (
                f"## {sid}\n<!-- section_id: {sid} -->\n\n"
                f"```yaml\nstatus: pending_enrichment\nenrichment_hint: \"x\"\n"
                f"{'items: []' if shape == 'list' else 'source_files: []'}\n```\n\n"
            )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, body)
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("reason" in e for e in res.errors))


# ---------------------------------------------------------------------------
# framework_specific bag validation.
# ---------------------------------------------------------------------------


class FrameworkSpecificBag(unittest.TestCase):
    def test_unknown_bag_key_errors(self):
        # H5: unknown keys are now errors (closed schema), not warnings.
        # Bag missing all required keys → also errors.
        body = all_core_sections_pending()
        body += (
            "## Framework Specific\n<!-- section_id: framework_specific -->\n\n"
            "```yaml\nsymfony:\n  unknown_bag_key:\n    status: ok\n    items: []\n```\n\n"
        )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, body)
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(
                any("not declared in recipe schema" in e for e in res.errors),
                msg=f"errors: {res.errors}",
            )

    def test_required_bag_key_missing_errors(self):
        body = all_core_sections_pending()
        # symfony FRAMEWORK_SPECIFIC_SCHEMA requires voters, forms, etc.
        # Provide only `voters` → others missing.
        body += (
            "## Framework Specific\n<!-- section_id: framework_specific -->\n\n"
            "```yaml\nsymfony:\n  voters:\n    status: ok\n    items: []\n```\n\n"
        )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, body)
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(
                any("required by recipe schema but missing" in e for e in res.errors),
                msg=f"errors: {res.errors}",
            )

    def test_unknown_item_keys_warn(self):
        # When status=ok with items containing keys outside SectionSpec.item_keys,
        # validator warns (allows recipe evolution without breaking strict mode).
        body = all_core_sections_pending()
        # Build body with all required symfony bag keys present, voters items
        # contain an unknown 'extra_field' key.
        bag = "symfony:\n"
        for k in ("voters", "forms", "serializer_groups", "doctrine_listeners"):
            bag += f"  {k}:\n    status: pending_enrichment\n    enrichment_hint: \"x\"\n    items: []\n"
        for k in ("twig_overrides", "firewalls", "messenger_transports"):
            bag += f"  {k}:\n    status: pending_enrichment\n    enrichment_hint: \"x\"\n    source_files: []\n"
        # Override voters with status=ok + items having unknown key.
        bag = bag.replace(
            "voters:\n    status: pending_enrichment\n    enrichment_hint: \"x\"\n    items: []",
            "voters:\n    status: ok\n    items:\n      - class: X\n        file: src/X.php\n        attributes: []\n        extra_field: nope",
        )
        body += (
            "## Framework Specific\n<!-- section_id: framework_specific -->\n\n"
            f"```yaml\n{bag}```\n\n"
        )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, body)
            res = vc.validate_context_file(p)
            self.assertTrue(
                any("unknown keys" in w for w in res.warnings),
                msg=f"warnings: {res.warnings}",
            )

    def test_missing_recipe_key_in_bag_errors(self):
        body = all_core_sections_pending()
        body += (
            "## Framework Specific\n<!-- section_id: framework_specific -->\n\n"
            "```yaml\nlaravel:\n  policies:\n    status: ok\n    items: []\n```\n\n"
        )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, body)
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("missing key for recipe 'symfony'" in e for e in res.errors))

    def test_known_bag_key_validated_for_shape(self):
        # voters is list-shape; status=ok without items is invalid.
        body = all_core_sections_pending()
        body += (
            "## Framework Specific\n<!-- section_id: framework_specific -->\n\n"
            "```yaml\nsymfony:\n  voters:\n    status: ok\n```\n\n"
        )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, body)
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())


# ---------------------------------------------------------------------------
# Recipe-driven sanity probes — full pipeline integration.
# ---------------------------------------------------------------------------


class SanityProbesIntegration(unittest.TestCase):
    """Drive the full pipe: recon_inventory generates CONTEXT, validator + sanity reads it."""

    def test_recipe_run_produces_clean_inventory(self):
        # Post-S2: recipe collects real items for every probe-targeted section.
        # Sanity must pass without coverage errors on the minimal fixture.
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            subprocess.run(
                [sys.executable, str(RECON), str(FIX_MIN), "--recipe", "symfony",
                 "--review-root", str(review_root), "--no-console"],
                check=True, capture_output=True, timeout=60,
            )
            res = vc.sanity_check(review_root, project_root=FIX_MIN)
            self.assertTrue(res.ok(), msg=f"errors: {res.errors}")

    def test_full_coverage_no_warnings(self):
        # Synthesize a CONTEXT.md with status=ok matching all glob targets:
        # symfony recipe sanity probes look for *Controller.php (http_route),
        # *Handler.php (message_handler), *Repository.php (data_access),
        # *Voter*.php (framework_specific.symfony.voters),
        # *Listener.php / *Subscriber.php (event_listener).
        attack_surface_decls = [
            ("http_route", "src/Controller/PostController.php"),
            ("http_route", "src/Controller/AuthController.php"),
            ("http_route", "src/Controller/UserController.php"),
            ("message_handler", "src/Messenger/SendEmailHandler.php"),
            ("event_listener", "src/EventListener/RequestListener.php"),
            ("cli_command", "src/Command/SyncCommand.php"),
        ]
        attack_surface_items = "\n".join(
            f"  - kind: {k}\n    file: {p}" for k, p in attack_surface_decls
        )
        repos = [
            "src/Repository/PostRepository.php",
            "src/Repository/UserRepository.php",
        ]
        data_access_items = "\n".join(f"  - file: {p}" for p in repos)
        body = (
            "## Attack Surface\n<!-- section_id: attack_surface -->\n\n"
            f"```yaml\nstatus: ok\nitems:\n{attack_surface_items}\n```\n\n"
            "## Data Access\n<!-- section_id: data_access -->\n\n"
            f"```yaml\nstatus: ok\nitems:\n{data_access_items}\n```\n\n"
        )
        for sid, (shape, _) in vc.CORE_SECTIONS_V2.items():
            if sid in ("attack_surface", "data_access"):
                continue
            body += (
                f"## {sid}\n<!-- section_id: {sid} -->\n\n"
                f"```yaml\nstatus: unknown\nreason: \"S1 stub\"\n```\n\n"
            )
        body += (
            "## Framework Specific\n<!-- section_id: framework_specific -->\n\n"
            "```yaml\nsymfony:\n  voters:\n    status: ok\n    items:\n      - file: src/Security/Voter/PostVoter.php\n```\n\n"
        )
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            write_context(review_root, VALID_FRONTMATTER_V2, body)
            res = vc.sanity_check(review_root, project_root=FIX_MIN)
            # All globs covered → no missing-coverage warnings/errors.
            errs = [e for e in res.errors if "missing" in e.lower()]
            self.assertEqual(errs, [])

    def test_low_coverage_above_20pct_errors(self):
        # Declare only 1 of 3 controllers → ~67% diff.
        body = (
            "## Attack Surface\n<!-- section_id: attack_surface -->\n\n"
            "```yaml\nstatus: ok\nitems:\n  - kind: http_route\n    file: src/Controller/PostController.php\n```\n\n"
        )
        for sid, (shape, _) in vc.CORE_SECTIONS_V2.items():
            if sid == "attack_surface":
                continue
            body += (
                f"## {sid}\n<!-- section_id: {sid} -->\n\n"
                f"```yaml\nstatus: unknown\nreason: \"S1 stub\"\n```\n\n"
            )
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            write_context(review_root, VALID_FRONTMATTER_V2, body)
            res = vc.sanity_check(review_root, project_root=FIX_MIN)
            self.assertFalse(res.ok(), msg=f"unexpectedly clean: {res.warnings}")

    def test_hallucination_warns(self):
        body = (
            "## Attack Surface\n<!-- section_id: attack_surface -->\n\n"
            "```yaml\nstatus: ok\nitems:\n"
            "  - kind: http_route\n    file: src/Controller/PostController.php\n"
            "  - kind: http_route\n    file: src/Controller/AuthController.php\n"
            "  - kind: http_route\n    file: src/Controller/UserController.php\n"
            "  - kind: http_route\n    file: src/Controller/HallucinatedController.php\n"
            "```\n\n"
        )
        for sid, (shape, _) in vc.CORE_SECTIONS_V2.items():
            if sid == "attack_surface":
                continue
            body += (
                f"## {sid}\n<!-- section_id: {sid} -->\n\n"
                f"```yaml\nstatus: unknown\nreason: \"S1 stub\"\n```\n\n"
            )
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            write_context(review_root, VALID_FRONTMATTER_V2, body)
            res = vc.sanity_check(review_root, project_root=FIX_MIN)
            self.assertTrue(any("not on disk" in w for w in res.warnings),
                            msg=f"warnings: {res.warnings}")


# ---------------------------------------------------------------------------
# Sanity probe content_filter — narrows globs by file content (regex).
# Used to disambiguate name-based collisions like *Command.php
# (Symfony Console vs DDD/CQRS Command DTOs vs Messenger messages).
# ---------------------------------------------------------------------------


class SanityProbeContentFilter(unittest.TestCase):
    def _write_php(self, root: Path, rel: str, body: str) -> None:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    def test_filter_by_content_keeps_matching_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_php(root, "a.php", "<?php\nuse Symfony\\Component\\Console\\Command\\Command;\n")
            self._write_php(root, "b.php", "<?php\n// no marker\n")
            kept = vc._filter_by_content(
                root, {"a.php", "b.php"},
                r"Symfony\\Component\\Console\\Command\\Command",
            )
            self.assertEqual(kept, {"a.php"})

    def test_filter_by_content_handles_unreadable_files(self):
        # Non-existent files in the input set must be silently skipped, not raise.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_php(root, "real.php", "<?php\nmarker\n")
            kept = vc._filter_by_content(
                root, {"real.php", "ghost.php"}, r"marker",
            )
            self.assertEqual(kept, {"real.php"})

    def test_filter_by_content_invalid_regex_returns_input(self):
        # Defensive: bad regex from a recipe must not crash sanity_check.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_php(root, "x.php", "<?php\n")
            kept = vc._filter_by_content(root, {"x.php"}, r"[unclosed")
            self.assertEqual(kept, {"x.php"})

    def test_probe_with_content_filter_excludes_non_matching_files(self):
        # End-to-end: build a fake project with one real Symfony Console command
        # and one CQRS Command DTO. Declare only the Console one. Probe with
        # content_filter should NOT flag the DTO as "missing".
        with tempfile.TemporaryDirectory() as td:
            project = Path(td) / "project"
            self._write_php(project, "src/Command/SyncCommand.php",
                "<?php\nuse Symfony\\Component\\Console\\Command\\Command;\n"
                "use Symfony\\Component\\Console\\Attribute\\AsCommand;\n"
                "#[AsCommand(name: 'app:sync')] final class SyncCommand extends Command {}\n")
            self._write_php(project, "src/Application/Order/Command/CreateOrderCommand.php",
                "<?php\nnamespace App\\Application\\Order\\Command;\n"
                "final class CreateOrderCommand {}\n")

            from recon.types import SanityProbe

            class FakeRecipe:
                EXCLUDE_PATHS = ()

                @staticmethod
                def sanity_probes():
                    return [SanityProbe(
                        section_path="attack_surface",
                        glob_patterns=["src/**/*Command.php"],
                        label="CLI commands",
                        kind_filter="cli_command",
                        content_filter=r"Symfony\\Component\\Console\\Command\\Command|#\[\s*AsCommand\b",
                    )]

            body = (
                "## Attack Surface\n<!-- section_id: attack_surface -->\n\n"
                "```yaml\nstatus: ok\nitems:\n"
                "  - kind: cli_command\n    file: src/Command/SyncCommand.php\n```\n\n"
            )
            for sid, (shape, _) in vc.CORE_SECTIONS_V2.items():
                if sid == "attack_surface":
                    continue
                body += (
                    f"## {sid}\n<!-- section_id: {sid} -->\n\n"
                    f"```yaml\nstatus: unknown\nreason: \"stub\"\n```\n\n"
                )
            review_root = Path(td) / "review"
            write_context(review_root, VALID_FRONTMATTER_V2, body)

            res = vc.sanity_check(review_root, project_root=project,
                                  recipe_loader=lambda _name: FakeRecipe())
            # CQRS DTO filtered out by content_filter → declared 1 == found 1.
            self.assertTrue(res.ok(), msg=f"errors: {res.errors}; warnings: {res.warnings}")

    def test_probe_without_content_filter_fails_on_same_layout(self):
        # Control: same layout, same probe but content_filter=None → DTO leaks
        # into the "found" set and the probe correctly flags missing coverage.
        # Pinned so we don't silently lose the false-positive signal.
        with tempfile.TemporaryDirectory() as td:
            project = Path(td) / "project"
            self._write_php(project, "src/Command/SyncCommand.php",
                "<?php\nuse Symfony\\Component\\Console\\Command\\Command;\n"
                "#[AsCommand(name: 'app:sync')] final class SyncCommand extends Command {}\n")
            # Names must end in `Command.php` (not `Command0.php`) to match the glob.
            for verb in ("Create", "Update", "Delete", "Archive", "Approve",
                         "Reject", "Submit", "Cancel", "Renew", "Expire"):
                self._write_php(project, f"src/Application/Order/Command/{verb}OrderCommand.php",
                    f"<?php\nfinal class {verb}OrderCommand {{}}\n")

            from recon.types import SanityProbe

            class FakeRecipe:
                EXCLUDE_PATHS = ()

                @staticmethod
                def sanity_probes():
                    return [SanityProbe(
                        section_path="attack_surface",
                        glob_patterns=["src/**/*Command.php"],
                        label="CLI commands",
                        kind_filter="cli_command",
                    )]

            body = (
                "## Attack Surface\n<!-- section_id: attack_surface -->\n\n"
                "```yaml\nstatus: ok\nitems:\n"
                "  - kind: cli_command\n    file: src/Command/SyncCommand.php\n```\n\n"
            )
            for sid, (shape, _) in vc.CORE_SECTIONS_V2.items():
                if sid == "attack_surface":
                    continue
                body += (
                    f"## {sid}\n<!-- section_id: {sid} -->\n\n"
                    f"```yaml\nstatus: unknown\nreason: \"stub\"\n```\n\n"
                )
            review_root = Path(td) / "review"
            write_context(review_root, VALID_FRONTMATTER_V2, body)

            res = vc.sanity_check(review_root, project_root=project,
                                  recipe_loader=lambda _name: FakeRecipe())
            self.assertFalse(res.ok(),
                             msg="without content_filter the noisy probe should error")


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


class CliContract(unittest.TestCase):
    def test_review_root_required(self):
        proc = subprocess.run(
            [sys.executable, str(VALIDATE)], capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 2)

    def test_missing_context_md_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.run(
                [sys.executable, str(VALIDATE), "--review-root", td],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("CONTEXT.md not found", proc.stderr)

    def test_valid_run_exits_0(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            subprocess.run(
                [sys.executable, str(RECON), str(FIX_MIN), "--recipe", "symfony",
                 "--review-root", str(review_root), "--no-console"],
                check=True, capture_output=True, timeout=30,
            )
            proc = subprocess.run(
                [sys.executable, str(VALIDATE), "--review-root", str(review_root)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertIn("OK", proc.stdout)

    def test_sanity_flag_runs_probes(self):
        with tempfile.TemporaryDirectory() as td:
            review_root = Path(td) / "review"
            subprocess.run(
                [sys.executable, str(RECON), str(FIX_MIN), "--recipe", "symfony",
                 "--review-root", str(review_root), "--no-console"],
                check=True, capture_output=True, timeout=60,
            )
            proc = subprocess.run(
                [sys.executable, str(VALIDATE), "--review-root", str(review_root),
                 "--sanity", "--project-root", str(FIX_MIN)],
                capture_output=True, text=True, timeout=15,
            )
            # Recipe-driven sanity probes complete successfully on the
            # minimal fixture (full coverage from static-only inventory).
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)


# ---------------------------------------------------------------------------
# Edit-friendly parsing — extra blank lines tolerated.
# ---------------------------------------------------------------------------


class EditFriendly(unittest.TestCase):
    def test_extra_blank_lines_between_sections(self):
        # Generate normal body and pad blanks between every section.
        body = all_core_sections_pending()
        padded = body.replace("\n\n## ", "\n\n\n\n## ")
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, padded)
            res = vc.validate_context_file(p)
            self.assertTrue(res.ok(), msg=f"errors: {res.errors}")


class SchemaRevisionTests(unittest.TestCase):
    """3.4.0 minor versioning via `schema_revision` (optional, int 1..99)."""

    def test_schema_revision_optional_assumes_1(self):
        """schema_revision absent → frontmatter still valid (3.3.0 contract)."""
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertTrue(res.ok(), msg=f"errors: {res.errors}")

    def test_schema_revision_int_valid(self):
        fm = VALID_FRONTMATTER_V2 + "\nschema_revision: 2"
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertTrue(res.ok(), msg=f"errors: {res.errors}")

    def test_schema_revision_invalid_type(self):
        fm = VALID_FRONTMATTER_V2 + '\nschema_revision: "two"'
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("schema_revision must be int" in e for e in res.errors))

    def test_schema_revision_out_of_range_errors(self):
        fm = VALID_FRONTMATTER_V2 + "\nschema_revision: 0"
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("out of range" in e for e in res.errors))

    def test_schema_revision_bool_rejected(self):
        """bool is a Python int subclass — explicit rejection."""
        fm = VALID_FRONTMATTER_V2 + "\nschema_revision: true"
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())


class CapabilityFlagsTests(unittest.TestCase):
    """Optional `capabilities` dict in frontmatter — keys free, values enum."""

    def test_capabilities_optional_valid_enum(self):
        fm = VALID_FRONTMATTER_V2 + textwrap.dedent("""
            capabilities:
              routes_authz_matrix: emitted
              sensitive_columns: not_supported_by_recipe
              runtime: not_applicable
        """).rstrip()
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertTrue(res.ok(), msg=f"errors: {res.errors}")

    def test_capabilities_invalid_enum(self):
        fm = VALID_FRONTMATTER_V2 + textwrap.dedent("""
            capabilities:
              routes_authz_matrix: yes
        """).rstrip()
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("capabilities.routes_authz_matrix" in e for e in res.errors))

    def test_capabilities_must_be_mapping(self):
        fm = VALID_FRONTMATTER_V2 + '\ncapabilities: "emitted"'
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), fm, all_core_sections_pending())
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(any("capabilities must be a mapping" in e for e in res.errors))


class ClosedSchemaUnknownKeysTests(unittest.TestCase):
    """Closed-schema invariant: unknown framework_specific bag keys → error.

    Wave 2.5 removed the 3.4.0 transitional allowlist (FUTURE_FRAMEWORK_KEYS_3_4)
    after symfony + laravel recipes declared `routes_authz_matrix`,
    `sensitive_columns`, `runtime`. The closed-schema rule is now uniformly
    applied; only outright typos (`voterz`) still hard-error.
    """

    def test_unknown_non_future_key_still_errors(self):
        body = all_core_sections_pending()
        body += (
            "## Framework Specific\n<!-- section_id: framework_specific -->\n\n"
            "```yaml\nsymfony:\n  voterz:\n    status: ok\n    items: []\n```\n\n"
        )
        with tempfile.TemporaryDirectory() as td:
            p = write_context(Path(td), VALID_FRONTMATTER_V2, body)
            res = vc.validate_context_file(p)
            self.assertFalse(res.ok())
            self.assertTrue(
                any("voterz is not declared in recipe schema" in e for e in res.errors),
                msg=f"errors: {res.errors}",
            )


if __name__ == "__main__":
    unittest.main()
