"""Tests for plan_waves.py (schema v2)."""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import plan_waves as pw  # noqa: E402


PLUGIN_ROOT = Path(pw.__file__).resolve().parent.parent  # vr/code-review/


# ---------------------------------------------------------------------------
# Fixture builders.
# ---------------------------------------------------------------------------


BASE_FRONTMATTER_TEMPLATE = """---
schema_version: 2
generated_at: "2026-04-13T12:00:00Z"
git_rev: "abc"
project_fingerprint: "pf"
code_fingerprint: "cf"
scope: project
stack:
  language: php
  framework: {framework}
  framework_version: null
  detected_via: test
recipe_used: {recipe}
tool_versions:
  mcp_phpstorm: available
sources_used:
  - test
missing_sections: []
recon_confidence:
  level: high
  ceiling: high
---
"""


def _section(sid: str, yaml_body: str) -> str:
    return f"## {sid}\n<!-- section_id: {sid} -->\n```yaml\n{yaml_body}\n```\n\n"


# Default (empty-ok) bodies for every required core section.
_DEFAULT_SECTION_BODIES: dict[str, str] = {
    # list-shape
    "attack_surface":   "status: ok\nitems: []",
    "data_access":      "status: ok\nitems: []",
    "authz_usage":      "status: ok\nitems: []",
    "output_renderers": "status: ok\nitems: []",
    "serialization":    "status: ok\nitems: []",
    "file_operations":  "status: ok\nitems: []",
    "http_clients":     "status: ok\nitems: []",
    "fintech_markers":  "status: ok\nitems: []",
    "frontend_assets":  "status: ok\nitems: []",
    # scalar (need source_files)
    "auth_layer":       "status: ok\ndata:\n  kind: session\nsource_files:\n  - config/security.yaml",
    "secrets":          "status: ok\ndata:\n  hardcoded_count: 0\nsource_files:\n  - .env",
}


def _all_sections(**overrides: str) -> str:
    parts: list[str] = []
    for sid, default in _DEFAULT_SECTION_BODIES.items():
        body = overrides.get(sid, default)
        parts.append(_section(sid, body))
    if "framework_specific" in overrides:
        parts.append(_section("framework_specific", overrides["framework_specific"]))
    return "".join(parts)


def _build_context(
    *,
    framework: str = "symfony",
    recipe: str = "symfony",
    **section_overrides: str,
) -> Path:
    fm = BASE_FRONTMATTER_TEMPLATE.format(framework=framework, recipe=recipe)
    body = _all_sections(**section_overrides)
    f = tempfile.NamedTemporaryFile("w", suffix=".md", delete=False)
    f.write(fm + body)
    f.close()
    return Path(f.name)


def _build_generic_php(**overrides: str) -> Path:
    return _build_context(framework="none", recipe="generic_php", **overrides)


def _ctx(
    stack: str,
    *,
    language: str | None = None,
    addons: tuple[str, ...] = (),
    integrations: tuple[str, ...] = (),
) -> "pw.ResolutionContext":
    """Compact helper for ResolutionContext in resolve_checklists tests."""
    return pw.ResolutionContext(
        language=language,
        stack=stack,
        addons=addons,
        integrations=integrations,
    )


# ---------------------------------------------------------------------------
# Frontmatter / stack tests.
# ---------------------------------------------------------------------------


class StackFromFrontmatterTests(unittest.TestCase):
    def test_symfony_stack(self):
        p = _build_context(framework="symfony")
        try:
            ctx = pw.parse_context(p)
            self.assertEqual(ctx.stack, "symfony")
        finally:
            p.unlink()

    def test_generic_php_stack_none(self):
        p = _build_generic_php()
        try:
            ctx = pw.parse_context(p)
            self.assertEqual(ctx.stack, "none")
        finally:
            p.unlink()

    def test_unknown_when_missing(self):
        # Frontmatter without `stack` block.
        fm = (
            "---\n"
            "schema_version: 2\n"
            'generated_at: "2026-04-13T12:00:00Z"\n'
            'git_rev: "abc"\n'
            'project_fingerprint: "pf"\n'
            'code_fingerprint: "cf"\n'
            "scope: project\n"
            "tool_versions:\n  mcp_phpstorm: available\n"
            "sources_used: [test]\n"
            "missing_sections: []\n"
            'recon_confidence: high\n'
            "---\n"
        )
        body = _all_sections()
        f = tempfile.NamedTemporaryFile("w", suffix=".md", delete=False)
        f.write(fm + body)
        f.close()
        p = Path(f.name)
        try:
            ctx = pw.parse_context(p)
            self.assertEqual(ctx.stack, "unknown")
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# ParsedContext.resolution_context (frontmatter → ResolutionContext).
# ---------------------------------------------------------------------------


def _build_context_with_stack_block(stack_yaml: str) -> Path:
    """Write a temp CONTEXT.md whose frontmatter `stack:` is custom `stack_yaml`.

    `stack_yaml` is the body inside the `stack:` mapping (already indented), or
    the literal `null` to mean "no stack block".
    """
    if stack_yaml == "__NO_STACK__":
        fm = (
            "---\n"
            "schema_version: 2\n"
            'generated_at: "2026-04-13T12:00:00Z"\n'
            'git_rev: "abc"\n'
            'project_fingerprint: "pf"\n'
            'code_fingerprint: "cf"\n'
            "scope: project\n"
            "recipe_used: generic_php\n"
            "tool_versions:\n  mcp_phpstorm: available\n"
            "sources_used:\n  - test\n"
            "missing_sections: []\n"
            "recon_confidence:\n  level: high\n  ceiling: high\n"
            "---\n"
        )
    else:
        fm = (
            "---\n"
            "schema_version: 2\n"
            'generated_at: "2026-04-13T12:00:00Z"\n'
            'git_rev: "abc"\n'
            'project_fingerprint: "pf"\n'
            'code_fingerprint: "cf"\n'
            "scope: project\n"
            "stack:\n"
            f"{stack_yaml}"
            "recipe_used: symfony\n"
            "tool_versions:\n  mcp_phpstorm: available\n"
            "sources_used:\n  - test\n"
            "missing_sections: []\n"
            "recon_confidence:\n  level: high\n  ceiling: high\n"
            "---\n"
        )
    body = _all_sections()
    f = tempfile.NamedTemporaryFile("w", suffix=".md", delete=False)
    f.write(fm + body)
    f.close()
    return Path(f.name)


class ResolutionContextFromParsedTests(unittest.TestCase):
    def test_full_context_extraction(self):
        stack_yaml = (
            "  language: php\n"
            "  framework: symfony\n"
            "  framework_version: null\n"
            "  detected_via: test\n"
            "  addons:\n"
            "    - api-platform\n"
            "    - easyadmin\n"
            "  integrations:\n"
            "    - auth0\n"
            "    - stripe\n"
        )
        p = _build_context_with_stack_block(stack_yaml)
        try:
            ctx = pw.parse_context(p)
            rc = ctx.resolution_context
            self.assertEqual(
                rc,
                pw.ResolutionContext(
                    language="php",
                    stack="symfony",
                    addons=("api-platform", "easyadmin"),
                    integrations=("auth0", "stripe"),
                ),
            )
        finally:
            p.unlink()

    def test_missing_addons_defaults_to_empty(self):
        stack_yaml = (
            "  language: php\n"
            "  framework: symfony\n"
            "  framework_version: null\n"
            "  detected_via: test\n"
        )
        p = _build_context_with_stack_block(stack_yaml)
        try:
            ctx = pw.parse_context(p)
            rc = ctx.resolution_context
            self.assertEqual(rc.addons, ())
            self.assertEqual(rc.integrations, ())
            self.assertEqual(rc.language, "php")
            self.assertEqual(rc.stack, "symfony")
        finally:
            p.unlink()

    def test_addons_sorted_and_deduped(self):
        stack_yaml = (
            "  language: php\n"
            "  framework: symfony\n"
            "  framework_version: null\n"
            "  detected_via: test\n"
            "  addons:\n"
            "    - easyadmin\n"
            "    - api-platform\n"
            "    - easyadmin\n"
        )
        p = _build_context_with_stack_block(stack_yaml)
        try:
            ctx = pw.parse_context(p)
            rc = ctx.resolution_context
            self.assertEqual(rc.addons, ("api-platform", "easyadmin"))
        finally:
            p.unlink()

    def test_non_string_items_dropped(self):
        # YAML allows mixed-type lists. ResolutionContext drops non-strings.
        stack_yaml = (
            "  language: php\n"
            "  framework: symfony\n"
            "  framework_version: null\n"
            "  detected_via: test\n"
            "  addons:\n"
            "    - valid\n"
            "    - 5\n"
            "    - null\n"
        )
        p = _build_context_with_stack_block(stack_yaml)
        try:
            ctx = pw.parse_context(p)
            rc = ctx.resolution_context
            self.assertEqual(rc.addons, ("valid",))
        finally:
            p.unlink()

    def test_empty_language_string_becomes_none(self):
        stack_yaml = (
            '  language: ""\n'
            "  framework: symfony\n"
            "  framework_version: null\n"
            "  detected_via: test\n"
        )
        p = _build_context_with_stack_block(stack_yaml)
        try:
            ctx = pw.parse_context(p)
            rc = ctx.resolution_context
            self.assertIsNone(rc.language)
        finally:
            p.unlink()

    def test_missing_stack_block(self):
        p = _build_context_with_stack_block("__NO_STACK__")
        try:
            ctx = pw.parse_context(p)
            rc = ctx.resolution_context
            self.assertEqual(
                rc,
                pw.ResolutionContext(
                    language=None,
                    stack="unknown",
                    addons=(),
                    integrations=(),
                ),
            )
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# Dot-notation resolution.
# ---------------------------------------------------------------------------


class DotNotationTests(unittest.TestCase):
    def test_top_level_section(self):
        p = _build_context(
            attack_surface=textwrap.dedent("""\
                status: ok
                items:
                  - kind: http_route
                    file: src/Controller/A.php
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            payload = ctx.payload_at("attack_surface")
            self.assertIsNotNone(payload)
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(len(payload["items"]), 1)
        finally:
            p.unlink()

    def test_framework_specific_dot_path(self):
        fs = textwrap.dedent("""\
            symfony:
              voters:
                status: ok
                items:
                  - class: App\\Security\\UserVoter
                    file: src/Security/UserVoter.php
                    line: 12
        """).strip()
        p = _build_context(framework_specific=fs)
        try:
            ctx = pw.parse_context(p)
            payload = ctx.payload_at("framework_specific.symfony.voters")
            self.assertIsNotNone(payload)
            self.assertEqual(payload["status"], "ok")
            items = ctx.section_items("framework_specific.symfony.voters")
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["file"], "src/Security/UserVoter.php")
        finally:
            p.unlink()

    def test_dot_path_missing_returns_none(self):
        p = _build_context()  # no framework_specific
        try:
            ctx = pw.parse_context(p)
            self.assertIsNone(ctx.payload_at("framework_specific.symfony.voters"))
            self.assertEqual(ctx.section_items("framework_specific.symfony.voters"), [])
            self.assertEqual(ctx.section_status("framework_specific.symfony.voters"), "missing")
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# Wave triggers.
# ---------------------------------------------------------------------------


def _attack_surface(*kinds_and_files: tuple[str, str]) -> str:
    items_yaml = "\n".join(
        f"  - kind: {k}\n    file: {f}\n    identifier: {f}"
        for k, f in kinds_and_files
    )
    return f"status: ok\nitems:\n{items_yaml}"


class WaveTriggerTests(unittest.TestCase):
    def test_symfony_full_triggers_all_waves(self):
        p = _build_context(
            framework="symfony",
            attack_surface=_attack_surface(
                ("http_route", "src/Controller/A.php"),
                ("message_handler", "src/Handler/M.php"),
                ("event_listener", "src/Listener/L.php"),
                ("cli_command", "src/Command/C.php"),
            ),
            output_renderers=textwrap.dedent("""\
                status: ok
                items:
                  - kind: template
                    file: templates/home.html.twig
            """).strip(),
            file_operations=textwrap.dedent("""\
                status: ok
                items:
                  - kind: file_op
                    file: src/Controller/UploadController.php
            """).strip(),
            fintech_markers=textwrap.dedent("""\
                status: ok
                items:
                  - kind: fintech
                    file: composer.json
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            self.assertEqual(ctx.stack, "symfony")
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            waves = {s["wave_id"] for s in plan}
            for wid in ("W1", "W2", "W3", "W4", "W5", "W6"):
                self.assertIn(wid, waves, f"{wid} should trigger on full Symfony fixture")
            self.assertNotIn("WINF", waves)
        finally:
            p.unlink()

    def test_w1_triggers_for_generic_php(self):
        """W1 trigger is `always` — symfony_only flag removed."""
        p = _build_generic_php(
            attack_surface=_attack_surface(("http_route", "src/Controller/A.php")),
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            waves = {s["wave_id"] for s in plan}
            self.assertIn("W1", waves)
            self.assertIn("W2", waves)
            self.assertIn("W4", waves)
        finally:
            p.unlink()

    def test_w3_skipped_when_no_output_no_frontend(self):
        p = _build_context(
            framework="symfony",
            attack_surface=_attack_surface(("http_route", "src/Controller/A.php")),
            output_renderers="status: ok\nitems: []",
            frontend_assets="status: ok\nitems: []",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            self.assertNotIn("W3", {s["wave_id"] for s in plan})
        finally:
            p.unlink()

    def test_w3_triggered_by_frontend_only(self):
        p = _build_context(
            framework="symfony",
            attack_surface=_attack_surface(("http_route", "src/Controller/A.php")),
            output_renderers="status: ok\nitems: []",
            frontend_assets=textwrap.dedent("""\
                status: ok
                items:
                  - kind: importmap
                    file: importmap.php
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            self.assertIn("W3", {s["wave_id"] for s in plan})
        finally:
            p.unlink()

    def test_w5_skipped_when_no_fileops_no_httpclient(self):
        p = _build_context(
            framework="symfony",
            attack_surface=_attack_surface(("http_route", "src/Controller/A.php")),
            file_operations="status: ok\nitems: []",
            http_clients="status: ok\nitems: []",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            self.assertNotIn("W5", {s["wave_id"] for s in plan})
        finally:
            p.unlink()

    def test_w6_skipped_when_no_fintech(self):
        p = _build_context(
            framework="symfony",
            attack_surface=_attack_surface(("http_route", "src/Controller/A.php")),
            fintech_markers="status: ok\nitems: []",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            self.assertNotIn("W6", {s["wave_id"] for s in plan})
        finally:
            p.unlink()

    def test_exploratory_added_with_flag(self):
        p = _build_context()
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, exploratory=True)
            self.assertIn("WINF", {s["wave_id"] for s in plan})
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# Kind filter.
# ---------------------------------------------------------------------------


class RelevantKindFilterTests(unittest.TestCase):
    def test_attack_surface_filtered_by_relevant_kinds_for_w3(self):
        """W3 keeps http_route / http_route_admin entries; cli_command is dropped."""
        p = _build_context(
            framework="symfony",
            attack_surface=_attack_surface(
                ("http_route", "src/Controller/Web.php"),
                ("cli_command", "src/Command/Cron.php"),
            ),
            output_renderers=textwrap.dedent("""\
                status: ok
                items:
                  - kind: template
                    file: templates/home.html.twig
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w3 = [s for s in plan if s["wave_id"] == "W3"]
            self.assertTrue(w3)
            target = set()
            for s in w3:
                target |= set(s["target_files"])
            # http_route entry kept, cli_command entry filtered out, template kept (no kind filter on output_renderers).
            self.assertIn("src/Controller/Web.php", target)
            self.assertIn("templates/home.html.twig", target)
            self.assertNotIn("src/Command/Cron.php", target)
        finally:
            p.unlink()

    def test_kind_filter_does_not_affect_data_access_repository(self):
        """W2 relevant_kinds doesn't include 'repository', but data_access items
        should still be loaded — kind filter applies to attack_surface only."""
        p = _build_context(
            framework="symfony",
            attack_surface=_attack_surface(("http_route", "src/Controller/A.php")),
            data_access=textwrap.dedent("""\
                status: ok
                items:
                  - kind: repository
                    class: App\\Repository\\UserRepository
                    file: src/Repository/UserRepository.php
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w2 = [s for s in plan if s["wave_id"] == "W2"]
            self.assertTrue(w2)
            target = set()
            for s in w2:
                target |= set(s["target_files"])
            self.assertIn("src/Repository/UserRepository.php", target)
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# Model selection.
# ---------------------------------------------------------------------------


class ModelSelectionTests(unittest.TestCase):
    def _full_ctx(self) -> Path:
        return _build_context(
            framework="symfony",
            attack_surface=_attack_surface(
                ("http_route", "src/Controller/A.php"),
                ("message_handler", "src/Handler/M.php"),
                ("event_listener", "src/Listener/L.php"),
                ("cli_command", "src/Command/C.php"),
            ),
            output_renderers=textwrap.dedent("""\
                status: ok
                items:
                  - kind: template
                    file: templates/home.html.twig
            """).strip(),
            file_operations=textwrap.dedent("""\
                status: ok
                items:
                  - kind: file_op
                    file: src/Service/Foo.php
            """).strip(),
            fintech_markers=textwrap.dedent("""\
                status: ok
                items:
                  - kind: fintech
                    file: composer.json
            """).strip(),
        )

    def test_default_balanced(self):
        p = self._full_ctx()
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            by_wave = {s["wave_id"]: s["model"] for s in plan}
            self.assertEqual(by_wave.get("W1"), "opus")
            self.assertEqual(by_wave.get("W2"), "opus")
            self.assertEqual(by_wave.get("W3"), "sonnet")
            self.assertEqual(by_wave.get("W4"), "sonnet")
            self.assertEqual(by_wave.get("W5"), "sonnet")
            self.assertEqual(by_wave.get("W6"), "opus")
        finally:
            p.unlink()

    def test_all_opus_legacy(self):
        p = self._full_ctx()
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, all_opus=True, exploratory=True)
            by_wave = {s["wave_id"]: s["model"] for s in plan}
            self.assertEqual(by_wave.get("W1"), "opus")
            self.assertEqual(by_wave.get("W2"), "opus")
            # W3 default_model=sonnet — --all-opus does NOT promote sonnet-only waves.
            self.assertEqual(by_wave.get("W3"), "sonnet")
            self.assertEqual(by_wave.get("W4"), "opus")
            self.assertEqual(by_wave.get("W5"), "opus")
            self.assertEqual(by_wave.get("W6"), "opus")
            self.assertEqual(by_wave.get("WINF"), "opus")
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# Autosplit.
# ---------------------------------------------------------------------------


class AutosplitTests(unittest.TestCase):
    def test_opus_split_at_50(self):
        items = "\n".join(
            f"  - kind: http_route\n    file: src/Controller/C{i}.php\n    identifier: r{i}"
            for i in range(120)
        )
        p = _build_context(
            framework="symfony",
            attack_surface=f"status: ok\nitems:\n{items}",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w2_chunks = [s for s in plan if s["wave_id"] == "W2"]
            self.assertGreater(len(w2_chunks), 1)
            for s in w2_chunks:
                self.assertLessEqual(len(s["target_files"]), 50)
            total = sum(len(s["target_files"]) for s in w2_chunks)
            self.assertEqual(total, 120)
        finally:
            p.unlink()

    def test_sonnet_split_at_30(self):
        items = "\n".join(
            f"  - kind: template\n    file: templates/page{i}.html.twig"
            for i in range(100)
        )
        p = _build_context(
            framework="symfony",
            output_renderers=f"status: ok\nitems:\n{items}",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w3_chunks = [s for s in plan if s["wave_id"] == "W3"]
            self.assertGreater(len(w3_chunks), 1)
            for s in w3_chunks:
                self.assertLessEqual(len(s["target_files"]), 30)
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# Scope glob.
# ---------------------------------------------------------------------------


class ScopeGlobTests(unittest.TestCase):
    def test_scope_glob_filters_files(self):
        items = "\n".join([
            "  - kind: repository\n    file: src/Repository/UserRepo.php",
            "  - kind: repository\n    file: src/Repository/ProductRepo.php",
            "  - kind: repository\n    file: src/Service/Other.php",
        ])
        p = _build_context(
            framework="symfony",
            data_access=f"status: ok\nitems:\n{items}",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, scope_glob="src/Repository/*")
            w2 = [s for s in plan if s["wave_id"] == "W2"]
            self.assertEqual(len(w2), 1)
            for f in w2[0]["target_files"]:
                self.assertTrue(f.startswith("src/Repository/"))
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# mode=changes (channel 1: touched_by_diff in items).
# ---------------------------------------------------------------------------


class ChangesChannel1Tests(unittest.TestCase):
    def test_only_touched_items(self):
        items = (
            "  - kind: repository\n"
            "    file: src/Repository/UserRepo.php\n"
            "    touched_by_diff: true\n"
            "  - kind: repository\n"
            "    file: src/Repository/ProductRepo.php\n"
            "    touched_by_diff: false"
        )
        p = _build_context(
            framework="symfony",
            data_access=f"status: ok\nitems:\n{items}",
        )
        try:
            ctx = pw.parse_context(p)
            diff = {"src/Repository/UserRepo.php"}
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, diff_files=diff)
            for s in plan:
                self.assertEqual(s["mode"], "changes")
                self.assertTrue(s["slice_id"].endswith("_CHANGES"))
            w2 = [s for s in plan if s["wave_id"] == "W2"]
            self.assertTrue(w2, "W2 expected (touched_by_diff=true present)")
            collected = set()
            for s in w2:
                collected |= set(s["target_files"])
            self.assertEqual(collected, {"src/Repository/UserRepo.php"})
        finally:
            p.unlink()

    def test_wave_skipped_when_no_intersection(self):
        # Only data_access items touched. W4 (serialization) has nothing.
        items = (
            "  - kind: repository\n"
            "    file: src/Repository/UserRepo.php\n"
            "    touched_by_diff: true"
        )
        p = _build_context(
            framework="symfony",
            data_access=f"status: ok\nitems:\n{items}",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, diff_files={"src/Repository/UserRepo.php"})
            waves = {s["wave_id"] for s in plan}
            self.assertIn("W2", waves)
            self.assertNotIn("W4", waves)
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# mode=changes (channel 2: scalar source_files intersect diff_files).
# ---------------------------------------------------------------------------


class ChangesChannel2Tests(unittest.TestCase):
    def test_scalar_source_files_intersect_diff_pulls_them_in(self):
        """auth_layer.source_files contains config/security.yaml. If diff
        touches that yaml, W1 should add the source_files to target_files."""
        p = _build_context(
            framework="symfony",
            attack_surface="status: ok\nitems: []",
            data_access="status: ok\nitems: []",
            authz_usage="status: ok\nitems: []",
            auth_layer=textwrap.dedent("""\
                status: ok
                data:
                  kind: session
                source_files:
                  - config/packages/security.yaml
                  - config/packages/framework.yaml
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            diff = {"config/packages/security.yaml"}
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, diff_files=diff)
            w1 = [s for s in plan if s["wave_id"] == "W1"]
            self.assertTrue(w1, "W1 expected (auth_layer source_files intersect diff)")
            collected = set()
            for s in w1:
                collected |= set(s["target_files"])
            # Whole config block re-read, not just the intersected file.
            self.assertIn("config/packages/security.yaml", collected)
            self.assertIn("config/packages/framework.yaml", collected)
        finally:
            p.unlink()

    def test_scalar_dot_notation_firewalls_channel2(self):
        """framework_specific.symfony.firewalls (scalar, dot-notation) —
        source_files intersection pulls files for W1."""
        fs = textwrap.dedent("""\
            symfony:
              firewalls:
                status: ok
                data:
                  firewalls:
                    main: lazy
                source_files:
                  - config/packages/security.yaml
                  - config/packages/dev/security.yaml
        """).strip()
        p = _build_context(
            framework="symfony",
            attack_surface="status: ok\nitems: []",
            data_access="status: ok\nitems: []",
            authz_usage="status: ok\nitems: []",
            framework_specific=fs,
        )
        try:
            ctx = pw.parse_context(p)
            diff = {"config/packages/security.yaml"}
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, diff_files=diff)
            w1 = [s for s in plan if s["wave_id"] == "W1"]
            self.assertTrue(w1, "W1 expected (firewalls source_files intersect diff)")
            collected = set()
            for s in w1:
                collected |= set(s["target_files"])
            self.assertIn("config/packages/security.yaml", collected)
            self.assertIn("config/packages/dev/security.yaml", collected)
        finally:
            p.unlink()

    def test_scalar_secrets_channel2_w4(self):
        p = _build_context(
            framework="symfony",
            attack_surface="status: ok\nitems: []",
            serialization="status: ok\nitems: []",
            secrets=textwrap.dedent("""\
                status: ok
                data:
                  hardcoded_count: 0
                source_files:
                  - .env
                  - .env.local
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, diff_files={".env"})
            w4 = [s for s in plan if s["wave_id"] == "W4"]
            self.assertTrue(w4, "W4 expected (secrets source_files intersect diff)")
            collected = set()
            for s in w4:
                collected |= set(s["target_files"])
            self.assertIn(".env", collected)
            self.assertIn(".env.local", collected)
        finally:
            p.unlink()

    def test_scalar_status_unknown_does_not_trigger_channel2(self):
        """Scalar with status=unknown has no source_files in payload — must
        not contribute to target_files even if recipe accidentally writes one."""
        p = _build_context(
            framework="symfony",
            attack_surface="status: ok\nitems: []",
            auth_layer=textwrap.dedent("""\
                status: unknown
                reason: detector failed
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            self.assertEqual(ctx.scalar_source_files("auth_layer"), [])
        finally:
            p.unlink()

    def test_diff_path_normalized(self):
        """`./prefix` in diff_files normalizes to recipe POSIX form."""
        p = _build_context(
            framework="symfony",
            data_access=textwrap.dedent("""\
                status: ok
                items:
                  - kind: repository
                    file: src/Repo/A.php
                    touched_by_diff: true
            """).strip(),
            attack_surface="status: ok\nitems: []",
            authz_usage="status: ok\nitems: []",
        )
        try:
            ctx = pw.parse_context(p)
            # Caller passes diff with leading ./ — must still match recipe paths.
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, diff_files={"./src/Repo/A.php"})
            w2 = [s for s in plan if s["wave_id"] == "W2"]
            self.assertTrue(w2)
            collected = set()
            for s in w2:
                collected |= set(s["target_files"])
            self.assertIn("src/Repo/A.php", collected)
        finally:
            p.unlink()

    def test_scalar_no_intersection_skips_wave(self):
        p = _build_context(
            framework="symfony",
            attack_surface="status: ok\nitems: []",
            data_access="status: ok\nitems: []",
            authz_usage="status: ok\nitems: []",
            auth_layer=textwrap.dedent("""\
                status: ok
                data:
                  kind: session
                source_files:
                  - config/packages/security.yaml
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            diff = {"src/Other.php"}  # not intersecting any scalar / list source
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, diff_files=diff)
            self.assertNotIn("W1", {s["wave_id"] for s in plan})
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# Vendor / tests filters.
# ---------------------------------------------------------------------------


class VendorTestsFilterTests(unittest.TestCase):
    def test_vendor_excluded_by_default(self):
        items = (
            "  - kind: repository\n    file: src/Repository/UserRepo.php\n"
            "  - kind: repository\n    file: vendor/foo/bar/src/Bar.php\n"
            "  - kind: repository\n    file: node_modules/some/lib.php"
        )
        p = _build_context(
            framework="symfony",
            data_access=f"status: ok\nitems:\n{items}",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            collected = set()
            for s in plan:
                collected |= set(s["target_files"])
            self.assertIn("src/Repository/UserRepo.php", collected)
            self.assertNotIn("vendor/foo/bar/src/Bar.php", collected)
            self.assertNotIn("node_modules/some/lib.php", collected)
        finally:
            p.unlink()

    def test_tests_excluded_by_default(self):
        items = (
            "  - kind: repository\n    file: src/Repository/UserRepo.php\n"
            "  - kind: repository\n    file: tests/Repository/FakeRepo.php"
        )
        p = _build_context(
            framework="symfony",
            data_access=f"status: ok\nitems:\n{items}",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            collected = set()
            for s in plan:
                collected |= set(s["target_files"])
            self.assertIn("src/Repository/UserRepo.php", collected)
            self.assertNotIn("tests/Repository/FakeRepo.php", collected)
        finally:
            p.unlink()

    def test_include_vendor_opt_in(self):
        items = (
            "  - kind: repository\n    file: src/Repo/R.php\n"
            "  - kind: repository\n    file: vendor/v/b/B.php"
        )
        p = _build_context(
            framework="symfony",
            data_access=f"status: ok\nitems:\n{items}",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, include_vendor=True)
            collected = set()
            for s in plan:
                collected |= set(s["target_files"])
            self.assertIn("vendor/v/b/B.php", collected)
        finally:
            p.unlink()

    def test_include_tests_opt_in(self):
        items = (
            "  - kind: repository\n    file: src/Repo/R.php\n"
            "  - kind: repository\n    file: tests/T.php"
        )
        p = _build_context(
            framework="symfony",
            data_access=f"status: ok\nitems:\n{items}",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, include_tests=True)
            collected = set()
            for s in plan:
                collected |= set(s["target_files"])
            self.assertIn("tests/T.php", collected)
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# resolve_checklists.
# ---------------------------------------------------------------------------


class ResolveChecklistsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = Path(self.tmp)
        # Mock layout.
        (self.root / "checklists" / "core").mkdir(parents=True)
        (self.root / "checklists" / "stacks" / "symfony").mkdir(parents=True)
        (self.root / "checklists" / "core" / "auth.md").write_text("auth core")
        (self.root / "checklists" / "core" / "disclosure.md").write_text("disclosure core")
        (self.root / "checklists" / "stacks" / "symfony" / "auth.md").write_text("auth symfony")
        # Note: NO stacks/symfony/disclosure.md → graceful skip.

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_core_only_when_stack_none(self):
        out = pw.resolve_checklists(("auth", "disclosure"), _ctx("none"), self.root)
        # Only core/* — stacks/none/ is skipped by stack guard.
        self.assertEqual(len(out), 2)
        for s in out:
            self.assertTrue(s.endswith("/core/auth.md") or s.endswith("/core/disclosure.md"))

    def test_core_only_when_stack_unknown(self):
        out = pw.resolve_checklists(("auth",), _ctx("unknown"), self.root)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].endswith("/core/auth.md"))

    def test_core_plus_stack_when_stack_present(self):
        out = pw.resolve_checklists(("auth", "disclosure"), _ctx("symfony"), self.root)
        # Order: per-theme chain (core → stack), themes preserve their order.
        # auth: core/auth, stacks/symfony/auth.
        # disclosure: core/disclosure (no stacks/symfony/disclosure → skip).
        self.assertEqual(len(out), 3)
        self.assertTrue(out[0].endswith("/core/auth.md"))
        self.assertTrue(out[1].endswith("/stacks/symfony/auth.md"))
        self.assertTrue(out[2].endswith("/core/disclosure.md"))

    def test_graceful_skip_missing_files(self):
        out = pw.resolve_checklists(("nonexistent",), _ctx("symfony"), self.root)
        self.assertEqual(out, [])

    def test_plugin_root_none_returns_empty(self):
        self.assertEqual(pw.resolve_checklists(("auth",), _ctx("symfony"), None), [])

    def test_returns_absolute_paths(self):
        out = pw.resolve_checklists(("auth",), _ctx("symfony"), self.root)
        for p in out:
            self.assertTrue(Path(p).is_absolute())

    # --- 5-layer chain coverage (languages / addons / integrations) ---

    def test_languages_layer_resolves(self):
        # Add languages/php/auth.md to the mock layout.
        lang_dir = self.root / "checklists" / "languages" / "php"
        lang_dir.mkdir(parents=True)
        (lang_dir / "auth.md").write_text("auth php")
        out = pw.resolve_checklists(("auth",), _ctx("symfony", language="php"), self.root)
        # Expected order: core → languages → stacks.
        self.assertEqual(len(out), 3)
        self.assertTrue(out[0].endswith("/core/auth.md"))
        self.assertTrue(out[1].endswith("/languages/php/auth.md"))
        self.assertTrue(out[2].endswith("/stacks/symfony/auth.md"))

    def test_languages_layer_skipped_when_language_none(self):
        # File exists but language=None should suppress the entire languages layer.
        lang_dir = self.root / "checklists" / "languages" / "php"
        lang_dir.mkdir(parents=True)
        (lang_dir / "auth.md").write_text("auth php")
        out = pw.resolve_checklists(("auth",), _ctx("symfony", language=None), self.root)
        for s in out:
            self.assertNotIn("/languages/php/auth.md", s)

    def test_addons_in_caller_order_per_theme(self):
        # Two addon checklists for `auth`. Pass them deliberately unsorted to
        # prove ResolutionContext.__post_init__ normalization (alphabetical).
        ad_root = self.root / "checklists" / "stacks" / "symfony" / "addons"
        (ad_root / "api-platform").mkdir(parents=True)
        (ad_root / "easyadmin").mkdir(parents=True)
        (ad_root / "api-platform" / "auth.md").write_text("auth api-platform")
        (ad_root / "easyadmin" / "auth.md").write_text("auth easyadmin")
        # Pass in reverse order; resolver should still emit alphabetical.
        out = pw.resolve_checklists(
            ("auth",),
            _ctx("symfony", addons=("easyadmin", "api-platform")),
            self.root,
        )
        # Expected: core, stack, addons/api-platform, addons/easyadmin (alpha).
        self.assertEqual(len(out), 4)
        self.assertTrue(out[0].endswith("/core/auth.md"))
        self.assertTrue(out[1].endswith("/stacks/symfony/auth.md"))
        self.assertTrue(out[2].endswith("/stacks/symfony/addons/api-platform/auth.md"))
        self.assertTrue(out[3].endswith("/stacks/symfony/addons/easyadmin/auth.md"))

    def test_integrations_apply_when_stack_none(self):
        # Integrations are independent of the stack layer.
        ig_dir = self.root / "checklists" / "integrations" / "stripe"
        ig_dir.mkdir(parents=True)
        (ig_dir / "auth.md").write_text("auth stripe")
        out = pw.resolve_checklists(
            ("auth",),
            _ctx("none", integrations=("stripe",)),
            self.root,
        )
        # No stack layer (none/unknown disables it), but integrations apply.
        self.assertEqual(len(out), 2)
        self.assertTrue(out[0].endswith("/core/auth.md"))
        self.assertTrue(out[1].endswith("/integrations/stripe/auth.md"))

    def test_addons_skipped_when_stack_unknown(self):
        # Addons live under stacks/{stack}/addons — without an active stack they
        # cannot resolve.
        ad_dir = self.root / "checklists" / "stacks" / "symfony" / "addons" / "easyadmin"
        ad_dir.mkdir(parents=True)
        (ad_dir / "auth.md").write_text("auth easyadmin")
        out = pw.resolve_checklists(
            ("auth",),
            _ctx("unknown", addons=("easyadmin",)),
            self.root,
        )
        for s in out:
            self.assertNotIn("/addons/easyadmin/", s)

    def test_per_theme_interleaving(self):
        # Add a stack-level disclosure file so we have core + stack at two themes.
        (self.root / "checklists" / "stacks" / "symfony" / "disclosure.md").write_text(
            "disclosure symfony"
        )
        out = pw.resolve_checklists(
            ("auth", "disclosure"),
            _ctx("symfony"),
            self.root,
        )
        # Expected interleave: core/auth, stacks/symfony/auth,
        # core/disclosure, stacks/symfony/disclosure.
        self.assertEqual(len(out), 4)
        self.assertTrue(out[0].endswith("/core/auth.md"))
        self.assertTrue(out[1].endswith("/stacks/symfony/auth.md"))
        self.assertTrue(out[2].endswith("/core/disclosure.md"))
        self.assertTrue(out[3].endswith("/stacks/symfony/disclosure.md"))

    def test_full_5_layer_chain_for_single_theme(self):
        # Populate all 5 layers for theme "auth".
        cl = self.root / "checklists"
        lang_dir = cl / "languages" / "php"
        lang_dir.mkdir(parents=True)
        (lang_dir / "auth.md").write_text("auth php")
        addon_dir = cl / "stacks" / "symfony" / "addons" / "easyadmin"
        addon_dir.mkdir(parents=True)
        (addon_dir / "auth.md").write_text("auth easyadmin")
        ig_dir = cl / "integrations" / "auth0"
        ig_dir.mkdir(parents=True)
        (ig_dir / "auth.md").write_text("auth auth0")
        # core/auth.md and stacks/symfony/auth.md already created in setUp.
        out = pw.resolve_checklists(
            ("auth",),
            _ctx(
                "symfony",
                language="php",
                addons=("easyadmin",),
                integrations=("auth0",),
            ),
            self.root,
        )
        # Expected order: core → languages → stacks → addons → integrations.
        self.assertEqual(len(out), 5)
        self.assertTrue(out[0].endswith("/core/auth.md"))
        self.assertTrue(out[1].endswith("/languages/php/auth.md"))
        self.assertTrue(out[2].endswith("/stacks/symfony/auth.md"))
        self.assertTrue(out[3].endswith("/stacks/symfony/addons/easyadmin/auth.md"))
        self.assertTrue(out[4].endswith("/integrations/auth0/auth.md"))


class ResolveChecklistsRealLayoutTests(unittest.TestCase):
    """Sanity check against the real plugin layout shipped with this code."""

    def test_w1_checklists_resolve_for_symfony(self):
        out = pw.resolve_checklists(("auth", "disclosure"), _ctx("symfony"), PLUGIN_ROOT)
        # We expect at least core/auth, core/disclosure, stacks/symfony/auth, stacks/symfony/disclosure.
        suffixes = sorted(p.split("checklists/", 1)[-1] for p in out)
        self.assertIn("core/auth.md", suffixes)
        self.assertIn("core/disclosure.md", suffixes)
        self.assertIn("stacks/symfony/auth.md", suffixes)
        self.assertIn("stacks/symfony/disclosure.md", suffixes)

    def test_generic_php_loads_only_core(self):
        out = pw.resolve_checklists(("auth", "disclosure"), _ctx("none"), PLUGIN_ROOT)
        suffixes = [p.split("checklists/", 1)[-1] for p in out]
        # Should be only core/* — no stacks/none/ subtree exists.
        for s in suffixes:
            self.assertTrue(s.startswith("core/"), f"unexpected non-core path: {s}")

    def test_w1_checklists_resolve_for_laravel(self):
        out = pw.resolve_checklists(("auth", "disclosure"), _ctx("laravel"), PLUGIN_ROOT)
        suffixes = sorted(p.split("checklists/", 1)[-1] for p in out)
        self.assertIn("core/auth.md", suffixes)
        self.assertIn("core/disclosure.md", suffixes)
        self.assertIn("stacks/laravel/auth.md", suffixes)
        self.assertIn("stacks/laravel/disclosure.md", suffixes)

    def test_laravel_full_theme_set_resolves(self):
        """All themes used by WAVES should have laravel-specific checklists where Symfony does."""
        themes = ("auth", "disclosure", "injection", "data-access",
                  "output-render", "serialization", "crypto")
        out = pw.resolve_checklists(themes, _ctx("laravel"), PLUGIN_ROOT)
        suffixes = {p.split("checklists/", 1)[-1] for p in out}
        for t in themes:
            self.assertIn(f"stacks/laravel/{t}.md", suffixes, f"missing {t} laravel checklist")


# ---------------------------------------------------------------------------
# build_plan integration on real plugin layout.
# ---------------------------------------------------------------------------


class BuildPlanChecklistsTests(unittest.TestCase):
    def test_w1_checklists_included_for_symfony(self):
        p = _build_context(
            framework="symfony",
            attack_surface=_attack_surface(("http_route", "src/Controller/A.php")),
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w1 = next(s for s in plan if s["wave_id"] == "W1")
            cls = w1["checklists"]
            for c in cls:
                self.assertTrue(Path(c).is_absolute())
            suffixes = [c.split("checklists/", 1)[-1] for c in cls]
            self.assertIn("core/auth.md", suffixes)
            self.assertIn("stacks/symfony/auth.md", suffixes)
        finally:
            p.unlink()

    def test_generic_php_w1_only_core_checklists(self):
        p = _build_generic_php(
            attack_surface=_attack_surface(("http_route", "src/Controller/A.php")),
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w1 = next(s for s in plan if s["wave_id"] == "W1")
            cls = w1["checklists"]
            suffixes = [c.split("checklists/", 1)[-1] for c in cls]
            for s in suffixes:
                self.assertTrue(s.startswith("core/"),
                                f"generic_php W1 picked up non-core checklist: {s}")
            self.assertIn("core/auth.md", suffixes)
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# WINF (exploratory).
# ---------------------------------------------------------------------------


class WinfChunkSizeTests(unittest.TestCase):
    def test_winf_uses_winf_split(self):
        items = "\n".join(
            f"  - kind: http_route\n    file: src/Controller/C{i}.php\n    identifier: r{i}"
            for i in range(197)
        )
        p = _build_context(
            framework="symfony",
            attack_surface=f"status: ok\nitems:\n{items}",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, exploratory=True)
            winf = [s for s in plan if s["wave_id"] == "WINF"]
            self.assertGreater(len(winf), 0)
            # ceil(197 / 65) = 4 parts max.
            self.assertLessEqual(len(winf), 4,
                                 f"WINF should have ≤4 parts for 197 files, got {len(winf)}")
            total = sum(len(s["target_files"]) for s in winf)
            self.assertEqual(total, 197)
        finally:
            p.unlink()

    def test_split_files_respects_override(self):
        files = [f"f{i}.php" for i in range(100)]
        chunks = pw.split_files(files, "sonnet", limit_override=65)
        self.assertEqual(len(chunks), 2)
        for c in chunks:
            self.assertLessEqual(len(c), 65)


class WinfAnchorPointsTests(unittest.TestCase):
    def test_winf_includes_focused_entry_points(self):
        ep = "\n".join(
            f"  - kind: http_route\n    file: src/Controller/C{i}.php\n    identifier: route_{i}"
            for i in range(5)
        )
        p = _build_context(
            framework="symfony",
            attack_surface=f"status: ok\nitems:\n{ep}",
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, exploratory=True)
            focused = set()
            for s in plan:
                if s["wave_id"] != "WINF":
                    focused.update(s["entry_points_in_scope"])
            winf_slices = [s for s in plan if s["wave_id"] == "WINF"]
            self.assertGreater(len(winf_slices), 0)
            winf_eps = set(winf_slices[0]["entry_points_in_scope"])
            self.assertTrue(focused.issubset(winf_eps),
                            f"WINF missing focused entry points: {focused - winf_eps}")
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# Edge cases for collect_files require_touched semantics.
# ---------------------------------------------------------------------------


class CollectFilesEdgeCases(unittest.TestCase):
    """Channel 1 contract: `touched_by_diff is True` is the SOLE signal in
    plan_waves. Recipe owns this flag. plan_waves never falls back to
    re-checking `diff_files` against item.file — that would split source-of-
    truth and mask recipe bugs (DoD #5)."""

    def _ctx_with_data_access(self, items_yaml: str) -> pw.ParsedContext:
        p = _build_context(
            framework="symfony",
            data_access=f"status: ok\nitems:\n{items_yaml}",
        )
        try:
            return pw.parse_context(p)
        finally:
            p.unlink()

    def test_touched_true_included(self):
        items = (
            "  - kind: repository\n    file: src/Repo/A.php\n    touched_by_diff: true"
        )
        ctx = self._ctx_with_data_access(items)
        files = pw.collect_files(("data_access",), None, ctx, require_touched=True)
        self.assertIn("src/Repo/A.php", files)

    def test_touched_false_excluded(self):
        items = (
            "  - kind: repository\n    file: src/Repo/A.php\n    touched_by_diff: false"
        )
        ctx = self._ctx_with_data_access(items)
        files = pw.collect_files(("data_access",), None, ctx, require_touched=True)
        self.assertNotIn("src/Repo/A.php", files)

    def test_touched_missing_excluded(self):
        # Missing key → not flagged by recipe → not included. Strict.
        items = "  - kind: repository\n    file: src/Repo/A.php"
        ctx = self._ctx_with_data_access(items)
        files = pw.collect_files(("data_access",), None, ctx, require_touched=True)
        self.assertNotIn("src/Repo/A.php", files)

    def test_touched_string_false_excluded(self):
        # `is True` (not bool()) — guards against a hand-edited yaml leaking
        # the string `"false"` (truthy under bool()).
        items = (
            "  - kind: repository\n    file: src/Repo/A.php\n"
            "    touched_by_diff: \"false\""
        )
        ctx = self._ctx_with_data_access(items)
        files = pw.collect_files(("data_access",), None, ctx, require_touched=True)
        self.assertNotIn("src/Repo/A.php", files)

    def test_no_require_touched_includes_all(self):
        items = (
            "  - kind: repository\n    file: src/Repo/A.php\n"
            "  - kind: repository\n    file: src/Repo/B.php\n    touched_by_diff: false"
        )
        ctx = self._ctx_with_data_access(items)
        files = pw.collect_files(("data_access",), None, ctx, require_touched=False)
        self.assertIn("src/Repo/A.php", files)
        self.assertIn("src/Repo/B.php", files)


class SchemaVersionGuardTests(unittest.TestCase):
    def test_v1_context_rejected(self):
        fm = (
            "---\n"
            "schema_version: 1\n"
            'generated_at: "2026-04-13T12:00:00Z"\n'
            'git_rev: "abc"\n'
            "---\n"
        )
        f = tempfile.NamedTemporaryFile("w", suffix=".md", delete=False)
        f.write(fm + "\n")
        f.close()
        p = Path(f.name)
        try:
            with self.assertRaisesRegex(ValueError, "schema_version"):
                pw.parse_context(p)
        finally:
            p.unlink()


class ItemFileFqnTests(unittest.TestCase):
    def test_leading_backslash_fqn_handled_symfony(self):
        """`\\App\\Controller\\X` → `src/Controller/X.php` (leading slash stripped) under Symfony."""
        item = {"controller": "\\App\\Controller\\Foo"}
        self.assertEqual(pw._item_file(item, stack="symfony"), "src/Controller/Foo.php")

    def test_method_suffix_stripped_symfony(self):
        item = {"controller": "App\\Controller\\Foo::index"}
        self.assertEqual(pw._item_file(item, stack="symfony"), "src/Controller/Foo.php")

    def test_file_field_wins_over_fqn(self):
        item = {"controller": "App\\X", "file": "explicit/path.php"}
        # Stack-independent — `file` takes precedence regardless of stack.
        self.assertEqual(pw._item_file(item, stack="symfony"), "explicit/path.php")
        self.assertEqual(pw._item_file(item, stack="laravel"), "explicit/path.php")

    def test_app_namespace_resolves_to_app_for_laravel(self):
        """`App\\Http\\Controllers\\X` → `app/Http/Controllers/X.php` under Laravel."""
        item = {"controller": "App\\Http\\Controllers\\Foo"}
        self.assertEqual(pw._item_file(item, stack="laravel"), "app/Http/Controllers/Foo.php")

    def test_app_namespace_resolves_to_src_for_symfony(self):
        item = {"controller": "App\\Controller\\Foo"}
        self.assertEqual(pw._item_file(item, stack="symfony"), "src/Controller/Foo.php")

    def test_unknown_stack_returns_none_for_app_fqn(self):
        """Unknown stack has no canonical App\\ root; fallback bails."""
        item = {"class": "App\\Foo"}
        self.assertIsNone(pw._item_file(item, stack="unknown"))

    def test_default_stack_argument_is_unknown(self):
        """Calling without stack defaults to 'unknown' → conservative None for App\\."""
        item = {"class": "App\\Foo"}
        self.assertIsNone(pw._item_file(item))

    def test_non_app_namespace_passes_through(self):
        """Non-App\\ FQNs return slash-converted form regardless of stack."""
        item = {"class": "Acme\\Domain\\Order"}
        self.assertEqual(pw._item_file(item, stack="symfony"), "Acme/Domain/Order.php")
        self.assertEqual(pw._item_file(item, stack="laravel"), "Acme/Domain/Order.php")


class VendorPathRemoveprefixTests(unittest.TestCase):
    def test_dotdot_not_treated_as_vendor(self):
        # `lstrip("./")` would yield `vendor/foo` (false positive).
        # `removeprefix("./")` leaves `../vendor/foo` intact, so the prefix
        # check naturally fails → not vendor.
        self.assertFalse(pw._is_vendor_path("../vendor/foo.php"))

    def test_dot_slash_vendor_is_vendor(self):
        self.assertTrue(pw._is_vendor_path("./vendor/foo.php"))

    def test_plain_vendor_is_vendor(self):
        self.assertTrue(pw._is_vendor_path("vendor/foo.php"))


class WinfBehaviourTests(unittest.TestCase):
    def test_winf_relevant_kinds_is_none(self):
        """Exploratory wave must NOT filter by kind — forward-compat with
        future recipes that emit new entry kinds."""
        self.assertIsNone(pw.EXPLORATORY_WAVE.relevant_kinds)
        self.assertIsNone(pw.EXPLORATORY_WAVE.entry_point_kinds)

    def test_winf_themes_is_union_of_all_waves(self):
        focused_themes: set[str] = set()
        for w in pw.WAVES:
            focused_themes.update(w.themes)
        self.assertEqual(set(pw.EXPLORATORY_WAVE.themes), focused_themes)

    def test_winf_loads_all_themes_checklists(self):
        p = _build_context(
            framework="symfony",
            attack_surface=_attack_surface(("http_route", "src/Controller/A.php")),
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, exploratory=True)
            winf = next(s for s in plan if s["wave_id"] == "WINF")
            cls = winf["checklists"]
            self.assertGreater(len(cls), 0,
                               "WINF must load checklists union of all themes")
            # Should include core/auth.md, core/injection.md (etc).
            suffixes = [c.split("checklists/", 1)[-1] for c in cls]
            self.assertIn("core/auth.md", suffixes)
            self.assertIn("core/injection.md", suffixes)
        finally:
            p.unlink()

    def test_winf_skipped_when_changes_empty(self):
        """mode=changes + nothing intersects diff → WINF must not be emitted."""
        p = _build_context(
            framework="symfony",
            attack_surface=_attack_surface(("http_route", "src/Controller/A.php")),
        )
        try:
            ctx = pw.parse_context(p)
            # Diff doesn't touch any item nor any scalar source_file.
            plan = pw.build_plan(
                ctx, plugin_root=PLUGIN_ROOT,
                diff_files={"unrelated/file.php"}, exploratory=True,
            )
            self.assertNotIn("WINF", {s["wave_id"] for s in plan},
                             "WINF must be skipped in mode=changes when no files match")
        finally:
            p.unlink()

    def test_winf_emitted_in_project_mode_even_with_no_files(self):
        """Project mode WINF: target_files may be empty but slice still emits
        (worker uses CONTEXT.md sections as exploratory anchor)."""
        p = _build_context(framework="symfony")
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT, exploratory=True)
            winf = [s for s in plan if s["wave_id"] == "WINF"]
            self.assertEqual(len(winf), 1)
            self.assertEqual(winf[0]["target_files"], [])
        finally:
            p.unlink()


class TargetFilesPreciseCountTests(unittest.TestCase):
    """DoD #7 — Symfony-like fixture: target_files counts per wave are
    deterministic and predictable from item counts."""

    def test_w1_collects_attack_surface_and_data_access(self):
        p = _build_context(
            framework="symfony",
            attack_surface=_attack_surface(
                ("http_route", "src/Controller/Web.php"),
                ("http_route_admin", "src/Controller/Admin/UserCrud.php"),
                ("cli_command", "src/Command/Cron.php"),
                ("event_listener", "src/Listener/L.php"),  # not in W1 kinds
            ),
            data_access=textwrap.dedent("""\
                status: ok
                items:
                  - kind: repository
                    file: src/Repository/UserRepo.php
                  - kind: repository
                    file: src/Repository/PostRepo.php
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w1 = [s for s in plan if s["wave_id"] == "W1"]
            self.assertEqual(len(w1), 1, "single chunk for ≤50 files")
            target = set(w1[0]["target_files"])
            # http_route, http_route_admin, cli_command, message_handler are W1
            # entry kinds; event_listener IS NOT.
            self.assertEqual(
                target,
                {
                    "src/Controller/Web.php",
                    "src/Controller/Admin/UserCrud.php",
                    "src/Command/Cron.php",
                    "src/Repository/UserRepo.php",
                    "src/Repository/PostRepo.php",
                },
            )
        finally:
            p.unlink()


class ConceptResolverTests(unittest.TestCase):
    """Concept enum + CONCEPT_RESOLVERS extension point."""

    def test_concepts_used_by_waves_are_in_enum(self):
        """Every concept declared in WAVES.relevant_concepts must be in ALL_CONCEPTS.
        Catches typos like `relevant_concepts=("auth_guarda",)` that would silently
        resolve to []."""
        for wave in pw.WAVES:
            for concept in wave.relevant_concepts:
                with self.subTest(wave=wave.wave_id, concept=concept):
                    self.assertIn(
                        concept, pw.ALL_CONCEPTS,
                        f"{wave.wave_id} declares unknown concept {concept!r}",
                    )

    def test_concepts_in_resolvers_are_in_enum(self):
        """Catches typos in CONCEPT_RESOLVERS keys."""
        for (_stack, concept) in pw.CONCEPT_RESOLVERS:
            with self.subTest(concept=concept):
                self.assertIn(concept, pw.ALL_CONCEPTS)

    def test_symfony_auth_guards_resolves_to_voters_and_firewalls(self):
        paths = pw.resolve_concept_paths("symfony", "auth_guards")
        self.assertIn("framework_specific.symfony.voters", paths)
        self.assertIn("framework_specific.symfony.firewalls", paths)

    def test_unknown_stack_returns_empty(self):
        self.assertEqual(pw.resolve_concept_paths("django", "auth_guards"), [])

    def test_unknown_concept_returns_empty(self):
        self.assertEqual(pw.resolve_concept_paths("symfony", "no_such_concept"), [])

    def test_resolved_section_paths_w1_symfony_includes_voters(self):
        w1 = next(w for w in pw.WAVES if w.wave_id == "W1")
        paths = pw.resolved_section_paths(w1, "symfony")
        self.assertIn("authz_usage", paths)
        self.assertIn("framework_specific.symfony.voters", paths)
        self.assertIn("framework_specific.symfony.firewalls", paths)

    def test_resolved_section_paths_drops_duplicates(self):
        """If a path appears in both core and a concept resolver — emitted once."""
        w1 = next(w for w in pw.WAVES if w.wave_id == "W1")
        paths = pw.resolved_section_paths(w1, "symfony")
        self.assertEqual(len(paths), len(set(paths)))

    def test_resolved_section_paths_for_unknown_stack_keeps_core(self):
        """Unknown stack → resolver returns []; core paths still included."""
        w1 = next(w for w in pw.WAVES if w.wave_id == "W1")
        paths = pw.resolved_section_paths(w1, "unknown")
        self.assertIn("authz_usage", paths)
        self.assertNotIn("framework_specific.symfony.voters", paths)

    def test_w1_laravel_includes_middleware_groups(self):
        """Regression: Laravel middleware/auth changes must reach W1 (auth)."""
        w1 = next(w for w in pw.WAVES if w.wave_id == "W1")
        paths = pw.resolved_section_paths(w1, "laravel")
        self.assertIn("framework_specific.laravel.policies", paths)
        self.assertIn("framework_specific.laravel.middleware_groups", paths)

    def test_graphql_layer_concept_present_in_w1_and_w2(self):
        """W1 (auth) and W2 (injection) must consume graphql_layer for Symfony AND Laravel."""
        w1 = next(w for w in pw.WAVES if w.wave_id == "W1")
        w2 = next(w for w in pw.WAVES if w.wave_id == "W2")
        self.assertIn("graphql_layer", w1.relevant_concepts)
        self.assertIn("graphql_layer", w2.relevant_concepts)
        # Resolver must surface the path under each stack.
        for stack in ("symfony", "laravel"):
            for wave in (w1, w2):
                with self.subTest(stack=stack, wave=wave.wave_id):
                    paths = pw.resolved_section_paths(wave, stack)
                    self.assertIn(f"framework_specific.{stack}.graphql_layer", paths)

    def test_admin_surface_concept_resolves_for_symfony(self):
        """v3.2: admin_surface concept maps to easyadmin_crud_controllers + admin_authz_coverage."""
        paths = pw.resolve_concept_paths("symfony", "admin_surface")
        self.assertIn("framework_specific.symfony.easyadmin_crud_controllers", paths)
        self.assertIn("framework_specific.symfony.admin_authz_coverage", paths)

    def test_admin_surface_consumed_by_w1_and_w2(self):
        """admin_surface must reach W1 (auth/disclosure recall on identity / sensitive
        fields) and W2 (data-access mass-assignment recall)."""
        w1 = next(w for w in pw.WAVES if w.wave_id == "W1")
        w2 = next(w for w in pw.WAVES if w.wave_id == "W2")
        self.assertIn("admin_surface", w1.relevant_concepts)
        self.assertIn("admin_surface", w2.relevant_concepts)
        for wave in (w1, w2):
            with self.subTest(wave=wave.wave_id):
                paths = pw.resolved_section_paths(wave, "symfony")
                self.assertIn("framework_specific.symfony.easyadmin_crud_controllers", paths)
                self.assertIn("framework_specific.symfony.admin_authz_coverage", paths)

    def test_admin_surface_unknown_stack_returns_empty(self):
        """Stacks without admin enumeration (laravel/django/generic) get no paths."""
        for stack in ("laravel", "django", "generic_php", "unknown"):
            with self.subTest(stack=stack):
                self.assertEqual(pw.resolve_concept_paths(stack, "admin_surface"), [])

    # --- 3.4.0 additions: route_authz_matrix / sensitive_data_model /
    #     long_running_runtime concepts. ---

    def test_w1_resolves_new_concepts_for_symfony(self):
        """W1 should resolve route_authz_matrix + sensitive_data_model for symfony.
        long_running_runtime is laravel-only — symfony resolver returns []."""
        self.assertEqual(
            pw.resolve_concept_paths("symfony", "route_authz_matrix"),
            ["framework_specific.symfony.routes_authz_matrix"],
        )
        self.assertEqual(
            pw.resolve_concept_paths("symfony", "sensitive_data_model"),
            ["framework_specific.symfony.sensitive_columns"],
        )
        self.assertEqual(
            pw.resolve_concept_paths("symfony", "long_running_runtime"),
            [],
        )

    def test_w1_resolves_new_concepts_for_laravel(self):
        """All three new concepts resolve for laravel (long_running_runtime included)."""
        self.assertEqual(
            pw.resolve_concept_paths("laravel", "route_authz_matrix"),
            ["framework_specific.laravel.routes_authz_matrix"],
        )
        self.assertEqual(
            pw.resolve_concept_paths("laravel", "sensitive_data_model"),
            ["framework_specific.laravel.sensitive_columns"],
        )
        self.assertEqual(
            pw.resolve_concept_paths("laravel", "long_running_runtime"),
            ["framework_specific.laravel.runtime"],
        )

    def test_new_concepts_present_in_w1_w2_w4(self):
        """W1 declares all three; W2 declares route_authz_matrix; W4 declares
        sensitive_data_model."""
        w1 = next(w for w in pw.WAVES if w.wave_id == "W1")
        w2 = next(w for w in pw.WAVES if w.wave_id == "W2")
        w4 = next(w for w in pw.WAVES if w.wave_id == "W4")
        for c in ("route_authz_matrix", "sensitive_data_model", "long_running_runtime"):
            with self.subTest(wave="W1", concept=c):
                self.assertIn(c, w1.relevant_concepts)
        self.assertIn("route_authz_matrix", w2.relevant_concepts)
        self.assertIn("sensitive_data_model", w4.relevant_concepts)

    def test_winf_includes_new_concepts(self):
        """WINF (exploratory) — union of focused waves' concepts → all three."""
        for c in ("route_authz_matrix", "sensitive_data_model", "long_running_runtime"):
            with self.subTest(concept=c):
                self.assertIn(c, pw.EXPLORATORY_WAVE.relevant_concepts)

    def test_3_3_0_context_compat_no_new_sections(self):
        """A 3.3.0-style CONTEXT.md (no routes_authz_matrix / sensitive_columns
        / runtime sections) still parses + plan builds.

        Resolver always emits the per-stack path for new concepts, but the
        worker tolerates `payload_at(...)` returning None — that's the
        backward-compat contract documented in plan §1.7."""
        p = _build_context()
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w1 = next(s for s in plan if s["wave_id"] == "W1")
            # Static resolver still emits the section path even when the
            # CONTEXT.md doesn't carry that section; that's how downstream
            # workers know to look.
            self.assertIn(
                "framework_specific.symfony.routes_authz_matrix",
                w1["relevant_section_paths"],
            )
            self.assertIn(
                "framework_specific.symfony.sensitive_columns",
                w1["relevant_section_paths"],
            )
            # Sanity: `payload_at` returns None for absent sections — proves
            # the back-compat contract.
            self.assertIsNone(
                ctx.payload_at("framework_specific.symfony.routes_authz_matrix")
            )
        finally:
            p.unlink()


class SymfonyRegressionAfterRewireTests(unittest.TestCase):
    """B4.1 regression: Symfony plan output must contain the same
    framework_specific paths the WAVES tuple used to hardcode."""

    def test_w1_symfony_emits_voters_and_firewalls(self):
        p = _build_context()
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w1 = next(s for s in plan if s["wave_id"] == "W1")
            self.assertIn("framework_specific.symfony.voters", w1["relevant_section_paths"])
            self.assertIn("framework_specific.symfony.firewalls", w1["relevant_section_paths"])
        finally:
            p.unlink()

    def test_w2_symfony_emits_forms(self):
        p = _build_context()
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w2 = next(s for s in plan if s["wave_id"] == "W2")
            self.assertIn("framework_specific.symfony.forms", w2["relevant_section_paths"])
        finally:
            p.unlink()

    def test_w3_symfony_emits_twig_overrides(self):
        # W3 only triggers if has_output_or_frontend.
        p = _build_context(
            output_renderers=textwrap.dedent("""
                status: ok
                items:
                  - kind: template_render
                    file: src/Controller/Foo.php
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w3 = next(s for s in plan if s["wave_id"] == "W3")
            self.assertIn("framework_specific.symfony.twig_overrides", w3["relevant_section_paths"])
        finally:
            p.unlink()

    def test_w4_symfony_emits_messenger_transports(self):
        p = _build_context()
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            w4 = next(s for s in plan if s["wave_id"] == "W4")
            self.assertIn(
                "framework_specific.symfony.messenger_transports",
                w4["relevant_section_paths"],
            )
        finally:
            p.unlink()

    def test_generic_php_no_framework_specific_paths(self):
        """Generic PHP — no framework_specific.* paths in any slice."""
        p = _build_generic_php()
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(ctx, plugin_root=PLUGIN_ROOT)
            for slice_ in plan:
                for path in slice_["relevant_section_paths"]:
                    self.assertFalse(
                        path.startswith("framework_specific."),
                        msg=f"unexpected framework path {path!r} in {slice_['slice_id']}",
                    )
        finally:
            p.unlink()


class ConsumerKindsToWavesTests(unittest.TestCase):
    """Inverse index `kind → [wave_ids]` is derived from WAVES.relevant_kinds."""

    def test_index_contains_known_kinds(self):
        idx = pw.consumer_kinds_to_waves()
        # http_route appears in W1, W2, W3, W5 (and W6 if fintech-detected).
        self.assertIn("W1", idx["http_route"])
        self.assertIn("W2", idx["http_route"])
        self.assertIn("W3", idx["http_route"])

    def test_message_handler_in_w4(self):
        idx = pw.consumer_kinds_to_waves()
        self.assertIn("W4", idx["message_handler"])

    def test_template_render_only_in_w3(self):
        idx = pw.consumer_kinds_to_waves()
        self.assertEqual(idx["template_render"], ["W3"])

    def test_winf_excluded_from_index(self):
        """EXPLORATORY_WAVE has relevant_kinds=None — must not appear."""
        idx = pw.consumer_kinds_to_waves()
        for waves in idx.values():
            self.assertNotIn("WINF", waves)

    def test_unknown_kind_absent(self):
        idx = pw.consumer_kinds_to_waves()
        self.assertNotIn("garbage_kind", idx)


class LookupKindForFileTests(unittest.TestCase):
    def test_lookup_in_attack_surface(self):
        p = _build_context(
            attack_surface=textwrap.dedent("""
                status: ok
                items:
                  - kind: http_route
                    file: src/Controller/Foo.php
                  - kind: message_handler
                    file: src/Messenger/BarHandler.php
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            self.assertEqual(pw.lookup_kind_for_file("src/Controller/Foo.php", ctx), "http_route")
            self.assertEqual(pw.lookup_kind_for_file("src/Messenger/BarHandler.php", ctx), "message_handler")
        finally:
            p.unlink()

    def test_lookup_normalizes_leading_dot_slash(self):
        p = _build_context(
            attack_surface=textwrap.dedent("""
                status: ok
                items:
                  - kind: http_route
                    file: src/Controller/Foo.php
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            self.assertEqual(pw.lookup_kind_for_file("./src/Controller/Foo.php", ctx), "http_route")
        finally:
            p.unlink()

    def test_lookup_returns_none_when_absent(self):
        p = _build_context(
            attack_surface=textwrap.dedent("""
                status: ok
                items:
                  - kind: http_route
                    file: src/Controller/Foo.php
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            self.assertIsNone(pw.lookup_kind_for_file("src/Service/Unknown.php", ctx))
        finally:
            p.unlink()

    def test_lookup_in_framework_specific(self):
        p = _build_context(
            framework_specific=textwrap.dedent("""
                status: ok
                symfony:
                  voters:
                    status: ok
                    items:
                      - kind: voter
                        file: src/Security/Voter/PostVoter.php
            """).strip(),
        )
        try:
            ctx = pw.parse_context(p)
            self.assertEqual(
                pw.lookup_kind_for_file("src/Security/Voter/PostVoter.php", ctx),
                "voter",
            )
        finally:
            p.unlink()


class ExtraTargetFilesTests(unittest.TestCase):
    """`extra_target_files` injects files into target_files of every wave + WINF.

    Used by /security-changes orchestrator to flag consumers of removed
    Voter/Policy/Middleware classes (which themselves are not in the diff but
    must be reviewed because the protection they relied on disappeared).
    """

    def _full_symfony_ctx(self) -> Path:
        return _build_context(
            framework="symfony",
            attack_surface=_attack_surface(
                ("http_route", "src/Controller/A.php"),
                ("message_handler", "src/Handler/M.php"),
                ("event_listener", "src/Listener/L.php"),
                ("cli_command", "src/Command/C.php"),
            ),
            output_renderers=textwrap.dedent("""\
                status: ok
                items:
                  - kind: template
                    file: templates/home.html.twig
            """).strip(),
            file_operations=textwrap.dedent("""\
                status: ok
                items:
                  - kind: file_op
                    file: src/Controller/UploadController.php
            """).strip(),
            fintech_markers=textwrap.dedent("""\
                status: ok
                items:
                  - kind: fintech
                    file: composer.json
            """).strip(),
        )

    def test_extra_target_files_added_to_each_wave(self):
        p = self._full_symfony_ctx()
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(
                ctx,
                plugin_root=PLUGIN_ROOT,
                extra_target_files=["extra/Foo.php"],
            )
            self.assertTrue(plan, "plan should not be empty for full Symfony fixture")
            for slice_ in plan:
                self.assertIn(
                    "extra/Foo.php", slice_["target_files"],
                    f"wave {slice_['wave_id']}/{slice_['slice_id']} missing extra file",
                )
        finally:
            p.unlink()

    def test_extra_target_files_normalized(self):
        """Leading `./` is stripped to match recipe's POSIX form."""
        p = self._full_symfony_ctx()
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(
                ctx,
                plugin_root=PLUGIN_ROOT,
                extra_target_files=["./extra/Bar.php", "  ./extra/Baz.php  "],
            )
            for slice_ in plan:
                self.assertIn("extra/Bar.php", slice_["target_files"])
                self.assertIn("extra/Baz.php", slice_["target_files"])
                # Ensure leading `./` form did NOT leak through alongside
                # normalized form.
                self.assertNotIn("./extra/Bar.php", slice_["target_files"])
        finally:
            p.unlink()

    def test_extra_target_files_winf_too(self):
        """Exploratory wave must also receive the extra files."""
        p = self._full_symfony_ctx()
        try:
            ctx = pw.parse_context(p)
            plan = pw.build_plan(
                ctx,
                plugin_root=PLUGIN_ROOT,
                exploratory=True,
                extra_target_files=["extra/Voter.php"],
            )
            winf = [s for s in plan if s["wave_id"] == "WINF"]
            self.assertTrue(winf, "WINF must be in plan when exploratory=True")
            for slice_ in winf:
                self.assertIn("extra/Voter.php", slice_["target_files"])
        finally:
            p.unlink()

    def test_extra_target_files_changes_mode_no_diff_intersection(self):
        """In changes-mode a wave with no diff intersection still surfaces if
        extra_target_files is non-empty (point of the flag)."""
        p = self._full_symfony_ctx()
        try:
            ctx = pw.parse_context(p)
            # diff_files is empty → without extra, all waves drop out in changes mode.
            plan = pw.build_plan(
                ctx,
                plugin_root=PLUGIN_ROOT,
                diff_files=set(),
                extra_target_files=["consumers/of/removed/Voter.php"],
            )
            self.assertTrue(
                plan,
                "expected at least one wave to surface for extra files in changes mode",
            )
            for slice_ in plan:
                self.assertIn("consumers/of/removed/Voter.php", slice_["target_files"])
                self.assertEqual(slice_["mode"], "changes")
        finally:
            p.unlink()

    def test_main_extra_target_files_csv(self):
        """CLI `--extra-target-files=a.php,b.php` parses into both."""
        ctx_path = self._full_symfony_ctx()
        try:
            with tempfile.TemporaryDirectory() as td:
                target = Path(td) / "waves_plan.json"
                rc = pw.main([
                    str(ctx_path),
                    "--plugin-root", str(PLUGIN_ROOT),
                    "--save-plan", str(target),
                    "--extra-target-files=a.php,b.php,./c.php",
                ])
                self.assertEqual(rc, 0)
                import json as _json
                payload = _json.loads(target.read_text(encoding="utf-8"))
                self.assertTrue(payload)
                for slice_ in payload:
                    for f in ("a.php", "b.php", "c.php"):
                        self.assertIn(f, slice_["target_files"])
        finally:
            ctx_path.unlink()

    def test_main_extra_target_files_empty_csv_no_op(self):
        """Empty / whitespace-only CSV must not crash and must not add files."""
        ctx_path = self._full_symfony_ctx()
        try:
            with tempfile.TemporaryDirectory() as td:
                target = Path(td) / "waves_plan.json"
                rc = pw.main([
                    str(ctx_path),
                    "--plugin-root", str(PLUGIN_ROOT),
                    "--save-plan", str(target),
                    "--extra-target-files=,, ,",
                ])
                self.assertEqual(rc, 0)
        finally:
            ctx_path.unlink()


class SavePlanCliTests(unittest.TestCase):
    """`--save-plan` writes the generated plan as JSON atomically."""

    def test_main_save_plan_writes_json(self):
        ctx_path = _build_context()
        try:
            with tempfile.TemporaryDirectory() as td:
                target = Path(td) / "waves_plan.json"
                rc = pw.main([
                    str(ctx_path),
                    "--plugin-root", str(PLUGIN_ROOT),
                    "--save-plan", str(target),
                ])
                self.assertEqual(rc, 0)
                self.assertTrue(target.is_file(), f"expected {target} to exist")
                import json as _json
                payload = _json.loads(target.read_text(encoding="utf-8"))
                self.assertIsInstance(payload, list)
                # At least W1 + W2 always trigger.
                wave_ids = {s["wave_id"] for s in payload}
                self.assertIn("W1", wave_ids)
                self.assertIn("W2", wave_ids)
                # Each slice carries `checklists` list of absolute paths.
                w1 = next(s for s in payload if s["wave_id"] == "W1")
                self.assertIn("checklists", w1)
                self.assertIsInstance(w1["checklists"], list)
        finally:
            ctx_path.unlink()

    def test_main_save_plan_no_temp_file_left_behind(self):
        """Atomic rename leaves no `.tmp` artefact."""
        ctx_path = _build_context()
        try:
            with tempfile.TemporaryDirectory() as td:
                target = Path(td) / "waves_plan.json"
                rc = pw.main([
                    str(ctx_path),
                    "--plugin-root", str(PLUGIN_ROOT),
                    "--save-plan", str(target),
                ])
                self.assertEqual(rc, 0)
                tmp = target.with_suffix(target.suffix + ".tmp")
                self.assertFalse(tmp.exists(), f"unexpected leftover {tmp}")
        finally:
            ctx_path.unlink()

    def test_main_without_save_plan_writes_nothing(self):
        ctx_path = _build_context()
        try:
            with tempfile.TemporaryDirectory() as td:
                rc = pw.main([
                    str(ctx_path),
                    "--plugin-root", str(PLUGIN_ROOT),
                ])
                self.assertEqual(rc, 0)
                self.assertEqual(list(Path(td).iterdir()), [])
        finally:
            ctx_path.unlink()


if __name__ == "__main__":
    unittest.main()
