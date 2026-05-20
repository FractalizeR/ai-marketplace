"""Tests for bin/map_consumers_to_waves.py CLI."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

PLUGIN_BIN = Path(__file__).resolve().parent.parent
CLI_SCRIPT = str(PLUGIN_BIN / "map_consumers_to_waves.py")

sys.path.insert(0, str(PLUGIN_BIN))


_FRONTMATTER = """---
schema_version: 2
generated_at: "2026-04-13T12:00:00Z"
git_rev: "abc"
project_fingerprint: "pf"
code_fingerprint: "cf"
scope: project
stack:
  language: php
  framework: symfony
  framework_version: null
  detected_via: test
recipe_used: symfony
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


def _section(sid: str, body: str) -> str:
    return f"## {sid}\n<!-- section_id: {sid} -->\n```yaml\n{body}\n```\n\n"


def _all_sections(attack_surface_body: str) -> str:
    parts = [_section("attack_surface", attack_surface_body)]
    for sid in (
        "data_access", "authz_usage", "output_renderers", "serialization",
        "file_operations", "http_clients", "fintech_markers", "frontend_assets",
    ):
        parts.append(_section(sid, "status: ok\nitems: []"))
    parts.append(_section(
        "auth_layer",
        "status: ok\ndata:\n  kind: session\nsource_files:\n  - config/security.yaml",
    ))
    parts.append(_section(
        "secrets",
        "status: ok\ndata:\n  hardcoded_count: 0\nsource_files:\n  - .env",
    ))
    return "".join(parts)


def _make_review_root(attack_surface_body: str) -> Path:
    review_root = Path(tempfile.mkdtemp())
    (review_root / "CONTEXT.md").write_text(
        _FRONTMATTER + _all_sections(attack_surface_body),
        encoding="utf-8",
    )
    return review_root


class MapConsumersToWavesCliTests(unittest.TestCase):
    def test_known_consumer_maps_to_expected_waves(self):
        review_root = _make_review_root(textwrap.dedent("""
            status: ok
            items:
              - kind: http_route
                file: src/Controller/Foo.php
              - kind: message_handler
                file: src/Messenger/BarHandler.php
        """).strip())
        result = subprocess.run(
            [sys.executable, CLI_SCRIPT,
             "--review-root", str(review_root),
             "--consumer", "src/Controller/Foo.php",
             "--consumer", "src/Messenger/BarHandler.php"],
            capture_output=True, text=True, check=True,
        )
        out = json.loads(result.stdout)
        self.assertEqual(out["src/Controller/Foo.php"]["kind"], "http_route")
        # http_route is covered by W1, W2, W3, W5.
        self.assertIn("W1", out["src/Controller/Foo.php"]["waves"])
        self.assertIn("W2", out["src/Controller/Foo.php"]["waves"])
        self.assertEqual(out["src/Messenger/BarHandler.php"]["kind"], "message_handler")
        self.assertIn("W4", out["src/Messenger/BarHandler.php"]["waves"])

    def test_unknown_consumer_returns_empty_waves(self):
        review_root = _make_review_root(textwrap.dedent("""
            status: ok
            items:
              - kind: http_route
                file: src/Controller/Foo.php
        """).strip())
        result = subprocess.run(
            [sys.executable, CLI_SCRIPT,
             "--review-root", str(review_root),
             "--consumer", "src/Service/UnknownService.php"],
            capture_output=True, text=True, check=True,
        )
        out = json.loads(result.stdout)
        self.assertIsNone(out["src/Service/UnknownService.php"]["kind"])
        self.assertEqual(out["src/Service/UnknownService.php"]["waves"], [])

    def test_consumers_file(self):
        review_root = _make_review_root(textwrap.dedent("""
            status: ok
            items:
              - kind: http_route
                file: src/Controller/A.php
              - kind: cli_command
                file: src/Command/B.php
        """).strip())
        consumers_file = review_root / "consumers.txt"
        consumers_file.write_text("src/Controller/A.php\nsrc/Command/B.php\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, CLI_SCRIPT,
             "--review-root", str(review_root),
             "--consumers-file", str(consumers_file)],
            capture_output=True, text=True, check=True,
        )
        out = json.loads(result.stdout)
        self.assertEqual(out["src/Controller/A.php"]["kind"], "http_route")
        self.assertEqual(out["src/Command/B.php"]["kind"], "cli_command")

    def test_no_consumers_provided(self):
        review_root = _make_review_root("status: ok\nitems: []")
        result = subprocess.run(
            [sys.executable, CLI_SCRIPT, "--review-root", str(review_root)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("no consumers", result.stderr)

    def test_missing_context(self):
        review_root = Path(tempfile.mkdtemp())  # no CONTEXT.md
        result = subprocess.run(
            [sys.executable, CLI_SCRIPT,
             "--review-root", str(review_root),
             "--consumer", "src/X.php"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
