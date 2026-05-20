"""Tests for bin/recon/graphql_detect.py — recipe-agnostic GraphQL detection."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN_BIN = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_BIN))

from recon.graphql_detect import detect_graphql  # noqa: E402


def _make_project(composer_data: dict, *, files: dict[str, str] | None = None) -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "composer.json").write_text(json.dumps(composer_data), encoding="utf-8")
    if files:
        for rel, content in files.items():
            full = root / rel
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(content, encoding="utf-8")
    return root


class GraphQLDetectionTests(unittest.TestCase):
    def test_returns_none_when_no_composer(self):
        empty = Path(tempfile.mkdtemp())
        self.assertIsNone(detect_graphql(empty))

    def test_returns_none_when_no_graphql_lib(self):
        root = _make_project({"require": {"laravel/framework": "^10.0"}})
        self.assertIsNone(detect_graphql(root))

    def test_detects_lighthouse(self):
        root = _make_project(
            {"require": {"nuwave/lighthouse": "^6.0"}},
            files={
                "graphql/schema.graphql": "type Query { ping: String }",
                "app/GraphQL/Queries/Ping.php": "<?php",
            },
        )
        result = detect_graphql(root)
        self.assertIsNotNone(result)
        self.assertEqual(result["library_name"], "lighthouse")
        self.assertIn("graphql/schema.graphql", result["schema_files"])
        self.assertIn("app/GraphQL/Queries", result["resolvers_dir"])

    def test_detects_rebing_laravel(self):
        root = _make_project(
            {"require": {"rebing/graphql-laravel": "^9.0"}},
            files={"app/GraphQL/Type/UserType.php": "<?php"},
        )
        result = detect_graphql(root)
        self.assertEqual(result["library_name"], "rebing-laravel")
        self.assertIn("app/GraphQL/Type", result["resolvers_dir"])
        self.assertEqual(result["schema_files"], [])

    def test_detects_api_platform(self):
        root = _make_project(
            {"require": {"api-platform/core": "^3.0"}},
            files={"src/GraphQl/Resolver/PingResolver.php": "<?php"},
        )
        result = detect_graphql(root)
        self.assertEqual(result["library_name"], "api-platform")
        self.assertIn("src/GraphQl/Resolver", result["resolvers_dir"])

    def test_detects_webonyx_as_fallback(self):
        root = _make_project(
            {"require": {"webonyx/graphql-php": "^15.0"}},
        )
        result = detect_graphql(root)
        self.assertEqual(result["library_name"], "webonyx")
        # webonyx — no conventions; resolvers_dir/schema_files empty by design.
        self.assertEqual(result["schema_files"], [])
        self.assertEqual(result["resolvers_dir"], [])

    def test_lighthouse_wins_over_webonyx(self):
        """Lighthouse depends on webonyx transitively. Detection prefers the
        higher-level signal."""
        root = _make_project({"require": {
            "nuwave/lighthouse": "^6.0",
            "webonyx/graphql-php": "^15.0",
        }})
        result = detect_graphql(root)
        self.assertEqual(result["library_name"], "lighthouse")

    def test_rebing_wins_over_webonyx(self):
        root = _make_project({"require": {
            "rebing/graphql-laravel": "^9.0",
            "webonyx/graphql-php": "^15.0",
        }})
        result = detect_graphql(root)
        self.assertEqual(result["library_name"], "rebing-laravel")

    def test_api_platform_wins_over_webonyx(self):
        root = _make_project({"require": {
            "api-platform/core": "^3.0",
            "webonyx/graphql-php": "^15.0",
        }})
        result = detect_graphql(root)
        self.assertEqual(result["library_name"], "api-platform")

    def test_resolvers_dir_only_lists_existing(self):
        """When a convention dir is absent on disk, it's omitted from output."""
        root = _make_project(
            {"require": {"nuwave/lighthouse": "^6.0"}},
            files={"app/GraphQL/Queries/Ping.php": "<?php"},
            # graphql/schema.graphql absent — must not appear
            # app/GraphQL/Mutations absent — must not appear
        )
        result = detect_graphql(root)
        self.assertEqual(result["schema_files"], [])
        self.assertEqual(result["resolvers_dir"], ["app/GraphQL/Queries"])

    def test_invalid_composer_json_returns_none(self):
        root = Path(tempfile.mkdtemp())
        (root / "composer.json").write_text("{invalid json", encoding="utf-8")
        self.assertIsNone(detect_graphql(root))

    def test_detects_in_require_dev(self):
        """A library in require-dev still counts."""
        root = _make_project(
            {"require-dev": {"webonyx/graphql-php": "^15.0"}},
        )
        result = detect_graphql(root)
        self.assertEqual(result["library_name"], "webonyx")

    def test_oversized_composer_json_returns_none(self):
        """DoS guard: composer.json above 5 MB is skipped without parse."""
        from recon import graphql_detect
        root = Path(tempfile.mkdtemp())
        # Generate a >5MB composer.json with a giant filler key.
        filler = "x" * (graphql_detect._COMPOSER_MAX_BYTES + 1024)
        (root / "composer.json").write_text(
            '{"require":{"webonyx/graphql-php":"^15.0"},"_filler":"' + filler + '"}',
            encoding="utf-8",
        )
        self.assertIsNone(detect_graphql(root))


if __name__ == "__main__":
    unittest.main()
