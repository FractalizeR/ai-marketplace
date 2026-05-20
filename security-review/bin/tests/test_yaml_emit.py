"""Round-trip and edge-case tests for recon.yaml_emit."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recon.yaml_emit import dump_yaml_subset, dump_frontmatter  # noqa: E402
from validate_context import parse_yaml_subset, YamlSubsetError  # noqa: E402


def _round_trip(value):
    text = dump_yaml_subset(value)
    return parse_yaml_subset(text), text


class RoundTripScalars(unittest.TestCase):
    def test_string_simple(self):
        out, _ = _round_trip({"k": "value"})
        self.assertEqual(out, {"k": "value"})

    def test_string_with_colon(self):
        out, text = _round_trip({"k": "a: b"})
        self.assertEqual(out, {"k": "a: b"})
        self.assertIn('"a: b"', text)

    def test_string_with_hash(self):
        out, _ = _round_trip({"k": "foo #bar"})
        self.assertEqual(out, {"k": "foo #bar"})

    def test_string_looks_like_number(self):
        out, text = _round_trip({"k": "42"})
        self.assertEqual(out, {"k": "42"})
        self.assertIn('"42"', text)

    def test_string_looks_like_bool(self):
        for s in ("true", "false", "yes", "no", "null", "TRUE"):
            out, text = _round_trip({"k": s})
            self.assertEqual(out, {"k": s}, f"failed on {s!r}")
            self.assertIn(f'"{s}"', text)

    def test_string_empty(self):
        out, _ = _round_trip({"k": ""})
        self.assertEqual(out, {"k": ""})

    def test_string_leading_dash(self):
        out, _ = _round_trip({"k": "-foo"})
        self.assertEqual(out, {"k": "-foo"})

    def test_string_with_backslash(self):
        out, _ = _round_trip({"k": r"path\to\file"})
        self.assertEqual(out, {"k": r"path\to\file"})

    def test_string_with_double_quote(self):
        out, _ = _round_trip({"k": 'say "hi"'})
        self.assertEqual(out, {"k": 'say "hi"'})

    def test_unicode_string_with_colon(self):
        # Regression: previously parser used unicode_escape which mangled Cyrillic.
        out, _ = _round_trip({"k": "Привет: мир"})
        self.assertEqual(out, {"k": "Привет: мир"})

    def test_unicode_emoji(self):
        out, _ = _round_trip({"emoji": "🦀 crab"})
        self.assertEqual(out, {"emoji": "🦀 crab"})

    def test_string_with_literal_backslash_n(self):
        # `\n` as two characters, not newline.
        d = {"k": r"a\nb"}
        out, _ = _round_trip(d)
        self.assertEqual(out, d)

    def test_int(self):
        out, _ = _round_trip({"k": 42, "n": -7})
        self.assertEqual(out, {"k": 42, "n": -7})

    def test_float(self):
        out, _ = _round_trip({"k": 3.14, "n": -0.5})
        self.assertEqual(out, {"k": 3.14, "n": -0.5})

    def test_bool(self):
        out, _ = _round_trip({"a": True, "b": False})
        self.assertEqual(out, {"a": True, "b": False})

    def test_null(self):
        out, _ = _round_trip({"a": None})
        self.assertEqual(out, {"a": None})


class RoundTripStructures(unittest.TestCase):
    def test_nested_dict(self):
        d = {"stack": {"language": "php", "framework": "symfony", "framework_version": "7.0"}}
        out, _ = _round_trip(d)
        self.assertEqual(out, d)

    def test_list_of_scalars(self):
        d = {"sources_used": ["extract_php_metadata.php", "config:routes.yaml"]}
        out, _ = _round_trip(d)
        self.assertEqual(out, d)

    def test_empty_list(self):
        d = {"missing_sections": []}
        out, _ = _round_trip(d)
        self.assertEqual(out, d)

    def test_list_of_dicts(self):
        d = {
            "items": [
                {"kind": "http_route", "file": "src/Foo.php", "line": 10},
                {"kind": "cli_command", "file": "src/Bar.php", "line": 20},
            ]
        }
        out, _ = _round_trip(d)
        self.assertEqual(out, d)

    def test_list_of_dicts_with_nested_list(self):
        d = {
            "items": [
                {"kind": "http_route", "methods": ["GET", "POST"], "file": "src/Foo.php"},
            ]
        }
        out, _ = _round_trip(d)
        self.assertEqual(out, d)

    def test_list_of_dicts_with_nested_dict(self):
        d = {
            "items": [
                {"name": "main", "config": {"pattern": "^/api", "stateless": True}},
            ]
        }
        out, _ = _round_trip(d)
        self.assertEqual(out, d)

    def test_deeply_nested(self):
        d = {
            "framework_specific": {
                "symfony": {
                    "voters": {
                        "status": "ok",
                        "items": [{"class": "PostVoter", "attributes": ["VIEW", "EDIT"]}],
                    }
                }
            }
        }
        out, _ = _round_trip(d)
        self.assertEqual(out, d)

    def test_block_scalar_multiline(self):
        d = {
            "summary": "line one\nline two\nline three",
        }
        out, text = _round_trip(d)
        self.assertEqual(out, d)
        self.assertIn("summary: |", text)

    def test_block_scalar_with_blank_line(self):
        d = {"summary": "para 1\n\npara 2"}
        out, _ = _round_trip(d)
        self.assertEqual(out, d)


class FrontmatterShape(unittest.TestCase):
    def test_realistic_frontmatter_round_trip(self):
        fm = {
            "schema_version": 2,
            "generated_at": "2026-05-05T12:00:00Z",
            "git_rev": "abc123",
            "project_fingerprint": "p1",
            "code_fingerprint": "c1",
            "scope": "project",
            "stack": {
                "language": "php",
                "framework": "symfony",
                "framework_version": "7.0",
                "detected_via": "composer.json",
            },
            "recipe_used": "symfony",
            "tool_versions": {"symfony": "7.0", "doctrine": "3.0", "mcp_phpstorm": "available"},
            "sources_used": ["extract_php_metadata.php", "config:routes.yaml"],
            "missing_sections": [],
            "recon_confidence": "medium",
            "warnings": ["console_disabled_by_flag"],
        }
        out, text = _round_trip(fm)
        self.assertEqual(out, fm)
        # Frontmatter wrapper too.
        wrapped = dump_frontmatter(fm)
        self.assertTrue(wrapped.startswith("---\n"))
        self.assertTrue(wrapped.endswith("---\n"))


class Errors(unittest.TestCase):
    def test_empty_dict_at_top_raises(self):
        with self.assertRaises(ValueError):
            dump_yaml_subset({})

    def test_empty_dict_value_raises(self):
        with self.assertRaises(ValueError):
            dump_yaml_subset({"k": {}})

    def test_invalid_key_raises(self):
        for bad in ("with-dash", "with space", "1leading_digit", ""):
            with self.assertRaises(ValueError):
                dump_yaml_subset({bad: 1})

    def test_unsupported_type_raises(self):
        with self.assertRaises(ValueError):
            dump_yaml_subset({"k": object()})

    def test_nested_list_raises(self):
        with self.assertRaises(ValueError):
            dump_yaml_subset({"k": [[1, 2]]})

    def test_multiline_in_list_raises(self):
        with self.assertRaises(ValueError):
            dump_yaml_subset({"k": ["one\ntwo"]})

    def test_nan_inf_raises(self):
        with self.assertRaises(ValueError):
            dump_yaml_subset({"k": float("inf")})
        with self.assertRaises(ValueError):
            dump_yaml_subset({"k": float("nan")})


class IndentationContract(unittest.TestCase):
    def test_two_space_indent(self):
        text = dump_yaml_subset({"a": {"b": {"c": 1}}})
        lines = text.splitlines()
        self.assertEqual(lines[0], "a:")
        self.assertEqual(lines[1], "  b:")
        self.assertEqual(lines[2], "    c: 1")

    def test_list_under_dict_indent(self):
        text = dump_yaml_subset({"items": [{"k": "v"}]})
        lines = text.splitlines()
        self.assertEqual(lines[0], "items:")
        self.assertEqual(lines[1], "  - k: v")


if __name__ == "__main__":
    unittest.main()
