"""Tests for sink_snippet normalization in Finding.sink_hash.

Workers obfuscate local variable names as `$var_<N>` per the prompt rules in
`agents/security.md`. The numbering is non-deterministic across slices: the
same real variable can become `$var_1` in one slice and `$var_3` in another,
depending on which other variables appear in the worker's 5-line window.

Without normalization this caused identical findings to receive different
sink_hash values, forcing dedupe into the heuristic
[MERGED_DESPITE_HASH_MISMATCH] fallback (4× in the event run).

These tests pin down the normalization contract:
  * Different `$var_<N>` numberings on otherwise identical snippets must
    produce the same sink_hash.
  * Snippets without any `$var_<N>` token must hash byte-for-byte
    (no-op normalization, backwards-compatible with existing baselines).
"""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

# Make `bin/` importable when tests run via `python3 -m unittest discover -s bin/tests`.
_BIN = Path(__file__).resolve().parent.parent
if str(_BIN) not in sys.path:
    sys.path.insert(0, str(_BIN))

from dedupe.models import Finding, _normalize_snippet_for_hash  # noqa: E402


class SnippetNormalizationTests(unittest.TestCase):
    def test_snippet_normalization_makes_hash_stable(self):
        """Two snippets that differ only in `$var_<N>` numbering hash equally."""
        snippet_a = "assert($var_1 === '<STR>')"
        snippet_b = "assert($var_3 === '<STR>')"
        f1 = Finding(title_line="a", sink_snippet=snippet_a)
        f2 = Finding(title_line="b", sink_snippet=snippet_b)
        self.assertEqual(
            f1.sink_hash, f2.sink_hash,
            f"normalized hashes must match: {f1.sink_hash} vs {f2.sink_hash} "
            f"(snippets: {snippet_a!r} vs {snippet_b!r})",
        )

    def test_snippet_normalization_handles_multiple_placeholders(self):
        """Different numbering schemes across multiple variables collapse."""
        # Same query semantically; worker A numbered `$em` first, worker B
        # numbered `$dql` first.
        snippet_a = "$var_1->createQuery($var_2 . $var_3)"
        snippet_b = "$var_5->createQuery($var_2 . $var_7)"
        f1 = Finding(title_line="a", sink_snippet=snippet_a)
        f2 = Finding(title_line="b", sink_snippet=snippet_b)
        self.assertEqual(f1.sink_hash, f2.sink_hash)

    def test_no_placeholder_snippets_unchanged(self):
        """Snippets without `$var_<N>` tokens hash exactly the same as before."""
        # This is the contract test_hash_value_matches_sha256 already covers,
        # but we re-assert it explicitly for the normalization layer.
        plain = "abc"
        f = Finding(title_line="x", sink_snippet=plain)
        expected = hashlib.sha256(plain.encode("utf-8")).hexdigest()[:8]
        self.assertEqual(f.sink_hash, expected)

    def test_snippets_differing_outside_placeholders_still_differ(self):
        """Normalization MUST NOT collapse genuinely different snippets."""
        f1 = Finding(title_line="a", sink_snippet="$var_1->raw('SELECT 1')")
        f2 = Finding(title_line="b", sink_snippet="$var_1->raw('SELECT 2')")
        self.assertNotEqual(f1.sink_hash, f2.sink_hash)

    def test_normalize_helper_is_noop_without_placeholder(self):
        """Direct unit test on the helper — no allocation when not needed."""
        s = "$accessToken === 'real_var_name_42'"
        # `'real_var_name_42'` contains the substring `var_42` but it is NOT
        # preceded by `$`, so the regex must not match.
        self.assertEqual(_normalize_snippet_for_hash(s), s)

    def test_normalize_helper_collapses_all_placeholders(self):
        s = "$var_1 + $var_2 + $var_99"
        self.assertEqual(_normalize_snippet_for_hash(s), "$VAR + $VAR + $VAR")


if __name__ == "__main__":
    unittest.main()
