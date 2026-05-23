"""Tests for the dedupe package (formerly dedupe_findings.py)."""

from __future__ import annotations

import hashlib
import re
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dedupe as df  # noqa: E402
import dedupe_findings as dff  # noqa: E402
from dedupe.parser import _parse_finding_block  # noqa: E402
from dedupe.pipeline import _normalize_symbol  # noqa: E402
from dedupe.renderer import _family_slug, _group_by_family  # noqa: E402

# Path to the CLI entry point (for subprocess tests).
_CLI_SCRIPT = str(Path(__file__).resolve().parent.parent / "dedupe_findings.py")


def _mk_finding_md(
    n: int,
    sink_file: str,
    sink_line: int,
    sink_kind: str,
    root_cause_family: str,
    enclosing_symbol: str,
    sink_snippet: str,
    *,
    severity: str = "High",
    confidence: int = 9,
    category: str = "sql_injection",
    description: str = "Test desc",
    discovered_via: str = "checklist:auth.md",
) -> str:
    snippet_block = "\n".join("    " + ln for ln in sink_snippet.splitlines())
    return (
        f"# Vulnerability {n}: [{category}]: `{sink_file}:{sink_line}`\n"
        f"\n"
        f"* **Severity**: {severity}\n"
        f"* **Confidence**: {confidence}/10\n"
        f"* **Category**: {category}\n"
        f"* **sink_kind**: {sink_kind}\n"
        f"* **root_cause_family**: {root_cause_family}\n"
        f"* **enclosing_symbol**: {enclosing_symbol}\n"
        f"* **sink_snippet**: |\n"
        f"{snippet_block}\n"
        f"* **Description**: {description}\n"
        f"* **Data path**: X -> Y -> {sink_file}:{sink_line}\n"
        f"* **Exploitation scenario**: test payload\n"
        f"* **Impact**: test impact\n"
        f"* **Recommendation**: test fix\n"
        f"* **Discovered via**: {discovered_via}\n"
        f"\n"
    )


def _write_findings(content: str, filename: str) -> Path:
    tmpdir = Path(tempfile.mkdtemp())
    path = tmpdir / filename
    path.write_text(content, encoding="utf-8")
    return path


class ParserTests(unittest.TestCase):
    def test_parses_single_finding(self):
        md = _mk_finding_md(
            n=1,
            sink_file="src/Repo.php",
            sink_line=42,
            sink_kind="dql_concat",
            root_cause_family="injection",
            enclosing_symbol="Repo::find",
            sink_snippet="$dql = 'SELECT u FROM u ' . $sort;",
        )
        p = _write_findings(md, "SECURITY_REVIEW_RESULTS_W2.md")
        findings = df.parse_findings_file(p)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.sink_file, "src/Repo.php")
        self.assertEqual(f.sink_line, 42)
        self.assertEqual(f.sink_kind, "dql_concat")
        self.assertEqual(f.root_cause_family, "injection")
        self.assertEqual(f.enclosing_symbol, "Repo::find")
        self.assertIn("$dql", f.sink_snippet)
        self.assertIn("SELECT", f.sink_snippet)
        self.assertEqual(f.severity, "High")
        self.assertEqual(f.confidence, 9)
        self.assertEqual(f.slice_id, "W2")

    def test_parses_english_keys(self):
        """Regression: FIELD_RE must accept English field keys
        (Category, Description, Data path, Exploitation scenario,
        Impact, Recommendation) -- without this `category` is empty
        and the index shows `--`, the header shows `[]`."""
        md = _mk_finding_md(
            n=1,
            sink_file="src/X.php",
            sink_line=1,
            sink_kind="csrf_missing",
            root_cause_family="authz",
            enclosing_symbol="X::m",
            sink_snippet="$x = 1;",
            category="oauth_state_missing",
            description="OAuth state missing",
        )
        p = _write_findings(md, "SECURITY_REVIEW_RESULTS_W1.md")
        findings = df.parse_findings_file(p)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.category, "oauth_state_missing")
        self.assertEqual(f.description, "OAuth state missing")
        self.assertEqual(f.data_path, "X -> Y -> src/X.php:1")
        self.assertEqual(f.exploit, "test payload")
        self.assertEqual(f.impact, "test impact")
        self.assertEqual(f.recommendation, "test fix")

    def test_parses_multiple_findings(self):
        md = _mk_finding_md(
            1, "src/A.php", 10, "dql_concat", "injection", "A::m",
            "line1\nline2\nline3",
        ) + _mk_finding_md(
            2, "src/B.php", 20, "missing_authz", "authz", "B::m",
            "other1\nother2",
        )
        p = _write_findings(md, "SECURITY_REVIEW_RESULTS_W1.md")
        findings = df.parse_findings_file(p)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].sink_file, "src/A.php")
        self.assertEqual(findings[1].sink_file, "src/B.php")

    def test_php_attribute_in_snippet_not_treated_as_heading(self):
        """Regression: the parser broke sink_snippet on any line starting with `#`,
        including PHP attributes `#[ORM\\Column]` / `#[Route]` / `#[AsCommand]`.
        This produced an empty snippet -> sink_hash='nohash00' -> dedupe lost the
        stable hash for all Doctrine entity property findings (encryption-at-rest).
        Now it only breaks on real markdown headings (`# H1`, `## H2`)."""
        snippet = (
            "#[ORM\\Column(type: 'string', nullable: false)]\n"
            "private string $accessToken;\n"
            "#[ORM\\Column(type: 'string', nullable: true)]\n"
            "private ?string $refreshToken;"
        )
        md = _mk_finding_md(
            1, "src/Entity/IntegrationToken.php", 33,
            "hardcoded_secret", "crypto", "IntegrationToken",
            snippet,
        )
        p = _write_findings(md, "SECURITY_REVIEW_RESULTS_W1.md")
        findings = df.parse_findings_file(p)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIn("#[ORM\\Column", f.sink_snippet)
        self.assertIn("$accessToken", f.sink_snippet)
        self.assertIn("$refreshToken", f.sink_snippet)
        self.assertNotEqual(f.sink_hash, "nohash00",
                            f"snippet must produce stable hash, got nohash00 with snippet={f.sink_snippet!r}")

    def test_markdown_heading_in_snippet_still_breaks(self):
        """Control: a real markdown heading (`#` + space) inside the snippet
        breaks extraction -- this is intentional, otherwise one block would
        consume its neighbor."""
        from dedupe.parser import _extract_snippet_block
        lines = [
            "* **sink_snippet**: |",
            "    valid line",
            "    # H1 inside snippet",
            "    after heading",
        ]
        snippet, _ = _extract_snippet_block(lines, 0, "|")
        self.assertIn("valid line", snippet)
        self.assertNotIn("after heading", snippet,
                         "real `# H1` heading must stop snippet extraction")

    def test_parser_unknown_sink_kind(self):
        """Regression: a typo `weakrandom` (instead of `weak_random`) does not
        slip through silently -- the parser emits a UserWarning, the finding
        gets `is_custom_sink=True`, and `dedupe()` flags it as `[CUSTOM_SINK]`
        (either in main via auto-promote, or in manual_review)."""
        import warnings as _warnings
        md = _mk_finding_md(
            n=1,
            sink_file="src/Util/Random.php",
            sink_line=15,
            sink_kind="weakrandom",   # typo of weak_random
            root_cause_family="crypto",
            enclosing_symbol="Random::token",
            sink_snippet="$token = mt_rand();",
            severity="High",
            confidence=9,
        )
        p = _write_findings(md, "SECURITY_REVIEW_RESULTS_W4.md")
        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            findings = df.parse_findings_file(p)
        # Warning was emitted with the bad identifier in the message.
        warn_msgs = [str(w.message) for w in caught if issubclass(w.category, UserWarning)]
        self.assertTrue(
            any("weakrandom" in m for m in warn_msgs),
            f"expected UserWarning mentioning `weakrandom`, got {warn_msgs!r}",
        )
        # is_custom_sink kicks in for unknown kind even without `other:` prefix.
        self.assertEqual(len(findings), 1)
        self.assertTrue(
            findings[0].is_custom_sink,
            "finding with unknown sink_kind must be flagged as custom_sink",
        )
        # End-to-end: the finding emerges with [CUSTOM_SINK] flag from dedupe
        # (auto-promoted to main because severity High + confidence 9 + known
        # symbol + sink_file present — see _should_promote_custom_sink).
        merged, manual = df.dedupe(findings)
        all_results = merged + manual
        self.assertEqual(len(all_results), 1)
        self.assertIn(df.FLAG_CUSTOM_SINK, all_results[0].flags)

    def test_route_attribute_in_snippet_kept(self):
        """Covers `#[Route('/path')]` -- another typical PHP attribute
        frequently seen in controller findings."""
        snippet = (
            "#[Route('/api/v1/oauth/callback', methods: ['GET'])]\n"
            "public function handleAccessCode(Request $request): Response {"
        )
        md = _mk_finding_md(
            1, "src/Crm/Api/Integration/IntegrationController.php", 29,
            "csrf_missing", "authz", "IntegrationController::handleAccessCode",
            snippet,
        )
        p = _write_findings(md, "SECURITY_REVIEW_RESULTS_W1.md")
        findings = df.parse_findings_file(p)
        self.assertIn("#[Route(", findings[0].sink_snippet)
        self.assertIn("handleAccessCode", findings[0].sink_snippet)


class SliceIdDerivationTests(unittest.TestCase):
    """Verify _derive_slice_id resolution order (v3 layout / legacy / fallback)."""

    def test_v3_layout_uses_path_stem(self):
        from dedupe.parser import _derive_slice_id

        self.assertEqual(_derive_slice_id(Path("/tmp/security-review-claude/waves/W1.md")), "W1")
        self.assertEqual(_derive_slice_id(Path("/x/security-review-foo/waves/W2_PART1.md")), "W2_PART1")
        self.assertEqual(_derive_slice_id(Path("waves/W∞.md")), "W∞")

    def test_legacy_layout_uses_captured_group(self):
        from dedupe.parser import _derive_slice_id

        self.assertEqual(_derive_slice_id(Path("/tmp/SECURITY_REVIEW_RESULTS_W2.md")), "W2")
        self.assertEqual(_derive_slice_id(Path("SECURITY_REVIEW_RESULTS_W3_PART1.md")), "W3_PART1")

    def test_fallback_to_path_stem(self):
        from dedupe.parser import _derive_slice_id

        self.assertEqual(_derive_slice_id(Path("/tmp/some_other_file.md")), "some_other_file")

    def test_v3_layout_takes_precedence_over_legacy_regex(self):
        """File in waves/ named like legacy → v3 rule wins (path.stem keeps the prefix)."""
        from dedupe.parser import _derive_slice_id

        path = Path("/x/security-review-claude/waves/SECURITY_REVIEW_RESULTS_W1.md")
        self.assertEqual(_derive_slice_id(path), "SECURITY_REVIEW_RESULTS_W1")

    def test_parse_findings_file_v3_layout(self):
        """parse_findings_file should set slice_id correctly for v3 layout."""
        md = _mk_finding_md(
            n=1, sink_file="src/X.php", sink_line=10,
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="X::m", sink_snippet="raw",
        )
        tmpdir = Path(tempfile.mkdtemp())
        waves_dir = tmpdir / "waves"
        waves_dir.mkdir()
        path = waves_dir / "W1_PART1.md"
        path.write_text(md, encoding="utf-8")
        findings = df.parse_findings_file(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].slice_id, "W1_PART1")


class SinkHashTests(unittest.TestCase):
    def test_hash_deterministic(self):
        f1 = df.Finding(title_line="x", sink_snippet="hello world")
        f2 = df.Finding(title_line="y", sink_snippet="hello world")
        self.assertEqual(f1.sink_hash, f2.sink_hash)

    def test_hash_differs_on_content(self):
        f1 = df.Finding(title_line="x", sink_snippet="hello world")
        f2 = df.Finding(title_line="y", sink_snippet="hello worldz")
        self.assertNotEqual(f1.sink_hash, f2.sink_hash)

    def test_hash_value_matches_sha256(self):
        f = df.Finding(title_line="x", sink_snippet="abc")
        expected = hashlib.sha256(b"abc").hexdigest()[:8]
        self.assertEqual(f.sink_hash, expected)


class DedupeTests(unittest.TestCase):
    def test_single_finding_not_merged(self):
        f = df.Finding(
            title_line="h",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="A::m",
            sink_snippet="x",
        )
        merged, manual = df.dedupe([f])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0].merged_from), 0)
        self.assertEqual(manual, [])

    def test_two_identical_merge(self):
        snippet = "$q = $em->createQuery($s);"
        f1 = df.Finding(
            title_line="h1",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="A::m",
            sink_snippet=snippet, slice_id="W1", severity="High", confidence=8,
        )
        f2 = df.Finding(
            title_line="h2",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="A::m",
            sink_snippet=snippet, slice_id="W2", severity="Critical", confidence=10,
        )
        merged, manual = df.dedupe([f1, f2])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0].merged_from), 1)
        self.assertEqual(merged[0].severity, "Critical")
        self.assertEqual(merged[0].confidence, 10)
        self.assertCountEqual(merged[0].slice_ids, ["W1", "W2"])

    def test_different_sink_hash_fallback_merge(self):
        """After v6.1 adaptive dedupe: different hash with identical
        (file, kind, family, symbol) -> merge with flag, not split."""
        f1 = df.Finding(
            title_line="h1",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="A::m",
            sink_snippet="line A",
        )
        f2 = df.Finding(
            title_line="h2",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="A::m",
            sink_snippet="line B",
        )
        merged, manual = df.dedupe([f1, f2])
        self.assertEqual(len(merged), 1)
        self.assertIn(df.FLAG_MERGED_DESPITE_HASH_MISMATCH, merged[0].flags)

    def test_hash_mismatch_merges_pick_higher_confidence(self):
        """Pinned regression for [MERGED_DESPITE_HASH_MISMATCH]: with identical
        (file, kind, family, symbol) but different snippets (-> different
        sink_hash) and different confidence -- the Pass 2 fallback heuristic
        merges both records and picks the primary with the higher confidence.
        (`_pick_primary` ranks by (severity, confidence, len(raw_body));
        confidence breaks the tie here before raw_body length is even
        consulted.) On a production run this heuristic fired 4 times; the test
        guards it against unintentional changes during refactoring."""
        f_low = df.Finding(
            title_line="h_low",
            sink_file="src/Repo.php", sink_line=42,
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find",
            sink_snippet="$q = $em->createQuery($a);",
            severity="High", confidence=8,
            raw_body="short body",
            slice_id="W_low",
        )
        f_high = df.Finding(
            title_line="h_high",
            sink_file="src/Repo.php", sink_line=42,
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find",
            sink_snippet="$q = $em->createQuery($b);",  # different → different hash
            severity="High", confidence=10,
            raw_body="much longer body with more details about the sink",
            slice_id="W_high",
        )
        # Sanity: confirm hashes really differ so the test exercises Pass 2.
        self.assertNotEqual(f_low.sink_hash, f_high.sink_hash)

        merged, manual = df.dedupe([f_low, f_high])
        self.assertEqual(len(merged), 1)
        self.assertEqual(manual, [])
        mf = merged[0]
        self.assertIn(df.FLAG_MERGED_DESPITE_HASH_MISMATCH, mf.flags)
        # Primary must be the finding with the higher confidence (severity tied -> confidence wins).
        self.assertEqual(mf.primary.title_line, "h_high")
        self.assertEqual(mf.primary.confidence, 10)
        self.assertCountEqual(mf.slice_ids, ["W_low", "W_high"])

    def test_hash_mismatch_does_not_cross_sink_kind(self):
        """Negative control for [MERGED_DESPITE_HASH_MISMATCH]: the Pass 2
        fallback heuristic drops only sink_hash, NOT sink_kind. Two findings
        with identical (file, family, symbol) and different sink_kind stay as
        separate merged records (guard against over-merge when refactoring
        Pass 2).

        Different sink_line is used so that Pass 3 cross-sink merge does not
        collapse them either (it groups by (file, line, symbol)) -- otherwise
        the test would verify Pass 3, not Pass 2."""
        f_dql = df.Finding(
            title_line="h_dql",
            sink_file="src/Repo.php", sink_line=42,
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find",
            sink_snippet="$q = $em->createQuery($a);",
            severity="High", confidence=9,
        )
        f_sql = df.Finding(
            title_line="h_sql",
            sink_file="src/Repo.php", sink_line=99,
            sink_kind="sql_concat", root_cause_family="injection",
            enclosing_symbol="Repo::find",
            sink_snippet="$conn->exec(\"SELECT \" . $b);",
            severity="High", confidence=9,
        )
        merged, manual = df.dedupe([f_dql, f_sql])
        self.assertEqual(
            len(merged), 2,
            "Pass 2 hash-mismatch heuristic must not collapse different sink_kind",
        )
        for mf in merged:
            self.assertNotIn(df.FLAG_MERGED_DESPITE_HASH_MISMATCH, mf.flags)
            self.assertNotIn(df.FLAG_CROSS_SINK_MERGE, mf.flags)

    def test_different_family_not_merged_but_cross_referenced(self):
        snippet = "code"
        f_auth = df.Finding(
            title_line="h1", category="missing_authz",
            sink_file="a.php", sink_kind="missing_authz",
            root_cause_family="authz", enclosing_symbol="A::m",
            sink_snippet=snippet,
        )
        f_inj = df.Finding(
            title_line="h2", category="dql",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="A::m",
            sink_snippet=snippet,
        )
        merged, manual = df.dedupe([f_auth, f_inj])
        self.assertEqual(len(merged), 2)
        labels0 = merged[0].related
        labels1 = merged[1].related
        self.assertTrue(labels0, "expected cross-reference on first finding")
        self.assertTrue(labels1, "expected cross-reference on second finding")

    def test_unknown_symbol_still_merged_between_each_other(self):
        """Two findings with enclosing_symbol=unknown, same file+sink_kind+family+hash
        should NOT go to Manual review — they merge via fallback-1 strategy."""
        snippet = "code"
        f1 = df.Finding(
            title_line="h1",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="unknown",
            sink_snippet=snippet, slice_id="W1",
        )
        f2 = df.Finding(
            title_line="h2",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="unknown",
            sink_snippet=snippet, slice_id="W2",
        )
        merged, manual = df.dedupe([f1, f2])
        self.assertEqual(len(merged), 1)
        self.assertEqual(manual, [])
        self.assertIn(df.FLAG_MERGED_WITHOUT_SYMBOL, merged[0].flags)

    def test_custom_sink_merges_by_file_line_in_manual(self):
        """Custom sinks go to Manual but MERGE if same file+line_bucket+category."""
        f1 = df.Finding(
            title_line="h1",
            sink_file=".env", sink_line=3, category="hardcoded_secret",
            sink_kind="other:dotenv_secret",
            root_cause_family="disclosure", enclosing_symbol="A::m",
            sink_snippet="APP_SECRET=leak",
        )
        f2 = df.Finding(
            title_line="h2",
            sink_file=".env", sink_line=4, category="hardcoded_secret",
            sink_kind="other:dotenv_secret",
            root_cause_family="disclosure", enclosing_symbol="A::m",
            sink_snippet="APP_SECRET=leak",
        )
        merged, manual = df.dedupe([f1, f2])
        self.assertEqual(merged, [])
        self.assertEqual(len(manual), 1, "two findings in same line_bucket should merge")
        self.assertIn(df.FLAG_CUSTOM_SINK, manual[0].flags)
        self.assertIn(df.FLAG_MERGED_BY_FILE_LINE, manual[0].flags)

    def test_conflicting_severity_flag(self):
        snippet = "code"
        f_medium = df.Finding(
            title_line="h1",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="A::m",
            sink_snippet=snippet, severity="Medium", confidence=9,
        )
        f_critical = df.Finding(
            title_line="h2",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="A::m",
            sink_snippet=snippet, severity="Critical", confidence=9,
        )
        merged, manual = df.dedupe([f_medium, f_critical])
        self.assertEqual(len(merged), 1)
        self.assertIn(df.FLAG_CONFLICTING_SEVERITY, merged[0].flags)

    def test_confidence_disagreement_flag(self):
        snippet = "code"
        f_low = df.Finding(
            title_line="h1",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="A::m",
            sink_snippet=snippet, severity="High", confidence=8,
        )
        f_high = df.Finding(
            title_line="h2",
            sink_file="a.php", sink_kind="dql_concat",
            root_cause_family="injection", enclosing_symbol="A::m",
            sink_snippet=snippet, severity="High", confidence=10,
        )
        merged, manual = df.dedupe([f_low, f_high])
        self.assertIn(df.FLAG_CONFIDENCE_DISAGREEMENT, merged[0].flags)

    def test_known_other_kind_normalised_to_canonical(self):
        """`other:tokens_visible_in_ui` is a known custom kind that recurs
        across projects (admin UI exposes OAuth tokens as plain TextField).
        Pre-pass normalisation rewrites it to `sensitive_field_unmasked` /
        `disclosure` so the finding loses CUSTOM_SINK and lands in the main
        list (no manual review needed even at Medium severity)."""
        f = df.Finding(
            title_line="h",
            sink_file="src/Admin/IntegrationTokenCrudController.php",
            sink_line=43,
            sink_kind="other:tokens_visible_in_ui",
            root_cause_family="other:disclosure",
            enclosing_symbol="IntegrationTokenCrudController::configureFields",
            sink_snippet="TextField::new('accessToken', 'Access Token'),",
            severity="Medium", confidence=9,
        )
        merged, manual = df.dedupe([f])
        self.assertEqual(len(merged), 1, "should NOT go to manual review")
        self.assertEqual(manual, [])
        self.assertEqual(merged[0].primary.sink_kind, "sensitive_field_unmasked")
        self.assertEqual(merged[0].primary.root_cause_family, "disclosure")
        self.assertNotIn(df.FLAG_CUSTOM_SINK, merged[0].flags,
                         "normalised kind must not retain CUSTOM_SINK flag")

    def test_known_other_kind_preserves_explicit_standard_family(self):
        """If the worker set sink_kind=other:* but root_cause_family is already
        standard (e.g. `disclosure`), the pre-pass keeps the worker's family."""
        f = df.Finding(
            title_line="h",
            sink_file="src/Admin/X.php", sink_line=10,
            sink_kind="other:tokens_visible_in_ui",
            root_cause_family="disclosure",  # already standard
            enclosing_symbol="X::configureFields",
            sink_snippet="TextField::new('secretKey'),",
            severity="High", confidence=9,
        )
        merged, _ = df.dedupe([f])
        self.assertEqual(merged[0].primary.sink_kind, "sensitive_field_unmasked")
        self.assertEqual(merged[0].primary.root_cause_family, "disclosure")

    def test_unknown_other_kind_still_goes_to_manual_review(self):
        """Control: an `other:*` kind NOT in KNOWN_OTHER_KINDS still flows
        through the custom-sink path. Severity Medium → manual review."""
        f = df.Finding(
            title_line="h",
            sink_file="src/X.php", sink_line=10,
            sink_kind="other:novel_unmapped_pattern",
            root_cause_family="other:weird",
            enclosing_symbol="X::method",
            sink_snippet="snippet",
            severity="Medium", confidence=9,
        )
        merged, manual = df.dedupe([f])
        self.assertEqual(merged, [])
        self.assertEqual(len(manual), 1)
        self.assertIn(df.FLAG_CUSTOM_SINK, manual[0].flags)

    def test_known_other_kinds_merge_with_canonical_peers(self):
        """Two findings: one with `other:plaintext_oauth_tokens`, one with the
        canonical `hardcoded_secret`. After normalisation they merge as one
        (same file + canonical kind + family + symbol + snippet)."""
        snippet = "#[ORM\\Column(type: 'string')] private string $accessToken;"
        f_other = df.Finding(
            title_line="h1",
            sink_file="src/Entity/IntegrationToken.php", sink_line=33,
            sink_kind="other:plaintext_oauth_tokens",
            root_cause_family="crypto",
            enclosing_symbol="IntegrationToken",
            sink_snippet=snippet, severity="High", confidence=9,
        )
        f_canonical = df.Finding(
            title_line="h2",
            sink_file="src/Entity/IntegrationToken.php", sink_line=33,
            sink_kind="hardcoded_secret",
            root_cause_family="crypto",
            enclosing_symbol="IntegrationToken",
            sink_snippet=snippet, severity="High", confidence=9,
        )
        merged, manual = df.dedupe([f_other, f_canonical])
        self.assertEqual(len(merged), 1)
        self.assertEqual(manual, [])
        self.assertEqual(merged[0].primary.sink_kind, "hardcoded_secret")

    def test_trait_aggregation(self):
        """Same sink_file (trait), two vulnerabilities from different callers
        but same enclosing trait method → merge (trait is root cause)."""
        snippet = "$q = $em->createQuery($dql);"
        f1 = df.Finding(
            title_line="h1",
            sink_file="src/Repository/QueryTrait.php",
            sink_kind="dql_concat",
            root_cause_family="injection",
            enclosing_symbol="QueryTrait::buildQuery",
            sink_snippet=snippet, slice_id="W2_UserRepo",
        )
        f2 = df.Finding(
            title_line="h2",
            sink_file="src/Repository/QueryTrait.php",
            sink_kind="dql_concat",
            root_cause_family="injection",
            enclosing_symbol="QueryTrait::buildQuery",
            sink_snippet=snippet, slice_id="W2_ProductRepo",
        )
        merged, manual = df.dedupe([f1, f2])
        self.assertEqual(len(merged), 1)
        self.assertCountEqual(merged[0].slice_ids, ["W2_UserRepo", "W2_ProductRepo"])


class EndToEndTests(unittest.TestCase):
    def test_dedupe_cli_end_to_end(self):
        md1 = _mk_finding_md(
            1, "src/Repo.php", 42, "dql_concat", "injection", "Repo::find",
            "$dql = 'SELECT' . $s;",
            severity="High", confidence=9,
        )
        md2 = _mk_finding_md(
            1, "src/Repo.php", 42, "dql_concat", "injection", "Repo::find",
            "$dql = 'SELECT' . $s;",
            severity="Critical", confidence=10,
        )
        tmpdir = Path(tempfile.mkdtemp())
        (tmpdir / "SECURITY_REVIEW_RESULTS_W1.md").write_text(md1)
        (tmpdir / "SECURITY_REVIEW_RESULTS_W2.md").write_text(md2)
        output = tmpdir / "SECURITY_REVIEW_RESULTS.md"

        import subprocess
        result = subprocess.run(
            [
                sys.executable,
                _CLI_SCRIPT,
                "--input-glob",
                str(tmpdir / "SECURITY_REVIEW_RESULTS_*.md"),
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertTrue(output.is_file())
        report = output.read_text()
        self.assertIn("# SECURITY_REVIEW_RESULTS", report)
        self.assertIn("Critical", report)
        self.assertIn("dql_concat", report)

    def test_idempotent_rehash(self):
        """Two runs over same files produce the same sink_hash."""
        md = _mk_finding_md(
            1, "src/R.php", 10, "dql_concat", "injection", "R::m",
            "some snippet with $var",
        )
        p1 = _write_findings(md, "SECURITY_REVIEW_RESULTS_X.md")
        f1 = df.parse_findings_file(p1)[0]
        f2 = df.parse_findings_file(p1)[0]
        self.assertEqual(f1.sink_hash, f2.sink_hash)


_CONTEXT_WITH_GAP = """---
schema_version: 2
recipe_used: symfony
environment:
  containerized: true
  container_signals:
    - docker-compose.yml
  host_php_present: true
  host_php_version: "8.4.1"
  console_mode: disabled
  console_gap: true
  console_gap_reason: "env_runner_unknown: containerized project"
---
body
"""

_CONTEXT_NO_GAP = """---
schema_version: 2
recipe_used: symfony
environment:
  containerized: false
  host_php_present: true
  host_php_version: "8.4.1"
  console_mode: host
  console_gap: false
  console_gap_reason: null
---
body
"""


class CoverageGapsTests(unittest.TestCase):
    def test_read_coverage_gaps_returns_line_when_gap(self):
        rr = Path(tempfile.mkdtemp())
        (rr / "CONTEXT.md").write_text(_CONTEXT_WITH_GAP, encoding="utf-8")
        gaps = dff.read_coverage_gaps(rr)
        self.assertEqual(len(gaps), 1)
        self.assertIn("Console enrichment not performed", gaps[0])
        self.assertIn("env_runner_unknown", gaps[0])

    def test_read_coverage_gaps_empty_when_no_gap(self):
        rr = Path(tempfile.mkdtemp())
        (rr / "CONTEXT.md").write_text(_CONTEXT_NO_GAP, encoding="utf-8")
        self.assertEqual(dff.read_coverage_gaps(rr), [])

    def test_read_coverage_gaps_empty_when_no_context(self):
        rr = Path(tempfile.mkdtemp())
        self.assertEqual(dff.read_coverage_gaps(rr), [])

    def test_report_includes_coverage_gaps_section(self):
        import subprocess
        rr = Path(tempfile.mkdtemp())
        (rr / "CONTEXT.md").write_text(_CONTEXT_WITH_GAP, encoding="utf-8")
        waves = rr / "waves"
        waves.mkdir()
        (waves / "W1.md").write_text(
            _mk_finding_md(
                1, "src/Repo.php", 42, "dql_concat", "injection", "Repo::find",
                "$dql = 'SELECT' . $s;",
            )
        )
        output = rr / "REPORT.md"
        result = subprocess.run(
            [sys.executable, _CLI_SCRIPT,
             "--input-glob", str(waves / "*.md"),
             "--output", str(output), "--no-state"],
            capture_output=True, text=True, check=True,
        )
        report = output.read_text()
        self.assertIn("## Coverage Gaps", report)
        self.assertIn("Console enrichment not performed", report)

    def test_report_omits_section_when_no_gap(self):
        import subprocess
        rr = Path(tempfile.mkdtemp())
        (rr / "CONTEXT.md").write_text(_CONTEXT_NO_GAP, encoding="utf-8")
        waves = rr / "waves"
        waves.mkdir()
        (waves / "W1.md").write_text(
            _mk_finding_md(
                1, "src/Repo.php", 42, "dql_concat", "injection", "Repo::find",
                "$dql = 'SELECT' . $s;",
            )
        )
        output = rr / "REPORT.md"
        subprocess.run(
            [sys.executable, _CLI_SCRIPT,
             "--input-glob", str(waves / "*.md"),
             "--output", str(output), "--no-state"],
            capture_output=True, text=True, check=True,
        )
        self.assertNotIn("## Coverage Gaps", output.read_text())


class SymbolNormalizationTests(unittest.TestCase):
    def test_strips_namespace(self):
        self.assertEqual(
            _normalize_symbol("App\\Foo\\Bar\\Listener::onRequest"),
            "Listener::onRequest",
        )

    def test_strips_backticks(self):
        self.assertEqual(
            _normalize_symbol("`Listener::onRequest`"),
            "Listener::onRequest",
        )

    def test_strips_parenthetical(self):
        self.assertEqual(
            _normalize_symbol("Foo::bar (and all other event controllers)"),
            "Foo::bar",
        )

    def test_already_short(self):
        self.assertEqual(
            _normalize_symbol("Listener::onRequest"),
            "Listener::onRequest",
        )

    def test_strips_namespace_from_bare_class(self):
        """Regression from event v2.2.0: entity-sink findings carry
        enclosing_symbol = full FQCN without `::method`."""
        self.assertEqual(
            _normalize_symbol("App\\Crm\\Core\\Common\\Integration\\IntegrationToken"),
            "IntegrationToken",
        )
        self.assertEqual(
            _normalize_symbol("IntegrationToken"),
            "IntegrationToken",
        )
        self.assertEqual(
            _normalize_symbol("App\\Foo\\IntegrationToken (entity)"),
            "IntegrationToken",
        )

    def test_unknown_stays_unknown(self):
        self.assertEqual(_normalize_symbol("unknown"), "unknown")
        self.assertEqual(_normalize_symbol(""), "unknown")
        self.assertEqual(_normalize_symbol("UNKNOWN"), "unknown")

    def test_merges_findings_with_namespace_variations(self):
        """Regression from a production run: workers write the symbol in
        different ways, fallback merge must collapse them."""
        snippet = "code"
        f1 = df.Finding(
            title_line="h1",
            sink_file="src/Log/Listener.php", sink_line=20,
            sink_kind="pii_in_logs", root_cause_family="disclosure",
            enclosing_symbol="App\\Crm\\Log\\Listener::onRequest",
            sink_snippet=snippet + "_a",
        )
        f2 = df.Finding(
            title_line="h2",
            sink_file="src/Log/Listener.php", sink_line=20,
            sink_kind="pii_in_logs", root_cause_family="disclosure",
            enclosing_symbol="Listener::onRequest",
            sink_snippet=snippet + "_b",
        )
        f3 = df.Finding(
            title_line="h3",
            sink_file="src/Log/Listener.php", sink_line=20,
            sink_kind="pii_in_logs", root_cause_family="disclosure",
            enclosing_symbol="`Listener::onRequest`",
            sink_snippet=snippet + "_c",
        )
        merged, _manual = df.dedupe([f1, f2, f3])
        self.assertEqual(len(merged), 1,
                         f"expected 1 merged finding, got {len(merged)}")


class FallbackMergeTests(unittest.TestCase):
    """Regression: different workers produce different sink_hash for same
    vulnerability because sink_snippet normalisation varies across LLM instances."""

    def _mk(self, snippet: str, severity: str = "High") -> df.Finding:
        return df.Finding(
            title_line="h", severity=severity, confidence=9,
            sink_file="src/Log/Listener.php", sink_line=20,
            sink_kind="pii_in_logs",
            root_cause_family="disclosure",
            enclosing_symbol="Listener::onKernelRequest",
            sink_snippet=snippet,
            description="logging headers",
            raw_body="raw body",
        )

    def test_same_hash_primary_merge(self):
        f1 = self._mk("$logger->debug(...)")
        f2 = self._mk("$logger->debug(...)")
        self.assertEqual(f1.sink_hash, f2.sink_hash)
        merged, _manual = df.dedupe([f1, f2])
        self.assertEqual(len(merged), 1)
        self.assertNotIn(df.FLAG_MERGED_DESPITE_HASH_MISMATCH, merged[0].flags)

    def test_different_hash_same_identity_fallback_merge(self):
        """Different snippets (different normalization), but matching
        file + kind + family + symbol -> must merge with a flag."""
        f1 = self._mk("$logger->debug('Request', ['headers' => $var_1])")
        f2 = self._mk("$this->logger->debug('Request', ['headers' => $req])")
        f3 = self._mk("$requestLogger->debug(..., ['headers' => $request->headers])")
        hashes = {f.sink_hash for f in (f1, f2, f3)}
        self.assertEqual(len(hashes), 3, "expected different hashes")

        merged, _manual = df.dedupe([f1, f2, f3])
        self.assertEqual(len(merged), 1,
                         f"expected 1 merged finding, got {len(merged)}")
        self.assertIn(df.FLAG_MERGED_DESPITE_HASH_MISMATCH, merged[0].flags)
        all_items = [merged[0].primary] + merged[0].merged_from
        self.assertEqual(len(all_items), 3)

    def test_different_identity_no_fallback_merge(self):
        """Different files -- do not merge even via fallback."""
        f1 = self._mk("code1")
        f1.sink_file = "src/A.php"
        f2 = self._mk("code2")
        f2.sink_file = "src/B.php"
        merged, _manual = df.dedupe([f1, f2])
        self.assertEqual(len(merged), 2)

    def test_different_sink_kind_cross_sink_merge(self):
        """Different sink_kind but identical (file, line, symbol) -- pass 3
        cross-sink merge collapses them with the [CROSS_SINK_MERGE] flag."""
        f1 = self._mk("code")
        f1.sink_kind = "pii_in_logs"
        f2 = self._mk("code2")
        f2.sink_kind = "hardcoded_secret"
        merged, _manual = df.dedupe([f1, f2])
        self.assertEqual(len(merged), 1,
                         f"expected 1 merged (cross-sink), got {len(merged)}")
        self.assertIn(df.FLAG_CROSS_SINK_MERGE, merged[0].flags)
        alt = merged[0].alternative_sink_kinds
        self.assertTrue(
            {merged[0].primary.sink_kind, *alt} == {"pii_in_logs", "hardcoded_secret"},
            f"unexpected kinds: primary={merged[0].primary.sink_kind!r}, alt={alt!r}",
        )

    def test_different_sink_kind_different_location_no_merge(self):
        """Different sink_kind AND different locations -- do not merge."""
        f1 = self._mk("code")
        f1.sink_kind = "pii_in_logs"
        f1.sink_line = 20
        f2 = self._mk("code2")
        f2.sink_kind = "hardcoded_secret"
        f2.sink_file = "src/Entity/Token.php"
        f2.sink_line = 50
        merged, _manual = df.dedupe([f1, f2])
        self.assertEqual(len(merged), 2)


class SnippetParserTests(unittest.TestCase):
    def test_snippet_with_yaml_pipe_indent(self):
        body = (
            "* **sink_kind**: dql_concat\n"
            "* **sink_snippet**: |\n"
            "    $q = 'SELECT';\n"
            "    $q .= $user;\n"
            "* **Description**: test\n"
        )
        f = _parse_finding_block("# Vulnerability 1: [x]: `a.php:1`", body)
        self.assertIn("SELECT", f.sink_snippet)
        self.assertIn("$user", f.sink_snippet)
        self.assertNotIn("Description", f.sink_snippet)

    def test_snippet_with_fenced_block(self):
        body = (
            "* **sink_kind**: dql_concat\n"
            "* **sink_snippet**:\n"
            "    ```\n"
            "    $q = 'SELECT';\n"
            "    $q .= $user;\n"
            "    ```\n"
            "* **Description**: test\n"
        )
        f = _parse_finding_block("# Vulnerability 1: [x]: `a.php:1`", body)
        self.assertIn("SELECT", f.sink_snippet)
        self.assertNotIn("```", f.sink_snippet)

    def test_snippet_inline_single_line(self):
        body = (
            "* **sink_kind**: dql_concat\n"
            "* **sink_snippet**: $q = $user . $x;\n"
            "* **Description**: test\n"
        )
        f = _parse_finding_block("# Vulnerability 1: [x]: `a.php:1`", body)
        self.assertEqual(f.sink_snippet, "$q = $user . $x;")

    def test_snippet_multiline_without_pipe(self):
        body = (
            "* **sink_kind**: dql_concat\n"
            "* **sink_snippet**:\n"
            "    $a = 1;\n"
            "    $b = 2;\n"
            "* **Description**: test\n"
        )
        f = _parse_finding_block("# Vulnerability 1: [x]: `a.php:1`", body)
        self.assertIn("$a", f.sink_snippet)
        self.assertIn("$b", f.sink_snippet)


class RenderingTests(unittest.TestCase):
    def test_render_replays_full_body(self):
        """The final report must contain Description / Exploit / Recommendation
        from the original raw_body, not lose them."""
        md = _mk_finding_md(
            1, "src/R.php", 10, "dql_concat", "injection", "R::m",
            "$q = 'SELECT' . $user;",
            description="SQL injection via user input",
        )
        p = _write_findings(md, "SECURITY_REVIEW_RESULTS_W1.md")
        findings = df.parse_findings_file(p)
        merged, manual = df.dedupe(findings)
        self.assertEqual(len(merged), 1)
        report = df.render_finding(1, merged[0])
        self.assertIn("Description", report)
        self.assertIn("SQL injection via user input", report)
        self.assertIn("Exploitation scenario", report)
        self.assertIn("Recommendation", report)
        self.assertIn("sink_hash", report)

    def test_title_single_category_verbatim(self):
        """The header shows the category verbatim when there is only one."""
        md = _mk_finding_md(
            1, "src/R.php", 10, "dql_concat", "injection", "R::m",
            "$q = 'SELECT' . $user;", category="sql_injection_dql",
        )
        findings = df.parse_findings_file(_write_findings(md, "W1.md"))
        merged, _ = df.dedupe(findings)
        title_line = df.render_finding(1, merged[0]).splitlines()[0]
        self.assertIn("[sql_injection_dql]", title_line)
        self.assertNotIn("more)", title_line)

    def test_title_multiple_categories_trimmed(self):
        """Regression v2.2.0 event: multi-merge of categories bloated the header."""
        f1 = df.Finding(
            title_line="h1",
            sink_file="src/R.php", sink_line=10,
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="R::m",
            sink_snippet="snip",
            category="sql_injection_primary",
            raw_body="* **Category**: sql_injection_primary\n",
        )
        f2 = df.Finding(
            title_line="h2",
            sink_file="src/R.php", sink_line=10,
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="R::m",
            sink_snippet="snip",
            category="sql_injection_variant_two",
            raw_body="* **Category**: sql_injection_variant_two\n",
        )
        f3 = df.Finding(
            title_line="h3",
            sink_file="src/R.php", sink_line=10,
            sink_kind="dql_concat", root_cause_family="injection",
            enclosing_symbol="R::m",
            sink_snippet="snip",
            category="sql_injection_variant_three",
            raw_body="* **Category**: sql_injection_variant_three\n",
        )
        merged, _ = df.dedupe([f1, f2, f3])
        self.assertEqual(len(merged), 1)
        title_line = df.render_finding(1, merged[0]).splitlines()[0]
        self.assertIn("(+2 more)", title_line)
        self.assertLess(len(title_line), 150)

    def test_render_with_merged_updates_severity_and_confidence(self):
        snippet = "$x = 1;"
        md1 = _mk_finding_md(
            1, "src/R.php", 10, "dql_concat", "injection", "R::m",
            snippet, severity="Medium", confidence=8,
        )
        md2 = _mk_finding_md(
            1, "src/R.php", 10, "dql_concat", "injection", "R::m",
            snippet, severity="Critical", confidence=10,
        )
        p1 = _write_findings(md1, "SECURITY_REVIEW_RESULTS_W1.md")
        p2 = _write_findings(md2, "SECURITY_REVIEW_RESULTS_W2.md")
        findings = df.parse_findings_file(p1) + df.parse_findings_file(p2)
        merged, _manual = df.dedupe(findings)
        self.assertEqual(len(merged), 1)
        report = df.render_finding(1, merged[0])
        self.assertIn("Severity**: Critical", report)
        self.assertIn("Confidence**: 10/10", report)


class ParseFailedFindingTests(unittest.TestCase):
    """Findings without sink_file are not dropped -- they go to manual_review
    with the [PARSE_FAILED] flag."""

    def _mk(self, sink_file: str = "src/X.php", sink_line: int = 10) -> df.Finding:
        return df.Finding(
            title_line="h", severity="High", confidence=9,
            sink_file=sink_file, sink_line=sink_line,
            sink_kind="pii_in_logs", root_cause_family="disclosure",
            enclosing_symbol="X::y",
            sink_snippet="code",
            raw_body="raw",
        )

    def test_empty_sink_file_goes_to_manual_with_parse_failed(self):
        f = self._mk(sink_file="")
        merged, manual = df.dedupe([f])
        self.assertEqual(len(merged), 0)
        self.assertEqual(len(manual), 1)
        self.assertIn(df.FLAG_PARSE_FAILED, manual[0].flags)
        self.assertIn(df.FLAG_NO_FILE, manual[0].flags)

    def test_whitespace_sink_file_goes_to_manual_with_parse_failed(self):
        f = self._mk(sink_file="   ")
        merged, manual = df.dedupe([f])
        self.assertEqual(len(manual), 1)
        self.assertIn(df.FLAG_PARSE_FAILED, manual[0].flags)

    def test_line_zero_alone_tolerated(self):
        """sink_line=0 with a valid sink_file -- keep in main."""
        f = self._mk(sink_file="config/packages/security.yaml", sink_line=0)
        merged, manual = df.dedupe([f])
        parse_failed = [m for m in manual if df.FLAG_PARSE_FAILED in m.flags]
        self.assertEqual(len(parse_failed), 0)
        self.assertEqual(len(merged) + len(manual), 1)

    def test_valid_and_parse_failed_split_correctly(self):
        ok = self._mk(sink_file="src/OK.php", sink_line=5)
        bad = self._mk(sink_file="")
        merged, manual = df.dedupe([ok, bad])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(manual), 1)
        self.assertIn(df.FLAG_PARSE_FAILED, manual[0].flags)


class CrossSinkMergeTests(unittest.TestCase):
    """Pass 3: different workers pick different sink_kind for the same vulnerability."""

    def _mk(self, sink_kind: str, family: str = "crypto",
            severity: str = "High", snippet: str = "code") -> df.Finding:
        return df.Finding(
            title_line="h", severity=severity, confidence=9,
            sink_file="src/Entity/Token.php", sink_line=33,
            sink_kind=sink_kind, root_cause_family=family,
            enclosing_symbol="Token::__construct",
            sink_snippet=snippet,
            raw_body=f"body-{sink_kind}",
        )

    def test_cross_sink_merge_collapses(self):
        f1 = self._mk("hardcoded_secret", snippet="#[ORM\\Column]")
        f2 = self._mk("other:plaintext_oauth_token_at_rest", snippet="#[ORM\\Column]\n    string $token;")
        merged, manual = df.dedupe([f1, f2])
        self.assertEqual(len(merged) + len(manual), 1,
                         f"merged={len(merged)}, manual={len(manual)}")
        target = merged[0] if merged else manual[0]
        self.assertIn(df.FLAG_CROSS_SINK_MERGE, target.flags)
        self.assertTrue(len(target.alternative_sink_kinds) >= 1)

    def test_cross_sink_prefers_well_known_kind(self):
        """When choosing the primary -- prefer a non-other:* sink_kind."""
        f_custom = self._mk("other:plaintext_oauth_token_at_rest",
                            snippet="code_a")
        f_known = self._mk("hardcoded_secret", snippet="code_b")
        merged, _manual = df.dedupe([f_custom, f_known])
        self.assertEqual(len(merged) + len(_manual), 1)
        target = merged[0] if merged else _manual[0]
        self.assertEqual(target.primary.sink_kind, "hardcoded_secret")
        self.assertIn("other:plaintext_oauth_token_at_rest",
                      target.alternative_sink_kinds)

    def test_cross_sink_takes_max_severity(self):
        f_high = self._mk("hardcoded_secret", severity="High", snippet="a")
        f_medium = self._mk("other:secret", severity="Medium", snippet="b")
        merged, manual = df.dedupe([f_high, f_medium])
        target = (merged + manual)[0]
        self.assertEqual(target.severity, "High")

    def test_cross_sink_different_symbol_no_merge(self):
        """Different enclosing_symbol -> no pass3 merge."""
        f1 = self._mk("hardcoded_secret", snippet="a")
        f2 = self._mk("other:x", snippet="b")
        f2.enclosing_symbol = "OtherClass::foo"
        merged, manual = df.dedupe([f1, f2])
        self.assertEqual(len(merged) + len(manual), 2)


class AutoPromoteTests(unittest.TestCase):
    """other:* findings with severity>=High, confidence>=8 and a known symbol
    are promoted to the main list."""

    def _mk(self, severity: str = "Critical", confidence: int = 9,
            symbol: str = "Auth::check", sink_file: str = "src/Auth.php") -> df.Finding:
        return df.Finding(
            title_line="h", severity=severity, confidence=confidence,
            sink_file=sink_file, sink_line=10,
            sink_kind="other:identity_from_unsigned_headers",
            root_cause_family="authz",
            enclosing_symbol=symbol,
            sink_snippet="code",
            raw_body="body",
        )

    def test_critical_with_known_symbol_promoted(self):
        f = self._mk(severity="Critical", confidence=9)
        merged, manual = df.dedupe([f])
        self.assertEqual(len(merged), 1,
                         f"expected Critical other:* to promote, got merged={len(merged)}")
        self.assertEqual(len(manual), 0)
        self.assertIn(df.FLAG_CUSTOM_SINK, merged[0].flags)

    def test_high_with_known_symbol_promoted(self):
        f = self._mk(severity="High", confidence=8)
        merged, manual = df.dedupe([f])
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(manual), 0)

    def test_medium_stays_in_manual(self):
        f = self._mk(severity="Medium", confidence=9)
        merged, manual = df.dedupe([f])
        self.assertEqual(len(merged), 0)
        self.assertEqual(len(manual), 1)

    def test_unknown_symbol_stays_in_manual(self):
        f = self._mk(severity="High", confidence=9, symbol="unknown")
        merged, manual = df.dedupe([f])
        self.assertEqual(len(merged), 0)
        self.assertEqual(len(manual), 1)

    def test_low_confidence_stays_in_manual(self):
        f = self._mk(severity="High", confidence=7)
        merged, manual = df.dedupe([f])
        self.assertEqual(len(merged), 0)
        self.assertEqual(len(manual), 1)


class SplitReportTests(unittest.TestCase):
    """Report is sliced by root_cause_family into separate files + index."""

    def _mk(self, family: str, severity: str = "High",
            sink_file: str = "src/X.php", sink_line: int = 10,
            sink_kind: str = "") -> df.Finding:
        return df.Finding(
            title_line="h", severity=severity, confidence=9,
            sink_file=sink_file, sink_line=sink_line,
            sink_kind=sink_kind or family + "_kind",
            root_cause_family=family,
            enclosing_symbol="X::y",
            sink_snippet=f"code-{family}",
            raw_body=f"body-{family}",
        )

    def test_family_slug_normalization(self):
        self.assertEqual(_family_slug("authz"), "authz")
        self.assertEqual(_family_slug("Authz"), "authz")
        self.assertEqual(_family_slug("business_logic"), "business_logic")
        self.assertEqual(_family_slug(""), "uncategorized")
        self.assertEqual(_family_slug("cross-site scripting"), "cross_site_scripting")

    def test_group_by_family_splits(self):
        f1 = self._mk("authz", sink_file="src/A.php")
        f2 = self._mk("injection", sink_file="src/B.php")
        f3 = self._mk("authz", sink_file="src/C.php")
        merged, _manual = df.dedupe([f1, f2, f3])
        groups = _group_by_family(merged)
        self.assertEqual(set(groups.keys()), {"authz", "injection"})
        self.assertEqual(len(groups["authz"]), 2)
        self.assertEqual(len(groups["injection"]), 1)

    def test_other_prefix_in_family_stripped(self):
        f = self._mk("other:custom_family")
        merged, manual = df.dedupe([f])
        all_f = merged + manual
        if merged:
            groups = _group_by_family(merged)
            self.assertIn("custom_family", groups)

    def test_write_split_report_creates_files(self):
        f1 = self._mk("authz", sink_file="src/A.php")
        f2 = self._mk("injection", sink_file="src/B.php")
        merged, manual = df.dedupe([f1, f2])
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            out = td_path / "SECURITY_REVIEW_RESULTS.md"
            details = td_path / "SECURITY_REVIEW_RESULTS"
            written = df.write_split_report(merged, manual, out, details)
            self.assertTrue(out.exists())
            self.assertTrue((details / "authz.md").exists())
            self.assertTrue((details / "injection.md").exists())
            index = out.read_text(encoding="utf-8")
            self.assertIn("Executive Summary", index)
            self.assertIn("src/A.php:10", index)
            self.assertIn("src/B.php:10", index)
            self.assertIn("authz.md", index)
            self.assertIn("injection.md", index)
            authz_detail = (details / "authz.md").read_text(encoding="utf-8")
            self.assertIn("body-authz", authz_detail)
            self.assertEqual(len(written), 3)

    def test_write_split_report_manual_includes_parse_failed(self):
        """Custom-sink Medium and parse-failed both land in manual_review.md."""
        f_manual = self._mk("authz", severity="Medium",
                            sink_kind="other:experimental")
        f_bad = df.Finding(
            title_line="h", severity="High", confidence=9,
            sink_file="", sink_line=0,
            sink_kind="pii_in_logs", root_cause_family="disclosure",
            enclosing_symbol="X::y",
            sink_snippet="code",
            raw_body="body",
        )
        merged, manual = df.dedupe([f_manual, f_bad])
        self.assertEqual(len(manual), 2)
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            out = td_path / "R.md"
            details = td_path / "R"
            df.write_split_report(merged, manual, out, details)
            self.assertTrue((details / "manual_review.md").exists())
            self.assertFalse((details / "malformed.md").exists(),
                             "malformed.md is no longer generated -- everything in manual_review.md")
            index_text = out.read_text(encoding="utf-8")
            self.assertIn("Manual review: 2 finding", index_text)
            self.assertIn("parse failed: 1", index_text)
            self.assertIn("Action required", index_text)
            mr_text = (details / "manual_review.md").read_text(encoding="utf-8")
            self.assertIn(df.FLAG_PARSE_FAILED, mr_text)


class EndToEndFixtureTests(unittest.TestCase):
    """Fixture of two wave files covering the key dedupe paths together."""

    FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "e2e"

    def _run_dedupe(self) -> tuple[list, list]:
        paths = sorted(self.FIXTURE_DIR.glob("SECURITY_REVIEW_RESULTS_*.md"))
        self.assertGreaterEqual(len(paths), 2, "fixture must have ≥ 2 wave files")
        all_f: list = []
        for p in paths:
            all_f.extend(df.parse_findings_file(p))
        return df.dedupe(all_f)

    def test_counts_match_expected(self):
        main, manual = self._run_dedupe()
        self.assertEqual(len(main), 2,
                         f"main={[m.primary.sink_file for m in main]}")
        self.assertEqual(len(manual), 2,
                         f"manual={[m.primary.sink_file for m in manual]}")
        parse_failed = [m for m in manual if df.FLAG_PARSE_FAILED in m.flags]
        self.assertEqual(len(parse_failed), 1)

    def test_repo_fallback_merge_with_conflict_flags(self):
        main, _ = self._run_dedupe()
        repo = next((m for m in main if "Repo.php" in m.primary.sink_file), None)
        self.assertIsNotNone(repo)
        self.assertEqual(repo.severity, "Critical")
        self.assertEqual(repo.confidence, 10)
        self.assertIn(df.FLAG_MERGED_DESPITE_HASH_MISMATCH, repo.flags)
        self.assertIn(df.FLAG_CONFLICTING_SEVERITY, repo.flags)
        self.assertIn(df.FLAG_CONFIDENCE_DISAGREEMENT, repo.flags)

    def test_token_cross_sink_merge_and_autopromote(self):
        main, _ = self._run_dedupe()
        token = next((m for m in main if "Token.php" in m.primary.sink_file), None)
        self.assertIsNotNone(token, "Token.php:33 must be in main list (auto-promoted)")
        self.assertIn(df.FLAG_CROSS_SINK_MERGE, token.flags)
        self.assertIn(df.FLAG_CUSTOM_SINK, token.flags)
        self.assertEqual(len(token.alternative_sink_kinds), 1)

    def test_low_confidence_custom_sink_stays_manual(self):
        _, manual = self._run_dedupe()
        misc = next((m for m in manual if "Misc.php" in m.primary.sink_file), None)
        self.assertIsNotNone(misc)
        self.assertTrue(misc.primary.sink_kind.startswith("other:"))

    def test_parse_failed_empty_sink_file_goes_to_manual(self):
        main, manual = self._run_dedupe()
        self.assertTrue(all(m.primary.sink_file for m in main))
        parse_failed = [m for m in manual if df.FLAG_PARSE_FAILED in m.flags]
        self.assertEqual(len(parse_failed), 1)
        self.assertEqual(parse_failed[0].primary.sink_file, "")

    def test_category_parsed(self):
        main, _ = self._run_dedupe()
        for mf in main:
            self.assertTrue(
                mf.categories or mf.primary.category,
                f"category empty for {mf.primary.sink_file}:{mf.primary.sink_line}",
            )


class TitleFallbackParsingTests(unittest.TestCase):
    """Fallback: title without :line -- parser extracts the file from backtick content."""

    def test_title_with_file_no_line_extracts_file(self):
        header = "# Vulnerability 5: [Secrets in URL]: `config/api/packages/security.yaml`"
        body = (
            "* **Severity**: Medium\n"
            "* **Confidence**: 8/10\n"
            "* **Category**: Secrets in URL\n"
            "* **sink_kind**: pii_in_logs\n"
            "* **root_cause_family**: disclosure\n"
            "* **enclosing_symbol**: lexik_jwt_authentication config\n"
            "* **sink_snippet**: |\n"
            "    $var_1->getRequestUri()\n"
            "* **Description**: test\n"
        )
        f = _parse_finding_block(header, body)
        self.assertEqual(f.sink_file, "config/api/packages/security.yaml")
        self.assertEqual(f.sink_line, 0)

    def test_title_with_multi_path_extracts_first(self):
        header = "# Vulnerability 5: [x]: `config/api/packages/security.yaml + LogRequestListener`"
        body = "* **Severity**: Medium\n* **sink_kind**: pii_in_logs\n"
        f = _parse_finding_block(header, body)
        self.assertEqual(f.sink_file, "config/api/packages/security.yaml")

    def test_title_with_proper_loc_still_preferred(self):
        header = "# Vulnerability 1: [x]: `src/Foo.php:42`"
        body = "* **Severity**: High\n"
        f = _parse_finding_block(header, body)
        self.assertEqual(f.sink_file, "src/Foo.php")
        self.assertEqual(f.sink_line, 42)

    def test_title_no_backticks_no_file(self):
        header = "# Vulnerability 1: [x]: no backticks"
        body = "* **Severity**: High\n"
        f = _parse_finding_block(header, body)
        self.assertEqual(f.sink_file, "")

    def test_fallback_finding_not_parse_failed(self):
        header = "# Vulnerability 1: [x]: `config/security.yaml`"
        body = (
            "* **Severity**: High\n"
            "* **Confidence**: 9/10\n"
            "* **sink_kind**: missing_authz\n"
            "* **root_cause_family**: authz\n"
            "* **enclosing_symbol**: X::y\n"
            "* **sink_snippet**: |\n"
            "    admin_tokens:\n"
        )
        f = _parse_finding_block(header, body)
        self.assertEqual(f.sink_file, "config/security.yaml")
        merged, manual = df.dedupe([f])
        parse_failed = [m for m in manual if df.FLAG_PARSE_FAILED in m.flags]
        self.assertEqual(len(parse_failed), 0)


class ReflowMarkdownTests(unittest.TestCase):
    """Final .md formatting: reflow must wrap to <=width."""

    def test_short_lines_unchanged(self):
        text = "# Header\n\nShort line.\n\n* **Severity**: Critical\n"
        self.assertEqual(df.reflow_markdown(text, width=100), text)

    def test_wraps_long_prose(self):
        long_line = "This is a very long paragraph " * 20
        out = df.reflow_markdown(long_line, width=80)
        self.assertNotEqual(out, long_line)
        for line in out.splitlines():
            self.assertLessEqual(len(line), 80)

    def test_preserves_fenced_code(self):
        text = (
            "```\n"
            "def f():\n"
            "    x = 'this is a very long string that would otherwise get wrapped by textwrap'\n"
            "```\n"
        )
        self.assertEqual(df.reflow_markdown(text, width=40), text)

    def test_preserves_indented_block_scalar(self):
        text = (
            "* **sink_snippet**: |\n"
            "    $very_long_var = $request->query->get('some_parameter_that_is_long');\n"
        )
        self.assertEqual(df.reflow_markdown(text, width=40), text)

    def test_preserves_table_rows(self):
        text = (
            "| Severity | File:Line | Category |\n"
            "|---|---|---|\n"
            "| Critical | `src/very/long/path/to/controller.php:1234` | `csrf_missing` |\n"
        )
        self.assertEqual(df.reflow_markdown(text, width=40), text)

    def test_wraps_field_line_with_hanging_indent(self):
        long_desc = (
            "* **Description**: OAuth state is missing, an attacker can substitute "
            "the token in the callback and gain access to another CRM via refresh in IntegrationTokenManager."
        )
        out = df.reflow_markdown(long_desc, width=80)
        lines = out.splitlines()
        self.assertGreater(len(lines), 1)
        self.assertTrue(lines[0].startswith("* **Description**:"))
        for cont in lines[1:]:
            self.assertTrue(cont.startswith(" "))
            self.assertFalse(cont.lstrip().startswith(("* ", "- ", "+ ")))
        for line in lines:
            self.assertLessEqual(len(line), 80)

    def test_wraps_numbered_list_with_hanging_indent(self):
        long_item = (
            "  1. Implement a state parameter (random >=128 bit, bound to the "
            "admin session or to a pending flow in the DB with TTL 5-10 min), compare in the callback via hash_equals."
        )
        out = df.reflow_markdown(long_item, width=80)
        lines = out.splitlines()
        self.assertGreater(len(lines), 1)
        self.assertTrue(lines[0].lstrip().startswith("1."))
        for cont in lines[1:]:
            self.assertFalse(cont.lstrip().startswith(("* ", "- ", "+ ")))
            self.assertFalse(re.match(r"^\s*\d+\.", cont))

    def test_preserves_heading_even_if_long(self):
        long_heading = "# " + "X" * 200
        out = df.reflow_markdown(long_heading, width=40)
        self.assertEqual(out, long_heading)

    def test_reflow_applied_in_split_report(self):
        """Regression: confirm that write_split_report applies reflow."""
        f = _parse_finding_block(
            "# Vulnerability 1: [x]: `a.php:1`",
            "* **Severity**: High\n"
            "* **Confidence**: 9/10\n"
            "* **Category**: test_cat\n"
            "* **sink_kind**: native_sql_concat\n"
            "* **root_cause_family**: injection\n"
            "* **enclosing_symbol**: A::m\n"
            "* **sink_snippet**: |\n"
            "    $x = 1;\n"
            "* **Description**: " + ("very long text " * 30) + "\n",
        )
        f.source_file = "W1.md"
        merged, manual = df.dedupe([f])
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            out = td_path / "R.md"
            df.write_split_report(merged, manual, out, td_path / "R")
            detail = (td_path / "R" / "injection.md").read_text(encoding="utf-8")
            for line in detail.splitlines():
                self.assertLessEqual(
                    len(line), df.DEFAULT_WRAP_WIDTH,
                    f"line exceeds DEFAULT_WRAP_WIDTH: {line!r}",
                )


if __name__ == "__main__":
    unittest.main()
