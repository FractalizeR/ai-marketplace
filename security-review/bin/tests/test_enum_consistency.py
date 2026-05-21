"""Contract: prompt-side enum lists in markdown stay byte-aligned with the
Python single source of truth `models.SINK_KIND_TO_FAMILY`.

Files involved:
  - vr/code-review/bin/dedupe/models.py (authoritative)
  - vr/code-review/agents/security.md (operator-visible enum line)
  - vr/code-review/checklists/_meta.md (enum line + mapping table)

If a future PR adds a sink_kind to one place but forgets the others, these
tests fail with a diff that points at the divergent file.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dedupe.models import SINK_KIND_TO_FAMILY  # noqa: E402

# Plugin root: tests/ → bin/ → code-review/.
_PLUGIN_ROOT = Path(__file__).resolve().parents[2]
_SECURITY_MD = _PLUGIN_ROOT / "agents" / "security.md"
_META_MD = _PLUGIN_ROOT / "checklists" / "_meta.md"

# Identifiers in lowercase_underscore form. Used to extract every backticked
# token from a single markdown line.
_IDENT_RE = re.compile(r"`([a-z][a-z0-9_]*)`")

# Mapping table row: `<a>`, `<b>` | `family` (we accept comma-separated kinds
# in the left column to allow future grouping).
_MAPPING_ROW_RE = re.compile(
    r"^\|\s*((?:`[a-z][a-z0-9_]*`(?:\s*,\s*)?)+)\s*\|\s*`([a-z_]+)`\s*\|\s*$",
    re.MULTILINE,
)


def _kinds_from_enum_line(text: str, header: str) -> set[str]:
    """Extract sink_kind identifiers from the line after a header.

    Header lookup is fuzzy: we find a heading that mentions `sink_kind` and
    grab the next paragraph (single physical line). We then collect every
    backticked identifier from that paragraph.
    """
    # Find the closest heading containing `sink_kind` and `enum`.
    heading_re = re.compile(rf"^#{{2,4}}\s+{re.escape(header)}.*$", re.MULTILINE)
    m = heading_re.search(text)
    if not m:
        raise AssertionError(
            f"Heading {header!r} not found in markdown. Sections may have been renamed."
        )
    # Take the body until the next blank-line+heading pair.
    rest = text[m.end():]
    # Strip leading blank lines.
    rest = rest.lstrip("\n")
    # First non-blank "paragraph" — until the next blank line.
    paragraph = rest.split("\n\n", 1)[0]
    return set(_IDENT_RE.findall(paragraph))


_INJECTION_MD = _PLUGIN_ROOT / "checklists" / "core" / "injection.md"
_AUTH_MD = _PLUGIN_ROOT / "checklists" / "core" / "auth.md"
_OUTPUT_RENDER_MD = _PLUGIN_ROOT / "checklists" / "core" / "output-render.md"
_SSRF_FILEOPS_MD = _PLUGIN_ROOT / "checklists" / "core" / "ssrf-fileops.md"
_FINTECH_MD = _PLUGIN_ROOT / "checklists" / "core" / "fintech.md"


class EnumConsistencyContract(unittest.TestCase):
    """Markdown lists of sink_kind must equal the Python enum exactly."""

    def test_security_md_lists_all_kinds_from_python(self):
        text = _SECURITY_MD.read_text(encoding="utf-8")
        kinds = _kinds_from_enum_line(text, "Closed enum `sink_kind`")
        py_kinds = set(SINK_KIND_TO_FAMILY.keys())
        missing = py_kinds - kinds
        extra = kinds - py_kinds
        self.assertFalse(
            missing or extra,
            f"agents/security.md sink_kind enum out of sync.\n"
            f"  In Python but missing in security.md: {sorted(missing)}\n"
            f"  In security.md but missing in Python: {sorted(extra)}",
        )

    def test_meta_md_lists_all_kinds_from_python(self):
        text = _META_MD.read_text(encoding="utf-8")
        # The meta file has an enum block introduced by "`sink_kind` enum values:"
        # -- capture the next paragraph after that line.
        marker_re = re.compile(r"`sink_kind` enum values:\s*\n", re.MULTILINE)
        m = marker_re.search(text)
        self.assertIsNotNone(
            m, "checklists/_meta.md does not contain the enum marker line"
        )
        rest = text[m.end():]
        paragraph = rest.split("\n\n", 1)[0]
        kinds = set(_IDENT_RE.findall(paragraph))
        py_kinds = set(SINK_KIND_TO_FAMILY.keys())
        missing = py_kinds - kinds
        extra = kinds - py_kinds
        self.assertFalse(
            missing or extra,
            f"checklists/_meta.md sink_kind enum out of sync.\n"
            f"  In Python but missing in _meta.md: {sorted(missing)}\n"
            f"  In _meta.md but missing in Python: {sorted(extra)}",
        )

    def test_meta_md_mapping_matches_python(self):
        """The `sink_kind | root_cause_family` table in _meta.md must reproduce
        every (kind, family) pair from `SINK_KIND_TO_FAMILY`."""
        text = _META_MD.read_text(encoding="utf-8")
        markdown_pairs: dict[str, str] = {}
        for row in _MAPPING_ROW_RE.finditer(text):
            kinds_chunk, family = row.group(1), row.group(2)
            for k in _IDENT_RE.findall(kinds_chunk):
                markdown_pairs[k] = family
        # Compare the dicts directly.
        self.assertEqual(
            markdown_pairs,
            SINK_KIND_TO_FAMILY,
            "Mapping table in checklists/_meta.md does not match SINK_KIND_TO_FAMILY.\n"
            f"  Markdown: {sorted(markdown_pairs.items())}\n"
            f"  Python:   {sorted(SINK_KIND_TO_FAMILY.items())}",
        )


class Stage6InjectionSubKinds(unittest.TestCase):
    """Stage 6 — three new injection sub-kinds wired into the enum and core checklist."""

    def test_ldap_xpath_nosql_families_registered(self):
        """The three new sink_kinds are present in SINK_KIND_TO_FAMILY with family=injection."""
        for kind in ("ldap_injection", "xpath_injection", "nosql_injection"):
            self.assertIn(
                kind,
                SINK_KIND_TO_FAMILY,
                f"{kind!r} missing from SINK_KIND_TO_FAMILY (Python source of truth)",
            )
            self.assertEqual(
                SINK_KIND_TO_FAMILY[kind],
                "injection",
                f"{kind!r} should belong to the `injection` family",
            )

    def test_total_sink_kind_count(self):
        """Total sink_kind count after Stage 6 should be 41 (38 + 3)."""
        self.assertEqual(
            len(SINK_KIND_TO_FAMILY),
            41,
            "Total sink_kind count drifted; update this test alongside the enum.",
        )

    def test_injection_md_lists_new_sub_kinds_under_recommended(self):
        """checklists/core/injection.md must declare the 3 new sink_kinds in
        its `## Recommended sink_kinds` section."""
        text = _INJECTION_MD.read_text(encoding="utf-8")
        # Capture the body of the `## Recommended sink_kinds` section until the next H2.
        m = re.search(
            r"^##\s+Recommended sink_kinds\s*$(.*?)^##\s+",
            text,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(
            m, "`## Recommended sink_kinds` section missing in core/injection.md"
        )
        body = m.group(1)
        for kind in ("ldap_injection", "xpath_injection", "nosql_injection"):
            self.assertIn(
                f"`{kind}`",
                body,
                f"core/injection.md `## Recommended sink_kinds` must mention `{kind}` "
                "so workers know the new sub-kind is in scope for this checklist.",
            )


def _trusted_patterns_section(text: str) -> str:
    """Extract the body of the `## Trusted patterns (do NOT flag)` section from
    a checklist markdown text. Returns the body up to the next H2 heading (or
    end-of-file). Empty string if the section is absent."""
    m = re.search(
        r"^##\s+Trusted patterns \(do NOT flag\)\s*$(.*?)(?=^##\s+|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    return m.group(1) if m else ""


class Stage6TrustedPatternsConvention(unittest.TestCase):
    """Stage 6 — `## Trusted patterns (do NOT flag)` convention is documented in
    `_meta.md` and seeded in three core checklists (auth, output-render, injection)."""

    def test_meta_md_documents_trusted_patterns_convention(self):
        text = _META_MD.read_text(encoding="utf-8")
        self.assertIn(
            "Trusted patterns (do NOT flag)",
            text,
            "_meta.md must document the optional `## Trusted patterns (do NOT flag)` "
            "section convention so checklists can opt in consistently.",
        )

    def test_core_auth_seeds_trusted_patterns(self):
        text = _AUTH_MD.read_text(encoding="utf-8")
        self.assertIn(
            "## Trusted patterns (do NOT flag)",
            text,
            "core/auth.md must seed `## Trusted patterns (do NOT flag)` "
            "(CSPRNG wrappers, hash_equals, password_hash).",
        )
        section = _trusted_patterns_section(text)
        self.assertIn(
            "random_bytes",
            section,
            "core/auth.md `## Trusted patterns` section must list `random_bytes` "
            "as the canonical CSPRNG primitive.",
        )

    def test_core_output_render_seeds_trusted_patterns(self):
        text = _OUTPUT_RENDER_MD.read_text(encoding="utf-8")
        self.assertIn(
            "## Trusted patterns (do NOT flag)",
            text,
            "core/output-render.md must seed `## Trusted patterns (do NOT flag)` "
            "(Twig/Blade/React/Vue auto-escape).",
        )
        section = _trusted_patterns_section(text)
        self.assertIn(
            "autoescape",
            section,
            "core/output-render.md `## Trusted patterns` section must reference "
            "`autoescape` (Twig/Blade auto-escape) as the canonical safe-by-construction "
            "primitive.",
        )

    def test_core_injection_seeds_trusted_patterns(self):
        text = _INJECTION_MD.read_text(encoding="utf-8")
        self.assertIn(
            "## Trusted patterns (do NOT flag)",
            text,
            "core/injection.md must seed `## Trusted patterns (do NOT flag)` "
            "(Doctrine/Eloquent scalar binding, PDO prepared statements).",
        )
        section = _trusted_patterns_section(text)
        self.assertIn(
            "findOneBy",
            section,
            "core/injection.md `## Trusted patterns` section must list Doctrine "
            "`findOneBy` as the canonical scalar-binding safe pattern.",
        )


class Stage6ConfidenceCaps(unittest.TestCase):
    """Stage 6 — new confidence caps for path-only SSRF/redirect_open and
    qualified race_condition floor."""

    def test_ssrf_fileops_documents_path_only_caps(self):
        text = _SSRF_FILEOPS_MD.read_text(encoding="utf-8")
        # Both redirect_open and ssrf must reference the path-only / max confidence cap.
        self.assertIn(
            "max confidence 5",
            text,
            "core/ssrf-fileops.md must declare the path-only confidence cap "
            "(max confidence 5) for `redirect_open` and `ssrf`.",
        )
        self.assertIn(
            "path-only control",
            text,
            "core/ssrf-fileops.md must explicitly describe the 'path-only control' "
            "trigger for the confidence cap.",
        )

    def test_fintech_documents_race_condition_qualification(self):
        text = _FINTECH_MD.read_text(encoding="utf-8")
        self.assertIn(
            "race_condition",
            text,
            "core/fintech.md must keep `race_condition` in scope.",
        )
        # The qualified floor and the read-side cap must both be present.
        self.assertIn(
            "concrete state mutation",
            text,
            "core/fintech.md must qualify the `race_condition` floor as requiring "
            "concrete state mutation (TOCTOU on file/account/balance/inventory).",
        )
        self.assertIn(
            "max confidence 4",
            text,
            "core/fintech.md must declare the read-side stale-cache cap "
            "(max confidence 4) for race_condition.",
        )


if __name__ == "__main__":
    unittest.main()
