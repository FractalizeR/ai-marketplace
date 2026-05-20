"""Deduplicate security findings across SECURITY_REVIEW_RESULTS_*.md files.

Public API re-exported here for convenience. CLI entry point is
bin/dedupe_findings.py (invoked as a standalone script).

Internal helpers (_parse_finding_block, _normalize_symbol, _family_slug,
_group_by_family) are accessible via direct submodule imports
(e.g. `from dedupe.parser import _parse_finding_block`).
"""

from .models import (
    FLAG_CONFIDENCE_DISAGREEMENT,
    FLAG_CONFLICTING_SEVERITY,
    FLAG_CROSS_SINK_MERGE,
    FLAG_CUSTOM_SINK,
    FLAG_MERGED_BY_FILE_LINE,
    FLAG_MERGED_DESPITE_HASH_MISMATCH,
    FLAG_MERGED_WITHOUT_SYMBOL,
    FLAG_NO_FILE,
    FLAG_PARSE_FAILED,
    FLAG_REFUTE_CLAIMED,
    KNOWN_ROOT_CAUSE_FAMILIES,
    KNOWN_SINK_KINDS,
    SEVERITY_BY_RANK,
    SEVERITY_RANK,
    SINK_KIND_TO_FAMILY,
    Finding,
    MergedFinding,
)
from .parser import parse_findings_file
from .pipeline import dedupe
from .refute import (
    RefuteInvalid,
    RefuteRecord,
    apply_refute_records,
    parse_refute_md,
    validate_refute_evidence,
    write_refute_invalid_md,
)
from .reflow import (
    DEFAULT_WRAP_WIDTH,
    reflow_markdown,
)
from .renderer import (
    render_finding,
    render_report,
    write_split_report,
)

__all__ = [
    # Models & constants
    "Finding",
    "MergedFinding",
    "SEVERITY_RANK",
    "SEVERITY_BY_RANK",
    "SINK_KIND_TO_FAMILY",
    "KNOWN_SINK_KINDS",
    "KNOWN_ROOT_CAUSE_FAMILIES",
    "FLAG_PARSE_FAILED",
    "FLAG_NO_FILE",
    "FLAG_CUSTOM_SINK",
    "FLAG_MERGED_BY_FILE_LINE",
    "FLAG_MERGED_WITHOUT_SYMBOL",
    "FLAG_MERGED_DESPITE_HASH_MISMATCH",
    "FLAG_CROSS_SINK_MERGE",
    "FLAG_CONFLICTING_SEVERITY",
    "FLAG_CONFIDENCE_DISAGREEMENT",
    "FLAG_REFUTE_CLAIMED",
    # Parser
    "parse_findings_file",
    # Pipeline
    "dedupe",
    # Refute
    "RefuteRecord",
    "RefuteInvalid",
    "parse_refute_md",
    "validate_refute_evidence",
    "apply_refute_records",
    "write_refute_invalid_md",
    # Renderer
    "render_finding",
    "render_report",
    "write_split_report",
    # Reflow
    "reflow_markdown",
    "DEFAULT_WRAP_WIDTH",
]
