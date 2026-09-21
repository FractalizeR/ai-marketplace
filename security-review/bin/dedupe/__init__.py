"""Deduplicate security findings across SECURITY_REVIEW_RESULTS_*.md files.

Public API re-exported here for convenience. CLI entry point is
bin/dedupe_findings.py (invoked as a standalone script).

Internal helpers (_parse_finding_block, _normalize_symbol, _family_slug,
_group_by_family) are accessible via direct submodule imports
(e.g. `from dedupe.parser import _parse_finding_block`).
"""

from .models import (
    CONDITION_KEYS,
    FLAG_CONFIDENCE_DISAGREEMENT,
    FLAG_CONFLICTING_SEVERITY,
    FLAG_CROSS_SINK_MERGE,
    FLAG_CUSTOM_SINK,
    FLAG_MERGED_BY_FILE_LINE,
    FLAG_MERGED_DESPITE_HASH_MISMATCH,
    FLAG_MERGED_WITHOUT_SYMBOL,
    FLAG_NO_FILE,
    FLAG_NV_INCOMPLETE,
    FLAG_PARSE_FAILED,
    FLAG_REFUTE_CLAIMED,
    FLAG_VERDICT_HAS_SEVERITY,
    KNOWN_ROOT_CAUSE_FAMILIES,
    KNOWN_SINK_KINDS,
    SEVERITY_BY_RANK,
    SEVERITY_RANK,
    SINK_KIND_TO_FAMILY,
    Finding,
    HardeningNote,
    MergedFinding,
    NeedsValidation,
    ParsedWave,
    SideRecords,
)
from .export import (
    FINDINGS_JSON_NAME,
    SCHEMA_VERSION,
    build_findings_export,
    write_findings_json,
)
from .parser import WaveFormatError, parse_findings_file, parse_wave
from .pipeline import attach_side_records, dedupe
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
    "NeedsValidation",
    "HardeningNote",
    "ParsedWave",
    "SideRecords",
    "CONDITION_KEYS",
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
    "FLAG_VERDICT_HAS_SEVERITY",
    "FLAG_NV_INCOMPLETE",
    # Parser
    "parse_findings_file",
    "parse_wave",
    "WaveFormatError",
    # Pipeline
    "dedupe",
    "attach_side_records",
    # Export
    "SCHEMA_VERSION",
    "FINDINGS_JSON_NAME",
    "build_findings_export",
    "write_findings_json",
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
