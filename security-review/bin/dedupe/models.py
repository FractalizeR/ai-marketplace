"""Data models and constants for the dedupe pipeline.

Defines Finding, MergedFinding dataclasses, severity ranks, and flag constants.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Literal

# ---------------------------------------------------------------------------
# Snippet normalization for stable sink_hash.
#
# Workers normalize sink_snippet per prompt rules in agents/security.md, which
# include obfuscating local variable names as `$var_<N>` (sequential top-down).
# This numbering is non-deterministic across slices: the same real variable
# (e.g. `$accessToken`) can become `$var_1` in one slice and `$var_3` in
# another, depending on what other variables appear in the worker's 5-line
# window. That causes identical findings to receive different sink_hash
# values, forcing dedupe into the heuristic [MERGED_DESPITE_HASH_MISMATCH]
# fallback (observed 4× in event run).
#
# We collapse all `$var_<digits>` placeholders to a single literal `$VAR`
# before hashing — only when the snippet actually contains such placeholders.
# Real PHP code rarely names variables `$var_1`, but if it does, the collapse
# only affects the hash, not the displayed snippet, and any two snippets that
# would already be considered identical by content remain so.
# ---------------------------------------------------------------------------

_VAR_PLACEHOLDER_RE = re.compile(r"\$var_\d+")


def _normalize_snippet_for_hash(snippet: str) -> str:
    """Collapse worker-emitted `$var_<N>` placeholders to a stable `$VAR`.

    No-op when the snippet has no `$var_<N>` token, so snippets that workers
    chose not to obfuscate (or that come from non-LLM sources) are unaffected.
    """
    if not _VAR_PLACEHOLDER_RE.search(snippet):
        return snippet
    return _VAR_PLACEHOLDER_RE.sub("$VAR", snippet)


def _sink_hash_from_snippet(snippet: str) -> str:
    """sha256(normalized snippet)[:8] — the single sink-identity computation
    shared by `Finding`, `NeedsValidation` and `HardeningNote`.

    `sink_hash` is a `@property` on all three, never a stored field: a field
    would be a second source of truth for identity (E6 probe finding).
    """
    if not snippet:
        return "nohash00"
    normalized = _normalize_snippet_for_hash(snippet)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:8]

# ---------------------------------------------------------------------------
# Severity.
# ---------------------------------------------------------------------------

SEVERITY_RANK = {"Medium": 1, "High": 2, "Critical": 3}
SEVERITY_BY_RANK = {v: k for k, v in SEVERITY_RANK.items()}

# ---------------------------------------------------------------------------
# Flag constants — single source of truth for all flag strings.
# ---------------------------------------------------------------------------

FLAG_PARSE_FAILED = "[PARSE_FAILED]"
FLAG_NO_FILE = "[NO_FILE]"
FLAG_CUSTOM_SINK = "[CUSTOM_SINK]"
FLAG_MERGED_BY_FILE_LINE = "[MERGED_BY_FILE_LINE]"
FLAG_MERGED_WITHOUT_SYMBOL = "[MERGED_WITHOUT_SYMBOL]"
FLAG_MERGED_DESPITE_HASH_MISMATCH = "[MERGED_DESPITE_HASH_MISMATCH]"
FLAG_CROSS_SINK_MERGE = "[CROSS_SINK_MERGE]"
FLAG_CONFLICTING_SEVERITY = "[CONFLICTING SEVERITY]"
FLAG_CONFIDENCE_DISAGREEMENT = "[CONFIDENCE DISAGREEMENT]"
FLAG_REFUTE_CLAIMED = "[REFUTE_CLAIMED]"

# Verdict-bucket parsing flags (Stage 2 / P2.1) — set directly on
# `NeedsValidation`/`HardeningNote` by the parser, since these types have no
# `Merged*` wrapper of their own (unlike `Finding` -> `MergedFinding`).
FLAG_VERDICT_HAS_SEVERITY = "[VERDICT_HAS_SEVERITY]"   # worker put Severity/Confidence on a bucket record; dropped
FLAG_NV_INCOMPLETE = "[NV_INCOMPLETE]"                  # needs_validation missing blockers and/or a validation plan


# ---------------------------------------------------------------------------
# Wave output format versioning.
#
# `<!-- wave_format: N -->` must be the first non-empty line of a worker's
# wave file. Absent -> legacy (pre-Stage-2) single-type parsing. Present with
# a version this build does not know -> loud refusal, not a silent partial
# parse (see `parser.WaveFormatError`).
# ---------------------------------------------------------------------------

WAVE_FORMAT_VERSION = 2


# ---------------------------------------------------------------------------
# Worker verdict / resolution verdict (Stage 2 — verdict buckets).
# ---------------------------------------------------------------------------

WORKER_VERDICT = Literal["confirmed", "needs_validation", "hardening"]
RESOLUTION_VERDICT = Literal["rejected", "reaffirmed"]


# ---------------------------------------------------------------------------
# Closed enum: condition_keys.
#
# Same three-way sync discipline as SINK_KIND_TO_FAMILY: this dict/frozenset
# is mirrored in agents/security.md and checklists/_meta.md.
# `test_enum_consistency.py` verifies alignment. Escape hatch `other:<name>`,
# same convention as `sink_kind`.
# ---------------------------------------------------------------------------

CONDITION_KEYS: frozenset[str] = frozenset(
    {
        "internal_network_only",
        "admin_only",
        "needs_trusted_integration_compromise",
        "needs_separate_primitive",
        "deployment_control_not_in_source",
        "requires_victim_interaction",
        "requires_attacker_owned_account",
    }
)


# ---------------------------------------------------------------------------
# Closed enum: sink_kind → root_cause_family.
#
# Single source of truth for both Python pipeline (parser validation, dedup
# bucketing) and prompt-side enums in agents/security.md + checklists/_meta.md.
# `test_enum_consistency.py` parses both markdown files and verifies the lists
# are byte-for-byte the same set of identifiers as `SINK_KIND_TO_FAMILY`.
#
# Adding a new sink_kind: extend this dict, mirror the value in agents/security.md
# (closed enum line) and checklists/_meta.md (enum line + mapping table).
# Removing one: same drill, but check `pipeline.KNOWN_OTHER_KINDS` doesn't still
# canonicalise into it.
# ---------------------------------------------------------------------------

SINK_KIND_TO_FAMILY: dict[str, str] = {
    # Injection family.
    "dql_concat": "injection",
    "native_sql_concat": "injection",
    "command_exec": "injection",
    "file_include_dynamic": "injection",
    "path_traversal": "injection",
    "ldap_injection": "injection",
    "xpath_injection": "injection",
    "nosql_injection": "injection",
    # XSS family.
    "unsafe_html_render": "xss",
    "template_raw": "xss",
    "ssti": "xss",
    # Deserialization.
    "unserialize_untrusted": "deserialization",
    # Authz.
    "missing_authz": "authz",
    "idor_lookup": "authz",
    "mass_assignment": "authz",
    "csrf_missing": "authz",
    "cors_misconfig": "authz",
    "oauth_state_missing": "authz",
    "oidc_misconfig": "authz",
    # Crypto.
    "weak_hash": "crypto",
    "hardcoded_secret": "crypto",
    "weak_random": "crypto",
    "jwks_spoof": "crypto",
    "tls_validation_bypass": "crypto",
    # Disclosure.
    "pii_in_logs": "disclosure",
    "stacktrace_exposed": "disclosure",
    "secret_in_response": "disclosure",
    "sensitive_field_unmasked": "disclosure",
    # SSRF.
    "xxe": "ssrf",
    "ssrf": "ssrf",
    # Webhook.
    "webhook_unverified": "webhook",
    "webhook_replay": "webhook",
    # Business logic.
    "redirect_open": "business_logic",
    "decimal_arith": "business_logic",
    "race_condition": "business_logic",
    "type_juggling": "business_logic",
    # Security response headers (3.5.0).
    "csp_missing": "xss",
    "csp_unsafe_inline": "xss",
    "clickjacking_unprotected": "clickjacking",
    "hsts_missing": "crypto",
    "mime_sniff_unprotected": "xss",
}

KNOWN_SINK_KINDS: frozenset[str] = frozenset(SINK_KIND_TO_FAMILY)
KNOWN_ROOT_CAUSE_FAMILIES: frozenset[str] = frozenset(SINK_KIND_TO_FAMILY.values())


# ---------------------------------------------------------------------------
# Finding model.
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    title_line: str           # original `# Vulnerability ...` header
    sink_file: str = ""
    sink_line: int = 0
    severity: str = "Medium"
    confidence: int = 8
    category: str = ""
    sink_kind: str = ""
    root_cause_family: str = ""
    enclosing_symbol: str = "unknown"
    sink_snippet: str = ""
    description: str = ""
    data_path: str = ""
    exploit: str = ""
    impact: str = ""
    recommendation: str = ""
    discovered_via: str = ""
    raw_body: str = ""        # original markdown body for replaying
    source_file: str = ""     # which SECURITY_REVIEW_RESULTS_*.md did this come from
    slice_id: str = ""
    condition_keys: list[str] = field(default_factory=list)

    @property
    def sink_hash(self) -> str:
        """sha256(normalized sink_snippet)[:8].

        See `_normalize_snippet_for_hash` — `$var_<N>` placeholders emitted
        by LLM workers are collapsed before hashing to neutralize the
        non-deterministic numbering across slices.
        """
        return _sink_hash_from_snippet(self.sink_snippet)

    @property
    def dedup_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.sink_file,
            self.sink_kind,
            self.root_cause_family,
            self.enclosing_symbol,
            self.sink_hash,
        )

    @property
    def is_custom_sink(self) -> bool:
        if self.sink_kind.startswith("other:") or self.root_cause_family.startswith("other:"):
            return True
        # Unknown sink_kind (typo or unmapped value) is treated as custom too:
        # otherwise a typo like `weakrandom` would silently bucket as a normal
        # finding and bypass `[CUSTOM_SINK]` flag + manual_review fallback.
        # Empty sink_kind is allowed (worker may legitimately omit it for
        # malformed payloads — `_is_malformed` handles those separately).
        if self.sink_kind and self.sink_kind not in KNOWN_SINK_KINDS:
            return True
        return False

    @property
    def is_unknown_symbol(self) -> bool:
        return self.enclosing_symbol == "unknown" or not self.enclosing_symbol


@dataclass
class MergedFinding:
    primary: Finding
    merged_from: list[Finding] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    related: list[str] = field(default_factory=list)   # references by stable ID
    alternative_sink_kinds: list[str] = field(default_factory=list)
    alternative_root_cause_families: list[str] = field(default_factory=list)
    # Adversarial refute pass annotations (filled by `dedupe.refute` when
    # `--refute=<path>` is supplied). Empty by default. See agents/security-refute.md
    # and bin/dedupe/refute.py for the contract.
    refute_rationale: str = ""
    refute_confidence: int = 0
    refute_file: str = ""
    refute_line: int = 0

    @property
    def severity(self) -> str:
        all_sev = [self.primary.severity] + [f.severity for f in self.merged_from]
        rank = max(SEVERITY_RANK[s] for s in all_sev)
        return SEVERITY_BY_RANK[rank]

    @property
    def confidence(self) -> int:
        all_conf = [self.primary.confidence] + [f.confidence for f in self.merged_from]
        return max(all_conf)

    @property
    def categories(self) -> list[str]:
        seen = []
        for c in [self.primary.category] + [f.category for f in self.merged_from]:
            if c and c not in seen:
                seen.append(c)
        return seen

    @property
    def slice_ids(self) -> list[str]:
        seen = []
        for s in [self.primary.slice_id] + [f.slice_id for f in self.merged_from]:
            if s and s not in seen:
                seen.append(s)
        return seen


# ---------------------------------------------------------------------------
# Verdict buckets (Stage 2): `needs_validation` and `hardening`.
#
# Both are mutable (NOT frozen) like `Finding` — see the E6 probe:
# `pipeline._normalize_known_other_kinds` mutates `sink_kind`/`root_cause_family`
# in place on `other:*` records, which would raise `FrozenInstanceError` on a
# frozen dataclass; and `frozen=True` combined with list fields would also
# break `__hash__` (`TypeError: unhashable type: 'list'`).
#
# Neither carries `severity`/`confidence` — that is deliberate, not an
# oversight: these buckets are explicitly barred from having a severity
# (Stage 2 decision). `sink_hash` is a `@property`, never a field, for the
# same reason as `Finding.sink_hash` (single source of truth for identity).
# Both carry the same six location fields as `Finding.dedup_key` inputs, so
# `attach_side_records` (P2.2) can index them by `sink_hash` alongside
# `Finding`/`MergedFinding` without a shared base class.
# ---------------------------------------------------------------------------


@dataclass
class NeedsValidation:
    sink_file: str = ""
    sink_line: int = 0
    sink_kind: str = ""
    enclosing_symbol: str = "unknown"
    sink_snippet: str = ""
    root_cause_family: str = ""
    claimed_root_cause: str = ""
    trace: str = ""
    blockers: list[str] = field(default_factory=list)
    validation_plan_local: str | None = None
    validation_plan_deployment: str | None = None
    condition_keys: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    raw_body: str = ""
    source_file: str = ""
    slice_id: str = ""

    @property
    def sink_hash(self) -> str:
        return _sink_hash_from_snippet(self.sink_snippet)


@dataclass
class HardeningNote:
    sink_file: str = ""
    sink_line: int = 0
    sink_kind: str = ""
    enclosing_symbol: str = "unknown"
    sink_snippet: str = ""
    root_cause_family: str = ""
    text: str = ""
    condition_keys: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    raw_body: str = ""
    source_file: str = ""
    slice_id: str = ""

    @property
    def sink_hash(self) -> str:
        return _sink_hash_from_snippet(self.sink_snippet)


@dataclass
class ParsedWave:
    """Return type of `parser.parse_wave` — the three block types a single
    wave file can now contain, kept apart (never merged into one list) so a
    caller can treat `confirmed` findings exactly as before Stage 2."""

    findings: list[Finding] = field(default_factory=list)
    needs_validation: list[NeedsValidation] = field(default_factory=list)
    hardening: list[HardeningNote] = field(default_factory=list)
