"""Three-pass deduplication pipeline for security findings.

Pass 0: format validation (malformed → manual review).
Pass 1: strict merge by primary key (includes sink_hash).
Pass 2: fallback merge (drops sink_hash, flags [MERGED_DESPITE_HASH_MISMATCH]).
Pass 3: cross-sink merge (same location, different sink_kind).

Pre-pass: normalize known custom sink kinds (other:*) into canonical kinds.
"""

from __future__ import annotations

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
    SEVERITY_RANK,
    Finding,
    MergedFinding,
)


# ---------------------------------------------------------------------------
# Known custom sink taxonomy.
#
# Worker prompts allow free-form `sink_kind: other:<label>` for unanticipated
# patterns. Those flow into manual_review by default (no auto-promote unless
# severity>=High). When a free-form kind keeps reappearing across projects,
# it earns a canonical mapping here — so it joins the standard kind family,
# gets cross-merged with peers, and lands in the right per-family detail file.
#
# How to extend: when a real run surfaces an `other:*` kind that's actually a
# typical pattern (admin UI exposing tokens, plaintext credentials at rest,
# etc.) — add it below with the canonical (kind, root_cause_family) pair.
# Run dedupe again to confirm the finding now appears in the family file.
# ---------------------------------------------------------------------------

KNOWN_OTHER_KINDS: dict[str, tuple[str, str]] = {
    # Admin UI exposes sensitive fields (OAuth tokens, secrets, API keys) as
    # plain TextField without masking. Pattern: EasyAdmin/Sonata
    # CrudController::configureFields() returns TextField('accessToken'|...).
    "other:tokens_visible_in_ui": ("sensitive_field_unmasked", "disclosure"),
    "other:oauth_tokens_in_admin_ui": ("sensitive_field_unmasked", "disclosure"),
    "other:secrets_visible_in_admin_ui": ("sensitive_field_unmasked", "disclosure"),
    # Plaintext OAuth credentials at rest (DB, JSON config column).
    # Already handled by hardcoded_secret/crypto, but workers sometimes invent
    # a custom kind for this — normalise to the canonical pair.
    "other:plaintext_oauth_tokens": ("hardcoded_secret", "crypto"),
    "other:oauth_tokens_plaintext_at_rest": ("hardcoded_secret", "crypto"),
    "other:plaintext_credentials_at_rest": ("hardcoded_secret", "crypto"),
}


def _normalize_known_other_kinds(findings: list[Finding]) -> None:
    """Rewrite `other:*` kinds with canonical (kind, family) pairs in-place.

    Enables custom kinds that recur across projects to drop the CUSTOM_SINK
    flag, merge with regular findings, and land in per-family detail files
    instead of manual_review.md.
    """
    for f in findings:
        canonical = KNOWN_OTHER_KINDS.get(f.sink_kind)
        if canonical is None:
            continue
        new_kind, new_family = canonical
        f.sink_kind = new_kind
        # Only overwrite family if it was empty or also custom — preserve
        # an explicit standard family the worker may have already set.
        if not f.root_cause_family or f.root_cause_family.startswith("other:"):
            f.root_cause_family = new_family


# ---------------------------------------------------------------------------
# Symbol normalization.
# ---------------------------------------------------------------------------


def _normalize_symbol(raw: str) -> str:
    """Normalise enclosing_symbol to canonical form for dedup.

    Strips backticks/whitespace, drops leading namespace components so
    `App\\Crm\\Log\\Listener::onRequest` and `Listener::onRequest`
    collapse to the same key.
    """
    if not raw:
        return "unknown"
    s = raw.strip().strip("`").strip()
    if not s or s.lower() == "unknown":
        return "unknown"
    if "(" in s:
        s = s.split("(", 1)[0].strip()
    if "::" in s:
        cls, _, method = s.rpartition("::")
        cls = cls.rsplit("\\", 1)[-1]
        return f"{cls}::{method}"
    return s.rsplit("\\", 1)[-1]


# ---------------------------------------------------------------------------
# Bucketing.
# ---------------------------------------------------------------------------


def _dedup_bucket(f: Finding) -> tuple[str, tuple, tuple]:
    """Classify finding into a dedup strategy.

    Returns (strategy, primary_key, fallback_key).
    """
    if f.is_custom_sink:
        bucket = f.sink_line // 5 if f.sink_line else 0
        key = (f.sink_file, bucket, f.category, "CUSTOM_SINK")
        return "custom_sink", key, key

    has_hash = bool(f.sink_snippet) and f.sink_hash != "nohash00"
    norm_symbol = _normalize_symbol(f.enclosing_symbol)

    if f.is_unknown_symbol:
        primary = (
            f.sink_file, f.sink_kind, f.root_cause_family,
            f.sink_hash if has_hash else f"line_bucket_{f.sink_line // 5}",
        )
        fallback = (
            f.sink_file, f.sink_kind, f.root_cause_family,
            f"line_bucket_{f.sink_line // 5}",
        )
        return "unknown_symbol", primary, fallback

    primary = (f.sink_file, f.sink_kind, f.root_cause_family, norm_symbol, f.sink_hash)
    fallback = (f.sink_file, f.sink_kind, f.root_cause_family, norm_symbol)
    return "primary", primary, fallback


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _is_malformed(f: Finding) -> bool:
    """Finding too broken to be actionable: no sink_file."""
    return not f.sink_file.strip()


def _pick_primary(group: list[Finding]) -> Finding:
    """Pick the finding with the richest body as primary."""
    return max(group, key=lambda f: (f.confidence, len(f.raw_body or "")))


def _add_flag(mf: MergedFinding, flag: str) -> None:
    """Append flag if not already present (idempotent)."""
    if flag not in mf.flags:
        mf.flags.append(flag)


def _check_conflict_flags(mf: MergedFinding) -> None:
    """Evaluate and attach severity/confidence conflict flags. Idempotent."""
    all_items = [mf.primary] + mf.merged_from
    sev_ranks = [SEVERITY_RANK[x.severity] for x in all_items]
    if max(sev_ranks) - min(sev_ranks) >= 2:
        _add_flag(mf, FLAG_CONFLICTING_SEVERITY)
    confs = [x.confidence for x in all_items]
    if max(confs) - min(confs) >= 2:
        _add_flag(mf, FLAG_CONFIDENCE_DISAGREEMENT)


def _attach_flags(mf: MergedFinding, strategy: str) -> None:
    """Add strategy-specific and conflict flags to a merged finding."""
    if strategy == "unknown_symbol":
        _add_flag(mf, FLAG_MERGED_WITHOUT_SYMBOL)
    elif strategy == "custom_sink":
        _add_flag(mf, FLAG_CUSTOM_SINK)
        all_items = [mf.primary] + mf.merged_from
        if len(all_items) > 1:
            _add_flag(mf, FLAG_MERGED_BY_FILE_LINE)
    _check_conflict_flags(mf)


def _is_custom_sink_finding(mf: MergedFinding) -> bool:
    return FLAG_CUSTOM_SINK in mf.flags or mf.primary.is_custom_sink


def _should_promote_custom_sink(mf: MergedFinding) -> bool:
    """Auto-promote other:* finding to main list if actionable.

    Criteria: severity >= High AND confidence >= 8 AND enclosing_symbol
    is known AND sink_file is set.
    """
    if SEVERITY_RANK.get(mf.severity, 0) < SEVERITY_RANK["High"]:
        return False
    if mf.confidence < 8:
        return False
    if mf.primary.is_unknown_symbol:
        return False
    if not mf.primary.sink_file.strip():
        return False
    return True


# ---------------------------------------------------------------------------
# Cross-reference.
# ---------------------------------------------------------------------------


def _build_cross_references(merged: list[MergedFinding]) -> None:
    by_loc: dict[tuple[str, str], list[MergedFinding]] = {}
    for mf in merged:
        key = (mf.primary.sink_file, mf.primary.enclosing_symbol)
        by_loc.setdefault(key, []).append(mf)
    for mf in merged:
        loc_key = (mf.primary.sink_file, mf.primary.enclosing_symbol)
        peers = [p for p in by_loc.get(loc_key, []) if p is not mf]
        for peer in peers:
            if (
                peer.primary.root_cause_family != mf.primary.root_cause_family
                or peer.primary.sink_kind != mf.primary.sink_kind
            ):
                label = f"{peer.primary.sink_kind}/{peer.primary.root_cause_family}"
                if label not in mf.related:
                    mf.related.append(label)


# ---------------------------------------------------------------------------
# Pass 3: cross-sink merge.
# ---------------------------------------------------------------------------


def _pass3_cross_sink_merge(merged: list[MergedFinding]) -> list[MergedFinding]:
    """Collapse MergedFindings at identical code location but classified
    with different sink_kind/root_cause_family."""
    if len(merged) < 2:
        return merged

    buckets: dict[tuple[str, int, str], list[MergedFinding]] = {}
    for mf in merged:
        p = mf.primary
        if not p.sink_file or not p.sink_line:
            key = (p.sink_file or "__no_loc__", id(mf), "")
        else:
            key = (p.sink_file, p.sink_line, _normalize_symbol(p.enclosing_symbol))
        buckets.setdefault(key, []).append(mf)

    result: list[MergedFinding] = []
    for key, group in buckets.items():
        if len(group) == 1:
            result.append(group[0])
            continue

        kinds = {mf.primary.sink_kind for mf in group}
        if len(kinds) <= 1:
            result.extend(group)
            continue

        non_custom = [mf for mf in group if not mf.primary.sink_kind.startswith("other:")]
        winner_pool = non_custom if non_custom else group
        winner = max(
            winner_pool,
            key=lambda m: (SEVERITY_RANK.get(m.severity, 0), m.confidence, len(m.primary.raw_body or "")),
        )

        alt_kinds: list[str] = list(winner.alternative_sink_kinds)
        alt_families: list[str] = list(winner.alternative_root_cause_families)
        for loser in group:
            if loser is winner:
                continue
            if loser.primary.sink_kind and loser.primary.sink_kind not in alt_kinds and loser.primary.sink_kind != winner.primary.sink_kind:
                alt_kinds.append(loser.primary.sink_kind)
            if loser.primary.root_cause_family and loser.primary.root_cause_family not in alt_families and loser.primary.root_cause_family != winner.primary.root_cause_family:
                alt_families.append(loser.primary.root_cause_family)
            winner.merged_from.append(loser.primary)
            winner.merged_from.extend(loser.merged_from)

        winner.alternative_sink_kinds = alt_kinds
        winner.alternative_root_cause_families = alt_families
        _add_flag(winner, FLAG_CROSS_SINK_MERGE)
        _check_conflict_flags(winner)
        result.append(winner)

    return result


# ---------------------------------------------------------------------------
# Main dedupe entry point.
# ---------------------------------------------------------------------------


def dedupe(findings: list[Finding]) -> tuple[list[MergedFinding], list[MergedFinding]]:
    """Return (main_findings, manual_review_findings).

    Passes:
      Pre: normalize known other:* kinds → canonical (kind, family).
      0 (format validation): findings without sink_file → manual review.
      1 (strict): merge by primary_key (includes sink_hash).
      2 (hash-mismatch): fallback merge on (file, kind, family, symbol).
      3 (cross-sink): same location, different sink_kind → collapse.
    """
    # Pre-pass: rewrite known other:* kinds (in-place mutation).
    _normalize_known_other_kinds(findings)

    # Pass 0: format validation.
    parse_failed: list[MergedFinding] = []
    valid: list[Finding] = []
    for f in findings:
        if _is_malformed(f):
            mf = MergedFinding(primary=f)
            mf.flags.append(FLAG_PARSE_FAILED)
            if not f.sink_file.strip():
                mf.flags.append(FLAG_NO_FILE)
            parse_failed.append(mf)
            continue
        valid.append(f)

    # Pass 1: bucket by primary_key.
    primary_buckets: dict[tuple, list[Finding]] = {}
    strategy_by_primary: dict[tuple, str] = {}
    fallback_by_primary: dict[tuple, tuple] = {}

    for f in valid:
        strategy, primary_key, fallback_key = _dedup_bucket(f)
        primary_buckets.setdefault(primary_key, []).append(f)
        strategy_by_primary[primary_key] = strategy
        fallback_by_primary[primary_key] = fallback_key

    pass1_merges: list[tuple[str, tuple, MergedFinding]] = []
    for pk, group in primary_buckets.items():
        strategy = strategy_by_primary[pk]
        fk = fallback_by_primary[pk]

        primary = _pick_primary(group)
        mf = MergedFinding(primary=primary)
        for extra in group:
            if extra is primary:
                continue
            mf.merged_from.append(extra)
        pass1_merges.append((strategy, fk, mf))

    # Pass 2: merge pass-1 groups that share fallback_key.
    by_fallback: dict[tuple, list[tuple[str, MergedFinding]]] = {}
    for strategy, fk, mf in pass1_merges:
        if strategy == "custom_sink":
            continue
        by_fallback.setdefault(fk, []).append((strategy, mf))

    merged: list[MergedFinding] = []
    consumed_ids: set[int] = set()

    for strategy, fk, mf in pass1_merges:
        if id(mf) in consumed_ids:
            continue
        if strategy == "custom_sink":
            _attach_flags(mf, strategy)
            merged.append(mf)
            consumed_ids.add(id(mf))
            continue

        peers = [peer_mf for peer_strat, peer_mf in by_fallback.get(fk, [])
                 if id(peer_mf) not in consumed_ids and peer_mf is not mf]

        if peers:
            for peer in peers:
                consumed_ids.add(id(peer))
                mf.merged_from.append(peer.primary)
                mf.merged_from.extend(peer.merged_from)
            _add_flag(mf, FLAG_MERGED_DESPITE_HASH_MISMATCH)
            all_items = [mf.primary] + mf.merged_from
            new_primary = _pick_primary(all_items)
            if new_primary is not mf.primary:
                rest = [x for x in all_items if x is not new_primary]
                mf.primary = new_primary
                mf.merged_from = rest

        _attach_flags(mf, strategy)
        merged.append(mf)
        consumed_ids.add(id(mf))

    # Pass 3: cross-sink merge.
    merged = _pass3_cross_sink_merge(merged)

    # Split into main + manual review.
    main_findings: list[MergedFinding] = []
    manual_review: list[MergedFinding] = []

    for mf in merged:
        if _is_custom_sink_finding(mf):
            if _should_promote_custom_sink(mf):
                _add_flag(mf, FLAG_CUSTOM_SINK)
                main_findings.append(mf)
            else:
                manual_review.append(mf)
        else:
            main_findings.append(mf)

    _build_cross_references(main_findings)

    parse_failed.sort(
        key=lambda m: (m.primary.source_file, m.primary.sink_file or "", m.primary.sink_line),
    )
    manual_review.extend(parse_failed)

    main_findings.sort(
        key=lambda m: (-SEVERITY_RANK[m.severity], m.primary.sink_file, m.primary.sink_line),
    )
    manual_review.sort(
        key=lambda m: (
            1 if FLAG_PARSE_FAILED in m.flags else 0,
            m.primary.sink_file,
            m.primary.sink_line,
        ),
    )
    return main_findings, manual_review
