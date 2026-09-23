"""Three-pass deduplication pipeline for security findings.

Pass 0: format validation (malformed → manual review).
Pass 1: strict merge by primary key (includes sink_hash).
Pass 2: fallback merge (drops sink_hash, flags [MERGED_DESPITE_HASH_MISMATCH]).
Pass 3: cross-sink merge (same location, different sink_kind).

Pre-pass: normalize known custom sink kinds (other:*) into canonical kinds.
"""

from __future__ import annotations

from typing import Optional

from .models import (
    FLAG_ATTACHED_WITHOUT_HASH,
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
    HardeningNote,
    MergedFinding,
    NeedsValidation,
    SideRecords,
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


def _normalize_known_other_kinds(findings: list[Finding | NeedsValidation | HardeningNote]) -> None:
    """Rewrite `other:*` kinds with canonical (kind, family) pairs in-place.

    Enables custom kinds that recur across projects to drop the CUSTOM_SINK
    flag, merge with regular findings, and land in per-family detail files
    instead of manual_review.md.

    Duck-typed over `sink_kind`/`root_cause_family` only, so `dedupe()`'s
    pre-pass (Finding) and `attach_side_records`' pre-pass (NeedsValidation /
    HardeningNote) are the SAME pass, not a copy -- P2.2 decision (03-verdict
    -buckets.md): a bucket record's `other:*` sink_kind must canonicalize
    identically to a Finding's, or the two would disagree on the sink_kind
    half of dedup identity for no reason.
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


# ---------------------------------------------------------------------------
# Verdict-bucket attachment (Stage 2 / P2.2).
#
# `dedupe()` above is NOT touched and NOT called from here. E6 probe
# (memory/cloudflare-borrow-plan/E6-pipeline-probe.md) showed empirically
# that `dedupe()` reads twelve members off a record, including `severity`,
# `confidence` and `raw_body` -- none of which `NeedsValidation` /
# `HardeningNote` have, by construction (Stage-2 decision: buckets carry no
# severity). So bucket records never enter `dedupe()`'s merge; they attach
# to its *output* as an annotation instead.
# ---------------------------------------------------------------------------


def _has_unknown_symbol(record) -> bool:
    """`Finding.is_unknown_symbol`, recomputed from a field a bucket record has.

    Deliberately the RAW comparison, not the normalized one: `_dedup_bucket`
    picks its branch this way, and a record that answered the question
    differently from the finding it belongs to would key into a branch the
    finding never entered. Reading `is_unknown_symbol` off the record instead
    is what `AttachSideRecordsSpyTests` forbids.
    """
    return record.enclosing_symbol == "unknown" or not record.enclosing_symbol


def _record_fallback_key(record) -> tuple:
    """Pass-2 key for a bucket record: the same shape `_dedup_bucket` builds
    for a Finding, computed from fields a bucket record actually has."""
    if _has_unknown_symbol(record):
        return (
            record.sink_file, record.sink_kind, record.root_cause_family,
            f"line_bucket_{record.sink_line // 5}",
        )
    return (
        record.sink_file, record.sink_kind, record.root_cause_family,
        _normalize_symbol(record.enclosing_symbol),
    )


def _record_location_key(record) -> tuple:
    """Pass-3 key for a bucket record: one code location, any classification."""
    return (record.sink_file, record.sink_line, _normalize_symbol(record.enclosing_symbol))


def _pick_nearest(candidates: list[tuple[int, "MergedFinding"]], sink_line: int) -> MergedFinding:
    """Nearest by line, ties going to whichever was indexed first.

    Deterministic on purpose: `findings.json` must be byte-identical across
    repeated runs over the same waves, and a set-ordered pick would break that.
    """
    best_mf = candidates[0][1]
    best_delta = abs(candidates[0][0] - sink_line)
    for line, mf in candidates[1:]:
        delta = abs(line - sink_line)
        if delta < best_delta:
            best_mf, best_delta = mf, delta
    return best_mf


def attach_side_records(
    merged: list[MergedFinding],
    needs_validation: list[NeedsValidation],
    hardening: list[HardeningNote],
) -> SideRecords:
    """Bind `needs_validation` / `hardening` bucket records to the confirmed
    findings `dedupe()` already merged.

    A bound record becomes an ANNOTATION on that MergedFinding (appended to its
    own `.needs_validation` / `.hardening` list) rather than a competing report
    entry -- e.g. `confirmed` in W1 + `needs_validation` in W3 on the same sink
    collapses to one finding with a note, not two report rows.

    Binding is tried in three tiers, most exact first, and a record that binds
    in one is never offered to the next:

      1. `sink_hash` -- the record and the finding quoted the same sink text.
      2. `dedupe()`'s own Pass-2 fallback key (file, kind, family, symbol; a
         line bucket when the symbol is unknown). Two workers routinely quote
         one sink slightly differently, so their hashes diverge while every
         other coordinate agrees -- this is the tier that case needs.
      3. `dedupe()`'s own Pass-3 key (file, line, symbol), which ignores kind
         and family: one location classified two ways. Pass 3 only fires when the
       classifications actually differ, and so does this tier.

    Tiers 2 and 3 borrow `dedupe()`'s own keys rather than inventing a second,
    looser notion of "the same sink". They are NOT the identity "binds exactly
    when `dedupe()` would have merged it": `dedupe()` registers one fallback
    key per Pass-1 group and buckets Pass 3 by `primary` alone, while these
    index every constituent `Finding`. So the rule is the slightly wider one:
    a record binds to the group `dedupe()` put a finding with that coordinate
    into. Matching is on the record's *location*, not its text, so a bound
    record carries `FLAG_ATTACHED_WITHOUT_HASH` and the report says the binding
    was not by snippet -- a reader must be able to tell the two apart.

    Findings whose `dedupe()` strategy is `custom_sink` are left out of tiers 2
    and 3 entirely: `dedupe()` excludes them from its own fallback merge, and
    their key has a different shape. A record beside one stays unattached.

    A `nohash00` sink_hash (empty snippet) never participates in tier 1 -- it is
    a sentinel, not a real hash, so treating it as one would let two unrelated
    empty-snippet records from different files "collide". Tiers 2 and 3 carry no
    hash, so such a record can still bind there, which is the point: a record
    with no usable snippet is exactly what tier 1 cannot help.

    Tier 1 keys on the hash alone: two distinct MergedFindings that happen to
    share one real sink_hash (identical snippet, different file or symbol --
    the hash is truncated to 32 bits, so possible though rare) put a record on
    whichever was indexed first. A documented simplification, unchanged here,
    and not exercised by production data so far.

    Records not bound anywhere are returned unattached, for the report's own
    standalone `## Needs validation` / `## Hardening notes` sections.

    This function never reads `severity`/`confidence`/`raw_body`/
    `is_custom_sink`/`is_unknown_symbol` off a bucket record.
    `severity`/`confidence`/`is_custom_sink`/`is_unknown_symbol` do not exist
    on one (Stage-2 decision: buckets carry no severity), so a stray access
    would raise -- but `raw_body` DOES exist and would resolve silently, which
    is why `AttachSideRecordsSpyTests` in `test_dedupe_findings.py` asserts the
    whole set with a spy rather than relying on an incidental crash. It covers
    every tier. `MergedFinding` itself has no `sink_hash` of its own, which is
    why all three indexes are built over its `Finding` members.

    `other:*` sink_kind canonicalization (`_normalize_known_other_kinds`) runs
    over both bucket lists in place, the same pre-pass `dedupe()` runs over
    `findings` -- so a bucket record's `sink_kind` is canonical before it is
    ever matched or rendered, same as a Finding's.
    """
    _normalize_known_other_kinds(needs_validation)
    _normalize_known_other_kinds(hardening)

    by_hash: dict[str, MergedFinding] = {}
    by_fallback: dict[tuple, list[tuple[int, MergedFinding]]] = {}
    by_location: dict[tuple, list[tuple[int, MergedFinding]]] = {}
    for mf in merged:
        for f in [mf.primary] + mf.merged_from:
            if f.sink_hash != "nohash00":
                by_hash.setdefault(f.sink_hash, mf)
            if _is_malformed(f):
                # `dedupe()` drops these on Pass 0, before any location merge
                # runs, so they are not a place a record could have merged
                # into. Their key degenerates to ("", kind, family, bucket 0);
                # leaving them in is also what kept a record whose own location
                # the parser could not read from staying standalone, since such
                # a record keys to the same degenerate tuple.
                continue
            strategy, _primary_key, fallback_key = _dedup_bucket(f)
            if strategy == "custom_sink":
                continue
            by_fallback.setdefault(fallback_key, []).append((f.sink_line, mf))
            if f.sink_line:
                location_key = (f.sink_file, f.sink_line, _normalize_symbol(f.enclosing_symbol))
                by_location.setdefault(location_key, []).append((f.sink_line, f.sink_kind, mf))

    result = SideRecords()

    def _bind(record) -> Optional[tuple[MergedFinding, bool]]:
        """Return (finding, bound_by_hash) for the first tier that matches."""
        if record.sink_hash != "nohash00":
            target = by_hash.get(record.sink_hash)
            if target is not None:
                return target, True
        candidates = by_fallback.get(_record_fallback_key(record))
        if candidates:
            return _pick_nearest(candidates, record.sink_line), False
        # Pass 3 collapses a location only when the group holds MORE THAN ONE
        # sink_kind (`_pass3_cross_sink_merge`: `if len(kinds) <= 1: continue`).
        # Same kind at the same place with a different family is two groups to
        # `dedupe()`, so it must stay two here as well.
        located = [
            (line, mf) for line, kind, mf in by_location.get(_record_location_key(record), [])
            if kind != record.sink_kind
        ]
        if located:
            return _pick_nearest(located, record.sink_line), False
        return None

    def _mark(record, bound_by_hash: bool) -> None:
        """Set the flag from THIS call's outcome, so a record re-bound against
        a different `merged` does not keep a mark the new binding contradicts."""
        while FLAG_ATTACHED_WITHOUT_HASH in record.flags:
            record.flags.remove(FLAG_ATTACHED_WITHOUT_HASH)
        if not bound_by_hash:
            record.flags.append(FLAG_ATTACHED_WITHOUT_HASH)

    for nv in needs_validation:
        bound = _bind(nv)
        if bound is None:
            _mark(nv, True)
            result.unmatched_needs_validation.append(nv)
            continue
        target, bound_by_hash = bound
        _mark(nv, bound_by_hash)
        if not any(x is nv for x in target.needs_validation):
            target.needs_validation.append(nv)
        result.matched.append((nv.sink_hash, target))

    for hn in hardening:
        bound = _bind(hn)
        if bound is None:
            _mark(hn, True)
            result.unmatched_hardening.append(hn)
            continue
        target, bound_by_hash = bound
        _mark(hn, bound_by_hash)
        if not any(x is hn for x in target.hardening):
            target.hardening.append(hn)
        result.matched.append((hn.sink_hash, target))

    return result
