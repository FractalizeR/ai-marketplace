# Business logic / state machine integrity

> Some items in this file are adapted from `cloudflare/security-audit-skill` (MIT License) — see [`THIRD_PARTY_NOTICES.md`](../../../THIRD_PARTY_NOTICES.md) for the license text and the full list of affected files.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

Standard scanners cannot find these — they are logic errors, not syntax patterns. Read each major workflow (order, approval, subscription, invite, application) end to end and ask: can a step be skipped, repeated, replayed, or reached out of order?

## Recommended sink_kinds

- `race_condition` — concurrent operations that produce an invalid state (cross-ref `fintech.md`, which layers a money-domain floor and a read-side cap on top of the generic qualification below)
- `type_juggling` — loose comparison / implicit type coercion that flips a state-machine or workflow decision (cross-ref `crypto.md` for the security-value-comparison case)

## Confidence floor rules

- **`race_condition` qualified floor — concrete state mutation**: **confidence ≥ 8** only when the race window allows mutating shared state with a security or business consequence: TOCTOU on an approval flag, a one-time invite/coupon-redemption flag, a last-seat/last-slot counter, a signup/application uniqueness check. The mutation must be the exploit primitive, not a side effect. This is the same qualification `fintech.md` states for money-mutating state (balance, ledger) — this file's version applies to any other state-machine field.
- **`race_condition` confidence cap — read-side stale-cache races**: a pure read-side race where one observer briefly sees stale cached state, with no persisted mutation → **max confidence 4**. Not every "concurrent access without lock" is a security bug.

## State machine violations

- Step-skipping: an endpoint for step 3 of a workflow (e.g. "confirm shipment") is callable without step 1/2 ("create order" / "pay") having completed — the handler trusts the record's presence, not its current status.
- Backwards / replay transitions: a completed workflow (e.g. `status: approved`) can be re-submitted to the same transition endpoint and re-enter a state that should only be reachable once (double approval, re-issued voucher, re-sent invite).
- Invalid-state reachability: two mutating requests hitting different endpoints each perform a valid-looking transition, but their combination reaches a state the state machine never declares (e.g. `cancelled` + `shipped` both true).
- Partial-failure rollback: a workflow with more than one side effect (charge stock, then notify, then mark complete) leaves earlier side effects applied when a later step throws — no compensating transaction / saga rollback.
- Status check performed against a stale in-memory or cached copy of the record rather than the authoritative row read inside the same transaction as the mutation.
- Numeric / quantity manipulation feeding a transition: negative quantity, zero quantity, or overflow accepted by a "confirm" endpoint without validating against the state the record was actually created with.
- Default / fallback behavior when a dependency needed to validate a transition (feature flag service, external status check) is unavailable — does the handler fail closed (reject the transition) or fail open (allow it)?

## Race conditions with business impact

Concurrent requests that produce an invalid state through a non-atomic check-then-act sequence. `fintech.md` states the same qualified floor for the money domain specifically (balance/ledger mutations); this section is the general form, for any state-machine field with a security or business consequence: an approval flag, a seat/slot counter, a one-time invite or coupon-redemption flag, a "claimed" marker.

- `if (record.status == 'pending') { record.status = 'approved'; ... }` without a row lock or optimistic-locking version check — two concurrent requests can both read `pending` and both apply the side effect of approval (double-approve).
- Last-slot / last-seat reservation: capacity check and decrement are two separate statements, not one atomic `UPDATE ... WHERE remaining > 0`.
- One-time-use token or invite: the "already used" check and the "mark used" write are not the same atomic operation — concurrent redemption uses the token twice.
- Idempotency-key handling on a non-monetary mutating endpoint (e.g. "submit application once") that checks-then-inserts instead of relying on a DB unique constraint.

## Cross-references

- Money-domain race conditions (balance debits, ledger mutations, payment idempotency) — see `fintech.md`, which restates the confidence floor above for that domain and adds money-specific patterns (double-charge, ledger invariants, FX arbitrage windows). `fintech.md` rides W6 (`trigger="has_fintech"`) and is only in scope on projects with detected fintech markers, unlike this file.
- Access-boundary violations disguised as a business-logic bypass (input to one operation bypassing a restriction enforced on a different operation for the same effect) — see `auth.md`.
