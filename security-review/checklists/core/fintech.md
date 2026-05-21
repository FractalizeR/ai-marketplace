# Fintech / business logic / concurrency / money handling

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path), reporting is **mandatory**, even if it does not fall under any of the items below. The checklist is a search priority pointer, not a filter.

## Recommended sink_kinds

- `race_condition` — race condition in a critical operation (balance, promo codes)
- `decimal_arith` — float/double for monetary operations
- `idor_lookup` — IDOR on financial operations (cross-ref `auth.md`)
- `webhook_unverified` — webhook without signature (cross-ref `auth.md`)

## Confidence floor rules

- **`race_condition` qualified floor — concrete state mutation**: **confidence ≥ 8** only when the race window allows mutating shared state with security impact: TOCTOU on file ops (`is_writable` → `file_put_contents`), account state (balance debit, promo redeem, invite consume), inventory (last seat reservation), uniqueness (signup with duplicate-key check then insert). The mutation must be the exploit primitive, not a side effect.
- **`race_condition` confidence cap — read-side stale-cache races**: pure read-side races where one observer briefly sees stale cached state without any persisted mutation → **max confidence 4**. Not every "concurrent access without lock" is a security bug; cache freshness gaps without state mutation are reliability concerns, not vulnerabilities.

## Concurrency / race conditions

- Double debit / double card charge: processing without a transactional lock
- Multiple use of a promo code / discount via parallel requests
- Check-then-act on balance: `if (balance >= amount) { balance -= amount }` without transaction + row lock
- Missing `SELECT ... FOR UPDATE` (pessimistic lock) for financial operations
- Missing optimistic locking (version column / `@Version` or ORM equivalent) for entities edited concurrently
- Transaction isolation level too weak (READ COMMITTED on PostgreSQL — default, but for finance SERIALIZABLE is sometimes required)
- `DELETE + INSERT` instead of `UPSERT` in high-concurrency scenarios → race on uniqueness

## Precision / rounding

- `float` / `double` for money: `0.1 + 0.2 !== 0.3`
- Should be: `int` (cents), `string`, or a specialized Money library (`brick/money`, `moneyphp/money`)
- Database decimal column with insufficient precision (scale < 2 for RUB/USD, < 8 for crypto)
- Rounding in the wrong direction: `round($amount, 2)` (banker's rounding is not used where required)
- Currency converters with intermediate `float`
- `number_format($money, 2)` for DB storage (string representation, loses precision)

## Business logic manipulation

- Coefficients / rates passed via request: `$loan_rate = $request->...->get('rate')` — must be backend-only
- Passing `price` via a hidden form field — must always be computed server-side
- Negative values: quantity, amount can be negative → refund on "purchase"
- Integer overflow in operations with large amounts (in languages with signed int)
- Bypass of min/max validation via missing server-side check (frontend-only validation)
- Mortgage/loan calculator with user-controlled parameters that directly form a commitment

## IDOR on money

- `/transaction/{id}` without an owner check: any authenticated user sees other users' transactions
- `/invoice/{id}/download` without authz
- Account balance endpoint: `/account/{id}/balance` accepts `id` from URL
- Transfer endpoint: `from_account` is passed by the client without verifying that the current user owns it

## Idempotency / duplicate processing

- Missing idempotency key on payment endpoints — client retry causes double-charge
- Webhook handler processes the same event twice (no `processed_events` table with uniqueness)
- Async retry: handler is not idempotent → on retry, duplicate side-effects (email send + balance change)
- Missing DB unique constraint on natural keys that must be unique
- `Stripe-Signature` / webhook id not stored as a dedup key

## Ledger invariants

- `debit + credit != 0` (double-entry bookkeeping violated)
- Missing audit trail for balance mutations
- Reconciliation does not check sum(transactions) == current_balance
- Soft-delete is not accounted for in balance calculation → a deleted transaction can be restored and break the balance
- Rollback on a partial transaction leaves inconsistent state

## Payment gateway integration

- Callback URL without signature verification (Stripe, Tinkoff, YooKassa) — attacker generates a fake success callback (cross-ref `auth.md`)
- Callback is processed before async confirmation is received → user sees paid, no actual debit
- Amount / currency taken from callback rather than reconciled with local order record
- Refund / void endpoints without authz check on ownership

## FX / currency conversion

- Currency rate taken from API at display time but used at debit time minutes later → arbitrage window
- Amount stored in one currency but rate stored as `float` → precision loss on reverse conversion
- Source of truth for FX rate not fixed (provider changes, rate jitters)

## Async financial operations (queue/message handlers)

- Message contains `amount` and `userId` without signature / encryption → if transport is compromised, fake messages alter balance
- Handler without authz: relies on the message being "from some trusted system"
- Retry without idempotency → duplicate balance mutation
- Missing dead-letter queue / alerting on failures in financial handlers
