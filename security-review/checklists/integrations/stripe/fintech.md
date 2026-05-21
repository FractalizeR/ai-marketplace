# Payments / fintech (Stripe)

> This checklist extends `core/fintech.md` for projects that use Stripe for payments. On instruction conflict, this file takes precedence as the more specific layer. The worker loads both files at once.

**These are typical patterns of the category, not an exhaustive list.** If you discover an exploitable vulnerability that passes the methodology (input source → transformations → sink + concrete exploit path) — reporting is **mandatory**, even if it does not fall under any item below. The checklist is a search-priority pointer, not a filter.

## Confidence floor rules

- **Live Stripe secret key (`sk_live_...`) committed to git** (literal in code, `.env` committed, or `config/services.php` containing a real value rather than `env(...)`) → `hardcoded_secret` **confidence ≥ 10**. Absolute evidence. A live secret grants full API access: charge / refund / read all customer PII; rotation requires platform support.
- **Webhook handler without `Stripe\Webhook::constructEvent` call** or with `endpoint_secret = ''` / `endpoint_secret = null` → `webhook_unverified` **confidence ≥ 9**. The handler trusts attacker-supplied payloads. The constructEvent helper verifies the `Stripe-Signature` header against the endpoint secret AND enforces the timestamp tolerance — both must happen.
- **Webhook handler that catches `SignatureVerificationException` and continues processing the payload** → `webhook_unverified` confidence ≥ 9. Catch+log+200 OK is the canonical bypass.

## Webhook signature verification

Stripe webhook authenticity is enforced by the `Stripe-Signature` header — HMAC-SHA256 of the raw request body and a timestamp, signed with an endpoint secret. The official SDK exposes `Stripe\Webhook::constructEvent($payload, $sig_header, $endpoint_secret, $tolerance = 300)`.

- **`constructEvent` not called at all**: handler json-decodes `$_POST` or `php://input` directly and acts on `event.type`. Attacker forges any event. Sink: `webhook_unverified`.
- **Endpoint secret pulled from a request parameter**: `constructEvent($payload, $sig, $_GET['secret'])` — pseudo-defence; attacker supplies their own secret with a matching signature. Sink: `webhook_unverified`.
- **Raw body modified before verification**: `json_decode($body); … constructEvent(json_encode($decoded), $sig, $secret)` re-encodes the payload, changing whitespace / key order → signature mismatch → developer "fixes" by disabling verification. Read `php://input` once, pass that exact byte string to `constructEvent`.
- **`tolerance` parameter raised**: the default 300-second (5-minute) tolerance is also a replay window. Setting `tolerance` to 3600+ for "robustness" widens the window proportionally. Sink: `webhook_replay`.

## Webhook idempotency

Stripe retries webhooks aggressively (5+ attempts with exponential backoff) — handlers receive the same `event.id` multiple times.

- **No idempotency check on state-mutating handlers**: a `charge.succeeded` handler that grants entitlement / fulfills an order without checking `event.id` against an idempotency-keyed log will double-spend on the inevitable retry. Sink: `webhook_replay`.
- **Idempotency keyed on `data.object.id` (PaymentIntent/Charge ID) instead of `event.id`**: two different events (e.g. `payment_intent.succeeded` + `charge.succeeded`) refer to the same payment but have different `event.id` — keying on the wrong one yields false-positive duplicates AND misses real duplicates. Sink: `webhook_replay`.
- **Idempotency log written AFTER fulfillment** rather than before, without a database transaction wrapping both: power loss between the two writes leaves the system in "fulfilled, no log" state → retry re-fulfills. Architectural finding; cross-ref `core/fintech.md` (race conditions).

## Amount handling — smallest currency unit

Stripe represents amounts in the SMALLEST CURRENCY UNIT (cents for USD/EUR/GBP, whole units for zero-decimal currencies like JPY/KRW/VND, satoshis for crypto). The `amount` field on `Charge`, `PaymentIntent`, `Refund`, etc. is an integer in that unit.

- **Treating `amount` as the major unit**: `$event->data->object->amount` read as dollars/euros → 100× understatement (USD/EUR) or arbitrary error (zero-decimal currencies). Code paths: fulfillment thresholds (`if ($amount >= 50)`), display ("You paid $$amount"), accounting export. Sink: `decimal_arith`.
- **Floating-point amount arithmetic**: `$amount = floor($priceInDollars * 100)` introduces FP rounding errors. Always use integer math and the explicit unit-per-currency table from Stripe docs.
- **Zero-decimal currency confusion**: code that divides by 100 universally treats `amount = 1000` as 10 JPY for display when the actual amount is 1000 JPY (100× display error). Sink: `decimal_arith`.
- **Refund > original charge**: partial-refund handlers that sum refund attempts must not exceed the original amount. Stripe enforces this on its side, but a self-service refund flow that calls `Stripe::create()` without tracking running totals can over-refund via parallel requests. Cross-ref `core/fintech.md` ledger invariants.

## Currency mismatch

Multi-currency platforms must validate that a charge currency matches the entity (order / subscription / wallet) currency.

- **Currency not checked**: handler receives `currency = "eur"` event for an order denominated in USD; comparing `$event->amount` to the stored `$order->total_usd` is meaningless. Sink: `decimal_arith` (semantic mismatch) or `business_logic` via `other:`.
- **Stored amounts in dollars while Stripe events report cents**: persistent confusion → silent miscalculation; especially dangerous in CSV/accounting exports.

## PaymentMethod / Customer ownership (IDOR)

Stripe's `PaymentMethod`, `Customer`, and `SetupIntent` IDs are predictable by enumeration (`pm_…`, `cus_…`) only by Stripe, but they ARE attacker-controllable in API calls.

- **Charging a `payment_method_id` without checking ownership**: endpoint accepts `payment_method_id` from the request and calls `PaymentIntent::create([..., 'payment_method' => $_POST['pm']])` against the attacker's selected target customer. Without a server-side check `$pm->customer == session.user.stripe_customer_id`, the attacker bills someone else's card. Sink: `idor_lookup`.
- **Customer ID confusion**: passing user-supplied `customer` in `PaymentIntent::create` without verifying the customer belongs to the authenticated user; alternatively, allowing the user to attach a `PaymentMethod` to a customer they don't own. Sink: `idor_lookup` / `missing_authz`.

## Stripe Connect (platform / connected accounts)

Stripe Connect uses the `Stripe-Account` header (or `stripe_account` request option) to scope API calls to a connected account. Misuse is catastrophic.

- **`Stripe-Account` header missing on platform API calls**: charge funds land on the platform account instead of the seller. Cross-ref: `core/fintech.md` (ledger invariants).
- **`stripe_account` taken from request input**: `$stripe->paymentIntents->create([...], ['stripe_account' => $_POST['account']])` — attacker sets it to a competitor's connected account, charges land there. Sink: `idor_lookup` / `missing_authz`.
- **Webhook from a connected account routed to platform handler**: events for connected accounts carry `account` field; platform-only handlers must reject events with `account` set. Sink: `webhook_unverified` (insufficient scope check).

## Test mode vs live mode

Stripe issues two distinct sets of keys: test (`pk_test_*` / `sk_test_*`) and live (`pk_live_*` / `sk_live_*`). They never cross.

- **Same webhook endpoint registered for both test and live**: a live-fulfillment handler that doesn't gate on key prefix accepts test events from the dashboard's "Send test webhook" feature → free fulfillment in production. Architecture-level finding; sometimes there's no in-code defence, only configuration-level.
- **Test secret key shipped to production**: code falls back to `'sk_test_…'` when env var is missing; production runs in test mode silently — real cards never charged. Cross-ref `core/fintech.md`.

## API key in repository

- **Live secret key (`sk_live_*`) literal in source**: see Confidence floor rules above (`hardcoded_secret` ≥ 10).
- **Test secret key (`sk_test_*`) literal in source**: still leaks the test dashboard and any test-mode customer data; `hardcoded_secret` ≥ 7 (test customers can include real PII).
- **`STRIPE_SECRET` committed in `.env`** (not `.env.example`): same severity as a code-literal — both are in git history. Cross-ref `core/disclosure.md` (`secrets`).

## Worker search patterns

- `Stripe\\Webhook::constructEvent\(` — check argument 3 (endpoint secret) is from env / config service, not literal `""`/`null`/`$_GET[]`.
- `Stripe::setApiKey\(` / `\\StripeClient\(` — secret-key construction; check source of the key value.
- `payment_intent\.|charge\.|invoice\.|customer\.subscription\.` event-type strings in handlers — find the dispatch table and verify each branch has idempotency.
- `->amount\b` access on Stripe objects — verify smallest-unit handling.
- `Stripe-Account` header / `stripe_account` option in API calls — verify the value comes from authenticated session, not request input.
- `sk_live_` / `sk_test_` literals — see Confidence floor rules.
