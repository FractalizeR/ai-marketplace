# Fintech / business logic / concurrency / money handling

**Это типичные паттерны категории, не исчерпывающий список.** Если ты обнаружил эксплуатируемую уязвимость, проходящую методологию (источник входа → трансформации → sink + конкретный путь эксплуатации) — репортить **обязательно**, даже если она не подпадает ни под один пункт ниже. Чек-лист — указатель приоритета поиска, а не фильтр.

## Recommended sink_kinds

- `race_condition` — race condition в критичной операции (баланс, промокоды)
- `decimal_arith` — float/double для денежных операций
- `idor_lookup` — IDOR на финансовых операциях (cross-ref `auth.md`)
- `webhook_unverified` — webhook без подписи (cross-ref `auth.md`)

## Concurrency / race conditions

- Двойное списание / двойная зарядка карты: обработка без transactional lock
- Множественное использование промокода / скидки через параллельные запросы
- Check-then-act на балансе: `if (balance >= amount) { balance -= amount }` без transaction + row lock
- Missing `SELECT ... FOR UPDATE` (pessimistic lock) для финансовых операций
- Отсутствие optimistic locking (version-column / `@Version` или эквивалент в ORM) для entities, которые редактируются конкурентно
- Transaction isolation level слишком слабый (READ COMMITTED на PostgreSQL — default, но для финансов иногда нужен SERIALIZABLE)
- `DELETE + INSERT` вместо `UPSERT` в high-concurrency сценариях → race на уникальности

## Precision / rounding

- `float` / `double` для денег: `0.1 + 0.2 !== 0.3`
- Должно быть: `int` (cents), `string`, либо специализированная Money library (`brick/money`, `moneyphp/money`)
- Database decimal column с недостаточной precision (scale < 2 для RUB/USD, < 8 для crypto)
- Округление в неправильную сторону: `round($amount, 2)` (banker's rounding не используется там, где нужен)
- Convertors валют с промежуточным `float`
- `number_format($money, 2)` для хранения в БД (строковое представление, теряет precision)

## Business logic manipulation

- Коэффициенты / ставки передаются через request: `$loan_rate = $request->...->get('rate')` — должны быть backend-only
- Передача `price` через hidden form field — всегда должно вычисляться server-side
- Negative values: quantity, amount могут быть отрицательными → возврат средств при «покупке»
- Integer overflow в операциях с большими суммами (в языках со знаковыми int)
- Bypass min/max validation через отсутствие server-side check (только frontend validation)
- Mortgage/loan calculator с user-controlled параметрами, напрямую формирующими commitment

## IDOR на деньгах

- `/transaction/{id}` без проверки владельца: any authenticated user видит чужие транзакции
- `/invoice/{id}/download` без authz
- Account balance endpoint: `/account/{id}/balance` принимает `id` из URL
- Transfer endpoint: `from_account` передаётся клиентом без verify что текущий пользователь владеет им

## Idempotency / duplicate processing

- Отсутствие idempotency key на платёжных endpoints — retry от клиента вызывает double-charge
- Webhook handler обрабатывает то же событие дважды (нет `processed_events` таблицы с уникальностью)
- Async retry: handler не idempotent → при retry повторные side-effects (email send + баланс change)
- DB unique constraint отсутствует на natural keys, которые должны быть уникальны
- `Stripe-Signature` / webhook id не сохраняются как dedup key

## Ledger invariants

- `debit + credit != 0` (double-entry bookkeeping нарушен)
- Отсутствие audit trail для balance mutations
- Reconciliation не проверяет sum(transactions) == current_balance
- Soft-delete не учитывается в balance calculation → можно восстановить удалённую транзакцию и сломать баланс
- Rollback на частичной транзакции оставляет inconsistent state

## Payment gateway integration

- Callback URL без signature verification (Stripe, Tinkoff, YooKassa) — attacker генерит фейковый success callback (cross-ref `auth.md`)
- Callback обрабатывается до получения async confirmation → user видит paid, реально не списалось
- Amount / currency берётся из callback, а не сверяется с локальным order record
- Refund / void endpoints без authz-check на ownership

## FX / currency conversion

- Курс валют берётся из API на момент отображения, но используется при списании через минуты → arbitrage window
- Сохранение amount в одной валюте, но хранение курса как `float` → потеря precision при reverse conversion
- Source of truth для FX rate не зафиксирован (провайдер меняется, курс дёргается)

## Async финансовые операции (queue/message handlers)

- Сообщение содержит `amount` и `userId` без подписи / encryption → если transport скомпрометирован, фейковые сообщения меняют баланс
- Handler без authz: полагается на то, что сообщение «откуда-то от доверенной системы»
- Retry без idempotency → duplicate balance mutation
- Отсутствие dead-letter queue / alerting на failures в финансовых handlers
