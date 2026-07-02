### 9. Safety net + progress per worker

The unifying contract is unchanged: each worker writes `<REVIEW_ROOT>/waves/<slice_id>.md`, and that file is the only thing dedupe reads. On Codex the safety net works off the **dispatcher's captured stdout** (under `--capture-dir`, materialized from each worker's `-o {capture}` last message), not an in-process response message.

The dispatcher classifies each planned slice after the run; **you** handle recovery from its captures:

1. If `waves/<slice_id>.md` is present (a fresh write this run) → success, regardless of exit code or timeout.
2. If the file is missing but the worker's captured stdout (under `--capture-dir`) contains the markdown findings body (`# Vulnerability ...` blocks) → **you (the orchestrator) recover it**: read that capture and Write the findings to `<REVIEW_ROOT>/waves/<slice_id>.md` yourself — exactly as the Claude harness recovers from a worker's response message (the worker→file contract is the only thing dedupe reads). The dispatcher library exposes a `recover_capture` hook for this, but the shipped CLI does **not** auto-invoke it, so on Codex the recovery is this orchestrator step. That turns the gap into a success.
3. If the file is still missing and nothing is recoverable → the slice is a **coverage gap**. Run the dispatcher with `--allow-gaps` so it records the gap to `<REVIEW_ROOT>/dispatch_gaps.json` (classified two-step: a fresh wave file is success regardless of exit/timeout, else `timeout > crash > missing_write`) instead of raising — the report is **not blocked**; `dedupe_findings.py --dispatch-gaps=<path>` folds it into REPORT.md's `## Coverage Gaps` with a prominent **INCOMPLETE** marker.

Read the dispatcher's JSON result (`{all_present, results, gaps:[slice_id...]}`) and `dispatch_gaps.json` to print a one-line status per slice:
- `✓ <slice_id>: saved findings` — wave file present
- `⚠ <slice_id>: worker wrote no file, recovered from captured stdout` — safety net fired
- `✗ <slice_id>: coverage gap (<timeout|crash|missing_write>)` — unrecoverable, recorded in dispatch_gaps.json

We do not retry workers. Continue with the remaining slices; a clean later run clears any stale `dispatch_gaps.json` automatically.
