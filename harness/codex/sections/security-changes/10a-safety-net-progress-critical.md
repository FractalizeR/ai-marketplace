### 10a. Safety net + progress (CRITICAL)

The unifying contract is unchanged: each worker writes `<REVIEW_ROOT>/waves/<slice_id>.md`, and that file is the only thing dedupe reads. On Codex the safety net works off the **dispatcher's captured stdout** (under `--capture-dir`, materialized from each worker's `-o {capture}` last message), not an in-process response message — and it is **always on**.

The dispatcher classifies each planned slice after the run; **you** handle recovery from its captures:

1. `waves/<slice_id>.md` present (a fresh write this run) → success, regardless of exit code or timeout.
2. File missing but the worker's captured stdout (under `--capture-dir`) contains the markdown findings body (`# Vulnerability ...` blocks) → **you (the orchestrator) recover it**: read that capture and Write the findings to `<REVIEW_ROOT>/waves/<slice_id>.md` yourself, as the Claude harness recovers from a worker's response message. The dispatcher library has a `recover_capture` hook, but the shipped CLI does **not** auto-invoke it — on Codex this recovery is the orchestrator's step. That turns the gap into a success.
3. File still missing and nothing recoverable → a **coverage gap**. Run the dispatcher with `--allow-gaps` so it records the gap to `<REVIEW_ROOT>/dispatch_gaps.json` (classified `timeout > crash > missing_write`) instead of raising — the report is **not blocked**; `dedupe_findings.py --dispatch-gaps=<path>` folds it into REPORT.md's `## Coverage Gaps` with a prominent **INCOMPLETE** marker.

Read the dispatcher's JSON result (`{all_present, results, gaps:[slice_id...]}`) and `dispatch_gaps.json` to print a one-line status per slice:
- `✓ <slice_id>: saved findings` — wave file present
- `⚠ <slice_id>: worker wrote no file, recovered from captured stdout` — safety net fired
- `✗ <slice_id>: coverage gap (<timeout|crash|missing_write>)` — unrecoverable, recorded in dispatch_gaps.json

Worker retry is absent — on a crash the slice is marked not covered. Continue with the remaining slices; a clean later run clears any stale `dispatch_gaps.json` automatically.
