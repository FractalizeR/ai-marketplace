### 8. Parallel worker launch

Codex has no named agents and no in-process subagent fan-out — each wave runs as its own external `codex exec` process that **reads and follows** the bundled worker agent file (`agents/security.md` under the shared core). The shared dispatcher (`shared/dispatch.py`, `dispatch_waves`) launches one worker per plan slice, **≤6 concurrent** (`ThreadPoolExecutor`, hard-capped), and enforces the wave-file contract: each worker writes its findings to `<REVIEW_ROOT>/waves/<slice_id>.md`.

Run the whole plan in **one** dispatcher call — it batches internally (`max_parallel=6`) so you do not split batches by hand:

```bash
python3 ${FR_SECURITY_CORE_ROOT}/bin/shared/dispatch.py \
  --plan "<REVIEW_ROOT>/waves_plan.json" \
  --model-map "<REVIEW_ROOT>/.model_map.json" \
  --project-root "<PROJECT_ROOT>" \
  --review-root "<REVIEW_ROOT>" \
  --core-root "${FR_SECURITY_CORE_ROOT}" \
  --max-parallel 6 \
  --capture-dir "<REVIEW_ROOT>/captures" \
  --allow-gaps \
  --worker-cmd-template 'codex exec -m {model} -C {project_root} -s workspace-write --add-dir {review_root} --skip-git-repo-check -o {capture} "read and follow {core_root}/agents/security.md then audit this slice: review_root={review_root} project_root={project_root} core_root={core_root} slice_id={slice_id} slice_config={slice_config} mode=project"'
```

The read-follow path uses the `{core_root}` **dispatch placeholder**, not `${FR_SECURITY_CORE_ROOT}` — the dispatcher `str.format`-substitutes the template into argv, and `${FR_SECURITY_CORE_ROOT}` would be parsed as an unknown `{FR_SECURITY_CORE_ROOT}` field and abort the fan-out before any process launches. `-C {project_root}` sets each worker's cwd; `--add-dir {review_root}` grants the wave-file write (the review root lies outside `project_root` in a composite repo, so `workspace-write` would otherwise deny it); `-o {capture}` records the worker's last message under `--capture-dir` for the safety net.

`--allow-gaps` is **required**, not optional: in strict mode a single crashed or timed-out worker raises `DispatchGapError` (exit 2) *before* the JSON result or `dispatch_gaps.json` is written, and a blind re-run would then delete every already-written wave file (freshness protocol) and redo all workers. With `--allow-gaps` the gap is recorded instead (exit 1), the JSON result is printed, and step 9 reconciles it.

**Model tiering carries over as `-m {model}` per external process, not as a distinct agent per tier** (Codex has none). The dispatcher reads each slice's `"model"` field from the plan (`opus`/`sonnet`), maps it through the resolved `{high, fast}` tier map (`LABEL_TO_TIER = {opus→high, sonnet→fast}`) in `<REVIEW_ROOT>/.model_map.json`, and substitutes the concrete model id into `{model}`. Trust-boundary waves (W1/W2/W6 → opus → high) and mechanical data-flow waves (W3/W4/W5/W∞ → sonnet → fast) thus run on the right tier per process. `--all-opus` is honored upstream by `plan_waves.py`, which already wrote `opus` into every slice's `"model"`.

`project_root` and `core_root` are forwarded **absolute** (per the Step 0.4 invariant) so each worker resolves `target_files` / `entry_points_in_scope` / paths inside `CONTEXT.md` correctly when `project_root != cwd` (composite repos). Each slice's full inputs (`relevant_section_paths`, `checklists`, `entry_points_in_scope`, `target_files`) reach the worker through its per-slice config file, which the dispatcher writes from the plan and exposes as `{slice_config}`.

**Freshness (AD-2A8):** the dispatcher deletes every planned slice's `waves/<slice_id>.md` before fan-out, so a stale prior file plus a crashed worker is still detected as a gap (handled in step 9). Worker stdout is captured under `--capture-dir` for the safety net.
