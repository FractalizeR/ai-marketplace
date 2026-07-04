### 10. Parallel worker launch in `mode=changes`

Same external-process model as the project audit — OpenCode has no in-process subagent fan-out, so each wave runs as its own `opencode run` process (worker via `--agent security`), **≤6 concurrent**, via the shared dispatcher (`shared/dispatch.py`, `dispatch_waves`). Each worker writes `<REVIEW_ROOT>/waves/<slice_id>.md` (the unifying contract); here slice ids carry the `_CHANGES` suffix and `target_files` are the touched subset.

**Fold the grep finds into the plan first.** In the in-process harness the reverse-grep (step 7) / forward-grep (step 8) consumers and the deterministic consumer→wave mapping (step 8a) are injected per-worker at launch. OpenCode workers read their inputs from the per-slice config the dispatcher writes **straight from `waves_plan.json`**, so before dispatching, merge each mapped consumer into the `entry_points_in_scope` of the slices step 8a assigned it to (consumers with `waves: []` go to every slice as fallback). The `--extra-target-files` consumers were already merged into `target_files` by `plan_waves.py` in step 9.

Then dispatch the whole plan in **one** call (it batches internally at `max_parallel=6`):

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
  --worker-cmd-template 'opencode run -m {model} --agent security "review_root={review_root} project_root={project_root} core_root={core_root} slice_id={slice_id} slice_config={slice_config} mode=changes"'
```

`--allow-gaps` is **required**, not optional: in strict mode a single crashed or timed-out worker raises `DispatchGapError` (exit 2) *before* the JSON result or `dispatch_gaps.json` is written, and a blind re-run would then delete every already-written wave file (freshness protocol) and redo all workers. With `--allow-gaps` the gap is recorded instead (exit 1) and step 10a reconciles it.

**Model tiering carries over as `-m {model}` on the one `security` agent, not as a distinct agent per tier.** The dispatcher reads each slice's `"model"` field (`opus`/`sonnet`), maps it through `LABEL_TO_TIER = {opus→high, sonnet→fast}` against the resolved `{high, fast}` tier map in `<REVIEW_ROOT>/.model_map.json`, and substitutes the concrete model id into `{model}`. `--all-opus` is honored upstream by `plan_waves.py`.

`project_root` and `core_root` are forwarded **absolute** (Step 0.4 invariant) so each worker resolves `target_files` / `entry_points_in_scope` / paths inside `CONTEXT.md` correctly when `project_root != cwd` (composite repos). Each slice's full inputs reach the worker through its per-slice `{slice_config}` file, written by the dispatcher from the plan. **Freshness (AD-2A8):** planned `waves/<slice_id>.md` files are deleted before fan-out, so a stale file plus a crashed worker is still a gap (step 10a).

