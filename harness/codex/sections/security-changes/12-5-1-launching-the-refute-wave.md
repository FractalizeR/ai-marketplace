#### 12.5.1. Launching the refute wave

Read the `<REVIEW_ROOT>/REPORT.md` index table. Split rows into batches of ≤20 findings (first 20 → batch_index=0, next 20 → batch_index=1, etc.).

Each batch is **one `codex exec` process** that reads and follows the bundled refute agent file. **Parallelism is forbidden** — every batch appends to the single file `<REVIEW_ROOT>/refute.md`, so concurrent writers would corrupt it. Drive the batches strictly **sequentially**, one `codex exec` at a time, waiting for each to finish before starting the next.

Clean `refute.md` **once before the loop** (not per batch) so appends across batches accumulate — do NOT route this through the role dispatcher per batch, whose freshness step would unlink `refute.md` and discard earlier batches:

```bash
rm -f "<REVIEW_ROOT>/refute.md"
```

Then, for each batch in order (`batch_index = 0 .. N-1`):

```bash
codex exec -m <FAST_TIER> -C <PROJECT_ROOT> -s workspace-write --add-dir <REVIEW_ROOT> --skip-git-repo-check -o "<REVIEW_ROOT>/captures/refute-<i>.capture.txt" "read and follow <FR_SECURITY_CORE_ROOT>/agents/security-refute.md then refute: review_root=<REVIEW_ROOT> batch_index=<i> findings_slice=<≤20 finding rows from the REPORT.md index>"
```

`<FAST_TIER>` is the fast-tier model id from `<REVIEW_ROOT>/.model_map.json` (refute is the mechanical second pass). `--add-dir <REVIEW_ROOT>` grants the append write to `refute.md` (outside `project_root` under `workspace-write`). The refute agent appends its YAML verdicts to `<REVIEW_ROOT>/refute.md`; because the runs are sequential there is exactly one writer at any time. Soft timeout 10 minutes per batch — if a process does not return in time, print a warning "adversarial pass partial — N of M findings reviewed" and continue with the partial refute. Refute never blocks the main report.
