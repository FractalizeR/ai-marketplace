<!-- source-sha256: 0f57df500f0b0d1285df740c9c10074c92c118b62e8ead8a50ae19475f7c598d -->
### 6. Optional `--interactive` checkpoint

Codex runs headless (`codex exec`, approval `never`) with no interactive-prompt primitive, so there is **no inventory checkpoint** on this harness. Even when `--interactive` is passed, skip this step: the recon process is authoritative and **CONTEXT.md is not modified** here. The pipeline proceeds directly to wave planning (step 7) on the recon inventory as written.

If you need to correct or reprioritize the inventory, do it out of band — edit `<REVIEW_ROOT>/CONTEXT.md` by hand between runs, or re-run recon — then continue.
