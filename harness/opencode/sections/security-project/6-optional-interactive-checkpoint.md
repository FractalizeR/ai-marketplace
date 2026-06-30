### 6. Optional `--interactive` checkpoint

OpenCode has no interactive-prompt primitive, so there is **no inventory checkpoint** on this harness. Even when `--interactive` is passed, skip this step: the recon process is authoritative and **CONTEXT.md is not modified** here. The pipeline proceeds directly to wave planning (step 7) on the recon inventory as written.

If you need to correct or reprioritize the inventory, do it out of band — edit `<REVIEW_ROOT>/CONTEXT.md` by hand between runs, or re-run recon — then continue.

