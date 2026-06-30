### 6. Summary and optional checkpoint

Print a summary to the user with emphasis on touched items (section names — those present in this CONTEXT.md):

```
Recon complete (recon_confidence: <level>, ceiling: <level>).
Stack: <framework>
Console: <frontmatter.environment.console_mode> <if environment.console_gap: "⚠️ coverage gap — " + environment.console_gap_reason>
Diff touched:
  - attack_surface: <N touched of M total>
  - data_access: <N touched>
  - authz_usage / recon_bags.stack.<stack>.<authz key>: <touched listing>
  - serialization / file_operations / http_clients: <touched listing>
  - secrets / fintech_markers / recon_bags.stack.<stack>.* config: <touched|untouched>
```

OpenCode has no interactive-prompt primitive, so there is **no inventory checkpoint** on this harness. Even when `--interactive` is passed, skip it: the recon process is authoritative and CONTEXT.md is not modified here. Proceed directly to reverse-grep (step 7). To correct or reprioritize the inventory, edit `<REVIEW_ROOT>/CONTEXT.md` by hand between runs, or re-run recon.

