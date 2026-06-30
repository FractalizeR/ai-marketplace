"""Shared multi-environment helpers for fr-security-review (Phase 2A).

This is a subpackage of `bin/` (which is itself NOT a package — see the engine
invocation convention: each script puts `.../bin` on `sys.path[0]` and imports
top-level). `shared` is importable as `from shared.X import ...` once `.../bin`
is on `sys.path`.

Modules:
    contracts        — typed dataclasses, Callable aliases, typed exceptions.
    model_resolver   — AD7 discover -> propose -> confirm -> persist tier map.
    dispatch         — AD4 external-process wave fan-out + single-process role.

stdlib only. Subprocess is the single injected seam (a `runner` callable).
"""
