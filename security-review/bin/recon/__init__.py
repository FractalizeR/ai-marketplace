"""Recon inventory subsystem (schema v2).

Public API:
- types.InventoryResult / SectionPayload / SanityProbe / StackMatch
- yaml_emit.dump_yaml_subset(value) -> str — emits parse_yaml_subset-compatible YAML
- recipes.load_recipe(name) -> recipe module
"""
