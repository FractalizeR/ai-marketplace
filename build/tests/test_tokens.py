"""Registry coverage + completeness/no-leak scan."""

import unittest

import _common
from _common import ARTIFACTS, read

from extract import (
    CAT_AGENT_FRONTMATTER, CAT_ARGS, CAT_AUQ, CAT_CMD_FRONTMATTER,
    CAT_CORE_ROOT, CAT_MCP, CAT_TASK, extract,
)
from segments import Tier
from tokens import REGISTRY, active_leak_patterns


class RegistryCoverageTests(unittest.TestCase):
    def test_every_extract_category_in_registry(self):
        for cat in (CAT_CORE_ROOT, CAT_ARGS, CAT_CMD_FRONTMATTER,
                    CAT_AGENT_FRONTMATTER, CAT_TASK, CAT_AUQ, CAT_MCP):
            self.assertIn(cat, REGISTRY)

    def test_every_registry_entry_has_tier_and_renderer(self):
        for cat, spec in REGISTRY.items():
            self.assertIsInstance(spec.tier, Tier)
            self.assertTrue(spec.claude_renderer, f"{cat} has no claude_renderer")

    def test_active_body_categories_have_leak_pattern(self):
        # Every ACTIVE category that can appear in body prose needs a leak
        # pattern (frontmatter categories are positional → None is allowed).
        positional = {CAT_CMD_FRONTMATTER, CAT_AGENT_FRONTMATTER}
        for cat, spec in REGISTRY.items():
            if spec.tier in (Tier.ACTIVE_CANONICAL, Tier.ACTIVE_PARSED) and cat not in positional:
                self.assertIsNotNone(spec.leak_pattern, f"{cat} missing leak_pattern")


class NoLeakTests(unittest.TestCase):
    def test_neutral_segments_contain_no_active_tokens(self):
        patterns = active_leak_patterns()
        for path, kind in ARTIFACTS.items():
            for s in extract(read(path), kind):
                if s.tier is not Tier.NEUTRAL:
                    continue
                for cat, rx in patterns:
                    m = rx.search(s.original_text)
                    self.assertIsNone(
                        m,
                        f"{cat} token leaked into NEUTRAL text in {path.name}: "
                        f"{s.original_text[max(0, (m.start() if m else 0) - 20):][:60]!r}",
                    )


if __name__ == "__main__":
    unittest.main()
