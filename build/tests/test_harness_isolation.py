"""Guard: the Claude path can never be routed through the section-fold layer.

Claude byte-identity is structurally protected only because the Claude adapter
uses the token fold (`build`) and the OpenCode build alone walks sections
(`build_sectioned`). A future refactor that gave ClaudeAdapter a `render_section`
or routed `--harness=claude` through `_run_opencode` would silently break that —
these tests fail first.
"""

import unittest

import _common  # noqa: F401

from adapters import (
    ClaudeAdapter,
    CodexAdapter,
    FakeAdapter,
    OpenCodeAdapter,
    get_adapter,
)


class ClaudeIsolationTests(unittest.TestCase):
    def test_claude_adapter_has_no_render_section(self):
        # Claude byte-identity holds only because it never walks the section fold.
        self.assertFalse(hasattr(ClaudeAdapter(), "render_section"))
        self.assertFalse(hasattr(FakeAdapter(), "render_section"))

    def test_section_walking_adapters_have_render_section(self):
        self.assertTrue(hasattr(OpenCodeAdapter(), "render_section"))
        self.assertTrue(hasattr(CodexAdapter(), "render_section"))

    def test_codex_in_adapter_map(self):
        self.assertIsInstance(get_adapter("codex"), CodexAdapter)


if __name__ == "__main__":
    unittest.main()
