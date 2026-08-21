from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts/check_markdown_links.py"
SPEC = importlib.util.spec_from_file_location("check_markdown_links", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
LINKS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LINKS
SPEC.loader.exec_module(LINKS)


class MarkdownLinkTests(unittest.TestCase):
    def test_fenced_commands_are_not_links(self) -> None:
        text = "before\n```md\n[private](docs/private.md)\n```\n[public](README.md)\n"
        self.assertEqual(LINKS.destinations(text), ("README.md",))

    def test_relative_and_root_targets_are_canonical(self) -> None:
        self.assertEqual(
            LINKS.resolve_target("tutorial/README.md", "../docs/language_spec.md#values"),
            "docs/language_spec.md",
        )
        self.assertEqual(
            LINKS.resolve_target("docs/language_spec.md", "/SECURITY.md"),
            "SECURITY.md",
        )

    def test_external_and_same_page_links_need_no_file_target(self) -> None:
        self.assertIsNone(LINKS.resolve_target("README.md", "https://example.com/a"))
        self.assertIsNone(LINKS.resolve_target("README.md", "#build"))

    def test_repository_escape_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "escapes"):
            LINKS.resolve_target("README.md", "../outside.md")


if __name__ == "__main__":
    unittest.main()
