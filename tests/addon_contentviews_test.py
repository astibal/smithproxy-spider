"""Custom content-view contracts and generation isolation."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from addon_contentviews_contract import collect
from addon_contentviews_helpers_contract import collect as collect_helpers
from addon_contentviews_legacy_contract import collect as collect_legacy
from addon_contentviews_signal_contract import collect as collect_signal
from addon_contentviews import (
    describe_registered,
    reencode_registered,
    render_registered,
)
from addon_modules import compatibility_modules
from addon_options import Options


class ContentviewTests(unittest.TestCase):
    def test_reference_legacy_bridge_contract(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_contentviews_legacy_v12.json").read_text()
        )
        module = compatibility_modules()["mitmproxy.contentviews"]
        self.assertEqual(collect_legacy(module), corpus["observations"])

    def test_reference_public_helper_contract(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_contentviews_helpers_v12.json").read_text()
        )
        options = Options()
        modules = compatibility_modules(options=options)
        actual = collect_helpers(
            modules["mitmproxy.contentviews"],
            modules["mitmproxy.http"],
            modules["mitmproxy.tcp"],
            modules["mitmproxy.udp"],
            modules["mitmproxy.websocket"],
            modules["mitmproxy.dns"],
            modules["mitmproxy.connection"],
            options,
        )
        self.assertEqual(actual, corpus["observations"])

    def test_reference_registry_signal_contract(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_contentviews_signal_v12.json").read_text()
        )
        module = compatibility_modules()["mitmproxy.contentviews"]
        self.assertEqual(collect_signal(module), corpus["observations"])

    def test_public_contract_matches_reference_corpus(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_contentviews_v12.json").read_text()
        )
        module = compatibility_modules()["mitmproxy.contentviews"]
        self.assertEqual(collect(module), corpus["cases"])

    def test_each_compatibility_generation_owns_its_registry(self):
        first = compatibility_modules()["mitmproxy.contentviews"]
        second = compatibility_modules()["mitmproxy.contentviews"]

        class Private(first.Contentview):
            def prettify(self, data, metadata):
                return "private"

        first.add(Private)
        self.assertIsNotNone(first.registry.get("private"))
        self.assertIsNone(second.registry.get("private"))

    def test_public_result_type_is_generation_agnostic(self):
        first = compatibility_modules()["mitmproxy.contentviews"]
        second = compatibility_modules()["mitmproxy.contentviews"]

        self.assertIs(first.ContentviewResult, second.ContentviewResult)

        result = first.ContentviewResult("text", "none", None, "plain text")
        self.assertEqual(result.text, "text")
        self.assertEqual(result.description, "plain text")

    def test_public_helper_reports_an_empty_custom_registry(self):
        modules = compatibility_modules()
        contentviews = modules["mitmproxy.contentviews"]
        request = modules["mitmproxy.http"].Request.make(
            "GET",
            "https://example.test/",
        )

        result = contentviews.prettify_message(request, object())

        self.assertEqual(result.text, "No content view is available.")
        self.assertEqual(result.syntax_highlight, "error")
        self.assertIsNone(result.view_name)
        self.assertEqual(result.description, "")

    def test_registry_selection_ignores_broken_priorities(self):
        module = compatibility_modules()["mitmproxy.contentviews"]

        class DefaultContentview(module.Contentview):
            def prettify(self, data, metadata):
                return "default"

        class PreferredContentview(module.Contentview):
            def prettify(self, data, metadata):
                return "preferred"

            def render_priority(self, data, metadata):
                return 10

        class InvalidPriority(module.Contentview):
            def prettify(self, data, metadata):
                return "invalid"

            def render_priority(self, data, metadata):
                return "high"

        class BrokenPriority(module.Contentview):
            def prettify(self, data, metadata):
                return "broken"

            def render_priority(self, data, metadata):
                raise RuntimeError("priority failed")

        default = DefaultContentview()
        preferred = PreferredContentview()
        module.add(default)
        module.add(preferred)
        module.add(InvalidPriority)
        module.add(BrokenPriority)

        marker = object()
        self.assertIs(module.registry.get(42, marker), marker)
        self.assertIs(module.registry["PREFERRED"], preferred)
        self.assertEqual(set(module.registry.keys()), set(module.registry.available_views()))
        self.assertIn(preferred, module.registry.values())
        self.assertIn(("default", default), module.registry.items())
        self.assertEqual(sorted((preferred, default)), [default, preferred])

        metadata = module.Metadata(content_type="application/octet-stream")
        selected = module.registry.get_view(b"payload", metadata)
        self.assertIs(selected, preferred)

    def test_registered_view_descriptions_validate_public_metadata(self):
        module = compatibility_modules()["mitmproxy.contentviews"]

        class Interactive(module.InteractiveContentview):
            syntax_highlight = "yaml"

            def prettify(self, data, metadata):
                return "value"

            def reencode(self, prettified, metadata):
                return prettified.encode("ascii")

        module.add(Interactive)
        self.assertEqual(describe_registered(module.registry), [{
            "key": "interactive",
            "name": "Interactive",
            "syntax_highlight": "yaml",
            "interactive": True,
        }])

        class MissingName(module.Contentview):
            name = ""

            def prettify(self, data, metadata):
                return "value"

        module.add(MissingName)
        with self.assertRaisesRegex(ValueError, "1 to 256"):
            describe_registered(module.registry)

        module = compatibility_modules()["mitmproxy.contentviews"]

        class InvalidSyntax(module.Contentview):
            syntax_highlight = "python"

            def prettify(self, data, metadata):
                return "value"

        module.add(InvalidSyntax)
        with self.assertRaisesRegex(ValueError, "syntax highlight"):
            describe_registered(module.registry)

    def test_render_boundary_rejects_invalid_view_results(self):
        module = compatibility_modules()["mitmproxy.contentviews"]
        with self.assertRaisesRegex(ValueError, "No registered"):
            render_registered(module.registry, b"payload")

        class InvalidText(module.Contentview):
            def prettify(self, data, metadata):
                return b"not text"

        module.add(InvalidText)
        with self.assertRaisesRegex(TypeError, "must return str"):
            render_registered(module.registry, b"payload")

        module = compatibility_modules()["mitmproxy.contentviews"]

        class InvalidSyntax(module.Contentview):
            syntax_highlight = "python"

            def prettify(self, data, metadata):
                return "text"

        module.add(InvalidSyntax)
        with self.assertRaisesRegex(ValueError, "syntax highlight"):
            render_registered(module.registry, b"payload")

    def test_reencode_boundary_requires_an_interactive_byte_result(self):
        module = compatibility_modules()["mitmproxy.contentviews"]
        with self.assertRaisesRegex(ValueError, "Unknown content view"):
            reencode_registered(module.registry, "text", b"original", None, "missing")

        class ReadOnly(module.Contentview):
            def prettify(self, data, metadata):
                return "text"

        module.add(ReadOnly)
        with self.assertRaisesRegex(ValueError, "not interactive"):
            reencode_registered(module.registry, "text", b"original", None, "readonly")

        class InvalidInteractive(module.InteractiveContentview):
            def prettify(self, data, metadata):
                return "text"

            def reencode(self, prettified, metadata):
                return prettified

        module.add(InvalidInteractive)
        with self.assertRaisesRegex(TypeError, "must return bytes"):
            reencode_registered(
                module.registry, "text", b"original", None, "invalidinteractive")


if __name__ == "__main__":
    unittest.main()
