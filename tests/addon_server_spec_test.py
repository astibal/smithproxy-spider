"""Public server-spec parsing parity against mitmproxy 12.3.1."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import addon_server_spec
from addon_modules import compatibility_modules
from addon_server_spec_contract import collect


class ServerSpecTests(unittest.TestCase):
    def test_reference_contract(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_server_spec_v12.json").read_text()
        )
        self.assertEqual(corpus["reference"], "mitmproxy 12.3.1")
        self.assertEqual(collect(addon_server_spec), corpus["cases"])

    def test_scoped_public_imports_share_one_module(self):
        modules = compatibility_modules()
        exported = modules["mitmproxy.net.server_spec"]
        self.assertIs(modules["mitmproxy.net"].server_spec, exported)
        self.assertIs(modules["mitmproxy.connection"].server_spec, exported)
        self.assertIs(exported.parse, addon_server_spec.parse)

    def test_parser_is_cached_and_has_no_resolution_side_effects(self):
        first = addon_server_spec.parse("https://example.test", "tcp")
        second = addon_server_spec.parse("https://example.test", "tcp")
        self.assertIs(first, second)
        self.assertEqual(first, ("https", ("example.test", 443)))


if __name__ == "__main__":
    unittest.main()
