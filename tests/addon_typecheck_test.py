"""Option type-helper parity against public mitmproxy 12.3.1 behavior."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from addon_modules import compatibility_modules
from addon_typecheck_contract import collect


class TypecheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(
            (ROOT / "tests/corpus/addon_typecheck_v12.json").read_text()
        )

    def test_complete_public_contract_matches_reference(self):
        public = compatibility_modules()["mitmproxy.utils.typecheck"]
        self.assertEqual(self.corpus["reference"], "mitmproxy 12.3.1")
        self.assertEqual(collect(public), self.corpus["typecheck"])

    def test_options_use_the_same_public_validator(self):
        modules = compatibility_modules()
        public = modules["mitmproxy.utils.typecheck"]

        public.check_option_type("ratio", 1, float)
        with self.assertRaisesRegex(TypeError, "Expected <class 'bool'>"):
            public.check_option_type("enabled", 1, bool)


if __name__ == "__main__":
    unittest.main()
