"""Weak signal parity against public mitmproxy 12.3.1 behavior."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from addon_modules import compatibility_modules
from addon_signal_contract import collect


class SignalTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(
            (ROOT / "tests/corpus/addon_signals_v12.json").read_text()
        )

    async def test_public_contract_matches_reference(self):
        public = compatibility_modules()["mitmproxy.utils.signals"]
        self.assertEqual(self.corpus["reference"], "mitmproxy 12.3.1")
        self.assertEqual(await collect(public), self.corpus["signals"])


if __name__ == "__main__":
    unittest.main()
