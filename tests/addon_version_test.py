"""The scoped facade advertises the exact API contract it implements."""

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_modules import compatibility_modules
from addon_loader import REFERENCE_CHECKED, REFERENCE_RELEASE, TARGET_API_MAJOR


class VersionTests(unittest.TestCase):
    def test_reference_version_contract(self):
        self.assertEqual(TARGET_API_MAJOR, 12)
        self.assertEqual(REFERENCE_RELEASE, '12.3.1')
        self.assertEqual(REFERENCE_CHECKED, '2026-10-31')
        modules = compatibility_modules()
        version = modules['mitmproxy.version']
        self.assertIs(modules['mitmproxy'].version, version)
        self.assertEqual(version.VERSION, '12.3.1')
        self.assertEqual(version.MITMPROXY, 'mitmproxy 12.3.1')
        self.assertEqual(version.FLOW_FORMAT_VERSION, 21)
        self.assertFalse(hasattr(modules['mitmproxy'], '__version__'))


if __name__ == '__main__':
    unittest.main()
