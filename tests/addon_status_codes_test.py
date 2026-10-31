"""Clean-room contract for the public mitmproxy 12 status-code table."""

import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

import addon_status_codes as status_codes
from addon_modules import compatibility_modules


class StatusCodeTests(unittest.TestCase):
    def test_reference_contract_digest(self):
        names = sorted(
            name for name in status_codes.__all__
            if name != 'RESPONSES'
        )
        payload = {
            'constants': {
                name: getattr(status_codes, name)
                for name in names
            },
            'responses': status_codes.RESPONSES,
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(',', ':'),
        ).encode()

        self.assertEqual(len(names), 64)
        self.assertEqual(len(status_codes.RESPONSES), 64)
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            'd671f7667166ab11258045d13fb0a5ccbc9ed04a598fa8df2665aa8c9379cf8b',
        )

    def test_http_and_canonical_module_share_the_same_table(self):
        modules = compatibility_modules()
        http = modules['mitmproxy.http']
        canonical = modules['mitmproxy.net.http.status_codes']

        self.assertIs(http.status_codes, canonical)
        self.assertEqual(canonical.OK, 200)
        self.assertEqual(canonical.RESPONSES[418], "I'm a teapot")


if __name__ == '__main__':
    unittest.main()
