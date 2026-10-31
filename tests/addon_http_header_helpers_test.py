"""Public HTTP header-helper contracts observed from mitmproxy 12.3.1."""

from collections import OrderedDict
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_modules import compatibility_modules


class HttpHeaderHelperTests(unittest.TestCase):
    def setUp(self):
        self.headers = compatibility_modules()['mitmproxy.net.http.headers']

    def test_content_type_parser_preserves_public_flat_parameter_rules(self):
        cases = {
            '': None,
            'bad': None,
            'TEXT/PLAIN': ('text', 'plain', OrderedDict()),
            'a/b/c': ('a', 'b/c', OrderedDict()),
            'a/b; x = v ; x=last': ('a', 'b', OrderedDict((('x', 'last'),))),
            'a/b;broken;=value': ('a', 'b', OrderedDict((('', 'value'),))),
            'multipart/form-data; boundary="a;b"': (
                'multipart', 'form-data', OrderedDict((('boundary', '"a'),))
            ),
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(self.headers.parse_content_type(value), expected)

    def test_content_type_assembly_keeps_order_and_values_literal(self):
        self.assertEqual(
            self.headers.assemble_content_type(
                'TEXT', 'PLAIN', OrderedDict((('charset', 'utf-8'), ('empty', '')))
            ),
            'TEXT/PLAIN; charset=utf-8; empty=',
        )
        self.assertEqual(
            self.headers.assemble_content_type('multipart', 'form-data', {'boundary': 'a;b'}),
            'multipart/form-data; boundary=a;b',
        )

    def test_encoding_inference_contract(self):
        html_meta = b'<meta charset="windows-1252">'
        html_equiv = (
            b'<meta http-equiv="Content-Type" '
            b'content="text/html; charset=Shift_JIS">'
        )
        xml = b'<?xml version="1.0" encoding="UTF-16"?>'
        cases = (
            ('', b'', 'latin-1'),
            ('text/plain', b'', 'latin-1'),
            ('text/plain; charset=utf-8', b'', 'utf-8'),
            ('text/plain;charset="utf-8"', b'', '"utf-8"'),
            ('application/json', b'', 'utf8'),
            ('application/problem+json', b'', 'utf8'),
            ('text/css', b'', 'utf8'),
            ('text/html', b'', 'utf8'),
            ('text/html', html_meta, 'windows-1252'),
            ('text/html', html_equiv, 'Shift_JIS'),
            ('TEXT/HTML', html_meta, 'latin-1'),
            ('APPLICATION/JSON', b'', 'latin-1'),
            ('text/plain; CHARSET=utf-8', b'', 'latin-1'),
            ('text/xml', xml, 'UTF-16'),
            ('image/svg+xml', xml, 'UTF-16'),
            ('application/octet-stream', b'', 'latin-1'),
        )
        for content_type, content, expected in cases:
            with self.subTest(content_type=content_type, content=content):
                self.assertEqual(
                    self.headers.infer_content_encoding(content_type, content),
                    expected,
                )


if __name__ == '__main__':
    unittest.main()
