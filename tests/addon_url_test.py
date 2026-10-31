"""Public URL-helper contracts observed from mitmproxy 12.3.1."""

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import runpy
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

import addon_url as url
from addon_loader import compatibility_imports
from addon_modules import compatibility_modules


class UrlTests(unittest.TestCase):
    def test_complete_black_box_probe_matches_reference_corpus(self):
        output = StringIO()
        with compatibility_imports(compatibility_modules()):
            with redirect_stdout(output):
                runpy.run_path(str(ROOT / 'tests/probes/addon_url_probe.py'))

        actual = json.loads(output.getvalue())
        expected = json.loads(
            (ROOT / 'tests/corpus/addon_url_v12.json').read_text()
        )
        self.assertEqual(actual, expected)

    def test_module_identity_and_default_ports(self):
        modules = compatibility_modules()
        canonical = modules['mitmproxy.net.http.url']
        self.assertIs(modules['mitmproxy.http'].url, canonical)
        self.assertEqual(canonical.default_port('http'), 80)
        self.assertEqual(canonical.default_port(b'https'), 443)
        self.assertIsNone(canonical.default_port('HTTP'))

    def test_host_port_and_authority_contract(self):
        self.assertEqual(url.hostport('http', 'example.com', 80), 'example.com')
        self.assertEqual(url.hostport('http', 'example.com', 81), 'example.com:81')
        self.assertEqual(url.hostport(b'http', b'example.com', 80), b'example.com')
        self.assertTrue(url.is_valid_host('::1'))
        self.assertTrue(url.is_valid_host(b'example.com'))
        self.assertFalse(url.is_valid_host('[::1]'))
        self.assertFalse(url.is_valid_host('bad host'))
        self.assertEqual(url.parse_authority('[::1]:443', True), ('::1', 443))
        self.assertEqual(
            url.parse_authority('example.com', True),
            ('example.com', None),
        )
        self.assertEqual(url.parse_authority('bad:port', False), ('bad:port', None))
        with self.assertRaises(ValueError):
            url.parse_authority('bad:port', True)

    def test_host_validation_matches_reference_edge_contract(self):
        for host in (
            '-bad.example',
            'bad-.example',
            'under_score.example',
            'bücher.example',
            'x' * 63 + '.example',
        ):
            with self.subTest(host=host):
                self.assertTrue(url.is_valid_host(host))

        for host in (
            '',
            '.',
            'a..b',
            'example.com..',
            'slash/example',
            'x' * 64 + '.example',
            'x' * 256,
            b'b\xc3\xbccher.example',
            b'\xff',
        ):
            with self.subTest(host=host):
                self.assertFalse(url.is_valid_host(host))

        with self.assertRaises(AttributeError):
            url.is_valid_host(None)
        with self.assertRaises(AttributeError):
            url.is_valid_host(1)

    def test_unchecked_authority_retains_an_invalid_candidate(self):
        self.assertEqual(
            url.parse_authority('example.com:65536', False),
            ('example.com:65536', None),
        )
        with self.assertRaises(ValueError):
            url.parse_authority('example.com:65536', True)

    def test_parse_and_unparse_contract(self):
        self.assertEqual(
            url.parse('https://example.com:8443/a?b=1'),
            (b'https', b'example.com', 8443, b'/a?b=1'),
        )
        self.assertEqual(
            url.parse('//example.com/path'),
            (b'', b'example.com', 80, b'/path'),
        )
        with self.assertRaisesRegex(ValueError, 'No hostname given'):
            url.parse('not a url')
        with self.assertRaises(ValueError):
            url.parse('http://example.com:bad/')
        with self.assertRaises(ValueError):
            url.parse('http://example.com:65536/')
        self.assertEqual(
            url.unparse('http', 'example.com', 81, '/a'),
            'http://example.com:81/a',
        )
        self.assertEqual(
            url.unparse(b'http', b'example.com', 80, b'/a'),
            b'http://example.com/a',
        )

    def test_query_and_quoting_contract(self):
        self.assertEqual(url.decode('a=&a=2'), [('a', ''), ('a', '2')])
        self.assertEqual(url.decode(b'a=1'), [(b'a', b'1')])
        self.assertEqual(url.encode([('a', 'x y')]), 'a=x+y')
        self.assertEqual(url.quote('a/b?c', '/'), 'a/b%3Fc')
        self.assertEqual(url.unquote('%C3%A9'), 'é')


if __name__ == '__main__':
    unittest.main()
