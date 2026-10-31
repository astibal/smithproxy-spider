"""Public encoding-helper contracts observed from mitmproxy 12.3.1."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

import addon_encoding as encoding
from addon_encoding_contract import collect
from addon_modules import compatibility_modules


class EncodingTests(unittest.TestCase):
    def test_complete_public_codec_surface_matches_reference(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_encoding_v12.json').read_text()
        )
        public = compatibility_modules()['mitmproxy.net.encoding']
        self.assertEqual(collect(public), corpus['encoding'])

    def test_public_module_and_identity_values(self):
        public = compatibility_modules()['mitmproxy.net.encoding']
        self.assertEqual(public.__all__, ('encode', 'decode'))
        self.assertIsNone(public.encode(None, 'unknown'))
        self.assertIsNone(public.decode(None, 'unknown'))
        self.assertEqual(public.encode(b'bytes', 'identity'), b'bytes')
        self.assertEqual(public.decode('text', 'none'), 'text')

    def test_http_codings_round_trip_binary_content(self):
        body = bytes(range(256)) * 3
        for coding in ('gzip', 'deflate', 'br', 'zstd'):
            with self.subTest(coding=coding):
                wire = encoding.encode(body, coding)
                self.assertIsInstance(wire, bytes)
                self.assertNotEqual(wire, body)
                self.assertEqual(encoding.decode(wire, coding), body)

        # These stable reference bytes also fix compression levels and gzip's
        # portable timestamp/OS header fields.
        self.assertEqual(
            encoding.encode(b'abc', 'gzip').hex(),
            '1f8b08000000000004ff4b4c4a0600c241243503000000',
        )
        self.assertEqual(encoding.encode(b'abc', 'deflate').hex(), '78014b4c4a0600024d0127')
        self.assertEqual(encoding.encode(b'abc', 'br').hex(), '0b018061626303')
        self.assertEqual(encoding.encode(b'abc', 'zstd').hex(), '28b52ffd2003190000616263')

    def test_gzip_decoder_matches_the_public_stream_boundary(self):
        first = encoding.encode(b'first', 'gzip')
        second = encoding.encode(b'second', 'gzip')
        self.assertEqual(encoding.decode(first + second, 'gzip'), b'first')
        self.assertEqual(encoding.decode(first + b'trailing', 'gzip'), b'first')
        self.assertEqual(encoding.decode(first[:-1], 'gzip'), b'first')
        self.assertEqual(encoding.decode(b'', 'gzip'), b'')

    def test_character_codecs_and_error_policy(self):
        self.assertEqual(encoding.encode('ž', 'utf-8'), b'\xc5\xbe')
        self.assertEqual(encoding.encode('ž', 'latin-1', 'replace'), b'?')
        self.assertEqual(encoding.decode(b'\xff', 'utf-8', 'replace'), '\ufffd')
        self.assertEqual(encoding.decode(b'\xff', 'utf-8', 'ignore'), '')
        with self.assertRaises(TypeError):
            encoding.encode(b'not text', 'utf-8')
        with self.assertRaises(TypeError):
            encoding.decode('not bytes', 'utf-8')

    def test_errors_are_contextual_and_do_not_return_partial_content(self):
        with self.assertRaisesRegex(ValueError, "when decoding b'bad' with 'gzip'"):
            encoding.decode(b'bad', 'gzip')
        with self.assertRaisesRegex(ValueError, "when encoding 'x' with 'unknown'"):
            encoding.encode('x', 'unknown')
        with self.assertRaisesRegex(ValueError, "when decoding b'x' with 'unknown'"):
            encoding.decode(b'x', 'unknown')


if __name__ == '__main__':
    unittest.main()
