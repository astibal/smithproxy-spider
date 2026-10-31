"""Public HTTP validation contracts observed from mitmproxy 12.3.1."""

from pathlib import Path
import sys
from typing import get_args
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_modules import compatibility_modules


class HttpValidateTests(unittest.TestCase):
    def setUp(self):
        modules = compatibility_modules()
        self.http = modules['mitmproxy.http']
        self.validate = modules['mitmproxy.net.http.validate']

    def test_content_length_contract(self):
        for value, expected in (
            ('0', 0), ('1', 1), (b'42', 42),
            ('18446744073709551616', 18446744073709551616),
        ):
            self.assertEqual(self.validate.parse_content_length(value), expected)
        for value in ('', '00', '-1', '+1', ' 1', '1 ', '1,1', '1_0'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate.parse_content_length(value)

    def test_transfer_encoding_contract(self):
        self.assertEqual(get_args(self.validate.TransferEncoding), (
            'chunked',
            'compress,chunked',
            'deflate,chunked',
            'gzip,chunked',
            'compress',
            'deflate',
            'gzip',
            'identity',
        ))
        accepted = {
            'chunked': 'chunked',
            'Chunked': 'chunked',
            'gzip, chunked': 'gzip,chunked',
            'gzip,\tchunked': 'gzip,chunked',
            b'deflate, chunked': 'deflate,chunked',
            'identity': 'identity',
        }
        for value, expected in accepted.items():
            self.assertEqual(self.validate.parse_transfer_encoding(value), expected)
        for value in ('', ' gzip, chunked ', 'br', 'trailers', 'gzip,,chunked', 'é'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate.parse_transfer_encoding(value)

    def message(self, *, request=True, version='HTTP/1.1', status=200, fields=()):
        if request:
            message = self.http.Request.make('GET', 'http://example.test/')
        else:
            message = self.http.Response.make(status)
        message.http_version = version
        message.headers = self.http.Headers(fields)
        return message

    def test_message_validation_contract(self):
        self.assertIsNone(self.validate.validate_headers(self.message()))
        self.assertIsNone(self.validate.validate_headers(self.message(
            fields=((b'transfer-encoding', b'gzip, chunked'),))))
        self.assertIsNone(self.validate.validate_headers(self.message(
            request=False, fields=((b'transfer-encoding', b'gzip'),))))

        failures = (
            self.message(fields=((b'content-length', b'00'),)),
            self.message(fields=((b'content-length', b'1'), (b'content-length', b'1'))),
            self.message(fields=((b'content-length', b'1'),
                                 (b'transfer-encoding', b'chunked'))),
            self.message(version='HTTP/2.0',
                         fields=((b'transfer-encoding', b'chunked'),)),
            self.message(fields=((b'transfer-encoding', b'gzip'),)),
            self.message(request=False, status=204,
                         fields=((b'transfer-encoding', b'chunked'),)),
        )
        for message in failures:
            with self.subTest(message=message), self.assertRaises(ValueError):
                self.validate.validate_headers(message)

        self.assertIsNone(self.validate.validate_headers(self.message(
            request=False, status=304,
            fields=((b'transfer-encoding', b'chunked'),),
        )))


if __name__ == '__main__':
    unittest.main()
