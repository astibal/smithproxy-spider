"""Public multipart-helper contracts observed from mitmproxy 12.3.1."""

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_modules import compatibility_modules


class MultipartHelperTests(unittest.TestCase):
    def setUp(self):
        modules = compatibility_modules()
        self.http = modules['mitmproxy.http']
        self.multipart = modules['mitmproxy.net.http.multipart']

    def test_public_helpers_and_request_view_share_one_representation(self):
        content_type = 'multipart/form-data; boundary=x'
        fields = [(b'a', b'first'), (b'a', b'second'), (b'b', b'line1\nline2')]
        wire = self.multipart.encode_multipart(content_type, fields)
        self.assertEqual(
            wire,
            b'--x\r\nContent-Disposition: form-data; name="a"\r\n'
            b'Content-Type: text/plain; charset=utf-8\r\n\r\nfirst\r\n\r\n'
            b'--x\r\nContent-Disposition: form-data; name="a"\r\n'
            b'Content-Type: text/plain; charset=utf-8\r\n\r\nsecond\r\n\r\n'
            b'--x\r\nContent-Disposition: form-data; name="b"\r\n'
            b'Content-Type: text/plain; charset=utf-8\r\n\r\nline1\nline2\r\n\r\n'
            b'--x--\r\n',
        )
        expected_view = [(b'a', b'first'), (b'a', b'second'), (b'b', b'line1line2')]
        self.assertEqual(self.multipart.decode_multipart(content_type, wire), expected_view)

        request = self.http.Request.make('POST', 'http://example.test/', wire,
                                         {'content-type': content_type})
        self.assertEqual(list(request.multipart_form.items(multi=True)), expected_view)

    def test_missing_and_literal_quoted_boundaries(self):
        body = (
            b'--x\r\nContent-Disposition: form-data; name="a"\r\n\r\nb\r\n'
            b'--x--\r\n'
        )
        self.assertEqual(self.multipart.decode_multipart(None, body), [])
        self.assertEqual(self.multipart.decode_multipart('multipart/form-data', body), [])
        self.assertEqual(
            self.multipart.decode_multipart('multipart/form-data; boundary="x"', body),
            [],
        )
        self.assertEqual(self.multipart.encode_multipart(None, [(b'a', b'b')]), b'')

    def test_legacy_names_preserve_reference_v12_behavior_and_warnings(self):
        content_type = 'multipart/form-data; boundary=x'
        fields = [(b'a', b'value')]
        expected = self.multipart.encode_multipart(content_type, fields)

        with self.assertWarnsRegex(
            DeprecationWarning,
            r'multipart\.decode is deprecated, use multipart\.decode_multipart instead\.',
        ):
            self.assertEqual(self.multipart.decode(content_type, fields), expected)

        with self.assertWarnsRegex(
            DeprecationWarning,
            r'multipart\.encode is deprecated, use multipart\.encode_multipart instead\.',
        ):
            self.assertEqual(self.multipart.encode(content_type, fields), expected)


if __name__ == '__main__':
    unittest.main()
