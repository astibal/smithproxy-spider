"""Byte/text helper parity for public addon utilities."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

import addon_strutils as strutils


class StringUtilityTests(unittest.TestCase):
    def test_public_regex_constants(self):
        self.assertEqual(strutils.MULTILINE_CONTENT, r'[\s\S]*?')
        self.assertEqual(
            strutils.MULTILINE_CONTENT_LINE_CONTINUATION,
            r'(?:.|(?<=\\)\n)*?',
        )
        self.assertEqual(strutils.NO_ESCAPE, r'(?<!\\)(?:\\\\)*')
        self.assertEqual(strutils.SINGLELINE_CONTENT, r'.*?')

    def test_line_and_control_helpers_match_reference(self):
        self.assertEqual(strutils.clean_hanging_newline('line\n\n'), 'line\n')
        self.assertEqual(strutils.clean_hanging_newline(b'line\n'), b'line\n')
        self.assertEqual(strutils.cut_after_n_lines('one\ntwo\nthree', 2),
                         'one\ntwo\n')
        self.assertEqual(strutils.cut_after_n_lines('one\r\ntwo\r\nthree', 2),
                         'one\r\ntwo\r\n')
        with self.assertRaises(AssertionError):
            strutils.cut_after_n_lines('one', 0)
        self.assertEqual(
            strutils.escape_control_characters('a\x00b\x1fc\x7f'),
            'a.b.c.',
        )
        self.assertEqual(
            strutils.escape_control_characters('a\tb\nc\rd'),
            'a\tb\nc\rd',
        )
        self.assertEqual(
            strutils.escape_control_characters('a\tb\nc\rd', False),
            'a.b.c.d',
        )

    def test_binary_xml_and_hexdump_helpers_match_reference(self):
        self.assertFalse(strutils.is_mostly_bin(b''))
        self.assertTrue(strutils.is_mostly_bin(b'\x00'))
        self.assertFalse(strutils.is_mostly_bin(b'abc\x00'))
        self.assertTrue(strutils.is_mostly_bin(bytes(range(32))))
        self.assertFalse(strutils.is_mostly_bin(bytes(range(256))))
        self.assertTrue(strutils.is_xml(b'  <broken'))
        self.assertFalse(strutils.is_xml(b'\xef\xbb\xbf<root/>'))
        self.assertFalse(strutils.is_xml('<root/>'))
        self.assertEqual(list(strutils.hexdump(bytes(range(20)))), [
            ('0000000000',
             '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f',
             '................'),
            ('0000000010',
             '10 11 12 13                                    ',
             '....'),
        ])

    def test_special_area_helpers_match_reference(self):
        patterns = [r'/\*[\s\S]*?\*/', r'".*?"']
        self.assertEqual(
            strutils.split_special_areas('a "one" b /* two */ c', patterns),
            ['a ', '"one"', ' b ', '/* two */', ' c'],
        )
        quoted = ["'" + strutils.SINGLELINE_CONTENT + "'"]
        escaped = strutils.escape_special_areas(
            "before '{x}' after",
            quoted,
            '{}',
        )
        self.assertEqual(escaped, "before '\ue07bx\ue07d' after")
        self.assertEqual(strutils.unescape_special_areas(escaped),
                         "before '{x}' after")

    def test_reference_escaping_matrix(self):
        cases = {
            b'': '',
            b'hello': 'hello',
            b'line\nnext\tend\r': r'line\nnext\tend\r',
            b'\\"\'': '\\\\"\'',
            bytes(range(9)): r'\x00\x01\x02\x03\x04\x05\x06\x07\x08',
            b'\x7f\x80\xff': r'\x7f\x80\xff',
            'čaj'.encode(): r'\xc4\x8daj',
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(strutils.bytes_to_escaped_str(value), expected)

        self.assertEqual(
            strutils.bytes_to_escaped_str(b'line\nnext\tend\r', keep_spacing=True),
            'line\nnext\tend\r',
        )
        self.assertEqual(
            strutils.bytes_to_escaped_str(b"'", escape_single_quotes=True),
            r"\'",
        )

    def test_reference_unescaping_and_type_preservation(self):
        cases = {
            '': b'',
            'hello': b'hello',
            r'line\nnext': b'line\nnext',
            r'\x00\xff': b'\x00\xff',
            r'\q': b'\\q',
            'čaj': 'čaj'.encode(),
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(strutils.escaped_str_to_bytes(value), expected)
        with self.assertRaisesRegex(ValueError, 'Trailing'):
            strutils.escaped_str_to_bytes('tail\\')

        raw = b'value'
        text = 'value'
        self.assertIs(strutils.always_bytes(raw), raw)
        self.assertIs(strutils.always_str(text), text)
        self.assertIsNone(strutils.always_bytes(None))
        self.assertIsNone(strutils.always_str(None))
        self.assertEqual(strutils.always_bytes(text), raw)
        self.assertEqual(strutils.always_str(raw), text)
        with self.assertRaisesRegex(TypeError, 'but got int'):
            strutils.always_bytes(1)
        with self.assertRaisesRegex(ValueError, 'bytes, but is str'):
            strutils.bytes_to_escaped_str('value')
        with self.assertRaisesRegex(ValueError, 'str, but is bytes'):
            strutils.escaped_str_to_bytes(b'value')


if __name__ == '__main__':
    unittest.main()
