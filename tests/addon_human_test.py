"""Public human-formatting contracts observed from mitmproxy 12.3.1."""

from contextlib import contextmanager
import os
from pathlib import Path
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_modules import compatibility_modules


@contextmanager
def utc_timezone():
    previous = os.environ.get('TZ')
    os.environ['TZ'] = 'UTC'
    time.tzset()
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = previous
        time.tzset()


class HumanTests(unittest.TestCase):
    def setUp(self):
        self.human = compatibility_modules()['mitmproxy.utils.human']

    def test_duration_boundaries(self):
        cases = {
            None: '', 0: '0ms', 0.0005: '0ms', 0.0009: '1ms',
            0.999: '999ms', 1: '1.00s', 9.99: '9.99s', 10: '10.0s',
            99.9: '99.9s', 100: '100s', 3600: '3600s', -0.001: '-1ms',
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(self.human.pretty_duration(value), expected)

    def test_size_boundaries(self):
        cases = {
            -1: '-1b', 0: '0b', 1023: '1023b', 1024: '1.0k',
            10240: '10.0k', 102400: '100k', 1024 ** 2: '1.0m',
            1024 ** 3: '1.0g', 1024 ** 4: '1.0t', 1024 ** 5: '1024t',
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(self.human.pretty_size(value), expected)

    def test_size_parser(self):
        cases = {
            None: None, 0: 0, 1.5: 1, '0': 0, '1b': 1,
            '1k': 1024, '10m': 10 * 1024 ** 2,
            '2g': 2 * 1024 ** 3, '1t': 1024 ** 4,
            ' 1k': 1024, '+1k': 1024, '-1k': -1024,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(self.human.parse_size(value), expected)
        for value in ('', '1.5k', '1K', '1kb', 'abc'):
            with self.subTest(invalid=value):
                with self.assertRaisesRegex(ValueError, 'Invalid size specification'):
                    self.human.parse_size(value)

    def test_address_formatter(self):
        cases = {
            None: '<no address>',
            ('127.0.0.1', 80): '127.0.0.1:80',
            ('::1', 443): '[::1]:443',
            ('fe80::1%eth0', 53): '[fe80::1%eth0]:53',
            ('example.test', 0): 'example.test:0',
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(self.human.format_address(value), expected)

    def test_local_timestamp_format_and_millisecond_truncation(self):
        with utc_timezone():
            self.assertEqual(self.human.format_timestamp(0), '1970-01-01 00:00:00')
            self.assertEqual(
                self.human.format_timestamp_with_milli(1.2345),
                '1970-01-01 00:00:01.234',
            )
            self.assertEqual(
                self.human.format_timestamp_with_milli(-0.001),
                '1969-12-31 23:59:59.999',
            )


if __name__ == '__main__':
    unittest.main()
