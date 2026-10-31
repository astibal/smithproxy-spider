"""Public cookie helper contracts observed from mitmproxy 12.3.1."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

import addon_http_message
from addon_modules import compatibility_modules


class CookieHelperTests(unittest.TestCase):
    def setUp(self):
        modules = compatibility_modules()
        self.cookies = modules['mitmproxy.net.http.cookies']
        self.assertIs(modules['mitmproxy.http'].cookies, self.cookies)

    def test_request_parse_and_format(self):
        self.assertEqual(
            self.cookies.parse_cookie_header('a="x;y"; bare; x='),
            [['a', 'x;y'], ['bare', ''], ['x', '']],
        )
        self.assertEqual(
            self.cookies.parse_cookie_headers(['a=1', 'b=2; c=3']),
            [['a', '1'], ['b', '2'], ['c', '3']],
        )
        self.assertEqual(
            self.cookies.format_cookie_header(
                [('a', '1'), ('quoted', 'x y'), ('bare', None)]
            ),
            'a=1; quoted="x y"; bare',
        )

    def test_set_cookie_parse_format_and_grouping(self):
        parsed = self.cookies.parse_set_cookie_header(
            'a=1, b=2; Expires=Wed, 21 Oct 2015 07:28:00 GMT'
        )
        self.assertEqual(
            [(name, value, attrs.fields) for name, value, attrs in parsed],
            [('a', '1', ()),
             ('b', '2', (('Expires', 'Wed, 21 Oct 2015 07:28:00 GMT'),))],
        )
        attrs = self.cookies.CookieAttrs([('Path', '/'), ('Secure', None)])
        self.assertEqual(
            self.cookies.format_set_cookie_header([('a', '1', attrs)]),
            'a=1; Path=/; Secure',
        )
        grouped = self.cookies.group_cookies([
            ('a', '1'), ('Path', '/'), ('b', '2'), ('Secure', None),
        ])
        self.assertEqual(
            [(name, value, item.fields) for name, value, item in grouped],
            [('a', '1', (('Path', '/'),)),
             ('b', '2', (('Secure', None),))],
        )

    def test_expiry_and_refresh_contract(self):
        with patch.object(addon_http_message.time, 'time', return_value=1000):
            self.assertEqual(
                self.cookies.get_expiration_ts(
                    self.cookies.CookieAttrs([('Max-Age', '10')])
                ),
                1010,
            )
            self.assertTrue(
                self.cookies.is_expired(
                    self.cookies.CookieAttrs([('Max-Age', '-2')])
                )
            )

        expires = self.cookies.CookieAttrs([
            ('Expires', 'Wed, 21 Oct 2015 07:28:00 GMT'),
            ('Max-Age', '10'),
        ])
        self.assertEqual(self.cookies.get_expiration_ts(expires), 1445412480)
        self.assertEqual(
            self.cookies.refresh_set_cookie_header(
                'a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT',
                60,
            ),
            'a=1; Expires=Wed, 21 Oct 2015 07:29:00 GMT',
        )
        self.assertEqual(
            self.cookies.refresh_set_cookie_header('a=1; Expires=invalid', 60),
            'a=1',
        )
        self.assertEqual(
            self.cookies.refresh_set_cookie_header(
                'a=; Expires=Wed, 21 Oct 2015 07:28:00 GMT',
                60,
            ),
            'a=; Expires=Wed, 21 Oct 2015 07:29:00 GMT',
        )
        with self.assertRaisesRegex(ValueError, 'Invalid Cookie'):
            self.cookies.refresh_set_cookie_header('bare', 60)
        with self.assertRaisesRegex(ValueError, 'Invalid Cookie'):
            self.cookies.refresh_set_cookie_header(
                '=; Expires=Wed, 21 Oct 2015 07:28:00 GMT',
                60,
            )


if __name__ == '__main__':
    unittest.main()
