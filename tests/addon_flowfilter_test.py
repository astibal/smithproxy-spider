"""Clean-room flow-filter parity against public 12.3.1 observations."""

from pathlib import Path
import json
import os
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

import addon_connection as connection
import addon_flow as flow
import addon_flowfilter as flowfilter
import addon_http_message as http
import addon_dns as dns
from addon_flowfilter_contract import collect
from addon_flowfilter_edges_contract import collect as collect_edges

HTTP = SimpleNamespace(
    HTTPFlow=flow.HTTPFlow,
    Request=http.Request,
    Response=http.Response,
)


def peers(transport):
    return (
        connection.Client(
            peername=('10.0.0.5', 54321),
            sockname=('10.0.0.1', 8080),
            transport_protocol=transport,
        ),
        connection.Server(
            address=('example.org', 443),
            transport_protocol=transport,
        ),
    )


class FlowFilterTests(unittest.TestCase):
    def test_adversarial_parser_matches_reference_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_flowfilter_edges_v12.json').read_text()
        )
        self.assertEqual(corpus['reference'], 'mitmproxy 12.3.1')
        self.assertEqual(collect_edges(flowfilter), corpus['cases'])

    def test_dns_filter_matches_the_public_dns_flow_model(self):
        item = dns.DNSFlow(*peers('udp'))
        self.assertTrue(flowfilter.match('~dns', item))
        self.assertTrue(flowfilter.match('~all', item))
        self.assertFalse(flowfilter.match('~udp', item))

    def test_reference_http_transport_and_logic_matrix(self):
        actual = collect(flowfilter, HTTP, flow, flow, flow, peers)
        all_names = {'pending', 'completed', 'failed', 'websocket', 'asset', 'tcp', 'udp'}
        http_names = {'pending', 'completed', 'failed', 'websocket', 'asset'}
        responses = {'completed', 'failed', 'websocket', 'asset'}
        html_responses = {'completed', 'failed', 'websocket'}
        expected = {
            '~all': all_names,
            '~http': http_names,
            '~tcp': {'tcp'},
            '~udp': {'udp'},
            '~dns': set(),
            '~websocket': {'websocket'},
            '~q': {'pending'},
            '~s': responses,
            '~e': {'failed'},
            '~marked': http_names,
            '~marker warning': http_names,
            '~comment useful': http_names,
            '~meta fixture': http_names,
            '~replay': http_names,
            '~replayq': http_names,
            '~replays': set(),
            '~m get': http_names,
            '~d example\\.org': http_names,
            '~u path\\?q=1': http_names,
            '~c 201': responses,
            '~h x-test: one': set(),
            '~h "x-test: one"': http_names,
            '~hq x-test': http_names,
            '~hs x-response': responses,
            '~b hello': http_names,
            '~bq request': http_names,
            '~bs response': responses,
            '~t text/html': html_responses,
            '~tq application/json': http_names,
            '~ts text/html': html_responses,
            '~a': {'asset'},
            '~src 10\\.0\\.0\\.5': all_names,
            '~dst example\\.org:443': all_names,
            '~q ~m GET': {'pending'},
            '~q & ~m GET': {'pending'},
            '~q | ~tcp': {'pending', 'tcp'},
            '!(~q & ~t "text/html")': all_names,
            'example\\.org': http_names,
            'example\\.org path': http_names,
        }
        for expression, matches in expected.items():
            with self.subTest(expression=expression):
                observed = actual['match/' + expression]
                self.assertEqual(
                    {name for name, matched in observed.items() if matched},
                    matches,
                )
        self.assertEqual(
            {name for name, matched in actual['match/none'].items() if matched},
            all_names,
        )

    def test_reference_errors_and_descriptions(self):
        actual = collect(flowfilter, HTTP, flow, flow, flow, peers)
        expected_errors = {
            '': 'Empty filter expression',
            ' ': "Invalid filter expression: ' '",
            '~bogus': "Invalid filter expression: '~bogus'",
            '(': "Invalid filter expression: '('",
            '~c x': "Invalid filter expression: '~c x'",
            '~u': "Invalid filter expression: '~u'",
            '~q |': "Invalid filter expression: '~q |'",
            '()': "Invalid filter expression: '()'",
            '~u [': "Invalid filter expression: '~u ['",
        }
        for expression, message in expected_errors.items():
            with self.subTest(expression=expression):
                self.assertEqual(
                    actual['invalid/' + repr(expression)],
                    {'error': 'ValueError', 'message': message},
                )

        self.assertEqual(actual['describe/.'], {
            'type': 'FUrl', 'text': 'url matches /./i',
        })
        self.assertEqual(actual['describe/~all'], {
            'type': 'FAll', 'text': 'all flows',
        })
        self.assertEqual(actual['describe/~q ~m GET'], {
            'type': 'FAnd', 'text': 'has no response and method matches /GET/i',
        })
        self.assertEqual(actual['describe/!(~q & ~t "text/html")'], {
            'type': 'FNot',
            'text': 'not (has no response and content type matches /text/html/i)',
        })

    def test_documented_case_sensitive_environment_switch(self):
        client, server = peers('tcp')
        item = flow.HTTPFlow(client, server, live=True)
        item.request = http.Request.make('GET', 'https://example.org/')

        self.assertTrue(flowfilter.match('~m get', item))
        insensitive = flowfilter.parse('~m get')
        with patch.dict(os.environ, {'MITMPROXY_CASE_SENSITIVE_FILTERS': '1'}):
            self.assertFalse(flowfilter.match('~m get', item))
            self.assertTrue(flowfilter.match('~m GET', item))
            self.assertEqual(str(insensitive), 'method matches /get/i')

            sensitive = flowfilter.parse('~m GET')
        self.assertEqual(str(sensitive), 'method matches /GET/')

    def test_reference_regex_modes_and_public_descriptions(self):
        client, server = peers('tcp')
        item = flow.HTTPFlow(client, server, live=True)
        item.request = http.Request.make(
            'POST', 'https://example.org/', b'first\nsecond')
        item.comment = 'first\nsecond'
        item.metadata = {'note': 'first\nsecond'}

        self.assertTrue(flowfilter.match('~bq "first.second"', item))
        self.assertTrue(flowfilter.match('~comment "^second$"', item))
        self.assertTrue(flowfilter.match('~meta "^second$"', item))
        descriptions = {
            '~a': 'is asset',
            '~bq x': 'body request matches /x/is',
            '~c 200': 'response code is 200',
            '~comment x': 'comment matches /x/im',
            '~dns': 'is a DNS Flow',
            '~e': 'has error',
            '~hq x': 'req. header matches /x/im',
            '~http': 'is an HTTP Flow',
            '~marked': 'is marked',
            '~meta x': 'flow metadata matches /x/im',
            '~replayq': 'request has been replayed',
            '~s': 'has response',
            '~tcp': 'is a TCP Flow',
            '~tq x': 'req. content type matches /x/i',
            '~udp': 'is a UDP Flow',
            '~websocket': 'is a Websocket Flow',
        }
        for expression, expected in descriptions.items():
            with self.subTest(expression=expression):
                self.assertEqual(str(flowfilter.parse(expression)), expected)

    def test_reference_nested_expression_descriptions(self):
        descriptions = {
            '!~q': 'not has no response',
            '!!~q': 'not not has no response',
            '~q & ~s & ~e': 'has no response and has response and has error',
            '~q | ~s | ~e': 'has no response or has response or has error',
            '~q | ~s & ~m GET':
                'has no response or (has response and method matches /GET/i)',
            '( ~q | ~s ) & ~m GET':
                '(has no response or has response) and method matches /GET/i',
            '!(~q & ~t "text/html")':
                'not (has no response and content type matches /text/html/i)',
        }
        for expression, expected in descriptions.items():
            with self.subTest(expression=expression):
                self.assertEqual(str(flowfilter.parse(expression)), expected)

    def test_reference_operator_and_parenthesis_boundaries(self):
        invalid = (
            '~q& ~m GET',
            '~q|~s',
            '(~q)',
            '(~q | ~s)',
        )
        for expression in invalid:
            with self.subTest(expression=expression):
                with self.assertRaisesRegex(ValueError, 'Invalid filter expression'):
                    flowfilter.parse(expression)

        descriptions = {
            '~q &~m GET': 'has no response and method matches /GET/i',
            '( ~q )&~s': 'has no response and has response',
            '~m GET&~q': 'method matches /GET&/i and has no response',
            '~m GET| ~s': 'method matches /GET|/i and has response',
            '( ~q )': 'has no response',
        }
        for expression, expected in descriptions.items():
            with self.subTest(expression=expression):
                self.assertEqual(str(flowfilter.parse(expression)), expected)


if __name__ == '__main__':
    unittest.main()
