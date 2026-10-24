import importlib.util
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
import inspection_language as language
from inspection_api import api_schema
language.api_schema = api_schema


@unittest.skipUnless(importlib.util.find_spec('jedi'), 'optional Jedi dependency unavailable')
class LanguageTests(unittest.TestCase):
    def query(self, source, action='complete', line=None, column=None):
        lines = source.split('\n')
        return language.language_query({'script': source, 'language_action': action,
            'line': line or len(lines), 'column': len(lines[-1]) if column is None else column})

    def labels(self, source):
        return {item['label'] for item in self.query(source)['items']}

    def test_alias_and_iteration(self):
        self.assertIn('header_blocks', self.labels('h2 = api.http2\nh2.'))
        self.assertIn('stream_id', self.labels('for frame in api.http2.frames:\n    frame.'))
        self.assertIn('value', self.labels('for block in api.http2.header_blocks:\n    for header in block.headers:\n        header.'))
        self.assertIn('upper', self.labels('value = "hello"\nvalue.'))
        self.assertIn('increment', self.labels('shared = api.storage.namespace("stats")\nshared.'))
        self.assertIn('get', self.labels('state = api.state\nstate.'))
        self.assertIn('commit', self.labels('draft = api.message.snapshot()\ndraft.'))
        self.assertIn('set_header', self.labels('draft = api.message.snapshot()\ndraft.http1.'))

    def test_scope(self):
        self.assertNotIn('stream_id', self.labels('frame = api.http2.frames[0]\ndef f(frame: str):\n    frame.'))
        self.assertIn('upper', self.labels('frame = api.http2.frames[0]\ndef f(frame: str):\n    frame.'))

    def test_help_and_signatures(self):
        result = self.query('for frame in api.http2.frames:\n    frame', 'hover')
        self.assertTrue(any('H2Frame' in item['detail'] for item in result['items']))
        result = self.query('h2 = api.http2\nh2.available', 'hover')
        self.assertTrue(any('HTTP/2' in item['info'] for item in result['items']))
        result = self.query('api.hexdump(', 'signature')
        self.assertIn('limit', result['items'][0]['label'])

    def test_syntax_mapping_and_no_execution(self):
        result = self.query('if True\n    return None', 'diagnostics')
        self.assertEqual(result['diagnostics'][0]['line'], 1)
        result = self.query('raise RuntimeError("never execute")\nx = api.http2\nx.')
        self.assertTrue(result['ok'])
        self.assertIn('frames', {item['label'] for item in result['items']})
        self.assertEqual(self.query('return None', 'diagnostics')['diagnostics'], [])

    def test_validation(self):
        with self.assertRaises(ValueError):
            self.query('x', column=20)
        with self.assertRaises(ValueError):
            self.query('x' * 65537)


if __name__ == '__main__':
    unittest.main()
