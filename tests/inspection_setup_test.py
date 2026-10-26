"""Setup and content run in the same real sandboxed script API."""
import base64
import unittest

from inspection_cookbook_test import run, fixture


def setup_event():
    return {'action': 'connection-start', 'id': 'setup-test', 'details': {'info': {
        'phase': 'setup', 'session': 'tcp://127.0.0.1:1234-tcp://127.0.0.2:80',
        'destination': {'host': '127.0.0.2', 'port': '80'},
        'webhook_control': {'version': 1, 'sequence': 0, 'rewrite': False},
    }}}


class SetupTests(unittest.TestCase):
    def test_legacy_missing_permission_is_not_explicit_denial(self):
        for control, allowed in (({}, True), ({'version': 1, 'sequence': 1}, True),
                                 ({'rewrite': True}, True), ({'rewrite': False}, False)):
            with self.subTest(control=control):
                event = fixture('h1')
                event['details']['info']['webhook_control'] = control
                result = run("return api.bytes + b'x'", event)
                self.assertEqual(result['ok'], allowed, result)
                if allowed:
                    original = base64.b64decode(event['details']['info']['content'])
                    self.assertEqual(base64.b64decode(result['replacement']), original + b'x')
                else:
                    self.assertIsNone(result['replacement'])
                    self.assertIn('not reserved at connection-start', result['error'])

    def test_explicit_opt_in_without_fake_payload(self):
        result = run("assert api.phase == 'setup'\nassert api.message is None\n"
                     "assert not api.bytes\napi.connection.request_rewrite()\n"
                     "api.connection.request_rewrite()\napi.state['armed'] = True", setup_event())
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['rewrite_requested'])
        self.assertIsNone(result['replacement'])
        self.assertEqual(result['instance_state'], {'armed': True})
        self.assertNotIn('translated', result)

    def test_read_only_by_default(self):
        result = run('return None', setup_event())
        self.assertTrue(result['ok'], result)
        self.assertFalse(result['rewrite_requested'])

    def test_failed_setup_does_not_publish_permission(self):
        for suffix in ("raise ValueError('broken')", "return b'x'", "return b''",
                       'api.connection.set_mode(Mode.Translate)', 'api.message.commit()'):
            with self.subTest(suffix=suffix):
                result = run('api.connection.request_rewrite()\n' + suffix, setup_event(),
                             instance={'mode': 'flow'})
                self.assertFalse(result['ok'], result)
                self.assertIsNone(result['replacement'])
                self.assertNotIn('rewrite_requested', result)

    def test_late_opt_in_fails(self):
        result = run('api.connection.request_rewrite()', fixture('h1'))
        self.assertFalse(result['ok'], result)
        self.assertIn('only allowed during connection-start setup', result['error'])

    def test_same_script_carries_state_from_setup_to_content(self):
        script = ("if api.phase == 'setup':\n"
                  "    api.connection.request_rewrite()\n"
                  "    api.state['target'] = api.info['destination']['host']\n"
                  "    return\n"
                  "assert api.phase == 'content'\n"
                  "assert api.state['target'] == '127.0.0.2'\n"
                  "return api.message.commit()")
        setup = run(script, setup_event(), instance={'mode': 'flow'})
        event = fixture('h1')
        event['details']['info']['webhook_control'] = {'rewrite': True}
        result = run(script, event, instance={'mode': 'flow'}, instance_state=setup['instance_state'])
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['replacement'], event['details']['info']['content'])

    def test_unreserved_content_accepts_same_size_in_easy_and_expert(self):
        for kind in ('h1', 'h2', 'opaque'):
            event = fixture(kind)
            event['details']['info']['webhook_control'] = {'rewrite': False}
            original = base64.b64decode(event['details']['info']['content'])

            for safety in ('Easy', 'Expert'):
                with self.subTest(kind=kind, safety=safety):
                    result = run(f'return api.message.commit(safety=Safety.{safety})', event)
                    self.assertTrue(result['ok'], result)
                    self.assertEqual(base64.b64decode(result['replacement']), original)

            # No body-only restriction: even replacing headers with arbitrary
            # bytes is permitted. It does NOT promise a coherent protocol.
            for expression in ("b'x' * len(api.bytes)", "bytearray(b'x' * len(api.bytes))",
                               "memoryview(b'x' * len(api.bytes))", "'x' * len(api.bytes)"):
                with self.subTest(kind=kind, expression=expression):
                    result = run('return ' + expression, event)
                    self.assertTrue(result['ok'], result)
                    self.assertEqual(base64.b64decode(result['replacement']), b'x' * len(original))
                    self.assertNotIn('translated', result)
                    self.assertIsNone(result['held_parts'])

    def test_unreserved_content_rejects_length_changes(self):
        event = fixture('h1')
        event['details']['info']['webhook_control'] = {'rewrite': False}
        for script in ("return b''", "return api.bytes[:-1]", "return api.bytes + b'x'",
                       "api.bytes = b'x'\nreturn b'y'"):
            with self.subTest(script=script):
                result = run(script, event)
                self.assertFalse(result['ok'], result)
                self.assertIn('not reserved at connection-start', result['error'])
                self.assertIsNone(result['replacement'])
        self.assertTrue(run('return None', event)['ok'])

    def test_size_is_measured_in_encoded_bytes_not_characters_or_elements(self):
        event = fixture('opaque')  # Eight wire bytes.
        event['details']['info']['webhook_control'] = {'rewrite': False}
        for script in ("return '\u00e9' * 4", "return memoryview(b'x' * 8).cast('H')"):
            result = run(script, event)
            self.assertTrue(result['ok'], result)
            self.assertEqual(len(base64.b64decode(result['replacement'])), 8)

        result = run("return '\u00e9' * len(api.bytes)", event)
        self.assertFalse(result['ok'], result)
        self.assertIn('Length-changing rewrite', result['error'])

    def test_same_size_exception_does_not_authorize_hold(self):
        event = fixture('opaque')
        event['details']['info']['webhook_control'] = {'rewrite': False}
        # The exception is for plain replacements, not ownership of held input.
        script = ("part = api.message.parts[0]\n"
                  "api.message.parts.hold_from(part)\n"
                  "return api.message.commit()")
        result = run(script, event, hold_allowed=True, instance={'mode': 'flow'})
        self.assertFalse(result['ok'], result)
        self.assertIn('Hold and Translate require', result['error'])
        self.assertNotIn('held_parts', result)
        self.assertIsNone(result['replacement'])


if __name__ == '__main__':
    unittest.main()
