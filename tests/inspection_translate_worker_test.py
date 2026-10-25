"""Live module checkpoints across fresh, sandboxed workers (no worker affinity)."""
import base64
from pathlib import Path
import re
import unittest

import hpack
from inspection_cookbook_test import run
from inspection_h2_test import frame, unpack, Oracle


def event(data, side='L'):
    return {'id': 'translate', 'details': {'info': {
        'side': side, 'content': base64.b64encode(data).decode(),
        'content_annotations': [[0, 9, 'h2.frame.header']],
    }}}


class TranslateWorkerTests(unittest.TestCase):
    def test_documented_examples_with_real_dynamic_indices(self):
        documentation = (Path(__file__).resolve().parents[1] / 'docs/H2_TRANSLATE_LIVE.md').read_text()
        examples = dict(re.findall(
            r'<!-- translate-example: ([\w-]+) -->\s*```python\n(.*?)```',
            documentation, re.S,
        ))
        self.assertEqual(set(examples), {
            'replace-header', 'unchanged', 'indexed-once', 'missing-translate', 'hold-incomplete',
        })

        for name in ('replace-header', 'unchanged', 'indexed-once'):
            with self.subTest(example=name):
                sender, receiver = hpack.Encoder(), Oracle()
                checkpoint, user_state = None, {}

                for turn in range(1, 4):
                    block = sender.encode([(b'x-lab', b'original')], huffman=False)

                    if turn > 1:
                        self.assertEqual(block, b'\xbe')  # Source dynamic index 62.

                    result = run(
                        examples[name], event(frame(block, 1, 4, 3)),
                        translate_allowed=turn == 1, translate_active=turn > 1,
                        translate_state=checkpoint, instance_state=user_state,
                    )
                    self.assertTrue(result['ok'], result)
                    checkpoint = result['translate_state']
                    user_state = result['instance_state']
                    value = b'original'

                    if name == 'replace-header':
                        value = b'spider'
                    elif name == 'indexed-once' and turn == 2:
                        value = b'changed'

                    output = base64.b64decode(result['replacement'])
                    self.assertEqual(receiver.decode(unpack(output)[0][3]), [(b'x-lab', value)])

                failure = run(
                    examples['missing-translate'], event(frame(b'\xbe', 1, 4, 3)),
                    translate_active=True, translate_state=checkpoint,
                )
                self.assertFalse(failure['ok'], failure)
                self.assertIn('requires return api.message.translate()', failure['error'])
                self.assertIsNone(failure['replacement'])
                self.assertNotIn('translate_state', failure)

    def test_tables_survive_fresh_workers_and_every_callback_is_explicit(self):
        sender, receiver = hpack.Encoder(), Oracle()
        state = None
        for turn in range(20):
            original = [(b'x-lab', b'original')]
            wire = frame(sender.encode(original, huffman=False), 1, 4, 3)
            script = ('api.message.parts[0].headers.set_header(b"x-lab", b"changed")\n'
                      if turn == 0 else '') + 'return api.message.translate()'
            result = run(script, event(wire), translate_allowed=turn == 0,
                         translate_active=turn != 0, translate_state=state)
            self.assertTrue(result['ok'], result)
            self.assertTrue(result['translated'])
            state = result['translate_state']
            output = base64.b64decode(result['replacement'])
            expected = [(b'x-lab', b'changed')] if turn == 0 else original
            self.assertEqual(receiver.decode(unpack(output)[0][3]), expected)

        for script in ('return None', 'return api.message.commit()',
                       'api.message.translate()\nraise ValueError("after")'):
            result = run(script, event(frame(sender.encode(original), 1, 4, 3)),
                         translate_active=True, translate_state=state)
            self.assertFalse(result['ok'], result)
            self.assertIsNone(result['replacement'])
            self.assertNotIn('translate_state', result)

    def test_default_settings_and_data_are_translated_explicitly(self):
        for wire in (frame(b'', 4, 0, 0), frame(b'body')):
            result = run('return api.message.translate()', event(wire), translate_allowed=True)
            self.assertTrue(result['ok'], result)
            self.assertEqual(base64.b64decode(result['replacement']), wire)

    def test_unsupported_input_does_not_break_regular_rewrite(self):
        wire = frame(b'\x00\x01\x00\x01\x00\x00', 4, 0, 0)
        for script, expected in (('return None', True), ('return api.message.translate()', False)):
            result = run(script, event(wire), translate_allowed=True)
            self.assertEqual(result['ok'], expected, result)

    def test_table_roundtrip_after_input_resize_and_eviction(self):
        sender, receiver = hpack.Encoder(), Oracle()
        sender.header_table_size = 128
        state = None
        for turn in range(12):
            fields = [(b'x', str(turn % 3).encode() * 30)]
            result = run('return api.message.translate()', event(frame(sender.encode(fields), 1, 4)),
                         translate_allowed=state is None, translate_active=state is not None,
                         translate_state=state)
            self.assertTrue(result['ok'], result)
            state = result['translate_state']
            self.assertEqual(receiver.decode(unpack(base64.b64decode(result['replacement']))[0][3]), fields)

    def test_failed_assembly_retry_keeps_output_table_atomic(self):
        wire = frame(b'\x40\x01x\x03old', 1, 4)
        script = '''
part = api.message.parts[0]
part.max_frame_size = 1
try:
    api.message.translate()
except CommitException:
    part.max_frame_size = 16384
return api.message.translate()
'''
        result = run(script, event(wire), translate_allowed=True)
        self.assertTrue(result['ok'], result)
        self.assertEqual(Oracle().decode(unpack(base64.b64decode(result['replacement']))[0][3]), [(b'x', b'old')])


if __name__ == '__main__':
    unittest.main()
