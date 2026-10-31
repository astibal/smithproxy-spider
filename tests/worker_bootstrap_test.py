"""The packaged worker must retain normal python -c execution semantics."""
import json
import random
import subprocess
import sys
import unittest
from pathlib import Path
import tempfile

from worker_bootstrap import addon_modules, packed, packed_arguments


class WorkerBootstrapTests(unittest.TestCase):
    def test_packing_is_reproducible(self):
        source = 'from fixture import value\nprint(value)\n'
        modules = {'fixture': 'value = "Unicode λ"\n'}
        self.assertEqual(packed(source, modules), packed(source, modules))

    def test_unused_addon_modules_are_not_executed(self):
        source = 'import sys\nprint("unused_addon" in sys.modules)\n'
        modules = {'unused_addon': 'raise RuntimeError("must not load")'}
        result = subprocess.run(
            [sys.executable, '-I', '-c', packed(source, modules)],
            check=True, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.stdout, 'False\n')

    def test_bundled_addon_modules_need_no_checkout_or_reference(self):
        root = Path(__file__).resolve().parents[1]
        modules = addon_modules(root)
        source = '''from __future__ import annotations
import json
import sys
from addon_loader import compile_script
from addon_http_message import Request
from addon_parts import H2MessageBinding
from addon_h2_events import H2AddonEvents
from addon_native import NativeAddonAdapter
from addon_flow import HTTPFlow
selection, code = compile_script("#!mitmproxy\\ndef request(flow): pass", "spider")
request = Request.make("GET", "https://example.org/?x=1&x=2")
request.query["x"] = "changed"
print(json.dumps([selection.api, request.path, "mitmproxy" in sys.modules]))
'''
        with tempfile.TemporaryDirectory() as directory:
            arguments = packed_arguments(source, modules)
            result = subprocess.run(
                [sys.executable, '-I', '-c', *arguments],
                cwd=directory, check=True, capture_output=True, text=True,
                timeout=5,
            )
        self.assertEqual(json.loads(result.stdout),
                         ['mitmproxy', '/?x=changed', False])

    def test_bundled_modules_register_before_dataclass_execution(self):
        module = ('from __future__ import annotations\n'
                  'from dataclasses import dataclass\n'
                  '@dataclass\nclass Item:\n    value: str\n')
        source = 'from item import Item\nprint(Item("ok").value)\n'
        result = subprocess.run(
            [sys.executable, '-I', '-c', packed(source, {'item': module})],
            check=True, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.stdout, 'ok\n')

    def test_invalid_module_names_fail_at_build_time(self):
        with self.assertRaisesRegex(ValueError, 'simple identifiers'):
            packed('pass', {'bad.module': 'pass'})

    def test_invalid_module_syntax_fails_at_build_time(self):
        with self.assertRaises(SyntaxError):
            packed('pass', {'broken': 'def incomplete('})

    def test_large_source_unicode_and_arguments(self):
        source = ('from __future__ import annotations\n' + '# padding\n' * 20000 +
                  'import json, sys\n'
                  'print(json.dumps(["Unicode λ", sys.argv, "__file__" in globals()]))\n')
        self.assertGreater(len(source), 128 * 1024)
        result = subprocess.run(
            [sys.executable, '-c', packed(source), '--persistent'],
            check=True, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(json.loads(result.stdout),
                         ['Unicode λ', ['-c', '--persistent'], False])

    def test_chunked_production_arguments_preserve_worker_arguments(self):
        # Random comments compress poorly enough to require several payload
        # arguments while remaining valid Python source.
        random_source = random.Random(7).randbytes(220000).hex()
        source = (
            'import json,sys\n' +
            '\n'.join('# ' + random_source[offset:offset + 100]
                      for offset in range(0, len(random_source), 100)) +
            '\nprint(json.dumps(sys.argv))\n'
        )
        arguments = packed_arguments(source)
        self.assertGreater(len(arguments), 3)
        self.assertTrue(all(len(value.encode()) < 120 * 1024
                            for value in arguments))
        result = subprocess.run(
            [sys.executable, '-I', '-c', *arguments, '--persistent'],
            check=True, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(json.loads(result.stdout), ['-c', '--persistent'])

    def test_chunked_packing_is_reproducible(self):
        source = 'from fixture import value\nprint(value)\n'
        modules = {'fixture': 'value = "Unicode λ"\n'}
        self.assertEqual(packed_arguments(source, modules),
                         packed_arguments(source, modules))

    def test_incompressible_source_fails_at_build_time(self):
        source = random.Random(42).randbytes(200000).hex()

        with self.assertRaisesRegex(ValueError, 'argument budget'):
            packed(source)


if __name__ == '__main__':
    unittest.main()
