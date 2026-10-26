"""The packaged worker must retain normal python -c execution semantics."""
import json
import random
import subprocess
import sys
import unittest

from worker_bootstrap import packed


class WorkerBootstrapTests(unittest.TestCase):
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

    def test_incompressible_source_fails_at_build_time(self):
        source = random.Random(42).randbytes(200000).hex()

        with self.assertRaisesRegex(ValueError, 'argument budget'):
            packed(source)


if __name__ == '__main__':
    unittest.main()
