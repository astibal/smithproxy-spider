"""The application can diagnose its broker without starting proxy/UI services."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from auth_broker_test import responder

EXECUTABLE = sys.argv.pop()


class AuthBrokerCliTests(unittest.TestCase):
    def test_configuration_errors(self):
        for arguments in [('--auth-check', 'alice'), ('--auth-socket', ''),
                          ('--auth-socket', 'relative'), ('--auth-socket', '/' + 'x' * 108)]:
            with self.subTest(arguments=arguments):
                result = subprocess.run([EXECUTABLE, *arguments], input='secret\n', text=True,
                                        capture_output=True, timeout=4)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('secret', result.stdout + result.stderr)

    def test_diagnostic_uses_the_host_transport(self):
        with tempfile.TemporaryDirectory(prefix='spider-auth-cli-') as directory:
            path = Path(directory) / 'auth.sock'
            command = [EXECUTABLE, '--auth-socket', str(path), '--auth-check', 'alice']
            for status, code in [('accepted', 0), ('rejected', 1)]:
                body = json.dumps(dict(version=1, status=status, identity='alice', groups=['users'])).encode()
                with responder(path, body):
                    result = subprocess.run(command, input='secret\n', text=True,
                                            capture_output=True, timeout=4)
                self.assertEqual(result.returncode, code)
                self.assertEqual(result.stdout, status + '\n')
                self.assertEqual(result.stderr, '')

            result = subprocess.run(command, input='secret\n', text=True,
                                    capture_output=True, timeout=4)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, 'unavailable\n')


if __name__ == '__main__':
    unittest.main()
