"""Exercise the real concatenated worker in disposable child processes."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = '\n'.join((ROOT / 'src' / name).read_text() for name in (
    'inspection_api.py', 'inspection_h2.py', 'inspection_hold.py', 'inspection_language.py', 'inspection_sandbox.py', 'inspection_worker.py'))


class SandboxTests(unittest.TestCase):
    def run_script(self, script, worker_source=SOURCE, **extra):
        request = {'script': script, 'event': {'details': {'info': {
            'content': base64.b64encode(b'hello').decode()}}}, **extra}
        result = subprocess.run([sys.executable, '-I', '-c', worker_source],
                                input=json.dumps(request), capture_output=True,
                                text=True, timeout=8, env={'PATH': '/usr/bin:/bin'})
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_supported_operations(self):
        result = self.run_script('''import json, re, math, zlib
api.state['answer'] = math.sqrt(81)
api.print(json.dumps({'text': re.sub('h', 'H', api.text)}))
return zlib.decompress(zlib.compress(api.bytes))''')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['instance_state'], {'answer': 9})
        self.assertEqual(base64.b64decode(result['replacement']), b'hello')

    def test_denied_operations(self):
        operations = {
            'read secrets': "open('/etc/passwd').read()",
            'read proc': "open('/proc/self/environ', 'rb').read()",
            'list home': "__import__('os').listdir('/home')",
            'write outside storage': "open('/tmp/spider-sandbox-must-not-exist', 'w')",
            'tcp socket': "__import__('socket').socket()",
            'unix socket': "__import__('socket').socket(__import__('socket').AF_UNIX)",
            'fork': "__import__('os').fork()",
            'exec': "__import__('os').execv('/bin/true', ['true'])",
            'signal': "__import__('os').kill(__import__('os').getppid(), 0)",
            'session escape': "__import__('os').setsid()",
            'async signal owner': "import fcntl, os\nfcntl.fcntl(1, fcntl.F_SETOWN, os.getppid())",
            'raise limits': "__import__('resource').setrlimit(__import__('resource').RLIMIT_CPU, (9, 9))",
        }
        for name, operation in operations.items():
            with self.subTest(name=name):
                result = self.run_script(operation)
                self.assertFalse(result['ok'], result)
                if name == 'raise limits':
                    self.assertIn('not allowed to raise maximum limit', result['error'])
                else:
                    self.assertIn('PermissionError', result['error'])

    def test_storage_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            storage = root / 'storage'
            storage.mkdir()
            secret = root / 'secret'
            secret.write_text('untouched')
            (storage / 'escape').symlink_to(secret)
            result = self.run_script("s = api.storage.namespace('test')\napi.print(s.increment('n'))",
                                     storage_directory=str(storage))
            self.assertTrue(result['ok'], result)
            result = self.run_script("api.print(api.storage.namespace('test').get('n'))",
                                     storage_directory=str(storage))
            self.assertEqual(result['logs'], ['1'])
            for mode in ('r', 'w'):
                result = self.run_script(f"open({str(storage / 'escape')!r}, {mode!r})",
                                         storage_directory=str(storage))
                self.assertFalse(result['ok'], result)
            self.assertEqual(secret.read_text(), 'untouched')

    def test_fail_closed(self):
        result = self.run_script("raise AssertionError('must not execute')", storage_directory='/')
        self.assertEqual(result['error_kind'], 'sandbox_unavailable')
        self.assertNotIn('AssertionError', result['error'])

    def test_missing_kernel_and_library_fail_closed(self):
        for original, replacement in (
            ('abi = libc.syscall(create, 0, 0, 1)', 'abi = -1'),
            ("ctypes.CDLL('libseccomp.so.2', use_errno=True)",
             "ctypes.CDLL('lib-spider-deliberately-missing.so', use_errno=True)"),
        ):
            with self.subTest(failure=original):
                self.assertIn(original, SOURCE)
                result = self.run_script("raise AssertionError('must not execute')",
                                         worker_source=SOURCE.replace(original, replacement))
                self.assertEqual(result['error_kind'], 'sandbox_unavailable')
                self.assertNotIn('AssertionError', result['error'])

    def test_native_calls_cannot_bypass_policy(self):
        result = self.run_script('''import ctypes, errno
c = ctypes.CDLL(None, use_errno=True)
assert c.open(b'/etc/passwd', 0) == -1
assert ctypes.get_errno() == errno.EACCES
assert c.socket(2, 1, 0) == -1
assert ctypes.get_errno() == errno.EPERM
assert c.fork() == -1
assert ctypes.get_errno() == errno.EPERM
api.print('native calls denied')''')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['logs'], ['native calls denied'])

    def test_symlink_storage_root_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            link = Path(temporary) / 'link'
            link.symlink_to(temporary, target_is_directory=True)
            result = self.run_script('return None', storage_directory=str(link))
            self.assertEqual(result['error_kind'], 'sandbox_unavailable')

    def test_limits_and_recovery(self):
        for script, error in (
            ("return b'x' * (1024 * 1024 + 1)", 'replacement exceeds'),
            ("api.state['large'] = 'x' * 65537", 'api.state exceeds'),
            ("data = bytearray(512 * 1024 * 1024)", 'MemoryError'),
        ):
            with self.subTest(script=script):
                result = self.run_script(script)
                self.assertFalse(result['ok'], result)
                self.assertIsNone(result['replacement'])
                self.assertIn(error, result['error'])
        result = self.run_script('return api.bytes')
        self.assertTrue(result['ok'], result)

    def test_runtime_files_are_read_only(self):
        import sysconfig
        target = str(Path(sysconfig.get_path('stdlib')) / 'json' / '__init__.py')
        result = self.run_script(f"api.print(len(open({target!r}).read()))")
        self.assertTrue(result['ok'], result)
        # O_WRONLY without O_TRUNC: even a broken policy cannot alter the file.
        result = self.run_script(f"import os\nfd = os.open({target!r}, os.O_WRONLY)\nos.close(fd)")
        self.assertFalse(result['ok'], result)

    def test_validate_only_still_checks_sandbox(self):
        result = self.run_script("return None", validate_only=True, storage_directory='/')
        self.assertEqual(result['error_kind'], 'sandbox_unavailable')


if __name__ == '__main__':
    unittest.main()
