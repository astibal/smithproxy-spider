"""Async addons run under the kernel policy, without gaining network access."""

import errno
import json
from pathlib import Path
import subprocess
import sys
import unittest

from worker_bootstrap import addon_modules, packed_arguments

ROOT = Path(__file__).resolve().parents[1]
class AddonSandboxTests(unittest.TestCase):
    def run_child(self, body, *, native=False):
        modules = addon_modules(ROOT)
        sources = ['inspection_sandbox.py']
        if native:
            sources = ['inspection_api.py', 'inspection_h2.py', 'inspection_hold.py',
                       'inspection_chunked.py', 'inspection_translate.py'] + sources
        source = '\n'.join((ROOT / 'src' / name).read_text() for name in sources)
        source += '\n' + body
        arguments = packed_arguments(source, modules)
        result = subprocess.run(
            [sys.executable, '-I', '-c', *arguments],
            capture_output=True, text=True, timeout=8,
            env={'PATH': '/usr/bin:/bin'},
        )
        self.assertEqual(result.returncode, 0, result.stderr[-6000:])
        return json.loads(result.stdout)

    def test_native_translate_and_persistent_addon_share_the_real_sandbox(self):
        result = self.run_child('''
import asyncio
import json
import selectors
from types import SimpleNamespace
from addon_runtime import AddonGeneration
from addon_h2_events import H2AddonEvents
from addon_native import NativeAddonAdapter

selector = selectors.EpollSelector()
loop = asyncio.SelectorEventLoop(selector)
install_script_sandbox(event_loop_fd=selector.fileno())

source = """
import asyncio
import socket
loads = 0
calls = 0
denied = 0
finished = False
def load(loader):
    global loads, denied
    loads += 1
    try:
        socket.socket()
    except PermissionError:
        denied += 1
async def request(flow):
    global calls
    await asyncio.sleep(0.001)
    calls += 1
    flow.request.path = '/changed/' + str(calls)
def done():
    global finished
    finished = True
"""

async def run():
    generation = AddonGeneration(source, H2AddonEvents.HOOKS)
    assert not await generation.start()
    adapter = NativeAddonAdapter(generation)
    http2 = Http2(False, (), ())
    observations = []
    logs = []
    for identity in ('first', 'second'):
        setup = SimpleNamespace(
            phase='setup', session_id=identity,
            instance=SimpleNamespace(mode='flow'),
            connection=Connection(phase='setup', instance_mode='flow'))
        adapter.setup(setup, None, None)
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/original')]
        block = b''.join(http2.Header(name, value, indexing='without')._encode()
                         for name, value in fields)
        wire = len(block).to_bytes(3, 'big') + b'\\x01\\x05\\x00\\x00\\x00\\x01' + block
        message = Message(wire, len(wire),
                          {'content_annotations': [[0, 9, 'h2.frame.header']]})
        _prepare_translation(message, {
            'event': {'details': {'info': {'side': 'L'}}},
            'translate_allowed': True, 'hold_credit_available': True,
        })
        api = SimpleNamespace(
            phase='content', session_id=identity, side='L', message=message,
            http2=http2, print=lambda *values: logs.append(values),
            connection=Connection(message, instance_mode='flow'))
        replacement = await adapter.content(api)
        assert replacement is message._translation.result
        # Reinterpret actual output through the native reader, not the addon
        # object that the hook changed. Each connection has its own HPACK state.
        annotations = []
        offset = 0
        while offset < len(replacement):
            annotations.append([offset, offset + 9, 'h2.frame.header'])
            size = int.from_bytes(replacement[offset:offset + 3], 'big')
            offset += 9 + size
        emitted = Message(replacement, len(replacement),
                          {'content_annotations': annotations})
        _prepare_translation(emitted, {
            'event': {'details': {'info': {'side': 'L'}}},
            'translate_allowed': True,
        })
        header = next(part for part in emitted.parts if part.frame_type == 1)
        path = next(field.value for field in header.headers.entries
                    if field.name == b':path')
        observations.append([setup.connection._rewrite_requested, path.decode()])
    assert not await adapter.close()
    assert not logs, logs
    module = generation.addon.module
    return [observations, module.loads, module.calls, module.denied,
            module.finished, generation.active_flows, adapter.active_connections]

try:
    result = loop.run_until_complete(run())
finally:
    loop.close()
print(json.dumps(result))
''', native=True)
        self.assertEqual(result, [
            [[True, '/changed/1'], [True, '/changed/2']], 1, 2, 1, True, 0, 0,
        ])

    def test_async_hook_and_timers_work_but_external_operations_stay_denied(self):
        result = self.run_child('''
import asyncio
import json
import selectors
from addon_runtime import AddonGeneration

selector = selectors.EpollSelector()
loop = asyncio.SelectorEventLoop(selector)
install_script_sandbox(event_loop_fd=selector.fileno())

source = """
import asyncio
import os
import socket
from mitmproxy import ctx
denied = []
calls = 0
def load(loader):
    loader.add_option('increment', int, 1, 'Counter increment')
async def request(flow):
    global calls
    await asyncio.sleep(0.001)
    calls += ctx.options.increment
    for name, operation in [
        ('socket', lambda: socket.socket()),
        ('fork', os.fork),
        ('secrets', lambda: open('/etc/passwd').read()),
    ]:
        try:
            operation()
        except PermissionError:
            denied.append(name)
"""

async def run():
    generation = AddonGeneration(source, {'request'})
    assert not await generation.start(None)
    for _ in range(2):
        assert not await generation.dispatch('request', None)
    await generation.close()
    return [generation.addon.module.calls, generation.addon.module.denied]

try:
    result = loop.run_until_complete(run())
finally:
    loop.close()
print(json.dumps(result))
''')
        self.assertEqual(result, [2, ['socket', 'fork', 'secrets'] * 2])

    def test_only_the_exact_prepared_epoll_descriptor_is_allowed(self):
        result = self.run_child('''
import json
import select
allowed = select.epoll()
other = select.epoll()
install_script_sandbox(event_loop_fd=allowed.fileno())
result = [allowed.poll(0)]
for operation in (lambda: other.poll(0), select.epoll):
    try:
        operation()
        result.append('unexpectedly allowed')
    except PermissionError:
        result.append('denied')
allowed.close()
other.close()
print(json.dumps(result))
''')
        self.assertEqual(result, [[], 'denied', 'denied'])

    def test_default_policy_still_denies_even_existing_epoll(self):
        result = self.run_child('''
import json
import select
descriptor = select.epoll()
install_script_sandbox()
try:
    descriptor.poll(0)
    result = 'unexpectedly allowed'
except PermissionError:
    result = 'denied'
descriptor.close()
print(json.dumps(result))
''')
        self.assertEqual(result, 'denied')

    def test_thread_clone_is_allowed_but_process_creation_remains_denied(self):
        result = self.run_child('''
import ctypes
import errno
import json
import os
import socket
import threading

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
install_script_sandbox()

values = []

def child():
    values.append('thread')
    for name, operation in (
            ('socket', socket.socket), ('fork', os.fork)):
        try:
            operation()
            values.append(name + ' unexpectedly allowed')
        except PermissionError:
            values.append(name + ' denied')

thread = threading.Thread(target=child)
thread.start()
thread.join()

try:
    os.fork()
    fork_result = 'unexpectedly allowed'
except PermissionError:
    fork_result = 'denied'

ctypes.set_errno(0)
clone3_result = libc.syscall(435, 0, 0)
clone3_errno = ctypes.get_errno()
print(json.dumps([values, fork_result, clone3_result, clone3_errno]))
''')
        self.assertEqual(result, [
            ['thread', 'socket denied', 'fork denied'],
            'denied', -1, errno.ENOSYS,
        ])

    def test_non_epoll_descriptor_is_rejected_before_installation(self):
        result = self.run_child('''
import json
import os
descriptor = os.open('/dev/null', os.O_RDONLY)
try:
    try:
        install_script_sandbox(event_loop_fd=descriptor)
        result = 'unexpectedly allowed'
    except SandboxUnavailable as error:
        result = str(error)
finally:
    os.close(descriptor)
print(json.dumps(result))
''')
        self.assertIn('must refer to epoll', result)

    def test_dns_model_is_available_in_a_packaged_worker_without_enabling_hooks(self):
        result = self.run_child('''
import asyncio
import json
from addon_runtime import AddonGeneration

source = """
from mitmproxy import dns
result = None
def request(flow):
    global result
    query = dns.DNSMessage(
        id=7, query=True, op_code=dns.op_codes.QUERY,
        authoritative_answer=False, truncation=False,
        recursion_desired=True, recursion_available=False, reserved=0,
        response_code=dns.response_codes.NOERROR,
        questions=[dns.Question('example.test', dns.types.A, dns.classes.IN)],
        answers=[], authorities=[], additionals=[], timestamp=1,
    )
    answer = query.succeed([
        dns.ResourceRecord('example.test', dns.types.A, dns.classes.IN,
                           30, bytes.fromhex('c0000201'))
    ])
    result = [answer.answers[0].to_json(), answer.packed.hex()]
"""

async def run():
    generation = AddonGeneration(source, {'request'})
    assert not await generation.start()
    assert not await generation.dispatch('request', None)
    result = generation.addon.module.result
    await generation.close()
    return result

print(json.dumps(asyncio.run(run())))
''')
        self.assertEqual(result[0], {
            'name': 'example.test', 'type': 'A', 'class': 'IN',
            'ttl': 30, 'data': '192.0.2.1',
        })
        self.assertTrue(result[1].startswith('00078180'))


if __name__ == '__main__':
    unittest.main()
