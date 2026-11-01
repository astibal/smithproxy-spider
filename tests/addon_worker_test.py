"""Exercise addon lifecycle through the packaged worker's actual JSON protocol."""

import base64
import gzip
import json
from pathlib import Path
import select
import subprocess
import sys
import unittest

import hpack

from inspection_cookbook_test import WORKER
from inspection_h2_test import frame, unpack
from worker_bootstrap import addon_modules, packed_arguments
from addon_live_http_contract import (
    ADDON_SOURCE, MATRIX_SOURCE, PIPELINE_SOURCE, TRAILER_SOURCE,
    canonical_headers, decoded_body, matrix_cases, matrix_request_wire,
    matrix_response_wire, parse_http1_message, parse_http1_stream,
    selected_headers,
)


ROOT = Path(__file__).resolve().parents[1]
MODULES = addon_modules(ROOT)


def worker_command(*arguments, prefix=''):
    """Launch the same bounded argument vector used by production."""
    source = WORKER
    if prefix:
        future_import = 'from __future__ import annotations\n'
        if future_import not in source:
            raise AssertionError('Worker source lost its future-import boundary')
        source = source.replace(
            future_import, future_import + prefix + '\n', 1)
    payload = packed_arguments(source, MODULES)
    return [sys.executable, '-I', '-c', *payload, *arguments]


def callback(identity, action, wire=b''):
    info = {'side': 'L', 'content': base64.b64encode(wire).decode(),
            'webhook_control': {'content-reverse': True}}
    if wire:
        annotations = []
        offset = 0
        while offset < len(wire):
            annotations.append([offset, offset + 9, 'h2.frame.header'])
            offset += 9 + int.from_bytes(wire[offset:offset + 3], 'big')
        info['content_annotations'] = annotations
    return {
        'event': {'id': identity, 'action': action, 'details': {'info': info}},
        'instance': {'mode': 'flow'}, 'translate_allowed': True,
        'hold_allowed': True, 'hold_credit_available': True,
    }


def h1_callback(identity, wire, *, side='L', connection_close=None):
    request = callback(identity, 'connection-content')
    info = request['event']['details']['info']
    info['side'] = side
    info['content'] = base64.b64encode(wire).decode()
    line_end = wire.index(b'\r\n') + 2
    head_end = wire.index(b'\r\n\r\n') + 4
    info['content_annotations'] = [
        [0, line_end, 'http1.start_line'],
        [line_end, head_end, 'http1.headers'],
    ]
    if connection_close is not None:
        info['webhook_control']['connection-close'] = connection_close
    return request


def h1_continuation(identity, wire, *, side='L'):
    request = callback(identity, 'connection-content')
    info = request['event']['details']['info']
    info['side'] = side
    info['content'] = base64.b64encode(wire).decode()
    return request


def h1_pipeline_callback(identity, messages, *, side='L'):
    wire = b''.join(messages)
    request = callback(identity, 'connection-content')
    info = request['event']['details']['info']
    info['side'] = side
    info['content'] = base64.b64encode(wire).decode()
    info['content_annotations'] = []
    offset = 0
    for message in messages:
        line_end = message.index(b'\r\n') + 2
        head_end = message.index(b'\r\n\r\n') + 4
        info['content_annotations'].extend((
            [offset, offset + line_end, 'http1.start_line'],
            [offset + line_end, offset + head_end, 'http1.headers'],
        ))
        offset += len(message)
    return request


def raw_transport(kind='tcp'):
    return {
        'version': 1,
        'kind': kind,
        'delivery': 'raw',
        'client': {
            'peername': ['192.0.2.10', 41000],
            'sockname': ['192.0.2.20', 443],
        },
        'server': {
            'address': ['198.51.100.30', 443],
            'peername': ['198.51.100.30', 443],
            'sockname': ['192.0.2.20', 52000],
        },
    }


def raw_callback(identity, action, transport, wire=b'', *, side='L',
                 sequence=None, terminal=None):
    request = callback(identity, action, wire)
    info = request['event']['details']['info']
    info['side'] = side
    envelope = json.loads(json.dumps(transport))
    if sequence is not None:
        envelope.update({
            'direction': ('client-to-server' if side == 'L'
                          else 'server-to-client'),
            'sequence': sequence,
            'unit': ('stream-chunk' if transport['kind'] == 'tcp'
                     else 'datagram'),
        })
    if terminal is not None:
        envelope['terminal'] = terminal
    info['raw_transport'] = envelope
    return request


class AddonWorkerTests(unittest.TestCase):
    def test_packaged_worker_dispatches_explicit_raw_transport_lifecycle(self):
        source = '''#!mitmproxy
def tcp_start(flow):
    print("start", flow.client_conn.peername, flow.server_conn.address)

def tcp_message(flow):
    message = flow.messages[-1]
    prefix = b"client:" if message.from_client else b"server:"
    message.content = prefix + message.content.upper()
    print("message", message.from_client, len(flow.messages))

def tcp_end(flow):
    print("end", flow.live, len(flow.messages))
'''
        transport = raw_transport('tcp')
        callbacks = [
            raw_callback('raw-worker', 'connection-start', transport),
            raw_callback(
                'raw-worker', 'connection-content', transport, b'hello',
                side='L', sequence=10),
            raw_callback(
                'raw-worker', 'connection-content', transport, b'world',
                side='R', sequence=11),
            raw_callback(
                'raw-worker', 'connection-stop', transport,
                terminal={'state': 'closed', 'message': ''}),
        ]
        output, stderr = self.run_worker({'script': source}, callbacks)

        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        self.assertTrue(output[1]['ok'], output[1])
        self.assertTrue(output[1]['rewrite_requested'])
        self.assertEqual(output[1]['logs'], [
            "start ('192.0.2.10', 41000) ('198.51.100.30', 443)",
        ])
        self.assertEqual(base64.b64decode(output[2]['replacement']), b'client:HELLO')
        self.assertEqual(output[2]['logs'], ['message True 1'])
        self.assertEqual(base64.b64decode(output[3]['replacement']), b'server:WORLD')
        self.assertEqual(output[3]['logs'], ['message False 2'])
        self.assertEqual(output[4]['logs'], ['end True 2'])
        self.assertNotIn('Traceback', stderr)

    def test_packaged_worker_preserves_an_empty_udp_datagram(self):
        source = '''#!mitmproxy
def udp_message(flow):
    message = flow.messages[-1]
    assert message.content == b""
    message.content = b"expanded"
'''
        transport = raw_transport('udp')
        output, stderr = self.run_worker({'script': source}, [
            raw_callback('udp-worker', 'connection-start', transport),
            raw_callback(
                'udp-worker', 'connection-content', transport, b'',
                side='L', sequence=0),
            raw_callback(
                'udp-worker', 'connection-stop', transport,
                terminal={'state': 'closed', 'message': ''}),
        ])

        self.assertTrue(output[1]['ok'], output[1])
        self.assertTrue(output[2]['ok'], output[2])
        self.assertEqual(base64.b64decode(output[2]['replacement']), b'expanded')
        self.assertTrue(output[3]['ok'], output[3])
        self.assertNotIn('Traceback', stderr)

    def test_master_log_and_event_loop_are_live_in_packaged_worker(self):
        source = '''#!mitmproxy
import asyncio
from mitmproxy import ctx

assert ctx.master.log is ctx.log
assert ctx.log.master is ctx.master
assert ctx.master.event_loop is asyncio.get_running_loop()
assert ctx.master.event_loop.is_running()

def request(flow):
    flow.request.headers["x-master-contract"] = "live"
'''
        wire = frame(hpack.Encoder().encode([
            (b':method', b'GET'),
            (b':scheme', b'https'),
            (b':authority', b'example.test'),
            (b':path', b'/'),
        ]), 1, 5)
        output, stderr = self.run_worker(
            {'script': source},
            [callback('master-contract', 'connection-start'),
             callback('master-contract', 'connection-content', wire)],
        )

        self.assertTrue(output[1]['ok'])
        self.assertTrue(output[2]['ok'])
        frames = unpack(base64.b64decode(output[2]['replacement']))
        headers = hpack.Decoder().decode(frames[0][3], raw=True)
        self.assertIn((b'x-master-contract', b'live'), headers)
        self.assertNotIn('Traceback', stderr)

    def test_packaged_worker_delivers_only_explicit_add_log_events(self):
        source = '''#!mitmproxy
import logging
from mitmproxy import ctx, log

def add_log(entry):
    print("ADD_LOG", entry.msg, entry.level, type(entry).__name__)

def request(flow):
    logging.info("ordinary standard log")
    ctx.log.info("ordinary legacy log")
    ctx.master.addons.trigger(log.AddLogHook(
        log.LogEntry("explicit event", "warn")
    ))
'''
        wire = frame(hpack.Encoder().encode([
            (b':method', b'GET'),
            (b':scheme', b'https'),
            (b':authority', b'example.test'),
            (b':path', b'/'),
        ]), 1, 5)
        output, stderr = self.run_worker(
            {'script': source},
            [callback('explicit-add-log', 'connection-start'),
             callback('explicit-add-log', 'connection-content', wire)],
        )

        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        self.assertTrue(output[1]['ok'], output[1])
        self.assertTrue(output[2]['ok'], output[2])
        hook_records = [
            record for record in output[2]['logs']
            if record.startswith('ADD_LOG ')
        ]
        self.assertEqual(
            hook_records,
            ['ADD_LOG explicit event warn LogEntry'],
        )
        self.assertNotIn('ADD_LOG ordinary standard log', output[2]['logs'])
        self.assertNotIn('ADD_LOG ordinary legacy log', output[2]['logs'])
        self.assertNotIn('Traceback', stderr)

    def test_custom_content_view_uses_the_persistent_sandboxed_generation(self):
        source = '''#!mitmproxy
from mitmproxy import contentviews
print("view generation loaded")
class Probe(contentviews.InteractiveContentview):
    syntax_highlight = "yaml"
    calls = 0
    def prettify(self, data, metadata):
        self.calls += 1
        if data == b"fail":
            raise ValueError("deliberate render failure")
        return data.decode().upper() + ":" + str(self.calls)
    def render_priority(self, data, metadata):
        return 5 if metadata.content_type == "text/probe" else -1
    def reencode(self, text, metadata):
        assert metadata.original_data == b"original"
        return text.lower().encode()
contentviews.add(Probe)
'''
        encoded = lambda value: base64.b64encode(value).decode()
        callbacks = [
            {'content_view_action': 'list'},
            {'content_view_action': 'render', 'data': encoded(b'hello'),
             'content_type': 'text/probe', 'view_name': 'auto'},
            {'content_view_action': 'render', 'data': encoded(b'fail'),
             'content_type': 'text/probe', 'view_name': 'Probe'},
            {'content_view_action': 'render', 'data': encoded(b'again'),
             'content_type': 'text/probe', 'view_name': 'probe'},
            {'content_view_action': 'reencode', 'data': encoded(b'original'),
             'content_type': 'text/probe', 'view_name': 'Probe',
             'text': 'EDITED'},
        ]
        output, stderr = self.run_worker({'script': source}, callbacks)
        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        listed, first, failed, second, reencoded = output[1:]
        self.assertEqual(listed['views'], [{
            'key': 'probe', 'name': 'Probe', 'syntax_highlight': 'yaml',
            'interactive': True,
        }])
        self.assertEqual(listed['logs'], ['view generation loaded'])
        self.assertEqual(first['text'], 'HELLO:1')
        self.assertEqual(first['view_name'], 'Probe')
        self.assertTrue(first['interactive'])
        self.assertFalse(failed['ok'])
        self.assertIn('deliberate render failure', failed['error'])
        self.assertFalse(failed['_worker_recycle'])
        self.assertEqual(second['text'], 'AGAIN:3')
        self.assertEqual(base64.b64decode(reencoded['data']), b'edited')
        self.assertNotIn('Traceback', stderr)

    def test_legacy_content_view_runs_through_the_persistent_generation(self):
        source = '''#!mitmproxy
from mitmproxy import contentviews
from mitmproxy.contentviews.base import View

assert View is contentviews.View
assert contentviews._compat.LegacyContentview is contentviews.LegacyContentview

class LegacyProbe(View):
    name = "Legacy Worker Probe"
    calls = 0

    def __call__(self, data, **metadata):
        self.calls += 1
        assert metadata == {"content_type": "text/legacy"}
        return "legacy", iter([
            [("header", b"legacy "), ("text", data)],
            [("error", str(self.calls))],
        ])

    def render_priority(self, data, **metadata):
        return 9

contentviews.add(LegacyProbe)
'''
        encoded = lambda value: base64.b64encode(value).decode()
        output, stderr = self.run_worker(
            {'script': source},
            [
                {'content_view_action': 'list'},
                {
                    'content_view_action': 'render',
                    'data': encoded(b'payload'),
                    'content_type': 'text/legacy',
                    'view_name': 'auto',
                },
            ],
        )

        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        self.assertEqual(output[1]['views'], [{
            'key': 'legacy worker probe',
            'name': 'Legacy Worker Probe',
            'syntax_highlight': 'none',
            'interactive': False,
        }])
        self.assertEqual(output[2]['text'], 'legacy payload\n1')
        self.assertEqual(output[2]['view_name'], 'Legacy Worker Probe')
        self.assertFalse(output[2]['interactive'])
        self.assertNotIn('Traceback', stderr)

    def test_public_content_view_helpers_run_inside_native_http_generation(self):
        source = '''#!mitmproxy
from mitmproxy import contentviews

registrations = []

def registered(view):
    registrations.append(view.name)

contentviews.registry.on_change.connect(registered)

class WorkerProbe(contentviews.InteractiveContentview):
    name = "WorkerProbe"
    syntax_highlight = "yaml"

    def prettify(self, data, metadata):
        return metadata.content_type + ":" + data.decode("ascii")

    def render_priority(self, data, metadata):
        return 100

    def reencode(self, text, metadata):
        assert metadata.original_data is None
        return (metadata.content_type + ":" + text).encode("ascii")

contentviews.add(WorkerProbe)

def request(flow):
    assert registrations == ["WorkerProbe"]
    rendered = contentviews.prettify_message(
        flow.request, flow, "WorkerProbe")
    encoded = contentviews.reencode_message(
        "edited", flow.request, flow, "WorkerProbe")
    flow.request.headers["x-content-view-helper"] = (
        rendered.text + "|" + encoded.decode("ascii") + "|" +
        str(rendered.view_name)
    )
'''
        wire = frame(hpack.Encoder().encode([
            (b':method', b'POST'),
            (b':scheme', b'https'),
            (b':authority', b'example.test'),
            (b':path', b'/'),
            (b'content-type', b'text/probe'),
        ]), 1, 5)
        output, stderr = self.run_worker(
            {'script': source},
            [callback('content-view-helper', 'connection-start'),
             callback('content-view-helper', 'connection-content', wire)],
        )

        self.assertTrue(output[1]['ok'])
        self.assertTrue(output[2]['ok'])
        frames = unpack(base64.b64decode(output[2]['replacement']))
        headers = hpack.Decoder().decode(frames[0][3], raw=True)
        self.assertIn(
            (b'x-content-view-helper',
             b'text/probe:|text/probe:edited|WorkerProbe'),
            headers,
        )
        self.assertNotIn('Traceback', stderr)

    def test_http2_trailer_mutation_matches_reference_end_to_end_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_live_h2_trailers_v12.json').read_text()
        )

        request_encoder = hpack.Encoder()
        request_wire = (
            frame(request_encoder.encode([
                (b':method', b'POST'),
                (b':scheme', b'https'),
                (b':authority', b'input.example'),
                (b':path', b'/trailers'),
                (b'content-length', b'7'),
            ]), 1, 4)
            + frame(b'old-one', 0, 0)
            + frame(request_encoder.encode([
                (b'x-input-trailer', b'request'),
                (b'x-remove', b'request'),
            ]), 1, 5)
        )
        response_encoder = hpack.Encoder()
        response_wire = (
            frame(response_encoder.encode([
                (b':status', b'201'),
                (b'content-length', b'8'),
            ]), 1, 4)
            + frame(b'origin-1', 0, 0)
            + frame(response_encoder.encode([
                (b'x-input-trailer', b'response'),
                (b'x-remove', b'response'),
            ]), 1, 5)
        )
        response_callback = callback(
            'differential-trailers', 'connection-content', response_wire
        )
        response_callback['event']['details']['info']['side'] = 'R'
        callbacks = [
            callback('differential-trailers', 'connection-start'),
            callback('differential-trailers', 'connection-content', request_wire),
            response_callback,
            callback('differential-trailers', 'connection-stop'),
        ]
        output, _ = self.run_worker({'script': TRAILER_SOURCE}, callbacks)
        request_result = output[2]
        response_result = output[3]
        self.assertTrue(request_result['ok'], request_result)
        self.assertTrue(response_result['ok'], response_result)

        def decode(wire, *, request):
            decoder = hpack.Decoder()
            initial = []
            trailers = []
            body = bytearray()
            for kind, _, _, payload in unpack(wire):
                if kind == 1:
                    fields = decoder.decode(payload, raw=True)
                    if any(name.startswith(b':') for name, _ in fields):
                        initial = fields
                    else:
                        trailers = fields
                elif kind == 0:
                    body.extend(payload)
            pseudo = dict((name, value) for name, value in initial
                          if name.startswith(b':'))
            result = {
                'body': body.decode('latin-1'),
                'trailers': [
                    [name.decode('latin-1'), value.decode('latin-1')]
                    for name, value in trailers
                    if name in (b'x-addon-trailer', b'x-input-trailer', b'x-remove')
                ],
            }
            if request:
                result.update({
                    'method': pseudo[b':method'].decode('latin-1'),
                    'path': pseudo[b':path'].decode('latin-1'),
                })
            else:
                result['status'] = int(pseudo[b':status'])
            return result

        self.assertEqual(
            decode(base64.b64decode(request_result['replacement']), request=True),
            corpus['request'],
        )
        self.assertEqual(
            decode(base64.b64decode(response_result['replacement']), request=False),
            corpus['response'],
        )

    def test_fragmented_http2_messages_match_reference_live_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_live_h2_v12.json').read_text()
        )
        process = subprocess.Popen(
            worker_command('--persistent'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )

        def carried(item, previous, request_id):
            item.update({
                '_request_id': request_id,
                'translate_active': True,
                'translate_allowed': False,
                'translate_state': previous['translate_state'],
                'translate_control': previous['translate_control'],
                'held_parts': previous.get('held_parts'),
                'hold_credit_reserved': previous.get(
                    'hold_credit_reservation', False
                ),
            })
            return item

        try:
            self.assertEqual(self.exchange(process, {'script': ADDON_SOURCE}),
                             {'ready': True, 'script_api': 'mitmproxy'})
            setup = callback('fragmented-differential', 'connection-start')
            setup['_request_id'] = 1
            current = self.exchange(process, setup)
            self.assertTrue(current['ok'], current)

            request_fields = [
                (b':method', b'POST'),
                (b':scheme', b'https'),
                (b':authority', b'input.example'),
                (b':path', b'/original-h2'),
                (b'x-client', b'1'),
                (b'content-type', b'application/octet-stream'),
                (b'content-length', b'7'),
            ]
            request_first = callback(
                'fragmented-differential', 'connection-content',
                frame(hpack.Encoder().encode(request_fields), 1, 4)
                + frame(b'old-', 0, 0),
            )
            request_first['_request_id'] = 2
            request_held = self.exchange(process, request_first)
            self.assertTrue(request_held['ok'], request_held)
            self.assertEqual(request_held['hold']['state'], 'holding')

            request_final = callback(
                'fragmented-differential', 'connection-content',
                frame(b'one', 0, 1),
            )
            request_final = carried(request_final, request_held, 3)
            request_released = self.exchange(process, request_final)
            self.assertTrue(request_released['ok'], request_released)
            self.assertEqual(request_released['hold']['state'], 'released')

            response_fields = [
                (b':status', b'201'),
                (b'content-type', b'text/plain'),
                (b'x-origin', b'1'),
                (b'content-length', b'8'),
            ]
            response_first = callback(
                'fragmented-differential', 'connection-content',
                frame(hpack.Encoder().encode(response_fields), 1, 4)
                + frame(b'origin-', 0, 0),
            )
            response_first['event']['details']['info']['side'] = 'R'
            response_first.update({
                '_request_id': 4,
                'translate_active': True,
                'translate_allowed': False,
                'translate_state': None,
                'translate_control': request_released['translate_control'],
                'held_parts': None,
                'hold_credit_reserved': False,
            })
            response_held = self.exchange(process, response_first)
            self.assertTrue(response_held['ok'], response_held)
            self.assertEqual(response_held['hold']['state'], 'holding')

            response_final = callback(
                'fragmented-differential', 'connection-content',
                frame(b'1', 0, 1),
            )
            response_final['event']['details']['info']['side'] = 'R'
            response_final = carried(response_final, response_held, 5)
            response_released = self.exchange(process, response_final)
            self.assertTrue(response_released['ok'], response_released)
            self.assertEqual(response_released['hold']['state'], 'released')

            def output_bytes(*responses):
                return b''.join(
                    base64.b64decode(response['replacement'])
                    for response in responses if response.get('replacement')
                )

            def decoded(wire):
                headers = []
                body = bytearray()
                decoder = hpack.Decoder()
                for kind, _, _, payload in unpack(wire):
                    if kind == 1:
                        headers = decoder.decode(payload, raw=True)
                    elif kind == 0:
                        body.extend(payload)
                pseudo = dict((name, value) for name, value in headers
                              if name.startswith(b':'))
                regular = [(name.decode('latin-1'), value.decode('latin-1'))
                           for name, value in headers if not name.startswith(b':')]
                return pseudo, selected_headers(regular), body.decode('latin-1')

            pseudo, headers, body = decoded(output_bytes(
                request_held, request_released
            ))
            self.assertEqual({
                'method': pseudo[b':method'].decode('latin-1'),
                'path': pseudo[b':path'].decode('latin-1'),
                'headers': headers,
                'body': body,
            }, corpus['request'])
            pseudo, headers, body = decoded(output_bytes(
                response_held, response_released
            ))
            self.assertEqual({
                'status': int(pseudo[b':status']),
                'headers': headers,
                'body': body,
            }, corpus['response'])

            process.stdin.close()
            process.stdin = None
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr[-6000:])
            self.assertEqual(stdout, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_http2_multiplexing_matches_reference_end_to_end_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_live_h2_multiplex_v12.json').read_text()
        )
        request_encoder = hpack.Encoder()
        request_wire = b''
        for stream_id, original in ((1, b'first'), (3, b'second')):
            request_wire += frame(request_encoder.encode([
                (b':method', b'GET'),
                (b':scheme', b'https'),
                (b':authority', b'input.example'),
                (b':path', b'/' + original),
                (b'content-length', b'0'),
            ]), 1, 5, stream_id)

        response_encoder = hpack.Encoder()
        response_wire = b''
        for sequence, stream_id in ((2, 3), (1, 1)):
            response_wire += frame(response_encoder.encode([
                (b':status', b'200'),
                (b'x-origin', str(sequence).encode()),
                (b'content-length', b'8'),
            ]), 1, 4, stream_id)
            response_wire += frame(
                f'origin-{sequence}'.encode(), 0, 1, stream_id
            )
        response_callback = callback(
            'differential-multiplex', 'connection-content', response_wire
        )
        response_callback['event']['details']['info']['side'] = 'R'
        callbacks = [
            callback('differential-multiplex', 'connection-start'),
            callback('differential-multiplex', 'connection-content', request_wire),
            response_callback,
            callback('differential-multiplex', 'connection-stop'),
        ]
        output, _ = self.run_worker({'script': PIPELINE_SOURCE}, callbacks)
        request_result = output[2]
        response_result = output[3]
        self.assertTrue(request_result['ok'], request_result)
        self.assertTrue(response_result['ok'], response_result)

        request_decoder = hpack.Decoder()
        observed_requests = []
        for kind, _, stream_id, payload in unpack(
                base64.b64decode(request_result['replacement'])):
            if kind != 1:
                continue
            fields = request_decoder.decode(payload, raw=True)
            pseudo = dict((name, value) for name, value in fields
                          if name.startswith(b':'))
            regular = [(name.decode('latin-1'), value.decode('latin-1'))
                       for name, value in fields if not name.startswith(b':')]
            observed_requests.append({
                'method': pseudo[b':method'].decode('latin-1'),
                'path': pseudo[b':path'].decode('latin-1'),
                'headers': selected_headers(regular),
            })

        response_decoder = hpack.Decoder()
        by_stream = {1: {'body': bytearray()}, 3: {'body': bytearray()}}
        for kind, _, stream_id, payload in unpack(
                base64.b64decode(response_result['replacement'])):
            if kind == 1:
                fields = response_decoder.decode(payload, raw=True)
                status = next(value for name, value in fields
                              if name == b':status')
                regular = [(name.decode('latin-1'), value.decode('latin-1'))
                           for name, value in fields if not name.startswith(b':')]
                by_stream[stream_id].update({
                    'stream': stream_id,
                    'status': int(status),
                    'headers': selected_headers(regular),
                })
            elif kind == 0:
                by_stream[stream_id]['body'].extend(payload)
        observed_responses = []
        for stream_id in (1, 3):
            result = by_stream[stream_id]
            result['body'] = result['body'].decode('latin-1')
            observed_responses.append(result)

        self.assertEqual(observed_requests, corpus['requests'])
        self.assertEqual(observed_responses, corpus['responses'])

    def test_http1_pipeline_matches_reference_end_to_end_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_live_http_pipeline_v12.json').read_text()
        )
        requests = (
            b'GET /first HTTP/1.1\r\nHost: input.example\r\n'
            b'Content-Length: 0\r\n\r\n',
            b'GET /second HTTP/1.1\r\nHost: input.example\r\n'
            b'Content-Length: 0\r\nConnection: close\r\n\r\n',
        )
        responses = (
            b'HTTP/1.1 200 Origin 1\r\nX-Origin: 1\r\n'
            b'Content-Length: 0\r\n\r\n',
            b'HTTP/1.1 200 Origin 2\r\nX-Origin: 2\r\n'
            b'Content-Length: 0\r\n\r\n',
        )
        callbacks = [
            callback('differential-pipeline', 'connection-start'),
            h1_pipeline_callback('differential-pipeline', requests),
            h1_pipeline_callback('differential-pipeline', responses, side='R'),
            callback('differential-pipeline', 'connection-stop'),
        ]
        output, _ = self.run_worker({'script': PIPELINE_SOURCE}, callbacks)
        request_result = output[2]
        response_result = output[3]
        self.assertTrue(request_result['ok'], request_result)
        self.assertTrue(response_result['ok'], response_result)

        observed_requests = []
        for message in parse_http1_stream(
                base64.b64decode(request_result['replacement'])):
            method, path, _ = message['start'].split(' ', 2)
            observed_requests.append({
                'method': method,
                'path': path,
                'headers': message['headers'],
            })
        observed_responses = parse_http1_stream(
            base64.b64decode(response_result['replacement']))
        self.assertEqual(observed_requests, corpus['requests'])
        self.assertEqual(observed_responses, corpus['responses'])

    def test_http2_mutation_matrix_matches_reference_semantics(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_live_http_matrix_v12.json').read_text()
        )
        scenarios = matrix_cases()
        callbacks = []
        for position, scenario in enumerate(scenarios):
            identity = 'matrix-h2-' + str(position)
            request_body = scenario['body']
            request_fields = [
                (b':method', scenario['method'].encode()),
                (b':scheme', b'https'),
                (b':authority', b'input.example'),
                (b':path', scenario['path'].encode()),
                (b'x-case', str(scenario['case']).encode()),
                (b'x-remove', b'request'),
                (b'x-multi', b'old'),
                (b'content-type', b'application/octet-stream'),
            ]
            if scenario['gzip_request']:
                request_body = gzip.compress(request_body, mtime=0)
                request_fields.append((b'content-encoding', b'gzip'))
            request_fields.append((b'content-length', str(len(request_body)).encode()))
            request_wire = (
                frame(hpack.Encoder().encode(request_fields), 1, 4)
                + frame(request_body, 0, 1)
            )

            case = scenario['case']
            response_body = f'origin-{case}-'.encode() + b'y' * ((case * 13) % 193)
            response_fields = [
                (b':status', b'201'),
                (b'content-type', b'application/octet-stream'),
                (b'x-origin', str(case).encode()),
                (b'x-remove', b'response'),
                (b'x-multi', b'old'),
            ]
            if scenario['gzip_response']:
                response_body = gzip.compress(response_body, mtime=0)
                response_fields.append((b'content-encoding', b'gzip'))
            response_fields.append((b'content-length', str(len(response_body)).encode()))
            response_wire = (
                frame(hpack.Encoder().encode(response_fields), 1, 4)
                + frame(response_body, 0, 1)
            )
            response_callback = callback(
                identity, 'connection-content', response_wire
            )
            response_callback['event']['details']['info']['side'] = 'R'
            callbacks.extend((
                callback(identity, 'connection-start'),
                callback(identity, 'connection-content', request_wire),
                response_callback,
                callback(identity, 'connection-stop'),
            ))

        output, _ = self.run_worker({'script': MATRIX_SOURCE}, callbacks)
        self.assertEqual(len(output), len(callbacks) + 1, output)

        def decoded(result, decoder):
            self.assertTrue(result['ok'], result)
            frames = unpack(base64.b64decode(result['replacement']))
            header_block = next(payload for kind, _, _, payload in frames if kind == 1)
            headers = decoder.decode(header_block, raw=True)
            body = b''.join(payload for kind, _, _, payload in frames if kind == 0)
            regular = [(name.decode('latin-1'), value.decode('latin-1'))
                       for name, value in headers if not name.startswith(b':')]
            pseudo = dict((name, value) for name, value in headers if name.startswith(b':'))
            return pseudo, canonical_headers(regular), body

        requests = []
        responses = []
        for position, scenario in enumerate(scenarios):
            request_result = output[2 + position * 4]
            response_result = output[3 + position * 4]
            pseudo, headers, body = decoded(request_result, hpack.Decoder())
            requests.append({
                'case': scenario['case'],
                'method': pseudo[b':method'].decode('latin-1'),
                'path': pseudo[b':path'].decode('latin-1'),
                'headers': headers,
                'body': decoded_body(
                    ((name, value) for name, values in headers.items()
                     for value in values), body
                ).decode('latin-1'),
            })
            pseudo, headers, body = decoded(response_result, hpack.Decoder())
            responses.append({
                'case': scenario['case'],
                'status': int(pseudo[b':status']),
                'headers': headers,
                'body': decoded_body(
                    ((name, value) for name, values in headers.items()
                     for value in values), body
                ).decode('latin-1'),
            })

        expected_responses = [
            {key: value for key, value in item.items() if key != 'reason'}
            for item in corpus['responses']
        ]
        self.assertEqual(requests, corpus['requests'])
        self.assertEqual(responses, expected_responses)

    def test_http1_mutation_matrix_matches_reference_wire_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_live_http_matrix_v12.json').read_text()
        )
        scenarios = matrix_cases()
        callbacks = []
        for scenario in scenarios:
            identity = 'matrix-' + str(scenario['case'])
            callbacks.extend((
                callback(identity, 'connection-start'),
                h1_callback(identity, matrix_request_wire(scenario)),
                h1_callback(identity, matrix_response_wire(scenario), side='R'),
                callback(identity, 'connection-stop'),
            ))
        output, _ = self.run_worker({'script': MATRIX_SOURCE}, callbacks)

        requests = []
        responses = []
        for position, scenario in enumerate(scenarios):
            request_result = output[2 + position * 4]
            response_result = output[3 + position * 4]
            self.assertTrue(request_result['ok'], request_result)
            self.assertTrue(response_result['ok'], response_result)

            start, headers, body = parse_http1_message(
                base64.b64decode(request_result['replacement'])
            )
            method, path, _ = start.split(' ', 2)
            requests.append({
                'case': scenario['case'],
                'method': method,
                'path': path,
                'headers': canonical_headers(headers),
                'body': decoded_body(headers, body).decode('latin-1'),
            })

            start, headers, body = parse_http1_message(
                base64.b64decode(response_result['replacement'])
            )
            _, status, reason = start.split(' ', 2)
            responses.append({
                'case': scenario['case'],
                'status': int(status),
                'reason': reason,
                'headers': canonical_headers(headers),
                'body': decoded_body(headers, body).decode('latin-1'),
            })

        self.assertEqual(requests, corpus['requests'])
        self.assertEqual(responses, corpus['responses'])

    def test_http2_live_mutations_match_reference_end_to_end_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_live_h2_v12.json').read_text()
        )
        request_headers = [
            (b':method', b'POST'),
            (b':scheme', b'https'),
            (b':authority', b'input.example'),
            (b':path', b'/original-h2'),
            (b'x-client', b'1'),
            (b'content-type', b'application/octet-stream'),
            (b'content-length', b'7'),
        ]
        response_headers = [
            (b':status', b'201'),
            (b'content-type', b'text/plain'),
            (b'x-origin', b'1'),
            (b'content-length', b'8'),
        ]
        request_wire = (
            frame(hpack.Encoder().encode(request_headers), 1, 4)
            + frame(b'old-one', 0, 1)
        )
        response_wire = (
            frame(hpack.Encoder().encode(response_headers), 1, 4)
            + frame(b'origin-1', 0, 1)
        )
        response_callback = callback('live-h2', 'connection-content', response_wire)
        response_callback['event']['details']['info']['side'] = 'R'
        callbacks = [
            callback('live-h2', 'connection-start'),
            callback('live-h2', 'connection-content', request_wire),
            response_callback,
            callback('live-h2', 'connection-stop'),
        ]
        output, _ = self.run_worker({'script': ADDON_SOURCE}, callbacks)
        self.assertTrue(output[2]['ok'], output[2])
        self.assertTrue(output[3]['ok'], output[3])

        def decoded(wire):
            frames = unpack(wire)
            header_block = next(payload for kind, _, _, payload in frames if kind == 1)
            headers = hpack.Decoder().decode(header_block, raw=True)
            body = b''.join(payload for kind, _, _, payload in frames if kind == 0)
            regular = [(name.decode('latin-1'), value.decode('latin-1'))
                       for name, value in headers if not name.startswith(b':')]
            return headers, selected_headers(regular), body

        headers, regular, body = decoded(base64.b64decode(output[2]['replacement']))
        pseudo = dict((name, value) for name, value in headers if name.startswith(b':'))
        actual_request = {
            'method': pseudo[b':method'].decode('latin-1'),
            'path': pseudo[b':path'].decode('latin-1'),
            'headers': regular,
            'body': body.decode('latin-1'),
        }
        headers, regular, body = decoded(base64.b64decode(output[3]['replacement']))
        pseudo = dict((name, value) for name, value in headers if name.startswith(b':'))
        actual_response = {
            'status': int(pseudo[b':status']),
            'headers': regular,
            'body': body.decode('latin-1'),
        }
        self.assertEqual(actual_request, corpus['request'])
        self.assertEqual(actual_response, corpus['response'])

    def test_http1_live_mutations_match_reference_end_to_end_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_live_http_v12.json').read_text()
        )
        callbacks = []
        requests = (
            (b'POST /original-one HTTP/1.1\r\nContent-Length: 7\r\n'
             b'Host: input.example\r\nX-Client: 1\r\n'
             b'Content-Type: application/octet-stream\r\n\r\nold-one'),
            (b'GET /original-two HTTP/1.1\r\nHost: input.example\r\n'
             b'X-Client: 2\r\nContent-Type: application/octet-stream\r\n\r\n'),
            (b'POST /original-three HTTP/1.1\r\nContent-Length: 29\r\n'
             b'Host: input.example\r\nX-Client: 3\r\n'
             b'Content-Type: application/octet-stream\r\n'
             b'Content-Encoding: gzip\r\n\r\n' +
             gzip.compress(b'old-three', mtime=0)),
        )
        responses = (
            (b'HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n'
             b'X-Origin: 1\r\nContent-Length: 8\r\n\r\norigin-1'),
            (b'HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n'
             b'X-Origin: 2\r\nContent-Length: 8\r\n\r\norigin-2'),
            (b'HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n'
             b'X-Origin: 3\r\nContent-Encoding: gzip\r\nContent-Length: 28\r\n\r\n' +
             gzip.compress(b'origin-3', mtime=0)),
        )
        for sequence, (request, response) in enumerate(zip(requests, responses), 1):
            identity = 'live-http-' + str(sequence)
            callbacks.extend((
                callback(identity, 'connection-start'),
                h1_callback(identity, request),
                h1_callback(identity, response, side='R'),
                callback(identity, 'connection-stop'),
            ))

        output, _ = self.run_worker({'script': ADDON_SOURCE}, callbacks)
        actual_requests = []
        actual_responses = []
        for sequence in range(3):
            request_result = output[2 + sequence * 4]
            response_result = output[3 + sequence * 4]
            self.assertTrue(request_result['ok'], request_result)
            self.assertTrue(response_result['ok'], response_result)

            start, headers, body = parse_http1_message(
                base64.b64decode(request_result['replacement'])
            )
            method, path, _ = start.split(' ', 2)
            actual_requests.append({
                'method': method,
                'path': path,
                'headers': headers,
                'body': decoded_body(headers, body).decode('latin-1'),
            })

            start, headers, body = parse_http1_message(
                base64.b64decode(response_result['replacement'])
            )
            _, status, reason = start.split(' ', 2)
            actual_responses.append({
                'status': int(status),
                'reason': reason,
                'headers': headers,
                'body': decoded_body(headers, body).decode('latin-1'),
            })

        self.assertEqual(actual_requests, corpus['requests'])
        self.assertEqual(actual_responses, corpus['responses'])

    def test_h2_local_response_returns_atomic_peer_checkpoint_and_reverse_output(self):
        source = '''#!mitmproxy
from mitmproxy import http
events = []
def request(flow):
    events.append("request")
    flow.response = http.Response.make(
        204,
        b"local body",
        [(b"X-Local", b"yes")],
    )
def responseheaders(flow):
    events.append("responseheaders")
def response(flow):
    events.append("response")
    flow.response.trailers = http.Headers([(b"X-Finished", b"yes")])
'''
        fields = [
            (b':method', b'GET'),
            (b':scheme', b'https'),
            (b':authority', b'example.test'),
            (b':path', b'/local'),
        ]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [
            callback('local-response', 'connection-start'),
            callback('local-response', 'connection-content', wire),
        ]
        output, stderr = self.run_worker({'script': source}, callbacks)
        result = output[2]
        self.assertTrue(result['ok'], result)
        self.assertEqual(base64.b64decode(result['replacement']), b'')
        self.assertIsInstance(result['translate_state'], dict)
        self.assertIsInstance(result['peer_translate_state'], dict)
        frames = unpack(base64.b64decode(result['replacement_reverse']))
        decoder = hpack.Decoder()
        headers = decoder.decode(frames[0][3], raw=True)
        trailers = decoder.decode(frames[-1][3], raw=True)
        self.assertIn((b':status', b'204'), headers)
        self.assertIn((b'x-local', b'yes'), headers)
        self.assertIn((b'content-length', b'10'), headers)
        self.assertIn((b'x-finished', b'yes'), trailers)
        self.assertEqual(
            b''.join(payload for kind, flags, stream, payload in frames if kind == 0),
            b'local body',
        )
        self.assertNotIn('Traceback', stderr)

    def test_h1_local_response_checkpoint_preserves_pipeline_order(self):
        source = '''#!mitmproxy
from mitmproxy import http
def request(flow):
    if flow.request.path == "/local":
        flow.response = http.Response.make(204, b"local body", {"X-Local": "yes"})
def response(flow):
    if flow.request.path == "/local":
        flow.response.trailers = http.Headers([(b"X-Finished", b"yes")])
'''
        process = subprocess.Popen(
            worker_command('--persistent'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        first = b'GET /origin HTTP/1.1\r\nHost: example.test\r\n\r\n'
        second = b'GET /local HTTP/1.1\r\nHost: example.test\r\n\r\n'
        origin = b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin'
        try:
            self.assertEqual(self.exchange(process, {'script': source}),
                             {'ready': True, 'script_api': 'mitmproxy'})
            setup = callback('h1-local', 'connection-start')
            setup['_request_id'] = 1
            self.assertTrue(self.exchange(process, setup)['rewrite_requested'])

            requests = h1_pipeline_callback('h1-local', (first, second))
            requests['_request_id'] = 2
            queued = self.exchange(process, requests)
            self.assertTrue(queued['ok'], queued)
            self.assertEqual(base64.b64decode(queued['replacement']), first)
            self.assertNotIn('replacement_reverse', queued)
            self.assertEqual(queued['h1_response_state']['slots'][0], 'origin')
            self.assertIn('response', queued['h1_response_state']['slots'][1])

            response = h1_callback('h1-local', origin, side='R')
            response.update({
                '_request_id': 3,
                'h1_response_state': queued['h1_response_state'],
            })
            flushed = self.exchange(process, response)
            self.assertTrue(flushed['ok'], flushed)
            wire = base64.b64decode(flushed['replacement'])
            self.assertTrue(wire.startswith(origin))
            local = wire[len(origin):]
            self.assertTrue(local.startswith(b'HTTP/1.1 204 No Content\r\n'))
            self.assertIn(b'Transfer-Encoding: chunked\r\n', local)
            self.assertTrue(local.endswith(
                b'a\r\nlocal body\r\n0\r\nX-Finished: yes\r\n\r\n'))
            self.assertEqual(flushed['h1_response_state']['slots'], [])

            process.stdin.close()
            process.stdin = None
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr[-6000:])
            self.assertEqual(stdout, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_h1_kill_crosses_packaged_worker_without_wire_content(self):
        source = '''#!mitmproxy
events = []
def requestheaders(flow):
    events.append("requestheaders")
    flow.kill()
    events.append("requestheaders-after-kill")
def error(flow):
    assert str(flow.error) == "Connection killed."
    events.append("error")
    print("EVENTS", events)
'''
        process = subprocess.Popen(
            worker_command('--persistent'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        wire = b'GET /kill HTTP/1.1\r\nHost: example.test\r\n\r\n'
        try:
            self.assertEqual(
                self.exchange(process, {'script': source}),
                {'ready': True, 'script_api': 'mitmproxy'},
            )
            setup = callback('h1-kill-worker', 'connection-start')
            setup['_request_id'] = 1
            self.assertTrue(self.exchange(process, setup)['rewrite_requested'])

            request = h1_callback(
                'h1-kill-worker', wire, connection_close=True)
            request['_request_id'] = 2
            killed = self.exchange(process, request)
            self.assertTrue(killed['ok'], killed)
            self.assertEqual(
                killed['connection_close'],
                {'reason': 'Connection killed.'},
            )
            self.assertEqual(base64.b64decode(killed['replacement']), b'')
            self.assertNotIn('replacement_reverse', killed)
            self.assertEqual(killed['h1_response_state']['slots'], [])
            self.assertEqual(killed['logs'], [
                "EVENTS ['requestheaders', 'requestheaders-after-kill', 'error']",
            ])

            stop = callback('h1-kill-worker', 'connection-stop')
            stop['_request_id'] = 3
            stopped = self.exchange(process, stop)
            self.assertTrue(stopped['ok'], stopped)

            # Closing one callback-local connection does not retire the addon
            # generation or discard its module state.
            setup = callback('h1-after-kill', 'connection-start')
            setup['_request_id'] = 4
            self.assertTrue(self.exchange(process, setup)['ok'])

            process.stdin.close()
            process.stdin = None
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr[-6000:])
            self.assertEqual(stdout, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_h1_kill_revalidates_capability_after_packaged_hold(self):
        source = '''#!mitmproxy
def request(flow):
    flow.kill()
'''
        process = subprocess.Popen(
            worker_command('--persistent'),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        head = (
            b'POST /kill HTTP/1.1\r\n'
            b'Host: example.test\r\n'
            b'Content-Length: 6\r\n\r\n'
        )
        try:
            self.assertEqual(
                self.exchange(process, {'script': source}),
                {'ready': True, 'script_api': 'mitmproxy'},
            )
            setup = callback('h1-kill-resume-worker', 'connection-start')
            setup['_request_id'] = 1
            self.assertTrue(self.exchange(process, setup)['rewrite_requested'])

            first = h1_callback(
                'h1-kill-resume-worker',
                head + b'abc',
                connection_close=True,
            )
            first['_request_id'] = 2
            held = self.exchange(process, first)
            self.assertTrue(held['ok'], held)
            self.assertEqual(held['hold']['state'], 'holding')
            self.assertNotIn('connection_close', held)

            # The producer must repeat transport capabilities on every
            # callback. Do not inherit authority from the callback which
            # created the retained body checkpoint.
            resumed = h1_continuation('h1-kill-resume-worker', b'def')
            resumed.update({
                '_request_id': 3,
                'held_parts': held['held_parts'],
                'h1_response_state': held['h1_response_state'],
            })
            rejected = self.exchange(process, resumed)
            self.assertFalse(rejected['ok'])
            self.assertIn(
                'HTTP/1 termination requires connection-close capability',
                rejected['error'],
            )
            self.assertIsNone(rejected['replacement'])
            self.assertNotIn('connection_close', rejected)

            process.stdin.close()
            process.stdin = None
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr[-6000:])
            self.assertEqual(stdout, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_h1_local_response_lifecycle_matches_reference_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_local_response_v12.json').read_text()
        )
        source = '''#!mitmproxy
import json
from mitmproxy import http
def report(name, flow):
    response = flow.response
    event = {
        "hook": name,
        "path": flow.request.path,
        "status": None if response is None else response.status_code,
        "body": None if response is None else response.raw_content.decode("latin-1"),
    }
    if response is not None and response.trailers is not None:
        event["trailers"] = [[name.decode("latin-1"), value.decode("latin-1")]
                             for name, value in response.trailers.fields]
    print("EVENT " + json.dumps(event, sort_keys=True))
def requestheaders(flow):
    report("requestheaders", flow)
    if flow.request.path == "/headers":
        flow.response = http.Response.make(
            201, b"from requestheaders", {"X-Origin": "requestheaders"})
def request(flow):
    report("request", flow)
    if flow.request.path == "/request":
        flow.response = http.Response.make(
            202, b"from request", {"X-Origin": "request"})
    elif flow.request.path == "/empty":
        flow.response = http.Response.make(204, b"body assigned to 204")
    elif flow.request.path == "/trailers":
        flow.response = http.Response.make(
            202, b"local response with trailers", {"X-Origin": "trailers"})
        flow.response.trailers = http.Headers([
            (b"x-local-trailer", b"one"),
            (b"x-local-trailer", b"two"),
        ])
def responseheaders(flow):
    report("responseheaders", flow)
    flow.response.headers["X-Response-Headers"] = "seen"
def response(flow):
    report("response", flow)
    flow.response.headers["X-Response"] = "seen"
    if flow.response.trailers is not None:
        flow.response.trailers.add("X-Response-Trailer", "seen")
    if flow.response.status_code != 204:
        flow.response.content += b" | response hook"
'''
        paths = ('/headers', '/request', '/empty', '/trailers')
        callbacks = []
        for index, path in enumerate(paths):
            identity = 'local-corpus-' + str(index)
            wire = (
                f'POST {path} HTTP/1.1\r\nHost: example.test\r\n'
                'Content-Length: 4\r\n\r\ntest'
            ).encode()
            callbacks.extend((
                callback(identity, 'connection-start'),
                h1_callback(identity, wire),
                callback(identity, 'connection-stop'),
            ))

        output, stderr = self.run_worker({'script': source}, callbacks)
        observed_events = []
        observed_responses = {}
        for index, path in enumerate(paths):
            result = output[2 + index * 3]
            self.assertTrue(result['ok'], result)
            self.assertEqual(base64.b64decode(result['replacement']), b'')
            observed_events.extend(
                json.loads(line.removeprefix('EVENT '))
                for line in result['logs'] if line.startswith('EVENT ')
            )

            wire = base64.b64decode(result['replacement_reverse'])
            head, body = wire.split(b'\r\n\r\n', 1)
            lines = head.split(b'\r\n')
            version, status, reason = lines[0].decode('latin-1').split(' ', 2)
            headers = []
            chunked = False
            length = None
            for line in lines[1:]:
                name, value = line.split(b':', 1)
                value = value.lstrip()
                headers.append([name.decode('latin-1'), value.decode('latin-1')])
                if name.lower() == b'transfer-encoding':
                    chunked = value.lower() == b'chunked'
                if name.lower() == b'content-length':
                    length = int(value)

            trailers = None
            if chunked:
                decoded = bytearray()
                trailers = []
                cursor = 0
                while True:
                    line_end = body.index(b'\r\n', cursor)
                    size = int(body[cursor:line_end], 16)
                    cursor = line_end + 2
                    if size:
                        decoded.extend(body[cursor:cursor + size])
                        cursor += size + 2
                        continue
                    trailer_end = body.index(b'\r\n\r\n', cursor)
                    for line in body[cursor:trailer_end].split(b'\r\n'):
                        name, value = line.split(b':', 1)
                        trailers.append([
                            name.decode('latin-1'),
                            value.lstrip().decode('latin-1'),
                        ])
                    body = bytes(decoded)
                    break
            elif length is not None:
                self.assertEqual(len(body), length)

            observed_responses[path] = {
                'version': version,
                'status': int(status),
                'reason': reason,
                'headers': headers,
                'body': body.decode('latin-1'),
                'trailers': trailers,
            }

        self.assertEqual(observed_events, corpus['events'])
        for path, actual in observed_responses.items():
            expected = corpus['responses'][path]
            self.assertEqual(
                (actual['version'], actual['status'], actual['reason'], actual['body']),
                (expected['version'], expected['status'], expected['reason'], expected['body']),
            )
            framing = {'connection', 'content-length', 'trailer', 'transfer-encoding'}
            actual_fields = [(name.lower(), value) for name, value in actual['headers']
                             if name.lower() not in framing]
            expected_fields = [(name.lower(), value) for name, value in expected['headers']
                               if name.lower() not in framing]
            self.assertEqual(actual_fields, expected_fields)

        self.assertEqual(observed_responses['/trailers']['trailers'], [
            ['x-local-trailer', 'one'],
            ['x-local-trailer', 'two'],
            ['X-Response-Trailer', 'seen'],
        ])
        self.assertNotIn('Traceback', stderr)

    def test_native_h1_helper_tracks_pass_through_before_local_response(self):
        source = '''if api.phase == "setup":
    api.connection.request_rewrite()
    return None
headers = [part for part in api.message.parts
           if part.type == PartType.Http1.Header]
if headers and headers[0].http1.method is not None:
    if headers[0].http1.target == "/local":
        api.message.respond(203, body=b"native local")
        return api.message.commit()
return None
'''
        process = subprocess.Popen(
            worker_command('--persistent'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        first = b'GET /origin HTTP/1.1\r\nHost: example.test\r\n\r\n'
        second = b'GET /local HTTP/1.1\r\nHost: example.test\r\n\r\n'
        origin = b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin'
        try:
            self.assertEqual(self.exchange(process, {'script': source}),
                             {'ready': True})
            setup = callback('native-h1-local', 'connection-start')
            setup['_request_id'] = 1
            self.assertTrue(self.exchange(process, setup)['rewrite_requested'])

            ordinary = h1_callback('native-h1-local', first)
            ordinary['_request_id'] = 2
            observed = self.exchange(process, ordinary)
            self.assertTrue(observed['ok'], observed)
            self.assertIsNone(observed['replacement'])
            self.assertEqual(observed['h1_response_state']['slots'], ['origin'])

            local = h1_callback('native-h1-local', second)
            local.update({
                '_request_id': 3,
                'h1_response_state': observed['h1_response_state'],
            })
            queued = self.exchange(process, local)
            self.assertTrue(queued['ok'], queued)
            self.assertEqual(base64.b64decode(queued['replacement']), b'')
            self.assertNotIn('replacement_reverse', queued)

            response = h1_callback('native-h1-local', origin, side='R')
            response.update({
                '_request_id': 4,
                'h1_response_state': queued['h1_response_state'],
            })
            flushed = self.exchange(process, response)
            self.assertTrue(flushed['ok'], flushed)
            wire = base64.b64decode(flushed['replacement'])
            self.assertTrue(wire.startswith(origin))
            self.assertIn(b'HTTP/1.1 203 Non-Authoritative Information\r\n',
                          wire[len(origin):])
            self.assertTrue(wire.endswith(b'native local'))

            process.stdin.close()
            process.stdin = None
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr[-6000:])
            self.assertEqual(stdout, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_http1_request_and_response_use_the_packaged_persistent_worker(self):
        source = '''#!mitmproxy
events = []
def request(flow):
    flow.metadata["path"] = flow.request.path
    flow.request.headers["x-addon"] = "request"
    events.append(["request", flow.request.path])
def response(flow):
    assert flow.metadata["path"] == "/original"
    flow.response.headers["x-addon"] = "response"
    flow.response.content = b"changed"
    events.append(["response", flow.response.status_code])
    print(repr(events))
'''
        request_wire = (b'GET /original HTTP/1.1\r\nHost: example.test\r\n\r\n')
        response_wire = (b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\noriginal')
        callbacks = [
            callback('http1', 'connection-start'),
            h1_callback('http1', request_wire),
            h1_callback('http1', response_wire, side='R'),
        ]
        output, stderr = self.run_worker({'script': source}, callbacks)
        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        request = output[2]
        response = output[3]
        self.assertTrue(request['ok'], request)
        self.assertTrue(response['ok'], response)
        self.assertIn(b'x-addon: request\r\n',
                      base64.b64decode(request['replacement']))
        response_bytes = base64.b64decode(response['replacement'])
        self.assertIn(b'x-addon: response\r\n', response_bytes)
        self.assertIn(b'Content-Length: 7\r\n', response_bytes)
        self.assertTrue(response_bytes.endswith(b'changed'))
        self.assertIn("[['request', '/original'], ['response', 200]]",
                      response['logs'])

    def test_fragmented_http1_body_uses_native_checkpoint_in_packaged_worker(self):
        source = '''#!mitmproxy
def requestheaders(flow):
    assert flow.request.raw_content is None
    flow.request.content = b"too early"
    assert flow.request.headers["content-length"] == "9"
    print("headers")
def request(flow):
    print("request")
    assert flow.request.content == b"abcdef"
    assert flow.request.headers["content-length"] == "9"
    flow.request.content = b"changed"
'''
        process = subprocess.Popen(
            worker_command('--persistent'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(self.exchange(process, {'script': source}),
                             {'ready': True, 'script_api': 'mitmproxy'})
            setup = callback('h1-body', 'connection-start')
            setup['_request_id'] = 1
            self.assertTrue(self.exchange(process, setup)['rewrite_requested'])

            head = (b'POST / HTTP/1.1\r\nHost: example.test\r\n'
                    b'Content-Length: 6\r\n\r\n')
            first = h1_callback('h1-body', head + b'abc')
            first['_request_id'] = 2
            held = self.exchange(process, first)
            self.assertTrue(held['ok'], held)
            self.assertEqual(held['logs'], ['headers'])
            self.assertEqual(held['hold']['state'], 'holding')
            self.assertEqual(base64.b64decode(held['replacement']), b'')

            second = h1_continuation('h1-body', b'def')
            second.update({'_request_id': 3, 'held_parts': held['held_parts']})
            released = self.exchange(process, second)
            self.assertTrue(released['ok'], released)
            self.assertEqual(released['logs'], ['request'])
            self.assertEqual(released['hold']['state'], 'released')
            result = base64.b64decode(released['replacement'])
            self.assertIn(b'Content-Length: 7\r\n', result)
            self.assertTrue(result.endswith(b'changed'))

            process.stdin.close()
            process.stdin = None
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr[-6000:])
            self.assertEqual(stdout, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_fragmented_http1_exchange_matches_reference_live_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_live_http_v12.json').read_text()
        )
        process = subprocess.Popen(
            worker_command('--persistent'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )

        def carry_checkpoint(item, previous, request_id):
            item.update({
                '_request_id': request_id,
                'held_parts': previous['held_parts'],
                'hold_credit_reserved': previous.get(
                    'hold_credit_reservation', False
                ),
            })
            return item

        try:
            self.assertEqual(self.exchange(process, {'script': ADDON_SOURCE}),
                             {'ready': True, 'script_api': 'mitmproxy'})
            setup = callback('fragmented-http1-differential', 'connection-start')
            setup['_request_id'] = 1
            self.assertTrue(self.exchange(process, setup)['rewrite_requested'])

            request_head = (
                b'POST /original-one HTTP/1.1\r\nContent-Length: 7\r\n'
                b'Host: input.example\r\nX-Client: 1\r\n'
                b'Content-Type: application/octet-stream\r\n\r\n'
            )
            request_first = h1_callback(
                'fragmented-http1-differential', request_head + b'old-'
            )
            request_first['_request_id'] = 2
            request_held = self.exchange(process, request_first)
            self.assertTrue(request_held['ok'], request_held)
            self.assertEqual(request_held['hold']['state'], 'holding')

            request_final = h1_continuation(
                'fragmented-http1-differential', b'one'
            )
            request_final = carry_checkpoint(request_final, request_held, 3)
            request_released = self.exchange(process, request_final)
            self.assertTrue(request_released['ok'], request_released)
            self.assertEqual(request_released['hold']['state'], 'released')

            response_head = (
                b'HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n'
                b'X-Origin: 1\r\nContent-Length: 8\r\n\r\n'
            )
            response_first = h1_callback(
                'fragmented-http1-differential', response_head + b'origin-',
                side='R',
            )
            response_first['_request_id'] = 4
            response_held = self.exchange(process, response_first)
            self.assertTrue(response_held['ok'], response_held)
            self.assertEqual(response_held['hold']['state'], 'holding')

            response_final = h1_continuation(
                'fragmented-http1-differential', b'1', side='R'
            )
            response_final = carry_checkpoint(response_final, response_held, 5)
            response_released = self.exchange(process, response_final)
            self.assertTrue(response_released['ok'], response_released)
            self.assertEqual(response_released['hold']['state'], 'released')

            def joined(*responses):
                return b''.join(
                    base64.b64decode(response['replacement'])
                    for response in responses if response.get('replacement')
                )

            start, headers, body = parse_http1_message(joined(
                request_held, request_released
            ))
            method, path, _ = start.split(' ', 2)
            self.assertEqual({
                'method': method,
                'path': path,
                'headers': headers,
                'body': decoded_body(headers, body).decode('latin-1'),
            }, corpus['requests'][0])

            start, headers, body = parse_http1_message(joined(
                response_held, response_released
            ))
            _, status, reason = start.split(' ', 2)
            self.assertEqual({
                'status': int(status),
                'reason': reason,
                'headers': headers,
                'body': decoded_body(headers, body).decode('latin-1'),
            }, corpus['responses'][0])

            process.stdin.close()
            process.stdin = None
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr[-6000:])
            self.assertEqual(stdout, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_http1_pipeline_keeps_fifo_flow_identity_in_packaged_worker(self):
        source = '''#!mitmproxy
events = []
def request(flow):
    events.append(flow.request.path)
def response(flow):
    flow.response.headers["x-request-path"] = flow.request.path
    events.append(str(flow.response.status_code))
    if len(events) == 4:
        print(",".join(events))
'''
        requests = (
            b'GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n',
            b'GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n',
        )
        responses = (
            b'HTTP/1.1 204 No Content\r\n\r\n',
            b'HTTP/1.1 304 Not Modified\r\n\r\n',
        )
        callbacks = [
            callback('h1-pipeline', 'connection-start'),
            h1_pipeline_callback('h1-pipeline', requests),
            h1_pipeline_callback('h1-pipeline', responses, side='R'),
        ]
        output, stderr = self.run_worker({'script': source}, callbacks)
        request = output[2]
        response = output[3]
        self.assertTrue(request['ok'], request)
        self.assertTrue(response['ok'], response)
        response_bytes = base64.b64decode(response['replacement'])
        self.assertIn(b'x-request-path: /one\r\n', response_bytes)
        self.assertIn(b'x-request-path: /two\r\n', response_bytes)
        self.assertIn('/one,/two,204,304', response['logs'])

    def test_connection_and_certificate_values_work_inside_packaged_sandbox(self):
        from addon_certs import Cert
        from addon_certs_test import certificate

        pem = Cert(certificate()).to_pem()
        source = '''#!mitmproxy
from mitmproxy import certs, connection, http, websocket
from mitmproxy.proxy import mode_specs
from typing import get_args
certificate_pem = CERTIFICATE_PEM
def request(flow):
    # Observed production endpoints remain unknown; detached objects must not
    # pretend to change or replace the native connection carrying this request.
    assert isinstance(flow.client_conn, connection.Client)
    assert isinstance(flow.server_conn, connection.Server)
    assert flow.client_conn.peername is None
    assert flow.client_conn.sockname is None
    assert flow.server_conn.address is None
    assert get_args(connection.Address) == (str, int)
    assert get_args(connection.TransportProtocol) == ("tcp", "udp")
    assert "TLSv1.3" in get_args(connection.TlsVersion)
    assert websocket.Opcode.TEXT == 1
    assert get_args(websocket.WebSocketMessageState) == (int, bool, bytes, float, bool, bool)
    assert http.status_codes.OK == 200
    assert http.status_codes.RESPONSES[418] == "I'm a teapot"
    cert = certs.Cert.from_pem(certificate_pem)
    server = connection.Server(address=("example.test", 443), certificate_list=[cert])
    mode = mode_specs.ProxyMode.parse("reverse:https://example.test@8443")
    client = connection.Client(peername=("127.0.0.1", 1234),
                               sockname=("127.0.0.1", 443), proxy_mode=mode)
    detached = http.HTTPFlow(client, server)
    detached.request = flow.request.copy()
    detached.websocket = websocket.WebSocketData([
        websocket.WebSocketMessage(1, True, b"saved websocket message", timestamp=123)
    ])
    restored = http.HTTPFlow.from_state(detached.get_state())
    assert isinstance(restored.server_conn, connection.Server)
    assert isinstance(restored.client_conn, connection.Client)
    assert restored.server_conn.certificate_list[0].to_pem() == certificate_pem
    assert restored.server_conn.state == connection.ConnectionState.CLOSED
    assert isinstance(restored.client_conn.proxy_mode, mode_specs.ReverseMode)
    assert restored.client_conn.proxy_mode.get_state() == "reverse:https://example.test@8443"
    assert restored.websocket.messages[0].text == "saved websocket message"
    assert isinstance(restored.websocket, http.WebSocketData)
    restored.websocket.messages[0].drop()
    assert not detached.websocket.messages[0].dropped
    flow.request.headers["x-restored-certificate"] = str(cert.serial)
    print("connection and certificate restored")
'''.replace('CERTIFICATE_PEM', repr(pem))
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [callback('descriptors', 'connection-start'),
                     callback('descriptors', 'connection-content', wire)]
        output, stderr = self.run_worker({'script': source}, callbacks)
        response = output[-1]
        self.assertTrue(response['ok'], response)
        self.assertIn('connection and certificate restored', response['logs'])
        frames = unpack(base64.b64decode(response['replacement']))
        header = next(payload for kind, flags, stream, payload in frames if kind == 1)
        self.assertIn((b'x-restored-certificate', b'123'),
                      hpack.Decoder().decode(header, raw=True))

    def test_public_message_base_type_in_annotations_and_live_request(self):
        source = '''#!mitmproxy
from mitmproxy import http
def mark(message: http.Message):
    assert isinstance(message, http.Message)
    message.headers["x-message-base"] = "shared"
def request(flow: http.HTTPFlow):
    assert isinstance(flow.request, http.Request)
    assert issubclass(http.Response, http.Message)
    response = http.Response.make(200, b"test")
    mark(response)
    mark(flow.request)
    print(response.headers["x-message-base"])
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [callback('message-base', 'connection-start'),
                     callback('message-base', 'connection-content', wire)]
        output, stderr = self.run_worker({'script': source}, callbacks)
        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        response = output[-1]
        self.assertTrue(response['ok'], response)
        self.assertIn('shared', response['logs'])
        frames = unpack(base64.b64decode(response['replacement']))
        header = next(payload for kind, flags, stream, payload in frames if kind == 1)
        self.assertIn((b'x-message-base', b'shared'),
                      hpack.Decoder().decode(header, raw=True))

    def test_registration_error_can_be_caught_during_worker_startup(self):
        source = '''#!mitmproxy
from mitmproxy import ctx
class Broken:
    def load(self, loader):
        raise ValueError("registration rejected")
    def done(self):
        print("unexpected done")
def load(loader):
    try:
        ctx.master.addons.add(Broken())
    except ValueError:
        assert ctx.master.addons.get("broken") is None
        print("registration caught")
def request(flow):
    pass
'''
        output, stderr = self.run_worker(
            {'script': source}, [callback('registration', 'connection-start')])
        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        self.assertTrue(output[1]['ok'], output)
        logs = '\n'.join(output[1]['logs'])
        self.assertIn('registration caught', logs)
        self.assertNotIn('unexpected done', logs + stderr)

    def test_nested_configuration_rejection_keeps_prior_error_in_worker_logs(self):
        source = '''#!mitmproxy
from mitmproxy import ctx, hooks, exceptions
def configure(updated):
    if "probe" in updated:
        raise ValueError("earlier callback failed")
class Rejecting:
    def configure(self, updated):
        if "probe" in updated:
            raise exceptions.OptionsError("rejected")
addons = [Rejecting()]
def request(flow):
    try:
        ctx.master.addons.trigger(hooks.ConfigureHook({"probe"}))
    except exceptions.OptionsError:
        print("rejection caught")
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [callback('errors', 'connection-start'),
                     callback('errors', 'connection-content', wire)]
        output, stderr = self.run_worker({'script': source}, callbacks)
        response = output[-1]
        self.assertTrue(response['ok'], response)
        self.assertIn('rejection caught', response['logs'])
        self.assertEqual('\n'.join(response['logs']).count('earlier callback failed'), 1)

    def test_public_lifecycle_handler_runs_inside_packaged_worker(self):
        source = '''#!mitmproxy
from mitmproxy import ctx, exceptions, hooks

events = []
mode = "success"

class First:
    def update(self, flows):
        events.append("first:" + mode)
        if mode == "ordinary":
            raise ValueError("ordinary lifecycle failure")
        if mode == "options":
            raise exceptions.OptionsError("lifecycle rejected")

class Second:
    async def update(self, flows):
        events.append("second:" + mode)

addons = [First(), Second()]

async def request(flow):
    global mode
    events.clear()
    for selected in ("success", "ordinary"):
        mode = selected
        assert await ctx.master.addons.handle_lifecycle(
            hooks.UpdateHook([flow])
        ) is None

    mode = "options"
    try:
        await ctx.master.addons.handle_lifecycle(hooks.UpdateHook([flow]))
    except exceptions.OptionsError:
        events.append("options:caught")

    flow.request.headers["x-lifecycle-events"] = ",".join(events)
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [callback('lifecycle-handler', 'connection-start'),
                     callback('lifecycle-handler', 'connection-content', wire)]
        output, stderr = self.run_worker({'script': source}, callbacks)
        response = output[-1]
        self.assertTrue(response['ok'], response)
        frames = unpack(base64.b64decode(response['replacement']))
        header = next(payload for kind, flags, stream, payload in frames if kind == 1)
        fields = dict(hpack.Decoder().decode(header, raw=True))
        self.assertEqual(fields[b'x-lifecycle-events'], (
            b'first:success,second:success,'
            b'first:ordinary,second:ordinary,'
            b'first:options,options:caught'
        ))
        self.assertEqual(
            '\n'.join(response['logs']).count('ordinary lifecycle failure'),
            1,
        )

    def test_failed_startup_cleans_registered_addons_without_hiding_original_error(self):
        source = '''#!mitmproxy
from mitmproxy import ctx
class Dynamic:
    name = "dynamic"
    def load(self, loader):
        print("dynamic loaded")
    def done(self):
        import __spider_addon__
        from mitmproxy import ctx
        assert ctx.master.addons.get(self.name) is self
        print("dynamic done")
        CLEANUP_ACTION
ctx.master.addons.add(Dynamic())
raise RuntimeError("original startup failure")
'''
        cases = (('pass', None),
                 ('raise ValueError("cleanup failure")', 'cleanup failure'),
                 ('raise SystemExit("cleanup aborted")', 'Addon startup cleanup aborted'))
        for cleanup, diagnostic in cases:
            with self.subTest(cleanup=cleanup):
                output, stderr = self.run_worker({'script': source.replace('CLEANUP_ACTION', cleanup)})
                self.assertEqual(len(output), 1)
                response = output[0]
                self.assertFalse(response['ok'])
                self.assertIn('original startup failure', response['error'])
                self.assertEqual(response['logs'].count('dynamic loaded'), 1)
                self.assertEqual(response['logs'].count('dynamic done'), 1)
                if diagnostic is not None:
                    self.assertIn(diagnostic, '\n'.join(response['logs']))
                self.assertNotIn('ready', response)

    def test_dynamic_addon_is_shared_by_connections_in_the_worker(self):
        source = '''#!mitmproxy
from mitmproxy import ctx
class Dynamic:
    name = "dynamic"
    def __init__(self):
        self.calls = 0
    def load(self, loader):
        print("dynamic loaded")
    def request(self, flow):
        self.calls += 1
        flow.request.path = "/dynamic/" + str(self.calls)
        print(self.calls)
    def done(self):
        print("dynamic done " + str(self.calls))
def request(flow):
    if ctx.master.addons.get("dynamic") is None:
        ctx.master.addons.add(Dynamic())
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = []
        for identity in ('first', 'second'):
            callbacks.append(callback(identity, 'connection-start'))
            callbacks.append(callback(identity, 'connection-content', wire))
        output, stderr = self.run_worker({'script': source}, callbacks)
        self.assertEqual(output[2]['logs'], ['dynamic loaded', '1'])
        self.assertEqual(output[4]['logs'], ['2'])
        for index, number in ((2, 1), (4, 2)):
            self.assertTrue(output[index]['ok'], output[index])
            frames = unpack(base64.b64decode(output[index]['replacement']))
            header = next(payload for kind, flags, stream, payload in frames if kind == 1)
            self.assertIn((b':path', ('/dynamic/' + str(number)).encode()),
                          hpack.Decoder().decode(header, raw=True))
        self.assertEqual(stderr.splitlines().count('dynamic done 2'), 1)

    def test_native_execution_and_validation_do_not_load_addon_dependencies(self):
        # Make absent optional runtime dependencies observable even on a test
        # machine where both codecs happen to be installed.
        blocker = '''import sys
class RejectAddonDependencies:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {"brotli", "zstandard", "cryptography", "emoji", "wsproto"}:
            raise ImportError("Addon dependency must not load on this path")
        return None
sys.meta_path.insert(0, RejectAddonDependencies())
'''
        cases = [
            {'script': 'print("native")'},
            {'script': 'print("native")', 'script_api': 'spider'},
            {'script': '#!mitmproxy\nimport brotli\ndef request(flow): pass',
             'validate_only': True},
        ]
        # Install the import blocker inside the bounded production payload.
        # This keeps the dependency check valid as the compatibility surface
        # grows beyond Linux's per-argument exec limit.
        command = worker_command(prefix=blocker)
        for initial in cases:
            with self.subTest(initial=initial):
                request = dict(callback('native', 'connection-start'), **initial)
                result = subprocess.run(
                    command,
                    input=json.dumps(request), text=True, capture_output=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr[-2000:])
                response = json.loads(result.stdout)
                self.assertTrue(response['ok'], response)
                if not initial.get('validate_only'):
                    self.assertEqual(response['logs'], ['native'])

    def test_compressed_content_mutation_inside_sandbox(self):
        source = '''#!mitmproxy
from mitmproxy import http
def request(flow):
    for coding in ("br", "zstd"):
        message = http.Response.make(200, b"original")
        message.encode(coding)
        assert message.content == b"original"
        message.content = b"changed"
        assert message.headers["content-encoding"] == coding
        assert message.content == b"changed"
        message.decode()
        assert message.raw_content == b"changed"
        print(coding)
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/codecs')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [callback('codecs', 'connection-start'),
                     callback('codecs', 'connection-content', wire)]
        output, stderr = self.run_worker({'script': source}, callbacks)
        self.assertTrue(output[-1]['ok'], output[-1])
        self.assertEqual(output[-1]['logs'], ['br', 'zstd'])

    def test_addon_command_changes_live_request_inside_sandbox(self):
        source = '''#!mitmproxy
from mitmproxy import command, ctx, flowfilter, types
from mitmproxy.coretypes import serializable
from mitmproxy.log import ALERT, LogEntry
from mitmproxy.net import encoding
from mitmproxy.utils import human, strutils
count = 0
@command.command("probe.next")
def next_value(amount: int) -> int:
    global count
    count += amount
    return count
def load(loader):
    loader.add_command("probe.explicit", next_value)
@command.command("probe.invalid")
def invalid(value: float) -> str:
    return str(value)
@command.command("probe.label")
def label(value: str) -> str:
    return value
def request(flow):
    assert isinstance(flow, serializable.Serializable)
    assert isinstance(flow.request, serializable.Serializable)
    assert ALERT == 21
    assert repr(LogEntry("ready", "alert")) == "LogEntry(ready, alert)"
    assert flowfilter.match('~m GET & ~d example\\.test', flow)
    assert strutils.bytes_to_escaped_str(b"line\\n") == r"line\\n"
    assert strutils.cut_after_n_lines("one\\ntwo\\nthree", 2) == "one\\ntwo\\n"
    assert strutils.is_mostly_bin(bytes(range(32)))
    assert strutils.is_xml(b"  <root/>")
    assert encoding.decode(encoding.encode(b"payload", "gzip"), "gzip") == b"payload"
    assert human.pretty_size(1536) == "1.5k"
    assert human.parse_size("2m") == 2 * 1024 * 1024
    assert human.format_address(("::1", 443)) == "[::1]:443"
    assert list(strutils.hexdump(b"abc")) == [
        ("0000000000", "61 62 63                                       ", "abc")
    ]
    parsed, remaining = ctx.master.commands.parse_partial('  probe.next\t"2"')
    assert [(item.value, item.type, item.valid) for item in parsed] == [
        ('  ', types.Space, True),
        ('probe.next', types.Cmd, True),
        ('    ', types.Space, True),
        ('"2"', int, False),
    ]
    assert remaining == []
    assert ctx.master.commands.execute('probe.label "two words"') == "two words"
    assert ctx.master.commands.execute('probe.label "unfinished words') == '"unfinished words'
    ctx.master.commands.execute("probe.next 2")
    value = ctx.master.commands.call("probe.explicit", 1)
    flow.request.headers["x-command-value"] = str(value)
    flow.request.headers["x-alert-level"] = str(ALERT)
    flow.request.headers["x-flowfilter"] = "matched"
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/commands')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = []
        for identity in ('first', 'second'):
            callbacks.extend([callback(identity, 'connection-start'),
                              callback(identity, 'connection-content', wire)])
        output, stderr = self.run_worker({'script': source}, callbacks)
        diagnostics = '\n'.join(line for response in output for line in response.get('logs', []))
        self.assertIn('probe.invalid', diagnostics)
        for index, expected in ((2, b'3'), (4, b'6')):
            response = output[index]
            self.assertTrue(response['ok'], response)
            frames = unpack(base64.b64decode(response['replacement']))
            headers = hpack.Decoder().decode(frames[0][3], raw=True)
            self.assertIn((b'x-command-value', expected), headers)
            self.assertIn((b'x-alert-level', b'21'), headers)
            self.assertIn((b'x-flowfilter', b'matched'), headers)

    def test_awaited_typed_command_shares_state_inside_packaged_worker(self):
        source = '''#!mitmproxy
import asyncio
from mitmproxy import command, ctx

count = 0

@command.command("probe.async-next")
async def async_next(amount: int) -> int:
    global count
    await asyncio.sleep(0)
    count += amount
    return count

async def request(flow):
    value = await ctx.master.commands.call("probe.async-next", 2)
    flow.request.headers["x-async-command"] = str(value)
'''
        wire = frame(hpack.Encoder().encode([
            (b':method', b'GET'),
            (b':scheme', b'https'),
            (b':authority', b'example.test'),
            (b':path', b'/async-command'),
        ]), 1, 5)
        callbacks = []
        for identity in ('async-command-one', 'async-command-two'):
            callbacks.extend((
                callback(identity, 'connection-start'),
                callback(identity, 'connection-content', wire),
                callback(identity, 'connection-stop'),
            ))

        output, _ = self.run_worker({'script': source}, callbacks)
        for result, expected in zip((output[2], output[5]), (b'2', b'4')):
            self.assertTrue(result['ok'], result)
            frames = unpack(base64.b64decode(result['replacement']))
            headers = hpack.Decoder().decode(frames[0][3], raw=True)
            self.assertIn((b'x-async-command', expected), headers)

    def test_flow_command_mutates_selected_live_object_inside_worker(self):
        source = '''#!mitmproxy
from collections.abc import Sequence
from mitmproxy import command, ctx
from mitmproxy.flow import Flow
current = []
@command.command("view.flows.resolve")
def resolve(expression: str) -> Sequence[Flow]:
    assert expression == "@current"
    return current
@command.command("probe.annotate")
def annotate(selected: Sequence[Flow]) -> None:
    assert selected is current
    for flow in selected:
        flow.request.headers["x-flow-command"] = "selected"
def request(flow):
    current[:] = [flow]
    ctx.master.commands.execute("probe.annotate @current")
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/flow-command')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [callback('flow-command', 'connection-start'),
                     callback('flow-command', 'connection-content', wire)]
        output, stderr = self.run_worker({'script': source}, callbacks)
        response = output[-1]
        self.assertTrue(response['ok'], response)
        frames = unpack(base64.b64decode(response['replacement']))
        headers = hpack.Decoder().decode(frames[0][3], raw=True)
        self.assertIn((b'x-flow-command', b'selected'), headers)

    def test_extended_command_types_inside_packaged_worker(self):
        source = '''#!mitmproxy
from collections.abc import Sequence
from mitmproxy import command, ctx, types
@command.command("probe.choices")
def choices() -> Sequence[str]:
    return ["one", "two"]
@command.command("probe.choice")
def choice(value: types.Choice("probe.choices")) -> str:
    return value
@command.command("probe.bytes")
def byte_count(value: bytes) -> int:
    return len(value)
@command.command("probe.cut")
def cut(fields: types.CutSpec) -> str:
    return "|".join(fields)
@command.command("probe.marker")
def marker(value: types.Marker) -> str:
    return value
def request(flow):
    assert types.CommandTypes.get(bytes).display == "bytes"
    assert types.CommandTypes.get(types.Choice("probe.choices")).display == "choice"
    assert ctx.master.commands.execute("probe.choice one") == "one"
    assert ctx.master.commands.call_strings("probe.bytes", [r"line\\nnext"]) == 9
    assert ctx.master.commands.execute("probe.cut request.method,response.status_code") == "request.method|response.status_code"
    value = ctx.master.commands.execute("probe.marker :warning:")
    flow.request.headers["x-extended-command"] = value
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/extended-command')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [callback('extended-command', 'connection-start'),
                     callback('extended-command', 'connection-content', wire)]
        output, stderr = self.run_worker({'script': source}, callbacks)
        response = output[-1]
        self.assertTrue(response['ok'], response)
        frames = unpack(base64.b64decode(response['replacement']))
        headers = hpack.Decoder().decode(frames[0][3], raw=True)
        self.assertIn((b'x-extended-command', b':warning:'), headers)

    def test_request_object_replacement_inside_packaged_worker(self):
        source = '''#!mitmproxy
selected = None
def requestheaders(flow):
    global selected
    flow.request = flow.request.copy()
    flow.request.headers["x-header-replacement"] = "yes"
    selected = flow.request
def request(flow):
    assert flow.request is selected
    original = flow.request
    flow.request = original.copy()
    flow.request.path = "/replaced"
    flow.request.content = b"replacement body"
    assert original.path == "/original"
'''
        fields = [(b':method', b'POST'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/original')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [callback('replace', 'connection-start'),
                     callback('replace', 'connection-content', wire)]
        output, stderr = self.run_worker({'script': source}, callbacks)
        response = output[-1]
        self.assertTrue(response['ok'], response)
        frames = unpack(base64.b64decode(response['replacement']))
        headers = hpack.Decoder().decode(frames[0][3], raw=True)
        self.assertIn((b':path', b'/replaced'), headers)
        self.assertIn((b'x-header-replacement', b'yes'), headers)
        self.assertEqual(b''.join(payload for kind, flags, stream, payload in frames
                                 if kind == 0), b'replacement body')

    def test_multipart_form_creation_inside_sandbox(self):
        source = '''#!mitmproxy
from mitmproxy.coretypes.multidict import MultiDict

def request(flow):
    flow.request.multipart_form = [(b"first", b"one"), (b"first", b"two")]
    form = flow.request.multipart_form
    assert isinstance(form.fields, list)
    assert not isinstance(form, MultiDict)
    assert not hasattr(form, "get_state")
    assert form.get_all(b"first") == [b"one", b"two"]
    try:
        form.add(b"first", b"third")
    except TypeError:
        pass
    else:
        raise AssertionError("List-backed insertion must match the reference")
    assert form.get_all(b"first") == [b"one", b"two"]
    flow.request.multipart_form[b"first"] = b"changed"
    print(flow.request.multipart_form[b"first"].decode())
'''
        fields = [(b':method', b'POST'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/form')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [callback('form', 'connection-start'),
                     callback('form', 'connection-content', wire)]
        output, stderr = self.run_worker({'script': source}, callbacks)
        self.assertTrue(output[-1]['ok'], output[-1])
        self.assertEqual(output[-1]['logs'], ['changed'])

    def test_logging_is_captured_by_the_current_callback(self):
        source = '''#!mitmproxy
import logging
from mitmproxy import ctx

logging.info("module startup")

def request(flow):
    logging.info("request %s", flow.request.path)
    ctx.log.warn("legacy warning")
    ctx.log.alert("attention")

def done():
    logging.info("generation shutdown")
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/logs')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [callback('one', 'connection-start'),
                     callback('one', 'connection-content', wire),
                     callback('two', 'connection-start'),
                     callback('two', 'connection-content', wire)]
        output, stderr = self.run_worker({'script': source}, callbacks)
        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        self.assertEqual(output[1]['logs'], ['INFO: module startup'])
        self.assertEqual(output[3]['logs'], [])
        for response in (output[2], output[4]):
            self.assertTrue(response['ok'], response)
            self.assertIn('INFO: request /logs', response['logs'])
            self.assertIn('WARNING: legacy warning', response['logs'])
            self.assertIn('ALERT: attention', response['logs'])
            self.assertNotIn('INFO: module startup', response['logs'])
        self.assertIn('INFO: generation shutdown', stderr)

    def exchange(self, process, request):
        process.stdin.write(json.dumps(request) + '\n')
        process.stdin.flush()
        ready, _, _ = select.select([process.stdout], [], [], 5)
        self.assertTrue(ready, 'Worker did not respond within five seconds')
        line = process.stdout.readline()
        self.assertTrue(line, 'Worker exited without a response')
        return json.loads(line)

    def run_worker(self, initial, callbacks=(), *, persistent=True):
        requests = [initial]
        for index, item in enumerate(callbacks):
            requests.append(dict(item, _request_id=index))
        arguments = worker_command()
        if persistent:
            arguments.append('--persistent')
        result = subprocess.run(
            arguments, input=''.join(json.dumps(item) + '\n' for item in requests),
            text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-6000:])
        return [json.loads(line) for line in result.stdout.splitlines()], result.stderr

    def test_one_generation_serves_multiple_connections_and_captures_lifecycle_output(self):
        source = '''#!mitmproxy
import asyncio
print('module loaded')
counter = 0
def load(loader):
    print('load')
def running():
    print('running')
async def request(flow):
    global counter
    await asyncio.sleep(0.001)
    counter += 1
    flow.request.path = '/changed/' + str(counter)
def error(flow):
    print('closed pending request')
def done():
    print('done')
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/original')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = []
        for identity in ('one', 'two'):
            callbacks.append(callback(identity, 'connection-start'))
            callbacks.append(callback(identity, 'connection-content', wire))
        for identity in ('one', 'two'):
            callbacks.append(callback(identity, 'connection-stop'))
        # Callback envelopes cannot replace the deployed script or its mode.
        callbacks[2]['script'] = 'raise RuntimeError("must not execute")'
        callbacks[2]['script_api'] = 'spider'
        output, stderr = self.run_worker({'script': source, 'script_api': 'spider'}, callbacks)
        self.assertEqual(output.pop(0), {'ready': True, 'script_api': 'mitmproxy'})
        self.assertEqual(len(output), 6)
        for index, response in enumerate(output):
            self.assertTrue(response['ok'], response)
            self.assertEqual(response['_request_id'], index)
            self.assertEqual(response['script_api'], 'mitmproxy')
            self.assertEqual(response['script_api_source'], 'shebang')
        self.assertEqual(output[0]['logs'], ['module loaded', 'load', 'running'])
        self.assertEqual(output[2]['logs'], [])
        for index, expected in ((1, b'/changed/1'), (3, b'/changed/2')):
            response = output[index]
            self.assertTrue(response['translated'])
            frames = unpack(base64.b64decode(response['replacement']))
            header = next(payload for kind, flags, stream, payload in frames if kind == 1)
            self.assertIn((b':path', expected), hpack.Decoder().decode(header, raw=True))
        self.assertTrue(output[0]['rewrite_requested'])
        self.assertTrue(output[2]['rewrite_requested'])
        self.assertEqual(output[4]['logs'], ['closed pending request'])
        self.assertEqual(output[5]['logs'], ['closed pending request'])
        self.assertEqual(stderr.splitlines().count('done'), 1)

    def test_packaged_worker_preserves_client_identity_and_lifecycle_order(self):
        source = '''#!mitmproxy
observed_client = None
def client_connected(client):
    global observed_client
    observed_client = client
    print("connected", client.connected, client.timestamp_end is None)
def request(flow):
    print("request", flow.client_conn is observed_client)
def client_disconnected(client):
    print("disconnected", client is observed_client,
          client.connected, client.timestamp_end is not None)
'''
        fields = [
            (b':method', b'GET'),
            (b':scheme', b'https'),
            (b':authority', b'example.test'),
            (b':path', b'/lifecycle'),
        ]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        output, stderr = self.run_worker(
            {'script': source},
            [
                callback('client-lifecycle', 'connection-start'),
                callback('client-lifecycle', 'connection-content', wire),
                callback('client-lifecycle', 'connection-stop'),
            ],
        )

        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        self.assertEqual(output[1]['logs'], ['connected True True'])
        self.assertEqual(output[2]['logs'], ['request True'])
        self.assertEqual(output[3]['logs'], ['disconnected True False True'])
        self.assertNotIn('Traceback', stderr)

    def test_packaged_worker_keeps_late_stream_selection_as_a_noop(self):
        source = '''#!mitmproxy
def request(flow):
    flow.request.stream = True
    print("late stream", flow.request.stream, flow.request.raw_content.decode("ascii"))
'''
        fields = [
            (b':method', b'POST'),
            (b':scheme', b'https'),
            (b':authority', b'example.test'),
            (b':path', b'/late-stream'),
            (b'content-length', b'4'),
        ]
        wire = frame(hpack.Encoder().encode(fields), 1, 4)
        wire += frame(b'body', 0, 1)
        output, stderr = self.run_worker(
            {'script': source},
            [
                callback('late-stream-worker', 'connection-start'),
                callback('late-stream-worker', 'connection-content', wire),
                callback('late-stream-worker', 'connection-stop'),
            ],
        )

        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        self.assertTrue(output[1]['ok'], output[1])
        self.assertTrue(output[2]['ok'], output[2])
        self.assertEqual(output[2]['logs'], ['late stream True body'])
        self.assertEqual(base64.b64decode(output[2]['replacement']), wire)
        self.assertTrue(output[3]['ok'], output[3])
        self.assertNotIn('Traceback', stderr)

    def test_concurrent_lifecycle_hook_keeps_generation_state_in_one_worker(self):
        source = '''#!mitmproxy
import asyncio
from mitmproxy.script import concurrent

state = []

@concurrent
async def running():
    await asyncio.sleep(0.001)
    state.append('ready')

def request(flow):
    assert state[0] == 'ready'
    state.append(flow.request.path)
    flow.request.path = '/state/' + str(len(state) - 1)

@concurrent
def done():
    print('concurrent state: ' + ','.join(state))
'''
        fields = [
            (b':method', b'GET'),
            (b':scheme', b'https'),
            (b':authority', b'example.test'),
            (b':path', b'/first'),
        ]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [
            callback('one', 'connection-start'),
            callback('one', 'connection-content', wire),
            callback('two', 'connection-start'),
            callback('two', 'connection-content', wire),
        ]

        output, stderr = self.run_worker({'script': source}, callbacks)

        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        for response in output[1:]:
            self.assertTrue(response['ok'], response)
        for index, expected in ((2, b'/state/1'), (4, b'/state/2')):
            replacement = base64.b64decode(output[index]['replacement'])
            header = next(
                payload for kind, _flags, _stream, payload in unpack(replacement)
                if kind == 1
            )
            fields = hpack.Decoder().decode(header, raw=True)
            self.assertIn((b':path', expected), fields)
        self.assertIn('concurrent state: ready,/first,/first', stderr)

    def test_module_execution_happens_after_sandbox_and_cannot_corrupt_ready_protocol(self):
        source = "print('starting')\nopen('/etc/passwd').read()"
        output, stderr = self.run_worker({'script': source, 'script_api': 'mitmproxy'})
        self.assertEqual(len(output), 1)
        self.assertFalse(output[0]['ok'])
        self.assertIn('PermissionError', output[0]['error'])
        self.assertEqual(output[0]['logs'], ['starting'])
        self.assertNotIn('ready', output[0])

    def test_public_data_options_and_exception_exports_are_packaged(self):
        source = '''#!mitmproxy
from mitmproxy import addonmanager, connection, dns, exceptions, flow, hooks, http, tcp, tls, udp
from mitmproxy import optmanager, options
from mitmproxy.net import server_spec
from mitmproxy.proxy import context
from mitmproxy.proxy.layers import modes
from mitmproxy.proxy.layers import quic
from mitmproxy.proxy.layers import http as http_hooks
from mitmproxy.proxy.layers import dns as dns_hooks
from mitmproxy.proxy.layers import tcp as tcp_hooks
from mitmproxy.proxy.layers import tls as tls_hooks
from mitmproxy.proxy.layers import udp as udp_hooks
from mitmproxy.proxy.layers import websocket as websocket_hooks
from mitmproxy.proxy.layers.http import _hooks as private_http_hooks
from mitmproxy.proxy import server_hooks
from mitmproxy.utils import signals, typecheck
from typing import Sequence

assert issubclass(exceptions.ControlException, exceptions.MitmproxyException)
assert issubclass(exceptions.OptionsError, exceptions.MitmproxyException)
assert issubclass(exceptions.AddonManagerError, exceptions.MitmproxyException)
assert not issubclass(exceptions.CommandError, exceptions.MitmproxyException)
assert options.Options().http2 is True
assert options.Options().mode == ["regular"]
assert optmanager.OptManager().keys() == set()
typecheck.check_option_type("ratio", 1, float)
typecheck.check_option_type("names", ["one", "two"], Sequence[str])
assert typecheck.typespec_to_str(Sequence[str]) == "sequence of str"
signal_events = []
signal = signals.SyncSignal(lambda value: None)
def receive_signal(value):
    signal_events.append(value)
signal.connect(receive_signal)
signal.send("packaged")
assert signal_events == ["packaged"]
assert addonmanager.AddonManager is not None
assert hooks.all_hooks["request"] is http_hooks.HttpRequestHook
assert hooks.all_hooks["tls_start_client"] is tls_hooks.TlsStartClientHook
assert hooks.all_hooks["quic_start_client"] is quic.QuicStartClientHook
assert hooks.all_hooks["tcp_message"] is tcp_hooks.TcpMessageHook
assert hooks.all_hooks["socks5_auth"] is modes.Socks5AuthHook
assert connection.mode_specs.ProxyMode is not None
assert connection.certs.Cert is not None
assert connection.human.format_address(("::1", 443)) == "[::1]:443"
assert connection.serializable.Serializable is not None
assert http.encoding is not None
assert http.encoding.decode_gzip(http.encoding.encode_gzip(b"worker")) == b"worker"
assert http.encoding.custom_encode["deflateraw"] is http.encoding.encode_deflate
assert http.flow is flow
assert http.serializable.Serializable is not None
assert http.flow.connection is connection
assert flow.version.VERSION == "12.3.1"
assert server_spec.parse("https://example.test", "tcp") == ("https", ("example.test", 443))
assert dns.domain_names.unpack(dns.domain_names.pack("worker.test")) == "worker.test"
assert dns.flow is flow
assert dns.https_records.HTTPSRecord is dns.HTTPSRecord
assert dns.serializable.Serializable is http.serializable.Serializable
auth = modes.Socks5AuthData(
    connection.Client(
        peername=("192.0.2.10", 41000),
        sockname=("192.0.2.1", 1080),
    ),
    "alice",
    "secret",
)
assert auth.valid is False
auth.valid = True
assert modes.Socks5AuthHook(auth).args() == [auth]
hello_body = bytes.fromhex(
    "0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "0000041301c02f0100002d00000011000f00000c6578616d706c652e74657374"
    "0010000e000c02683208687474702f312e31123400020102"
)
hello = tls.ClientHello(hello_body)
assert hello.sni == "example.test"
assert hello.alpn_protocols == [b"h2", b"http/1.1"]
tls_context = context.Context(auth.client_conn, options.Options())
hello_data = tls.ClientHelloData(tls_context, hello)
hello_data.ignore_connection = True
assert hello_data.ignore_connection is True
assert tls.TlsData(auth.client_conn, tls_context).ssl_conn is None
assert tls_hooks.TlsClienthelloHook(hello_data).args() == [hello_data]
quic_settings = quic.QuicTlsSettings(alpn_protocols=["h3"])
quic_data = quic.QuicTlsData(
    auth.client_conn,
    tls_context,
    settings=quic_settings,
)
assert isinstance(quic_data, tls.TlsData)
assert quic_data.settings.alpn_protocols == ["h3"]
assert quic.QuicStartClientHook(quic_data).blocking is True
assert quic.QuicStartServerHook(quic_data).args() == [quic_data]
server_data = server_hooks.ServerConnectionHookData(
    connection.Server(address=("example.test", 443)),
    auth.client_conn,
)
assert server_hooks.ClientConnectedHook(auth.client_conn).blocking is True
assert server_hooks.ServerConnectHook(server_data).args() == [server_data]
assert server_hooks.ServerConnectedHook(server_data).name == "server_connected"
http_flow = http.HTTPFlow(auth.client_conn, server_data.server, live=True)
assert http_hooks._hooks is private_http_hooks
assert http_hooks.HttpRequestHook(http_flow).args() == [http_flow]
assert http_hooks.HttpResponseHeadersHook(http_flow).name == "responseheaders"
assert http_hooks.HttpConnectHook(http_flow).blocking is True
dns_flow = dns.DNSFlow(auth.client_conn, server_data.server, live=True)
tcp_flow = tcp.TCPFlow(auth.client_conn, server_data.server, live=True)
udp_flow = udp.UDPFlow(auth.client_conn, server_data.server, live=True)
assert websocket_hooks.WebsocketStartHook(http_flow).args() == [http_flow]
assert dns_hooks.DnsResponseHook(dns_flow).name == "dns_response"
assert tcp_hooks.TcpMessageHook(tcp_flow).args() == [tcp_flow]
assert udp_hooks.UdpEndHook(udp_flow).blocking is True

def request(flow):
    assert isinstance(flow.request.data, http.RequestData)
    copied = flow.request.data.copy()
    copied.set_state({"headers": ((b"x-public-data", b"yes"),)})
    assert copied.headers is not flow.request.headers
    flow.request.headers["x-public-data"] = copied.headers["x-public-data"]
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/')]
        callbacks = [
            callback('public-surface', 'connection-start'),
            callback('public-surface', 'connection-content',
                     frame(hpack.Encoder().encode(fields), 1, 5)),
        ]
        output, stderr = self.run_worker({'script': source}, callbacks)
        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        self.assertTrue(output[2]['ok'], output[2])
        wire = base64.b64decode(output[2]['replacement'])
        encoded = next(payload for kind, flags, stream, payload in unpack(wire)
                       if kind == 1)
        self.assertIn((b'x-public-data', b'yes'),
                      hpack.Decoder().decode(encoded, raw=True))
        self.assertNotIn('Traceback', stderr)

    def test_saved_flow_roundtrip_is_available_inside_packaged_addon(self):
        source = '''#!mitmproxy
from io import BytesIO
from mitmproxy import connection, http, io

def request(flow):
    client = connection.Client(peername=("127.0.0.1", 1234),
                               sockname=("127.0.0.1", 8080))
    server = connection.Server(address=("example.test", 443))
    detached = http.HTTPFlow(client, server)
    detached.request = flow.request.copy()
    saved = BytesIO()
    io.FlowWriter(saved).add(detached)
    restored = list(io.FlowReader(BytesIO(saved.getvalue())).stream())
    assert len(restored) == 1
    assert restored[0].live is False
    flow.request.headers["x-saved-path"] = restored[0].request.path
'''
        fields = [(b':method', b'GET'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/saved')]
        wire = frame(hpack.Encoder().encode(fields), 1, 5)
        callbacks = [callback('saved-flow', 'connection-start'),
                     callback('saved-flow', 'connection-content', wire)]
        output, _ = self.run_worker({'script': source}, callbacks)
        response = output[-1]
        self.assertTrue(response['ok'], response)
        frames = unpack(base64.b64decode(response['replacement']))
        encoded = next(payload for kind, _, _, payload in frames if kind == 1)
        self.assertIn((b'x-saved-path', b'/saved'),
                      hpack.Decoder().decode(encoded, raw=True))

    def test_fragmented_body_uses_native_checkpoints_without_replaying_hooks(self):
        source = '''#!mitmproxy
def requestheaders(flow):
    print('headers')
    assert flow.request.raw_content is None
def request(flow):
    print('request')
    flow.request.content = flow.request.content.upper()
'''
        process = subprocess.Popen(
            worker_command('--persistent'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(self.exchange(process, {'script': source}),
                             {'ready': True, 'script_api': 'mitmproxy'})
            setup = callback('body', 'connection-start')
            setup['_request_id'] = 1
            self.assertTrue(self.exchange(process, setup)['rewrite_requested'])
            fields = [(b':method', b'POST'), (b':scheme', b'https'),
                      (b':authority', b'example.test'), (b':path', b'/'),
                      (b'content-length', b'4')]
            first = frame(hpack.Encoder().encode(fields), 1, 4) + frame(b'ab', flags=0)
            request = callback('body', 'connection-content', first)
            request['_request_id'] = 2
            held = self.exchange(process, request)
            self.assertTrue(held['ok'], held)
            self.assertEqual(held['logs'], ['headers'])
            self.assertEqual(held['hold']['state'], 'holding')
            request = callback('body', 'connection-content', frame(b'cd'))
            request.update({
                '_request_id': 3, 'translate_active': True, 'translate_allowed': False,
                'translate_state': held['translate_state'],
                'translate_control': held['translate_control'],
                'held_parts': held['held_parts'],
                'hold_credit_reserved': held['hold_credit_reservation'],
            })
            released = self.exchange(process, request)
            self.assertTrue(released['ok'], released)
            self.assertEqual(released['logs'], ['request'])
            self.assertEqual(released['hold']['state'], 'released')
            output = base64.b64decode(held['replacement']) + base64.b64decode(released['replacement'])
            body = b''.join(payload for kind, flags, stream, payload in unpack(output) if kind == 0)
            self.assertEqual(body, b'ABCD')
            process.stdin.close()
            process.stdin = None
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr[-6000:])
            self.assertEqual(stdout, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_sized_multiplexed_bodies_share_packaged_worker_reservation(self):
        source = '''#!mitmproxy
def requestheaders(flow):
    print(flow.request.path)
    assert flow.request.raw_content is None
'''
        process = subprocess.Popen(
            worker_command('--persistent'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(self.exchange(process, {'script': source}),
                             {'ready': True, 'script_api': 'mitmproxy'})
            setup = callback('multiplexed-bodies', 'connection-start')
            setup['_request_id'] = 1
            self.assertTrue(self.exchange(process, setup)['rewrite_requested'])

            encoder = hpack.Encoder()
            wire = bytearray()
            for stream, path in ((1, b'/one'), (3, b'/three')):
                fields = [
                    (b':method', b'POST'),
                    (b':scheme', b'https'),
                    (b':authority', b'example.test'),
                    (b':path', path),
                    (b'content-length', b'100000'),
                ]
                wire.extend(frame(encoder.encode(fields), 1, 4, stream))
                wire.extend(frame(b'partial', 0, 0, stream))
            request = callback(
                'multiplexed-bodies', 'connection-content', bytes(wire))
            request['_request_id'] = 2
            held = self.exchange(process, request)
            self.assertTrue(held['ok'], held)
            self.assertEqual(held['logs'], ['/one', '/three'])
            self.assertEqual(held['hold']['state'], 'holding')
            reservations = held['translate_control']['flow']['L']['bodies']
            self.assertEqual(
                {stream: body['limit'] for stream, body in reservations.items()},
                {'1': 100000, '3': 100000})

            process.stdin.close()
            process.stdin = None
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr[-6000:])
            self.assertEqual(stdout, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_packaged_worker_turns_upstream_goaway_into_pending_response(self):
        source = '''#!mitmproxy
def error(flow):
    print(flow.request.path, str(flow.error))
'''
        process = subprocess.Popen(
            worker_command('--persistent'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(self.exchange(process, {'script': source}),
                             {'ready': True, 'script_api': 'mitmproxy'})
            setup = callback('goaway-worker', 'connection-start')
            setup['_request_id'] = 1
            self.assertTrue(self.exchange(process, setup)['rewrite_requested'])

            fields = [
                (b':method', b'GET'),
                (b':scheme', b'https'),
                (b':authority', b'example.test'),
                (b':path', b'/pending'),
            ]
            request = callback(
                'goaway-worker',
                'connection-content',
                frame(hpack.Encoder().encode(fields), 1, 5),
            )
            request['_request_id'] = 2
            observed = self.exchange(process, request)
            self.assertTrue(observed['ok'], observed)

            goaway_wire = frame(bytes(8), 7, 0, 0)
            goaway = callback(
                'goaway-worker', 'connection-content', goaway_wire)
            goaway['event']['details']['info']['side'] = 'R'
            goaway.update({
                '_request_id': 3,
                'translate_active': True,
                'translate_allowed': False,
                'translate_state': None,
                'translate_control': observed['translate_control'],
            })
            failed = self.exchange(process, goaway)
            self.assertTrue(failed['ok'], failed)
            self.assertEqual(len(failed['logs']), 1)
            self.assertIn('/pending HTTP/2 connection closed', failed['logs'][0])

            wire = base64.b64decode(failed['replacement'])
            decoder = hpack.Decoder()
            headers = []
            body = bytearray()
            for kind, _, stream, payload in unpack(wire):
                self.assertEqual(stream, 1)
                if kind == 1:
                    headers = decoder.decode(payload, raw=True)
                elif kind == 0:
                    body.extend(payload)
            self.assertEqual(dict(headers)[b':status'], b'502')
            self.assertEqual(dict(headers)[b'server'], b'mitmproxy 12.3.1')
            self.assertNotIn(b'content-length', dict(headers))
            self.assertIn(b'HTTP/2 connection closed:', body)
            self.assertFalse(any(kind == 7 for kind, _, _, _ in unpack(wire)))

            process.stdin.close()
            process.stdin = None
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr[-6000:])
            self.assertEqual(stdout, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_packaged_worker_turns_upstream_reset_into_stream_response(self):
        source = '''#!mitmproxy
def error(flow):
    print(flow.request.path, str(flow.error))
'''
        process = subprocess.Popen(
            worker_command('--persistent'),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(self.exchange(process, {'script': source}),
                             {'ready': True, 'script_api': 'mitmproxy'})
            setup = callback('reset-worker', 'connection-start')
            setup['_request_id'] = 1
            self.assertTrue(self.exchange(process, setup)['rewrite_requested'])

            fields = [
                (b':method', b'GET'),
                (b':scheme', b'https'),
                (b':authority', b'example.test'),
                (b':path', b'/reset'),
            ]
            request = callback(
                'reset-worker',
                'connection-content',
                frame(hpack.Encoder().encode(fields), 1, 5),
            )
            request['_request_id'] = 2
            observed = self.exchange(process, request)
            self.assertTrue(observed['ok'], observed)

            reset_wire = frame((7).to_bytes(4, 'big'), 3, 0)
            reset = callback(
                'reset-worker', 'connection-content', reset_wire)
            reset['event']['details']['info']['side'] = 'R'
            reset.update({
                '_request_id': 3,
                'translate_active': True,
                'translate_allowed': False,
                'translate_state': None,
                'translate_control': observed['translate_control'],
            })
            failed = self.exchange(process, reset)
            self.assertTrue(failed['ok'], failed)
            self.assertEqual(len(failed['logs']), 1)
            self.assertIn(
                '/reset stream reset by client (REFUSED_STREAM)',
                failed['logs'][0],
            )

            wire = base64.b64decode(failed['replacement'])
            frames = unpack(wire)
            self.assertFalse(any(kind == 3 for kind, _, _, _ in frames))
            decoder = hpack.Decoder()
            headers = []
            body = bytearray()
            for kind, _, stream, payload in frames:
                self.assertEqual(stream, 1)
                if kind == 1:
                    headers = decoder.decode(payload, raw=True)
                elif kind == 0:
                    body.extend(payload)
            self.assertEqual(dict(headers)[b':status'], b'502')
            self.assertEqual(dict(headers)[b'server'], b'mitmproxy 12.3.1')
            self.assertNotIn(b'content-length', dict(headers))
            self.assertIn(b'stream reset by client (REFUSED_STREAM)', body)

            process.stdin.close()
            process.stdin = None
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr[-6000:])
            self.assertEqual(stdout, '')
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_validation_is_inert_and_single_shot_execution_remains_explicitly_unavailable(self):
        initial = {'script': 'raise RuntimeError("do not execute")', 'script_api': 'mitmproxy'}
        output, stderr = self.run_worker(dict(initial, validate_only=True), persistent=False)
        self.assertTrue(output[0]['ok'], output)
        self.assertEqual(output[0]['logs'], [])
        output, stderr = self.run_worker(initial, persistent=False)
        self.assertFalse(output[0]['ok'])
        self.assertEqual(output[0]['error_kind'], 'unsupported_script_api')

    def test_failed_callback_retires_generation_instead_of_reinitializing_it(self):
        source = "print('loaded once')\ndef done():\n    print('done once')\n"
        setup = callback('same', 'connection-start')
        output, stderr = self.run_worker(
            {'script': source, 'script_api': 'mitmproxy'},
            [setup, setup, callback('another', 'connection-start')],
        )
        self.assertEqual(len(output), 3)
        self.assertEqual(output[0], {'ready': True, 'script_api': 'mitmproxy'})
        self.assertEqual(output[1]['logs'], ['loaded once'])
        self.assertTrue(output[1]['ok'])
        self.assertFalse(output[2]['ok'])
        self.assertIn('already registered', output[2]['error'])
        self.assertTrue(output[2]['_worker_recycle'])
        self.assertEqual(stderr.splitlines().count('done once'), 1)


if __name__ == '__main__':
    unittest.main()
