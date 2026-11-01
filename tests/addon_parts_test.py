"""Compatibility message edits published by the real native H2 translator."""

import asyncio
import gzip
from collections import deque
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

import hpack
import h2.events

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from addon_http import Headers
from addon_http_message import Response
from addon_connection import Client as AddonClient, Server as AddonServer
from addon_runtime import AddonGeneration
from addon_parts import AddonMessageError, H1MessageBinding, H2MessageBinding
from addon_h1_events import H1AddonEvents
from addon_h2_events import H2AddonEvents
from addon_native import NativeAddonAdapter
from addon_runtime import AddonRuntimeError
from inspection_api import (Message, Http2, Connection as ApiConnection,
                            CommitException, HeldCommit, resume_message,
                            _prepare_h1_responses)
from inspection_h2_test import frame, unpack, message as native_message
from inspection_translate_windows_test import Peers, Bridge


H2 = Http2(False, (), ())
REQUEST = [(b":method", b"POST"), (b":scheme", b"https"),
           (b":authority", b"example.org"), (b":path", b"/first")]


class Connection:
    """Use the native two-way flow ledger, including its real initial handshake."""

    def __init__(self, started=True):
        self.bridge = Peers().bridge if started else Bridge()
        self.held = self.bridge.held

    def message(self, side, wire):
        return self.bridge.message(side, wire)

    def publish(self, side, message):
        return self.bridge.publish(side, message)

    def feed(self, side, wire):
        return self.publish(side, self.message(side, wire))


def encoded(fields, stream=1, end=False, encoder=None):
    if encoder is None:
        encoder = hpack.Encoder()
    return frame(encoder.encode(fields), 1, 5 if end else 4, stream)


def bind(message, stream=1):
    header = next(part for part in message.parts if part.frame_type == 1 and part.stream_id == stream)
    return H2MessageBinding(message, header, H2, connection=ApiConnection(message))


def h1_message(wire):
    start_end = wire.index(b'\r\n') + 2
    head_end = wire.index(b'\r\n\r\n') + 4
    info = {'content_annotations': [
        [0, start_end, 'http1.start_line'],
        [start_end, head_end, 'http1.headers'],
    ]}
    return Message(wire, len(wire), info)


def h1_messages(*messages):
    wire = b''.join(messages)
    annotations = []
    offset = 0
    for message in messages:
        line_end = message.index(b'\r\n') + 2
        head_end = message.index(b'\r\n\r\n') + 4
        annotations.extend((
            [offset, offset + line_end, 'http1.start_line'],
            [offset + line_end, offset + head_end, 'http1.headers'],
        ))
        offset += len(message)
    return Message(wire, len(wire), {'content_annotations': annotations})


def h1_flow_message(side, *messages, state=None, connection_close=None):
    message = h1_messages(*messages)
    control = {'content-reverse': True}
    if connection_close is not None:
        control['connection-close'] = connection_close
    _prepare_h1_responses(message, {
        'instance': {'mode': 'flow'},
        'h1_response_state': state,
        'event': {'details': {'info': {
            'side': side,
            'webhook_control': control,
        }}},
    })
    return message


class PartsTests(unittest.TestCase):
    def test_h2_event_body_limit_is_bounded_and_rejects_boolean_values(self):
        for value in (True, False, 0, -1, 256 * 1024 + 1, 1.0):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'retained body limit'):
                    H2AddonEvents(None, body_limit=value)

        self.assertEqual(H2AddonEvents(None, body_limit=1).body_limit, 1)
        maximum = 256 * 1024
        self.assertEqual(H2AddonEvents(None, body_limit=maximum).body_limit, maximum)

    def test_h2_body_reservation_uses_one_trustworthy_source_length(self):
        driver = H2AddonEvents(None)

        def observed_limit(extra_fields):
            connection = Connection()
            message = connection.message(
                'L', encoded(REQUEST + list(extra_fields)))
            return driver._reservation_limit(bind(message))

        self.assertEqual(observed_limit(((b'content-length', b'123'),)), 123)
        self.assertEqual(observed_limit(((b'content-length', b'0'),)), 1)
        self.assertEqual(
            observed_limit(((b'content-length', b'300000'),)), 256 * 1024)
        self.assertEqual(observed_limit(()), 256 * 1024)
        self.assertEqual(
            observed_limit(((b'content-length', b'12'),
                            (b'content-length', b'12'))),
            256 * 1024)
        self.assertEqual(
            observed_limit(((b'content-length', b'invalid'),)), 256 * 1024)

    def test_h1_binding_publishes_start_line_headers_and_body(self):
        wire = (b'POST /old HTTP/1.1\r\nHost: example.test\r\n'
                b'Content-Length: 3\r\nX-Original: yes\r\n\r\nold')
        message = h1_message(wire)
        binding = H1MessageBinding(message, message.parts[0])
        self.assertTrue(binding.complete)
        self.assertEqual(binding.message.method, 'POST')
        self.assertEqual(binding.message.path, '/old')
        self.assertEqual(binding.message.pretty_host, 'example.test')
        self.assertEqual(binding.message.raw_content, b'old')

        binding.message.method = 'PATCH'
        binding.message.path = '/new'
        binding.message.headers['x-added'] = 'yes'
        binding.message.content = b'new body'
        binding.apply()
        result = message.commit()
        self.assertTrue(result.startswith(b'PATCH /new HTTP/1.1\r\n'))
        self.assertIn(b'x-added: yes\r\n', result)
        self.assertIn(b'Content-Length: 8\r\n', result)
        self.assertTrue(result.endswith(b'new body'))

    def test_h1_binding_rejects_unpublishable_message_shapes_atomically(self):
        def binding_for(wire):
            message = h1_message(wire)
            return message, H1MessageBinding(message, message.parts[0])

        message, binding = binding_for(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')
        binding.message.http_version = 'HTTP/2.0'
        with self.assertRaisesRegex(AddonMessageError, 'another protocol'):
            binding.apply()
        self.assertEqual(message.commit(), b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')

        message, binding = binding_for(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')
        binding.message = SimpleNamespace(http_version='HTTP/1.1')
        with self.assertRaisesRegex(AddonMessageError, 'retain the HTTP message kind'):
            binding.apply()
        self.assertEqual(message.commit(), b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')

        message, binding = binding_for(
            b'POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\n')
        self.assertFalse(binding.complete)
        binding.message.raw_content = b'new'
        with self.assertRaisesRegex(AddonMessageError, 'complete byte body'):
            binding.apply()
        self.assertIsNone(binding.body_part._pending)

        message, binding = binding_for(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')
        binding.message.trailers = Headers([(b'x-finished', b'yes')])
        with self.assertRaisesRegex(AddonMessageError, 'trailers require chunked framing'):
            binding.apply()
        self.assertEqual(message.commit(), b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')

    def test_h2_binding_rejects_ambiguous_or_foreign_parts(self):
        transport = Connection()

        first = transport.message('L', encoded(REQUEST, stream=1, end=True))
        second = transport.message('L', encoded(REQUEST, stream=3, end=True))
        foreign_header = next(part for part in first.parts if part.frame_type == 1)
        with self.assertRaisesRegex(AddonMessageError, 'does not belong'):
            H2MessageBinding(
                second,
                foreign_header,
                H2,
                connection=ApiConnection(second),
            )

        message = transport.message('L', encoded(REQUEST, stream=5, end=True))
        header = next(part for part in message.parts if part.frame_type == 1)
        header.headers.entries.append(H2.Header(b':method', b'GET'))
        with self.assertRaisesRegex(AddonMessageError, 'Duplicate HTTP/2 pseudo-header'):
            H2MessageBinding(message, header, H2, connection=ApiConnection(message))

        encoder = hpack.Encoder()
        wire = encoded(REQUEST, stream=7, encoder=encoder)
        wire += encoded([(b'x-first-trailer', b'one')], stream=7, encoder=encoder)
        wire += encoded(
            [(b'x-second-trailer', b'two')],
            stream=7,
            end=True,
            encoder=encoder,
        )
        message = transport.message('L', wire)
        header = next(part for part in message.parts if part.frame_type == 1)
        with self.assertRaisesRegex(AddonMessageError, 'More than one trailing header block'):
            H2MessageBinding(message, header, H2, connection=ApiConnection(message))

    def test_h2_binding_rejects_invalid_mutations_before_native_staging(self):
        def complete_binding(stream):
            transport = Connection()
            message = transport.message('L', encoded(REQUEST, stream=stream, end=True))
            return message, bind(message, stream)

        message, binding = complete_binding(1)
        binding.message.http_version = 'HTTP/1.1'
        with self.assertRaisesRegex(AddonMessageError, 'transport protocol'):
            binding.apply()
        self.assertIsNone(message._translation.result)

        message, binding = complete_binding(1)
        binding.message.raw_content = None
        with self.assertRaisesRegex(AddonMessageError, 'replacement body'):
            binding.apply()
        self.assertIsNone(message._translation.result)

        message, binding = complete_binding(1)
        binding.message.trailers = Headers([(b':status', b'200')])
        with self.assertRaisesRegex(AddonMessageError, 'Pseudo-headers are not allowed'):
            binding.apply()
        self.assertIsNone(message._translation.result)

    def test_h1_absolute_form_preserves_destination_while_editing_path(self):
        wire = (
            b'GET http://example.test:8080/old?q=1 HTTP/1.1\r\n'
            b'Host: ignored.test\r\n\r\n'
        )
        message = h1_message(wire)
        binding = H1MessageBinding(message, message.parts[0])

        self.assertEqual(binding.message.scheme, 'http')
        self.assertEqual(binding.message.host, 'example.test')
        self.assertEqual(binding.message.port, 8080)
        self.assertEqual(binding.message.authority, 'example.test:8080')
        self.assertEqual(binding.message.path, '/old?q=1')

        binding.message.path = '/new?q=2'
        binding.apply()
        result = message.commit()
        self.assertTrue(result.startswith(
            b'GET http://example.test:8080/new?q=2 HTTP/1.1\r\n'
        ))

    def test_h1_malformed_host_does_not_invent_a_destination(self):
        wire = b'GET / HTTP/1.1\r\nHost: [broken\r\n\r\n'
        message = h1_message(wire)
        binding = H1MessageBinding(message, message.parts[0])

        self.assertEqual(binding.message.host, '')
        self.assertEqual(binding.message.port, 0)
        self.assertEqual(binding.message.host_header, '[broken')

    def test_h1_binding_rejects_untyped_and_startless_groups(self):
        message = h1_message(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')
        with self.assertRaisesRegex(AddonMessageError, 'typed HTTP/1 header'):
            H1MessageBinding(message, message.parts[1])

        header = message.parts[0]
        header.http1.method = None
        header.http1.status_code = None
        with self.assertRaisesRegex(AddonMessageError, 'no request or response'):
            H1MessageBinding(message, header)

    def test_h1_non_chunked_message_rejects_new_trailers(self):
        wire = b'POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nold'
        message = h1_message(wire)
        binding = H1MessageBinding(message, message.parts[0])
        binding.message.trailers = Headers(((b'x-end', b'done'),))

        with self.assertRaisesRegex(AddonMessageError, 'chunked framing'):
            binding.apply()

    def test_h1_binding_rejects_destination_changes(self):
        wire = (b'GET / HTTP/1.1\r\nHost: example.test\r\n'
                b'Transfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n'
                b'3\r\nold\r\n0\r\nX-End: done\r\n\r\n')
        message = h1_message(wire)
        binding = H1MessageBinding(message, message.parts[0])
        self.assertEqual(binding.message.trailers['x-end'], 'done')
        binding.message.host = 'other.test'
        with self.assertRaisesRegex(AddonMessageError, 'destination'):
            binding.apply()

    def test_h1_binding_publishes_ordered_trailer_changes(self):
        wire = (b'GET / HTTP/1.1\r\nHost: example.test\r\n'
                b'Transfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n'
                b'3\r\nold\r\n0\r\nX-End: done\r\n\r\n')
        message = h1_message(wire)
        binding = H1MessageBinding(message, message.parts[0])
        binding.message.trailers.set_all('x-end', ['changed', 'again'])
        binding.message.trailers['x-extra'] = 'yes'
        binding.apply()
        result = message.commit()
        self.assertIn(b'Trailer: X-End, x-extra\r\n', result)
        self.assertTrue(result.endswith(
            b'0\r\nX-End: changed\r\nx-end: again\r\nx-extra: yes\r\n\r\n'))

    def test_h1_binding_preserves_content_encoding_when_editing_plain_content(self):
        encoded_body = gzip.compress(b'old plain text')
        wire = (b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: '
                + str(len(encoded_body)).encode() + b'\r\n\r\n' + encoded_body)
        message = h1_message(wire)
        binding = H1MessageBinding(message, message.parts[0])
        self.assertEqual(binding.message.content, b'old plain text')
        binding.message.content = b'new plain text'
        binding.apply()
        result = message.commit()
        compressed = result.split(b'\r\n\r\n', 1)[1]
        self.assertEqual(gzip.decompress(compressed), b'new plain text')

    def test_destination_changes_fail_before_native_drafts_are_modified(self):
        changes = (('host', 'other.example'), ('port', 8443),
                   ('scheme', 'http'), ('url', 'https://other.example/new'))
        for attribute, value in changes:
            with self.subTest(attribute=attribute):
                connection = Connection()
                message = connection.message('L', encoded(REQUEST, end=True))
                binding = bind(message)
                original = tuple(binding.header.headers.entries)
                setattr(binding.message, attribute, value)
                with self.assertRaisesRegex(AddonMessageError, 'destination'):
                    binding.apply()
                self.assertEqual(tuple(binding.header.headers.entries), original)

    def test_authority_header_edit_does_not_change_routing_destination(self):
        connection = Connection()
        message = connection.message('L', encoded(REQUEST, end=True))
        binding = bind(message)
        destination = (binding.message.host, binding.message.port)
        binding.message.host_header = 'virtual.example'
        self.assertEqual((binding.message.host, binding.message.port), destination)
        binding.apply()
        output = unpack(connection.publish('L', message))
        self.assertIn((b':authority', b'virtual.example'),
                      hpack.Decoder().decode(output[0][3], raw=True))

    def test_h2_connect_without_scheme_or_path_remains_valid(self):
        connection = Connection()
        fields = [(b':method', b'CONNECT'),
                  (b':authority', b'tunnel.example:8443')]
        message = connection.message('L', encoded(fields, end=True))
        binding = bind(message)

        self.assertEqual(binding.message.host, 'tunnel.example')
        self.assertEqual(binding.message.port, 8443)
        self.assertEqual(binding.message.scheme, '')
        self.assertEqual(binding.message.path, '')

        binding.message.headers['x-inspected'] = 'yes'
        binding.apply()
        output = unpack(connection.publish('L', message))
        headers = hpack.Decoder().decode(output[0][3], raw=True)
        self.assertEqual(headers[:2], fields)
        self.assertIn((b'x-inspected', b'yes'), headers)

    def test_h2_binding_preserves_table_size_updates_while_editing_fields(self):
        connection = Connection()
        message = connection.message('L', encoded(REQUEST, end=True))
        header = next(part for part in message.parts if part.frame_type == 1)
        update = H2.TableSize(128)
        header.headers.entries.insert(0, update)
        binding = H2MessageBinding(
            message,
            header,
            H2,
            connection=ApiConnection(message),
        )

        binding.message.headers['x-inspected'] = 'yes'
        binding.apply()
        self.assertIs(header.headers.entries[0], update)
        self.assertEqual(header.headers.entries[0].indexing, 'table-size')
        self.assertEqual(header.headers.entries[0].index, 128)

    def test_h2_binding_rejects_foreign_and_unresolved_headers(self):
        connection = Connection()
        message = connection.message('L', encoded(REQUEST, end=True))
        other = connection.message('L', encoded(REQUEST, stream=3, end=True))
        foreign = next(part for part in other.parts if part.frame_type == 1)

        with self.assertRaisesRegex(AddonMessageError, 'does not belong'):
            H2MessageBinding(
                message,
                foreign,
                H2,
                connection=ApiConnection(message),
            )

        header = next(part for part in message.parts if part.frame_type == 1)
        header.headers.entries.append(H2.Header(None, b'value'))
        with self.assertRaisesRegex(AddonMessageError, 'resolved by Translate'):
            H2MessageBinding(
                message,
                header,
                H2,
                connection=ApiConnection(message),
            )

    def test_path_component_edit_preserves_parameters_through_translate(self):
        fields = [(name, b'/a//b;keep?x=1' if name == b':path' else value)
                  for name, value in REQUEST]
        connection = Connection()
        message = connection.message('L', encoded(fields, end=True))
        binding = bind(message)
        self.assertEqual(binding.message.path_components, ('a', 'b'))
        binding.message.path_components = ('new', '\udcff')
        binding.apply()
        output = unpack(connection.publish('L', message))
        headers = hpack.Decoder().decode(output[0][3], raw=True)
        self.assertIn((b':path', b'/new/%FF;keep?x=1'), headers)

    def test_compressed_response_mutation_publishes_through_translate(self):
        for coding in ('br', 'zstd'):
            with self.subTest(coding=coding):
                original = Response.make(200, b'original payload')
                original.encode(coding)
                connection = Connection()
                connection.feed('L', encoded(REQUEST, end=True))
                fields = [(b':status', b'200'),
                          (b'content-encoding', coding.encode()),
                          (b'content-length', str(len(original.raw_content)).encode())]
                message = connection.message('R', encoded(fields) + frame(original.raw_content))
                binding = bind(message)
                self.assertEqual(binding.message.content, b'original payload')
                binding.message.content = b'replacement payload' * 100
                binding.apply()
                output = unpack(connection.publish('R', message))
                headers = hpack.Decoder().decode(output[0][3], raw=True)
                body = b''.join(payload for kind, flags, stream, payload in output if kind == 0)
                received = Response(b'HTTP/2.0', 200, b'',
                                    [(name, value) for name, value in headers if not name.startswith(b':')],
                                    body, None, 0, 0)
                self.assertEqual(received.content, b'replacement payload' * 100)
                self.assertEqual(received.headers['content-encoding'], coding)
                self.assertEqual(int(received.headers['content-length']), len(body))

    def test_multipart_mutation_publishes_through_native_translate(self):
        original = b'--sample\r\nContent-Disposition: form-data; name="field"\r\n\r\nold\r\n--sample--\r\n'
        fields = REQUEST + [(b"content-type", b"multipart/form-data; boundary=sample"),
                            (b"content-length", str(len(original)).encode())]
        connection = Connection()
        message = connection.message("L", encoded(fields) + frame(original))
        binding = bind(message)
        self.assertEqual(binding.message.multipart_form[b"field"], b"old")
        binding.message.multipart_form.set_all(b"field", [b"new", b"second"])
        expected = binding.message.content
        binding.apply()
        output = unpack(connection.publish("L", message))
        headers = hpack.Decoder().decode(output[0][3], raw=True)
        self.assertIn((b"content-length", str(len(expected)).encode()), headers)
        body = b"".join(payload for kind, flags, stream, payload in output if kind == 0)
        self.assertEqual(body, expected)
        self.assertIn(b"\r\nnew\r\n", body)
        self.assertIn(b"\r\nsecond\r\n", body)

    def test_response_refresh_publishes_dates_without_changing_payload(self):
        connection = Connection()
        connection.feed("L", encoded(REQUEST, end=True))
        fields = [(b":status", b"200"), (b"date", b"Thu, 01 Jan 1970 00:00:10 GMT"),
                  (b"set-cookie", b"id=one; Expires=Thu, 01 Jan 1970 00:00:20 GMT")]
        message = connection.message("R", encoded(fields) + frame(b"original"))
        binding = bind(message)
        binding.message.timestamp_start = 100
        binding.message.refresh(200)
        binding.apply()
        output = unpack(connection.publish("R", message))
        headers = hpack.Decoder().decode(output[0][3], raw=True)
        self.assertIn((b"date", b"Thu, 01 Jan 1970 00:01:50 GMT"), headers)
        self.assertIn((b"set-cookie", b"id=one; Expires=Thu, 01 Jan 1970 00:02:00 GMT"),
                      headers)
        body = b"".join(payload for kind, flags, stream, payload in output if kind == 0)
        self.assertEqual(body, b"original")

    def test_response_cookie_attributes_publish_as_separate_headers(self):
        connection = Connection()
        connection.feed("L", encoded(REQUEST, end=True))
        fields = [(b":status", b"200"), (b"set-cookie", b"sid=old; Path=/"),
                  (b"set-cookie", b"theme=dark"), (b"x-keep", b"unchanged")]
        message = connection.message("R", encoded(fields) + frame(b"response"))
        binding = bind(message)
        value, attributes = binding.message.cookies["sid"]
        attributes["HttpOnly"] = None
        binding.message.cookies["sid"] = ("new", attributes)
        binding.apply()
        output = unpack(connection.publish("R", message))
        headers = hpack.Decoder().decode(output[0][3], raw=True)
        cookies = [value for name, value in headers if name == b"set-cookie"]
        self.assertEqual(cookies, [b"sid=new; Path=/; HttpOnly", b"theme=dark"])
        self.assertIn((b"x-keep", b"unchanged"), headers)
        body = b"".join(payload for kind, flags, stream, payload in output if kind == 0)
        self.assertEqual(body, b"response")

    def test_request_cookies_publish_through_native_translate(self):
        fields = REQUEST + [(b"cookie", b"session=old; theme=dark"),
                            (b"cookie", b"session=second"),
                            (b"x-keep", b"unchanged")]
        connection = Connection()
        message = connection.message("L", encoded(fields) + frame(b"payload"))
        binding = bind(message)
        cookies = binding.message.cookies
        self.assertEqual(cookies.get_all("session"), ["old", "second"])
        cookies["session"] = "new value"
        binding.apply()
        output = unpack(connection.publish("L", message))
        headers = hpack.Decoder().decode(output[0][3], raw=True)
        self.assertIn((b"cookie", b'session="new value"; theme=dark'), headers)
        self.assertEqual(sum(name == b"cookie" for name, value in headers), 1)
        self.assertIn((b"x-keep", b"unchanged"), headers)
        body = b"".join(payload for kind, flags, stream, payload in output if kind == 0)
        self.assertEqual(body, b"payload")

    def test_noop_keeps_native_publication_identical(self):
        fields = REQUEST + [(b"x-repeat", b"one"), (b"x-repeat", b"two")]
        wire = encoded(fields) + frame(b"payload")
        baseline = Connection().feed("L", wire)
        connection = Connection()
        message = connection.message("L", wire)
        binding = bind(message)
        self.assertTrue(binding.complete)
        self.assertEqual(binding.message.headers.get_all("x-repeat"), ["one", "two"])
        self.assertEqual(binding.message.raw_content, b"payload")
        binding.apply()
        self.assertEqual(connection.publish("L", message), baseline)

    def test_request_changes_use_native_header_and_data_drafts(self):
        connection = Connection()
        wire = encoded(REQUEST + [(b"content-length", b"4")]) + frame(b"test")
        message = connection.message("L", wire)
        binding = bind(message)
        binding.message.method = "PUT"
        binding.message.path = "/changed"
        binding.message.headers["X-Addon"] = "yes"
        binding.message.content = b"TEST"
        binding.apply()
        result = unpack(connection.publish("L", message))
        fields = hpack.Decoder().decode(result[0][3], raw=True)
        self.assertIn((b":method", b"PUT"), fields)
        self.assertIn((b":path", b"/changed"), fields)
        self.assertIn((b"x-addon", b"yes"), fields)
        self.assertEqual(result[1][3], b"TEST")

    def test_complete_frame_does_not_expose_an_incomplete_message_body(self):
        connection = Connection()
        message = connection.message("L", encoded(REQUEST) + frame(b"half", flags=0))
        binding = bind(message)
        self.assertTrue(binding.header.complete)
        self.assertFalse(binding.complete)
        self.assertIsNone(binding.message.raw_content)
        binding.message.content = b"replacement"
        before = message.commit()
        with self.assertRaises(AddonMessageError):
            binding.apply()
        self.assertEqual(message.commit(), before)

    def test_headers_can_be_edited_before_body_completion(self):
        connection = Connection()
        message = connection.message("L", encoded(REQUEST))
        binding = bind(message)
        binding.message.headers["x-added"] = "header hook"
        binding.apply()
        message.parts.hold_from(binding.header)
        self.assertEqual(connection.publish("L", message), b"")
        resumed = connection.message("L", frame(b"complete"))
        completed = bind(resumed)
        self.assertTrue(completed.complete)
        self.assertEqual(completed.message.content, b"complete")
        self.assertEqual(completed.message.headers["x-added"], "header hook")
        completed.apply()
        result = unpack(connection.publish("L", resumed))
        self.assertIn((b"x-added", b"header hook"), hpack.Decoder().decode(result[0][3], raw=True))

    def test_interleaved_streams_do_not_share_body_or_headers(self):
        encoder = hpack.Encoder()
        wire = (encoded(REQUEST, encoder=encoder) + frame(b"ab", flags=0)
                + encoded(REQUEST, stream=3, encoder=encoder) + frame(b"other", stream=3)
                + frame(b"cd"))
        connection = Connection()
        message = connection.message("L", wire)
        first = bind(message)
        other = bind(message, 3)
        first.message.content = b"ABCD"
        first.message.headers["x-stream"] = "one"
        first.apply()
        self.assertEqual(other.message.raw_content, b"other")
        self.assertNotIn("x-stream", other.message.headers)
        other.apply()
        result = unpack(connection.publish("L", message))
        self.assertEqual([stream for kind, flags, stream, body in result], [1, 1, 3, 3, 1])
        self.assertEqual([body for kind, flags, stream, body in result if kind == 0], [b"AB", b"other", b"CD"])

    def test_trailers_are_part_of_message_completion(self):
        encoder = hpack.Encoder()
        wire = encoded(REQUEST, encoder=encoder) + frame(b"body", flags=0)
        wire += encoded([(b"x-trailer", b"original")], end=True, encoder=encoder)
        connection = Connection()
        message = connection.message("L", wire)
        binding = bind(message)
        self.assertEqual(binding.message.trailers["x-trailer"], "original")
        binding.message.trailers["x-trailer"] = "changed"
        binding.apply()
        result = unpack(connection.publish("L", message))
        decoder = hpack.Decoder()
        decoder.decode(result[0][3])
        self.assertEqual(decoder.decode(result[-1][3], raw=True), [(b"x-trailer", b"changed")])
        self.assertTrue(result[-1][1] & 1)

    def test_removed_trailers_move_end_stream_to_existing_data(self):
        encoder = hpack.Encoder()
        wire = encoded(REQUEST, encoder=encoder) + frame(b"body", flags=0)
        wire += encoded([(b"x-trailer", b"original")], end=True, encoder=encoder)
        connection = Connection()
        message = connection.message("L", wire)
        binding = bind(message)
        binding.message.trailers = None
        binding.apply()
        result = unpack(connection.publish("L", message))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[-1], (0, 1, 1, b"body"))

    def test_invalid_pseudo_header_change_is_atomic(self):
        wire = encoded(REQUEST, end=True)
        message = Connection().message("L", wire)
        binding = bind(message)
        original = tuple(binding.header.headers.entries)
        binding.message.headers[":path"] = "/wrong API"
        with self.assertRaises(AddonMessageError):
            binding.apply()
        self.assertEqual(tuple(binding.header.headers.entries), original)

    def test_unresolved_indexed_fields_are_not_guessed(self):
        encoder = hpack.Encoder()
        encoder.encode(REQUEST)
        message = native_message(encoded(REQUEST, end=True, encoder=encoder))
        with self.assertRaises(AddonMessageError):
            bind(message)

    def test_resizing_body_is_received_by_independent_http2_peer(self):
        peers = Peers()
        client = peers.peers["L"]
        client.send_headers(1, REQUEST + [(b"content-length", b"4")])
        client.send_data(1, b"test", end_stream=True)
        replacement = b"a much larger body" * 5000

        def edit(message):
            binding = bind(message)
            binding.message.content = replacement
            binding.apply()

        peers.pump("L", client.data_to_send(), edit)
        self.assertEqual(b"".join(peers.received["R"]), replacement)
        self.assertEqual(peers.ended["R"], [1])

    def test_add_body_to_header_only_request_via_native_frame_factory(self):
        peers = Peers()
        client = peers.peers["L"]
        client.send_headers(1, REQUEST, end_stream=True)

        def edit(message):
            binding = bind(message)
            binding.message.content = b"new body"
            binding.apply()

        peers.pump("L", client.data_to_send(), edit)
        self.assertEqual(peers.received["R"], [b"new body"])
        self.assertEqual(peers.ended["R"], [1])

    def test_add_trailers_to_header_only_request(self):
        peers = Peers()
        client = peers.peers["L"]
        client.send_headers(1, REQUEST, end_stream=True)

        def edit(message):
            binding = bind(message)
            binding.message.trailers = Headers([(b"x-new", b"yes")])
            binding.apply()

        peers.pump("L", client.data_to_send(), edit)
        self.assertEqual(peers.ended["R"], [1])

    def test_compressed_response_is_read_without_recompression(self):
        wire_body = gzip.compress(b"a body", mtime=123456)
        wire = encoded([(b":status", b"200"), (b"content-encoding", b"gzip")]) + frame(wire_body)
        connection = Connection()
        message = connection.message("R", wire)
        binding = bind(message)
        self.assertEqual(binding.message.text, "a body")
        binding.apply()
        result = unpack(connection.publish("R", message))
        self.assertEqual(result[-1][3], wire_body)

    def test_every_fragment_boundary_preserves_stream_ownership(self):
        encoder = hpack.Encoder()
        block = encoder.encode(REQUEST + [(b"content-length", b"4")])
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        wire = preface + frame(b"", 4, 0, 0)
        wire += frame(block[:3], 1, 0, 1) + frame(block[3:], 9, 4, 1)
        wire += frame(b"ab", flags=0)
        wire += encoded(REQUEST, stream=3, end=True, encoder=encoder)
        wire += frame(b"cd")
        wire += frame(b"12345678", 6, 0, 0)

        def exercise(chunks):
            connection = Connection(started=False)
            calls = []
            output = bytearray()
            for chunk in chunks:
                message = connection.message("L", chunk)
                for part in message.parts:
                    if not part.complete:
                        message.parts.hold_from(part)
                        break
                    if part.frame_type != 1 or part.headers is None:
                        continue
                    binding = H2MessageBinding(message, part, H2, connection=ApiConnection(message))
                    if not binding.complete:
                        message.parts.hold_from(part)
                        break
                    calls.append(binding.stream_id)
                    binding.message.headers["x-stream"] = str(binding.stream_id)
                    if binding.message.raw_content:
                        binding.message.content = binding.message.content.upper()
                    binding.apply()
                output.extend(connection.publish("L", message))
            self.assertEqual(calls, [1, 3])
            self.assertIsNone(connection.held.get("L"))
            self.assertTrue(output.startswith(preface))
            decoder = hpack.Decoder()
            bodies = {}
            for kind, flags, stream, payload in unpack(bytes(output[len(preface):])):
                if kind == 1:
                    fields = decoder.decode(payload, raw=True)
                    self.assertIn((b"x-stream", str(stream).encode()), fields)
                elif kind == 0:
                    bodies[stream] = bodies.get(stream, b"") + payload
                elif kind == 6:
                    self.assertEqual(payload, b"12345678")
            self.assertEqual(bodies, {1: b"ABCD"})

        for split in range(1, len(wire)):
            with self.subTest(split=split):
                exercise([wire[:split], wire[split:]])
        exercise([bytes([byte]) for byte in wire])

    def test_complete_message_larger_than_window_uses_native_body_reservation(self):
        for output_size in (0, 120000):
            with self.subTest(output_size=output_size):
                peers = Peers()
                client = peers.peers["L"]
                body_size = 100000
                client.send_headers(1, REQUEST + [(b"content-length", str(body_size).encode())])
                calls = []

                def edit(message):
                    binding = bind(message)
                    if not binding.complete:
                        message.parts.hold_from(binding.header)
                        ApiConnection(message).http2.reserve_body(binding.header, 128 * 1024)
                        return
                    calls.append(binding.stream_id)
                    self.assertEqual(binding.message.content, b"x" * body_size)
                    binding.message.content = b"y" * output_size
                    binding.apply()

                peers.pump("L", client.data_to_send(), edit)
                sent = 0
                while sent < body_size:
                    count = min(16000, body_size - sent, client.local_flow_control_window(1))
                    self.assertGreater(count, 0, "The held request must not stall at the initial H2 window")
                    sent += count
                    client.send_data(1, b"x" * count, end_stream=sent == body_size)
                    peers.pump("L", client.data_to_send(), edit)
                self.assertEqual(calls, [1])
                self.assertEqual(b"".join(peers.received["R"]), b"y" * output_size)
                self.assertEqual(peers.ended["R"], [1])
                self.assertFalse(peers.bridge.reserved)
                self.assertEqual(client.outbound_flow_control_window, 65535)


class AddonPublicationTests(unittest.IsolatedAsyncioTestCase):
    async def test_h1_driver_rejects_empty_typed_callback(self):
        addon = AddonGeneration("", H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        try:
            with self.assertRaisesRegex(AddonMessageError, "no typed message"):
                await driver.rewrite(
                    "empty", "L", Message(b"", 0), None, None
                )
            self.assertEqual(addon.state, "failed")
        finally:
            driver.release_connection("empty")
            await addon.close()

    async def test_h1_driver_rejects_response_after_host_releases_flow_early(self):
        addon = AddonGeneration("", H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        try:
            request = h1_message(
                b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
            )
            await driver.rewrite("released", "L", request, None, None)
            self.assertIsNotNone(addon.release_flow("released", 1))

            response = h1_message(b"HTTP/1.1 204 No Content\r\n\r\n")
            with self.assertRaisesRegex(
                AddonMessageError,
                "no observed addon request",
            ):
                await driver.rewrite(
                    "released", "R", response, None, None
                )
            self.assertEqual(addon.state, "failed")
        finally:
            driver.release_connection("released")
            await addon.close()

    async def test_http_drivers_reject_wrong_direction_and_remain_failed(self):
        h1_addon = AddonGeneration('', H1AddonEvents.HOOKS)
        await h1_addon.start()
        h1_driver = H1AddonEvents(h1_addon)
        h1_request = b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n'
        try:
            with self.assertRaisesRegex(ValueError, 'L/R direction'):
                await h1_driver.rewrite(
                    'h1-direction', 'invalid', h1_message(h1_request), None, None)
            self.assertEqual(h1_addon.state, 'running')

            with self.assertRaisesRegex(AddonMessageError, 'direction'):
                await h1_driver.rewrite(
                    'h1-direction', 'R', h1_message(h1_request), None, None)
            self.assertEqual(h1_addon.state, 'failed')
            with self.assertRaisesRegex(AddonMessageError, 'generation failed'):
                await h1_driver.rewrite(
                    'h1-direction', 'L', h1_message(h1_request), None, None)
        finally:
            h1_driver.release_connection('h1-direction')
            await h1_addon.close()

        h2_addon = AddonGeneration('', H2AddonEvents.HOOKS)
        await h2_addon.start()
        h2_driver = H2AddonEvents(h2_addon)
        try:
            invalid = Connection().message('L', encoded(REQUEST, end=True))
            with self.assertRaisesRegex(ValueError, 'L/R direction'):
                await h2_driver.prepare(
                    'h2-direction', 'invalid', invalid, H2,
                    ApiConnection(invalid), None, None)
            self.assertEqual(h2_addon.state, 'running')

            wrong = Connection().message('L', encoded(REQUEST, end=True))
            with self.assertRaisesRegex(AddonMessageError, 'direction'):
                await h2_driver.translate(
                    'h2-direction', 'R', wrong, H2,
                    ApiConnection(wrong), None, None)
            self.assertEqual(h2_addon.state, 'failed')

            retry = Connection().message('L', encoded(REQUEST, end=True))
            with self.assertRaisesRegex(AddonMessageError, 'generation failed'):
                await h2_driver.translate(
                    'h2-direction', 'L', retry, H2,
                    ApiConnection(retry), None, None)
        finally:
            h2_driver.release_connection('h2-direction')
            await h2_addon.close()

    async def test_http_drivers_reject_responses_without_observed_requests(self):
        h1_addon = AddonGeneration('', H1AddonEvents.HOOKS)
        await h1_addon.start()
        h1_driver = H1AddonEvents(h1_addon)
        response = b'HTTP/1.1 204 No Content\r\n\r\n'
        try:
            with self.assertRaisesRegex(AddonMessageError, 'no observed addon request'):
                await h1_driver.rewrite(
                    'h1-orphan', 'R', h1_message(response), None, None)
            self.assertEqual(h1_addon.state, 'failed')
        finally:
            h1_driver.release_connection('h1-orphan')
            await h1_addon.close()

        h2_addon = AddonGeneration('', H2AddonEvents.HOOKS)
        await h2_addon.start()
        h2_driver = H2AddonEvents(h2_addon)
        orphan = Connection().message(
            'R', encoded([(b':status', b'204')], end=True))
        try:
            with self.assertRaisesRegex(AddonMessageError, 'no observed addon request'):
                await h2_driver.translate(
                    'h2-orphan', 'R', orphan, H2,
                    ApiConnection(orphan), None, None)
            self.assertEqual(h2_addon.state, 'failed')
        finally:
            h2_driver.release_connection('h2-orphan')
            await h2_addon.close()

    async def test_h1_driver_holds_body_and_dispatches_each_hook_once(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    assert flow.request.raw_content is None
    events.append("headers")
    flow.request.headers["x-addon"] = "yes"
def request(flow):
    events.append(["request", flow.request.content])
    flow.request.method = "PATCH"
    flow.request.content = b"changed"
''', H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        head = (b'POST /old HTTP/1.1\r\nHost: example.test\r\n'
                b'Content-Length: 6\r\n\r\n')
        try:
            first = h1_message(head + b'abc')
            held, failures = await driver.rewrite(
                'one', 'L', first, None, None)
            self.assertIsInstance(held, HeldCommit)
            self.assertEqual(failures, ())
            self.assertEqual(addon.addon.module.events, ['headers'])

            second = Message(b'def', 3)
            resume_message(second, held.checkpoint, {}, ())
            result, failures = await driver.rewrite(
                'one', 'L', second, None, None)
            self.assertEqual(failures, ())
            self.assertTrue(result.startswith(b'PATCH /old HTTP/1.1\r\n'))
            self.assertIn(b'x-addon: yes\r\n', result)
            self.assertTrue(result.endswith(b'changed'))
            self.assertEqual(addon.addon.module.events,
                             ['headers', ['request', b'abcdef']])
            self.assertEqual(addon.active_flows, 1)
        finally:
            driver.release_connection('one')
            await addon.close()

    async def test_h1_driver_handles_every_body_byte_boundary(self):
        body = bytes(range(32)) + b'\x00\xff\r\n'
        replacement = body[::-1] + b' changed'
        head = (
            b'POST /fragmented HTTP/1.1\r\n'
            b'Host: example.test\r\n'
            b'Content-Type: application/octet-stream\r\n'
            b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
        )
        source = '''events = []
def requestheaders(flow):
    events.append(["headers", flow.request.raw_content])
def request(flow):
    events.append(["request", flow.request.raw_content])
    flow.request.content = flow.request.content[::-1] + b" changed"
'''

        for cut in range(len(body) + 1):
            with self.subTest(cut=cut):
                addon = AddonGeneration(source, H1AddonEvents.HOOKS)
                await addon.start()
                driver = H1AddonEvents(addon)
                identity = 'h1-boundary-' + str(cut)
                try:
                    first = h1_message(head + body[:cut])
                    result, failures = await driver.rewrite(
                        identity, 'L', first, None, None)
                    self.assertEqual(failures, ())

                    if cut < len(body):
                        self.assertIsInstance(result, HeldCommit)
                        resumed = Message(body[cut:], len(body) - cut)
                        resume_message(resumed, result.checkpoint, {}, ())
                        result, failures = await driver.rewrite(
                            identity, 'L', resumed, None, None)
                        self.assertEqual(failures, ())

                    output_head, separator, output_body = bytes(result).partition(
                        b'\r\n\r\n'
                    )
                    self.assertEqual(separator, b'\r\n\r\n')
                    self.assertEqual(output_body, replacement)
                    self.assertIn(
                        b'Content-Length: ' + str(len(replacement)).encode(),
                        output_head,
                    )
                    self.assertEqual(addon.addon.module.events, [
                        ['headers', None],
                        ['request', body],
                    ])
                finally:
                    driver.release_connection(identity)
                    await addon.close()

    async def test_h1_response_handles_every_body_byte_boundary(self):
        body = b'response\x00payload\xff' + bytes(range(24))
        replacement = b'changed ' + body[::-1]
        response_head = (
            b'HTTP/1.1 200 OK\r\n'
            b'Content-Type: application/octet-stream\r\n'
            b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
        )
        source = '''events = []
def request(flow):
    events.append(["request", flow.request.path])
def responseheaders(flow):
    events.append(["headers", flow.response.raw_content])
def response(flow):
    events.append(["response", flow.response.raw_content])
    flow.response.status_code = 209
    flow.response.content = b"changed " + flow.response.content[::-1]
'''

        for cut in range(len(body) + 1):
            with self.subTest(cut=cut):
                addon = AddonGeneration(source, H1AddonEvents.HOOKS)
                await addon.start()
                driver = H1AddonEvents(addon)
                identity = 'h1-response-boundary-' + str(cut)
                try:
                    request = h1_message(
                        b'GET /fragmented HTTP/1.1\r\n'
                        b'Host: example.test\r\n\r\n'
                    )
                    request_result, failures = await driver.rewrite(
                        identity, 'L', request, None, None)
                    self.assertEqual(failures, ())
                    self.assertIsInstance(request_result, bytes)

                    first = h1_message(response_head + body[:cut])
                    result, failures = await driver.rewrite(
                        identity, 'R', first, None, None)
                    self.assertEqual(failures, ())

                    if cut < len(body):
                        self.assertIsInstance(result, HeldCommit)
                        resumed = Message(body[cut:], len(body) - cut)
                        resume_message(resumed, result.checkpoint, {}, ())
                        result, failures = await driver.rewrite(
                            identity, 'R', resumed, None, None)
                        self.assertEqual(failures, ())

                    output_head, separator, output_body = bytes(result).partition(
                        b'\r\n\r\n'
                    )
                    self.assertEqual(separator, b'\r\n\r\n')
                    self.assertTrue(output_head.startswith(
                        b'HTTP/1.1 209 OK\r\n'
                    ))
                    self.assertEqual(output_body, replacement)
                    self.assertIn(
                        b'Content-Length: ' + str(len(replacement)).encode(),
                        output_head,
                    )
                    self.assertEqual(addon.addon.module.events, [
                        ['request', '/fragmented'],
                        ['headers', None],
                        ['response', body],
                    ])
                    self.assertEqual(addon.active_flows, 0)
                finally:
                    driver.release_connection(identity)
                    await addon.close()

    async def test_h1_header_body_assignment_is_provisional(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    flow.request.content = b"too early"
    events.append(["headers", flow.request.raw_content, flow.request.headers["content-length"]])
def request(flow):
    events.append(["request", flow.request.raw_content, flow.request.headers["content-length"]])
''', H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        head = (b'POST /old HTTP/1.1\r\nHost: example.test\r\n'
                b'Content-Length: 6\r\n\r\n')
        try:
            first = h1_message(head + b'abc')
            held, failures = await driver.rewrite('one', 'L', first, None, None)
            self.assertEqual(failures, ())
            self.assertIsInstance(held, HeldCommit)

            second = Message(b'def', 3)
            resume_message(second, held.checkpoint, {}, ())
            result, failures = await driver.rewrite('one', 'L', second, None, None)
            self.assertEqual(failures, ())
            self.assertTrue(result.endswith(b'abcdef'))
            # Native H1 publication safely repairs framing after reproducing
            # the reference callback-visible provisional value.
            self.assertIn(b'Content-Length: 6\r\n', result)
            self.assertEqual(addon.addon.module.events, [
                ['headers', b'too early', '9'],
                ['request', b'abcdef', '9'],
            ])
        finally:
            driver.release_connection('one')
            await addon.close()

    async def test_h1_driver_rejects_unconnected_transport_decisions(self):
        cases = [
            ('flow.intercept()', 'Flow interception and termination'),
            ('flow.request.stream = True', 'Streaming callbacks', 'requestheaders'),
        ]
        wire = b'GET /guard HTTP/1.1\r\nHost: example.test\r\n\r\n'
        for case in cases:
            decision, reason, *hook = case
            with self.subTest(decision=decision):
                source = (
                    'from mitmproxy import http\ndef '
                    + (hook[0] if hook else 'request')
                    + '(flow):\n    '
                    + decision
                )
                addon = AddonGeneration(source, H1AddonEvents.HOOKS)
                await addon.start()
                driver = H1AddonEvents(addon)
                message = h1_message(wire)
                try:
                    with self.assertRaisesRegex(AddonMessageError, reason):
                        await driver.rewrite('guard', 'L', message, None, None)
                    self.assertEqual(addon.state, 'failed')
                    self.assertEqual(message.commit(), wire)
                finally:
                    driver.release_connection('guard')
                    await addon.close()

    async def test_h1_late_stream_selection_is_an_observable_noop(self):
        addon = AddonGeneration('''events = []
def request(flow):
    flow.request.stream = True
    events.append([flow.request.stream, flow.request.raw_content])
''', H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        wire = b'POST /late HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nbody'
        message = h1_message(wire)
        try:
            result, failures = await driver.rewrite(
                'late-stream', 'L', message, None, None)
            self.assertEqual(failures, ())
            self.assertEqual(result, wire)
            self.assertEqual(addon.addon.module.events, [[True, b'body']])
        finally:
            driver.release_connection('late-stream')
            await addon.close()

    async def test_h1_kill_hooks_close_only_after_native_publication(self):
        cases = (
            ('requestheaders', 'L', [
                'requestheaders', 'requestheaders-after-kill', 'error']),
            ('request', 'L', [
                'requestheaders', 'request', 'request-after-kill', 'error']),
            ('responseheaders', 'R', [
                'requestheaders', 'request',
                'responseheaders', 'responseheaders-after-kill', 'error']),
            ('response', 'R', [
                'requestheaders', 'request',
                'responseheaders', 'response', 'response-after-kill']),
        )
        request_wire = b'GET /kill HTTP/1.1\r\nHost: example.test\r\n\r\n'
        response_wire = b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody'

        for killed_hook, side, expected in cases:
            with self.subTest(hook=killed_hook):
                addon = AddonGeneration(f'''events = []
def report(name, flow):
    events.append(name)
def requestheaders(flow):
    report("requestheaders", flow)
    if {killed_hook!r} == "requestheaders":
        flow.kill()
        report("requestheaders-after-kill", flow)
def request(flow):
    report("request", flow)
    if {killed_hook!r} == "request":
        flow.kill()
        report("request-after-kill", flow)
def responseheaders(flow):
    report("responseheaders", flow)
    if {killed_hook!r} == "responseheaders":
        flow.kill()
        report("responseheaders-after-kill", flow)
def response(flow):
    report("response", flow)
    if {killed_hook!r} == "response":
        flow.kill()
        report("response-after-kill", flow)
def error(flow):
    assert str(flow.error) == "Connection killed."
    report("error", flow)
''', H1AddonEvents.HOOKS)
                await addon.start()
                driver = H1AddonEvents(addon)
                try:
                    request = h1_flow_message(
                        'L', request_wire, connection_close=True)
                    request_result, failures = await driver.rewrite(
                        'h1-kill', 'L', request, None, None)
                    self.assertEqual(failures, ())

                    if side == 'L':
                        self.assertEqual(request_result, b'')
                        terminal = request._h1_response
                    else:
                        self.assertEqual(request_result, request_wire)
                        response = h1_flow_message(
                            'R', response_wire,
                            state=request._h1_response.checkpoint,
                            connection_close=True,
                        )
                        response_result, failures = await driver.rewrite(
                            'h1-kill', 'R', response, None, None)
                        self.assertEqual(failures, ())
                        self.assertEqual(response_result, b'')
                        terminal = response._h1_response

                    self.assertEqual(
                        terminal.termination['reason'], 'Connection killed.')
                    self.assertEqual(terminal.reverse_output, b'')
                    self.assertEqual(terminal.checkpoint['slots'], [])
                    self.assertEqual(addon.addon.module.events, expected)
                    self.assertEqual(addon.active_flows, 0)
                finally:
                    driver.release_connection('h1-kill')
                    await addon.close()

    async def test_h1_kill_rejects_missing_or_invalid_capability_atomically(self):
        wire = b'GET /guard HTTP/1.1\r\nHost: example.test\r\n\r\n'
        source = 'def requestheaders(flow):\n    flow.kill()\n'
        for capability in (None, False, 1, 'true'):
            with self.subTest(capability=capability):
                addon = AddonGeneration(source, H1AddonEvents.HOOKS)
                await addon.start()
                driver = H1AddonEvents(addon)
                message = h1_flow_message(
                    'L', wire, connection_close=capability)
                try:
                    with self.assertRaisesRegex(
                            CommitException, 'connection-close capability'):
                        await driver.rewrite(
                            'h1-kill-capability', 'L', message, None, None)
                    self.assertIsNone(message._h1_response.result)
                    self.assertIsNone(message._h1_response.termination)
                    self.assertEqual(message.commit(), wire)
                    self.assertEqual(addon.state, 'failed')
                finally:
                    driver.release_connection('h1-kill-capability')
                    await addon.close()

    async def test_h1_kill_revalidates_capability_after_a_held_body(self):
        """A capability observed before a hold is not authority for its resume."""
        addon = AddonGeneration(
            'def request(flow):\n    flow.kill()\n',
            H1AddonEvents.HOOKS,
        )
        await addon.start()
        driver = H1AddonEvents(addon)
        head = (
            b'POST /kill HTTP/1.1\r\n'
            b'Host: example.test\r\n'
            b'Content-Length: 6\r\n\r\n'
        )
        try:
            first = h1_flow_message(
                'L', head + b'abc', connection_close=True)
            held, failures = await driver.rewrite(
                'h1-kill-resume', 'L', first, None, None)
            self.assertEqual(failures, ())
            self.assertIsInstance(held, HeldCommit)

            resumed = Message(b'def', 3)
            resume_message(resumed, held.checkpoint, {}, ())
            _prepare_h1_responses(resumed, {
                'instance': {'mode': 'flow'},
                'h1_response_state': first._h1_response.checkpoint,
                'event': {'details': {'info': {
                    'side': 'L',
                    'webhook_control': {'content-reverse': True},
                }}},
            })

            with self.assertRaisesRegex(
                    CommitException, 'connection-close capability'):
                await driver.rewrite(
                    'h1-kill-resume', 'L', resumed, None, None)

            self.assertIsNone(resumed._h1_response.result)
            self.assertIsNone(resumed._h1_response.termination)
            self.assertEqual(resumed.commit(), head + b'abcdef')
            self.assertEqual(addon.state, 'failed')
        finally:
            driver.release_connection('h1-kill-resume')
            await addon.close()

    async def test_h1_local_response_waits_behind_older_origin_response(self):
        addon = AddonGeneration('''from mitmproxy import http
events = []
def request(flow):
    events.append(["request", flow.request.path])
    if flow.request.path == "/local":
        flow.response = http.Response.make(204, b"local body", {"X-Local": "yes"})
def responseheaders(flow):
    events.append(["responseheaders", flow.request.path])
    if flow.request.path == "/local":
        flow.response.headers.add("X-Duplicate", "one")
        flow.response.headers.add("X-Duplicate", "two")
def response(flow):
    events.append(["response", flow.request.path])
    if flow.request.path == "/local":
        flow.response.trailers = http.Headers([(b"X-Finished", b"yes")])
''', H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        first = b'GET /origin HTTP/1.1\r\nHost: example.test\r\n\r\n'
        second = b'GET /local HTTP/1.1\r\nHost: example.test\r\n\r\n'
        try:
            requests = h1_flow_message('L', first, second)
            forward, failures = await driver.rewrite(
                'pipeline', 'L', requests, None, None)
            self.assertEqual(failures, ())
            self.assertEqual(forward, first)
            self.assertEqual(requests._h1_response.reverse_output, b'')
            state = requests._h1_response.checkpoint
            self.assertEqual(state['slots'][0], 'origin')
            self.assertIn('response', state['slots'][1])

            origin = b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin'
            response = h1_flow_message('R', origin, state=state)
            published, failures = await driver.rewrite(
                'pipeline', 'R', response, None, None)
            self.assertEqual(failures, ())
            self.assertTrue(published.startswith(origin))
            local = published[len(origin):]
            self.assertTrue(local.startswith(b'HTTP/1.1 204 No Content\r\n'))
            self.assertIn(b'X-Local: yes\r\n', local)
            self.assertEqual(local.count(b'X-Duplicate:'), 2)
            self.assertIn(b'Transfer-Encoding: chunked\r\n', local)
            self.assertTrue(local.endswith(
                b'a\r\nlocal body\r\n0\r\nX-Finished: yes\r\n\r\n'))
            self.assertEqual(response._h1_response.checkpoint['slots'], [])
            self.assertEqual(addon.addon.module.events, [
                ['request', '/origin'],
                ['request', '/local'],
                ['responseheaders', '/local'],
                ['response', '/local'],
                ['responseheaders', '/origin'],
                ['response', '/origin'],
            ])
        finally:
            driver.release_connection('pipeline')
            await addon.close()

    async def test_h1_requestheaders_local_response_still_runs_request_hook(self):
        addon = AddonGeneration('''from mitmproxy import http
events = []
def requestheaders(flow):
    events.append(["requestheaders", flow.request.raw_content])
    flow.response = http.Response.make(201, b"early")
def request(flow):
    events.append(["request", flow.request.raw_content, flow.response.status_code])
def responseheaders(flow):
    events.append(["responseheaders", flow.response.raw_content])
def response(flow):
    events.append(["response", flow.response.raw_content])
    flow.response.content += b" response"
''', H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        wire = (b'POST /early HTTP/1.1\r\nHost: example.test\r\n'
                b'Content-Length: 4\r\n\r\ntest')
        try:
            message = h1_flow_message('L', wire)
            result, failures = await driver.rewrite(
                'early', 'L', message, None, None)
            self.assertEqual(failures, ())
            self.assertEqual(result, b'')
            self.assertTrue(message._h1_response.reverse_output.endswith(
                b'early response'))
            self.assertEqual(addon.addon.module.events, [
                ['requestheaders', None],
                ['request', b'test', 201],
                ['responseheaders', b'early'],
                ['response', b'early'],
            ])
        finally:
            driver.release_connection('early')
            await addon.close()

    async def test_h1_driver_pairs_responses_and_preserves_addon_state(self):
        addon = AddonGeneration('''events = []
sequence = 0
def request(flow):
    global sequence
    sequence += 1
    flow.metadata["sequence"] = sequence
    events.append(["request", sequence, flow.request.path])
def response(flow):
    events.append(["response", flow.metadata["sequence"], flow.response.status_code])
    flow.response.headers["x-sequence"] = str(flow.metadata["sequence"])
''', H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        try:
            for number in (1, 2):
                request = h1_message(
                    f'GET /{number} HTTP/1.1\r\nHost: example.test\r\n\r\n'.encode())
                result, failures = await driver.rewrite(
                    'one', 'L', request, None, None)
                self.assertEqual(failures, ())
                self.assertEqual(result, request.commit())

                interim = h1_message(b'HTTP/1.1 103 Early Hints\r\n\r\n')
                result, failures = await driver.rewrite(
                    'one', 'R', interim, None, None)
                self.assertEqual(failures, ())
                self.assertEqual(result, interim.commit())

                response = h1_message(b'HTTP/1.1 204 No Content\r\n\r\n')
                result, failures = await driver.rewrite(
                    'one', 'R', response, None, None)
                self.assertEqual(failures, ())
                self.assertIn(f'x-sequence: {number}\r\n'.encode(), result)

            self.assertEqual(addon.addon.module.events, [
                ['request', 1, '/1'], ['response', 1, 204],
                ['request', 2, '/2'], ['response', 2, 204],
            ])
            self.assertEqual(addon.active_flows, 0)
        finally:
            driver.release_connection('one')
            await addon.close()

    async def test_h1_driver_rejects_untyped_pipelined_suffix_before_hooks(self):
        addon = AddonGeneration('''calls = 0
def request(flow):
    global calls
    calls += 1
''', H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        wire = (b'GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n'
                b'GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n')
        try:
            with self.assertRaisesRegex(AddonMessageError, 'Mixed typed and opaque'):
                await driver.rewrite('one', 'L', h1_message(wire), None, None)
            self.assertEqual(addon.addon.module.calls, 0)
            self.assertEqual(addon.state, 'failed')
        finally:
            driver.release_connection('one')
            await addon.close()

    async def test_h1_driver_dispatches_annotated_pipelines_in_fifo_order(self):
        addon = AddonGeneration('''events = []
def request(flow):
    events.append(["request", flow.request.path])
    flow.request.headers["x-path"] = flow.request.path
def response(flow):
    events.append(["response", flow.request.path, flow.response.status_code])
    flow.response.headers["x-path"] = flow.request.path
''', H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        request_one = b'GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n'
        request_two = b'GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n'
        response_one = b'HTTP/1.1 204 No Content\r\n\r\n'
        response_two = b'HTTP/1.1 304 Not Modified\r\n\r\n'
        interim = b'HTTP/1.1 103 Early Hints\r\n\r\n'
        try:
            request_result, failures = await driver.rewrite(
                'one', 'L', h1_messages(request_one, request_two), None, None)
            self.assertEqual(failures, ())
            self.assertIn(b'x-path: /one\r\n', request_result)
            self.assertIn(b'x-path: /two\r\n', request_result)
            self.assertEqual(addon.active_flows, 2)

            response_result, failures = await driver.rewrite(
                'one', 'R', h1_messages(interim, response_one, response_two), None, None)
            self.assertEqual(failures, ())
            self.assertTrue(response_result.startswith(interim))
            self.assertIn(b'x-path: /one\r\n', response_result)
            self.assertIn(b'x-path: /two\r\n', response_result)
            self.assertEqual(addon.addon.module.events, [
                ['request', '/one'], ['request', '/two'],
                ['response', '/one', 204], ['response', '/two', 304],
            ])
            self.assertEqual(addon.active_flows, 0)
        finally:
            driver.release_connection('one')
            await addon.close()

    async def test_h1_pipeline_publishes_complete_prefix_and_retains_final_body(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    events.append(["headers", flow.request.path])
def request(flow):
    events.append(["request", flow.request.path, flow.request.raw_content])
''', H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        first = b'GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n'
        second_head = (b'POST /two HTTP/1.1\r\nHost: example.test\r\n'
                       b'Content-Length: 6\r\n\r\n')
        try:
            message = h1_messages(first, second_head + b'abc')
            held, failures = await driver.rewrite(
                'one', 'L', message, None, None)
            self.assertEqual(failures, ())
            self.assertIsInstance(held, HeldCommit)
            self.assertEqual(held.prefix, first)
            self.assertEqual(addon.addon.module.events, [
                ['headers', '/one'], ['request', '/one', b''],
                ['headers', '/two'],
            ])

            resumed = Message(b'def', 3)
            resume_message(resumed, held.checkpoint, {}, ())
            result, failures = await driver.rewrite(
                'one', 'L', resumed, None, None)
            self.assertEqual(failures, ())
            self.assertTrue(result.endswith(b'abcdef'))
            self.assertEqual(addon.addon.module.events[-1],
                             ['request', '/two', b'abcdef'])
            self.assertEqual(addon.active_flows, 2)
        finally:
            driver.release_connection('one')
            await addon.close()

    async def test_h1_response_pipeline_publishes_prefix_and_retains_final_body(self):
        addon = AddonGeneration('''events = []
def request(flow):
    events.append(["request", flow.request.path])
def responseheaders(flow):
    events.append(["headers", flow.request.path])
def response(flow):
    events.append(["response", flow.request.path, flow.response.raw_content])
''', H1AddonEvents.HOOKS)
        await addon.start()
        driver = H1AddonEvents(addon)
        first_request = b'GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n'
        second_request = b'GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n'
        first_response = b'HTTP/1.1 204 No Content\r\n\r\n'
        second_head = (b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n')
        try:
            _, failures = await driver.rewrite(
                'one', 'L', h1_messages(first_request, second_request), None, None)
            self.assertEqual(failures, ())

            message = h1_messages(first_response, second_head + b'abc')
            held, failures = await driver.rewrite(
                'one', 'R', message, None, None)
            self.assertEqual(failures, ())
            self.assertIsInstance(held, HeldCommit)
            self.assertEqual(held.prefix, first_response)
            self.assertEqual(addon.addon.module.events, [
                ['request', '/one'], ['request', '/two'],
                ['headers', '/one'], ['response', '/one', b''],
                ['headers', '/two'],
            ])
            self.assertEqual(addon.active_flows, 1)

            resumed = Message(b'def', 3)
            resume_message(resumed, held.checkpoint, {}, ())
            result, failures = await driver.rewrite(
                'one', 'R', resumed, None, None)
            self.assertEqual(failures, ())
            self.assertTrue(result.endswith(b'abcdef'))
            self.assertEqual(addon.addon.module.events[-1],
                             ['response', '/two', b'abcdef'])
            self.assertEqual(addon.active_flows, 0)
        finally:
            driver.release_connection('one')
            await addon.close()

    async def test_rerouting_request_retires_generation_without_publication(self):
        addon = AddonGeneration('''calls = 0
def request(flow):
    global calls
    calls += 1
    flow.request.host = "other.example"
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()
        wire = encoded(REQUEST, end=True)
        message = connection.message('L', wire)
        header = message.parts[0]
        original = tuple(header.headers.entries)
        try:
            with self.assertRaisesRegex(AddonMessageError, 'destination'):
                await driver.translate('one', 'L', message, H2,
                                       ApiConnection(message), None, None)
            self.assertEqual(tuple(header.headers.entries), original)
            self.assertIsNone(message._translation.result)
            self.assertEqual(addon.state, 'failed')
            with self.assertRaisesRegex(AddonMessageError, 'generation failed'):
                await driver.translate('one', 'L', message, H2,
                                       ApiConnection(message), None, None)
            self.assertEqual(addon.addon.module.calls, 1)
        finally:
            driver.release_connection('one')
            await addon.close()

    async def test_invalid_informational_response_fails_before_hooks_or_publication(self):
        cases = ((b'101', False, 'status 101'),
                 (b'100', True, 'END_STREAM'),
                 (b'103', True, 'END_STREAM'))
        for status, end, reason in cases:
            with self.subTest(status=status, end=end):
                addon = AddonGeneration('''events = []
def responseheaders(flow):
    events.append(flow.response.status_code)
''', H2AddonEvents.HOOKS)
                await addon.start()
                self.addAsyncCleanup(addon.close)
                driver = H2AddonEvents(addon)
                connection = Connection()
                request = connection.message('L', encoded(REQUEST, end=True))
                failures, keys = await driver.prepare('one', 'L', request, H2,
                                                      ApiConnection(request), None, None)
                self.assertEqual(failures, ())
                connection.publish('L', request)
                driver.published(keys)

                response = connection.message('R', encoded([(b':status', status)], end=end))
                original = response.commit()
                with self.assertRaisesRegex(AddonMessageError, reason):
                    await driver.translate('one', 'R', response, H2,
                                           ApiConnection(response), None, None)
                self.assertEqual(addon.addon.module.events, [])
                self.assertEqual(response.commit(), original)
                with self.assertRaisesRegex(AddonMessageError, 'redeploy'):
                    await driver.prepare('one', 'R', response, H2,
                                         ApiConnection(response), None, None)

    async def test_informational_headers_do_not_become_final_response_trailers(self):
        await self._check_informational_responses(fragmented=False)

    async def test_push_promise_is_not_exposed_as_an_addon_http_flow(self):
        """Keep unsupported server push outside the HTTP addon lifecycle.

        mitmproxy 12 does not advertise HTTP/2 server-push support.  Spider's
        native translator may still observe a PUSH_PROMISE on an existing
        connection, but the compatibility adapter must not invent a request
        callback or a second HTTPFlow for it.
        """
        addon = AddonGeneration('''events = []
def request(flow):
    events.append(["request", flow.request.path])
def response(flow):
    events.append(["response", flow.response.status_code])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()

        async def feed(side, wire):
            message = connection.message(side, wire)
            failures, keys = await driver.prepare(
                "push", side, message, H2, ApiConnection(message), None, None
            )
            self.assertEqual(failures, ())
            result = connection.publish(side, message)
            driver.published(keys)
            return result

        try:
            await feed("L", encoded(REQUEST, end=True))
            self.assertEqual(addon.addon.module.events,
                             [["request", "/first"]])
            self.assertEqual(addon.active_flows, 1)

            encoder = hpack.Encoder()
            promised_request = encoder.encode([
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.org"),
                (b":path", b"/pushed"),
            ])
            push = frame(
                (2).to_bytes(4, "big") + promised_request,
                5,
                4,
                1,
            )
            self.assertEqual(await feed("R", push), push)
            self.assertEqual(addon.addon.module.events,
                             [["request", "/first"]])
            self.assertEqual(addon.active_flows, 1)

            await feed("R", encoded([(b":status", b"204")], end=True,
                                      encoder=encoder))
            self.assertEqual(addon.addon.module.events, [
                ["request", "/first"],
                ["response", 204],
            ])
            self.assertEqual(addon.active_flows, 0)
        finally:
            driver.release_connection("push")
            await addon.close()

    async def test_fragmented_informational_response_body_reservation(self):
        # Every split must preserve interim publication while reserving only
        # the final response body, without rerunning addon hooks.
        await self._check_informational_responses(fragmented=True)

    async def _check_informational_responses(self, *, fragmented):
        source = '''events = []
def responseheaders(flow):
    events.append(["headers", flow.response.status_code])
def response(flow):
    events.append(["response", flow.response.status_code, flow.response.content])
    flow.response.content = b"changed"
'''
        encoder = hpack.Encoder()
        wire = (encoded([(b":status", b"103")], encoder=encoder) +
                encoded([(b":status", b"100")], encoder=encoder) +
                encoded([(b":status", b"200")], encoder=encoder) + frame(b"original"))
        cuts = range(1, len(wire)) if fragmented else (0, len(wire))
        for cut in cuts:
            with self.subTest(cut=cut):
                addon = AddonGeneration(source, H2AddonEvents.HOOKS)
                await addon.start()
                driver = H2AddonEvents(addon)
                connection = Connection()

                async def feed(side, data):
                    message = connection.message(side, data)
                    failures, keys = await driver.prepare("one", side, message, H2,
                                                          ApiConnection(message), None, None)
                    self.assertEqual(failures, ())
                    result = connection.publish(side, message)
                    driver.published(keys)
                    return result

                await feed("L", encoded(REQUEST, end=True))
                output = await feed("R", wire[:cut]) if cut else b""
                if cut < len(wire):
                    output += await feed("R", wire[cut:])
                self.assertEqual(addon.addon.module.events,
                                 [["headers", 200], ["response", 200, b"original"]])
                decoded = unpack(output)
                decoder = hpack.Decoder()
                statuses = []
                for kind, flags, stream, payload in decoded:
                    if kind == 1:
                        headers = dict(decoder.decode(payload, raw=True))
                        statuses.append(headers[b":status"])
                self.assertEqual(statuses, [b"200"])
                body = b"".join(payload for kind, flags, stream, payload in decoded if kind == 0)
                self.assertEqual(body, b"changed")
                self.assertEqual(addon.active_flows, 0)
                await addon.close()

    async def test_expect_continue_matrix_matches_reference_policy(self):
        cases = (
            ('baseline', [(b'expect', b'100-continue')], b'test', True),
            ('mixed-case', [(b'Expect', b'100-Continue')], b'test', True),
            ('duplicate', [
                (b'expect', b'100-continue'),
                (b'expect', b'100-continue'),
            ], b'test', False),
            ('invalid', [(b'expect', b'something-else')], b'test', False),
            ('absent', [], b'test', False),
            ('bodyless', [(b'expect', b'100-continue')], None, True),
        )

        for name, expect_fields, body, should_continue in cases:
            with self.subTest(case=name):
                addon = AddonGeneration('''events = []
def requestheaders(flow):
    events.append(["requestheaders", flow.request.headers.get_all("expect")])
def request(flow):
    events.append(["request", flow.request.headers.get_all("expect"), flow.request.content])
''', H2AddonEvents.HOOKS)
                await addon.start()
                driver = H2AddonEvents(addon)
                connection = Connection()
                encoder = hpack.Encoder()

                async def feed(wire):
                    message = connection.message('L', wire)
                    result, failures = await driver.translate(
                        name, 'L', message, H2,
                        ApiConnection(message), None, None,
                    )
                    self.assertEqual(failures, ())
                    forward = connection.bridge.accept('L', message, result)
                    return forward, message._translation.reverse_output

                try:
                    request_fields = REQUEST + expect_fields
                    request = encoded(
                        request_fields,
                        end=body is None,
                        encoder=encoder,
                    )
                    forward, reverse = await feed(request)
                    published = forward
                    reverse_wire = reverse
                    if body is not None:
                        self.assertEqual(forward, b'')
                        body_forward, body_reverse = await feed(
                            frame(body, 0, 1, 1)
                        )
                        published += body_forward
                        reverse_wire += body_reverse

                    reverse_statuses = []
                    reverse_decoder = hpack.Decoder()
                    for kind, _, _, payload in unpack(reverse_wire):
                        if kind == 1:
                            fields = dict(reverse_decoder.decode(payload, raw=True))
                            reverse_statuses.append(fields[b':status'])
                    self.assertEqual(
                        reverse_statuses,
                        [b'100'] if should_continue else [],
                    )

                    request_decoder = hpack.Decoder()
                    upstream_fields = []
                    upstream_body = b''
                    for kind, _, _, payload in unpack(published):
                        if kind == 1:
                            upstream_fields.extend(
                                request_decoder.decode(payload, raw=True)
                            )
                        elif kind == 0:
                            upstream_body += payload
                    forwarded_expect = [
                        value for field, value in upstream_fields
                        if field.lower() == b'expect'
                    ]
                    self.assertEqual(
                        forwarded_expect,
                        [] if should_continue else [
                            value for _, value in expect_fields
                        ],
                    )
                    self.assertEqual(upstream_body, body or b'')

                    original_values = [
                        value.decode('ascii') for _, value in expect_fields
                    ]
                    completed_values = [] if should_continue else original_values
                    self.assertEqual(addon.addon.module.events, [
                        ['requestheaders', original_values],
                        ['request', completed_values, body or b''],
                    ])
                finally:
                    driver.release_connection(name)
                    await addon.close()

    async def test_expect_continue_handles_every_request_byte_boundary(self):
        source = '''events = []
def requestheaders(flow):
    events.append(["headers", flow.request.headers.get_all("expect")])
def request(flow):
    events.append(["request", flow.request.headers.get_all("expect"), flow.request.content])
'''
        body = b'test'
        wire = encoded(REQUEST + [
            (b'expect', b'100-continue'),
            (b'content-length', str(len(body)).encode('ascii')),
        ]) + frame(body, 0, 1, 1)

        for cut in range(1, len(wire)):
            with self.subTest(cut=cut):
                addon = AddonGeneration(source, H2AddonEvents.HOOKS)
                await addon.start()
                driver = H2AddonEvents(addon)
                connection = Connection()
                published = bytearray()
                reverse = bytearray()
                try:
                    for fragment in (wire[:cut], wire[cut:]):
                        message = connection.message('L', fragment)
                        result, failures = await driver.translate(
                            'expect-split', 'L', message, H2,
                            ApiConnection(message), None, None,
                        )
                        self.assertEqual(failures, ())
                        published.extend(
                            connection.bridge.accept('L', message, result)
                        )
                        reverse.extend(message._translation.reverse_output)

                    reverse_decoder = hpack.Decoder()
                    reverse_statuses = [
                        dict(reverse_decoder.decode(payload, raw=True))[b':status']
                        for kind, _, _, payload in unpack(bytes(reverse))
                        if kind == 1
                    ]
                    self.assertEqual(reverse_statuses, [b'100'])

                    request_decoder = hpack.Decoder()
                    upstream_headers = []
                    upstream_body = bytearray()
                    for kind, _, _, payload in unpack(bytes(published)):
                        if kind == 1:
                            upstream_headers.extend(
                                request_decoder.decode(payload, raw=True)
                            )
                        elif kind == 0:
                            upstream_body.extend(payload)
                    self.assertFalse(any(
                        name.lower() == b'expect'
                        for name, _ in upstream_headers
                    ))
                    self.assertEqual(bytes(upstream_body), body)
                    self.assertEqual(addon.addon.module.events, [
                        ['headers', ['100-continue']],
                        ['request', [], body],
                    ])
                finally:
                    driver.release_connection('expect-split')
                    await addon.close()

    async def test_expect_continue_does_not_precede_a_local_final_response(self):
        addon = AddonGeneration('''from mitmproxy import http
def requestheaders(flow):
    flow.response = http.Response.make(204, b"")
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()
        message = connection.message('L', encoded(
            REQUEST + [(b'expect', b'100-continue')],
            end=True,
        ))
        try:
            result, failures = await driver.translate(
                'local-final', 'L', message, H2,
                ApiConnection(message), None, None,
            )
            self.assertEqual(failures, ())
            forward = connection.bridge.accept('L', message, result)
            self.assertEqual(forward, b'')

            decoder = hpack.Decoder()
            statuses = [
                dict(decoder.decode(payload, raw=True))[b':status']
                for kind, _, _, payload in unpack(message._translation.reverse_output)
                if kind == 1
            ]
            self.assertEqual(statuses, [b'204'])
            self.assertEqual(addon.active_flows, 0)
        finally:
            driver.release_connection('local-final')
            await addon.close()

    async def test_native_adapter_setup_content_stop_share_one_generation(self):
        addon = AddonGeneration('''import asyncio
events = []
calls = 0
def requestheaders(flow):
    assert flow.request.raw_content is None
    events.append("headers")
async def request(flow):
    global calls
    await asyncio.sleep(0)
    calls += 1
    flow.request.content = str(calls).encode()
    events.append("request")
def error(flow):
    assert flow.error is not None
    events.append("error")
def done():
    events.append("done")
''', H2AddonEvents.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon)
        for identity in ('first', 'second'):
            setup = SimpleNamespace(phase='setup', session_id=identity,
                                    instance=SimpleNamespace(mode='flow'),
                                    connection=ApiConnection(phase='setup', instance_mode='flow'))
            adapter.setup(setup, SimpleNamespace(), SimpleNamespace())
            self.assertTrue(setup.connection._rewrite_requested)
            transport = Connection()
            output = bytearray()
            for wire in (encoded(REQUEST), frame(b'payload')):
                message = transport.message('L', wire)
                api = SimpleNamespace(phase='content', session_id=identity, side='L',
                                      message=message, http2=H2, print=self.fail,
                                      connection=ApiConnection(message, instance_mode='flow'))
                result = await adapter.content(api)
                output.extend(transport.bridge.accept('L', message, result))
            expected = b'1' if identity == 'first' else b'2'
            self.assertEqual(b''.join(payload for kind, flags, stream, payload in unpack(bytes(output))
                                     if kind == 0), expected)
        self.assertEqual(adapter.active_connections, 2)
        self.assertEqual(addon.active_flows, 2)
        self.assertEqual(await adapter.stop('first'), ())
        self.assertEqual(await adapter.stop('first'), ())
        self.assertEqual(adapter.active_connections, 1)
        self.assertEqual(addon.active_flows, 1)
        self.assertEqual(await adapter.close(), ())
        self.assertEqual(addon.addon.module.events,
                         ['headers', 'request', 'headers', 'request', 'error', 'error', 'done'])
        self.assertEqual(addon.state, 'closed')
        self.assertEqual(addon.active_flows, 0)
        self.assertEqual(adapter.active_connections, 0)

    async def test_native_adapter_shares_client_lifecycle_across_http_flows(self):
        reference = json.loads(
            (ROOT / 'tests/corpus/addon_connection_lifecycle_v12.json').read_text()
        )
        self.assertEqual(
            [event['hook'] for event in reference['events']],
            [
                'client_connected',
                'server_connect',
                'server_connected',
                'server_disconnected',
                'client_disconnected',
            ],
        )

        addon = AddonGeneration('''events = []
clients = []
servers = []
def client_connected(client):
    clients.append(client)
    events.append(("client_connected", client.connected,
                   client.timestamp_end is None))
def request(flow):
    clients.append(flow.client_conn)
    servers.append(flow.server_conn)
    events.append(("request", flow.request.path))
def client_disconnected(client):
    clients.append(client)
    events.append(("client_disconnected", client.connected,
                   client.timestamp_end is not None))
''', NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon)
        setup = SimpleNamespace(
            phase='setup', session_id='lifecycle', info={},
            instance=SimpleNamespace(mode='flow'),
            connection=ApiConnection(phase='setup', instance_mode='flow'),
        )
        client = AddonClient(
            peername=None,
            sockname=None,
            timestamp_start=None,
        )
        server = AddonServer(address=None)
        setup_result = adapter.setup(setup, client, server)
        self.assertIsNotNone(setup_result)
        self.assertEqual(await setup_result, ())

        transport = Connection()
        encoder = hpack.Encoder()
        wire = (
            encoded(REQUEST, stream=1, end=True, encoder=encoder) +
            encoded(
                [(name, b'/second' if name == b':path' else value)
                 for name, value in REQUEST],
                stream=3,
                end=True,
                encoder=encoder,
            )
        )
        message = transport.message('L', wire)
        api = SimpleNamespace(
            phase='content', session_id='lifecycle', side='L', info={},
            message=message, http2=H2, print=self.fail,
            connection=ApiConnection(message, instance_mode='flow'),
        )
        result = await adapter.content(api)
        transport.bridge.accept('L', message, result)
        self.assertEqual(await adapter.stop('lifecycle'), ())
        self.assertEqual(await adapter.stop('lifecycle'), ())

        module = addon.addon.module
        self.assertEqual(module.events, [
            ('client_connected', True, True),
            ('request', '/first'),
            ('request', '/second'),
            ('client_disconnected', False, True),
        ])
        self.assertEqual(len(module.clients), 4)
        self.assertTrue(all(client is module.clients[0]
                            for client in module.clients))
        self.assertEqual(len(module.servers), 2)
        self.assertIs(module.servers[0], module.servers[1])
        self.assertEqual(module.clients[0].state.value, 0)
        self.assertIsNotNone(module.clients[0].timestamp_start)
        self.assertIsNotNone(module.clients[0].timestamp_end)
        await adapter.close()

    async def test_fatal_client_connected_retires_the_native_registration(self):
        addon = AddonGeneration('''def client_connected(client):
    raise SystemExit("fatal connect")
''', NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon)
        setup = SimpleNamespace(
            phase='setup', session_id='fatal-connect', info={},
            instance=SimpleNamespace(mode='flow'),
            connection=ApiConnection(phase='setup', instance_mode='flow'),
        )
        with self.assertRaisesRegex(SystemExit, 'fatal connect'):
            await adapter.setup(setup, None, None)
        self.assertEqual(addon.state, 'failed')
        self.assertEqual(adapter.active_connections, 0)
        self.assertEqual(addon.active_flows, 0)
        await adapter.close()

    async def test_ordinary_client_lifecycle_failures_remain_reportable(self):
        addon = AddonGeneration('''events = []
def client_connected(client):
    events.append("connected")
    raise ValueError("connect failed")
def client_disconnected(client):
    events.append("disconnected")
    raise RuntimeError("disconnect failed")
''', NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon)
        setup = SimpleNamespace(
            phase='setup', session_id='ordinary-failures', info={},
            instance=SimpleNamespace(mode='flow'),
            connection=ApiConnection(phase='setup', instance_mode='flow'),
        )

        started = await adapter.setup(setup, None, None)
        self.assertEqual(len(started), 1)
        self.assertIsInstance(started[0].exception, ValueError)
        self.assertEqual(addon.state, 'running')
        self.assertEqual(adapter.active_connections, 1)

        stopped = await adapter.stop('ordinary-failures')
        self.assertEqual(len(stopped), 1)
        self.assertIsInstance(stopped[0].exception, RuntimeError)
        self.assertEqual(addon.addon.module.events,
                         ['connected', 'disconnected'])
        self.assertEqual(addon.state, 'running')
        self.assertEqual(adapter.active_connections, 0)
        await adapter.close()

    async def test_native_adapter_dispatches_h1_and_reports_hook_failure(self):
        addon = AddonGeneration('''def request(flow):
    flow.request.headers["x-adapter"] = "yes"
    raise ValueError("visible hook failure")
''', H1AddonEvents.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon)
        setup = SimpleNamespace(
            phase="setup",
            session_id="h1-adapter",
            instance=SimpleNamespace(mode="flow"),
            connection=ApiConnection(phase="setup", instance_mode="flow"),
        )
        adapter.setup(setup, None, None)

        message = h1_message(
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
        )
        printed = []
        api = SimpleNamespace(
            phase="content",
            session_id="h1-adapter",
            side="L",
            message=message,
            http2=H2,
            print=printed.append,
            connection=ApiConnection(message, instance_mode="flow"),
        )
        try:
            result = await adapter.content(api)
            self.assertIn(b"x-adapter: yes\r\n", result)
            self.assertEqual(printed, [
                "Addon module request: ValueError: visible hook failure"
            ])
            self.assertEqual(addon.state, "running")
        finally:
            await adapter.close()

    async def test_native_adapter_invalidates_generation_on_protocol_failure(self):
        addon = AddonGeneration("", H1AddonEvents.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon)
        setup = SimpleNamespace(
            phase="setup",
            session_id="invalid-h1",
            instance=SimpleNamespace(mode="flow"),
            connection=ApiConnection(phase="setup", instance_mode="flow"),
        )
        adapter.setup(setup, None, None)

        message = h1_message(
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
        )
        api = SimpleNamespace(
            phase="content",
            session_id="invalid-h1",
            side="R",
            message=message,
            http2=H2,
            print=self.fail,
            connection=ApiConnection(message, instance_mode="flow"),
        )
        try:
            with self.assertRaisesRegex(AddonMessageError, "direction"):
                await adapter.content(api)
            self.assertEqual(addon.state, "failed")
        finally:
            await adapter.close()

    async def test_native_adapter_requires_setup_and_bounded_connection_ownership(self):
        addon = AddonGeneration('pass', H2AddonEvents.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon, max_connections=1)
        transport = Connection()
        message = transport.message('L', encoded(REQUEST, end=True))
        api = SimpleNamespace(phase='content', session_id='first', side='L', message=message,
                              http2=H2, print=self.fail,
                              connection=ApiConnection(message, instance_mode='flow'))
        with self.assertRaisesRegex(AddonRuntimeError, 'without addon connection setup'):
            await adapter.content(api)
        setup = SimpleNamespace(phase='setup', session_id='first',
                                instance=SimpleNamespace(mode='message'),
                                connection=ApiConnection(phase='setup', instance_mode='flow'))
        with self.assertRaisesRegex(AddonRuntimeError, 'flow instantiation'):
            adapter.setup(setup, None, None)
        self.assertFalse(setup.connection._rewrite_requested)
        setup.instance.mode = 'flow'
        adapter.setup(setup, None, None)
        with self.assertRaisesRegex(AddonRuntimeError, 'already registered'):
            adapter.setup(setup, None, None)
        setup.session_id = 'second'
        with self.assertRaisesRegex(AddonRuntimeError, 'connection limit'):
            adapter.setup(setup, None, None)
        await adapter.stop('first')
        adapter.setup(setup, None, None)
        self.assertEqual(adapter.active_connections, 1)
        await adapter.close()

    async def test_native_adapter_rejects_invalid_lifecycle_boundaries(self):
        for limit in (True, 0, 1025):
            with self.subTest(limit=limit), self.assertRaisesRegex(
                    ValueError, 'Connection limit'):
                NativeAddonAdapter(SimpleNamespace(), max_connections=limit)

        addon = AddonGeneration('pass', H2AddonEvents.HOOKS)
        adapter = NativeAddonAdapter(addon)
        setup = SimpleNamespace(
            phase='setup', session_id='valid',
            instance=SimpleNamespace(mode='flow'),
            connection=ApiConnection(phase='setup', instance_mode='flow'))
        with self.assertRaisesRegex(AddonRuntimeError, 'not running'):
            adapter.setup(setup, None, None)

        await addon.start()
        setup.phase = 'content'
        with self.assertRaisesRegex(AddonRuntimeError, 'during native setup'):
            adapter.setup(setup, None, None)
        setup.phase = 'setup'

        for identity in (None, '', 'x' * 1025):
            with self.subTest(identity=identity):
                setup.session_id = identity
                with self.assertRaisesRegex(AddonRuntimeError, 'bounded connection identity'):
                    adapter.setup(setup, None, None)

        setup.session_id = 'valid'
        adapter.setup(setup, None, None)
        invalid_content = SimpleNamespace(
            phase='setup', session_id='valid', side='L', message=None,
            http2=H2, print=self.fail,
            connection=ApiConnection(phase='content', instance_mode='flow'))
        with self.assertRaisesRegex(AddonRuntimeError, 'native content callback'):
            await adapter.content(invalid_content)
        with self.assertRaisesRegex(AddonRuntimeError, 'bounded connection identity'):
            await adapter.stop('')

        await addon.close()
        valid_message = Connection().message('L', encoded(REQUEST, end=True))
        content = SimpleNamespace(
            phase='content', session_id='valid', side='L', message=valid_message,
            http2=H2, print=self.fail,
            connection=ApiConnection(valid_message, instance_mode='flow'))
        with self.assertRaisesRegex(AddonRuntimeError, 'not running'):
            await adapter.content(content)
        await adapter.close()

    async def test_connection_stop_isolates_multiplexed_errors_and_retained_state(self):
        addon = AddonGeneration('''events = []
def error(flow):
    events.append(flow.request.path)
    if flow.request.path == "/first/1":
        raise ValueError("one failed cleanup callback")
''', H2AddonEvents.HOOKS)
        await addon.start()
        # Two retained bodies share the native 256 KiB reservation budget.
        adapter = NativeAddonAdapter(addon, body_limit=64 * 1024)
        try:
            for identity in ('first', 'second'):
                setup = SimpleNamespace(
                    phase='setup', session_id=identity,
                    instance=SimpleNamespace(mode='flow'),
                    connection=ApiConnection(phase='setup', instance_mode='flow'))
                adapter.setup(setup, None, None)
                transport = Connection()
                encoder = hpack.Encoder()
                wire = b''
                for stream in (1, 3):
                    path = ('/' + identity + '/' + str(stream)).encode()
                    fields = [(name, path if name == b':path' else value)
                              for name, value in REQUEST]
                    wire += encoded(fields, stream=stream, encoder=encoder)
                    wire += frame(b'partial', 0, 0, stream)
                message = transport.message('L', wire)
                api = SimpleNamespace(
                    phase='content', session_id=identity, side='L', message=message,
                    http2=H2, print=self.fail,
                    connection=ApiConnection(message, instance_mode='flow'))
                result = await adapter.content(api)
                self.assertEqual(transport.bridge.accept('L', message, result), b'')

            self.assertEqual(addon.active_flows, 4)
            surviving = addon.connection_flows('second')
            failures = await adapter.stop('first')
            self.assertEqual(len(failures), 1)
            self.assertEqual(str(failures[0].exception), 'one failed cleanup callback')
            self.assertEqual(addon.addon.module.events, ['/first/1', '/first/3'])
            self.assertEqual(addon.state, 'running')
            self.assertEqual(addon.active_flows, 2)
            self.assertEqual(adapter.active_connections, 1)
            self.assertEqual(addon.connection_flows('second'), surviving)
            self.assertTrue(all(flow.live and flow.error is None for flow in surviving))
            self.assertTrue(all(key[0] == 'second' for key in adapter.http2._messages))
            self.assertEqual(await adapter.stop('first'), ())
            self.assertEqual(await adapter.close(), ())
            self.assertEqual(addon.addon.module.events,
                             ['/first/1', '/first/3', '/second/1', '/second/3'])
            self.assertEqual(addon.active_flows, 0)
            self.assertEqual(adapter.active_connections, 0)
            self.assertEqual(adapter.http2._messages, {})
        finally:
            await adapter.close()

    async def test_sized_multiplexed_bodies_share_default_reservation_budget(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    events.append(flow.request.path)
''', H2AddonEvents.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon)
        setup = SimpleNamespace(
            phase='setup', session_id='sized',
            instance=SimpleNamespace(mode='flow'),
            connection=ApiConnection(phase='setup', instance_mode='flow'))
        adapter.setup(setup, None, None)
        transport = Connection()
        encoder = hpack.Encoder()
        wire = b''
        for stream, path in ((1, b'/one'), (3, b'/three')):
            fields = [
                (name, path if name == b':path' else value)
                for name, value in REQUEST
            ]
            fields.append((b'content-length', b'100000'))
            wire += encoded(fields, stream=stream, encoder=encoder)
            wire += frame(b'partial', 0, 0, stream)

        message = transport.message('L', wire)
        api = SimpleNamespace(
            phase='content', session_id='sized', side='L', message=message,
            http2=H2, print=self.fail,
            connection=ApiConnection(message, instance_mode='flow'))
        try:
            result = await adapter.content(api)
            self.assertEqual(transport.bridge.accept('L', message, result), b'')
            reservations = transport.bridge.control['flow']['L']['bodies']
            self.assertEqual(
                {stream: body['limit'] for stream, body in reservations.items()},
                {'1': 100000, '3': 100000})
            self.assertEqual(addon.addon.module.events, ['/one', '/three'])
            self.assertEqual(addon.active_flows, 2)
        finally:
            await adapter.close()

    async def test_adapter_close_finishes_generation_after_fatal_error_hook(self):
        for abort in ('SystemExit', 'asyncio.CancelledError'):
            for fail_done in (False, True):
                with self.subTest(abort=abort, fail_done=fail_done):
                    source = '''import asyncio
events = []
def error(flow):
    events.append("error")
    raise ABORT("stop aborted")
def done():
    events.append("done")
    if FAIL_DONE:
        raise SystemExit("shutdown aborted")
'''.replace('ABORT', abort).replace('FAIL_DONE', repr(fail_done))
                    addon = AddonGeneration(source, H2AddonEvents.HOOKS)
                    await addon.start()
                    adapter = NativeAddonAdapter(addon)
                    flows = []
                    for identity in ('first', 'second'):
                        setup = SimpleNamespace(
                            phase='setup', session_id=identity,
                            instance=SimpleNamespace(mode='flow'),
                            connection=ApiConnection(phase='setup', instance_mode='flow'))
                        adapter.setup(setup, None, None)
                        transport = Connection()
                        message = transport.message('L', encoded(REQUEST, end=True))
                        api = SimpleNamespace(
                            phase='content', session_id=identity, side='L',
                            message=message, http2=H2, print=self.fail,
                            connection=ApiConnection(message, instance_mode='flow'))
                        result = await adapter.content(api)
                        transport.bridge.accept('L', message, result)
                        flows.extend(addon.connection_flows(identity))

                    expected = SystemExit if abort == 'SystemExit' else asyncio.CancelledError
                    with self.assertRaisesRegex(expected, 'stop aborted') as caught:
                        await adapter.close()
                    if fail_done:
                        self.assertIsInstance(caught.exception.__cause__, SystemExit)
                        self.assertEqual(str(caught.exception.__cause__), 'shutdown aborted')
                    self.assertEqual(addon.addon.module.events, ['error', 'done'])
                    self.assertEqual(addon.state, 'closed')
                    self.assertEqual(addon.active_flows, 0)
                    self.assertEqual(adapter.active_connections, 0)
                    self.assertEqual(adapter.http2._messages, {})
                    self.assertTrue(all(not flow.live for flow in flows))
                    self.assertEqual(await adapter.close(), ())
                    self.assertEqual(addon.addon.module.events, ['error', 'done'])

    async def test_multipart_field_edit_reaches_native_h2_output(self):
        addon = AddonGeneration('''def request(flow):
    form = flow.request.multipart_form
    assert list(form.fields) == [(b"upload", b"old")]
    form[b"upload"] = b"replacement payload"
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        body = (b'--sample\r\nContent-Disposition: form-data; '
                b'filename="example.txt"; name="upload"\r\n\r\n'
                b'old\r\n--sample--\r\n')
        headers = list(REQUEST) + [
            (b'content-type', b'multipart/form-data; boundary=sample'),
            (b'content-length', str(len(body)).encode()),
        ]
        message = transport.message('L', encoded(headers) + frame(body))
        try:
            result, failures = await driver.translate(
                'multipart', 'L', message, H2, ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            published = transport.bridge.accept('L', message, result)
            frames = unpack(published)
            output = b''.join(payload for kind, flags, stream, payload in frames if kind == 0)
            expected = (b'--sample\r\nContent-Disposition: form-data; name="upload"\r\n'
                        b'Content-Type: text/plain; charset=utf-8\r\n\r\n'
                        b'replacement payload\r\n\r\n--sample--\r\n')
            self.assertEqual(output, expected)
            fields = hpack.Decoder().decode(frames[0][3], raw=True)
            self.assertIn((b'content-length', str(len(expected)).encode()), fields)
        finally:
            driver.release_connection('multipart')
            await addon.close()

    async def test_transaction_entrypoint_publishes_once(self):
        addon = AddonGeneration('''def request(flow):
    flow.request.path = "/changed"
    flow.request.content = b"body"
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        message = transport.message('L', encoded(REQUEST, end=True))
        result, failures = await driver.translate('one', 'L', message, H2,
                                                  ApiConnection(message), None, None)
        self.assertEqual(failures, ())
        frames = unpack(result)
        self.assertIn((b':path', b'/changed'), hpack.Decoder().decode(frames[0][3], raw=True))
        self.assertEqual(b''.join(payload for kind, flags, stream, payload in frames if kind == 0), b'body')
        self.assertTrue(driver._messages[('one', 'L', 1)].published)
        self.assertEqual(addon.state, 'running')
        await addon.close()

    async def test_one_generation_correlates_equal_stream_ids_on_different_connections(self):
        addon = AddonGeneration('''counter = 0
flows = {}
def request(flow):
    global counter
    counter += 1
    flow.metadata["ordinal"] = counter
    flows[flow.id] = flow
def response(flow):
    assert flows.pop(flow.id) is flow
    flow.response.content = str(flow.metadata["ordinal"]).encode()
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connections = {name: Connection() for name in ('first', 'second')}
        clients = {name: SimpleNamespace(name=name) for name in connections}
        servers = {name: SimpleNamespace(name=name) for name in connections}

        async def feed(name, side, wire):
            transport = connections[name]
            message = transport.message(side, wire)
            failures, keys = await driver.prepare(name, side, message, H2,
                                                  ApiConnection(message), clients[name], servers[name])
            self.assertEqual(failures, ())
            output = transport.publish(side, message)
            driver.published(keys)
            return output

        for name in connections:
            await feed(name, 'L', encoded(REQUEST, end=True))
            flow = addon.get_flow(name, 1)
            self.assertIs(flow.client_conn, clients[name])
            self.assertIs(flow.server_conn, servers[name])
        self.assertEqual(addon.active_flows, 2)
        for name, ordinal in (('second', b'2'), ('first', b'1')):
            frames = unpack(await feed(name, 'R', encoded([(b':status', b'200')], end=True)))
            self.assertEqual(b''.join(payload for kind, flags, stream, payload in frames
                                     if kind == 0), ordinal)
        self.assertEqual(addon.active_flows, 0)
        self.assertEqual(addon.addon.module.counter, 2)
        self.assertEqual(addon.addon.module.flows, {})
        await addon.close()

    async def test_replacement_messages_survive_held_multiplexed_publication(self):
        addon = AddonGeneration('''events = []
def request(flow):
    original = flow.request
    flow.request = original.copy()
    flow.request.path += "/replacement"
    flow.request.content = b"request replacement"
    assert original.path != flow.request.path
    events.append(["request", flow.request.path])
def response(flow):
    flow.response = flow.response.copy()
    flow.response.status_code = 201
    flow.response.content = flow.request.path.encode()
    events.append(["response", flow.request.path])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon, body_limit=64 * 1024)
        transport = Connection()
        encoder = hpack.Encoder()

        async def feed(side, wire):
            message = transport.message(side, wire)
            result, failures = await driver.translate(
                'replace', side, message, H2, ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            return transport.bridge.accept(side, message, result)

        try:
            first = [(name, b'/one' if name == b':path' else value) for name, value in REQUEST]
            second = [(name, b'/two' if name == b':path' else value) for name, value in REQUEST]
            wire = encoded(first, encoder=encoder) + frame(b'pending', flags=0)
            wire += encoded(second, stream=3, encoder=encoder) + frame(b'complete', stream=3)
            self.assertEqual(await feed('L', wire), b'')
            retained = addon.get_flow('replace', 3).request
            self.assertEqual(retained.path, '/two/replacement')
            self.assertIs(driver._messages[('replace', 'L', 3)].message, retained)
            frames = unpack(await feed('L', frame(b'end')))
            decoder = hpack.Decoder()
            heads = {stream: decoder.decode(payload, raw=True)
                     for kind, flags, stream, payload in frames if kind == 1}
            for stream, path in ((1, b'/one/replacement'), (3, b'/two/replacement')):
                self.assertIn((b':path', path), heads[stream])
                body = b''.join(payload for kind, flags, ident, payload in frames
                                if kind == 0 and ident == stream)
                self.assertEqual(body, b'request replacement')
            self.assertIs(addon.get_flow('replace', 3).request, retained)

            response_encoder = hpack.Encoder()
            response_decoder = hpack.Decoder()
            for stream, path in ((3, b'/two/replacement'), (1, b'/one/replacement')):
                frames = unpack(await feed('R', encoded(
                    [(b':status', b'200')], stream=stream,
                    encoder=response_encoder, end=True)))
                self.assertIn((b':status', b'201'),
                              response_decoder.decode(frames[0][3], raw=True))
                self.assertEqual(b''.join(payload for kind, flags, ident, payload in frames
                                         if kind == 0), path)
            self.assertEqual(addon.addon.module.events, [
                ['request', '/two/replacement'], ['request', '/one/replacement'],
                ['response', '/two/replacement'], ['response', '/one/replacement'],
            ])
            self.assertEqual(addon.active_flows, 0)
        finally:
            driver.release_connection('replace')
            await addon.close()

    async def test_header_replacement_retains_identity_across_body_fragments(self):
        source = '''events = []
selected = {}
def replace(flow, kind):
    message = getattr(flow, kind).copy()
    assert message.raw_content is None
    message.headers["x-selected"] = kind
    setattr(flow, kind, message)
    selected[kind] = message
    events.append(kind + "headers")
def requestheaders(flow):
    replace(flow, "request")
def responseheaders(flow):
    replace(flow, "response")
def finish(flow, kind):
    message = getattr(flow, kind)
    assert message is selected[kind]
    assert message.raw_content == b"complete body"
    assert message.headers["x-selected"] == kind
    message.content = b"edited " + kind.encode()
    events.append(kind)
def request(flow):
    finish(flow, "request")
def response(flow):
    finish(flow, "response")
'''
        for fragmented in (False, True):
            with self.subTest(fragmented=fragmented):
                addon = AddonGeneration(source, H2AddonEvents.HOOKS)
                await addon.start()
                driver = H2AddonEvents(addon)
                transport = Connection()
                try:
                    for side, kind, fields in (('L', 'request', REQUEST),
                                               ('R', 'response', [(b':status', b'200')])):
                        wire = encoded(fields) + frame(b'complete body')
                        fragments = [wire[:len(wire) - 4], wire[-4:]] if fragmented else [wire]
                        output = bytearray()
                        for fragment in fragments:
                            message = transport.message(side, fragment)
                            result, failures = await driver.translate(
                                'headers', side, message, H2, ApiConnection(message), None, None)
                            self.assertEqual(failures, ())
                            output.extend(transport.bridge.accept(side, message, result))
                        frames = unpack(bytes(output))
                        headers = hpack.Decoder().decode(frames[0][3], raw=True)
                        self.assertIn((b'x-selected', kind.encode()), headers)
                        self.assertEqual(b''.join(data for typ, flags, stream, data in frames
                                                 if typ == 0), b'edited ' + kind.encode())
                    self.assertEqual(addon.addon.module.events,
                                     ['requestheaders', 'request', 'responseheaders', 'response'])
                    self.assertEqual(addon.active_flows, 0)
                finally:
                    driver.release_connection('headers')
                    await addon.close()

    async def test_header_body_assignment_is_replaced_by_observed_body(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    flow.request = flow.request.copy()
    flow.request.content = b"new request!!!!"
    events.append(["headers", flow.request.raw_content, flow.request.headers["content-length"]])
def request(flow):
    events.append(["request", flow.request.raw_content, flow.request.headers["content-length"]])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        try:
            head = transport.message('L', encoded(REQUEST + [(b'content-length', b'16')]))
            held, failures = await driver.translate(
                'headers', 'L', head, H2, ApiConnection(head), None, None)
            self.assertEqual(failures, ())
            self.assertIsInstance(held, HeldCommit)
            self.assertEqual(transport.bridge.accept('L', head, held), b'')

            body = transport.message('L', frame(b'original request'))
            result, failures = await driver.translate(
                'headers', 'L', body, H2, ApiConnection(body), None, None)
            self.assertEqual(failures, ())
            published = transport.bridge.accept('L', body, result)
            frames = unpack(published)
            headers = hpack.Decoder().decode(frames[0][3], raw=True)
            self.assertIn((b'content-length', b'15'), headers)
            self.assertEqual(b''.join(data for typ, flags, stream, data in frames
                                      if typ == 0), b'original request')
            reference = json.loads(
                (ROOT / 'tests/corpus/addon_early_body_v12.json').read_text())
            observed = reference['events'][:3]
            self.assertEqual(addon.addon.module.events, [
                ['headers', observed[1]['content'].encode('latin-1'),
                 observed[1]['content_length']],
                ['request', observed[2]['content'].encode('latin-1'),
                 observed[2]['content_length']],
            ])
            self.assertEqual(addon.state, 'running')
        finally:
            driver.release_connection('headers')
            await addon.close()

    async def test_complete_header_body_assignment_is_immediately_replaced(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    flow.request.content = b"too early"
    events.append(["headers", flow.request.raw_content, flow.request.headers["content-length"]])
def request(flow):
    events.append(["request", flow.request.raw_content, flow.request.headers["content-length"]])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        message = transport.message(
            'L', encoded(REQUEST + [(b'content-length', b'13')]) + frame(b'observed body'))
        try:
            result, failures = await driver.translate(
                'complete', 'L', message, H2, ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            published = transport.bridge.accept('L', message, result)
            frames = unpack(published)
            headers = hpack.Decoder().decode(frames[0][3], raw=True)
            self.assertIn((b'content-length', b'9'), headers)
            self.assertEqual(b''.join(data for typ, flags, stream, data in frames
                                      if typ == 0), b'observed body')
            self.assertEqual(addon.addon.module.events, [
                ['headers', b'too early', '9'],
                ['request', b'observed body', '9'],
            ])
        finally:
            driver.release_connection('complete')
            await addon.close()

    async def test_response_header_body_assignment_matches_reference_lifecycle(self):
        addon = AddonGeneration('''events = []
def responseheaders(flow):
    flow.response.content = b"new response!!!"
    events.append(["headers", flow.response.raw_content, flow.response.headers["content-length"]])
def response(flow):
    events.append(["response", flow.response.raw_content, flow.response.headers["content-length"]])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        try:
            request = transport.message('L', encoded(REQUEST, end=True))
            result, failures = await driver.translate(
                'response-headers', 'L', request, H2,
                ApiConnection(request), None, None)
            self.assertEqual(failures, ())
            transport.bridge.accept('L', request, result)

            fields = [(b':status', b'200'), (b'content-length', b'15')]
            head = transport.message('R', encoded(fields))
            held, failures = await driver.translate(
                'response-headers', 'R', head, H2,
                ApiConnection(head), None, None)
            self.assertEqual(failures, ())
            self.assertIsInstance(held, HeldCommit)
            self.assertEqual(transport.bridge.accept('R', head, held), b'')

            body = transport.message('R', frame(b'origin response'))
            result, failures = await driver.translate(
                'response-headers', 'R', body, H2,
                ApiConnection(body), None, None)
            self.assertEqual(failures, ())
            published = transport.bridge.accept('R', body, result)
            frames = unpack(published)
            self.assertEqual(b''.join(data for typ, flags, stream, data in frames
                                      if typ == 0), b'origin response')

            reference = json.loads(
                (ROOT / 'tests/corpus/addon_early_body_v12.json').read_text())
            observed = reference['events'][9:12]
            self.assertEqual(addon.addon.module.events, [
                ['headers', observed[1]['content'].encode('latin-1'),
                 observed[1]['content_length']],
                ['response', observed[2]['content'].encode('latin-1'),
                 observed[2]['content_length']],
            ])
            self.assertEqual(addon.active_flows, 0)
        finally:
            driver.release_connection('response-headers')
            await addon.close()

    async def test_replacement_messages_do_not_bypass_transport_guards(self):
        cases = [
            ('flow.request = None', 'retain the HTTP message kind'),
            ('flow.request = http.Response.make(200)', 'retain the HTTP message kind'),
            ('flow.request = flow.request.copy(); flow.request.host = "other.test"',
             'Changing the destination'),
            ('flow.request = flow.request.copy(); flow.request.http_version = "HTTP/1.1"',
             'Changing the transport protocol'),
            ('flow.request = flow.request.copy(); flow.request.raw_content = None',
             'replacement body'),
        ]
        for mutation, reason in cases:
            with self.subTest(mutation=mutation):
                source = 'from mitmproxy import http\ndef request(flow):\n'
                for statement in mutation.split('; '):
                    source += '    ' + statement + '\n'
                addon = AddonGeneration(source, H2AddonEvents.HOOKS)
                await addon.start()
                driver = H2AddonEvents(addon)
                transport = Connection()
                message = transport.message('L', encoded(REQUEST, end=True))
                try:
                    with self.assertRaisesRegex(AddonMessageError, reason):
                        await driver.translate('reject', 'L', message, H2,
                                               ApiConnection(message), None, None)
                    self.assertEqual(addon.state, 'failed')
                    self.assertIsNone(message._translation.result)
                finally:
                    driver.release_connection('reject')
                    await addon.close()

    async def test_h2_late_stream_selection_is_an_observable_noop(self):
        addon = AddonGeneration('''events = []
def request(flow):
    flow.request.stream = lambda chunk: chunk.upper()
    events.append([callable(flow.request.stream), flow.request.raw_content])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        wire = encoded(
            REQUEST + [(b'content-length', b'4')],
        ) + frame(b'body')
        message = transport.message('L', wire)
        try:
            result, failures = await driver.translate(
                'late-stream', 'L', message, H2,
                ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            self.assertEqual(transport.bridge.accept('L', message, result), wire)
            self.assertEqual(addon.addon.module.events, [[True, b'body']])
        finally:
            driver.release_connection('late-stream')
            await addon.close()

    async def test_h2_kill_hooks_publish_one_reset_and_match_reference_lifecycle(self):
        cases = (
            ('requestheaders', 'L', ['requestheaders', 'requestheaders-after-kill', 'error']),
            ('request', 'L', ['requestheaders', 'request', 'request-after-kill', 'error']),
            ('responseheaders', 'R', ['requestheaders', 'request',
                                      'responseheaders', 'responseheaders-after-kill', 'error']),
            ('response', 'R', ['requestheaders', 'request',
                               'responseheaders', 'response', 'response-after-kill']),
        )
        for killed_hook, side, expected in cases:
            with self.subTest(hook=killed_hook):
                addon = AddonGeneration(f'''events = []
def report(name, flow):
    events.append(name)
def requestheaders(flow):
    report("requestheaders", flow)
    if {killed_hook!r} == "requestheaders":
        flow.kill()
        report("requestheaders-after-kill", flow)
def request(flow):
    report("request", flow)
    if {killed_hook!r} == "request":
        flow.kill()
        report("request-after-kill", flow)
def responseheaders(flow):
    report("responseheaders", flow)
    if {killed_hook!r} == "responseheaders":
        flow.kill()
        report("responseheaders-after-kill", flow)
def response(flow):
    report("response", flow)
    if {killed_hook!r} == "response":
        flow.kill()
        report("response-after-kill", flow)
def error(flow):
    assert str(flow.error) == "Connection killed."
    report("error", flow)
''', H2AddonEvents.HOOKS)
                await addon.start()
                driver = H2AddonEvents(addon)
                transport = Connection()
                try:
                    request = transport.message('L', encoded(REQUEST, end=True))
                    request_result, failures = await driver.translate(
                        'kill', 'L', request, H2, ApiConnection(request), None, None)
                    self.assertEqual(failures, ())
                    request_forward = transport.bridge.accept('L', request, request_result)

                    if side == 'L':
                        self.assertEqual(request_forward, b'')
                        reset_wire = request._translation.reverse_output
                    else:
                        response = transport.message(
                            'R', encoded([(b':status', b'200')], end=True))
                        response_result, failures = await driver.translate(
                            'kill', 'R', response, H2, ApiConnection(response), None, None)
                        self.assertEqual(failures, ())
                        reset_wire = transport.bridge.accept('R', response, response_result)

                    resets = [item for item in unpack(reset_wire) if item[0] == 3]
                    self.assertEqual(resets, [(3, 0, 1, b'\x00\x00\x00\x02')])
                    self.assertEqual(addon.addon.module.events, expected)
                    self.assertEqual(addon.active_flows, 0)
                finally:
                    driver.release_connection('kill')
                    await addon.close()

    async def test_h2_requestheaders_kill_discards_late_data_without_replay(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    events.append("requestheaders")
    flow.kill()
    events.append("requestheaders-after-kill")
def request(flow):
    events.append("request")
def error(flow):
    events.append("error")
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        try:
            head = transport.message('L', encoded(REQUEST, end=False))
            result, failures = await driver.translate(
                'late-kill', 'L', head, H2, ApiConnection(head), None, None)
            self.assertEqual(failures, ())
            self.assertEqual(transport.bridge.accept('L', head, result), b'')
            self.assertEqual(
                [item for item in unpack(head._translation.reverse_output) if item[0] == 3],
                [(3, 0, 1, b'\x00\x00\x00\x02')],
            )

            for flags, payload in ((0, b'late'), (1, b'body')):
                message = transport.message('L', frame(payload, 0, flags, 1))
                result, failures = await driver.translate(
                    'late-kill', 'L', message, H2, ApiConnection(message), None, None)
                self.assertEqual(failures, ())
                self.assertEqual(transport.bridge.accept('L', message, result), b'')
                self.assertFalse(any(
                    item[0] == 3 for item in unpack(message._translation.reverse_output)
                ))

            self.assertEqual(addon.addon.module.events, [
                'requestheaders', 'requestheaders-after-kill', 'error',
            ])
            self.assertEqual(addon.active_flows, 0)
        finally:
            driver.release_connection('late-kill')
            await addon.close()

    async def test_h2_kill_error_hook_waits_for_native_publication(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    events.append("requestheaders")
    flow.kill()
    events.append("requestheaders-after-kill")
def error(flow):
    events.append("error")
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        message = transport.message('L', encoded(REQUEST, end=True))

        def fail_publication():
            raise CommitException('injected native publication failure')

        message._translation.translate = fail_publication
        try:
            with self.assertRaisesRegex(CommitException, 'injected native publication failure'):
                await driver.translate(
                    'failed-kill', 'L', message, H2,
                    ApiConnection(message), None, None)
            self.assertEqual(addon.addon.module.events, [
                'requestheaders', 'requestheaders-after-kill',
            ])
            self.assertEqual(addon.state, 'failed')
        finally:
            driver.release_connection('failed-kill')
            await addon.close()

    async def test_local_response_hooks_cannot_bypass_transport_guards(self):
        cases = (
            ('flow.response.stream = True', '', '', 'Streaming callbacks'),
            ('', 'flow.response = None', '', 'retain the local HTTP Response'),
            ('', '', 'flow.response = None', 'retain the local HTTP Response'),
            ('', '', 'flow.response.raw_content = None', 'complete byte body'),
        )
        for request_edit, headers_edit, response_edit, reason in cases:
            with self.subTest(reason=reason, edit=(request_edit, headers_edit, response_edit)):
                source = '''from mitmproxy import http
def request(flow):
    flow.response = http.Response.make(200, b"local")
'''
                if request_edit:
                    source += '    ' + request_edit + '\n'
                source += 'def responseheaders(flow):\n'
                source += '    ' + (headers_edit or 'pass') + '\n'
                source += 'def response(flow):\n'
                source += '    ' + (response_edit or 'pass') + '\n'

                addon = AddonGeneration(source, H2AddonEvents.HOOKS)
                await addon.start()
                driver = H2AddonEvents(addon)
                transport = Connection()
                message = transport.message('L', encoded(REQUEST, end=True))
                try:
                    with self.assertRaisesRegex(AddonMessageError, reason):
                        await driver.translate(
                            'local-guard', 'L', message, H2,
                            ApiConnection(message), None, None)
                    self.assertEqual(addon.state, 'failed')
                    self.assertIsNone(message._translation.result)
                finally:
                    driver.release_connection('local-guard')
                    await addon.close()

    async def test_local_response_late_stream_selection_is_a_noop(self):
        addon = AddonGeneration('''from mitmproxy import http
events = []
def request(flow):
    flow.response = http.Response.make(200, b"local")
def response(flow):
    flow.response.stream = True
    events.append([flow.response.stream, flow.response.raw_content])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        message = transport.message('L', encoded(REQUEST, end=True))
        try:
            result, failures = await driver.translate(
                'local-late-stream', 'L', message, H2,
                ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            self.assertEqual(transport.bridge.accept('L', message, result), b'')
            frames = unpack(bytes(transport.bridge.reverse))
            self.assertEqual(
                b''.join(payload for kind, _flags, _stream, payload in frames
                         if kind == 0),
                b'local',
            )
            self.assertEqual(addon.addon.module.events, [[True, b'local']])
        finally:
            driver.release_connection('local-late-stream')
            await addon.close()

    async def test_native_publication_failure_invalidates_generation_without_replaying_hooks(self):
        addon = AddonGeneration('''calls = 0
def request(flow):
    global calls
    calls += 1
    flow.request.content = b"x" * (512 * 1024)
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        message = transport.message('L', encoded(REQUEST, end=True))
        with self.assertRaisesRegex(CommitException, 'pending output'):
            await driver.translate('one', 'L', message, H2, ApiConnection(message), None, None)
        self.assertEqual(addon.state, 'failed')
        self.assertEqual(addon.addon.module.calls, 1)
        retry = transport.message('L', encoded(REQUEST, end=True))
        with self.assertRaisesRegex(AddonMessageError, 'generation failed'):
            await driver.translate('one', 'L', retry, H2, ApiConnection(retry), None, None)
        self.assertEqual(addon.addon.module.calls, 1)
        await addon.close()

    async def test_local_response_runs_response_hooks_and_uses_native_reverse_output(self):
        addon = AddonGeneration('''from mitmproxy import http
events = []
def requestheaders(flow):
    events.append("requestheaders")
    flow.response = http.Response.make(
        204,
        b"local body",
        [(b"X-Shared", b"compression state")],
    )
def request(flow):
    events.append("request")
def responseheaders(flow):
    events.append("responseheaders")
    flow.response.headers.add("X-Duplicate", "one")
    flow.response.headers.add("X-Duplicate", "two")
def response(flow):
    events.append("response")
    flow.response.trailers = http.Headers([(b"X-Finished", b"yes")])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        message = transport.message('L', encoded(REQUEST, end=True))
        try:
            result, failures = await driver.translate(
                'local', 'L', message, H2, ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            self.assertEqual(result, b'')
            frames = unpack(message._translation.reverse_output)
            decoder = hpack.Decoder()
            header_fields = decoder.decode(frames[0][3], raw=True)
            trailer_fields = decoder.decode(frames[-1][3], raw=True)
            self.assertIn((b':status', b'204'), header_fields)
            self.assertIn((b'content-length', b'10'), header_fields)
            self.assertEqual(
                [value for name, value in header_fields if name == b'x-duplicate'],
                [b'one', b'two'],
            )
            self.assertEqual(
                b''.join(payload for kind, flags, stream, payload in frames if kind == 0),
                b'local body',
            )
            self.assertIn((b'x-finished', b'yes'), trailer_fields)
            self.assertEqual(addon.addon.module.events, [
                'requestheaders', 'request', 'responseheaders', 'response',
            ])
            self.assertEqual(addon.active_flows, 0)
        finally:
            driver.release_connection('local')
            await addon.close()

    async def test_h2_local_responses_match_reference_lifecycle_and_message_semantics(self):
        """Compare multiplexed native output with the checked-in v12 oracle.

        HTTP/2 frame boundaries are deliberately not part of this comparison:
        peers may split a body into any number of DATA frames.  The observable
        message, hook lifecycle, stream termination and ordered fields are.
        """
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_local_response_h2_v12.json').read_text()
        )
        addon = AddonGeneration('''from mitmproxy import http
events = []
def report(name, flow):
    response = flow.response
    event = {
        "hook": name,
        "path": flow.request.path,
        "status": None if response is None else response.status_code,
        "body": None if response is None else response.raw_content.decode("latin-1"),
    }
    if response is not None and response.trailers is not None:
        event["trailers"] = [
            [name.decode("latin-1"), value.decode("latin-1")]
            for name, value in response.trailers.fields
        ]
    events.append(event)
def requestheaders(flow):
    report("requestheaders", flow)
    if flow.request.path == "/headers":
        flow.response = http.Response.make(
            201, b"from requestheaders", {"X-Origin": "requestheaders"})
def request(flow):
    report("request", flow)
    if flow.request.path == "/h2":
        flow.response = http.Response.make(
            203, b"from HTTP/2 request", {"X-Origin": "request"})
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
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        encoder = hpack.Encoder()
        decoder = hpack.Decoder()
        streams = (
            (1, '/headers'),
            (3, '/h2'),
            (5, '/empty'),
            (7, '/trailers'),
        )
        observed = {}
        try:
            for stream_id, path in streams:
                fields = [
                    (b':method', b'POST'),
                    (b':scheme', b'https'),
                    (b':authority', b'example.invalid'),
                    (b':path', path.encode('ascii')),
                    (b'content-length', b'4'),
                ]
                wire = encoded(fields, stream=stream_id, encoder=encoder)
                wire += frame(b'test', 0, 1, stream_id)
                message = transport.message('L', wire)
                result, failures = await driver.translate(
                    'local-corpus', 'L', message, H2,
                    ApiConnection(message), None, None)
                self.assertEqual(failures, ())
                self.assertEqual(result, b'')
                reverse_output = message._translation.reverse_output
                transport.bridge.accept('L', message, result)

                response_headers = None
                response_trailers = None
                body = bytearray()
                ended = False
                for kind, flags, observed_stream, payload in unpack(reverse_output):
                    if kind == 8:
                        # Consuming the request body returns peer flow-control
                        # credit independently of the generated response.
                        continue
                    self.assertEqual(observed_stream, stream_id)
                    if kind == 1:
                        fields = decoder.decode(payload, raw=True)
                        if response_headers is None:
                            response_headers = fields
                        else:
                            self.assertIsNone(response_trailers)
                            response_trailers = fields
                    elif kind == 0:
                        body.extend(payload)
                    else:
                        self.fail('Unexpected local-response frame type: ' + str(kind))
                    ended = ended or bool(flags & 1)

                self.assertTrue(ended)
                self.assertIsNotNone(response_headers)
                observed[path] = {
                    'headers': [[name.decode('latin-1'), value.decode('latin-1')]
                                for name, value in response_headers],
                    'body': bytes(body).decode('latin-1'),
                    'trailers': None if response_trailers is None else [
                        [name.decode('latin-1'), value.decode('latin-1')]
                        for name, value in response_trailers
                    ],
                }

            for path, expected in corpus['responses'].items():
                actual = observed[path]
                self.assertEqual(actual['headers'], expected['headers'])
                self.assertEqual(actual['body'], expected['body'])
                if expected['trailers'] is None:
                    self.assertIsNone(actual['trailers'])
                else:
                    # Native HTTP/2 validation intentionally canonicalizes the
                    # mixed-case field emitted by the reference implementation.
                    canonical = [[name.lower(), value]
                                 for name, value in expected['trailers']]
                    self.assertEqual(actual['trailers'], canonical)

            expected_events = {}
            for event in corpus['hooks']:
                expected_events.setdefault(event['path'], []).append(event)
            actual_events = {}
            for event in addon.addon.module.events:
                actual_events.setdefault(event['path'], []).append(event)
            self.assertEqual(actual_events, expected_events)
            self.assertEqual(addon.active_flows, 0)
        finally:
            driver.release_connection('local-corpus')
            await addon.close()

    async def test_h2_local_responses_resume_through_flow_control_with_a_sibling_stream(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_h2_flow_control_v12.json').read_text()
        )
        large_body = b'L' * (150 * 1024)
        addon = AddonGeneration('''from mitmproxy import http
def request(flow):
    if flow.request.path == "/large":
        flow.response = http.Response.make(
            200, b"L" * (150 * 1024), {"X-Flow-Case": "large"})
    else:
        flow.response = http.Response.make(
            201, b"small sibling", {"X-Flow-Case": "small"})
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        peers = Peers()

        async def pump(side, wire):
            queue = deque([(side, wire, None)])
            iterations = 0
            while queue:
                iterations += 1
                self.assertLess(iterations, 100, 'Flow-control feedback must terminate')
                source, payload, unused = queue.popleft()
                message = peers.bridge.message(source, payload)
                failures, keys = await driver.prepare(
                    'local-flow-control', source, message, H2,
                    ApiConnection(message), None, None)
                self.assertEqual(failures, ())
                forward = peers.bridge.publish(source, message)
                driver.published(keys)
                peers.deliver('R' if source == 'L' else 'L', forward, queue)
                peers.deliver(source, peers.bridge.reverse, queue)

        client = peers.peers['L']
        for stream_id, path in ((1, b'/large'), (3, b'/small')):
            client.send_headers(stream_id, [
                (b':method', b'GET'),
                (b':scheme', b'https'),
                (b':authority', b'example.test'),
                (b':path', path),
            ], end_stream=True)
        try:
            await pump('L', client.data_to_send())

            received = {1: bytearray(), 3: bytearray()}
            statuses = {}
            headers = {}
            for event in peers.events['L']:
                if isinstance(event, h2.events.ResponseReceived):
                    fields = event.headers
                    statuses[event.stream_id] = int(dict(fields)[b':status'])
                    headers[event.stream_id] = [
                        [name.decode('latin-1'), value.decode('latin-1')]
                        for name, value in fields
                        if name in (b'content-length', b'x-flow-case')
                    ]
                elif isinstance(event, h2.events.DataReceived):
                    received[event.stream_id].extend(event.data)

            paths = {1: '/large', 3: '/small'}
            observed = {}
            for stream_id, path in paths.items():
                body = bytes(received[stream_id])
                observed[path] = {
                    'status': statuses[stream_id],
                    'headers': headers[stream_id],
                    'body_length': len(body),
                    'body_sha256': hashlib.sha256(body).hexdigest(),
                    'ended': stream_id in peers.ended['L'],
                }
            self.assertEqual(observed, corpus['responses'])
            self.assertEqual(bytes(received[1]), large_body)
            self.assertEqual(bytes(received[3]), b'small sibling')
            self.assertEqual(set(peers.ended['L']), {1, 3})
            self.assertFalse(any(isinstance(event, h2.events.RequestReceived)
                                 for event in peers.events['R']))
            self.assertFalse(peers.bridge.reserved)
            self.assertEqual(addon.active_flows, 0)
        finally:
            driver.release_connection('local-flow-control')
            await addon.close()

    async def test_event_driver_reserves_body_credit_with_independent_h2_peers(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    events.append("headers")
def request(flow):
    assert flow.request.content == b"x" * (128 * 1024)
    events.append("request")
    flow.request.content = b"y" * (150 * 1024)
def response(flow):
    assert flow.response.status_code == 200
    assert flow.response.content == b"r" * (128 * 1024)
    events.append("response")
    flow.response.content = b"s" * (150 * 1024)
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        peers = Peers()

        async def pump(side, wire):
            queue = deque([(side, wire, None)])
            iterations = 0
            while queue:
                iterations += 1
                self.assertLess(iterations, 100, 'Flow-control feedback must terminate')
                source, payload, unused = queue.popleft()
                message = peers.bridge.message(source, payload)
                failures, keys = await driver.prepare('one', source, message, H2,
                                                      ApiConnection(message), None, None)
                self.assertEqual(failures, ())
                forward = peers.bridge.publish(source, message)
                driver.published(keys)
                peers.deliver('R' if source == 'L' else 'L', forward, queue)
                peers.deliver(source, peers.bridge.reverse, queue)

        client = peers.peers['L']
        client.send_headers(1, REQUEST + [(b'content-length', str(128 * 1024).encode())])
        await pump('L', client.data_to_send())
        remaining = 128 * 1024
        while remaining:
            count = min(16000, remaining, client.local_flow_control_window(1))
            self.assertGreater(count, 0, 'Retaining the body must not deadlock at 65535 bytes')
            remaining -= count
            client.send_data(1, b'x' * count, end_stream=remaining == 0)
            await pump('L', client.data_to_send())
        self.assertEqual(addon.addon.module.events, ['headers', 'request'])
        self.assertEqual(b''.join(peers.received['R']), b'y' * (150 * 1024))
        self.assertEqual(peers.ended['R'], [1])
        self.assertFalse(peers.bridge.reserved)
        self.assertEqual(client.outbound_flow_control_window, 65535)
        server = peers.peers['R']
        for status in (b'103', b'100'):
            server.send_headers(1, [(b':status', status)])
            await pump('R', server.data_to_send())
        server.send_headers(1, [(b':status', b'200'),
                                (b'content-length', str(128 * 1024).encode())])
        await pump('R', server.data_to_send())
        remaining = 128 * 1024
        while remaining:
            count = min(16000, remaining, server.local_flow_control_window(1))
            self.assertGreater(count, 0, 'Informational headers must not prevent body credit')
            remaining -= count
            server.send_data(1, b'r' * count, end_stream=remaining == 0)
            await pump('R', server.data_to_send())
        self.assertEqual(addon.addon.module.events, ['headers', 'request', 'response'])
        self.assertEqual(b''.join(peers.received['L']), b's' * (150 * 1024))
        self.assertEqual(peers.ended['L'], [1])
        self.assertFalse(peers.bridge.reserved)
        self.assertEqual(server.outbound_flow_control_window, 65535)
        driver.release_connection('one')
        await addon.close()

    async def test_event_driver_handles_every_byte_boundary(self):
        source = '''events = []
def requestheaders(flow):
    assert flow.request.content is None
    events.append("headers")
def request(flow):
    events.append("body")
    assert flow.request.content == b"payload"
    flow.request.content = b"replacement"
'''
        wire = encoded(REQUEST) + frame(b'payload')
        for cut in range(1, len(wire)):
            with self.subTest(cut=cut):
                addon = AddonGeneration(source, H2AddonEvents.HOOKS)
                await addon.start()
                driver = H2AddonEvents(addon)
                connection = Connection()
                output = bytearray()
                for fragment in (wire[:cut], wire[cut:]):
                    message = connection.message('L', fragment)
                    failures, keys = await driver.prepare('one', 'L', message, H2,
                                                          ApiConnection(message), None, None)
                    self.assertEqual(failures, ())
                    output.extend(connection.publish('L', message))
                    driver.published(keys)
                self.assertEqual(addon.addon.module.events, ['headers', 'body'])
                self.assertEqual(b''.join(payload for kind, flags, stream, payload in unpack(bytes(output))
                                         if kind == 0), b'replacement')
                driver.release_connection('one')
                await addon.close()

    async def test_local_response_handles_every_request_byte_boundary(self):
        source = '''from mitmproxy import http
events = []
def requestheaders(flow):
    events.append("headers")
def request(flow):
    events.append("request")
    flow.response = http.Response.make(203, b"local")
def responseheaders(flow):
    events.append("responseheaders")
def response(flow):
    events.append("response")
    flow.response.content += b" response"
'''
        body = b'payload'
        wire = encoded(REQUEST + [(b'content-length', str(len(body)).encode())])
        wire += frame(body)
        for cut in range(1, len(wire)):
            with self.subTest(cut=cut):
                addon = AddonGeneration(source, H2AddonEvents.HOOKS)
                await addon.start()
                driver = H2AddonEvents(addon)
                connection = Connection()
                forward = bytearray()
                reverse = bytearray()
                try:
                    for fragment in (wire[:cut], wire[cut:]):
                        message = connection.message('L', fragment)
                        failures, keys = await driver.prepare(
                            'local-fragment', 'L', message, H2,
                            ApiConnection(message), None, None)
                        self.assertEqual(failures, ())
                        forward.extend(connection.publish('L', message))
                        reverse.extend(connection.bridge.reverse)
                        driver.published(keys)

                    self.assertEqual(forward, b'')
                    self.assertEqual(
                        b''.join(payload for kind, flags, stream, payload
                                 in unpack(bytes(reverse)) if kind == 0),
                        b'local response',
                    )
                    self.assertEqual(addon.addon.module.events, [
                        'headers', 'request', 'responseheaders', 'response',
                    ])
                    self.assertEqual(addon.active_flows, 0)
                finally:
                    driver.release_connection('local-fragment')
                    await addon.close()

    async def test_reset_releases_retained_flow_and_delivers_error_once(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    events.append("headers")
def request(flow):
    events.append("must not complete")
def error(flow):
    assert flow.error is not None
    events.append("error")
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()
        for side, wire in [('L', encoded(REQUEST)), ('R', frame(b'\0\0\0\x08', 3, 0, 1))]:
            message = connection.message(side, wire)
            failures, keys = await driver.prepare('one', side, message, H2,
                                                  ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            connection.publish(side, message)
            driver.published(keys)
        self.assertEqual(addon.addon.module.events, ['headers', 'error'])
        self.assertEqual(addon.active_flows, 0)
        self.assertEqual(driver._messages, {})
        await addon.close()

    async def test_malformed_terminal_control_parts_fail_before_publication(self):
        cases = (
            (frame(b'\0\0\0\x08', 3, 0, 0), 'RST_STREAM'),
            (frame(b'\0\0\x08', 3, 0, 1), 'RST_STREAM'),
            (frame(b'\0' * 8, 7, 0, 1), 'GOAWAY'),
            (frame(b'\0' * 7, 7, 0, 0), 'GOAWAY'),
        )
        for wire, reason in cases:
            with self.subTest(reason=reason, wire=wire.hex()):
                addon = AddonGeneration('', H2AddonEvents.HOOKS)
                await addon.start()
                driver = H2AddonEvents(addon)
                message = native_message(wire)
                try:
                    with self.assertRaisesRegex(AddonMessageError, reason):
                        await driver.translate(
                            'malformed-control',
                            'R',
                            message,
                            H2,
                            ApiConnection(message),
                            None,
                            None,
                        )
                    self.assertEqual(addon.state, 'failed')
                    self.assertFalse(hasattr(message, '_translation'))
                finally:
                    driver.release_connection('malformed-control')
                    await addon.close()

    async def test_reset_and_coalesced_response_do_not_revive_the_flow(self):
        addon = AddonGeneration('''events = []
def responseheaders(flow):
    events.append("responseheaders")
def response(flow):
    events.append("response")
def error(flow):
    events.append(["error", str(flow.error)])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        transport = Connection()
        request = transport.message('L', encoded(REQUEST, end=True))
        result, failures = await driver.translate(
            'coalesced-reset', 'L', request, H2,
            ApiConnection(request), None, None)
        self.assertEqual(failures, ())
        transport.bridge.accept('L', request, result)

        reset = frame(b'\0\0\0\x08', 3, 0, 1)
        response = encoded([(b':status', b'200')], stream=1, end=True)
        message = transport.message('R', reset + response)
        try:
            result, failures = await driver.translate(
                'coalesced-reset', 'R', message, H2,
                ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            published = unpack(transport.bridge.accept('R', message, result))
            self.assertEqual(
                [(kind, stream, payload) for kind, flags, stream, payload in published],
                [(3, 1, b'\0\0\0\x08')],
            )
            self.assertEqual(addon.addon.module.events, [
                ['error', 'stream reset by client (CANCEL)'],
            ])
            self.assertEqual(addon.active_flows, 0)
            self.assertEqual(driver._messages, {})
        finally:
            driver.release_connection('coalesced-reset')
            await addon.close()

    async def test_reset_reason_matches_reference_and_waits_for_complete_frame(self):
        cases = (
            (0, 'NO_ERROR'),
            (1, 'PROTOCOL_ERROR'),
            (2, 'INTERNAL_ERROR'),
            (3, 'FLOW_CONTROL_ERROR'),
            (7, 'REFUSED_STREAM'),
            (8, 'CANCEL'),
            (11, 'ENHANCE_YOUR_CALM'),
            (123, '123'),
        )
        for code, label in cases:
            wire = frame(code.to_bytes(4, 'big'), 3, 0, 1)
            for split in range(1, len(wire)):
                with self.subTest(code=code, split=split):
                    addon = AddonGeneration('''errors = []
def error(flow):
    errors.append(str(flow.error))
''', H2AddonEvents.HOOKS)
                    await addon.start()
                    driver = H2AddonEvents(addon)
                    transport = Connection()
                    try:
                        published = b''
                        fragments = (('L', encoded(REQUEST, end=True)),
                                     ('R', wire[:split]), ('R', wire[split:]))
                        for index, (side, fragment) in enumerate(fragments):
                            message = transport.message(side, fragment)
                            result, failures = await driver.translate(
                                'reset', side, message, H2, ApiConnection(message), None, None)
                            self.assertEqual(failures, ())
                            published = transport.bridge.accept(side, message, result)
                            if index < 2:
                                self.assertEqual(addon.addon.module.errors, [])
                        self.assertEqual(addon.addon.module.errors,
                                         [f'stream reset by client ({label})'])
                        frames = unpack(published)
                        if code == 8:
                            self.assertEqual(
                                frames,
                                [(3, 0, 1, code.to_bytes(4, 'big'))],
                            )
                        else:
                            self.assertFalse(any(kind == 3 for kind, _, _, _ in frames))
                            head = next(payload for kind, _, _, payload in frames
                                        if kind == 1)
                            self.assertIn(
                                (b':status', b'502'),
                                hpack.Decoder().decode(head, raw=True),
                            )
                            body = b''.join(payload for kind, _, _, payload in frames
                                            if kind == 0)
                            self.assertIn(
                                f'stream reset by client ({label})'.encode(),
                                body,
                            )
                        self.assertEqual(addon.active_flows, 0)
                    finally:
                        driver.release_connection('reset')
                        await addon.close()

    async def test_coalesced_resets_deliver_errors_in_wire_order(self):
        addon = AddonGeneration('''events = []
def error(flow):
    events.append(flow.request.path)
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()
        encoder = hpack.Encoder()
        requests = b''
        for stream in (1, 3):
            fields = [(name, ('/' + str(stream)).encode() if name == b':path' else value)
                      for name, value in REQUEST]
            requests += encoded(fields, stream=stream, end=True, encoder=encoder)
        resets = b''.join(frame(b'\0\0\0\x08', 3, 0, stream)
                          for stream in (3, 1, 3))
        try:
            for side, wire in (('L', requests), ('R', resets)):
                message = connection.message(side, wire)
                failures, keys = await driver.prepare(
                    'one', side, message, H2, ApiConnection(message), None, None)
                self.assertEqual(failures, ())
                connection.publish(side, message)
                driver.published(keys)
            self.assertEqual(addon.addon.module.events, ['/3', '/1'])
            self.assertEqual(addon.active_flows, 0)
            self.assertEqual(driver._messages, {})
        finally:
            driver.release_connection('one')
            await addon.close()

    async def test_goaway_fails_every_pending_stream_and_suppresses_late_response(self):
        addon = AddonGeneration('''events = []
def error(flow):
    events.append(["error", flow.request.path])
def response(flow):
    events.append(["response", flow.request.path])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()
        encoder = hpack.Encoder()
        requests = b''
        for stream in (1, 3):
            fields = [(name, ('/' + str(stream)).encode() if name == b':path' else value)
                      for name, value in REQUEST]
            requests += encoded(fields, stream=stream, end=True, encoder=encoder)

        async def feed(side, wire):
            message = connection.message(side, wire)
            result, failures = await driver.translate(
                'one', side, message, H2, ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            return connection.bridge.accept(side, message, result)

        try:
            await feed('L', requests)
            goaway = frame((1).to_bytes(4, 'big') + bytes(4), 7, 0, 0)
            failed = unpack(await feed('R', goaway))
            self.assertFalse(any(kind == 7 for kind, _, _, _ in failed))
            decoder = hpack.Decoder()
            statuses = []
            for kind, _, stream, payload in failed:
                if kind == 1:
                    statuses.append((stream, dict(decoder.decode(payload, raw=True))[b':status']))
            self.assertEqual(statuses, [(1, b'502'), (3, b'502')])
            self.assertIsNone(addon.get_flow('one', 1))
            self.assertIsNone(addon.get_flow('one', 3))
            self.assertEqual(await feed('R', goaway), b'')
            self.assertEqual(
                await feed('R', encoded([(b':status', b'200')], end=True)),
                b'',
            )
            self.assertEqual(addon.addon.module.events,
                             [['error', '/1'], ['error', '/3']])
            self.assertEqual(addon.active_flows, 0)
            self.assertEqual(driver._messages, {})
        finally:
            driver.release_connection('one')
            await addon.close()

    async def test_goaway_preserves_prior_response_and_matches_reference_order(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    events.append(["requestheaders", flow.request.path])
def request(flow):
    events.append(["request", flow.request.path])
def responseheaders(flow):
    events.append(["responseheaders", flow.request.path, flow.response.status_code])
def response(flow):
    events.append(["response", flow.request.path, flow.response.status_code])
def error(flow):
    events.append(["error", flow.request.path, str(flow.error)])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()
        request_encoder = hpack.Encoder()
        requests = b''
        for stream in (1, 3):
            fields = [
                (name, b'GET' if name == b':method' else
                 ('/' + str(stream)).encode() if name == b':path' else value)
                for name, value in REQUEST
            ]
            requests += encoded(
                fields,
                stream=stream,
                end=True,
                encoder=request_encoder,
            )

        async def feed(side, wire):
            message = connection.message(side, wire)
            result, failures = await driver.translate(
                'reference-order', side, message, H2,
                ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            return connection.bridge.accept(side, message, result)

        reason = (
            'HTTP/2 connection closed: <ConnectionTerminated '
            'error_code:0, last_stream_id:1, additional_data:None>'
        )
        expected_body = (
            '<html>\n'
            '<head>\n'
            '    <title>502 Bad Gateway</title>\n'
            '</head>\n'
            '<body>\n'
            '    <h1>502 Bad Gateway</h1>\n'
            '    <p>HTTP/2 connection closed: &lt;ConnectionTerminated '
            'error_code:0, last_stream_id:1, additional_data:None&gt;</p>\n'
            '</body>\n'
            '</html>'
        ).encode()
        try:
            await feed('L', requests)
            response_encoder = hpack.Encoder()
            response = encoded(
                [(b':status', b'200')],
                stream=1,
                end=True,
                encoder=response_encoder,
            )
            goaway = frame((1).to_bytes(4, 'big') + bytes(4), 7, 0, 0)
            published = unpack(await feed('R', response + goaway))
            self.assertFalse(any(kind == 7 for kind, _, _, _ in published))

            decoder = hpack.Decoder()
            headers = []
            bodies = []
            for kind, _, stream, payload in published:
                if kind == 1:
                    headers.append((stream, decoder.decode(payload, raw=True)))
                elif kind == 0:
                    bodies.append((stream, payload))
            self.assertEqual(headers, [
                (3, [
                    (b':status', b'502'),
                    (b'server', b'mitmproxy 12.3.1'),
                    (b'content-type', b'text/html'),
                ]),
                (1, [(b':status', b'200')]),
            ])
            self.assertEqual(bodies, [(3, expected_body)])
            self.assertEqual(addon.addon.module.events, [
                ['requestheaders', '/1'],
                ['request', '/1'],
                ['requestheaders', '/3'],
                ['request', '/3'],
                ['error', '/3', reason],
                ['responseheaders', '/1', 200],
                ['response', '/1', 200],
            ])
        finally:
            driver.release_connection('reference-order')
            await addon.close()

    async def test_reset_after_goaway_uses_reference_connection_failure(self):
        addon = AddonGeneration('''events = []
def error(flow):
    events.append([flow.request.path, str(flow.error)])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()
        encoder = hpack.Encoder()
        requests = b''
        for stream in (1, 3):
            fields = [(name, ('/' + str(stream)).encode()
                       if name == b':path' else value)
                      for name, value in REQUEST]
            requests += encoded(fields, stream=stream, end=True, encoder=encoder)

        async def feed(side, wire):
            message = connection.message(side, wire)
            result, failures = await driver.translate(
                'reset-after', side, message, H2,
                ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            return connection.bridge.accept(side, message, result)

        reason = H2AddonEvents.GOAWAY_THEN_RESET_REASON
        try:
            await feed('L', requests)
            goaway = frame((1).to_bytes(4, 'big') + bytes(4), 7, 0, 0)
            reset = frame(bytes(4), 3, 0, 3)
            published = unpack(await feed('R', goaway + reset))
            self.assertFalse(any(kind in (3, 7) for kind, _, _, _ in published))
            decoder = hpack.Decoder()
            headers = []
            bodies = {}
            for kind, _, stream, payload in published:
                if kind == 1:
                    headers.append((stream, decoder.decode(payload, raw=True)))
                elif kind == 0:
                    bodies.setdefault(stream, bytearray()).extend(payload)
            self.assertEqual([stream for stream, _ in headers], [1, 3])
            self.assertTrue(all(dict(fields)[b':status'] == b'502'
                                for _, fields in headers))
            self.assertEqual(
                addon.addon.module.events,
                [['/1', reason], ['/3', reason]],
            )
            self.assertTrue(all(reason.encode() in body
                                for body in bodies.values()))
        finally:
            driver.release_connection('reset-after')
            await addon.close()

    async def test_reset_before_goaway_matches_two_local_failure_responses(self):
        addon = AddonGeneration('''events = []
def error(flow):
    events.append([flow.request.path, str(flow.error)])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()
        encoder = hpack.Encoder()
        requests = b''
        for stream in (1, 3):
            fields = [(name, ('/' + str(stream)).encode()
                       if name == b':path' else value)
                      for name, value in REQUEST]
            requests += encoded(fields, stream=stream, end=True, encoder=encoder)

        async def feed(side, wire):
            message = connection.message(side, wire)
            result, failures = await driver.translate(
                'reset-before', side, message, H2,
                ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            return connection.bridge.accept(side, message, result)

        reset_reason = 'stream reset by client (NO_ERROR)'
        goaway_reason = (
            'HTTP/2 connection closed: <ConnectionTerminated '
            'error_code:0, last_stream_id:1, additional_data:None>'
        )
        try:
            await feed('L', requests)
            reset = frame(bytes(4), 3, 0, 3)
            goaway = frame((1).to_bytes(4, 'big') + bytes(4), 7, 0, 0)
            published = unpack(await feed('R', reset + goaway))
            self.assertFalse(any(kind in (3, 7) for kind, _, _, _ in published))

            decoder = hpack.Decoder()
            headers = []
            bodies = {}
            for kind, _, stream, payload in published:
                if kind == 1:
                    headers.append((stream, decoder.decode(payload, raw=True)))
                elif kind == 0:
                    bodies.setdefault(stream, bytearray()).extend(payload)
            self.assertEqual([stream for stream, _ in headers], [3, 1])
            self.assertTrue(all(dict(fields)[b':status'] == b'502'
                                for _, fields in headers))
            self.assertIn(reset_reason.encode(), bodies[3])
            self.assertIn(
                goaway_reason.replace('<', '&lt;').replace('>', '&gt;').encode(),
                bodies[1],
            )
            self.assertEqual(addon.addon.module.events, [
                ['/3', reset_reason],
                ['/1', goaway_reason],
            ])
            self.assertEqual(addon.active_flows, 0)
            self.assertEqual(driver._messages, {})
        finally:
            driver.release_connection('reset-before')
            await addon.close()

    async def test_responseheaders_before_reset_is_observed_but_not_published(self):
        addon = AddonGeneration('''events = []
def responseheaders(flow):
    events.append(["responseheaders", flow.response.status_code])
def response(flow):
    events.append(["response", flow.response.status_code])
def error(flow):
    events.append(["error", str(flow.error)])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()

        async def feed(side, wire):
            message = connection.message(side, wire)
            result, failures = await driver.translate(
                'headers-reset', side, message, H2,
                ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            return connection.bridge.accept(side, message, result)

        try:
            await feed('L', encoded(REQUEST, end=True))
            response = encoded([(b':status', b'200')], end=False)
            reset = frame((7).to_bytes(4, 'big'), 3, 0, 1)
            published = unpack(await feed('R', response + reset))
            self.assertFalse(any(kind == 3 for kind, _, _, _ in published))
            decoder = hpack.Decoder()
            statuses = [
                dict(decoder.decode(payload, raw=True))[b':status']
                for kind, _, _, payload in published
                if kind == 1
            ]
            self.assertEqual(statuses, [b'502'])
            self.assertEqual(addon.addon.module.events, [
                ['responseheaders', 200],
                ['error', 'stream reset by client (REFUSED_STREAM)'],
            ])
            self.assertEqual(addon.active_flows, 0)
            self.assertEqual(driver._messages, {})
        finally:
            driver.release_connection('headers-reset')
            await addon.close()

    async def test_responseheaders_in_previous_callback_are_replaced_by_reset_failure(self):
        addon = AddonGeneration('''events = []
def responseheaders(flow):
    events.append(["responseheaders", flow.response.status_code])
def response(flow):
    events.append(["response", flow.response.status_code])
def error(flow):
    events.append(["error", str(flow.error)])
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()

        async def feed(side, wire):
            message = connection.message(side, wire)
            result, failures = await driver.translate(
                'separated-headers-reset', side, message, H2,
                ApiConnection(message), None, None)
            self.assertEqual(failures, ())
            return connection.bridge.accept(side, message, result)

        try:
            await feed('L', encoded(REQUEST, end=True))
            response = encoded([(b':status', b'200')], end=False)
            self.assertEqual(await feed('R', response), b'')
            self.assertEqual(addon.addon.module.events, [['responseheaders', 200]])

            reset = frame((7).to_bytes(4, 'big'), 3, 0, 1)
            published = unpack(await feed('R', reset))
            self.assertFalse(any(kind == 3 for kind, _, _, _ in published))
            decoder = hpack.Decoder()
            statuses = [
                dict(decoder.decode(payload, raw=True))[b':status']
                for kind, _, _, payload in published
                if kind == 1
            ]
            self.assertEqual(statuses, [b'502'])
            self.assertEqual(addon.addon.module.events, [
                ['responseheaders', 200],
                ['error', 'stream reset by client (REFUSED_STREAM)'],
            ])
            self.assertEqual(addon.active_flows, 0)
            self.assertEqual(driver._messages, {})
        finally:
            driver.release_connection('separated-headers-reset')
            await addon.close()

    async def test_goaway_fragmentation_reports_error_only_after_complete_payload(self):
        wire = frame(bytes(8), 7, 0, 0)
        for cut in range(1, len(wire)):
            with self.subTest(cut=cut):
                addon = AddonGeneration('''errors = []
def error(flow):
    errors.append(flow.request.path)
''', H2AddonEvents.HOOKS)
                await addon.start()
                driver = H2AddonEvents(addon)
                connection = Connection()
                try:
                    for index, (side, fragment) in enumerate((
                        ('L', encoded(REQUEST, end=True)),
                        ('R', wire[:cut]), ('R', wire[cut:]),
                    )):
                        message = connection.message(side, fragment)
                        result, failures = await driver.translate(
                            'one', side, message, H2, ApiConnection(message), None, None)
                        self.assertEqual(failures, ())
                        connection.bridge.accept(side, message, result)
                        self.assertEqual(addon.addon.module.errors,
                                         ['/first'] if index == 2 else [])
                    self.assertEqual(addon.active_flows, 0)
                    self.assertEqual(driver._messages, {})
                finally:
                    driver.release_connection('one')
                    await addon.close()

    def test_reference_goaway_corpora_fix_the_pending_stream_contract(self):
        cases = (
            ('addon_goaway_complete_no_error_v12.json', 0, 'before-goaway', 'GET', False),
            ('addon_goaway_complete_protocol_error_v12.json', 1, 'before-goaway', 'GET', False),
            ('addon_goaway_pending_no_error_v12.json', 0, 'pending', 'GET', False),
            ('addon_goaway_pending_protocol_error_v12.json', 1, 'pending', 'GET', False),
            ('addon_goaway_pending_unknown_error_v12.json', 123, 'pending', 'GET', False),
            ('addon_goaway_after_no_error_v12.json', 0, 'after-goaway', 'GET', False),
            ('addon_goaway_after_protocol_error_v12.json', 1, 'after-goaway', 'GET', False),
            ('addon_goaway_request_open_v12.json', 0, 'request-open', 'POST', False),
            ('addon_goaway_request_open_late_data_v12.json', 0, 'request-open', 'POST', True),
            ('addon_goaway_informational_v12.json', 0, 'informational-before-goaway', 'GET', False),
        )
        for filename, error_code, response_timing, method, late_data in cases:
            with self.subTest(filename=filename):
                corpus_path = ROOT / 'tests' / 'corpus' / filename
                corpus = json.loads(corpus_path.read_text())
                reason = (
                    'HTTP/2 connection closed: <ConnectionTerminated '
                    f'error_code:{error_code}, last_stream_id:1, '
                    'additional_data:None>'
                )

                self.assertEqual(corpus['reference'], 'mitmproxy 12.3.1')
                self.assertEqual(corpus['error_code'], error_code)
                self.assertEqual(corpus['method'], method)
                self.assertEqual(corpus['response_timing'], response_timing)
                if late_data:
                    self.assertIs(corpus['late_first_data_sent'], True)
                else:
                    self.assertNotIn('late_first_data_sent', corpus)
                if response_timing == 'informational-before-goaway':
                    self.assertEqual(corpus['client_informational'], [])
                else:
                    self.assertNotIn('client_informational', corpus)
                self.assertEqual(corpus['origin_requests'], [[1, '/1'], [3, '/3']])
                self.assertEqual(corpus['origin_errors'], [])
                self.assertEqual(corpus['retry_connections'], [])
                self.assertEqual(corpus['client_resets'], [])
                self.assertEqual(corpus['client_terminations'], [])

                expected_hooks = [
                    ['requestheaders', '/1'],
                    ['requestheaders', '/3'],
                ]
                if response_timing == 'request-open':
                    expected_hooks.append(['request', '/3'])
                else:
                    expected_hooks.extend((
                        ['request', '/1'],
                        ['request', '/3'],
                    ))
                if response_timing != 'before-goaway':
                    expected_hooks.extend((
                        ['error', '/1', reason],
                        ['error', '/3', reason],
                    ))
                    expected_statuses = [[1, '502'], [3, '502']]
                    expected_body_streams = [1, 3]
                    expected_ended = [1, 3]
                else:
                    expected_hooks.extend((
                        ['responseheaders', '/1', 200],
                        ['error', '/3', reason],
                        ['response', '/1', 200],
                    ))
                    expected_statuses = [[3, '502'], [1, '200']]
                    expected_body_streams = [3]
                    expected_ended = [3, 1]

                self.assertEqual(corpus['hooks'], expected_hooks)
                self.assertEqual(corpus['client_statuses'], expected_statuses)
                self.assertEqual(corpus['client_ended'], expected_ended)
                expected_headers = []
                for stream, status in expected_statuses:
                    fields = [[':status', status]]
                    if status == '502':
                        fields.extend((
                            ['server', 'mitmproxy 12.3.1'],
                            ['content-type', 'text/html'],
                        ))
                    expected_headers.append([stream, fields])
                self.assertEqual(corpus['client_headers'], expected_headers)
                self.assertEqual(
                    [stream for stream, _ in corpus['client_bodies']],
                    expected_body_streams,
                )
                for _, body in corpus['client_bodies']:
                    self.assertIn('<h1>502 Bad Gateway</h1>', body)
                    self.assertIn(reason.replace('<', '&lt;').replace('>', '&gt;'), body)

    def test_reference_goaway_reset_race_corpora_fix_wire_order(self):
        expectations = {
            'before': {
                'statuses': [[3, '502'], [1, '502']],
                'ended': [3, 1],
                'reasons': [
                    'stream reset by client (NO_ERROR)',
                    ('HTTP/2 connection closed: <ConnectionTerminated '
                     'error_code:0, last_stream_id:1, additional_data:None>'),
                ],
            },
            'after': {
                'statuses': [[1, '502'], [3, '502']],
                'ended': [1, 3],
                'reasons': [
                    ('HTTP/2 protocol error: Invalid input '
                     'ConnectionInputs.RECV_RST_STREAM in state '
                     'ConnectionState.CLOSED'),
                ] * 2,
            },
        }
        for order, expected in expectations.items():
            with self.subTest(order=order):
                path = ROOT / 'tests' / 'corpus' / (
                    f'addon_goaway_reset_{order}_v12.json')
                corpus = json.loads(path.read_text())
                self.assertEqual(corpus['reference'], 'mitmproxy 12.3.1')
                self.assertEqual(corpus['reset_goaway_order'], order)
                self.assertEqual(
                    corpus['response_timing'], f'reset-{order}-goaway')
                self.assertEqual(corpus['origin_errors'], [])
                self.assertEqual(corpus['retry_connections'], [])
                self.assertEqual(corpus['client_resets'], [])
                self.assertEqual(corpus['client_terminations'], [])
                self.assertEqual(corpus['client_statuses'], expected['statuses'])
                self.assertEqual(corpus['client_ended'], expected['ended'])
                self.assertEqual(
                    [hook[2] for hook in corpus['hooks'] if hook[0] == 'error'],
                    expected['reasons'],
                )
                self.assertTrue(all(
                    '<h1>502 Bad Gateway</h1>' in body
                    for _, body in corpus['client_bodies']
                ))

    def test_reference_reset_matrix_fixes_downstream_policy(self):
        path = ROOT / 'tests' / 'corpus' / 'addon_reset_matrix_v12.json'
        corpus = json.loads(path.read_text())

        self.assertEqual(corpus['reference'], 'mitmproxy 12.3.1')
        self.assertEqual(
            [case['error_code'] for case in corpus['cases']],
            [0, 1, 2, 3, 7, 8, 11, 123],
        )
        self.assertEqual(corpus['preceding_headers'], [
            {
                'kind': 'informational',
                'status': 103,
                'responseheaders_hook': False,
                'client_informational': False,
                'downstream_status': 502,
            },
            {
                'kind': 'final',
                'status': 200,
                'responseheaders_hook': True,
                'response_hook': False,
                'original_headers_published': False,
                'downstream_status': 502,
            },
            {
                'kind': 'final-separated',
                'status': 200,
                'responseheaders_hook': True,
                'response_hook': False,
                'original_headers_published': False,
                'downstream_status': 502,
            },
        ])
        for case in corpus['cases']:
            self.assertEqual(
                case['error'],
                f"stream reset by client ({case['label']})",
            )
            if case['error_code'] == 8:
                self.assertEqual(case['downstream'], 'reset')
                self.assertEqual(case['reset_error_code'], 8)
                self.assertNotIn('status', case)
            else:
                self.assertEqual(case['downstream'], 'response')
                self.assertEqual(case['status'], 502)
                self.assertNotIn('reset_error_code', case)

    def test_reference_expect_contract_requires_local_continue_and_hides_upstream_1xx(self):
        path = ROOT / 'tests' / 'corpus' / 'addon_h2_expect_v12.json'
        corpus = json.loads(path.read_text())

        self.assertEqual(corpus['reference'], 'mitmproxy 12.3.1')
        self.assertEqual(corpus['request'], {
            'case': 'baseline',
            'method': 'POST',
            'expect_fields': ['100-continue'],
            'body': 'test',
        })
        self.assertEqual(corpus['client'], {
            'statuses': ['100', '200'],
            'body': 'done',
        })
        self.assertFalse(corpus['origin']['expect_forwarded'])
        self.assertNotIn(
            'expect',
            [name for name, _ in corpus['origin']['headers']],
        )
        self.assertEqual(corpus['hooks'], [
            ['requestheaders', '100-continue', True],
            ['request', None, 'test'],
            ['responseheaders', 200],
            ['response', 200, 'done'],
        ])

        matrix_path = ROOT / 'tests' / 'corpus' / 'addon_h2_expect_matrix_v12.json'
        matrix = json.loads(matrix_path.read_text())
        self.assertEqual(matrix['reference'], 'mitmproxy 12.3.1')
        self.assertEqual(matrix['upstream_informational_statuses'], [103, 100])
        self.assertFalse(matrix['upstream_informational_published'])
        self.assertEqual(
            [case['name'] for case in matrix['cases']],
            ['baseline', 'mixed-case', 'duplicate', 'invalid', 'absent', 'bodyless'],
        )
        continue_cases = {
            case['name'] for case in matrix['cases'] if case['local_continue']
        }
        self.assertEqual(continue_cases, {'baseline', 'mixed-case', 'bodyless'})
        for case in matrix['cases']:
            self.assertEqual(
                case['expect_forwarded'],
                case['name'] in {'duplicate', 'invalid'},
            )

    async def test_event_driver_holds_body_and_preserves_message_identity(self):
        addon = AddonGeneration('''events = []
messages = {}
def requestheaders(flow):
    assert flow.request.raw_content is None
    assert flow.request.timestamp_end is None
    messages[flow.id] = flow.request
    flow.request.headers["x-header-hook"] = "yes"
    events.append(["headers", flow.request.path])
def request(flow):
    assert messages[flow.id] is flow.request
    events.append(["request", flow.request.content])
    flow.request.content = flow.request.content.upper()
def responseheaders(flow):
    assert flow.response.raw_content is None
    events.append(["responseheaders", flow.request.path])
def response(flow):
    assert messages.pop(flow.id) is flow.request
    events.append(["response", flow.response.content])
    flow.response.content = b"changed response"
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()
        client, server = SimpleNamespace(), SimpleNamespace()

        async def feed(side, wire):
            message = connection.message(side, wire)
            failures, published = await driver.prepare('one', side, message, H2,
                                                       ApiConnection(message), client, server)
            self.assertEqual(failures, ())
            result = connection.publish(side, message)
            driver.published(published)
            return result

        self.assertEqual(await feed('L', encoded(REQUEST)), b'')
        self.assertEqual(await feed('L', frame(b'hel', flags=0)), b'')
        result = unpack(await feed('L', frame(b'lo')))
        self.assertIn((b'x-header-hook', b'yes'), hpack.Decoder().decode(result[0][3], raw=True))
        self.assertEqual(b''.join(payload for kind, flags, stream, payload in result if kind == 0), b'HELLO')
        self.assertEqual(addon.addon.module.events, [['headers', '/first'], ['request', b'hello']])
        self.assertEqual(addon.active_flows, 1)
        result = unpack(await feed('R', encoded([(b':status', b'200')]) + frame(b'old')))
        self.assertEqual(b''.join(payload for kind, flags, stream, payload in result if kind == 0), b'changed response')
        self.assertEqual(addon.addon.module.events[-2:], [['responseheaders', '/first'], ['response', b'old']])
        self.assertEqual(addon.active_flows, 0)
        await addon.close()

    async def test_completed_later_stream_is_not_redispatched_behind_hold(self):
        addon = AddonGeneration('''events = []
def requestheaders(flow):
    events.append(["headers", flow.request.path])
def request(flow):
    events.append(["request", flow.request.path])
    flow.request.content = b"replacement-" + flow.request.path.encode()
''', H2AddonEvents.HOOKS)
        await addon.start()
        driver = H2AddonEvents(addon)
        connection = Connection()
        encoder = hpack.Encoder()
        client, server = SimpleNamespace(), SimpleNamespace()

        async def feed(wire):
            message = connection.message('L', wire)
            failures, published = await driver.prepare('one', 'L', message, H2,
                                                       ApiConnection(message), client, server)
            self.assertEqual(failures, ())
            output = connection.publish('L', message)
            driver.published(published)
            return output

        first = [(key, b'/one' if key == b':path' else value) for key, value in REQUEST]
        second = [(key, b'/two' if key == b':path' else value) for key, value in REQUEST]
        wire = encoded(first, encoder=encoder) + frame(b'a', flags=0)
        wire += encoded(second, stream=3, encoder=encoder) + frame(b'b', stream=3)
        self.assertEqual(await feed(wire), b'')
        self.assertEqual(addon.addon.module.events,
                         [['headers', '/one'], ['headers', '/two'], ['request', '/two']])
        result = unpack(await feed(frame(b'c')))
        for stream, expected in ((1, b'replacement-/one'), (3, b'replacement-/two')):
            self.assertEqual(b''.join(payload for kind, flags, ident, payload in result
                                     if kind == 0 and ident == stream), expected)
        self.assertEqual(addon.addon.module.events[-1], ['request', '/one'])
        self.assertEqual(len(addon.addon.module.events), 4)
        driver.release_connection('one')
        self.assertEqual(addon.active_flows, 0)
        await addon.close()

    async def test_addon_edits_both_directions_through_native_translate(self):
        addon = AddonGeneration('''#!mitmproxy
from mitmproxy import http
from mitmproxy.coretypes.multidict import MultiDict

seen = {}

def request(flow: http.HTTPFlow):
    seen[flow.id] = flow
    flow.metadata["original_path"] = flow.request.path
    flow.request.query = MultiDict([("source", "addon"), ("source", "test")]).fields
    flow.request.content = b"longer request body"
    flow.request.trailers = http.Headers([(b"x-request-end", b"yes")])

async def response(flow: http.HTTPFlow):
    assert seen.pop(flow.id) is flow
    flow.response.status_code = 201
    flow.response.headers["x-request-path"] = flow.metadata["original_path"]
    flow.response.content = b"changed response"
''', {"request", "response"})
        self.assertEqual(await addon.start(None), ())
        connection = Connection()
        request_encoder = hpack.Encoder()
        response_encoder = hpack.Encoder()
        request_decoder = hpack.Decoder()
        response_decoder = hpack.Decoder()
        client = SimpleNamespace()
        server = SimpleNamespace()

        for stream in (1, 3):
            fields = [(name, f"/stream-{stream}".encode() if name == b":path" else value)
                      for name, value in REQUEST]
            fields.append((b"content-length", b"3"))
            wire = encoded(fields, stream, encoder=request_encoder)
            wire += frame(b"old", 0, 1, stream)
            message = connection.message("L", wire)
            binding = bind(message, stream)
            flow = addon.create_flow("connection-1", stream, client, server)
            flow.request = binding.message
            self.assertEqual(await addon.dispatch("request", flow), ())
            binding.apply()
            published = unpack(connection.publish("L", message))
            blocks = [request_decoder.decode(payload, raw=True)
                      for kind, flags, ident, payload in published if kind == 1]
            self.assertIn((b":path", f"/stream-{stream}?source=addon&source=test".encode()), blocks[0])
            self.assertIn((b"content-length", b"19"), blocks[0])
            self.assertEqual(blocks[-1], [(b"x-request-end", b"yes")])
            self.assertEqual(b"".join(payload for kind, flags, ident, payload in published if kind == 0),
                             b"longer request body")
            self.assertEqual(sum(bool(flags & 1) for kind, flags, ident, payload in published
                                 if kind in (0, 1)), 1)

        # HTTP/2 responses need not arrive in request order. Preserve both the
        # addon instance and the corresponding flow while translating each side.
        for stream in (3, 1):
            wire = encoded([(b":status", b"200"), (b"content-length", b"3")],
                           stream, encoder=response_encoder)
            wire += frame(b"old", 0, 1, stream)
            message = connection.message("R", wire)
            binding = bind(message, stream)
            flow = addon.get_flow("connection-1", stream)
            flow.response = binding.message
            self.assertEqual(await addon.dispatch("response", flow), ())
            binding.apply()
            published = unpack(connection.publish("R", message))
            fields = response_decoder.decode(published[0][3], raw=True)
            self.assertIn((b":status", b"201"), fields)
            self.assertIn((b"x-request-path", f"/stream-{stream}".encode()), fields)
            self.assertEqual(b"".join(payload for kind, flags, ident, payload in published if kind == 0),
                             b"changed response")
            self.assertIs(addon.release_flow("connection-1", stream), flow)
        self.assertEqual(addon.addon.module.seen, {})
        self.assertEqual(addon.active_flows, 0)
        self.assertEqual(await addon.close(), ())
        self.assertNotIn("mitmproxy", sys.modules)


if __name__ == "__main__":
    unittest.main()
