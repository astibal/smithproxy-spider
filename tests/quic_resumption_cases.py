#!/usr/bin/env python3
"""Measure three independent HTTP/3 connections, reusing only the middle ticket."""

import argparse
import asyncio
from dataclasses import replace
import json
import subprocess
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.response = asyncio.get_running_loop().create_future()
        self.resumed = None
        self.body = bytearray()
        self.status = None

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.resumed = event.session_resumed

        if isinstance(event, ConnectionTerminated) and not self.response.done():
            self.response.set_exception(ConnectionError(event.reason_phrase))

        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                self.status = dict(item.headers).get(b':status', b'').decode()
            if isinstance(item, DataReceived):
                self.body.extend(item.data)
            if isinstance(item, (HeadersReceived, DataReceived)):
                if item.stream_ended and not self.response.done():
                    self.response.set_result(bytes(self.body))

    async def request(self, path):
        stream = self._quic.get_next_available_stream_id()
        self.http.send_headers(stream_id=stream, headers=[
            (b':method', b'GET'),
            (b':scheme', b'https'),
            (b':authority', b'origin.runner.lab'),
            (b':path', path.encode()),
        ], end_stream=True)
        self.transmit()
        return await asyncio.wait_for(self.response, 8)


async def measure(arguments):
    tickets = []
    results = []

    for name in ('fresh', 'resumed', 'fresh-control'):
        configuration = QuicConfiguration(
            is_client=True, alpn_protocols=['h3'], server_name='origin.runner.lab')
        configuration.load_verify_locations(cafile=str(arguments.ca))

        # A new configuration and UDP connection are created every time.
        # Never reuse the connection itself or send application bytes as 0-RTT.
        offer = name == 'resumed'
        if offer:
            assert tickets, 'First connection delivered no session ticket'
            configuration.session_ticket = tickets[-1]
            if arguments.resume_mode == 'wrong-name':
                # Deliberately bypass the client's local ticket/SNI association.
                # The proxy must still authenticate this new upstream identity.
                configuration.server_name = 'untrusted.invalid'
                configuration.session_ticket = replace(
                    tickets[-1], server_name=configuration.server_name)

        # Change only the resumed connection's deployment or origin trust.
        # The following fresh control must recover without restarting the proxy.
        mode = arguments.resume_mode if offer else 'baseline'
        if arguments.data_namespace:
            deployment = mode
            code = ('import json; from urllib.request import Request,urlopen; '
                    f'r=Request("http://127.0.0.1:59090/scenario",'
                    f'json.dumps({{"mode":{deployment!r}}}).encode()); '
                    'assert json.load(urlopen(r))["ready"]')
            subprocess.run(['ip', 'netns', 'exec', arguments.data_namespace,
                            'python3', '-c', code], check=True)

        if arguments.origin_switch:
            arguments.origin_switch.write_text('untrusted' if mode == 'untrusted' else 'trusted')
            await asyncio.sleep(.2)

        result = {'case': name, 'ticket_offered': offer, 'resumed': None}
        try:
            async with connect(arguments.host, 443, configuration=configuration,
                               create_protocol=Client,
                               session_ticket_handler=tickets.append) as client:
                result['resumed'] = client.resumed
                body = await client.request('/resumption-' + name)
                result['status'] = client.status
                result['body'] = body.decode()
                assert client.status == '200', result
                assert 'path=/resumption-' + name in result['body'], result

                # Allow post-handshake tickets to be processed before closing.
                await asyncio.sleep(.3)
        except Exception as error:
            result['error'] = type(error).__name__ + ': ' + str(error)

        results.append(result)
        arguments.output.write_text(json.dumps(results, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        await asyncio.sleep(.5)

    for result in results:
        denied = result['case'] == 'resumed' and arguments.resume_mode != 'baseline'
        assert ('error' in result) == denied, results
        if denied:
            assert 'body' not in result, result
            assert not result['error'].startswith('TimeoutError'), result
    assert [result['resumed'] for result in results] == [False, True, False], results


async def update_origin_identity(configuration, arguments):
    """Swap only future origin handshakes; established connections stay intact."""
    import os

    switch = Path(os.environ['QUIC_ORIGIN_RELEASE_FILE']).with_name('origin-trust')
    previous = 'trusted'
    while True:
        current = switch.read_text() if switch.exists() else 'trusted'
        if current != previous:
            directory = Path(arguments.certificate).parent
            if current == 'untrusted':
                configuration.load_cert_chain(directory / 'srv-cert.pem', directory / 'srv-key.pem')
            else:
                configuration.load_cert_chain(arguments.certificate, arguments.key)
            previous = current
            print('IDENTITY ' + current, flush=True)
        await asyncio.sleep(.02)


def exercise_resumption(path, verify):
    """Run inside the existing namespace lab, preserving all relay evidence."""
    import os
    import time

    root = path.parent.parent
    for mode in ('baseline', 'veto', 'untrusted', 'wrong-name'):
        offset = len(path.read_text().splitlines())
        result = subprocess.run([
            'ip', 'netns', 'exec', os.environ['CLIENT_NS'], 'python3', __file__,
            '--ca', str(root / 'config/certs/ca-cert.pem'),
            '--output', str(root / f'results/quic-resumption-{mode}.json'),
            '--resume-mode', mode, '--data-namespace', os.environ['DATA_NS'],
            '--origin-switch', str(root / 'results/origin-trust'),
        ])

        # Wait for natural retirement before evaluating callback order. Never
        # stop the proxy to manufacture the terminal events being asserted.
        deadline = time.monotonic() + 12
        while True:
            rows = [json.loads(line) for line in path.read_text().splitlines()[offset:]]
            parents = {row['event']['id'] for row in rows
                       if row['event']['action'] == 'connection-start'
                       and row['event'].get('details', {}).get('info', {}).get('scope') == 'transport'}
            stopped = {row['event']['id'] for row in rows
                       if row['event']['action'] == 'connection-stop'}
            if len(parents) == 3 and parents <= stopped:
                break
            assert time.monotonic() < deadline, (mode, parents, stopped)
            time.sleep(.05)

        verify(path)
        assert result.returncode == 0, f'QUIC resumption failed: {mode}'

        if mode != 'baseline':
            negative = [row for row in rows if row['mode'] == mode
                        and row['event']['action'] == 'quic-lifecycle']
            assert negative and all(row['status'] == 200 for row in negative), negative
            phases = [(row['event']['details']['quic']['envelope']['side'],
                       row['event']['details']['quic']['envelope']['event']) for row in negative]
            assert phases.count(('server', 'start')) == 1, phases
            assert ('server', 'established') not in phases, phases
            if mode == 'veto':
                assert any(row['reply'].get('proceed') is False for row in negative), negative
            else:
                assert phases.count(('server', 'failed')) == 1, phases

        print('PASS QUIC resumption:', mode, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='198.18.20.2')
    parser.add_argument('--ca', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--resume-mode', choices=['baseline', 'veto', 'untrusted', 'wrong-name'], default='baseline')
    parser.add_argument('--data-namespace')
    parser.add_argument('--origin-switch', type=Path)
    asyncio.run(measure(parser.parse_args()))
