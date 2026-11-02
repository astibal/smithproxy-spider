"""Authentication-only mitmproxy hooks over Smithproxy's AAA decision.

These observations precede target setup. They own neither a tunnel lifecycle
nor wire responses: the only published decision is an additional policy veto.
"""

import base64

from addon_connection import Client, Server
from addon_http import Headers
from addon_http_message import Request, Response
from addon_runtime import AddonRuntimeError
from addon_socks5_events import Socks5AddonEvents


class AuthenticationAddonAdapter:
    HOOKS = frozenset({'socks5_auth', 'http_connect'})

    def __init__(self, generation):
        self.generation = generation
        self.socks5 = Socks5AddonEvents(generation)

    async def authenticate(self, observation):
        peer = observation['peer']
        client = Client(peername=(peer['host'], int(peer['port'])), sockname=None)
        accepted = observation['status'] == 'accepted'

        if observation['protocol'] == 'socks5':
            decision, failures = await self.socks5.authenticate(client, {
                'version': 1,
                'event': 'authenticate',
                'username': observation['username'],
                'password': observation['password'],
                'valid': accepted,
            })
            if failures:
                raise AddonRuntimeError('Authentication callback failed')
            return accepted and decision.valid

        if observation['protocol'] != 'http-connect':
            raise AddonRuntimeError('Unknown authentication protocol')
        return await self._http_connect(client, observation, accepted)

    async def _http_connect(self, client, observation, accepted):
        # Older producers have no CONNECT metadata. Do not substitute a fake
        # destination or a reconstructed Authorization header for real input.
        context = observation['http_connect']
        raw = base64.b64decode(context['request_base64'], validate=True)
        if len(raw) >= 8192 or not raw.endswith(b'\r\n\r\n'):
            raise AddonRuntimeError('Incomplete CONNECT headers')
        lines = raw[:-4].split(b'\r\n')
        method, authority, version = lines[0].split()
        if method != b'CONNECT' or version not in (b'HTTP/1.0', b'HTTP/1.1'):
            raise AddonRuntimeError('Invalid CONNECT request line')

        fields = []
        for line in lines[1:]:
            name, separator, value = line.partition(b':')
            if not separator or not name or line[:1] in (b' ', b'\t'):
                raise AddonRuntimeError('Unsupported CONNECT header')
            fields.append((name, value.strip(b' \t')))
        headers = Headers(fields)
        if accepted:
            headers.pop('proxy-authorization', None)

        server = Server(address=(context['host'], context['port']))
        identity = client.id
        flow = self.generation.create_flow(identity, 1, client, server)
        try:
            flow.request = Request(context['host'], context['port'], method,
                                   b'', authority, b'', version, headers,
                                   b'', None, None, None)
            flow._mode = 'regular'
            flow.metadata['smithproxy_auth'] = {
                'status': observation['status'],
                'identity': observation['identity'],
                'groups': tuple(observation['groups']),
            }
            if accepted:
                flow.metadata['proxyauth'] = (observation['username'], observation['password'])
            else:
                code = 407 if observation['status'] == 'rejected' else 503
                flow.response = Response.make(code)

            # Request metadata is observational. Rerouting requires a separate
            # native control contract and cannot silently change this decision.
            original = flow.request.get_state()
            failures = await self.generation.dispatch('http_connect', flow)
            if failures:
                raise AddonRuntimeError('Authentication callback failed')
            if flow.intercepted or not isinstance(flow.request, Request):
                raise AddonRuntimeError('Unsupported authentication flow control')
            current = flow.request.get_state()
            for field in ('host', 'port', 'method', 'scheme', 'authority', 'path'):
                if current[field] != original[field]:
                    raise AddonRuntimeError('Authentication cannot reroute CONNECT')
            if flow.server_conn is not server or server.address != (context['host'], context['port']):
                raise AddonRuntimeError('Authentication cannot reroute CONNECT')
            if flow.error is not None or not flow.live:
                return False
            if flow.response is None:
                return accepted
            if not isinstance(flow.response, Response):
                raise AddonRuntimeError('Invalid authentication response')
            return accepted and 200 <= flow.response.status_code < 300
        finally:
            # No later connected/error hook is synthesized from an auth result.
            # The native proxy still has to resolve and connect the destination.
            self.generation.release_flow(identity, 1)

    async def close(self):
        return await self.generation.close()
