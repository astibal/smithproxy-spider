"""Native TLS meta editing, independent of the mitmproxy compatibility facade."""

import base64
from dataclasses import dataclass
from enum import Enum
import ipaddress
import re

from inspection_tls_hello import ParsedClientHello


class TlsEvent(Enum):
    CLIENT_HELLO = 'client_hello'
    START = 'start'
    ESTABLISHED = 'established'
    FAILED = 'failed'


class TlsSide(Enum):
    CLIENT = 'client'
    SERVER = 'server'


class TlsTransport(Enum):
    TLS = 'tls'
    QUIC = 'quic'


class TlsDecision(Enum):
    CONTINUE = 'continue'
    BYPASS = 'bypass'
    TERMINATE = 'terminate'


@dataclass(frozen=True)
class ClientHelloSnapshot:
    """Original peer offers and the initial native cipher expression."""

    sni: str | None
    alpn_offers: tuple[bytes, ...]
    cipher_suites: tuple[int, ...]
    extensions: tuple[tuple[int, bytes], ...]
    openssl_cipher_list: str | None


@dataclass(frozen=True)
class TlsCommit:
    """Owned immutable settings; publication requires returning this result."""

    decision: TlsDecision
    sni: str
    alpn_offers: tuple[bytes, ...]
    openssl_cipher_list: str | None

    def to_wire(self):
        return {
            'decision': self.decision.value,
            'sni': self.sni,
            'alpn_offers': [base64.b64encode(value).decode('ascii') for value in self.alpn_offers],
            'openssl_cipher_list': self.openssl_cipher_list,
        }

    def legacy_reply(self, editable=True):
        reply = {
            'proceed': self.decision is not TlsDecision.TERMINATE,
            'ignore_connection': self.decision is TlsDecision.BYPASS,
        }
        if editable and self.decision is TlsDecision.CONTINUE:
            wire = b''.join(bytes([len(value)]) + value for value in self.alpn_offers)
            reply['upstream'] = {
                'sni': self.sni,
                'alpn_base64': base64.b64encode(wire).decode('ascii'),
                'openssl_cipher_list': self.openssl_cipher_list,
            }
        return reply


def decode_offer(settings):
    """Decode the legacy length-prefixed ALPN list at the transport boundary."""
    if not isinstance(settings, dict) or not isinstance(settings.get('sni'), str):
        raise ValueError('Invalid native upstream settings')

    encoded = settings.get('alpn_base64')
    if not isinstance(encoded, str) or len(encoded) > 87380:
        raise ValueError('Invalid native ALPN offer')

    raw = base64.b64decode(encoded, validate=True)
    offers = []
    offset = 0
    while offset < len(raw):
        length = raw[offset]
        offset += 1
        if not length or offset + length > len(raw):
            raise ValueError('Invalid native ALPN protocol')
        offers.append(raw[offset:offset + length])
        offset += length

    return settings['sni'], tuple(offers)


def validate_offer(sni, alpn_offers, expression, initial, *, editable, cipher_editable):
    """Shared TCP offer checks for ClientHello and pre-handshake meta editing."""
    if not isinstance(sni, str):
        raise ValueError('SNI must be a hostname')

    if sni != initial[0] and sni:
        sni = sni.encode('idna').decode('ascii')
        try:
            ipaddress.ip_address(sni)
        except ValueError:
            pass
        else:
            raise ValueError('SNI cannot be an IP literal')

        labels = sni.removesuffix('.').split('.')
        if len(sni) > 253 or any(
            not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label)
            for label in labels
        ):
            raise ValueError('Invalid SNI hostname')

    if not isinstance(alpn_offers, (list, tuple)):
        raise ValueError('ALPN offers must be a list or tuple')
    offers = tuple(alpn_offers)
    if any(not isinstance(value, bytes) or not 1 <= len(value) <= 255
           or value not in initial[1] for value in offers):
        raise ValueError('ALPN must select from the native offer')
    if sum(1 + len(value) for value in offers) > 65535:
        raise ValueError('ALPN offer is too large')

    if expression is not None and (
        not isinstance(expression, str) or len(expression.encode()) > 65535 or '\0' in expression
    ):
        raise ValueError('Invalid OpenSSL cipher expression')

    if not editable and (sni, offers, expression) != initial:
        raise ValueError('Producer does not support TLS offer editing')
    if not cipher_editable and expression != initial[2]:
        raise ValueError('Producer does not support cipher editing')

    return sni, offers, expression


class ClientHelloDraft:
    """Prefilled outgoing TLS metadata, with an immutable original observation."""

    def __init__(self, observation):
        encoded = observation.get('client_hello_base64')
        if not isinstance(encoded, str) or not encoded or len(encoded) > 512 * 1024:
            raise ValueError('Invalid ClientHello body')

        self.parsed = ParsedClientHello(base64.b64decode(encoded, validate=True))
        settings = observation.get('upstream')
        self._editable = settings is not None
        self._cipher_editable = isinstance(settings, dict) and 'openssl_cipher_list' in settings
        self.sni = self.parsed.sni or ''
        self.alpn_offers = list(self.parsed.alpn_protocols)
        self.openssl_cipher_list = None
        if self._editable:
            self.sni, offers = decode_offer(settings)
            self.alpn_offers = list(offers)
            self.openssl_cipher_list = settings.get('openssl_cipher_list')

        self._initial = (self.sni, tuple(self.alpn_offers), self.openssl_cipher_list)
        self._original = ClientHelloSnapshot(
            self.parsed.sni, tuple(self.parsed.alpn_protocols),
            tuple(self.parsed.cipher_suites), tuple(self.parsed.extensions),
            self.openssl_cipher_list,
        )
        self.decision = TlsDecision.CONTINUE
        self._result = None
        self.commit()  # Validate producer values before exposing them to scripts.
        self._result = None

    def original(self):
        return self._original

    def commit(self):
        """Validate all fields before creating an immutable publication result."""
        if not isinstance(self.decision, TlsDecision):
            raise ValueError('Expected TlsDecision')

        sni, offers, expression = validate_offer(
            self.sni, self.alpn_offers, self.openssl_cipher_list, self._initial,
            editable=self._editable, cipher_editable=self._cipher_editable,
        )

        self._result = TlsCommit(self.decision, sni, offers, expression)
        return self._result

    def publish(self, result):
        if result is None:
            # Uncommitted edits must never leak into the reply.
            baseline = TlsCommit(TlsDecision.CONTINUE, *self._initial)
            return baseline.legacy_reply(self._editable)
        if not isinstance(result, TlsCommit) or result is not self._result:
            raise ValueError('Return this ClientHello draft commit result')
        return result.legacy_reply(self._editable)


@dataclass(frozen=True)
class TlsView:
    event: TlsEvent
    side: TlsSide
    attempt: int
    client_hello: ClientHelloDraft | None = None
    outcome: 'OutcomeDraft | None' = None
    start: 'TlsStartDraft | QuicStartDraft | None' = None
    transport: TlsTransport = TlsTransport.TLS

    @classmethod
    def from_observation(cls, observation, transport=TlsTransport.TLS):
        envelope = observation.get('envelope', {})
        if (type(envelope.get('version')) is not int or envelope['version'] != 1
                or type(envelope.get('attempt')) is not int or envelope['attempt'] < 1):
            raise ValueError('Invalid TLS envelope')

        if not isinstance(transport, TlsTransport):
            raise ValueError('Invalid TLS transport')
        side = TlsSide(envelope.get('side'))
        name = envelope.get('event')
        if name == 'client-hello' and side is TlsSide.CLIENT and transport is TlsTransport.TLS:
            return cls(TlsEvent.CLIENT_HELLO, side, envelope['attempt'],
                       client_hello=ClientHelloDraft(observation))

        # Import here to keep the draft implementation separate from the API
        # envelope without making it depend on the compatibility adapter.
        from inspection_tls_outcome import OutcomeDraft
        event = TlsEvent(name)
        if event is TlsEvent.START and transport is TlsTransport.QUIC:
            from inspection_quic import QuicStartDraft
            if side is not TlsSide.SERVER:
                raise ValueError('QUIC exposes upstream start only')
            return cls(event, side, envelope['attempt'],
                       start=QuicStartDraft(observation), transport=transport)

        if event is TlsEvent.START:
            from inspection_tls_start import TlsStartDraft
            return cls(event, side, envelope['attempt'], start=TlsStartDraft(observation, side))

        if event not in (TlsEvent.ESTABLISHED, TlsEvent.FAILED):
            raise ValueError('Unsupported TLS event')
        if transport is TlsTransport.QUIC:
            observation = dict(observation)
            alpn = observation.get('alpn', '')
            if not isinstance(alpn, str):
                raise ValueError('Invalid QUIC ALPN')
            observation['alpn_base64'] = base64.b64encode(alpn.encode('ascii')).decode('ascii')
        return cls(event, side, envelope['attempt'],
                   outcome=OutcomeDraft(observation, event), transport=transport)

    def publish(self, result):
        draft = self.outcome
        if self.event is TlsEvent.CLIENT_HELLO:
            draft = self.client_hello
        elif self.event is TlsEvent.START:
            draft = self.start
        return draft.publish(result)


def api_types():
    """Editor/reference declarations for the same native TLS objects."""
    availability = 'Explicit TLS subscription on a native flow deployment.'
    example = 'if api.tls is not None and api.tls.event is TlsEvent.CLIENT_HELLO:\n    hello = api.tls.client_hello\n    hello.sni = "origin.example"\n    return hello.commit()'

    def member(name, kind, description, access='read-only snapshot'):
        return {
            'name': name, 'type': kind, 'description': description,
            'example': example, 'availability': availability, 'access': access,
            'easy': 'TLS metadata validation is independent of content Safety modes.',
            'expert': 'Unsupported handshake operations remain unavailable.',
        }

    editable = [
        member('sni', 'str', 'Outgoing SNI; an empty string omits it.', 'mutable draft'),
        member('alpn_offers', 'list[bytes]', 'Select and order the effective native ALPN offer.', 'mutable draft'),
        member('openssl_cipher_list', 'str | None', 'OpenSSL TLS <=1.2 expression; None retains native defaults.', 'mutable draft'),
        member('decision', 'TlsDecision', 'Continue, bypass or terminate this handshake.', 'mutable draft'),
    ]
    original = member('original', 'ClientHelloSnapshot', 'Return the stored deeply immutable original values.')
    original['parameters'] = ''
    commit = member('commit', 'TlsCommit', 'Validate and freeze this draft. Return the result to publish it.')
    commit['parameters'] = ''

    definitions = {
        'TlsView': {
            'description': 'Session TLS notification; not application content.',
            'fields': [member('event', 'TlsEvent', 'Typed notification kind.'),
                       member('side', 'TlsSide', 'Client-facing or upstream-facing TLS leg.'),
                       member('attempt', 'int', 'Native handshake attempt identity.'),
                       member('client_hello', 'ClientHelloDraft | None', 'Draft present only for ClientHello.'),
                       member('outcome', 'OutcomeDraft | None', 'Facts and decision for established/failed events.'),
                       member('start', 'TlsStartDraft | QuicStartDraft | None', 'Prefilled settings for the selected transport.'),
                       member('transport', 'TlsTransport', 'TCP TLS or QUIC parent handshake.')],
            'methods': [],
        },
        'ClientHelloDraft': {
            'description': ClientHelloDraft.__doc__, 'fields': editable,
            'methods': [original, commit],
        },
        'ClientHelloSnapshot': {
            'description': ClientHelloSnapshot.__doc__,
            'fields': [
                member('sni', 'str | None', 'Original peer SNI.'),
                member('alpn_offers', 'tuple[bytes, ...]', 'Original peer ALPN offers.'),
                member('cipher_suites', 'tuple[int, ...]', 'Original peer cipher identifiers.'),
                member('extensions', 'tuple[tuple[int, bytes], ...]', 'Original peer extension values.'),
                member('openssl_cipher_list', 'str | None', 'Initial native expression, not a peer wire field.'),
            ],
            'methods': [],
        },
        'QuicStartSnapshot': {
            'description': 'Immutable effective QUIC offer.',
            'fields': [member('sni', 'str', 'Original outgoing SNI.'),
                       member('alpn_offers', 'tuple[bytes, ...]', 'One original ALPN protocol.'),
                       member('openssl_ciphersuites', 'str | None', 'Original TLS 1.3 cipher expression.')],
            'methods': [],
        },
        'QuicStartDraft': {
            'description': 'QUIC upstream meta editing; not an HTTP/3 stream.',
            'fields': [member('sni', 'str', 'Outgoing SNI.', 'mutable draft'),
                       member('alpn_offers', 'list[bytes]', 'Exactly one ASCII ALPN protocol.', 'mutable draft'),
                       member('openssl_ciphersuites', 'str | None', 'OpenSSL TLS 1.3 suites; None keeps defaults.', 'mutable draft'),
                       member('decision', 'TlsDecision', 'CONTINUE or TERMINATE.', 'mutable draft')],
            'methods': [dict(original, type='QuicStartSnapshot'), dict(commit, type='QuicStartCommit')],
        },
        'QuicStartCommit': {
            'description': 'Immutable QUIC offer decision.', 'fields': [], 'methods': [],
        },
        'TlsStartSnapshot': {
            'description': 'Original effective native start settings.',
            'fields': [dict(value) for value in editable[:3]], 'methods': [],
        },
        'TlsStartDraft': {
            'description': 'Upstream offer meta editing; client-facing settings remain read-only.',
            'fields': [dict(value) for value in editable[:3]] + [member('decision', 'TlsDecision', 'CONTINUE or TERMINATE at TLS start.', 'mutable draft')],
            'methods': [dict(original, type='TlsStartSnapshot'), dict(commit)],
        },
        'OutcomeSnapshot': {
            'description': 'Immutable handshake facts.', 'fields': [
                member('sni', 'str | None', 'Observed SNI.'),
                member('alpn', 'bytes | None', 'Negotiated ALPN bytes.'),
                member('cipher', 'str | None', 'Negotiated cipher name.'),
                member('tls_version', 'str | None', 'Observed TLS version.'),
                member('error', 'str | None', 'Native failure description.'),
                member('certificates', 'tuple[bytes, ...]', 'Public peer certificate chain as immutable PEM bytes.'),
            ], 'methods': [],
        },
        'OutcomeDraft': {
            'description': 'Observed facts remain read-only; an established session may be terminated.',
            'fields': [
                member('sni', 'str | None', 'Observed SNI.'),
                member('alpn', 'bytes | None', 'Negotiated ALPN bytes.'),
                member('cipher', 'str | None', 'Negotiated cipher name.'),
                member('tls_version', 'str | None', 'Observed TLS version.'),
                member('error', 'str | None', 'Native failure description.'),
                member('certificates', 'tuple[bytes, ...]', 'Public peer certificate chain as immutable PEM bytes.'),
            ] + [member('decision', 'TlsDecision', 'CONTINUE or TERMINATE; failed events accept CONTINUE only.', 'mutable draft')],
            'methods': [dict(original, type='OutcomeSnapshot'), dict(commit, type='DecisionCommit')],
        },
        'DecisionCommit': {
            'description': 'Immutable TLS decision.', 'fields': [], 'methods': [],
        },
        'TlsCommit': {
            'description': TlsCommit.__doc__, 'fields': [], 'methods': [],
        },
    }

    # Keep editor examples executable in the event for which each type exists.
    examples = {
        'OutcomeDraft': 'if api.tls is not None and api.tls.event is TlsEvent.ESTABLISHED:\n    outcome = api.tls.outcome\n    api.print(outcome.original().cipher)\n    return outcome.commit()',
        'TlsStartDraft': 'if api.tls is not None and api.tls.event is TlsEvent.START and api.tls.transport is TlsTransport.TLS:\n    start = api.tls.start\n    api.print(start.original().sni)\n    return start.commit()',
        'QuicStartDraft': 'if api.tls is not None and api.tls.event is TlsEvent.START and api.tls.transport is TlsTransport.QUIC:\n    start = api.tls.start\n    start.openssl_ciphersuites = "TLS_AES_128_GCM_SHA256"\n    return start.commit()',
    }
    # Each snapshot has its own field descriptors: marking them read-only
    # must not change the corresponding editable draft in editor help.
    for draft_name, snapshot_name in [('OutcomeDraft', 'OutcomeSnapshot'),
                                      ('TlsStartDraft', 'TlsStartSnapshot'),
                                      ('QuicStartDraft', 'QuicStartSnapshot')]:
        for name in (draft_name, snapshot_name):
            definition = definitions[name]
            for value in definition['fields'] + definition['methods']:
                value['example'] = examples[draft_name]
                if name == snapshot_name:
                    value['access'] = 'read-only snapshot'

    return definitions
