"""Owned handshake observations and explicit termination decisions."""

import base64
from dataclasses import dataclass

from inspection_tls import TlsDecision, TlsEvent


def optional_text(observation, name, limit):
    value = observation.get(name)
    if value is not None and (not isinstance(value, str) or len(value) > limit):
        raise ValueError('Invalid TLS metadata: ' + name)
    return value


@dataclass(frozen=True)
class OutcomeSnapshot:
    """Handshake facts. Certificates contain public PEM bytes, never keys."""

    sni: str | None
    alpn: bytes | None
    cipher: str | None
    tls_version: str | None
    error: str | None
    certificates: tuple[bytes, ...]

    @classmethod
    def from_observation(cls, observation, event):
        sni = optional_text(observation, 'sni', 255)
        cipher = optional_text(observation, 'cipher', 256)
        version = optional_text(observation, 'tls_version', 32)
        error = optional_text(observation, 'error', 1024)
        encoded = optional_text(observation, 'alpn_base64', 344)
        alpn = None if encoded is None else base64.b64decode(encoded, validate=True)
        if alpn is not None and len(alpn) > 255:
            raise ValueError('Invalid negotiated ALPN')
        if event is TlsEvent.FAILED and not error:
            raise ValueError('TLS failure requires an error')

        values = observation.get('certificates', [])
        if (not isinstance(values, list) or len(values) > 64
                or any(not isinstance(value, str) or len(value) > 65536 for value in values)):
            raise ValueError('Invalid peer certificate chain')

        certificates = tuple(value.encode('ascii') for value in values)
        for certificate in certificates:
            # The native view carries public PEM bytes, not an X509 runtime
            # object. Validate framing/encoding without loading a crypto engine
            # into every native worker; adapters parse their own Cert facade.
            begin = b'-----BEGIN CERTIFICATE-----'
            end = b'-----END CERTIFICATE-----'
            stripped = certificate.strip()
            if not stripped.startswith(begin) or not stripped.endswith(end):
                raise ValueError('Invalid peer certificate PEM')
            payload = b''.join(stripped[len(begin):-len(end)].split())
            if not payload or not base64.b64decode(payload, validate=True):
                raise ValueError('Empty peer certificate')

        return cls(sni, alpn, cipher, version, error, certificates)


@dataclass(frozen=True)
class DecisionCommit:
    decision: TlsDecision

    def legacy_reply(self):
        return {'proceed': self.decision is TlsDecision.CONTINUE}


class OutcomeDraft:
    """Read-only facts with a commit-able decision on an established transport."""

    def __init__(self, observation, event):
        self._original = OutcomeSnapshot.from_observation(observation, event)
        self._event = event
        self._result = None
        self.decision = TlsDecision.CONTINUE

    def original(self):
        return self._original

    @property
    def sni(self):
        return self._original.sni

    @property
    def alpn(self):
        return self._original.alpn

    @property
    def cipher(self):
        return self._original.cipher

    @property
    def tls_version(self):
        return self._original.tls_version

    @property
    def error(self):
        return self._original.error

    @property
    def certificates(self):
        return self._original.certificates

    def commit(self):
        allowed = (TlsDecision.CONTINUE, TlsDecision.TERMINATE)
        if self.decision not in allowed or not isinstance(self.decision, TlsDecision):
            raise ValueError('TLS outcomes cannot bypass the transport')
        if self._event is TlsEvent.FAILED and self.decision is not TlsDecision.CONTINUE:
            raise ValueError('A failed handshake is an observation, not a new decision point')

        self._result = DecisionCommit(self.decision)
        return self._result

    def publish(self, result):
        if result is None:
            return {'proceed': True}
        if not isinstance(result, DecisionCommit) or result is not self._result:
            raise ValueError('Return this TLS outcome commit result')
        return result.legacy_reply()
