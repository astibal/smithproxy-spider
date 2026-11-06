"""QUIC parent handshake meta editing, separate from HTTP/3 stream content."""

from dataclasses import dataclass

from inspection_tls import TlsDecision


@dataclass(frozen=True)
class QuicStartSnapshot:
    sni: str
    alpn_offers: tuple[bytes, ...]
    openssl_ciphersuites: str | None


@dataclass(frozen=True)
class QuicStartCommit:
    decision: TlsDecision
    sni: str
    alpn_offers: tuple[bytes, ...]
    openssl_ciphersuites: str | None

    def legacy_reply(self):
        if self.decision is TlsDecision.TERMINATE:
            return {'proceed': False}
        return {'proceed': True, 'upstream': {
            'sni': self.sni, 'alpn': self.alpn_offers[0].decode('ascii'),
            'ciphers': self.openssl_ciphersuites,
        }}


class QuicStartDraft:
    """Native QUIC offer. Certificate ownership and trust policy stay native."""

    def __init__(self, observation):
        offer = observation.get('upstream')
        if not isinstance(offer, dict) or not isinstance(offer.get('alpn'), str):
            raise ValueError('Invalid native QUIC offer')

        self.sni = offer.get('sni')
        self.alpn_offers = [offer['alpn'].encode('ascii')]
        self.openssl_ciphersuites = offer.get('ciphers')
        self.decision = TlsDecision.CONTINUE
        self._result = None
        validated = self.commit()
        self._original = QuicStartSnapshot(
            validated.sni, validated.alpn_offers, validated.openssl_ciphersuites,
        )
        self._result = None

    def original(self):
        return self._original

    def commit(self):
        if self.decision not in (TlsDecision.CONTINUE, TlsDecision.TERMINATE):
            raise ValueError('QUIC start accepts CONTINUE or TERMINATE')
        if not isinstance(self.sni, str) or '\0' in self.sni:
            raise ValueError('Invalid QUIC SNI')
        sni = self.sni.encode('idna').decode('ascii') if self.sni else ''
        if len(sni) > 255:
            raise ValueError('Invalid QUIC SNI')

        protocols = self.alpn_offers
        if (not isinstance(protocols, (list, tuple)) or len(protocols) != 1
                or not isinstance(protocols[0], bytes) or not 1 <= len(protocols[0]) <= 255):
            raise ValueError('Native QUIC requires one ALPN protocol')
        protocols[0].decode('ascii')

        expression = self.openssl_ciphersuites
        if expression is not None and (
            not isinstance(expression, str) or '\0' in expression or len(expression.encode()) > 4096
        ):
            raise ValueError('Invalid QUIC cipher expression')

        self._result = QuicStartCommit(self.decision, sni, tuple(protocols), expression)
        return self._result

    def publish(self, result):
        if result is None:
            original = self._original
            result = QuicStartCommit(TlsDecision.CONTINUE, original.sni,
                                     original.alpn_offers, original.openssl_ciphersuites)
        elif not isinstance(result, QuicStartCommit) or result is not self._result:
            raise ValueError('Return this QUIC start commit result')
        return result.legacy_reply()
