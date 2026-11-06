"""TCP TLS start settings; no live SSL object or handshake scheduling."""

from dataclasses import dataclass

from inspection_tls import TlsCommit, TlsDecision, TlsSide, decode_offer, validate_offer
from inspection_tls_outcome import optional_text


@dataclass(frozen=True)
class TlsStartSnapshot:
    sni: str | None
    alpn_offers: tuple[bytes, ...]
    openssl_cipher_list: str | None


class TlsStartDraft:
    """Effective upstream offer, or a client-facing observation and decision."""

    def __init__(self, observation, side):
        self._editable = side is TlsSide.SERVER
        self.sni = optional_text(observation, 'sni', 255) or ''
        self.alpn_offers = []
        self.openssl_cipher_list = None
        if self._editable:
            settings = observation.get('upstream')
            self.sni, offers = decode_offer(settings)
            self.alpn_offers = list(offers)
            self.openssl_cipher_list = settings.get('openssl_cipher_list')

        self._initial = (self.sni, tuple(self.alpn_offers), self.openssl_cipher_list)
        self._original = TlsStartSnapshot(*self._initial)
        self.decision = TlsDecision.CONTINUE
        self._result = None
        self.commit()
        self._result = None

    def original(self):
        return self._original

    def commit(self):
        if self.decision not in (TlsDecision.CONTINUE, TlsDecision.TERMINATE):
            raise ValueError('TLS start accepts CONTINUE or TERMINATE')

        sni, offers, expression = validate_offer(
            self.sni, self.alpn_offers, self.openssl_cipher_list, self._initial,
            editable=self._editable, cipher_editable=self._editable,
        )
        self._result = TlsCommit(self.decision, sni, offers, expression)
        return self._result

    def publish(self, result):
        if result is None:
            result = TlsCommit(TlsDecision.CONTINUE, *self._initial)
        elif not isinstance(result, TlsCommit) or result is not self._result:
            raise ValueError('Return this TLS start commit result')

        reply = result.legacy_reply(self._editable)
        reply.pop('ignore_connection')
        return reply
