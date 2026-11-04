"""Clean-room public TLS values for the addon compatibility facade."""

from __future__ import annotations

from dataclasses import dataclass

import addon_connection as connection
from addon_hooks import Hook
from addon_proxy_context import Context


class EndOfStreamError(EOFError):
    """A bounded ClientHello field extends beyond the supplied message."""


class _Reader:
    def __init__(self, data):
        self.data = memoryview(data)
        self.offset = 0

    @property
    def remaining(self):
        return len(self.data) - self.offset

    def read(self, count):
        if self.remaining < count:
            raise EndOfStreamError(
                f"requested {count} bytes, but only {self.remaining} bytes available"
            )
        start = self.offset
        self.offset += count
        return bytes(self.data[start:self.offset])

    def uint8(self):
        return self.read(1)[0]

    def uint16(self):
        return int.from_bytes(self.read(2), "big")


class ClientHello:
    """Parse the public fields of one complete TLS or DTLS ClientHello body."""

    def __init__(self, raw_client_hello: bytes, dtls: bool = False):
        if not isinstance(raw_client_hello, bytes):
            raise TypeError("raw_client_hello must be bytes")

        self._raw_bytes = raw_client_hello
        self._dtls = dtls
        reader = _Reader(raw_client_hello)
        reader.read(2)
        # TLS random is historically represented as a four-byte timestamp and
        # 28 random bytes. Reading it in those public wire units also preserves
        # the reference truncation diagnostics.
        reader.read(4)
        reader.read(28)
        reader.read(reader.uint8())
        if dtls:
            reader.read(reader.uint8())

        cipher_data = reader.read(reader.uint16())
        self._cipher_suites = [
            int.from_bytes(cipher_data[offset:offset + 2], "big")
            for offset in range(0, len(cipher_data), 2)
        ]
        reader.read(reader.uint8())

        self._extensions = []
        if reader.remaining:
            extensions = _Reader(reader.read(reader.uint16()))
            while extensions.remaining:
                extension_type = extensions.uint16()
                payload = extensions.read(extensions.uint16())
                self._extensions.append((extension_type, payload))

    def raw_bytes(self, wrap_in_record: bool = True):
        if self._dtls:
            raise NotImplementedError

        if not wrap_in_record:
            return self._raw_bytes

        handshake = b"\x01" + len(self._raw_bytes).to_bytes(3, "big")
        handshake += self._raw_bytes
        return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake

    @property
    def cipher_suites(self):
        return self._cipher_suites.copy()

    @property
    def sni(self):
        for extension_type, payload in self._extensions:
            if extension_type != 0:
                continue
            names = _Reader(payload)
            names = _Reader(names.read(names.uint16()))
            while names.remaining:
                name_type = names.uint8()
                name = names.read(names.uint16())
                if name_type == 0:
                    return name.decode("idna")
            return None
        return None

    @property
    def alpn_protocols(self):
        for extension_type, payload in self._extensions:
            if extension_type != 16:
                continue
            protocols = _Reader(payload)
            protocols = _Reader(protocols.read(protocols.uint16()))
            result = []
            while protocols.remaining:
                result.append(protocols.read(protocols.uint8()))
            return result
        return []

    @property
    def extensions(self):
        return self._extensions.copy()

    def __repr__(self):
        return (
            f"ClientHello(sni: {self.sni}, "
            f"alpn_protocols: {self.alpn_protocols!r})"
        )


@dataclass
class ClientHelloData:
    """Event data for a TLS ClientHello callback."""

    context: Context
    client_hello: ClientHello
    ignore_connection: bool = False
    establish_server_tls_first: bool = False


@dataclass
class TlsData:
    """Event data for TLS start and handshake callbacks."""

    conn: connection.Connection
    context: Context
    ssl_conn: object | None = None
    is_dtls: bool = False


@dataclass(eq=False)
class TlsClienthelloHook(Hook):
    data: ClientHelloData
    name = "tls_clienthello"
    blocking = True


@dataclass(eq=False)
class TlsStartClientHook(Hook):
    data: TlsData
    name = "tls_start_client"
    blocking = True


@dataclass(eq=False)
class TlsStartServerHook(Hook):
    data: TlsData
    name = "tls_start_server"
    blocking = True


@dataclass(eq=False)
class TlsEstablishedClientHook(Hook):
    data: TlsData
    name = "tls_established_client"
    blocking = True


@dataclass(eq=False)
class TlsEstablishedServerHook(Hook):
    data: TlsData
    name = "tls_established_server"
    blocking = True


@dataclass(eq=False)
class TlsFailedClientHook(Hook):
    data: TlsData
    name = "tls_failed_client"
    blocking = True


@dataclass(eq=False)
class TlsFailedServerHook(Hook):
    data: TlsData
    name = "tls_failed_server"
    blocking = True


ClientHello.__module__ = "mitmproxy.tls"
ClientHelloData.__module__ = "mitmproxy.tls"
TlsData.__module__ = "mitmproxy.tls"

for _hook in (
    TlsClienthelloHook,
    TlsStartClientHook,
    TlsStartServerHook,
    TlsEstablishedClientHook,
    TlsEstablishedServerHook,
    TlsFailedClientHook,
    TlsFailedServerHook,
):
    _hook.__module__ = "mitmproxy.proxy.layers.tls"
