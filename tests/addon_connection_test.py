"""Connection data semantics; no live transport or fabricated endpoint data."""

from pathlib import Path
from copy import deepcopy
import json
import sys
import typing
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
import addon_connection as connection
from addon_connection_adversarial_contract import collect as collect_adversarial
from addon_proxy_mode_contract import collect as collect_proxy_modes


class ConnectionTests(unittest.TestCase):
    def test_client_exposes_the_immutable_default_proxy_mode(self):
        self.assertEqual(
            connection.Client.proxy_mode,
            connection.ProxyMode.parse("regular"),
        )
        first = connection.Client(peername=("client", 1), sockname=("proxy", 2))
        second = connection.Client(peername=("client", 3), sockname=("proxy", 4))
        self.assertIs(first.proxy_mode, second.proxy_mode)

    def test_public_type_aliases_match_reference_contract(self):
        self.assertEqual(typing.get_origin(connection.Address), tuple)
        self.assertEqual(typing.get_args(connection.Address), (str, int))
        self.assertEqual(typing.get_origin(connection.TransportProtocol), typing.Literal)
        self.assertEqual(typing.get_args(connection.TransportProtocol), ('tcp', 'udp'))
        self.assertEqual(typing.get_origin(connection.TlsVersion), typing.Literal)
        self.assertEqual(typing.get_args(connection.TlsVersion), (
            'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3',
            'DTLSv0.9', 'DTLSv1', 'DTLSv1.2', 'QUICv1',
        ))

    def test_reference_proxy_mode_contract(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_proxy_modes_v12.json').read_text())
        self.assertEqual(collect_proxy_modes(connection), corpus['cases'])

    def test_reference_adversarial_contract(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_connection_adversarial_v12.json').read_text()
        )
        self.assertEqual(corpus['reference'], 'mitmproxy 12.3.1')
        self.assertEqual(collect_adversarial(connection), corpus['cases'])

    def test_state_round_trip_preserves_identity_not_socket_readiness(self):
        descriptors = [
            connection.Server(address=("example.org", 443), alpn_offers=(b"h2",)),
            connection.Client(peername=("client", 123), sockname=("proxy", 443)),
        ]
        for original in descriptors:
            with self.subTest(kind=type(original).__name__):
                original.state = connection.ConnectionState.OPEN
                state = original.get_state()
                expected = deepcopy(state)
                restored = type(original).from_state(state)
                self.assertEqual(restored.get_state(), expected)
                self.assertEqual(restored.id, original.id)
                self.assertEqual(restored.state, connection.ConnectionState.CLOSED)
                self.assertIsInstance(restored.alpn_offers, list)
                restored.alpn_offers.append(b"other")
                self.assertIn(b"other", state["alpn_offers"])
                self.assertNotIn(b"other", original.alpn_offers)

    def test_restore_rejects_missing_extra_and_invalid_fields(self):
        original = connection.Server(address=("example.org", 443))
        state = original.get_state()
        missing = dict(state)
        del missing["id"]
        with self.assertRaises(KeyError):
            connection.Server.from_state(missing)
        with self.assertRaises(ValueError):
            connection.Server.from_state(dict(state, extra=True))
        with self.assertRaises(ValueError):
            connection.Server.from_state(dict(state, timestamp_start="invalid"))
        self.assertEqual(original.get_state(), state)

    def test_set_state_preserves_open_destination_guard(self):
        server = connection.Server(address=("example.org", 443))
        state = server.get_state()
        server.state = connection.ConnectionState.OPEN
        consumed = dict(state)
        server.set_state(consumed)
        self.assertEqual(consumed, {})
        self.assertEqual(server.state, connection.ConnectionState.OPEN)
        with self.assertRaises(RuntimeError):
            server.set_state(dict(state, address=("other.example", 443)))
        self.assertEqual(server.address, ("example.org", 443))

    def test_serialized_state_contains_values_but_not_socket_state(self):
        server = connection.Server(address=("example.org", 443), id="fixed",
                                   timestamp_start=1, alpn_offers=(b"h2",),
                                   cipher_list=("cipher",), via=("http", ("proxy", 80)))
        server.state = connection.ConnectionState.OPEN
        state = server.get_state()
        self.assertNotIn("state", state)
        self.assertEqual(state["id"], "fixed")
        self.assertEqual(state["address"], ("example.org", 443))
        self.assertEqual(state["timestamp_start"], 1.0)
        self.assertIsInstance(state["timestamp_start"], float)
        self.assertEqual(state["alpn_offers"], [b"h2"])
        self.assertEqual(state["cipher_list"], ["cipher"])
        self.assertEqual(state["via"], ("http", ("proxy", 80)))
        self.assertEqual(state["certificate_list"], [])
        state["alpn_offers"].append(b"http/1.1")
        self.assertEqual(server.alpn_offers, (b"h2",))
        client = connection.Client(peername=("client", 123), sockname=("proxy", 443),
                                   timestamp_start=2, id="client-id")
        self.assertEqual(client.get_state()["proxy_mode"], "regular")
        self.assertIsNone(client.get_state()["mitmcert"])

    def test_serialization_rejects_invalid_scalar_fields(self):
        for name, value in (("tls", 1), ("id", 1), ("timestamp_start", "12.3"),
                            ("address", ("example.org", "443")), ("alpn", "h2")):
            with self.subTest(name=name):
                server = connection.Server(address=None)
                setattr(server, name, value)
                with self.assertRaises(ValueError):
                    server.get_state()

    def test_client_default_mode_is_an_immutable_descriptor(self):
        client = connection.Client(peername=("192.0.2.1", 1234),
                                   sockname=("192.0.2.2", 8080))
        self.assertIsInstance(client.timestamp_start, float)
        mode = client.proxy_mode
        self.assertEqual(type(mode).__name__, "RegularMode")
        self.assertEqual(mode.get_state(), "regular")
        self.assertEqual(repr(mode), "ProxyMode.parse('regular')")
        self.assertEqual(mode.description, "HTTP(S) proxy")
        self.assertEqual(mode.transport_protocol, "tcp")
        self.assertEqual(mode.listen_host(), "")
        self.assertEqual(mode.listen_host("localhost"), "localhost")
        self.assertEqual(mode.listen_port(), 8080)
        self.assertEqual(mode.listen_port(0), 0)
        self.assertEqual(mode.copy(), mode)
        self.assertIs(mode.copy(), mode)
        with self.assertRaises(AttributeError):
            mode.data = "changed"
        with self.assertRaises(AttributeError):
            mode.set_state("regular@80")

    def test_client_legacy_fields_and_copy(self):
        client = connection.Client(peername=("192.0.2.1", 1234),
                                   sockname=("192.0.2.2", 8080), cipher="cipher")
        with self.assertWarns(DeprecationWarning):
            client.address = ("192.0.2.3", 4321)
        self.assertEqual(client.peername, ("192.0.2.3", 4321))
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(client.cipher_name, "cipher")
        with self.assertRaises(AttributeError):
            client.cipher_name = "other"
        certificate = object()
        with self.assertWarns(DeprecationWarning):
            client.clientcert = certificate
        self.assertEqual(client.certificate_list, [certificate])
        with self.assertWarns(DeprecationWarning):
            client.clientcert = None
        self.assertEqual(client.certificate_list, [])
        client.state = connection.ConnectionState.OPEN
        copied = client.copy()
        self.assertNotEqual(copied.id, client.id)
        self.assertEqual(copied.peername, client.peername)
        self.assertEqual(copied.state, connection.ConnectionState.CLOSED)

    def test_legacy_properties_reference_current_fields(self):
        server = connection.Server(address=("target.example", 443),
                                   peername=("192.0.2.1", 443), alpn=b"h2")
        with self.assertWarnsRegex(DeprecationWarning, "Connection.alpn"):
            self.assertEqual(server.alpn_proto_negotiated, b"h2")
        with self.assertWarnsRegex(DeprecationWarning, "Server.peername"):
            self.assertEqual(server.ip_address, ("192.0.2.1", 443))
        with self.assertRaises(AttributeError):
            server.ip_address = ("192.0.2.2", 443)
        with self.assertRaises(AttributeError):
            server.alpn_proto_negotiated = b"http/1.1"
        server.peername = ("192.0.2.3", 443)
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(server.ip_address, ("192.0.2.3", 443))

    def test_legacy_certificate_accessor_replaces_the_chain(self):
        server = connection.Server(address=None)
        with self.assertWarns(DeprecationWarning):
            self.assertIsNone(server.cert)
        first, second = object(), object()
        server.certificate_list = [first, second]
        with self.assertWarns(DeprecationWarning):
            self.assertIs(server.cert, first)
        with self.assertWarns(DeprecationWarning):
            server.cert = second
        self.assertEqual(server.certificate_list, [second])
        with self.assertWarns(DeprecationWarning):
            server.cert = None
        self.assertEqual(server.certificate_list, [])

    def test_state_and_tls_are_independent(self):
        server = connection.Server(address=("example.org", 443))
        for state in connection.ConnectionState.__members__.values():
            server.state = state
            for timestamp in (None, 0, 2):
                server.timestamp_tls_setup = timestamp
                self.assertEqual(server.connected, state == connection.ConnectionState.OPEN)
                self.assertEqual(server.tls_established, timestamp is not None)

    def test_open_destination_is_immutable_but_observations_can_change(self):
        server = connection.Server(address=("example.org", 443))
        server.state = connection.ConnectionState.OPEN
        server.address = server.address
        server.via = None
        with self.assertRaisesRegex(RuntimeError, "server.address"):
            server.address = ("other.example", 80)
        with self.assertRaisesRegex(RuntimeError, "server.via"):
            server.via = ("http", ("proxy.example", 8080))
        server.peername = ("192.0.2.1", 443)
        self.assertEqual(server.peername, ("192.0.2.1", 443))
        with self.assertRaisesRegex(RuntimeError, "server.address"):
            connection.Server(address=("example.org", 443), state=connection.ConnectionState.OPEN)

    def test_identity_equality_and_detached_copy(self):
        first = connection.Server(address=("example.org", 443), id="same")
        second = connection.Server(address=None, id="same")
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        first.state = connection.ConnectionState.OPEN
        first.alpn_offers = [b"h2"]
        copied = first.copy()
        self.assertNotEqual(first.id, copied.id)
        self.assertEqual(copied.state, connection.ConnectionState.CLOSED)
        copied.alpn_offers.append(b"http/1.1")
        self.assertEqual(first.alpn_offers, [b"h2"])
        self.assertEqual(copied.address, first.address)


if __name__ == "__main__":
    unittest.main()
