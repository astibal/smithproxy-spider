"""Certificate value tests using ephemeral test keys, not a live trust store."""

from datetime import datetime, timezone
from ipaddress import ip_address
import json
from pathlib import Path
import sys
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from addon_certs import Cert
from addon_connection import Client, Server
from addon_certs_contract import collect


def certificate(serial=123, subject=None, extensions=(), key=None):
    if key is None:
        key = ec.generate_private_key(ec.SECP256R1())
    name = subject if subject is not None else x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "example.test"),
    ])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(serial)
               .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
               .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc)))
    for extension in extensions:
        builder = builder.add_extension(extension, critical=False)
    algorithm = hashes.SHA256()
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        algorithm = None
    return builder.sign(key, algorithm)


class CertificateTests(unittest.TestCase):
    def test_key_information_for_supported_public_key_families(self):
        keys = [
            (rsa.generate_private_key(65537, 2048), ("RSA", 2048)),
            (dsa.generate_private_key(1024), ("DSA", 1024)),
            (ec.generate_private_key(ec.SECP384R1()), ("EC (secp384r1)", 384)),
            (ed25519.Ed25519PrivateKey.generate(), ("Ed25519", -1)),
            (ed448.Ed448PrivateKey.generate(), ("Ed448", -1)),
        ]
        for key, expected in keys:
            with self.subTest(kind=expected[0]):
                self.assertEqual(Cert(certificate(key=key)).keyinfo, expected)

    def test_connection_restore_decodes_chain_without_mutating_pem_list(self):
        cert = Cert(certificate())
        server = Server(address=("example.test", 443), certificate_list=[cert])
        state = server.get_state()
        pem_chain = state["certificate_list"]
        restored = Server.from_state(state)
        self.assertEqual(restored.certificate_list, [cert])
        self.assertIsNot(restored.certificate_list, pem_chain)
        self.assertEqual(pem_chain, [cert.to_pem()])
        self.assertIs(state["certificate_list"], restored.certificate_list)

    def test_client_restore_decodes_interception_certificate(self):
        cert = Cert(certificate())
        client = Client(peername=("client", 123), sockname=("proxy", 443), mitmcert=cert)
        expected = client.get_state()
        state = dict(expected)
        restored = Client.from_state(state)
        self.assertEqual(restored.mitmcert, cert)
        self.assertEqual(restored.get_state(), expected)
        self.assertIs(state["mitmcert"], restored.mitmcert)

    def test_invalid_chain_preserves_existing_chain_after_partial_update(self):
        cert = Cert(certificate())
        server = Server(address=None, certificate_list=[cert])
        state = server.get_state()
        state["id"] = "updated-before-certificate-error"
        state["certificate_list"] = [b"invalid certificate"]
        with self.assertRaises(ValueError):
            server.set_state(state)
        self.assertEqual(server.id, "updated-before-certificate-error")
        self.assertEqual(server.certificate_list, [cert])
        self.assertNotIn("certificate_list", state)
        self.assertIn("alpn", state)

    def test_missing_optional_extensions_have_empty_values(self):
        value = Cert(certificate(subject=x509.Name([])))
        self.assertIsNone(value.cn)
        self.assertIsNone(value.organization)
        self.assertEqual(value.subject, [])
        self.assertEqual(value.issuer, [])
        self.assertEqual(value.altnames, x509.GeneralNames([]))
        self.assertFalse(value.is_ca)
        self.assertEqual(value.crl_distribution_points, [])
        self.assertEqual(value.keyinfo, ("EC (secp256r1)", 256))

    def test_names_preserve_order_duplicates_and_unknown_oids(self):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "first.test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "second.test"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, "123"),
        ])
        value = Cert(certificate(subject=subject))
        self.assertEqual(value.cn, "first.test")
        self.assertEqual(value.organization, "Test Org")
        self.assertEqual(value.subject, [
            ("CN", "first.test"), ("O", "Test Org"),
            ("CN", "second.test"), ("2.5.4.5", "123"),
        ])
        self.assertEqual(value.issuer, value.subject)

    def test_san_ca_and_distribution_points(self):
        names = [x509.DNSName("example.test"), x509.IPAddress(ip_address("192.0.2.1"))]
        point = x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier("https://example.test/crl")],
            relative_name=None, reasons=None, crl_issuer=None,
        )
        value = Cert(certificate(extensions=[
            x509.SubjectAlternativeName(names),
            x509.BasicConstraints(ca=True, path_length=None),
            x509.CRLDistributionPoints([point]),
        ]))
        self.assertEqual(value.altnames, x509.GeneralNames(names))
        self.assertTrue(value.is_ca)
        self.assertEqual(value.crl_distribution_points, ["https://example.test/crl"])

    def test_public_state_is_pem_and_round_trips(self):
        original = certificate()
        value = Cert(original)
        self.assertTrue(value.get_state().startswith(b"-----BEGIN CERTIFICATE-----"))
        self.assertEqual(value.get_state(), value.to_pem())
        restored = Cert.from_state(value.get_state())
        self.assertEqual(restored, value)
        self.assertEqual(hash(restored), hash(value))
        self.assertEqual(value.fingerprint(), original.fingerprint(hashes.SHA256()))
        self.assertEqual(value.serial, 123)
        self.assertEqual(value.notbefore, datetime(2020, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(value.notafter, datetime(2030, 1, 1, tzinfo=timezone.utc))
        self.assertIs(value.to_cryptography(), original)

    def test_copy_and_set_state_do_not_mutate_the_original(self):
        value = Cert(certificate())
        copied = value.copy()
        self.assertEqual(copied, value)
        self.assertIsNot(copied, value)
        copied.set_state(Cert(certificate(456)).get_state())
        self.assertEqual(copied.serial, 456)
        self.assertEqual(value.serial, 123)
        before = value.get_state()
        with self.assertRaises(ValueError):
            value.set_state(b"not a certificate")
        self.assertEqual(value.get_state(), before)

    def test_legacy_pyopenssl_conversion_matches_public_contract(self):
        original = certificate()
        legacy = crypto.X509.from_cryptography(original)

        converted = Cert.from_pyopenssl(legacy)
        self.assertEqual(converted.to_cryptography(), original)

        with self.assertWarnsRegex(
            DeprecationWarning,
            "Use `to_cryptography` instead.",
        ):
            restored = converted.to_pyopenssl()
        self.assertIsInstance(restored, crypto.X509)
        self.assertEqual(restored.to_cryptography(), original)

        corpus = json.loads(
            (Path(__file__).parent / "corpus/addon_certs_v12.json").read_text()
        )
        self.assertEqual(
            collect(Cert, crypto),
            corpus["certificate_conversion"],
        )


if __name__ == "__main__":
    unittest.main()
