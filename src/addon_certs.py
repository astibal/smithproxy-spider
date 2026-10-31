"""Public certificate values backed by cryptography, never private keys.

This module does not issue certificates, install trust or perform handshakes.
It is the serialization building block for addon connection descriptors.
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
import warnings

from addon_serializable import Serializable


class Cert(Serializable):
    def __init__(self, cert):
        self._cert = cert

    @classmethod
    def from_pem(cls, data):
        return cls(x509.load_pem_x509_certificate(data))

    @classmethod
    def from_pyopenssl(cls, cert):
        """Convert a public PyOpenSSL certificate without retaining its wrapper."""
        return cls(cert.to_cryptography())

    @classmethod
    def from_state(cls, state):
        return cls.from_pem(state)

    def to_pem(self):
        return self._cert.public_bytes(serialization.Encoding.PEM)

    def get_state(self):
        return self.to_pem()

    def set_state(self, state):
        parsed = x509.load_pem_x509_certificate(state)
        self._cert = parsed

    def to_cryptography(self):
        return self._cert

    def to_pyopenssl(self):
        """Return the legacy PyOpenSSL view retained by the public addon API."""
        warnings.warn(
            "Use `to_cryptography` instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        from OpenSSL import crypto

        return crypto.X509.from_cryptography(self._cert)

    def public_key(self):
        return self._cert.public_key()

    @staticmethod
    def _name_fields(name):
        aliases = {NameOID.COMMON_NAME: "CN", NameOID.ORGANIZATION_NAME: "O",
                   NameOID.ORGANIZATIONAL_UNIT_NAME: "OU", NameOID.COUNTRY_NAME: "C",
                   NameOID.LOCALITY_NAME: "L", NameOID.STATE_OR_PROVINCE_NAME: "ST",
                   NameOID.DOMAIN_COMPONENT: "DC", NameOID.USER_ID: "UID",
                   NameOID.STREET_ADDRESS: "STREET"}
        return [(aliases.get(item.oid, item.oid.dotted_string), item.value) for item in name]

    def _subject_value(self, oid):
        values = self._cert.subject.get_attributes_for_oid(oid)
        return values[0].value if values else None

    @property
    def subject(self):
        return self._name_fields(self._cert.subject)

    @property
    def issuer(self):
        return self._name_fields(self._cert.issuer)

    @property
    def cn(self):
        return self._subject_value(NameOID.COMMON_NAME)

    @property
    def organization(self):
        return self._subject_value(NameOID.ORGANIZATION_NAME)

    @property
    def altnames(self):
        try:
            extension = self._cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            return x509.GeneralNames([])
        return x509.GeneralNames(extension.value)

    @property
    def is_ca(self):
        try:
            extension = self._cert.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            return False
        return extension.value.ca

    @property
    def crl_distribution_points(self):
        try:
            extension = self._cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        except x509.ExtensionNotFound:
            return []
        locations = []
        for point in extension.value:
            for name in point.full_name or ():
                if isinstance(name, x509.UniformResourceIdentifier):
                    locations.append(name.value)
        return locations

    @property
    def keyinfo(self):
        key = self.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return "RSA", key.key_size
        if isinstance(key, dsa.DSAPublicKey):
            return "DSA", key.key_size
        if isinstance(key, ec.EllipticCurvePublicKey):
            return f"EC ({key.curve.name})", key.key_size
        if isinstance(key, ed25519.Ed25519PublicKey):
            return "Ed25519", -1
        if isinstance(key, ed448.Ed448PublicKey):
            return "Ed448", -1
        raise NotImplementedError("Certificate public-key type is not supported yet")

    def fingerprint(self):
        return self._cert.fingerprint(hashes.SHA256())

    @property
    def serial(self):
        return self._cert.serial_number

    @property
    def notbefore(self):
        return self._cert.not_valid_before_utc

    @property
    def notafter(self):
        return self._cert.not_valid_after_utc

    def has_expired(self):
        return datetime.now(timezone.utc) > self.notafter

    def copy(self):
        return type(self).from_state(self.get_state())

    def __eq__(self, other):
        if not isinstance(other, Cert):
            return NotImplemented
        return self._cert == other._cert

    def __hash__(self):
        return hash(self._cert)
