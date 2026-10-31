"""Certificate conversion observations shared by reference and adapter tests."""

from datetime import datetime, timezone
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def collect(cert_type, crypto):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "conversion.test"),
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(73)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    legacy = crypto.X509.from_cryptography(certificate)
    value = cert_type.from_pyopenssl(legacy)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        restored = value.to_pyopenssl()

    return {
        "public_surface": sorted(
            name for name in dir(cert_type) if not name.startswith("_")
        ),
        "from_serial": value.serial,
        "from_matches_cryptography": value.to_cryptography() == certificate,
        "to_type": [type(restored).__module__, type(restored).__name__],
        "to_matches_cryptography": restored.to_cryptography() == certificate,
        "warnings": [
            {
                "category": warning.category.__name__,
                "message": str(warning.message),
            }
            for warning in caught
        ],
    }
