"""Strict common validation for native transport envelopes."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_transport_envelope import (
    bounded_text,
    exact_object,
    network_address,
)


class EnvelopeError(ValueError):
    pass


class TransportEnvelopeTests(unittest.TestCase):
    def test_exact_object_accepts_only_the_declared_shape(self):
        value = {'one': 1, 'two': 2}
        self.assertIs(
            exact_object(EnvelopeError, 'value', value, ('one', 'two')),
            value,
        )
        for candidate, pattern in (([], 'object'), ({'one': 1}, 'unknown')):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(EnvelopeError, pattern):
                    exact_object(
                        EnvelopeError, 'value', candidate, ('one', 'two'))

    def test_bounded_text_handles_nullable_type_size_and_controls(self):
        self.assertIsNone(bounded_text(
            EnvelopeError, 'value', None, 10, nullable=True))
        self.assertEqual(
            bounded_text(EnvelopeError, 'value', 'text', 4), 'text')
        for value, nullable, pattern in (
            (None, False, 'bounded text'),
            (7, True, 'or null'),
            ('long', False, 'bounded text'),
            ('bad\ntext', False, 'bounded text'),
        ):
            with self.subTest(value=value):
                maximum = 3 if value == 'long' else 32
                with self.assertRaisesRegex(EnvelopeError, pattern):
                    bounded_text(
                        EnvelopeError, 'value', value, maximum,
                        nullable=nullable,
                    )

    def test_network_address_preserves_unknown_and_rejects_ambiguity(self):
        self.assertIsNone(network_address(
            EnvelopeError, 'address', None))
        self.assertEqual(
            network_address(
                EnvelopeError, 'address', ['192.0.2.1', 443]),
            ('192.0.2.1', 443),
        )
        for value, pattern in (
            (['host-only'], 'null or'),
            (['', 443], 'bounded text'),
            (['host', True], 'integer'),
            (['host', 65536], 'integer'),
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(EnvelopeError, pattern):
                    network_address(EnvelopeError, 'address', value)


if __name__ == '__main__':
    unittest.main()
