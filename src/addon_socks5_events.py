"""Dispatch one producer-owned SOCKS5 authentication decision."""

from dataclasses import dataclass

from addon_connection import Client
from addon_runtime import AddonRuntimeError
from addon_socks5 import Socks5AuthData
from addon_transport_envelope import bounded_text, exact_object


class Socks5TransportError(AddonRuntimeError):
    """The producer event cannot preserve SOCKS5 auth semantics."""


@dataclass(frozen=True)
class Socks5AuthObservation:
    username: str
    password: str
    valid: bool

    @classmethod
    def parse(cls, value):
        envelope = exact_object(
            Socks5TransportError,
            'socks5_auth',
            value,
            ('version', 'event', 'username', 'password', 'valid'),
        )
        if type(envelope['version']) is not int or envelope['version'] != 1:
            raise Socks5TransportError('socks5_auth.version must be 1')
        if envelope['event'] != 'authenticate':
            raise Socks5TransportError(
                'socks5_auth.event must be authenticate')
        username = bounded_text(
            Socks5TransportError,
            'socks5_auth.username',
            envelope['username'],
            1020,
        )
        password = bounded_text(
            Socks5TransportError,
            'socks5_auth.password',
            envelope['password'],
            1020,
        )
        valid = envelope['valid']
        if type(valid) is not bool:
            raise Socks5TransportError(
                'socks5_auth.valid must be a boolean')
        return cls(username, password, valid)


@dataclass(frozen=True)
class Socks5AuthDecision:
    valid: bool


class Socks5AddonEvents:
    """Run the auth override without retaining credential material."""

    HOOKS = frozenset({'socks5_auth'})

    def __init__(self, generation):
        self.generation = generation

    async def authenticate(self, client, value):
        if not isinstance(client, Client):
            raise Socks5TransportError(
                'SOCKS5 authentication requires the native Client descriptor')
        observation = Socks5AuthObservation.parse(value)
        data = Socks5AuthData(
            client,
            observation.username,
            observation.password,
            observation.valid,
        )
        failures = await self.generation.dispatch('socks5_auth', data)
        if type(data.valid) is not bool:
            raise Socks5TransportError(
                'SOCKS5 addon decision must remain a boolean')
        return Socks5AuthDecision(data.valid), tuple(failures)
