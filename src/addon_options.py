"""Spider-owned addon option values and registration.

``OptManager`` implements the generic public registry. ``Options`` adds the
standard v12 proxy option inventory so addons can inspect familiar settings.
These values describe compatibility defaults; they do not create listeners or
change Spider transport behavior.
"""

from collections.abc import Sequence
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import logging
from typing import get_args, get_origin

from addon_exceptions import MitmproxyException
from addon_signals import SyncSignal, make_weak_ref
from addon_typecheck import check_option_type


class OptionsError(MitmproxyException):
    """An addon rejected an otherwise well-typed configuration change."""


@dataclass
class _UnconvertedStrings:
    """Text option values retained until their declaration is available."""

    val: list[str]


@dataclass
class _Option:
    name: str
    typespec: object
    default: object
    help: str
    choices: object = None

    def __post_init__(self):
        check_option_type(self.name, self.default, self.typespec)
        self.default = deepcopy(self.default)
        self.choices = deepcopy(self.choices)
        self._value = deepcopy(self.default)

    def current(self):
        return deepcopy(self._value)

    def set(self, value):
        check_option_type(self.name, value, self.typespec)
        self._value = deepcopy(value)

    def reset(self):
        self._value = deepcopy(self.default)

    def has_changed(self):
        return self._value != self.default


class OptManager:
    def __init__(self):
        self._options = {}
        object.__setattr__(self, 'deferred', {})
        self._subscriptions = []
        object.__setattr__(self, 'changed', SyncSignal(lambda updated: None))
        object.__setattr__(self, 'errored', SyncSignal(lambda exc: None))
        self.changed.connect(self._notify_subscribers)

    def subscribe(self, func, opts):
        names = set(opts)
        for name in names:
            if name not in self._options:
                raise OptionsError('No such option: ' + name)
        self._subscriptions.append((make_weak_ref(func), names))

    def make_parser(self, parser, optname, metavar=None, short=None):
        """Add one declared option to an ``argparse``-compatible parser."""
        if optname not in self._options:
            return

        option = self._options[optname]
        long_name = '--' + optname.replace('_', '-')
        if option.typespec is bool:
            parser.add_argument(
                '--no-' + optname.replace('_', '-'),
                action='store_false',
                dest=optname,
                default=None,
            )
            parser.add_argument(
                long_name,
                action='store_true',
                dest=optname,
                default=None,
                help=option.help,
            )
            return

        optional = set(get_args(option.typespec))
        value_type = option.typespec
        if optional == {int, type(None)}:
            value_type = int
        elif optional == {str, type(None)}:
            value_type = str

        arguments = [long_name]
        if short is not None:
            arguments.append('-' + short)
        settings = {
            'dest': optname,
            'default': None,
            'help': option.help,
            'metavar': metavar,
        }
        is_sequence = get_origin(option.typespec) is Sequence
        if is_sequence:
            item_types = get_args(option.typespec)
            if item_types != (str,):
                raise ValueError('Unsupported option type: ' + str(option.typespec))
            settings['type'] = item_types[0]
            settings['action'] = 'append'
            settings['help'] += ' May be passed multiple times.'
        else:
            if value_type not in (int, str):
                raise ValueError('Unsupported option type: ' + str(option.typespec))
            settings['type'] = value_type
        parser.add_argument(*arguments, **settings)

    def _notify_subscribers(self, updated):
        for reference, names in tuple(self._subscriptions):
            receiver = reference()
            if receiver is not None and names.intersection(updated):
                receiver(self, updated)

    @contextmanager
    def rollback(self, updated, reraise=False):
        previous = deepcopy(self._options)
        try:
            yield
        except OptionsError as error:
            # Observers see the rejected values first, then the restored state.
            # Only deliberate configuration rejection rolls back: programming
            # errors and type errors retain the reference API's partial writes.
            self.errored.send(exc=error)
            self._options = previous
            self.changed.send(updated=updated)
            if reraise:
                raise

    def __getattr__(self, name):
        options = self.__dict__.get('_options', {})
        if name not in options:
            raise AttributeError('No such option: ' + name)
        return options[name].current()

    def __setattr__(self, name, value):
        if name.startswith('_'):
            object.__setattr__(self, name, value)
        else:
            self.update(**{name: value})

    def __contains__(self, name):
        return name in self._options

    def keys(self):
        return set(self._options)

    def items(self):
        return self._options.items()

    def add_option(self, name, typespec, default, help, choices=None):
        option = _Option(name, typespec, default, help, choices)
        self._options[name] = option
        self.changed.send(updated={name})

    def default(self, name):
        return deepcopy(self._options[name].default)

    def has_changed(self, name):
        return self._options[name].has_changed()

    def setter(self, attr):
        if attr not in self._options:
            raise KeyError('No such option: ' + attr)

        def assign(value):
            self.update(**{attr: value})

        return assign

    def toggler(self, attr):
        if attr not in self._options:
            raise KeyError('No such option: ' + attr)
        if self._options[attr].typespec is not bool:
            raise ValueError('Toggler can only be used with boolean options')

        def toggle():
            self.update(**{attr: not getattr(self, attr)})

        return toggle

    def merge(self, opts):
        # Prepare concatenations before publishing any changes. Keep the
        # caller's sequence type: a mismatched list/tuple is an API error,
        # not an instruction to silently normalize the option's value.
        values = {}
        for name, value in opts.items():
            if value is None:
                continue
            if isinstance(value, (list, tuple)):
                value = getattr(self, name) + value
            values[name] = value
        self.update(**values)

    def update_known(self, **values):
        # The public option API applies known values in order. A later type
        # error does not roll back earlier changes; the contract tests preserve
        # this distinction from a deployment-level configuration transaction.
        unknown = {}
        updated = set(values).intersection(self._options)
        with self.rollback(updated, reraise=True):
            for name, value in values.items():
                if name in self._options:
                    self._options[name].set(value)
                else:
                    unknown[name] = value
            if updated:
                self.changed.send(updated=updated)
        return unknown

    def _parse_string(self, name, value):
        option = self._options[name]
        typespec = option.typespec
        optional = set(get_args(typespec))
        if typespec is bool:
            if value in (None, '', 'true'):
                return True
            if value == 'false':
                return False
            if value == 'toggle':
                return not option.current()
            raise OptionsError('Invalid boolean value for ' + name)
        if typespec is str or optional == {str, type(None)}:
            if value is None and typespec is str:
                raise OptionsError('Missing string value for ' + name)
            return value
        if typespec is int or optional == {int, type(None)}:
            if optional and value in (None, ''):
                return None
            try:
                return int(value)
            except (TypeError, ValueError):
                raise OptionsError('Invalid integer value for ' + name) from None
        raise NotImplementedError('String configuration is unavailable for ' + name)

    def set(self, *specs, defer=False):
        # Parse the complete batch before notifying observers. Unlike update,
        # text configuration must not expose a partially parsed set of values.
        grouped = {}
        for spec in specs:
            name, separator, value = spec.partition('=')
            if name not in self._options and not defer:
                raise OptionsError('Unknown option: ' + name)
            grouped.setdefault(name, []).append(value if separator else None)
        known = {name: entries for name, entries in grouped.items() if name in self._options}
        values = self._parse_strings(known)
        # Unknown names are retained only after parsing succeeds, but before
        # configure runs. Rejecting a known value does not discard pending
        # values for addons that have not registered their options yet.
        for name, entries in grouped.items():
            if name not in self._options:
                self.deferred[name] = _UnconvertedStrings([
                    entry for entry in entries if entry is not None
                ])
        self.update(**values)

    def _parse_strings(self, grouped):
        values = {}
        for name, entries in grouped.items():
            if len(entries) != 1:
                raise OptionsError('Option specified multiple times: ' + name)
            values[name] = self._parse_string(name, entries[0])
        return values

    def process_deferred(self):
        ready = {name: value for name, value in self.deferred.items()
                 if name in self._options}
        values = {}
        for name, value in ready.items():
            if isinstance(value, _UnconvertedStrings):
                entries = value.val if value.val else [None]
                values.update(self._parse_strings({name: entries}))
            else:
                values[name] = value
        self.update(**values)
        # Retain the entire ready batch on parsing or configure failure. A
        # later explicit retry must observe the same pending specifications.
        for name in ready:
            del self.deferred[name]

    def update_defer(self, **values):
        """Update declared options and retain unknown typed values for later."""
        unknown = self.update_known(**values)
        self.deferred.update(unknown)

    def update(self, **values):
        unknown = self.update_known(**values)
        if unknown:
            raise KeyError('Unknown options: ' + ', '.join(unknown))

    def reset(self):
        for option in self._options.values():
            option.reset()
        self.changed.send(updated=self.keys())


class Options(OptManager):
    """Standard mitmproxy v12 option inventory exposed to addon scripts."""

    def __init__(self, **values):
        super().__init__()
        definitions = (
            ("server", bool, True, "Enable the proxy service."),
            ("showhost", bool, False, "Prefer Host when displaying URLs."),
            ("show_ignored_hosts", bool, False, "Display ignored traffic."),
            ("add_upstream_certs_to_client_chain", bool, False,
             "Include upstream certificates in the client chain."),
            ("confdir", str, "~/.mitmproxy", "Configuration directory."),
            ("certs", Sequence[str], [], "Additional TLS certificates."),
            ("cert_passphrase", str | None, None,
             "Passphrase for an additional certificate."),
            ("client_certs", str | None, None,
             "Client certificate file or directory."),
            ("ignore_hosts", Sequence[str], [], "Hosts forwarded without inspection."),
            ("allow_hosts", Sequence[str], [], "Hosts allowed for inspection."),
            ("tcp_hosts", Sequence[str], [], "Hosts handled as generic TCP."),
            ("udp_hosts", Sequence[str], [], "Hosts handled as generic UDP."),
            ("tcp_timeout", int, 600, "Inactive TCP timeout in seconds."),
            ("upstream_cert", bool, True, "Inspect upstream certificates."),
            ("http2", bool, True, "Enable HTTP/2 support."),
            ("http2_ping_keepalive", int, 58, "HTTP/2 idle PING interval."),
            ("http3", bool, True, "Enable HTTP/3 support."),
            ("websocket", bool, True, "Enable WebSocket support."),
            ("rawtcp", bool, True, "Enable generic TCP connections."),
            ("ssl_insecure", bool, False, "Disable upstream TLS verification."),
            ("ssl_verify_upstream_trusted_ca", str | None, None,
             "Trusted upstream CA file."),
            ("ssl_verify_upstream_trusted_confdir", str | None, None,
             "Trusted upstream CA directory."),
            ("http_connect_send_host_header", bool, True,
             "Send Host on upstream CONNECT requests."),
            ("content_view_lines_cutoff", int, 512,
             "Maximum number of rendered content lines."),
            ("protobuf_definitions", str | None, None,
             "Protocol Buffer schema path."),
            ("key_size", int, 2048, "Generated TLS key size."),
            ("listen_host", str, "", "Default listener address."),
            ("listen_port", int | None, None, "Default listener port."),
            ("mode", Sequence[str], ["regular"], "Configured proxy modes."),
        )
        for name, typespec, default, help_text in definitions:
            self.add_option(name, typespec, default, help_text)
        if values:
            self.update(**values)


class Loader:
    def __init__(self, options, commands=None):
        self.options = options
        self.commands = commands

    def add_command(self, path, func):
        if self.commands is None:
            from addon_commands import CommandError
            raise CommandError('No command registry is available for this loader')
        self.commands.add(path, func)

    def add_option(self, name, typespec, default, help, choices=None):
        if name in self.options:
            previous = dict(self.options.items())[name]
            if (previous.typespec == typespec and previous.default == default and
                    previous.help == help and previous.choices == choices):
                return
            logging.warning('Over-riding existing option %s', name)
        self.options.add_option(name, typespec, default, help, choices)
