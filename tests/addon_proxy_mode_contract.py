"""Public proxy-mode data-model observations shared with the reference probe."""


SPECS = (
    'regular', 'regular@127.0.0.1:8081', 'regular@8081', 'regular:foo',
    'transparent', 'transparent@0.0.0.0:9000', 'socks5', 'socks5@1081',
    'reverse:http://example.com', 'reverse:https://example.com',
    'reverse:tcp://example.com:123', 'reverse:udp://example.com:123',
    'reverse:dns://example.com:53', 'reverse:http3://example.com:443',
    'reverse:https://example.com@127.0.0.1:8443',
    'upstream:http://proxy.test:3128', 'upstream:https://proxy.test:8443',
    'upstream:https://u:p@proxy.test:8443',
    'wireguard', 'wireguard:config.conf', 'wireguard@51820',
    'local', 'local:curl', 'local:!curl', 'tun', 'tun:utun5',
    'dns', 'dns@5353', 'osproxy', 'osproxy:foo', 'bogus', '',
    'regular@host:notaport', 'regular@[::1]:8080',
)


def collect(mode_specs):
    cases = {}
    for spec in SPECS:
        try:
            mode = mode_specs.ProxyMode.parse(spec)
            cases[spec] = {
                'class': type(mode).__name__, 'full_spec': mode.full_spec,
                'data': mode.data, 'custom_host': mode.custom_listen_host,
                'custom_port': mode.custom_listen_port, 'type_name': mode.type_name,
                'description': mode.description, 'transport': mode.transport_protocol,
                'default_port': mode.default_port,
                'listen_host/default': mode.listen_host(),
                'listen_host/custom': mode.listen_host('fallback'),
                'listen_port/default': mode.listen_port(),
                'listen_port/custom': mode.listen_port(9999),
                'state': mode.get_state(), 'repr': repr(mode),
                'copy_identity': mode.copy() is mode,
                'parse_identity': mode_specs.ProxyMode.parse(spec) is mode,
                'restore_identity': mode_specs.ProxyMode.from_state(mode.get_state()) is mode,
            }
            try:
                mode.set_state(spec)
            except Exception as error:
                cases[spec]['set_state'] = {
                    'error': type(error).__name__, 'message': str(error),
                }
        except Exception as error:
            cases[spec] = {'error': type(error).__name__, 'message': str(error)}
    return cases
