"""Public flow-filter observations shared with the isolated reference probe."""


PATTERNS = (
    '~all', '~http', '~tcp', '~udp', '~dns', '~websocket', '~q', '~s',
    '~e', '~marked', '~marker warning', '~comment useful', '~meta fixture',
    '~replay', '~replayq', '~replays', '~m get', '~d example\\.org',
    '~u path\\?q=1', '~c 201', '~h x-test: one', '~h "x-test: one"', '~hq x-test',
    '~hs x-response', '~b hello', '~bq request', '~bs response',
    '~t text/html', '~tq application/json', '~ts text/html', '~a',
    '~src 10\\.0\\.0\\.5', '~dst example\\.org:443',
    '~q ~m GET', '~q & ~m GET', '~q | ~tcp', '!(~q & ~t "text/html")',
    'example\\.org', 'example\\.org path',
)


INVALID = ('', ' ', '~bogus', '(', '~c x', '~u', '~q |', '()', '~u [')


def collect(flowfilter, http, flow_module, tcp, udp, make_connections):
    def http_flow(*, response=True, websocket=False, error=False):
        client, server = make_connections('tcp')
        item = http.HTTPFlow(client, server, live=True)
        item.request = http.Request.make(
            'GET',
            'https://example.org/path?q=1',
            b'Hello Request',
            {'content-type': 'application/json', 'x-test': 'One'},
        )
        if response:
            item.response = http.Response.make(
                201,
                b'Hello Response',
                {'content-type': 'text/html', 'x-response': 'Two'},
            )
        if websocket:
            item.websocket = object()
        if error:
            item.error = flow_module.Error('upstream failed', 123)
        item.marked = ':warning:'
        item.comment = 'useful fixture'
        item.metadata = {'source': 'fixture', 'count': 2}
        item.is_replay = 'request'
        return item

    pending = http_flow(response=False)
    completed = http_flow()
    failed = http_flow(error=True)
    websocket = http_flow(websocket=True)
    asset = http_flow()
    asset.response.headers['content-type'] = 'image/png'
    client, server = make_connections('tcp')
    tcp_flow = tcp.TCPFlow(client, server, live=True)
    client, server = make_connections('udp')
    udp_flow = udp.UDPFlow(client, server, live=True)
    flows = {
        'pending': pending,
        'completed': completed,
        'failed': failed,
        'websocket': websocket,
        'asset': asset,
        'tcp': tcp_flow,
        'udp': udp_flow,
    }

    cases = {}
    for expression in PATTERNS:
        parsed = flowfilter.parse(expression)
        cases['match/' + expression] = {
            name: flowfilter.match(parsed, item)
            for name, item in flows.items()
        }
    cases['match/none'] = {
        name: flowfilter.match(None, item)
        for name, item in flows.items()
    }
    for expression in INVALID:
        try:
            flowfilter.parse(expression)
            cases['invalid/' + repr(expression)] = {'value': 'accepted'}
        except Exception as error:
            cases['invalid/' + repr(expression)] = {
                'error': type(error).__name__,
                'message': str(error),
            }
    for expression in ('.', '~all', '~q ~m GET', '!(~q & ~t "text/html")'):
        parsed = flowfilter.parse(expression)
        cases['describe/' + expression] = {
            'type': type(parsed).__name__,
            'text': str(parsed),
        }
    return cases
