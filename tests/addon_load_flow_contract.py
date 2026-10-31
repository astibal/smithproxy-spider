"""Public Master.load_flow observations shared by reference and adapter tests."""


async def collect(master, http, tcp, udp, dns, websocket, connection, flow_module):
    events = []

    class Recorder:
        def requestheaders(self, flow):
            events.append(["requestheaders", flow.type])

        def request(self, flow):
            events.append(["request", flow.type])

        def responseheaders(self, flow):
            events.append(["responseheaders", flow.type])

        def response(self, flow):
            events.append(["response", flow.type])

        def error(self, flow):
            events.append(["error", flow.type, flow.error.msg])

        def tcp_start(self, flow):
            events.append(["tcp_start", len(flow.messages)])

        def tcp_message(self, flow):
            message = flow.messages[-1]
            events.append([
                "tcp_message",
                message.from_client,
                message.content.decode("ascii"),
                len(flow.messages),
            ])

        def tcp_end(self, flow):
            events.append(["tcp_end", len(flow.messages)])

        def tcp_error(self, flow):
            events.append(["tcp_error", len(flow.messages), flow.error.msg])

        def udp_start(self, flow):
            events.append(["udp_start", len(flow.messages)])

        def udp_message(self, flow):
            message = flow.messages[-1]
            events.append([
                "udp_message",
                message.from_client,
                message.content.decode("ascii"),
                len(flow.messages),
            ])

        def udp_end(self, flow):
            events.append(["udp_end", len(flow.messages)])

        def udp_error(self, flow):
            events.append(["udp_error", len(flow.messages), flow.error.msg])

        def dns_request(self, flow):
            events.append(["dns_request", flow.request.id])

        def dns_response(self, flow):
            events.append(["dns_response", flow.response.id])

        def dns_error(self, flow):
            events.append(["dns_error", flow.error.msg])

        def websocket_start(self, flow):
            events.append(["websocket_start", len(flow.websocket.messages)])

        def websocket_message(self, flow):
            message = flow.websocket.messages[-1]
            events.append([
                "websocket_message",
                message.from_client,
                message.content.decode("ascii"),
                len(flow.websocket.messages),
            ])

        def websocket_end(self, flow):
            events.append([
                "websocket_end",
                len(flow.websocket.messages),
                flow.websocket.close_code,
            ])

    master.addons.add(Recorder())
    events.clear()

    def peers():
        return (
            connection.Client(
                peername=("127.0.0.1", 41000),
                sockname=("127.0.0.1", 8080),
            ),
            connection.Server(address=("example.test", 443)),
        )

    cases = {}

    async def observe(name, value):
        events.clear()
        original_list = getattr(value, "messages", None)
        original_messages = tuple(original_list or ())
        error = None
        returned = None
        try:
            returned = await master.load_flow(value)
        except Exception as failure:
            error = [type(failure).__name__, str(failure)]
        cases[name] = {
            "events": list(events),
            "error": error,
            "return_type": type(returned).__name__,
            "post_message_count": len(getattr(value, "messages", ())),
            "same_message_list": (
                None if original_list is None else value.messages is original_list
            ),
            "same_messages": (
                None if original_list is None
                else all(
                    current is original
                    for current, original in zip(value.messages, original_messages)
                )
            ),
        }

    client, server = peers()
    request_only = http.HTTPFlow(client, server)
    request_only.request = http.Request.make("GET", "https://example.test/one")
    await observe("http_request", request_only)

    client, server = peers()
    await observe("http_empty", http.HTTPFlow(client, server))

    client, server = peers()
    response = http.HTTPFlow(client, server)
    response.request = http.Request.make("POST", "https://example.test/two", b"request")
    response.response = http.Response.make(201, b"response")
    await observe("http_response", response)

    client, server = peers()
    response_error = http.HTTPFlow(client, server)
    response_error.request = http.Request.make(
        "GET", "https://example.test/response-error"
    )
    response_error.response = http.Response.make(202, b"response")
    response_error.error = flow_module.Error("late failure", 124)
    await observe("http_response_error", response_error)

    client, server = peers()
    failed = http.HTTPFlow(client, server)
    failed.request = http.Request.make("GET", "https://example.test/error")
    failed.error = flow_module.Error("recorded failure", 123)
    await observe("http_error", failed)

    client, server = peers()
    tcp_flow = tcp.TCPFlow(client, server)
    tcp_flow.messages.extend([
        tcp.TCPMessage(True, b"one", 1),
        tcp.TCPMessage(False, b"two", 2),
    ])
    await observe("tcp", tcp_flow)

    client, server = peers()
    tcp_error = tcp.TCPFlow(client, server)
    tcp_error.messages.append(tcp.TCPMessage(True, b"broken", 3))
    tcp_error.error = flow_module.Error("tcp failure", 125)
    await observe("tcp_error", tcp_error)

    client, server = peers()
    udp_flow = udp.UDPFlow(client, server)
    udp_flow.messages.extend([
        udp.UDPMessage(True, b"one", 1),
        udp.UDPMessage(False, b"two", 2),
    ])
    await observe("udp", udp_flow)

    client, server = peers()
    udp_error = udp.UDPFlow(client, server)
    udp_error.messages.append(udp.UDPMessage(False, b"broken", 3))
    udp_error.error = flow_module.Error("udp failure", 126)
    await observe("udp_error", udp_error)

    def dns_message(identifier, query):
        return dns.DNSMessage(
            id=identifier,
            query=query,
            op_code=dns.op_codes.QUERY,
            authoritative_answer=False,
            truncation=False,
            recursion_desired=True,
            recursion_available=not query,
            reserved=0,
            response_code=dns.response_codes.NOERROR,
            questions=[dns.Question(
                "example.test",
                dns.types.A,
                dns.classes.IN,
            )],
            answers=[],
            authorities=[],
            additionals=[],
            timestamp=1,
        )

    client, server = peers()
    dns_response = dns.DNSFlow(client, server)
    dns_response.request = dns_message(71, True)
    dns_response.response = dns_message(71, False)
    await observe("dns_response", dns_response)

    client, server = peers()
    await observe("dns_empty", dns.DNSFlow(client, server))

    client, server = peers()
    dns_error = dns.DNSFlow(client, server)
    dns_error.request = dns_message(72, True)
    dns_error.error = flow_module.Error("dns failure", 127)
    await observe("dns_error", dns_error)

    client, server = peers()
    websocket_flow = http.HTTPFlow(client, server)
    websocket_flow.request = http.Request.make(
        "GET", "https://example.test/socket"
    )
    websocket_flow.response = http.Response.make(101)
    websocket_flow.websocket = websocket.WebSocketData(
        messages=[
            websocket.WebSocketMessage(1, True, b"one", 1),
            websocket.WebSocketMessage(2, False, b"two", 2),
        ],
        closed_by_client=True,
        close_code=1000,
        close_reason="complete",
        timestamp_end=3,
    )
    await observe("websocket", websocket_flow)

    client, server = peers()
    open_websocket = http.HTTPFlow(client, server)
    open_websocket.request = http.Request.make(
        "GET", "https://example.test/open-socket"
    )
    open_websocket.response = http.Response.make(101)
    open_websocket.websocket = websocket.WebSocketData(
        messages=[websocket.WebSocketMessage(1, True, b"open", 4)]
    )
    await observe("websocket_open", open_websocket)

    await observe("foreign_object", object())

    class FailingAddon:
        name = "failing-load-flow-addon"

        def request(self, flow):
            events.append(["failing_request", flow.type])
            raise ValueError("load-flow callback failed")

    class FollowingAddon:
        name = "following-load-flow-addon"

        def request(self, flow):
            events.append(["following_request", flow.type])

    master.addons.add(FailingAddon())
    master.addons.add(FollowingAddon())
    client, server = peers()
    callback_error = http.HTTPFlow(client, server)
    callback_error.request = http.Request.make(
        "GET", "https://example.test/callback-error"
    )
    await observe("http_callback_error", callback_error)

    return cases
