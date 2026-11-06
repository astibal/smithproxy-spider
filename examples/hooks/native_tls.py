"""Enable tls_lifecycle and the desired start subscriptions on a flow deployment."""


def main(api, state):
    tls = api.tls
    if tls is None:
        return

    if tls.event is TlsEvent.START:
        start = tls.start
        api.print(tls.transport.value, tls.side.value, start.original().sni)
        return start.commit()

    if tls.event is TlsEvent.ESTABLISHED:
        outcome = tls.outcome
        api.print(outcome.tls_version, outcome.cipher, len(outcome.certificates))
        return outcome.commit()

    if tls.event is TlsEvent.FAILED:
        api.print(tls.side.value, tls.outcome.error)
