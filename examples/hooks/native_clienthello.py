"""Deploy with script_api=spider, instancing=flow and tls_clienthello=true."""


def main(api, state):
    if api.tls is None:
        return
    if api.tls.event is not TlsEvent.CLIENT_HELLO:
        return

    hello = api.tls.client_hello
    original = hello.original()

    # Meta editing selects the outgoing offer; it does not rewrite peer bytes.
    hello.sni = "origin.example"
    if original.openssl_cipher_list is not None:
        hello.openssl_cipher_list = original.openssl_cipher_list + ":!AES128"

    return hello.commit()
