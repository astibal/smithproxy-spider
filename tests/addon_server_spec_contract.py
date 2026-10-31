"""Public server-spec observations shared with the isolated reference probe."""


SPECS = (
    "example.com",
    "example.com:443",
    "example.com:0",
    "example.com:65535",
    "example.com:65536",
    "http://example.com",
    "http://example.com:8080",
    "https://example.com",
    "http3://example.com",
    "tls://example.com",
    "dtls://example.com",
    "tcp://example.com",
    "udp://example.com",
    "dns://8.8.8.8",
    "quic://example.com",
    "quic://example.com:8443",
    "tcp://[::1]:42",
    "[::1]:80",
    "[fe80::1%eth0]:53",
    "::1",
    "http://",
    "http://a:b",
    "http://user@example.com",
    "http://example.com/path",
    "http://example.com?query",
    "http://example.com#fragment",
    "ftp://example.com",
    "HTTP://example.com",
    " example.com:80",
    "example.com:80 ",
    "example.com:-1",
    "example.com:+1",
    "example.com:01",
    "example.com:",
    "localhost:1234",
    "täst.example:443",
    "127.0.0.1:3128",
    "0.0.0.0:0",
    "example.com.",
    ".example.com",
    "example..com",
    "-example.com",
    "example-.com",
    "_service.example",
    "a" * 63 + ".example",
    "a" * 64 + ".example",
    ("a" * 63 + ".") * 3 + "a" * 61,
    ("a" * 63 + ".") * 3 + "a" * 62,
    "café.example",
    "☃.example",
    "example。com",
    "127.0.0.1.",
    "127.00.0.1",
    "256.1.1.1",
    "[::1]",
    "[::1]:0",
    "[::1]:65535",
    "[::1]:65536",
    "[::ffff:192.0.2.1]:80",
    "[fe80::1%25eth0]:53",
    "[v1.example]:80",
    "[::1",
    "::1]",
    "[]:80",
    "http://[::1]",
    "http://[::1]:8080",
    "http://example.com:00080",
    "http://example.com:999999999999999999999",
    "http://example.com:",
    "http:///example.com",
    "http:example.com",
    "://example.com",
    "1http://example.com",
    "http+unix://example.com",
    "http://example.com/",
    "http://example.com?",
    "http://example.com#",
    "http://user:pass@example.com",
    "http://example.com:80/path",
    "http://example.com:80?query",
    "http://example.com:80#fragment",
    "\texample.com:80",
    "example.com:80\n",
    "example.com\x00:80",
    "localhost",
    "localhost.",
    "LOCALHOST:443",
    "xn--tst-qla.example:443",
    "",
)


DEFAULT_SCHEMES = ("http", "https", "http3", "tls", "dtls", "tcp", "udp", "dns", "quic", "bogus")


def collect(server_spec):
    cases = {}
    for spec in SPECS:
        for default in DEFAULT_SCHEMES:
            key = repr(spec) + " / " + default
            try:
                value = server_spec.parse(spec, default)
                cases[key] = {
                    "value": [value[0], [value[1][0], value[1][1]]],
                }
            except Exception as error:
                cases[key] = {
                    "error": type(error).__name__,
                    "message": str(error),
                }
    return cases
