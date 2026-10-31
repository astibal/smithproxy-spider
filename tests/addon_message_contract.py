"""Our black-box probes of the public HTTP addon object contract.

The same probes run against Spider offline and against an isolated reference
installation when refreshing the checked-in corpus. They do not inspect source.
"""

import gzip
import zlib


def serializable(value):
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, (tuple, list)):
        return [serializable(item) for item in value]
    if isinstance(value, dict):
        return {key: serializable(item) for key, item in value.items()}
    return value


def observed(operation):
    try:
        return serializable(operation())
    except Exception as error:
        return {"error": type(error).__name__}


def snapshot(message):
    result = {}
    properties = ["http_version", "is_http10", "is_http11", "is_http2", "is_http3",
                  "raw_content", "content", "text"]
    if hasattr(message, "method"):
        properties += ["method", "scheme", "authority", "host", "port", "path",
                       "url", "pretty_url", "host_header", "pretty_host",
                       "path_components", "first_line_format"]
    else:
        properties += ["status_code", "reason"]
    for name in properties:
        result[name] = observed(lambda: getattr(message, name))
    result["headers"] = serializable(message.headers.fields)
    result["trailers"] = serializable(message.trailers.fields) if message.trailers is not None else None
    result["lenient_content"] = observed(lambda: message.get_content(strict=False))
    result["lenient_text"] = observed(lambda: message.get_text(strict=False))
    return result


def collect(http):
    cases = {}

    def record(name, create, mutate=None):
        entry = {}
        try:
            message = create()
        except Exception as error:
            cases[name] = {"construction_error": type(error).__name__}
            return
        entry["before"] = snapshot(message)
        if mutate is not None:
            entry["operation"] = observed(lambda: mutate(message))
            entry["after"] = snapshot(message)
        cases[name] = entry

    urls = ["http://example.com", "https://example.com/a?q=1#fragment",
            "http://example.com:80/a", "https://example.com:8443/a",
            "http://[::1]:8080/a", "https://münich.example/čaj?q=čaj",
            "https://user:pass@example.com/a", "ftp://example.com/a",
            "example.com/a", "http://example.com:bad/", "http://example.com:0/",
            "http://example.com:65536/", "https://EXAMPLE.com/a%2Fb"]
    for index, url in enumerate(urls):
        record(f"url/{index}", lambda url=url: http.Request.make("get", url))

    def request():
        return http.Request.make("POST", "https://example.com/a?q=1", b"old",
                                 {"Host": "virtual.example", "X-Test": "yes"})

    mutations = [("method", "put"), ("method", b"PATCH"), ("scheme", "http"),
                 ("authority", "other.example:8443"), ("host", "new.example"),
                 ("host", "münich.example"), ("port", 8080), ("path", "/new?q=2"),
                 ("path", "/čaj"), ("url", "http://next.example:81/b?q=2"),
                 ("host_header", "vhost.example:9443"), ("host_header", None),
                 ("http_version", "HTTP/2.0"), ("path_components", ["a b", "x/y"])]
    for index, (field, value) in enumerate(mutations):
        record(f"request/set/{index}", request,
               lambda message, field=field, value=value: setattr(message, field, value))

    for status in [100, 200, 201, 204, 301, 404, 599, 999]:
        record(f"response/status/{status}", lambda status=status: http.Response.make(status))
    record("response/status/change", lambda: http.Response.make(200),
           lambda message: setattr(message, "status_code", 404))
    record("response/reason/change", lambda: http.Response.make(200),
           lambda message: setattr(message, "reason", "Café"))

    for kind in ("request", "response"):
        make = http.Response.make if kind == "response" else lambda **kwargs: http.Request.make("POST", "https://example.com/", **kwargs)
        for index, content in enumerate([b"", b"hello", "café", b"\xff", None, 42]):
            record(f"{kind}/content/make/{index}", lambda content=content, make=make: make(content=content))
        for index, headers in enumerate([{"Content-Length": "999"}, {"Transfer-Encoding": "chunked"},
                                         {"Content-Type": "text/plain; charset=iso-8859-1"},
                                         {"Content-Type": "application/json"},
                                         {"Content-Type": "text/plain; charset=not-a-charset"}]):
            record(f"{kind}/content/headers/{index}", lambda headers=headers, make=make: make(content="café", headers=headers))

    setters = [("raw_content", b"new longer body"), ("content", b"new longer body"),
               ("text", "café"), ("raw_content", None), ("content", None), ("text", None),
               ("content", "not bytes"), ("text", b"not text")]
    for index, (field, value) in enumerate(setters):
        record(f"message/set/{index}", lambda: http.Response.make(content=b"old"),
               lambda message, field=field, value=value: setattr(message, field, value))

    for index, (encoding, wire) in enumerate([
        ("gzip", gzip.compress(b"hello", mtime=0)),
        ("deflate", zlib.compress(b"hello")),
        ("deflate", zlib.compress(b"hello")[2:-4]),
        ("identity", b"hello"), ("unknown", b"hello"), ("gzip", b"broken"),
        ("GZIP", gzip.compress(b"hello", mtime=0)), ("gzip, deflate", b"hello"),
    ]):
        def encoded(encoding=encoding, wire=wire):
            return http.Response(b"HTTP/1.1", 200, b"OK", http.Headers([
                (b"content-encoding", encoding.encode()),
                (b"content-length", str(len(wire)).encode()),
            ]), wire, None, 1.0, 2.0)
        record(f"message/encoding/{index}", encoded)
        record(f"message/decode/{index}", encoded, lambda message: message.decode())
        record(f"message/decode-lenient/{index}", encoded, lambda message: message.decode(strict=False))

    for index, (content_type, wire) in enumerate([
        ("text/plain", b"caf\xe9"), ("text/plain; charset=iso-8859-1", b"caf\xe9"),
        ("application/json", b'{"text":"caf\xc3\xa9"}'),
        ("text/plain; charset=unknown", b"test"),
        ("text/plain; charset=utf-8", b"\xff"),
        ("text/html", b'<meta charset="windows-1252">caf\xe9'),
    ]):
        record(f"message/charset/{index}", lambda content_type=content_type, wire=wire:
               http.Response.make(content=wire, headers={"Content-Type": content_type}))

    for version in [b"HTTP/1.0", b"HTTP/1.1", b"HTTP/2.0", b"HTTP/3", b"HTTP/2"]:
        record(f"message/version/{version.decode()}", lambda version=version:
               http.Response(version, 200, b"OK", (), None, None, 1.0, None))
    return cases
