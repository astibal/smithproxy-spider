"""Adversarial public HTTP-message observations for differential testing."""


def collect(http):
    observations = {}

    def normalized(value):
        if isinstance(value, bytes):
            return {"bytes": value.hex()}
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        return {"type": type(value).__name__}

    def outcome(operation):
        try:
            return {"value": normalized(operation()), "error": None}
        except Exception as error:
            return {
                "value": None,
                "error": [type(error).__name__, str(error)],
            }

    invalid_headers = outcome(lambda: http.Request.make(
        "GET",
        "http://example.test/",
        {1: "value"},
    ))
    observations["invalid header name"] = invalid_headers
    observations["invalid response content"] = outcome(
        lambda: http.Response.make(200, {"not": "content"})
    )

    response = http.Response.make(
        200,
        b"wire",
        {"content-encoding": "unknown"},
    )
    strict = outcome(lambda: response.get_content(strict=True))
    permissive = response.get_content(strict=False)
    response.content = b"replacement"
    observations["unknown content coding"] = {
        "strict": strict,
        "permissive": permissive.decode("ascii"),
        "content": response.content.decode("ascii"),
        "content_encoding": response.headers.get("content-encoding"),
        "content_length": response.headers.get("content-length"),
    }

    empty = http.Response.make(
        200,
        b"",
        {"content-encoding": "gzip"},
    )
    empty.decode()
    observations["empty encoded body"] = {
        "raw_content": empty.raw_content.decode("ascii"),
        "content_encoding": empty.headers.get("content-encoding"),
        "content_length": empty.headers.get("content-length"),
    }

    text = http.Response.make(
        200,
        b"",
        {"content-type": "text/plain; format=flowed"},
    )
    text.text = "price: 10\u20ac"
    observations["text charset fallback"] = {
        "raw_content": text.raw_content.hex(),
        "content_type": text.headers.get("content-type"),
        "text": text.text,
    }

    unsupported = http.Response.make(200, b"body")
    encoding_error = outcome(lambda: unsupported.encode("unknown"))
    observations["unsupported encode"] = {
        "outcome": encoding_error,
        "content_encoding": unsupported.headers.get("content-encoding"),
        "raw_content": unsupported.raw_content.decode("ascii"),
    }

    h2 = http.Request.make("GET", "https://example.test/path")
    h2.http_version = "HTTP/2.0"
    h2.authority = "authority.test:8443"
    before = h2.host_header
    h2.host_header = None
    cleared = [h2.authority, h2.headers.get("host")]
    h2.host_header = "new.test:9443"
    observations["h2 host header"] = {
        "before": before,
        "cleared": cleared,
        "authority": h2.authority,
        "host": h2.headers.get("host"),
    }

    connect = http.Request.make("CONNECT", "https://example.test/")
    connect.authority = "example.test:443"
    observations["connect target"] = {
        "first_line_format": connect.first_line_format,
        "url": connect.url,
        "pretty_url": connect.pretty_url,
    }

    broken_host = http.Request.make("GET", "http://origin.test/path")
    broken_host.headers["host"] = "["
    observations["invalid display host"] = {
        "pretty_host": broken_host.pretty_host,
        "pretty_url": broken_host.pretty_url,
    }

    form = http.Request.make("POST", "http://example.test/form")
    form.headers["content-type"] = "application/x-www-form-urlencoded"
    form.raw_content = None
    observations["missing form body"] = {
        "items": list(form.urlencoded_form.items(multi=True)),
        "raw_content": form.raw_content,
    }

    return observations
