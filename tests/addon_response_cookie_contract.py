"""Set-Cookie behavior observed exclusively through public message objects."""


def collect(http):
    response = http.Response.make()
    parsed = []
    inputs = [
        "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
        "a=1; path=/a; Path=/b; secure; SECURE",
        'a="x;y"; Max-Age=0', "bare", "", "=x; Secure",
        "a=1, b=2; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
        "a=1; Path=/x, b=2",
        "a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT, b=2",
        "a=1; X=a,b", 'a=1; x="a,b"', "a=1; flag; empty=",
        "a=1; path = /foo ; secure", "a=1; Expires=invalid, b=2",
    ]
    for header in inputs:
        response.headers["set-cookie"] = header
        parsed.append([(name, value, attrs.fields)
                       for name, (value, attrs) in response.cookies.fields])

    response.headers.set_all("set-cookie", ["a=1; Path=/a; path=/b; Secure", "a=2"])
    view = response.cookies
    value, attrs = view["a"]
    lookup = [attrs["PATH"], attrs.get_all("PATH"), list(attrs), list(attrs.items())]
    attrs.set_all("PATH", ["/c", "/d", "/e"])
    attrs.add("path", "/f")
    detached = response.headers.get_all("set-cookie")
    view["a"] = (value, attrs)
    edited = response.headers.get_all("set-cookie")
    copied = attrs.copy()
    del copied["PaTh"]

    formatted = []
    for fields in [
        [("Path", "/"), ("HttpOnly", None)],
        [("x", "a b"), ("Secure", "")],
        [("Path", "a b; c"), ("Expires", "Wed, 21 Oct 2015 07:28:00 GMT")],
    ]:
        response.cookies = [("a", ("hello world", fields))]
        formatted.append(response.headers.get_all("set-cookie"))
    response.cookies.clear()
    return {"parsed": parsed, "lookup": lookup, "detached": detached,
            "edited": edited, "copied": copied.fields, "formatted": formatted,
            "cleared": response.headers.get_all("set-cookie")}
