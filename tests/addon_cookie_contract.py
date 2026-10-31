"""Public request-cookie observations; no reference implementation imports."""

from itertools import product


def collect_combinations(http):
    names = ["a", " a ", "", "Expires", "Path"]
    values = ["1", "", '"a;b"', '"a,b"', '"abc', '"a\\"b"', "a=b",
              "Wed, 21 Oct 2015 07:28:00 GMT",
              "Wednesday, 21-Oct-15 07:28:00 GMT", "bad, tail=2"]
    separators = ["; ", ", ", ";;", "\t;"]
    observations = []
    for name, value, separator in product(names, values, separators):
        header = name + "=" + value + separator + "b=2; Secure"
        request = http.Request.make("GET", "https://example.org/",
                                    headers={"Cookie": header})
        response = http.Response.make(headers={"Set-Cookie": header})
        observations.append({
            "header": header,
            "request": list(request.cookies.fields),
            "response": [(key, value, attrs.fields)
                         for key, (value, attrs) in response.cookies.fields],
        })
    return observations


def collect(http):
    parsed = []
    inputs = [
        'a=1; a=2; b=3',
        'a="hello world"; b="x;y"; c="a\\"b"',
        'bare; =empty; x=; y=a=b',
        ' a = b ; ; q = "x" ',
        'a=one, b=two',
        'a="unterminated',
        '$Version=1; a=2; $Path=/',
        'x="a\\nb"',
        'x="a\\;b"',
        'x="a\\\\b"',
        'x="a"junk; y=2',
        '; ;a=1;;',
        'a=1\t;\tb=2',
        'a="x\\',
    ]
    for header in inputs:
        request = http.Request.make("GET", "https://example.org/",
                                    headers={"cookie": header})
        parsed.append(list(request.cookies.fields))

    formatted = []
    for value in ("", "plain", "a b", "a;b", 'a"b', "a\\b", "café",
                  "a=b", "a\tb", "a,b", "a/b", "a@b", "a\x7fb"):
        request.cookies = [("x", value), ("x", "second")]
        formatted.append(request.headers.get_all("cookie"))

    request.headers.set_all("cookie", ["a=1", "b=2; a=3"])
    view = request.cookies
    multiple = list(view.fields)
    view.set_all("a", ["first", "last"])
    changed = request.headers.get_all("cookie")
    request.headers["cookie"] = "external=yes"
    live = list(view.fields)
    view.clear()
    cleared = request.headers.get_all("cookie")

    request.headers["cookie"] = "a=old; a=again"
    supplied_values = ["first", "second", "third"]
    view.set_all("a", supplied_values)
    first_assignment = list(view.fields)
    view.set_all("a", supplied_values)
    preserved_input = {
        "values": supplied_values,
        "first": first_assignment,
        "second": list(view.fields),
    }
    return {"parsed": parsed, "formatted": formatted, "multiple": multiple,
            "changed": changed, "live": live, "cleared": cleared,
            "preserved_input": preserved_input}
