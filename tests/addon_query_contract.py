"""Public query/form observations, runnable against either implementation."""


def collect(http):
    observations = []
    request = http.Request.make("POST", "https://example.org/a?x=1&x=2&blank#f")
    query = request.query

    def record():
        observations.append({
            "path": request.path,
            "fields": list(query.fields),
            "items": list(query.items()),
            "keys": list(query.keys(multi=True)),
        })

    record()
    query.set_all("x", ["A", "B", "C"])
    record()
    query.insert(1, "x", "inserted")
    record()
    query["x"] = "new"
    record()
    del query["blank"]
    record()
    query.clear()
    record()
    request.query = [("q", "café"), ("q", "a b")]
    record()
    request.path = "/other?bad=%FF&semi=a;b&blank&=empty&&plus=a+b"
    record()
    query.add("Case", "YES")
    query.add("case", "no")
    record()

    forms = []
    for media_type in ("text/plain", "application/x-www-form-urlencoded",
                       "application/x-www-form-urlencoded; charset=iso-8859-1",
                       "Application/X-WWW-Form-Urlencoded",
                       "text/plain; application/x-www-form-urlencoded"):
        request = http.Request.make("POST", "https://example.org/",
                                    b"x=%E9&x=a+b&blank",
                                    {"content-type": media_type})
        view = request.urlencoded_form
        before = list(view.fields)
        request.urlencoded_form = [("q", "café"), ("q", "a b")]
        view.add("blank", "")
        forms.append({
            "before": before,
            "after": list(view.fields),
            "body": request.content.hex(),
            "headers": list(request.headers.items()),
        })

    request = http.Request.make("GET", "https://example.org/?x=old&x=again")
    supplied_values = ["first", "second", "third"]
    request.query.set_all("x", supplied_values)
    first_assignment = list(request.query.fields)
    request.query.set_all("x", supplied_values)
    preserved_input = {
        "values": supplied_values,
        "first": first_assignment,
        "second": list(request.query.fields),
    }
    return {
        "queries": observations,
        "forms": forms,
        "preserved_input": preserved_input,
    }
