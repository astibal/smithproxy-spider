"""Public mapping-view behavior observed without reading reference sources."""

from addon_message_contract import observed, serializable


def field_values(value):
    if hasattr(value, "fields"):
        return field_values(value.fields)
    if isinstance(value, (list, tuple)):
        return [field_values(item) for item in value]
    return serializable(value)


def collect(http, multidict):
    cases = {}

    def create(kind):
        request = http.Request.make("POST", "https://example.test/?a=one&a=two",
                                   b"a=one&a=two", {
                                       "content-type": "application/x-www-form-urlencoded",
                                       "cookie": "a=one; a=two",
                                   })
        if kind == "multipart":
            request.headers["content-type"] = "multipart/form-data; boundary=sample"
            request.multipart_form = [(b"a", b"one"), (b"a", b"two")]
            return request.multipart_form, b"a", b"new"
        if kind == "response_cookies":
            response = http.Response.make(headers={"set-cookie": "a=one; Path=/"})
            return response.cookies, "a", ("new", multidict.CookieAttrs())
        if kind == "request_cookies":
            return request.cookies, "a", "new"
        if kind == "query":
            return request.query, "a", "new"
        return request.urlencoded_form, "a", "new"

    def snapshot(view):
        return {
            "fields_type": type(view.fields).__name__,
            "fields": field_values(view.fields),
            "serializable": [hasattr(view, name) for name in
                             ("get_state", "set_state", "from_state")],
            "is_owned": isinstance(view, multidict.MultiDict),
        }

    for kind in ("query", "urlencoded", "multipart", "request_cookies", "response_cookies"):
        for operation in ("add", "insert", "set", "set_all", "delete", "clear", "copy"):
            view, key, value = create(kind)
            before = snapshot(view)

            def mutate():
                if operation == "add":
                    view.add(key, value)
                elif operation == "insert":
                    view.insert(-1, key, value)
                elif operation == "set":
                    view[key] = value
                elif operation == "set_all":
                    view.set_all(key, [value])
                elif operation == "delete":
                    del view[key]
                elif operation == "clear":
                    view.clear()
                else:
                    detached = view.copy()
                    view[key] = value
                    return snapshot(detached)

            cases[kind + "/" + operation] = {
                "before": before,
                "operation": observed(mutate),
                "after": snapshot(view),
            }

    for container in (list, tuple):
        original = container((("a", "one"), ("a", "two")))
        writes = []
        view = multidict.MultiDictView(lambda: original, writes.append)
        supplied = [("b", "new")]
        view.fields = supplied
        cases["custom/" + container.__name__] = {
            "read_identity": view.fields is original,
            "write_identity": writes[0] is supplied,
            "before": snapshot(view),
            "view_equals_owned": view == multidict.MultiDict(original),
            "owned_equals_view": multidict.MultiDict(original) == view,
        }
    return cases
