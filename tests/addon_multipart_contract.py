"""Independent multipart form observations; no reference implementation code."""

from addon_message_contract import observed, serializable


def collect(http):
    cases = {}
    ordinary = b'--sample\r\nContent-Disposition: form-data; name="field"\r\n\r\nvalue\r\n--sample--\r\n'
    bodies = {
        "ordinary": ordinary,
        "empty": b"",
        "missing": None,
        "binary": ordinary.replace(b"value", b"\x00\xff\r\nnext"),
        "padding": ordinary.replace(b"value", b"  value \r\n\r\n"),
        "filename": ordinary.replace(b'name="field"', b'name="field"; filename="a.txt"'),
        "missing_name": ordinary.replace(b'; name="field"', b""),
        "unquoted_name": ordinary.replace(b'name="field"', b"name=field"),
        "upper_header": ordinary.replace(b"Content-Disposition", b"CONTENT-DISPOSITION"),
        "other_disposition": ordinary.replace(b"form-data", b"attachment"),
        "transfer_base64": ordinary.replace(b"\r\n\r\nvalue", b"\r\nContent-Transfer-Encoding: base64\r\n\r\ndmFsdWU="),
        "lf_only": ordinary.replace(b"\r\n", b"\n"),
        "no_close": ordinary.rsplit(b"--sample--", 1)[0],
        "preamble": b"before\r\n" + ordinary + b"after",
        "wrong_boundary": ordinary.replace(b"--sample", b"--wrong"),
        "empty_name": ordinary.replace(b'name="field"', b'name=""'),
        "upper_name": ordinary.replace(b'name="field"', b'NAME="field"'),
        "other_header": ordinary.replace(b"Content-Disposition: form-data;", b"X-Other:"),
        "filename_before_name": ordinary.replace(b'name="field"', b'filename="file.txt"; name="field"'),
        "duplicate_name": ordinary.replace(b'name="field"', b'name="first"; name="second"'),
        "escaped_name": ordinary.replace(b'name="field"', b'name="a\\"b"'),
        "name_in_other_header": ordinary.replace(b'\r\n\r\nvalue', b'\r\nX-Info: name="other"\r\n\r\nvalue'),
        "folded_header": ordinary.replace(b'; name=', b';\r\n name='),
        "embedded_boundary": ordinary.replace(b'value', b'prefix--samplemiddle'),
        "duplicate_fields": ordinary.replace(b'--sample--\r\n', ordinary),
        "name_only_second_header": ordinary.replace(b'; name="field"', b'\r\nX-Other: name="field"'),
        "leading_other_header": ordinary.replace(b'Content-Disposition:', b'X-Other: value\r\nContent-Disposition:'),
        "name_without_space": ordinary.replace(b'; name=', b';name='),
        "name_tab": ordinary.replace(b'; name=', b';\tname='),
    }
    for name, body in bodies.items():
        request = http.Request.make("POST", "https://example.test/", body or b"",
                                    {"content-type": "multipart/form-data; boundary=sample"})
        request.raw_content = body
        cases["read/" + name] = observed(lambda: request.multipart_form.fields)

    for content_type in ("", "text/plain", "multipart/form-data", "multipart/form-data; boundary=",
                         'multipart/form-data; boundary="sample"',
                         "MULTIPART/FORM-DATA; boundary=sample",
                         "multipart/form-data; BOUNDARY=sample",
                         "multipart/form-data; boundary =sample",
                         "multipart/form-data; boundary=wrong; boundary=sample",
                         "application/x-multipart/form-data; boundary=sample"):
        request = http.Request.make("POST", "https://example.test/", ordinary,
                                    {"content-type": content_type})
        cases["type/" + content_type] = observed(lambda: request.multipart_form.fields)

    values = [[], [(b"a", b"one"), (b"a", b"two")], [(b"binary", b"\x00\xff")],
              [(b'a"b', b"value")], [(b"a", b"line\r\nline")],
              [(b"a", b"--sample")], [("a", "value")], [(b"a", None)],
              [(b"a", b"x--samplex")], [(b"a", b"x\r\n--sample\r\ny")],
              [(b'', None)], [(None, b'value')], [(b'', b'x'), (b'a', b'y')]]
    for index, fields in enumerate(values):
        request = http.Request.make("POST", "https://example.test/", b"original",
                                    {"content-type": "multipart/form-data; boundary=sample"})
        operation = observed(lambda: setattr(request, "multipart_form", fields))
        cases["write/" + str(index)] = {
            "operation": operation,
            "content": serializable(request.content),
            "headers": serializable(request.headers.fields),
            "fields": observed(lambda: request.multipart_form.fields),
        }
    for content_type in ("multipart/form-data", 'multipart/form-data; boundary="sample"',
                         "multipart/form-data; boundary="):
        request = http.Request.make("POST", "https://example.test/", b"original",
                                    {"content-type": content_type})
        operation = observed(lambda: setattr(request, "multipart_form", [(b"a", b"value")]))
        cases["write_type/" + content_type] = {
            "operation": operation,
            "content": serializable(request.content),
            "fields": observed(lambda: request.multipart_form.fields),
        }

    request = http.Request.make("POST", "https://example.test/", ordinary,
                                {"content-type": "multipart/form-data; boundary=sample"})
    view = request.multipart_form
    view.set_all(b"field", [b"value", b"second"])
    view[b"extra"] = b"new"
    cases["view/duplicates"] = serializable(view.fields)
    request.content = ordinary.replace(b"value", b"replacement")
    cases["view/live"] = serializable(view.fields)
    view.clear()
    cases["view/clear"] = serializable(request.content)
    for name in (b'file.txt', b'file.html', b'file.json', b'file.png', b'file.bin',
                 b'file.tar.gz', b'line\r\nname', b'quote"name', b'', b'\xff'):
        request = http.Request.make("POST", "https://example.test/", b"original",
                                    {"content-type": "multipart/form-data; boundary=sample"})
        operation = observed(lambda: setattr(request, 'multipart_form', [(name, b'value')]))
        cases['write_name/' + name.hex()] = {
            'operation': operation,
            'content': serializable(request.content),
            'fields': observed(lambda: request.multipart_form.fields),
        }
    return cases
