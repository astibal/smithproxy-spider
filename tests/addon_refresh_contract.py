"""Observable refresh behavior for stored HTTP responses."""


def collect(http):
    observations = []
    headers = [
        [("Date", "Wed, 21 Oct 2015 07:28:00 GMT"),
         ("Expires", "Wed, 21 Oct 2015 08:28:00 GMT"),
         ("Last-Modified", "Wed, 21 Oct 2015 06:28:00 GMT"), ("Age", "42")],
        [("Date", "bad"), ("Expires", "0")],
        [("Date", "Wednesday, 21-Oct-15 07:28:00 GMT")],
        [("Date", "Wed, 21 Oct 2015 07:28:00 GMT"),
         ("Date", "Wed, 21 Oct 2015 08:28:00 GMT")],
    ]
    for fields in headers:
        response = http.Response.make(content=b"unchanged", headers=[
            (name.encode(), value.encode()) for name, value in fields])
        response.timestamp_start = 100
        response.timestamp_end = 102
        result = response.refresh(200.9)
        observations.append([result, list(response.headers.items(multi=True)),
                             response.timestamp_start, response.timestamp_end,
                             response.raw_content.hex()])

    cookies = []
    for header in [
        "a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=10",
        "a=1; expires=bad; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
        "a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; expires=bad",
        "a=1; Expires; Secure", "a=1, b=2; Expires=bad",
        'a="a b"; path=/', "nonsense", "",
        "a=; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
        'a=""; Expires=Wed, 21 Oct 2015 07:28:00 GMT',
        "=; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
    ]:
        response = http.Response.make(headers={"Set-Cookie": header})
        response.timestamp_start = 100
        response.refresh(200)
        cookies.append(response.headers.get_all("set-cookie"))
    return {"headers": observations, "cookies": cookies}
