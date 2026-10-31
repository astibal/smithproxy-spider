"""HTTP message contract and mutation tests without a reference dependency."""

from contextlib import redirect_stdout
import gzip
from io import StringIO
import json
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import addon_http_message as http
import addon_multidict as multidict
from addon_loader import compatibility_imports
from addon_modules import compatibility_modules
from addon_message_contract import collect
from addon_query_contract import collect as collect_query
from addon_cookie_contract import collect as collect_cookies
from addon_cookie_contract import collect_combinations as collect_cookie_combinations
from addon_response_cookie_contract import collect as collect_response_cookies
from addon_refresh_contract import collect as collect_refresh
from addon_multipart_contract import collect as collect_multipart
from addon_view_contract import collect as collect_views
from addon_content_coding_contract import collect as collect_codings
from addon_path_contract import collect as collect_paths
from addon_http_adversarial_contract import collect as collect_http_adversarial


class MessageTests(unittest.TestCase):
    def test_adversarial_http_mutations_match_reference(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_http_adversarial_v12.json').read_text()
        )
        self.assertEqual(
            collect_http_adversarial(http),
            corpus['observations'],
        )

    def test_multidict_probe_matches_reference_corpus(self):
        output = StringIO()
        with compatibility_imports(compatibility_modules()):
            with redirect_stdout(output):
                runpy.run_path(
                    str(ROOT / "tests/probes/addon_multidict_probe.py")
                )

        actual = json.loads(output.getvalue())
        expected = json.loads(
            (ROOT / "tests/corpus/addon_multidict_v12.json").read_text()
        )
        self.assertEqual(actual, expected)

    def test_reference_path_component_contract(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_paths_v12.json').read_text())
        actual = json.loads(json.dumps(collect_paths(http.Request)))
        self.assertEqual(actual.keys(), corpus['cases'].keys())
        for name, expected in corpus['cases'].items():
            with self.subTest(case=name):
                self.assertEqual(actual[name], expected)

    def test_reference_content_coding_contract(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_content_codings_v12.json').read_text())
        actual = collect_codings(http.Response)
        for name, expected in corpus['cases'].items():
            with self.subTest(case=name):
                self.assertEqual(actual[name], expected)

    def test_live_view_reference_contract(self):
        corpus = json.loads((ROOT / "tests/corpus/addon_views_v12.json").read_text())
        actual = collect_views(http, multidict)
        self.assertEqual(actual.keys(), corpus["cases"].keys())
        for name, expected in corpus["cases"].items():
            with self.subTest(case=name):
                self.assertEqual(actual[name], expected)

    def test_multipart_generated_boundary_and_compressed_body(self):
        request = http.Request.make("POST", "https://example.test/", b"old")
        request.encode("gzip")
        request.multipart_form = [(b"first", b"one"), (b"first", b"two")]
        content_type = request.headers["content-type"]
        boundary = content_type.split("boundary=", 1)[1].encode()
        self.assertTrue(request.content.startswith(b"--" + boundary + b"\r\n"))
        self.assertTrue(request.content.endswith(b"--" + boundary + b"--\r\n"))
        self.assertEqual(gzip.decompress(request.raw_content), request.content)
        self.assertEqual(int(request.headers["content-length"]), len(request.raw_content))
        view = request.multipart_form
        self.assertEqual(view.get_all(b"first"), [b"one", b"two"])
        view[b"first"] = b"changed"
        self.assertEqual(request.headers["content-type"], content_type)
        self.assertEqual(view.get_all(b"first"), [b"changed"])
        self.assertEqual(request.headers["content-encoding"], "gzip")

    def test_multipart_decode_failure_does_not_mutate_message(self):
        request = http.Request.make("POST", "https://example.test/", b"broken")
        request.headers["content-encoding"] = "gzip"
        request.headers["content-type"] = "multipart/form-data; boundary=sample"
        before = request.get_state()
        with self.assertRaises(ValueError):
            request.multipart_form.fields
        self.assertEqual(request.get_state(), before)

    def test_multipart_reference_contract(self):
        corpus = json.loads((ROOT / "tests/corpus/addon_multipart_v12.json").read_text())
        actual = collect_multipart(http)
        self.assertEqual(actual.keys(), corpus["cases"].keys())
        for name, expected in corpus["cases"].items():
            with self.subTest(case=name):
                self.assertEqual(actual[name], expected)

    def test_cookie_combinations_reference_contract(self):
        path = ROOT / "tests/corpus/addon_cookie_combinations_v12.json"
        expected = json.loads(path.read_text())["cases"]
        actual = json.loads(json.dumps(collect_cookie_combinations(http)))
        self.assertEqual(len(actual), 200)
        self.assertEqual(len(actual), len(expected))
        for observed, reference in zip(actual, expected):
            with self.subTest(header=reference["header"]):
                self.assertEqual(observed, reference)

    def test_response_refresh_contract(self):
        path = ROOT / "tests/corpus/addon_refresh_v12.json"
        corpus = json.loads(path.read_text())
        actual = json.loads(json.dumps(collect_refresh(http)))
        self.assertEqual(actual, corpus["cases"])

    def test_response_refresh_clock_default_and_negative_shift(self):
        for now, expected in ((None, "Thu, 01 Jan 1970 00:01:50 GMT"),
                              (0, "Thu, 01 Jan 1970 00:01:50 GMT"),
                              (-100, "Wed, 31 Dec 1969 23:56:50 GMT"),
                              (99.1, "Thu, 01 Jan 1970 00:00:09 GMT")):
            with self.subTest(now=now):
                response = http.Response.make(headers={
                    "Date": "Thu, 01 Jan 1970 00:00:10 GMT"})
                response.timestamp_start = 100
                with patch("time.time", return_value=200):
                    response.refresh(now)
                self.assertEqual(response.headers["date"], expected)
                self.assertEqual(response.timestamp_start, 100)

    def test_response_cookie_contract(self):
        path = ROOT / "tests/corpus/addon_response_cookies_v12.json"
        corpus = json.loads(path.read_text())
        actual = json.loads(json.dumps(collect_response_cookies(http)))
        self.assertEqual(actual, corpus["cases"])

    def test_response_cookie_write_is_atomic_and_preserves_body(self):
        response = http.Response.make(content=b"body", headers={"set-cookie": "a=1"})
        before = response.get_state()
        with self.assertRaises(TypeError):
            response.cookies = [("valid", ("ok", [])), ("invalid", (123, []))]
        self.assertEqual(response.get_state(), before)
        response.cookies = [("a", ("new", [("HttpOnly", None)]))]
        self.assertEqual(response.raw_content, b"body")
        self.assertEqual(response.headers["content-length"], "4")

    def test_response_cookie_view_tracks_external_headers(self):
        response = http.Response.make(headers={"set-cookie": "a=1; Secure"})
        view = response.cookies
        value, attributes = view["a"]
        attributes["SameSite"] = "Strict"
        self.assertEqual(response.headers["set-cookie"], "a=1; Secure")
        view["a"] = (value, attributes)
        self.assertEqual(response.headers["set-cookie"], "a=1; Secure; SameSite=Strict")
        response.headers["set-cookie"] = "b=2"
        self.assertNotIn("a", view)
        self.assertEqual(view["b"][0], "2")

    def test_request_cookie_contract(self):
        path = ROOT / "tests/corpus/addon_request_cookies_v12.json"
        corpus = json.loads(path.read_text())
        actual = json.loads(json.dumps(collect_cookies(http)))
        self.assertEqual(actual, corpus["cases"])

    def test_request_cookie_views_preserve_unrelated_fields(self):
        request = http.Request.make("POST", "https://example.org/", b"body",
                                    {"X-Keep": "yes"})
        view = request.cookies
        self.assertEqual(view.fields, ())
        view.add("session", "one")
        view.add("session", "two")
        detached = view.copy()
        request.headers["cookie"] = "changed=externally"
        self.assertEqual(view["changed"], "externally")
        self.assertEqual(detached.get_all("session"), ["one", "two"])
        self.assertEqual(request.headers["x-keep"], "yes")
        self.assertEqual(request.raw_content, b"body")
        self.assertEqual(request.headers["content-length"], "4")

    def test_request_cookie_write_failure_is_atomic(self):
        request = http.Request.make("GET", "https://example.org/",
                                    headers={"cookie": "original=yes"})
        before = request.get_state()
        with self.assertRaises(TypeError):
            request.cookies = [("valid", "value"), ("invalid", None)]
        self.assertEqual(request.get_state(), before)

    def test_request_cache_validators(self):
        request = http.Request.make("GET", "https://example.org/", headers={
            "If-Modified-Since": "yesterday",
            "If-None-Match": "etag",
            "If-Match": "keep-match",
            "If-Unmodified-Since": "keep-date",
            "If-Range": "keep-range",
            "Cache-Control": "max-age=0",
        })
        request.headers.add("IF-NONE-MATCH", "second-tag")
        self.assertIsNone(request.anticache())
        self.assertNotIn("if-modified-since", request.headers)
        self.assertNotIn("if-none-match", request.headers)
        self.assertEqual(request.headers["if-match"], "keep-match")
        self.assertEqual(request.headers["if-unmodified-since"], "keep-date")
        self.assertEqual(request.headers["if-range"], "keep-range")
        self.assertEqual(request.headers["cache-control"], "max-age=0")
        before = request.get_state()
        request.anticache()
        self.assertEqual(request.get_state(), before)

    def test_request_anticomp_replaces_all_advertisements(self):
        request = http.Request.make("GET", "https://example.org/")
        for value in ("gzip", "br"):
            request.headers.add("Accept-Encoding", value)
        self.assertIsNone(request.anticomp())
        self.assertEqual(request.headers.get_all("accept-encoding"), ["identity"])
        self.assertEqual(request.raw_content, b"")
        request.headers.pop("accept-encoding")
        request.anticomp()
        self.assertEqual(request.headers["accept-encoding"], "identity")

    def test_request_encoding_constraint_reference_observations(self):
        # Black-box observations from mitmproxy 12.3.1, not protocol assumptions.
        cases = [
            (None, None),
            ("", ""),
            ("GZIP, BR", ""),
            ("gzip;q=0.5, deflate;q=1", "gzip, deflate"),
            ("*", ""),
            ("zstd, br, gzip", "br, gzip, zstd"),
            ("xgzip, identity", "identity, gzip"),
            ("gzip, gzip", "gzip"),
            ("gzip ,deflate", "gzip, deflate"),
            ("compress, unknown", ""),
            ("gzip, deflate, br, zstd, identity, compress, *",
             "identity, br, gzip, zstd, deflate"),
        ]
        for advertised, expected in cases:
            with self.subTest(advertised=advertised):
                request = http.Request.make("GET", "https://example.org/")
                if advertised is not None:
                    request.headers["Accept-Encoding"] = advertised
                self.assertIsNone(request.constrain_encoding())
                actual = request.headers.get("accept-encoding")
                if expected is None:
                    self.assertIsNone(actual)
                else:
                    # The reference changes ordering across PYTHONHASHSEEDs.
                    # Compare tokens, retaining duplicates and empty fields so
                    # normalization cannot hide a substantive difference.
                    self.assertEqual(sorted(actual.split(", ")),
                                     sorted(expected.split(", ")))

    def test_query_and_form_contract(self):
        corpus = json.loads((ROOT / "tests/corpus/addon_query_v12.json").read_text())
        actual = json.loads(json.dumps(collect_query(http)))
        self.assertEqual(actual, corpus["cases"])

    def test_query_copy_is_detached(self):
        request = http.Request.make("GET", "https://example.org/?x=1&x=2")
        query = request.query
        copied = query.copy()
        request.path = "/?new=value"
        self.assertEqual(query.fields, (("new", "value"),))
        self.assertEqual(copied.fields, (("x", "1"), ("x", "2")))
        copied["x"] = "changed"
        self.assertEqual(request.path, "/?new=value")

    def test_multidict_equality_preserves_order_and_duplicates(self):
        from addon_multidict import MultiDict

        value = MultiDict([("x", "1"), ("x", "2")])
        self.assertEqual(value, value.copy())
        self.assertNotEqual(value, MultiDict([("x", "1")]))
        self.assertNotEqual(value, MultiDict([("x", "2"), ("x", "1")]))
        self.assertNotEqual(value, {"x": "1"})

    def test_public_message_contract(self):
        corpus = json.loads((ROOT / "tests/corpus/addon_messages_v12.json").read_text())
        self.assertEqual(corpus["reference"], "12.3.1")
        actual = collect(http)
        self.assertEqual(actual.keys(), corpus["cases"].keys())
        for name, expected in corpus["cases"].items():
            with self.subTest(case=name):
                self.assertEqual(actual[name], expected)

    def test_copy_and_serialized_state_are_independent(self):
        request = http.Request.make("POST", "https://example.org/", b"body")
        request.trailers = http.Headers([(b"x-checksum", b"123")])
        original = request.get_state()
        for copied in (request.copy(), http.Request.from_state(original)):
            self.assertEqual(copied.get_state(), original)
            copied.headers["x-test"] = "new"
            copied.trailers["x-checksum"] = "changed"
            copied.content = b"longer body"
            self.assertEqual(request.get_state(), original)
        request.set_state(original)
        self.assertEqual(request.get_state(), original)

    def test_reading_encoded_body_never_rewrites_wire(self):
        wire = gzip.compress(b"hello", mtime=12345)
        response = http.Response(b"HTTP/2.0", 200, b"", ((b"content-encoding", b"gzip"),),
                                 wire, None, 1.0, 2.0)
        original = response.get_state()
        for _ in range(3):
            self.assertEqual(response.content, b"hello")
            self.assertEqual(response.text, "hello")
        self.assertEqual(response.get_state(), original)

    def test_encoded_mutation_repairs_wire_length(self):
        for encoding in ("gzip", "deflate", "identity", "br", "zstd"):
            with self.subTest(encoding=encoding):
                response = http.Response.make(content=b"first")
                response.encode(encoding)
                response.content = b"a different body" * 1000
                self.assertEqual(response.content, b"a different body" * 1000)
                self.assertEqual(int(response.headers["content-length"]), len(response.raw_content))
                response.decode()
                self.assertNotIn("content-encoding", response.headers)
                self.assertEqual(response.raw_content, b"a different body" * 1000)

    def test_missing_content_is_not_empty_content(self):
        response = http.Response.make(content=b"present")
        length = response.headers["content-length"]
        response.content = None
        self.assertIsNone(response.raw_content)
        self.assertIsNone(response.text)
        self.assertEqual(response.headers["content-length"], length)
        response.content = b""
        self.assertEqual(response.raw_content, b"")
        self.assertEqual(response.headers["content-length"], "0")

    def test_failed_destination_update_keeps_original_fields(self):
        request = http.Request.make("GET", "https://example.org/", headers={"Host": "example.org"})
        before = request.get_state()
        with self.assertRaises(ValueError):
            request.url = "http://elsewhere.invalid:99999/"
        self.assertEqual(request.get_state(), before)

    def test_json_uses_decoded_content(self):
        response = http.Response.make(content=b'{"answer": 42}')
        response.encode("gzip")
        self.assertEqual(response.json(), {"answer": 42})


if __name__ == "__main__":
    unittest.main()
