"""Compare Spider HTTP objects with public reference behavior, offline."""

import json
from pathlib import Path
import random
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
from addon_http import Headers
from addon_headers_adversarial_contract import collect as collect_adversarial


def snapshot(headers):
    return {
        "fields": [[name.hex(), value.hex()] for name, value in headers.fields],
        "items": [list(pair) for pair in headers.items()],
        "multi": [list(pair) for pair in headers.items(multi=True)],
        "keys": list(headers),
        "length": len(headers),
        "wire": bytes(headers).hex(),
    }


class HeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads((ROOT / "tests/corpus/addon_headers_v12.json").read_text())

    def test_public_operations_match_reference_corpus(self):
        self.assertEqual(self.corpus["reference"], "12.3.1")
        for case in self.corpus["cases"]:
            with self.subTest(initial=case["initial"], operation=case["operation"]):
                headers = Headers([(bytes.fromhex(name), bytes.fromhex(value))
                                   for name, value in case["initial"]])
                self.assertEqual(snapshot(headers), case["before"])
                error = None
                try:
                    match case["operation"]:
                        case "set":
                            headers["x-a"] = "replacement"
                        case "set_all":
                            headers.set_all("a", ["new", "newer", "newest"])
                        case "remove":
                            del headers["x-a"]
                        case "add":
                            headers.add("x-a", "\u00e9")
                        case "insert":
                            headers.insert(1, "x-a", "middle")
                        case "unchanged":
                            pass
                        case _:
                            self.fail("Unknown corpus operation")
                except (KeyError, TypeError, ValueError) as failure:
                    error = type(failure).__name__
                self.assertEqual(error, case["error"])
                self.assertEqual(snapshot(headers), case["after"])

    def test_adversarial_mapping_contract_matches_reference(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_headers_adversarial_v12.json").read_text()
        )
        module = type("PublicHttp", (), {"Headers": Headers})
        self.assertEqual(corpus["reference"], "mitmproxy 12.3.1")
        self.assertEqual(collect_adversarial(module), corpus["cases"])

    def test_public_types_equality_and_keyword_conversion(self):
        expected = self.corpus["checks"]
        headers = Headers([(b"X", b"one"), (b"x", b"two")])
        self.assertEqual(type(headers.fields).__name__, expected["field_type"])
        self.assertEqual(type(headers.get_state()).__name__, expected["state_type"])
        self.assertEqual(headers["X"], expected["joined"])
        self.assertEqual(headers == Headers([(b"x", b"one"), (b"x", b"two")]), expected["equal_case_change"])
        self.assertEqual(headers == Headers([(b"x", b"two"), (b"X", b"one")]), expected["equal_order_change"])
        self.assertEqual(repr(headers), expected["repr"])
        self.assertEqual(snapshot(Headers(content_type="text/plain", x_test="yes")), expected["keyword"])

    def test_set_all_does_not_consume_callers_list(self):
        values = ["first", "second"]
        headers = Headers([(b"X", b"old")])
        headers.set_all("x", values)
        self.assertEqual(values, ["first", "second"])
        headers.set_all("x", values)
        self.assertEqual(headers.get_all("X"), values)

    def test_invalid_replacement_is_atomic(self):
        headers = Headers([(b"X", b"old"), (b"Y", b"other")])
        original = headers.fields
        with self.assertRaises(TypeError):
            headers.set_all("x", ["valid", object()])
        self.assertEqual(headers.fields, original)

    def test_all_bytes_round_trip_through_text_values(self):
        rng = random.Random(12)
        for _ in range(300):
            payload = rng.randbytes(rng.randrange(512))
            headers = Headers([(b"X", payload)])
            headers["X"] = headers["x"]
            self.assertEqual(headers.fields, ((b"X", payload),))

    def test_snapshot_and_copy_do_not_share_mutations(self):
        headers = Headers([(b"Set-Cookie", b"one=1"), (b"set-cookie", b"two=2")])
        copy = headers.copy()
        restored = Headers.from_state(headers.get_state())
        headers["set-cookie"] = "changed=3"
        self.assertEqual(copy, restored)
        self.assertEqual(copy.get_all("set-cookie"), ["one=1", "two=2"])
        self.assertNotEqual(copy, headers)

    def test_collection_views_state_and_type_errors(self):
        headers = Headers([(b"X", b"one"), (b"x", b"two")])

        self.assertEqual(headers.get_all(b"X"), ["one", "two"])
        self.assertEqual(headers.keys(), ["X"])
        self.assertEqual(headers.keys(multi=True), ["X", "x"])
        self.assertEqual(headers.values(), ["one, two"])
        self.assertEqual(headers.values(multi=True), ["one", "two"])
        self.assertNotEqual(headers, object())

        restored = Headers()
        restored.set_state(headers.get_state())
        self.assertEqual(restored, headers)

        with self.assertRaises(TypeError):
            Headers([("X", b"value")])
        with self.assertRaises(TypeError):
            headers.add("Y", object())
        with self.assertRaises(KeyError):
            _ = headers["missing"]


if __name__ == "__main__":
    unittest.main()
