"""Clean-room DNS model parity and independent wire-codec tests."""

from copy import deepcopy
import ipaddress
import json
from pathlib import Path
import struct
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import addon_connection as connection
import addon_dns as dns
import addon_dns_domain_names as domain_names
from addon_dns_domain_names_contract import collect as collect_domain_names
from addon_dns_https_records_contract import collect as collect_https_records
from addon_flow import Flow
from addon_modules import compatibility_modules


def normalized(value):
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, tuple):
        return {"tuple": [normalized(item) for item in value]}
    if isinstance(value, list):
        return [normalized(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalized(item) for key, item in value.items()}
    return value


def request():
    return dns.DNSMessage(
        id=0x1234,
        query=True,
        op_code=dns.op_codes.QUERY,
        authoritative_answer=False,
        truncation=False,
        recursion_desired=True,
        recursion_available=False,
        reserved=0,
        response_code=dns.response_codes.NOERROR,
        questions=[dns.Question("example.test", dns.types.A, dns.classes.IN)],
        answers=[],
        authorities=[],
        additionals=[],
        timestamp=123.5,
    )


def records():
    return [
        dns.ResourceRecord.A("a.test", ipaddress.IPv4Address("192.0.2.1"), ttl=10),
        dns.ResourceRecord.AAAA("aaaa.test", ipaddress.IPv6Address("2001:db8::1"), ttl=20),
        dns.ResourceRecord.CNAME("alias.test", "target.test", ttl=30),
        dns.ResourceRecord.PTR("1.2.0.192.in-addr.arpa", "ptr.test", ttl=40),
        dns.ResourceRecord.TXT("txt.test", "hello", ttl=50),
        dns.ResourceRecord("unknown.test", 65000, dns.classes.IN, 60, b"\x00\xff"),
    ]


class DNSModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(
            (ROOT / "tests/corpus/addon_dns_model_v12.json").read_text()
        )

    def test_domain_name_helpers_match_reference_contract(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_dns_domain_names_v12.json").read_text()
        )
        self.assertEqual(
            collect_domain_names(domain_names),
            corpus["domain_names"],
        )

    def test_https_record_helpers_match_reference_contract(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_dns_https_records_v12.json").read_text()
        )
        public = compatibility_modules()["mitmproxy.net.dns.https_records"]
        self.assertEqual(
            collect_https_records(public),
            corpus["https_records"],
        )

    def test_https_record_codec_rejects_truncated_parameters(self):
        value = dns.HTTPSRecord(
            1,
            ".",
            {dns.SVCParamKeys.ALPN.value: b"\x02h2", 65000: b"opaque"},
        )
        rendered = value.to_json()
        self.assertEqual(rendered["alpn"], "\\x02h2")
        self.assertEqual(rendered[65000], "opaque")
        restored = dns.HTTPSRecord.from_json(rendered)
        self.assertEqual(restored, value)

        for payload, message in (
            (b"", "truncated HTTPS record"),
            (b"\x00\x01\x00\x00", "truncated HTTPS parameter"),
            (b"\x00\x01\x00\x00\x01\x00\x02x",
             "truncated HTTPS parameter value"),
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(struct.error, message):
                    dns._decode_https_record(payload)

        malformed = dns.ResourceRecord.HTTPS(
            "example.test",
            dns.HTTPSRecord(
                1,
                ".",
                {dns.SVCParamKeys.ALPN.value: b"\x05h2"},
            ),
        )
        with self.assertRaisesRegex(struct.error, "truncated HTTPS ALPN"):
            _ = malformed.https_alpn

    def test_domain_name_codec_rejects_ambiguous_or_truncated_names(self):
        self.assertEqual(dns._encode_domain_name(""), b"\0")
        self.assertEqual(dns._encode_domain_name("."), b"\0")

        for name, message in (
            ("a..b", "Invalid DNS label"),
            ("x" * 64, "Invalid DNS label"),
            (".".join(["x" * 63] * 4), "exceeds 255 wire bytes"),
        ):
            with self.subTest(name_length=len(name)):
                with self.assertRaisesRegex(ValueError, message):
                    dns._encode_domain_name(name)

        malformed = (
            (b"\xc0", "truncated DNS compression pointer"),
            (b"\xc0\xff", "compression pointer is out of bounds"),
            (b"\xc0\x00", "compression pointer loop"),
            (b"\x40", "invalid DNS label length"),
            (b"\x03ab", "truncated DNS label"),
        )
        for payload, message in malformed:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(struct.error, message):
                    dns._decode_domain_name(payload, 0)

        with self.assertRaisesRegex(struct.error, "exceeds record data"):
            dns._decode_domain_name(b"\x03abc\0", 0, limit=3)

    def test_constant_and_conversion_contract(self):
        self.assertEqual(
            {
                "types": {
                    name: getattr(dns.types, name)
                    for name in dns.types._values
                },
                "classes": {
                    name: getattr(dns.classes, name)
                    for name in dns.classes._values
                },
                "op_codes": {
                    name: getattr(dns.op_codes, name)
                    for name in dns.op_codes._values
                },
                "response_codes": {
                    name: getattr(dns.response_codes, name)
                    for name in dns.response_codes._values
                },
            },
            self.corpus["constants"],
        )
        self.assertEqual(dns.types.to_str(65000), "TYPE(65000)")
        self.assertEqual(dns.types.from_str("A"), dns.types.A)
        self.assertEqual(dns.types.from_str("TYPE(65000)"), 65000)
        self.assertEqual(dns.types.from_str("65000"), 65000)
        with self.assertRaises(ValueError):
            dns.types.from_str("a")
        self.assertEqual(dns.response_codes.http_equiv_status_code(
            dns.response_codes.NXDOMAIN), 404)
        self.assertEqual(
            {
                str(value): dns.response_codes.http_equiv_status_code(value)
                for value in range(16)
            },
            self.corpus["model_edges"]["rcode_http_statuses"],
        )

    def test_questions_and_records_match_reference_state_and_json(self):
        value = request().questions[0]
        self.assertEqual(normalized(value.get_state()), self.corpus["question"]["state"])
        self.assertEqual(value.to_json(), self.corpus["question"]["json"])
        self.assertEqual(str(value), self.corpus["question"]["text"])

        for actual, expected in zip(records(), self.corpus["records"]):
            with self.subTest(name=actual.name):
                self.assertEqual(normalized(actual.get_state()), expected["state"])
                self.assertEqual(actual.to_json(), expected["json"])
                self.assertEqual(str(actual), expected["text"])

    def test_request_success_and_failure_match_reference(self):
        query = request()
        self.assertEqual(normalized(query.get_state()), self.corpus["request"]["state"])
        self.assertEqual(query.to_json(), self.corpus["request"]["json"])
        self.assertEqual(query.packed.hex(), self.corpus["request"]["packed"])
        self.assertIs(query.question, query.questions[0])
        self.assertEqual(query.content, query.packed)

        success = query.succeed(records()[:2])
        success.timestamp = 200.0
        self.assertEqual(normalized(success.get_state()), self.corpus["success"]["state"])
        self.assertEqual(success.to_json(), self.corpus["success"]["json"])
        self.assertEqual(success.packed.hex(), self.corpus["success"]["packed"])

        unpacked = dns.DNSMessage.unpack(success.packed, timestamp=456.0)
        self.assertEqual(normalized(unpacked.get_state()),
                         self.corpus["success"]["roundtrip_state"])

        failure = query.fail(dns.response_codes.NXDOMAIN)
        failure.timestamp = 201.0
        self.assertEqual(normalized(failure.get_state()), self.corpus["failure"]["state"])
        self.assertEqual(failure.to_json(), self.corpus["failure"]["json"])

    def test_reference_error_contract(self):
        query = request()
        with self.assertRaisesRegex(ValueError, "Attribute answers must not be None"):
            query.succeed(None)
        with self.assertRaisesRegex(ValueError, "response_code must be an error code"):
            query.fail(dns.response_codes.NOERROR)
        with self.assertRaisesRegex(struct.error, "buffer of 30 bytes"):
            dns.DNSMessage.unpack(query.packed + b"x")
        query.id = 70000
        with self.assertRaisesRegex(ValueError, "id 70000 is out of bounds"):
            _ = query.packed

    def test_unpack_accepts_compression_and_normalizes_record_data(self):
        # question name at offset 12; both the owner and CNAME target point to it.
        question = b"\x07example\x04test\x00" + struct.pack("!HH", 1, 1)
        cname_data = b"\xc0\x0c"
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 30,
                                             len(cname_data)) + cname_data
        packet = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + question + answer
        value = dns.DNSMessage.unpack(packet, timestamp=1)
        self.assertEqual(value.questions[0].name, "example.test")
        self.assertEqual(value.answers[0].name, "example.test")
        self.assertEqual(value.answers[0].domain_name, "example.test")
        self.assertNotIn(b"\xc0\x0c", value.answers[0].data)
        self.assertEqual(dns.DNSMessage.unpack(value.packed, timestamp=2).get_state()[
            "answers"], value.get_state()["answers"])

    def test_txt_wire_format_preserves_public_raw_text_value(self):
        value = request().succeed([dns.ResourceRecord.TXT("txt.test", "hello")])
        self.assertTrue(value.packed.endswith(b"\x00\x05hello"))
        unpacked = dns.DNSMessage.unpack(value.packed, timestamp=1)
        self.assertEqual(unpacked.answers[0].data, b"hello")
        self.assertEqual(unpacked.answers[0].text, "hello")

    def test_message_state_is_consumed_and_content_is_read_only(self):
        value = request()
        state = value.get_state()
        value.set_state(state)
        self.assertEqual(state, {})
        with self.assertRaises(AttributeError):
            value.content = value.packed

        question = dns.Question("example.test", dns.types.A, dns.classes.IN)
        question_state = question.get_state()
        question.set_state(question_state)
        self.assertEqual(question_state, {})

        record = records()[0]
        record_state = record.get_state()
        record.set_state(record_state)
        self.assertEqual(record_state, {})

        edges = self.corpus["model_edges"]
        self.assertEqual(edges["question_set_state_remaining"], {"value": {}})
        self.assertEqual(edges["record_set_state_remaining"], {"value": {}})
        self.assertEqual(edges["message_set_state_remaining"], {"value": {}})
        self.assertEqual(edges["content_assignment"], {
            "error": "AttributeError",
            "message": "property 'content' of 'DNSMessage' object has no setter",
        })

    def test_record_factory_ttl_is_keyword_only(self):
        with self.assertRaises(TypeError):
            dns.ResourceRecord.A("a.test", ipaddress.IPv4Address("192.0.2.1"), 10)
        with self.assertRaises(AttributeError):
            dns.ResourceRecord.A("a.test", "192.0.2.1")
        self.assertEqual(
            dns.ResourceRecord.A(
                name="a.test", ip=ipaddress.IPv4Address("192.0.2.1"), ttl=10
            ).ttl,
            10,
        )
        self.assertEqual(
            dns.ResourceRecord.CNAME(
                alias="alias.test", canonical="target.test"
            ).domain_name,
            "target.test",
        )
        self.assertEqual(
            dns.ResourceRecord.PTR(
                inaddr="1.2.0.192.in-addr.arpa", ptr="ptr.test"
            ).domain_name,
            "ptr.test",
        )
        self.assertEqual(dns.DNSMessage.unpack(buffer=request().packed).id, 0x1234)

    def test_record_properties_and_json_cover_every_supported_kind(self):
        ipv4 = dns.ResourceRecord.A(
            "a.test",
            ipaddress.IPv4Address("192.0.2.1"),
        )
        ipv4.ipv4_address = "198.51.100.2"
        self.assertEqual(str(ipv4.ipv4_address), "198.51.100.2")

        ipv6 = dns.ResourceRecord.AAAA(
            "aaaa.test",
            ipaddress.IPv6Address("2001:db8::1"),
        )
        ipv6.ipv6_address = "2001:db8::2"
        self.assertEqual(str(ipv6.ipv6_address), "2001:db8::2")

        cname = dns.ResourceRecord.CNAME("alias.test", "old.test")
        cname.domain_name = "new.test"
        self.assertEqual(cname.domain_name, "new.test")

        text = dns.ResourceRecord.TXT("txt.test", "old")
        text.text = "new"
        self.assertEqual(text.text, "new")

        values = [ipv4, ipv6, cname, text]
        for value in values:
            with self.subTest(record_type=value.type):
                restored = dns.ResourceRecord.from_json(value.to_json())
                self.assertEqual(restored.get_state(), value.get_state())

        raw = dns.ResourceRecord("raw.test", 65000, dns.classes.IN, 1,
                                 b"\x00\xff")
        self.assertEqual(
            dns.ResourceRecord.from_json(raw.to_json()).data,
            raw.data,
        )
        escaped = raw.to_json()
        escaped["data"] = "plain\\x00value"
        self.assertEqual(
            dns.ResourceRecord.from_json(escaped).data,
            b"plain\x00value",
        )

        cname.data += b"trailing"
        with self.assertRaisesRegex(struct.error, "trailing bytes"):
            _ = cname.domain_name

    def test_message_validates_all_header_bounds_and_required_sections(self):
        for field in ("questions", "answers", "authorities", "additionals"):
            arguments = {
                "id": 1,
                "query": True,
                "op_code": 0,
                "authoritative_answer": False,
                "truncation": False,
                "recursion_desired": False,
                "recursion_available": False,
                "reserved": 0,
                "response_code": 0,
                "questions": [],
                "answers": [],
                "authorities": [],
                "additionals": [],
            }
            arguments[field] = None
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, f"Attribute {field}"):
                    dns.DNSMessage(**arguments)

        for field, value in (
            ("id", -1),
            ("op_code", 16),
            ("reserved", 8),
            ("response_code", 16),
        ):
            value_message = request()
            setattr(value_message, field, value)
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    _ = value_message.packed

        empty = request()
        empty.questions.clear()
        self.assertIsNone(empty.question)
        self.assertEqual(str(empty), f"DNS message {empty.id}")

    def test_wire_decoder_fails_closed_for_each_truncated_section(self):
        with self.assertRaisesRegex(struct.error, "buffer of 12 bytes"):
            dns.DNSMessage.unpack(b"short")

        header = lambda questions=0, answers=0: struct.pack(
            "!HHHHHH", 1, 0, questions, answers, 0, 0
        )
        cases = (
            (header(questions=1) + b"\0", "truncated DNS question"),
            (header(answers=1) + b"\0", "truncated DNS resource record"),
            (header(answers=1) + b"\0"
             + struct.pack("!HHIH", dns.types.A, dns.classes.IN, 1, 2)
             + b"x", "truncated DNS resource data"),
            (header(answers=1) + b"\0"
             + struct.pack("!HHIH", dns.types.CNAME, dns.classes.IN, 1, 3)
             + b"\0xx", "trailing bytes after DNS resource name"),
        )
        for packet, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(struct.error, message):
                    dns.DNSMessage.unpack(packet)

    def test_long_txt_remains_raw_data_on_wire_and_roundtrip(self):
        record = dns.ResourceRecord.TXT("long.test", "x" * 256, ttl=5)
        value = request().succeed([record])
        expected = self.corpus["model_edges"]["long_txt"]
        self.assertEqual(len(record.data), expected["public_data_size"])
        self.assertEqual(value.packed[-260:].hex(), expected["wire_data_suffix"])
        restored = dns.DNSMessage.unpack(value.packed, timestamp=1).answers[0]
        self.assertEqual(len(restored.data), expected["roundtrip_data_size"])
        self.assertEqual(restored.data, record.data)

    def test_public_copy_json_and_offset_helpers_match_reference(self):
        edges = self.corpus["model_edges"]
        query = request()
        answer = records()[0]

        self.assertEqual(normalized(query.questions[0].copy().get_state()),
                         edges["question_copy"])
        self.assertEqual(normalized(dns.Question.from_json(
            query.questions[0].to_json()).get_state()),
            edges["question_from_json"])
        self.assertEqual(normalized(answer.copy().get_state()),
                         edges["record_copy"])
        self.assertEqual(normalized(dns.ResourceRecord.from_json(
            answer.to_json()).get_state()), edges["record_from_json"])
        self.assertEqual(normalized(dns.DNSMessage.from_json(
            query.to_json()).get_state()), edges["message_from_json"])

        prefix = b"prefix"
        suffix = b"suffix"
        offset, restored = dns.DNSMessage.unpack_from(
            prefix + query.packed + suffix, len(prefix), timestamp=456.0
        )
        self.assertEqual(
            {"offset": offset, "state": normalized(restored.get_state())},
            edges["unpack_from"],
        )

    def test_https_record_helpers_match_reference(self):
        expected = self.corpus["https"]
        value = dns.HTTPSRecord(
            1,
            "svc.example",
            {
                dns.SVCParamKeys.ALPN.value: b"\x02h2\x08http/1.1",
                dns.SVCParamKeys.ECH.value: b"echdata",
                dns.SVCParamKeys.PORT.value: b"\x01\xbb",
            },
        )
        record = dns.ResourceRecord.HTTPS("example.test", value, ttl=12)

        self.assertEqual(normalized(value.to_json()), expected["value_json"])
        self.assertEqual(normalized(vars(dns.HTTPSRecord.from_json(
            value.to_json()))), expected["value_from_json"])
        self.assertEqual(normalized(record.get_state()), expected["record_state"])
        self.assertEqual(normalized(record.to_json()), expected["record_json"])
        self.assertEqual(str(record), expected["record_text"])
        self.assertEqual(normalized(dns.ResourceRecord.from_json(
            record.to_json()).get_state()), expected["record_from_json"])
        self.assertEqual(normalized(record.https_alpn), expected["alpn"])
        self.assertEqual(record.https_ech, expected["ech"])

        alpn_record = record.copy()
        alpn_record.https_alpn = (b"h3", b"h2")
        self.assertEqual(normalized(alpn_record.get_state()), expected["set_alpn"])

        ech_record = record.copy()
        ech_record.https_ech = "bmV3LWVjaA=="
        self.assertEqual(normalized(ech_record.get_state()), expected["set_ech"])
        self.assertEqual(
            {name: getattr(dns.SVCParamKeys, name).value
             for name in dns.SVCParamKeys.__members__},
            expected["constants"],
        )

    def test_dns_flow_state_roundtrip_uses_generic_flow_loader(self):
        client = connection.Client(peername=("client", 53000),
                                   sockname=("proxy", 53),
                                   transport_protocol="udp")
        server = connection.Server(address=("resolver", 53),
                                   transport_protocol="udp")
        exchange = dns.DNSFlow(client, server, live=True)
        exchange.request = request()
        exchange.response = request().succeed(records()[:1])
        expected = exchange.get_state()
        consumed = deepcopy(expected)

        restored = Flow.from_state(consumed)
        self.assertEqual(consumed, {})
        self.assertIsInstance(restored, dns.DNSFlow)
        self.assertEqual(restored.get_state(), expected)
        self.assertFalse(restored.live)

    def test_scoped_public_modules_export_dns_without_reference_package(self):
        modules = compatibility_modules()
        public = modules["mitmproxy.dns"]
        self.assertIs(modules["mitmproxy"].dns, public)
        self.assertIs(public.types, modules["mitmproxy.net.dns.types"])
        self.assertEqual(public.types.__name__, "mitmproxy.net.dns.types")
        self.assertIs(public.DNSMessage, dns.DNSMessage)
        self.assertIs(public.HTTPSRecord, dns.HTTPSRecord)
        self.assertIs(
            modules["mitmproxy.net.dns.https_records"].HTTPSRecord,
            dns.HTTPSRecord,
        )
        self.assertEqual(public.response_codes.NXDOMAIN, 3)


if __name__ == "__main__":
    unittest.main()
