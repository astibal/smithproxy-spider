"""Public serialization base contracts observed from mitmproxy 12.3.1."""

from dataclasses import dataclass
from pathlib import Path
import sys
from enum import Enum
import json
from typing import Any, Literal, Sequence
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from addon_certs import Cert
from addon_connection import Client, Connection, ProxyMode, Server
from addon_dns import DNSFlow, DNSMessage, Question, ResourceRecord
from addon_flow import Error, Flow, HTTPFlow, TCPFlow, TCPMessage, UDPFlow, UDPMessage
from addon_http import Headers
from addon_http_message import Message, MessageData, Request, RequestData, Response, ResponseData
from addon_loader import compatibility_imports
from addon_modules import compatibility_modules
from addon_multidict import MultiDict, MultiDictView
from addon_serializable import Serializable, SerializableDataclass
from addon_websocket import WebSocketData, WebSocketMessage
from addon_serializable_contract import collect


@dataclass
class Child(SerializableDataclass):
    value: int


@dataclass
class Sample(SerializableDataclass):
    integer: int
    text: str
    optional: int | None
    numbers: list[int]
    pair: tuple[str, int]
    mapping: dict[str, int]
    child: Child
    children: list[Child]
    maybe_child: Child | None


class Plain(Serializable):
    def __init__(self, state):
        self.state = state

    @classmethod
    def from_state(cls, state):
        return cls(state)

    def get_state(self):
        return self.state

    def set_state(self, state):
        self.state = state


class Choice(Enum):
    FIRST = "first"
    SECOND = "second"


@dataclass
class AdditionalTypes(SerializableDataclass):
    values: Sequence[int]
    choice: Choice
    label: Literal["short", "long"]


class SerializableTests(unittest.TestCase):
    def sample(self):
        return Sample(
            1, "x", None, [2, 3], ("y", 4), {"a": 5},
            Child(6), [Child(7)], Child(8),
        )

    def test_reference_contract(self):
        import addon_serializable

        corpus = json.loads(
            (ROOT / "tests/corpus/addon_serializable_v12.json").read_text()
        )
        self.assertEqual(collect(addon_serializable), corpus["cases"])

    def test_abstract_base_and_copy_contract(self):
        with self.assertRaisesRegex(TypeError, "abstract class Serializable"):
            Serializable()
        original = Plain({"items": []})
        copied = original.copy()
        self.assertIsNot(copied, original)
        self.assertIs(copied.state, original.state)

    def test_dataclass_nested_state_roundtrip(self):
        original = self.sample()
        expected = {
            "integer": 1,
            "text": "x",
            "optional": None,
            "numbers": [2, 3],
            "pair": ("y", 4),
            "mapping": {"a": 5},
            "child": {"value": 6},
            "children": [{"value": 7}],
            "maybe_child": {"value": 8},
        }
        self.assertEqual(original.get_state(), expected)

        state = original.get_state()
        restored = Sample.from_state(state)
        self.assertEqual(restored, original)
        self.assertEqual(state["child"], Child(6))
        self.assertIsNot(restored.child, original.child)
        self.assertIsNot(restored.numbers, original.numbers)

        copied = original.copy()
        self.assertEqual(copied, original)
        self.assertIsNot(copied.child, original.child)
        self.assertIsNot(copied.numbers, original.numbers)

    def test_dataclass_set_state_consumes_input_and_validates_shape(self):
        value = self.sample()
        state = self.sample().get_state()
        state["child"] = {"value": 11}
        state["children"] = [{"value": 12}]
        state["pair"] = ["z", 13]
        value.set_state(state)
        self.assertEqual(state, {})
        self.assertEqual(value.child, Child(11))
        self.assertEqual(value.children, [Child(12)])
        self.assertEqual(value.pair, ("z", 13))

        with self.assertRaises(KeyError):
            value.set_state({"integer": 1})
        invalid = self.sample().get_state()
        invalid["integer"] = "bad"
        with self.assertRaisesRegex(ValueError, "Invalid value for integer"):
            self.sample().set_state(invalid)
        extra = self.sample().get_state()
        extra["extra"] = 1
        with self.assertRaisesRegex(ValueError, "Unexpected fields"):
            self.sample().set_state(extra)

    def test_any_annotation_is_not_silently_serialized(self):
        @dataclass
        class Unsupported(SerializableDataclass):
            value: Any

        with self.assertRaisesRegex(TypeError, "Unexpected type for value"):
            Unsupported("opaque").get_state()

    def test_sequence_enum_literal_and_unsupported_union_contracts(self):
        value = AdditionalTypes([1, 2], Choice.SECOND, "short")
        state = value.get_state()
        self.assertEqual(state, {
            "values": [1, 2], "choice": "second", "label": "short",
        })
        self.assertEqual(AdditionalTypes.from_state(state), value)

        @dataclass
        class BroadUnion(SerializableDataclass):
            value: int | str

        with self.assertRaisesRegex(AssertionError, "only `x \\| None` union"):
            BroadUnion(1).get_state()

        @dataclass
        class VariadicTuple(SerializableDataclass):
            value: tuple[int, ...]

        with self.assertRaisesRegex(TypeError, "Unexpected type for value"):
            VariadicTuple((1, 2)).get_state()

    def test_conversion_rejects_invalid_shapes_at_each_boundary(self):
        @dataclass
        class ReverseOptional(SerializableDataclass):
            value: None | int

        @dataclass
        class OnlyNone(SerializableDataclass):
            value: None

        @dataclass
        class Pair(SerializableDataclass):
            value: tuple[str, int]

        @dataclass
        class Nested(SerializableDataclass):
            value: Child

        self.assertEqual(ReverseOptional(7).get_state(), {"value": 7})

        with self.assertRaisesRegex(ValueError, "must not be None"):
            OnlyNone(None).get_state()
        with self.assertRaisesRegex(ValueError, "Invalid value for value"):
            Pair.from_state({"value": "not-a-pair"})
        with self.assertRaisesRegex(ValueError, "Invalid value for value"):
            Pair.from_state({"value": ["one"]})
        with self.assertRaisesRegex(ValueError, "Invalid value for value"):
            Nested("wrong").get_state()
        with self.assertRaisesRegex(ValueError, "Invalid state"):
            Child.from_state({"value": 1, "extra": 2})

    def test_abstract_method_bodies_fail_if_called_directly(self):
        with self.assertRaises(NotImplementedError):
            Serializable.from_state(None)
        with self.assertRaises(NotImplementedError):
            Serializable.get_state(object())
        with self.assertRaises(NotImplementedError):
            Serializable.set_state(object(), None)

    def test_public_model_uses_the_serializable_hierarchy(self):
        serializable = (
            Headers, MultiDict, MessageData, RequestData, ResponseData,
            Message, Request, Response, Flow, HTTPFlow, TCPMessage, UDPMessage,
            TCPFlow, UDPFlow, DNSFlow, WebSocketMessage, Cert, ProxyMode,
        )
        dataclass_serializable = (
            Error, Connection, Client, Server, WebSocketData,
            Question, ResourceRecord, DNSMessage,
        )
        for value in serializable:
            with self.subTest(type=value.__name__):
                self.assertTrue(issubclass(value, Serializable))
        for value in dataclass_serializable:
            with self.subTest(type=value.__name__):
                self.assertTrue(issubclass(value, SerializableDataclass))
        self.assertFalse(issubclass(MultiDictView, Serializable))

    def test_scoped_public_module_exports_the_same_bases(self):
        modules = compatibility_modules()
        with compatibility_imports(modules):
            from mitmproxy.coretypes import serializable

            self.assertIs(serializable.Serializable, Serializable)
            self.assertIs(serializable.SerializableDataclass, SerializableDataclass)
            self.assertIs(modules["mitmproxy.coretypes"].serializable, serializable)


if __name__ == "__main__":
    unittest.main()
