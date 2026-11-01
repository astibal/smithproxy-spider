"""Clean-room DNS values used by the addon compatibility facade.

The model deliberately owns no sockets and does not enable DNS addon hooks.
It provides the public message/state contract and an independent RFC 1035 wire
codec so a future native DNS transport can hand addons the same objects without
depending on mitmproxy at runtime.
"""

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
import base64
import ipaddress
import random
import struct
import time

from addon_flow import Flow
from addon_serializable import SerializableDataclass
from addon_strutils import bytes_to_escaped_str, escaped_str_to_bytes


class SVCParamKeys(Enum):
    MANDATORY = 0
    ALPN = 1
    NO_DEFAULT_ALPN = 2
    PORT = 3
    IPV4HINT = 4
    ECH = 5
    IPV6HINT = 6


@dataclass
class HTTPSRecord:
    """Structured value carried by HTTPS and SVCB resource records."""

    priority: int
    target_name: str
    params: dict

    def to_json(self):
        result = {
            "target_name": self.target_name,
            "priority": self.priority,
        }
        for key, value in self.params.items():
            try:
                name = SVCParamKeys(key).name.lower()
            except ValueError:
                name = key
            result[name] = bytes_to_escaped_str(value)
        return result

    @classmethod
    def from_json(cls, data):
        values = dict(data)
        target_name = values.pop("target_name")
        priority = values.pop("priority")
        params = {}
        for name, value in values.items():
            if isinstance(name, int):
                key = name
            else:
                key = SVCParamKeys[name.upper()].value
            params[key] = escaped_str_to_bytes(value)
        return cls(priority, target_name, params)


def _encode_https_record(record):
    result = bytearray(struct.pack("!H", record.priority))
    result.extend(_encode_domain_name(record.target_name))
    for key, value in record.params.items():
        result.extend(struct.pack("!HH", key, len(value)))
        result.extend(value)
    return bytes(result)


def _decode_https_record(data):
    if len(data) < 3:
        raise struct.error("truncated HTTPS record")
    priority = struct.unpack_from("!H", data, 0)[0]
    target_name, cursor = _decode_domain_name(data, 2)
    params = {}
    while cursor < len(data):
        if cursor + 4 > len(data):
            raise struct.error("truncated HTTPS parameter")
        key, length = struct.unpack_from("!HH", data, cursor)
        cursor += 4
        end = cursor + length
        if end > len(data):
            raise struct.error("truncated HTTPS parameter value")
        params[key] = data[cursor:end]
        cursor = end
    return HTTPSRecord(priority, target_name, params)


class _Constants:
    """Named integer constants with the conversion helpers used by addons."""

    def __init__(self, names, *, unknown_prefix=None):
        self._names = dict(names)
        self._values = {name: value for value, name in self._names.items()}
        self._unknown_prefix = unknown_prefix

        for value, name in self._names.items():
            setattr(self, name, value)

    def to_str(self, value):
        if value in self._names:
            return self._names[value]
        if self._unknown_prefix is not None:
            return f"{self._unknown_prefix}({value})"
        return str(value)

    def from_str(self, value):
        if value in self._values:
            return self._values[value]
        if (self._unknown_prefix is not None and
                value.startswith(self._unknown_prefix + "(") and
                value.endswith(")")):
            value = value[len(self._unknown_prefix) + 1:-1]
        return int(value)


types = _Constants({
    1: "A",
    2: "NS",
    3: "MD",
    4: "MF",
    5: "CNAME",
    6: "SOA",
    7: "MB",
    8: "MG",
    9: "MR",
    10: "NULL",
    11: "WKS",
    12: "PTR",
    13: "HINFO",
    14: "MINFO",
    15: "MX",
    16: "TXT",
    17: "RP",
    18: "AFSDB",
    19: "X25",
    20: "ISDN",
    21: "RT",
    22: "NSAP",
    23: "NSAP_PTR",
    24: "SIG",
    25: "KEY",
    26: "PX",
    27: "GPOS",
    28: "AAAA",
    29: "LOC",
    30: "NXT",
    31: "EID",
    32: "NIMLOC",
    33: "SRV",
    34: "ATMA",
    35: "NAPTR",
    36: "KX",
    37: "CERT",
    38: "A6",
    39: "DNAME",
    40: "SINK",
    41: "OPT",
    42: "APL",
    43: "DS",
    44: "SSHFP",
    45: "IPSECKEY",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    49: "DHCID",
    50: "NSEC3",
    51: "NSEC3PARAM",
    52: "TLSA",
    53: "SMIMEA",
    55: "HIP",
    56: "NINFO",
    57: "RKEY",
    58: "TALINK",
    59: "CDS",
    60: "CDNSKEY",
    61: "OPENPGPKEY",
    62: "CSYNC",
    63: "ZONEMD",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    100: "UINFO",
    101: "UID",
    102: "GID",
    103: "UNSPEC",
    104: "NID",
    105: "L32",
    106: "L64",
    107: "LP",
    108: "EUI48",
    109: "EUI64",
    249: "TKEY",
    250: "TSIG",
    251: "IXFR",
    252: "AXFR",
    253: "MAILB",
    254: "MAILA",
    255: "ANY",
    256: "URI",
    257: "CAA",
    258: "AVC",
    259: "DOA",
    260: "AMTRELAY",
    32768: "TA",
    32769: "DLV",
}, unknown_prefix="TYPE")

classes = _Constants({1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"},
                     unknown_prefix="CLASS")

op_codes = _Constants({
    0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE", 6: "DSO",
},
                      unknown_prefix="OPCODE")


class _ResponseCodes(_Constants):
    _HTTP_STATUS = {
        0: 200,
        1: 400,
        2: 500,
        3: 404,
        4: 501,
        5: 403,
        6: 409,
        7: 409,
        8: 410,
        9: 401,
        10: 404,
        11: 501,
    }

    def http_equiv_status_code(self, value):
        return self._HTTP_STATUS.get(value, 500)


response_codes = _ResponseCodes({
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
    11: "DSOTYPENI",
}, unknown_prefix="RCODE")


def _encode_domain_name(name):
    """Encode a presentation-format DNS name without compression."""

    if name in ("", "."):
        return b"\x00"

    labels = name.rstrip(".").split(".")
    encoded = bytearray()
    for label in labels:
        try:
            wire_label = label.encode("idna")
        except UnicodeError as exc:
            raise ValueError(f"Invalid DNS label: {label!r}") from exc

        if not wire_label or len(wire_label) > 63:
            raise ValueError(f"Invalid DNS label: {label!r}")
        encoded.append(len(wire_label))
        encoded.extend(wire_label)
    encoded.append(0)

    if len(encoded) > 255:
        raise ValueError("DNS name exceeds 255 wire bytes")
    return bytes(encoded)


def _decode_domain_name(message, offset, *, limit=None):
    """Decode one possibly compressed name and return its consumed offset."""

    labels = []
    cursor = offset
    consumed = None
    seen = set()

    while True:
        if cursor >= len(message) or (limit is not None and consumed is None and cursor >= limit):
            raise struct.error("truncated DNS name")

        length = message[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise struct.error("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= len(message):
                raise struct.error("DNS compression pointer is out of bounds")
            if pointer in seen:
                raise struct.error("DNS compression pointer loop")
            seen.add(pointer)
            if consumed is None:
                consumed = cursor + 2
            cursor = pointer
            continue

        if length & 0xC0:
            raise struct.error("invalid DNS label length")

        cursor += 1
        if length == 0:
            if consumed is None:
                consumed = cursor
            break
        if cursor + length > len(message):
            raise struct.error("truncated DNS label")
        if limit is not None and consumed is None and cursor + length > limit:
            raise struct.error("DNS name exceeds record data")

        label = message[cursor:cursor + length]
        labels.append(label.decode("idna"))
        cursor += length

    return ".".join(labels), consumed


_SINGLE_NAME_RDATA_TYPES = frozenset((
    types.NS,
    types.MD,
    types.MF,
    types.CNAME,
    types.MB,
    types.MG,
    types.MR,
    types.PTR,
))

_TWO_NAME_RDATA_TYPES = frozenset((
    types.MINFO,
    types.RP,
))

_PREFERENCE_NAME_RDATA_TYPES = frozenset((
    types.MX,
    types.AFSDB,
    types.RT,
))


def _decode_rdata_name(message, offset, limit):
    name, consumed = _decode_domain_name(message, offset, limit=limit)
    return _encode_domain_name(name), consumed


def _require_rdata_bytes(offset, size, limit, label):
    end = offset + size
    if end > limit:
        raise struct.error("truncated DNS " + label + " record data")
    return end


def _normalize_single_name_rdata(message, offset, limit):
    name, consumed = _decode_rdata_name(message, offset, limit)
    if consumed != limit:
        raise struct.error("trailing bytes after DNS resource name")
    return name


def _normalize_two_name_rdata(message, offset, limit):
    first, cursor = _decode_rdata_name(message, offset, limit)
    second, cursor = _decode_rdata_name(message, cursor, limit)
    if cursor != limit:
        raise struct.error("trailing bytes after DNS resource names")
    return first + second


def _normalize_prefixed_name_rdata(message, offset, limit, prefix_size, label):
    cursor = _require_rdata_bytes(offset, prefix_size, limit, label)
    prefix = message[offset:cursor]
    name, cursor = _decode_rdata_name(message, cursor, limit)
    if cursor != limit:
        raise struct.error("trailing bytes after DNS resource name")
    return prefix + name


def _normalize_soa_rdata(message, offset, limit):
    primary, cursor = _decode_rdata_name(message, offset, limit)
    responsible, cursor = _decode_rdata_name(message, cursor, limit)
    values_end = _require_rdata_bytes(cursor, 20, limit, "SOA")
    if values_end != limit:
        raise struct.error("trailing bytes after DNS SOA record")
    return primary + responsible + message[cursor:values_end]


def _normalize_px_rdata(message, offset, limit):
    cursor = _require_rdata_bytes(offset, 2, limit, "PX")
    prefix = message[offset:cursor]
    first, cursor = _decode_rdata_name(message, cursor, limit)
    second, cursor = _decode_rdata_name(message, cursor, limit)
    if cursor != limit:
        raise struct.error("trailing bytes after DNS PX record")
    return prefix + first + second


def _skip_character_string(message, offset, limit):
    length_end = _require_rdata_bytes(offset, 1, limit, "NAPTR")
    length = message[offset]
    return _require_rdata_bytes(length_end, length, limit, "NAPTR")


def _normalize_naptr_rdata(message, offset, limit):
    cursor = _require_rdata_bytes(offset, 4, limit, "NAPTR")
    for _ in range(3):
        cursor = _skip_character_string(message, cursor, limit)
    prefix = message[offset:cursor]
    replacement, cursor = _decode_rdata_name(message, cursor, limit)
    if cursor != limit:
        raise struct.error("trailing bytes after DNS NAPTR record")
    return prefix + replacement


def _normalize_record_data(record_type, message, offset, limit):
    """Expand compressed names for the RR formats normalized by mitmproxy."""

    if record_type in _SINGLE_NAME_RDATA_TYPES:
        return _normalize_single_name_rdata(message, offset, limit)
    if record_type in _TWO_NAME_RDATA_TYPES:
        return _normalize_two_name_rdata(message, offset, limit)
    if record_type in _PREFERENCE_NAME_RDATA_TYPES:
        return _normalize_prefixed_name_rdata(
            message,
            offset,
            limit,
            2,
            types.to_str(record_type),
        )
    if record_type == types.SOA:
        return _normalize_soa_rdata(message, offset, limit)
    if record_type == types.PX:
        return _normalize_px_rdata(message, offset, limit)
    if record_type == types.SRV:
        return _normalize_prefixed_name_rdata(
            message,
            offset,
            limit,
            6,
            "SRV",
        )
    if record_type == types.NAPTR:
        return _normalize_naptr_rdata(message, offset, limit)
    return message[offset:limit]


class Question(SerializableDataclass):
    HEADER = struct.Struct("!HH")

    def __init__(self, name, type, class_):
        self.name = name
        self.type = type
        self.class_ = class_

    def __str__(self):
        return self.name

    def get_state(self):
        return {"name": self.name, "type": self.type, "class_": self.class_}

    def set_state(self, state):
        self.name = state.pop("name")
        self.type = state.pop("type")
        self.class_ = state.pop("class_")
        if state:
            raise AssertionError("Unexpected DNS question state fields")

    @classmethod
    def from_state(cls, state):
        result = cls.__new__(cls)
        result.set_state(state)
        return result

    def copy(self):
        return type(self).from_state(deepcopy(self.get_state()))

    @classmethod
    def from_json(cls, data):
        return cls(data["name"], types.from_str(data["type"]),
                   classes.from_str(data["class"]))

    def to_json(self):
        return {
            "name": self.name,
            "type": types.to_str(self.type),
            "class": classes.to_str(self.class_),
        }


class ResourceRecord(SerializableDataclass):
    HEADER = struct.Struct("!HHIH")
    DEFAULT_TTL = 60

    def __init__(self, name, type, class_, ttl, data):
        self.name = name
        self.type = type
        self.class_ = class_
        self.ttl = ttl
        self.data = bytes(data)

    @classmethod
    def A(cls, name, ip, *, ttl=60):
        return cls(name, types.A, classes.IN, ttl, ip.packed)

    @classmethod
    def AAAA(cls, name, ip, *, ttl=60):
        return cls(name, types.AAAA, classes.IN, ttl, ip.packed)

    @classmethod
    def CNAME(cls, alias, canonical, *, ttl=60):
        return cls(alias, types.CNAME, classes.IN, ttl,
                   _encode_domain_name(canonical))

    @classmethod
    def PTR(cls, inaddr, ptr, *, ttl=60):
        return cls(inaddr, types.PTR, classes.IN, ttl,
                   _encode_domain_name(ptr))

    @classmethod
    def TXT(cls, name, text, *, ttl=60):
        return cls(name, types.TXT, classes.IN, ttl, text.encode("utf-8"))

    @classmethod
    def HTTPS(cls, name, record, ttl=60):
        return cls(name, types.HTTPS, classes.IN, ttl,
                   _encode_https_record(record))

    @property
    def ipv4_address(self):
        return ipaddress.IPv4Address(self.data)

    @ipv4_address.setter
    def ipv4_address(self, value):
        self.data = ipaddress.IPv4Address(value).packed

    @property
    def ipv6_address(self):
        return ipaddress.IPv6Address(self.data)

    @ipv6_address.setter
    def ipv6_address(self, value):
        self.data = ipaddress.IPv6Address(value).packed

    @property
    def domain_name(self):
        name, consumed = _decode_domain_name(self.data, 0)
        if consumed != len(self.data):
            raise struct.error("trailing bytes after DNS name")
        return name

    @domain_name.setter
    def domain_name(self, value):
        self.data = _encode_domain_name(value)

    @property
    def text(self):
        return self.data.decode("utf-8")

    @text.setter
    def text(self, value):
        self.data = value.encode("utf-8")

    @property
    def https_alpn(self):
        record = _decode_https_record(self.data)
        value = record.params.get(SVCParamKeys.ALPN.value, b"")
        result = []
        cursor = 0
        while cursor < len(value):
            length = value[cursor]
            cursor += 1
            end = cursor + length
            if end > len(value):
                raise struct.error("truncated HTTPS ALPN value")
            result.append(value[cursor:end])
            cursor = end
        return tuple(result)

    @https_alpn.setter
    def https_alpn(self, values):
        record = _decode_https_record(self.data)
        record.params[SVCParamKeys.ALPN.value] = b"".join(
            bytes((len(value),)) + value for value in values
        )
        self.data = _encode_https_record(record)

    @property
    def https_ech(self):
        record = _decode_https_record(self.data)
        return base64.b64encode(
            record.params.get(SVCParamKeys.ECH.value, b"")
        ).decode()

    @https_ech.setter
    def https_ech(self, value):
        record = _decode_https_record(self.data)
        record.params[SVCParamKeys.ECH.value] = base64.b64decode(value.encode())
        self.data = _encode_https_record(record)

    def __str__(self):
        if self.type == types.A:
            return str(self.ipv4_address)
        if self.type == types.AAAA:
            return str(self.ipv6_address)
        if self.type in (types.CNAME, types.PTR):
            return self.domain_name
        if self.type == types.TXT:
            return self.text
        if self.type == types.HTTPS:
            return str(_decode_https_record(self.data).to_json())
        return f"0x{self.data.hex()}"

    def get_state(self):
        return {
            "name": self.name,
            "type": self.type,
            "class_": self.class_,
            "ttl": self.ttl,
            "data": self.data,
        }

    def set_state(self, state):
        self.name = state.pop("name")
        self.type = state.pop("type")
        self.class_ = state.pop("class_")
        self.ttl = state.pop("ttl")
        self.data = bytes(state.pop("data"))
        if state:
            raise AssertionError("Unexpected DNS resource-record state fields")

    @classmethod
    def from_state(cls, state):
        result = cls.__new__(cls)
        result.set_state(state)
        return result

    def copy(self):
        return type(self).from_state(deepcopy(self.get_state()))

    @classmethod
    def from_json(cls, data):
        record_type = types.from_str(data["type"])
        if record_type == types.A:
            value = ipaddress.IPv4Address(data["data"]).packed
        elif record_type == types.AAAA:
            value = ipaddress.IPv6Address(data["data"]).packed
        elif record_type in (types.CNAME, types.PTR):
            value = _encode_domain_name(data["data"])
        elif record_type == types.TXT:
            value = data["data"].encode("utf-8")
        elif record_type == types.HTTPS:
            value = _encode_https_record(HTTPSRecord.from_json(data["data"]))
        elif data["data"].startswith("0x"):
            value = bytes.fromhex(data["data"][2:])
        else:
            value = escaped_str_to_bytes(data["data"])
        return cls(data["name"], record_type, classes.from_str(data["class"]),
                   data["ttl"], value)

    def to_json(self):
        data = str(self)
        if self.type == types.HTTPS:
            data = _decode_https_record(self.data).to_json()
        return {
            "name": self.name,
            "type": types.to_str(self.type),
            "class": classes.to_str(self.class_),
            "ttl": self.ttl,
            "data": data,
        }


class DNSMessage(SerializableDataclass):
    HEADER = struct.Struct("!HHHHHH")
    timestamp = None
    _SECTIONS = ("questions", "answers", "authorities", "additionals")

    def __init__(self, id, query, op_code, authoritative_answer, truncation,
                 recursion_desired, recursion_available, reserved,
                 response_code, questions, answers, authorities, additionals,
                 timestamp=None):
        self.id = id
        self.query = query
        self.op_code = op_code
        self.authoritative_answer = authoritative_answer
        self.truncation = truncation
        self.recursion_desired = recursion_desired
        self.recursion_available = recursion_available
        self.reserved = reserved
        self.response_code = response_code
        self.questions = self._required_list("questions", questions)
        self.answers = self._required_list("answers", answers)
        self.authorities = self._required_list("authorities", authorities)
        self.additionals = self._required_list("additionals", additionals)
        self.timestamp = time.time() if timestamp is None else timestamp

    @staticmethod
    def _required_list(name, value):
        if value is None:
            raise ValueError(f"Attribute {name} must not be None.")
        return list(value)

    @property
    def question(self):
        if len(self.questions) == 1:
            return self.questions[0]
        return None

    @property
    def size(self):
        records = self.answers + self.authorities + self.additionals
        return sum(len(record.data) for record in records)

    @property
    def content(self):
        return self.packed

    def __str__(self):
        if self.question is not None:
            return str(self.question)
        return f"DNS message {self.id}"

    def get_state(self):
        return {
            "id": self.id,
            "query": self.query,
            "op_code": self.op_code,
            "authoritative_answer": self.authoritative_answer,
            "truncation": self.truncation,
            "recursion_desired": self.recursion_desired,
            "recursion_available": self.recursion_available,
            "reserved": self.reserved,
            "response_code": self.response_code,
            "questions": [item.get_state() for item in self.questions],
            "answers": [item.get_state() for item in self.answers],
            "authorities": [item.get_state() for item in self.authorities],
            "additionals": [item.get_state() for item in self.additionals],
            "timestamp": self.timestamp,
        }

    def set_state(self, state):
        self.id = state.pop("id")
        self.query = state.pop("query")
        self.op_code = state.pop("op_code")
        self.authoritative_answer = state.pop("authoritative_answer")
        self.truncation = state.pop("truncation")
        self.recursion_desired = state.pop("recursion_desired")
        self.recursion_available = state.pop("recursion_available")
        self.reserved = state.pop("reserved")
        self.response_code = state.pop("response_code")
        self.questions = [Question.from_state(item)
                          for item in state.pop("questions")]
        self.answers = [ResourceRecord.from_state(item)
                        for item in state.pop("answers")]
        self.authorities = [ResourceRecord.from_state(item)
                            for item in state.pop("authorities")]
        self.additionals = [ResourceRecord.from_state(item)
                            for item in state.pop("additionals")]
        self.timestamp = state.pop("timestamp")
        if state:
            raise AssertionError("Unexpected DNS message state fields")

    @classmethod
    def from_state(cls, state):
        result = cls.__new__(cls)
        result.set_state(state)
        return result

    def copy(self):
        result = type(self).from_state(deepcopy(self.get_state()))
        result.id = random.randint(0, 65535)
        return result

    def succeed(self, answers):
        answers = self._required_list("answers", answers)
        result = type(self).from_state(deepcopy(self.get_state()))
        result.query = False
        result.authoritative_answer = False
        result.truncation = False
        result.recursion_available = True
        result.response_code = response_codes.NOERROR
        result.answers = answers
        result.authorities = []
        result.additionals = []
        result.timestamp = time.time()
        return result

    def fail(self, response_code):
        if response_code == response_codes.NOERROR:
            raise ValueError("response_code must be an error code.")
        result = type(self).from_state(deepcopy(self.get_state()))
        result.query = False
        result.authoritative_answer = False
        result.truncation = False
        result.response_code = response_code
        result.answers = []
        result.authorities = []
        result.additionals = []
        result.timestamp = time.time()
        return result

    def to_json(self):
        return {
            "id": self.id,
            "query": self.query,
            "op_code": op_codes.to_str(self.op_code),
            "authoritative_answer": self.authoritative_answer,
            "truncation": self.truncation,
            "recursion_desired": self.recursion_desired,
            "recursion_available": self.recursion_available,
            "response_code": response_codes.to_str(self.response_code),
            "status_code": response_codes.http_equiv_status_code(self.response_code),
            "questions": [item.to_json() for item in self.questions],
            "answers": [item.to_json() for item in self.answers],
            "authorities": [item.to_json() for item in self.authorities],
            "additionals": [item.to_json() for item in self.additionals],
            "size": self.size,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_json(cls, data):
        return cls(
            id=data["id"],
            query=data["query"],
            op_code=op_codes.from_str(data["op_code"]),
            authoritative_answer=data["authoritative_answer"],
            truncation=data["truncation"],
            recursion_desired=data["recursion_desired"],
            recursion_available=data["recursion_available"],
            reserved=0,
            response_code=response_codes.from_str(data["response_code"]),
            questions=[Question.from_json(item) for item in data["questions"]],
            answers=[ResourceRecord.from_json(item) for item in data["answers"]],
            authorities=[ResourceRecord.from_json(item)
                         for item in data["authorities"]],
            additionals=[ResourceRecord.from_json(item)
                         for item in data["additionals"]],
            timestamp=data.get("timestamp"),
        )

    def _validated_header(self):
        bounds = (
            ("id", self.id, 16),
            ("op_code", self.op_code, 4),
            ("reserved", self.reserved, 3),
            ("response_code", self.response_code, 4),
        )
        for name, value, bits in bounds:
            if not 0 <= value < (1 << bits):
                if name == "id":
                    raise ValueError(f"DNS message's id {value} is out of bounds.")
                raise ValueError(f"DNS message's {name} {value} is out of bounds.")

        flags = self.op_code << 11
        flags |= int(not self.query) << 15
        flags |= int(self.authoritative_answer) << 10
        flags |= int(self.truncation) << 9
        flags |= int(self.recursion_desired) << 8
        flags |= int(self.recursion_available) << 7
        flags |= self.reserved << 4
        flags |= self.response_code
        return flags

    @property
    def packed(self):
        flags = self._validated_header()
        result = bytearray(struct.pack(
            "!HHHHHH", self.id, flags, len(self.questions), len(self.answers),
            len(self.authorities), len(self.additionals)))

        for question in self.questions:
            result.extend(_encode_domain_name(question.name))
            result.extend(struct.pack("!HH", question.type, question.class_))

        for section in (self.answers, self.authorities, self.additionals):
            for record in section:
                wire_data = record.data
                result.extend(_encode_domain_name(record.name))
                result.extend(struct.pack("!HHIH", record.type, record.class_,
                                          record.ttl, len(wire_data)))
                result.extend(wire_data)
        return bytes(result)

    @classmethod
    def unpack(cls, buffer, timestamp=None):
        cursor, result = cls.unpack_from(buffer, 0, timestamp)
        if cursor != len(buffer):
            raise struct.error(f"unpack requires a buffer of {cursor} bytes")
        return result

    @classmethod
    def unpack_from(cls, buffer, offset, timestamp=None):
        content = bytes(buffer)[offset:]
        if len(content) < 12:
            raise struct.error("unpack requires a buffer of 12 bytes")

        id, flags, question_count, answer_count, authority_count, additional_count = \
            struct.unpack_from("!HHHHHH", content, 0)
        cursor = 12

        questions = []
        for _ in range(question_count):
            name, cursor = _decode_domain_name(content, cursor)
            if cursor + 4 > len(content):
                raise struct.error("truncated DNS question")
            record_type, record_class = struct.unpack_from("!HH", content, cursor)
            cursor += 4
            questions.append(Question(name, record_type, record_class))

        sections = []
        for count in (answer_count, authority_count, additional_count):
            records = []
            for _ in range(count):
                name, cursor = _decode_domain_name(content, cursor)
                if cursor + 10 > len(content):
                    raise struct.error("truncated DNS resource record")
                record_type, record_class, ttl, data_length = struct.unpack_from(
                    "!HHIH", content, cursor)
                cursor += 10
                data_end = cursor + data_length
                if data_end > len(content):
                    raise struct.error("truncated DNS resource data")

                data = _normalize_record_data(
                    record_type,
                    content,
                    cursor,
                    data_end,
                )

                cursor = data_end
                records.append(ResourceRecord(name, record_type, record_class,
                                              ttl, data))
            sections.append(records)

        result = cls(
            id=id,
            query=not bool(flags & 0x8000),
            op_code=(flags >> 11) & 0x0F,
            authoritative_answer=bool(flags & 0x0400),
            truncation=bool(flags & 0x0200),
            recursion_desired=bool(flags & 0x0100),
            recursion_available=bool(flags & 0x0080),
            reserved=(flags >> 4) & 0x07,
            response_code=flags & 0x0F,
            questions=questions,
            answers=sections[0],
            authorities=sections[1],
            additionals=sections[2],
            timestamp=time.time() if timestamp is None else timestamp,
        )
        return offset + cursor, result


class DNSFlow(Flow):
    """Detached DNS exchange state; native transport support is separate."""

    type = "dns"
    response = None

    def __init__(self, client_conn, server_conn, live=False):
        super().__init__(client_conn, server_conn, live)

    def get_state(self):
        state = super().get_state()
        state["request"] = None if self.request is None else self.request.get_state()
        state["response"] = None if self.response is None else self.response.get_state()
        return state

    def set_state(self, state):
        request = state.pop("request")
        response = state.pop("response")
        self.request = None if request is None else DNSMessage.from_state(request)
        self.response = None if response is None else DNSMessage.from_state(response)
        super().set_state(state)
