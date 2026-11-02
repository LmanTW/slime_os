"""Writing `contracts/frame-store/v1` stores from MCAP bags.

This module holds what the converter and the fixture writer share:

* an MCAP reader (https://mcap.dev/spec) for uncompressed bags, which reads the data section's
  records in file order and refuses any compressed chunk;
* the RIHS01 type hash of a ROS 2 message type, computed from its ros2msg schema text the way
  `rosidl_generator_type_description` computes it;
* the canonical encoder of a frame store, written from the generated contract module.

Every refusal is a `Refused` whose `kind` is one of `REFUSAL_CLASSES`. Nothing here imports the
frame-store exam: the exam judges this code with its own MCAP reader and its own decoder.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import frame_store_contract as contract  # noqa: E402  (generated from contracts/frame-store/v1)

REFUSAL_CLASSES = ("bag-hash", "bag", "compressed-chunk", "channel", "schema", "bound", "period")


class Refused(Exception):
    def __init__(self, kind: str, detail: str):
        assert kind in REFUSAL_CLASSES, kind
        super().__init__(detail)
        self.kind = kind


# MCAP.

MAGIC = b"\x89MCAP0\r\n"
OP_HEADER, OP_FOOTER, OP_SCHEMA, OP_CHANNEL, OP_MESSAGE, OP_CHUNK, OP_DATA_END = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F


@dataclass(frozen=True)
class Schema:
    name: str
    encoding: str
    data: bytes


@dataclass(frozen=True)
class Channel:
    topic: str
    schema_id: int
    message_encoding: str


@dataclass(frozen=True)
class Message:
    channel_id: int
    log_time: int
    data: bytes


class _Reader:
    def __init__(self, data: bytes, start: int, end: int):
        self.data, self.at, self.end = data, start, end

    def take(self, count: int) -> bytes:
        if count < 0 or self.at + count > self.end:
            raise Refused("bag", f"a record field runs past its record at byte {self.at}")
        value = self.data[self.at:self.at + count]
        self.at += count
        return value

    def unpack(self, form: str) -> tuple:
        return struct.unpack("<" + form, self.take(struct.calcsize("<" + form)))

    def text(self) -> str:
        (length,) = self.unpack("I")
        try:
            return self.take(length).decode("utf-8")
        except UnicodeDecodeError as error:
            raise Refused("bag", "a record holds a string that is not UTF-8") from error


def _records(data: bytes, start: int, end: int):
    at = start
    while at < end:
        if end - at < 9:
            raise Refused("bag", f"a record header at byte {at} runs past its container")
        opcode, length = struct.unpack_from("<BQ", data, at)
        body = at + 9
        if length > end - body:
            raise Refused("bag", f"record 0x{opcode:02x} at byte {at} runs past its container")
        yield opcode, body, body + length
        at = body + length


@dataclass
class Bag:
    schemas: dict[int, Schema]
    channels: dict[int, Channel]
    messages: list[Message]


def read_bag(data: bytes) -> Bag:
    """Every schema, channel and message in the data section, in file order."""
    if len(data) < 2 * len(MAGIC) or not data.startswith(MAGIC) or not data.endswith(MAGIC):
        raise Refused("bag", "the file does not start and end with the MCAP magic")
    bag = Bag({}, {}, [])
    records = _records(data, len(MAGIC), len(data) - len(MAGIC))
    first = next(records, None)
    if first is None or first[0] != OP_HEADER:
        raise Refused("bag", "the first record is not a header")
    for opcode, start, end in records:
        if opcode == OP_DATA_END:
            return bag
        if opcode == OP_CHUNK:
            _read_chunk(bag, data, start, end)
        elif opcode in (OP_SCHEMA, OP_CHANNEL, OP_MESSAGE):
            _read_definition(bag, opcode, data, start, end)
        elif opcode in (OP_FOOTER,):
            break
    raise Refused("bag", "the data section has no data end record")


def _read_chunk(bag: Bag, data: bytes, start: int, end: int) -> None:
    reader = _Reader(data, start, end)
    _, _, uncompressed_size, crc = reader.unpack("QQQI")
    compression = reader.text()
    (length,) = reader.unpack("Q")
    records_start = reader.at
    reader.take(length)
    if compression:
        raise Refused("compressed-chunk", f"a chunk is compressed with {compression!r}")
    if length != uncompressed_size or reader.at != end:
        raise Refused("bag", "a chunk's records do not match its declared size")
    if crc and zlib.crc32(data[records_start:records_start + length]) != crc:
        raise Refused("bag", "a chunk's CRC does not match")
    for opcode, record_start, record_end in _records(data, records_start, records_start + length):
        if opcode not in (OP_SCHEMA, OP_CHANNEL, OP_MESSAGE):
            raise Refused("bag", f"record 0x{opcode:02x} may not sit in a chunk")
        _read_definition(bag, opcode, data, record_start, record_end)


def _read_definition(bag: Bag, opcode: int, data: bytes, start: int, end: int) -> None:
    reader = _Reader(data, start, end)
    if opcode == OP_SCHEMA:
        (schema_id,) = reader.unpack("H")
        name, encoding = reader.text(), reader.text()
        (length,) = reader.unpack("I")
        _declare(bag.schemas, schema_id, Schema(name, encoding, reader.take(length)), "schema")
    elif opcode == OP_CHANNEL:
        channel_id, schema_id = reader.unpack("HH")
        topic, encoding = reader.text(), reader.text()
        (length,) = reader.unpack("I")
        reader.take(length)
        _declare(bag.channels, channel_id, Channel(topic, schema_id, encoding), "channel")
    else:
        channel_id, _, log_time, _ = reader.unpack("HIQQ")
        if channel_id not in bag.channels:
            raise Refused("bag", f"a message names undeclared channel {channel_id}")
        bag.messages.append(Message(channel_id, log_time, data[reader.at:end]))
        return
    if reader.at != end:
        raise Refused("bag", "a record leaves unread bytes")


def _declare(table: dict, key: int, value, what: str) -> None:
    if table.setdefault(key, value) != value:
        raise Refused("bag", f"{what} {key} is declared twice with different content")


# RIHS01.

NESTED = 1
PRIMITIVES = {
    "int8": 2, "uint8": 3, "int16": 4, "uint16": 5, "int32": 6, "uint32": 7, "int64": 8, "uint64": 9,
    "float32": 10, "float64": 11, "char": 3, "bool": 15, "byte": 16, "string": 17, "wstring": 18,
}
BOUNDED_STRING = {"string": 21, "wstring": 22}
FIXED_ARRAY, BOUNDED_SEQUENCE, UNBOUNDED_SEQUENCE = 48, 96, 144
SEPARATOR = re.compile(r"^=+$")
TYPE = re.compile(
    r"^(?P<base>[A-Za-z][A-Za-z0-9_]*(?:/[A-Za-z][A-Za-z0-9_]*){0,2})"
    r"(?:<=(?P<string_bound>\d+))?"
    r"(?:\[(?P<array>(?:<=)?\d*)\])?$"
)
NAME = re.compile(r"^[a-z][a-z0-9_]*$")


def _full_name(name: str, package: str) -> str:
    parts = name.split("/")
    if len(parts) == 1:
        return f"{package}/msg/{parts[0]}"
    if len(parts) == 2:
        return f"{parts[0]}/msg/{parts[1]}"
    if parts[1] != "msg":
        raise Refused("schema", f"{name} is not a message type")
    return name


def _field(token: str, name: str, package: str) -> dict:
    match = TYPE.fullmatch(token)
    if match is None or NAME.fullmatch(name) is None:
        raise Refused("schema", f"cannot read the field {token} {name}")
    base, string_bound, array = match["base"], match["string_bound"], match["array"]
    string_capacity = 0
    nested = ""
    if string_bound is not None:
        if base not in BOUNDED_STRING:
            raise Refused("schema", f"{base} cannot take a bound")
        type_id, string_capacity = BOUNDED_STRING[base], int(string_bound)
    elif base in PRIMITIVES:
        type_id = PRIMITIVES[base]
    else:
        type_id, nested = NESTED, _full_name(base, package)
    capacity = 0
    if array is not None:
        if array == "":
            type_id += UNBOUNDED_SEQUENCE
        elif array.startswith("<="):
            type_id, capacity = type_id + BOUNDED_SEQUENCE, int(array[2:])
        else:
            type_id, capacity = type_id + FIXED_ARRAY, int(array)
    return {
        "name": name,
        "type": {"type_id": type_id, "capacity": capacity, "string_capacity": string_capacity, "nested_type_name": nested},
    }


def _fields(text: str, type_name: str) -> list[dict]:
    package = type_name.split("/")[0]
    fields = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise Refused("schema", f"cannot read the line {line!r} of {type_name}")
        token, rest = parts
        name = re.split(r"[\s=#]", rest, maxsplit=1)[0]
        if rest[len(name):].lstrip().startswith("="):
            continue  # a constant, which a type description does not hold
        fields.append(_field(token, name, package))
    if not fields:
        # rosidl gives an empty structure one member, and its description records it.
        fields.append(_field("uint8", "structure_needs_at_least_one_member", package))
    return fields


def _definitions(type_name: str, schema: str) -> dict[str, str]:
    """The ros2msg text of each type the schema defines, by full type name."""
    sections: dict[str, str] = {}
    current, lines = type_name, []
    for line in schema.splitlines():
        if SEPARATOR.match(line.strip()):
            sections[current] = "\n".join(lines)
            current, lines = None, []
            continue
        if current is None:
            header = line.strip()
            if not header.startswith("MSG: "):
                raise Refused("schema", f"a dependency section starts with {header!r}, not MSG:")
            current = _full_name(header[len("MSG: "):].strip(), "")
            if current in sections:
                raise Refused("schema", f"{current} is defined twice")
            continue
        lines.append(line)
    if current is None:
        raise Refused("schema", "the schema ends with a separator")
    sections[current] = "\n".join(lines)
    return sections


def rihs01(type_name: str, schema: str) -> bytes:
    """The RIHS01 digest of `type_name`, whose ros2msg text with dependencies is `schema`."""
    full = _full_name(type_name, "")
    definitions = _definitions(full, schema)
    described: dict[str, dict] = {}
    pending = [full]
    while pending:
        name = pending.pop()
        if name in described:
            continue
        if name not in definitions:
            raise Refused("schema", f"the schema does not define {name}")
        fields = _fields(definitions[name], name)
        described[name] = {"type_name": name, "fields": fields}
        pending.extend(f["type"]["nested_type_name"] for f in fields if f["type"]["nested_type_name"])
    main = described.pop(full)
    referenced = [described[name] for name in sorted(described)]
    text = json.dumps(
        {"type_description": main, "referenced_type_descriptions": referenced},
        ensure_ascii=True, allow_nan=False, indent=None, separators=(", ", ": "), sort_keys=False,
    )
    return hashlib.sha256(text.encode("utf-8")).digest()


# The store.

def align(value: int) -> int:
    return (value + contract.ALIGNMENT - 1) // contract.ALIGNMENT * contract.ALIGNMENT


@dataclass(frozen=True)
class Store:
    topic: str
    type_name: str
    schema: str
    period_ns: int
    frames: tuple[tuple[int, bytes], ...]  # (log time, CDR payload), in log-time order


def encode(store: Store) -> bytes:
    """The canonical encoding of `store`. Refuses a store outside the contract's bounds."""
    texts = [store.topic.encode(), store.type_name.encode(), store.schema.encode()]
    bounds = (contract.MAX_TOPIC_BYTES, contract.MAX_TYPE_NAME_BYTES, contract.MAX_SCHEMA_BYTES)
    for raw, bound in zip(texts, bounds, strict=True):
        if not 1 <= len(raw) <= bound or b"\x00" in raw:
            raise Refused("bound", f"a text of {len(raw)} bytes is outside 1..{bound} or holds a NUL")
    if not 1 <= len(store.frames) <= contract.MAX_FRAMES:
        raise Refused("bound", f"{len(store.frames)} frames is outside 1..{contract.MAX_FRAMES}")
    if any(len(payload) > contract.MAX_PAYLOAD_BYTES for _, payload in store.frames):
        raise Refused("bound", f"a payload is above {contract.MAX_PAYLOAD_BYTES} bytes")
    if any(b[0] < a[0] for a, b in zip(store.frames, store.frames[1:], strict=False)):
        raise Refused("bound", "the frames are not in log-time order")
    text_end = contract.HEADER_BYTES + sum(len(raw) for raw in texts)
    data_start = align(text_end) + contract.INDEX_ENTRY_BYTES * len(store.frames)
    total = data_start + sum(align(len(payload)) for _, payload in store.frames)
    if total > contract.MAX_STORE_BYTES:
        raise Refused("bound", f"the store would be {total} bytes, above {contract.MAX_STORE_BYTES}")
    hash_digest = rihs01(store.type_name, store.schema)
    out = bytearray(
        contract.FRAME_STORE_HEADER.pack(
            contract.FRAME_STORE_MAGIC, contract.FORMAT_VERSION, contract.HASH_VERSION_RIHS01, b"\x00",
            len(store.frames), len(texts[0]), len(texts[1]), len(texts[2]), bytes(4), store.period_ns, hash_digest,
        )
    )
    out += b"".join(texts)
    out += bytes(align(len(out)) - len(out))
    cursor = data_start
    for log_time, payload in store.frames:
        out += contract.FRAME_INDEX_ENTRY.pack(cursor, len(payload), bytes(4), log_time)
        cursor = align(cursor + len(payload))
    for _, payload in store.frames:
        out += payload + bytes(align(len(payload)) - len(payload))
    assert len(out) == total
    return bytes(out)


class InvalidStore(Exception):
    """A byte string that is not a frame store; `kind` is one of the contract's refusal classes."""

    def __init__(self, kind: str, detail: str):
        assert kind in contract.REFUSAL_CLASSES, kind
        super().__init__(f"{kind}: {detail}")
        self.kind = kind


def _text(raw: bytes, what: str) -> None:
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InvalidStore("header", f"the {what} is not UTF-8") from error
    if b"\x00" in raw:
        raise InvalidStore("header", f"the {what} holds a NUL")


def validate(data: bytes) -> None:
    """Checks `data` as a frame store in the contract's order, as the Rust reader does, and raises
    `InvalidStore` with the class of the first check that fails."""
    size = len(data)
    if size > contract.MAX_STORE_BYTES:
        raise InvalidStore("store-bound", f"{size} bytes")
    if size < contract.HEADER_BYTES:
        raise InvalidStore("truncated", "shorter than the header")
    (magic, version, hash_version, reserved0, count, topic_len, type_len, schema_len, reserved1, period,
     _type_hash) = contract.FRAME_STORE_HEADER.unpack_from(data)
    if magic != contract.FRAME_STORE_MAGIC:
        raise InvalidStore("magic", f"magic {magic:#x}")
    if version != contract.FORMAT_VERSION:
        raise InvalidStore("version", f"version {version}")
    if hash_version != contract.HASH_VERSION_RIHS01 or any(reserved0) or any(reserved1) or period == 0:
        raise InvalidStore("header", "the hash version, a reserved field or the period")
    for length, bound in ((topic_len, contract.MAX_TOPIC_BYTES), (type_len, contract.MAX_TYPE_NAME_BYTES),
                          (schema_len, contract.MAX_SCHEMA_BYTES)):
        if not 1 <= length <= bound:
            raise InvalidStore("header", f"a text length {length} outside 1..{bound}")
    if not 1 <= count <= contract.MAX_FRAMES:
        raise InvalidStore("frame-count", f"{count} frames")
    topic_end = contract.HEADER_BYTES + topic_len
    type_end = topic_end + type_len
    text_end = type_end + schema_len
    index_start = align(text_end)
    data_start = index_start + contract.INDEX_ENTRY_BYTES * count
    if size < data_start:
        raise InvalidStore("truncated", "the store ends inside its index")
    _text(data[contract.HEADER_BYTES:topic_end], "topic")
    _text(data[topic_end:type_end], "type name")
    _text(data[type_end:text_end], "schema")
    if any(data[text_end:index_start]):
        raise InvalidStore("header", "a byte before the index is not zero")
    cursor = previous_end = data_start
    previous_time = None
    for index in range(count):
        offset, length, reserved, log_time = contract.FRAME_INDEX_ENTRY.unpack_from(
            data, index_start + contract.INDEX_ENTRY_BYTES * index)
        if any(reserved):
            raise InvalidStore("header", f"entry {index} has a reserved byte set")
        if length > contract.MAX_PAYLOAD_BYTES:
            raise InvalidStore("payload-bound", f"entry {index} holds {length} bytes")
        if previous_time is not None and log_time < previous_time:
            raise InvalidStore("order", f"entry {index} is earlier than entry {index - 1}")
        if offset > size or length > size - offset:
            raise InvalidStore("range", f"entry {index} ends past the store")
        if offset < cursor:
            raise InvalidStore("overlap", f"entry {index} starts before {cursor}")
        if offset > cursor or any(data[previous_end:offset]):
            raise InvalidStore("padding", f"entry {index} is not at the aligned end of the previous payload")
        previous_time = log_time
        previous_end = offset + length
        cursor = align(previous_end)
    if any(data[previous_end:min(cursor, size)]):
        raise InvalidStore("padding", "a byte after the last payload is not zero")
    if size < cursor:
        raise InvalidStore("range", "the store ends inside its last payload's padding")
    if size > cursor:
        raise InvalidStore("trailing", f"{size - cursor} bytes after the last payload")


def store_from_bag(bag: Bag, topic: str) -> Store:
    """The store for one channel: its messages in log-time order, file order among equal times.

    The declared period is the mean log-time step, rounded down: (last - first) / (frames - 1).
    """
    channels = [channel_id for channel_id, channel in bag.channels.items() if channel.topic == topic]
    if len(channels) != 1:
        raise Refused("channel", f"{len(channels)} channels carry {topic!r}")
    channel = bag.channels[channels[0]]
    schema = bag.schemas.get(channel.schema_id)
    if channel.message_encoding != "cdr" or schema is None or schema.encoding != "ros2msg":
        raise Refused("channel", f"{topic} is not CDR with a ros2msg schema")
    messages = sorted((m for m in bag.messages if m.channel_id == channels[0]), key=lambda m: m.log_time)
    if len(messages) < 2 or messages[-1].log_time == messages[0].log_time:
        raise Refused("period", f"{topic} has fewer than two distinct log times, so it has no period")
    period = (messages[-1].log_time - messages[0].log_time) // (len(messages) - 1)
    try:
        schema_text = schema.data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refused("schema", "the schema text is not UTF-8") from error
    return Store(topic, schema.name, schema_text, period, tuple((m.log_time, m.data) for m in messages))
