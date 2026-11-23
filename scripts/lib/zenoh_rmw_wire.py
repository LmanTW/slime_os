"""Host reference for the Zenoh messages an rmw_zenoh peer sends while it sets a session up.

`zenoh_wire.py` encodes the subset Profile 0 admitted for the demo. An rmw_zenoh 0.6.10 peer (zenoh
1.10.1) adds INIT extensions, key-expression aliases, and queryable and liveliness-token declarations.
This module reads those from bytes and writes them back, from the eclipse-zenoh wire layout and the bytes
the peer sent, never from the Rust decoder. `rebuild` re-encodes what `frame` read, so a reader and a
writer that agree with each other and with the capture cannot both be wrong the same way.

Layouts, as the captured bytes show them:

  INIT_SYN   <0xc1><version><zidlen-1 << 4 | whatami><zid><resolution><batch:u16le><extensions>
  FRAME      <0x25><sn:leb128> <network message>*          (reliable, no extension: INIT_ACK offered none)
  DECLARE    <0x1e | N interest | Z> [<interest id>] [<0x21><qos:leb128>] <declaration>
  D_KEYEXPR  <0x20><id><scope 0><keylen><key>
  D_SUBSCRIBER, D_QUERYABLE, D_TOKEN
             <kind | N suffix | M mapping | Z><id><scope> [<keylen><suffix>] [extensions]
  U_KEYEXPR, U_SUBSCRIBER, U_QUERYABLE, U_TOKEN
             <kind | Z><id> [extensions]
  D_FINAL    <0x1a>, behind a DECLARE with the interest bit
  PUSH       <0x1d | N | M | Z><scope> [<keylen><suffix>] [extensions] <Put>
"""

from __future__ import annotations

from dataclasses import dataclass

ID_INIT, ID_OPEN, ID_CLOSE, ID_FRAME = 1, 2, 3, 5
ID_PUSH, ID_DECLARE = 0x1D, 0x1E
D_KEYEXPR, U_KEYEXPR, D_SUBSCRIBER, U_SUBSCRIBER, D_QUERYABLE, U_QUERYABLE, D_TOKEN, U_TOKEN, D_FINAL = 0, 1, 2, 3, 4, 5, 6, 7, 0x1A
NAMES = {
    D_KEYEXPR: "keyexpr",
    U_KEYEXPR: "unkeyexpr",
    D_SUBSCRIBER: "subscriber",
    U_SUBSCRIBER: "unsubscriber",
    D_QUERYABLE: "queryable",
    U_QUERYABLE: "unqueryable",
    D_TOKEN: "token",
    U_TOKEN: "untoken",
    D_FINAL: "final",
}
WITH_KEY = (D_SUBSCRIBER, D_QUERYABLE, D_TOKEN)
WITH_KEY_NAMES = tuple(NAMES[code] for code in WITH_KEY)
BY_ID = (U_KEYEXPR, U_SUBSCRIBER, U_QUERYABLE, U_TOKEN)
FLAG_N, FLAG_M, FLAG_Z = 0x20, 0x40, 0x80
EXT_QOS = 1
ENC_UNIT, ENC_Z64, ENC_ZBUF = 0, 1, 2


class RmwWireError(ValueError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RmwWireError(message)


def leb128(value: int) -> bytes:
    _need(value >= 0, "negative LEB128")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def left(self) -> int:
        return len(self.data) - self.at

    def u8(self) -> int:
        _need(self.left() >= 1, "truncated")
        value = self.data[self.at]
        self.at += 1
        return value

    def take(self, count: int) -> bytes:
        _need(self.left() >= count, "truncated")
        chunk = self.data[self.at : self.at + count]
        self.at += count
        return chunk

    def leb(self) -> int:
        start = self.at
        value = shift = 0
        while True:
            byte = self.u8()
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
            _need(shift <= 63, "LEB128 over 63 bits")
        _need(self.at - start == len(leb128(value)), "non-canonical LEB128")
        return value


@dataclass(frozen=True)
class Extension:
    ident: int
    mandatory: bool
    encoding: int
    value: int | bytes | None


def extensions(reader: Reader) -> tuple[Extension, ...]:
    """A chain: id in the low 4 bits, mandatory in bit 4, encoding in bits 5 and 6, more in bit 7."""
    out: list[Extension] = []
    while True:
        header = reader.u8()
        encoding = (header >> 5) & 3
        if encoding == ENC_UNIT:
            value: int | bytes | None = None
        elif encoding == ENC_Z64:
            value = reader.leb()
        elif encoding == ENC_ZBUF:
            value = reader.take(reader.leb())
        else:
            raise RmwWireError("reserved extension encoding")
        out.append(Extension(header & 0x0F, bool(header & 0x10), encoding, value))
        if not header & 0x80:
            return tuple(out)


def encode_extensions(chain: tuple[Extension, ...]) -> bytes:
    out = bytearray()
    for index, extension in enumerate(chain):
        header = extension.ident | (0x10 if extension.mandatory else 0) | (extension.encoding << 5)
        header |= 0x80 if index + 1 < len(chain) else 0
        out.append(header)
        if extension.encoding == ENC_Z64:
            out += leb128(int(extension.value))  # type: ignore[arg-type]
        elif extension.encoding == ENC_ZBUF:
            raw = bytes(extension.value)  # type: ignore[arg-type]
            out += leb128(len(raw)) + raw
    return bytes(out)


@dataclass(frozen=True)
class Init:
    zid: bytes
    whatami: int
    resolution: int
    batch: int
    extensions: tuple[Extension, ...]
    cookie: bytes | None = None


def _init(batch: bytes, ack: bool) -> Init:
    reader = Reader(batch)
    header = reader.u8()
    _need(header & 0x1F == ID_INIT and bool(header & FLAG_N) == ack, "not an INIT_ACK" if ack else "not an INIT_SYN")
    _need(reader.u8() == 9, "the wire version is not 9")
    packed = reader.u8()
    _need(packed & 0x0C == 0, "reserved bits in the INIT identity byte")
    zid = reader.take(1 + (packed >> 4))
    resolution, size = 10, 0xFFFF
    if header & FLAG_M:
        resolution = reader.u8()
        size = int.from_bytes(reader.take(2), "little")
    cookie = reader.take(reader.leb()) if ack else None
    chain = extensions(reader) if header & FLAG_Z else ()
    _need(reader.left() == 0, "bytes after the INIT")
    return Init(zid, packed & 3, resolution, size, chain, cookie)


def init_syn(batch: bytes) -> Init:
    return _init(batch, False)


def init_ack(batch: bytes) -> Init:
    return _init(batch, True)


def open_syn_cookie(batch: bytes) -> bytes:
    """The cookie an OPEN_SYN echoes: <hdr><lease><initial sn><cookie>."""
    reader = Reader(batch)
    header = reader.u8()
    _need(header & 0x1F == ID_OPEN and not header & FLAG_N, "not an OPEN_SYN")
    reader.leb()
    reader.leb()
    cookie = reader.take(reader.leb())
    _need(reader.left() == 0 and not header & FLAG_Z, "an OPEN_SYN with an extension or trailing bytes")
    return cookie


@dataclass(frozen=True)
class Message:
    """One network message of a FRAME, reduced to the facts an exam compares."""

    kind: str
    ident: int | None = None
    scope: int | None = None
    suffix: str | None = None
    sender: bool = False
    interest: int | None = None
    qos: int | None = None
    inner: tuple[Extension, ...] = ()
    span: bytes = b""
    timestamp: tuple[int, bytes] | None = None
    encoding: tuple[int, bytes | None] | None = None
    put_extensions: tuple[Extension, ...] = ()
    payload: bytes = b""


def _declaration(reader: Reader, interest: int | None, qos: int | None) -> Message:
    header = reader.u8()
    kind = header & 0x1F
    _need(kind in NAMES, f"declaration {kind} is not one the exam names")
    name = NAMES[kind]
    if kind == D_FINAL:
        _need(header == D_FINAL and interest is not None, "a DeclareFinal that is not bare or has no interest")
        return Message(name, interest=interest, qos=qos)
    _need(interest is None, "the interest bit on a declaration that is not a DeclareFinal")
    ident = reader.leb()
    if kind == D_KEYEXPR:
        _need(header == (D_KEYEXPR | FLAG_N), "a DeclareKeyExpr that is not the named form with no other flag")
        scope = reader.leb()
        _need(scope == 0, "a DeclareKeyExpr with a scope")
        suffix = reader.take(reader.leb()).decode("utf-8")
        return Message(name, ident, scope, suffix, qos=qos)
    if kind in WITH_KEY:
        scope = reader.leb()
        suffix = reader.take(reader.leb()).decode("utf-8") if header & FLAG_N else None
        chain = extensions(reader) if header & FLAG_Z else ()
        return Message(name, ident, scope, suffix, bool(header & FLAG_M), qos=qos, inner=chain)
    _need(not header & (FLAG_N | FLAG_M), "an undeclaration with a flag the exam does not name")
    chain = extensions(reader) if header & FLAG_Z else ()
    return Message(name, ident, qos=qos, inner=chain)


def network(reader: Reader) -> Message:
    start = reader.at
    header = reader.u8()
    kind = header & 0x1F
    if kind == ID_DECLARE:
        _need(not header & FLAG_M, "a DECLARE with a reserved bit")
        interest = reader.leb() if header & FLAG_N else None
        qos = None
        if header & FLAG_Z:
            chain = extensions(reader)
            _need(len(chain) == 1 and chain[0].ident == EXT_QOS and chain[0].encoding == ENC_Z64 and not chain[0].mandatory, "a DECLARE extension that is not the network QoS")
            qos = int(chain[0].value)  # type: ignore[arg-type]
        message = _declaration(reader, interest, qos)
    elif kind == ID_PUSH:
        scope = reader.leb()
        suffix = reader.take(reader.leb()).decode("utf-8") if header & FLAG_N else None
        chain = extensions(reader) if header & FLAG_Z else ()
        put = reader.u8()
        _need(put & 0x1F == 1, "a PUSH body that is not a Put")
        timestamp = None
        if put & FLAG_N:
            time = reader.leb()
            timestamp = (time, reader.take(reader.leb()))
        encoding = None
        if put & FLAG_M:
            identifier = reader.leb()
            encoding = (identifier, reader.take(reader.leb()) if identifier & 1 else None)
        put_chain = extensions(reader) if put & FLAG_Z else ()
        payload = reader.take(reader.leb())
        message = Message(
            "push", None, scope, suffix, bool(header & FLAG_M), inner=chain, timestamp=timestamp,
            encoding=encoding, put_extensions=put_chain, payload=payload,
        )
    else:
        raise RmwWireError(f"network message {kind:#x} is not one the exam names")
    return Message(**{**message.__dict__, "span": reader.data[start : reader.at]})


def frame(batch: bytes) -> tuple[int, list[Message]]:
    reader = Reader(batch)
    _need(reader.u8() == ID_FRAME | FLAG_N, "a FRAME that is not reliable with no extension")
    sn = reader.leb()
    messages: list[Message] = []
    while reader.left():
        messages.append(network(reader))
    _need(bool(messages), "a FRAME with no message")
    return sn, messages


def _encode_push(message: Message) -> bytes:
    flags = (FLAG_N if message.suffix is not None else 0) | (FLAG_M if message.sender else 0) | (FLAG_Z if message.inner else 0)
    out = bytearray([ID_PUSH | flags]) + leb128(message.scope or 0)
    if message.suffix is not None:
        raw = message.suffix.encode()
        out += leb128(len(raw)) + raw
    if message.inner:
        out += encode_extensions(message.inner)
    put = 1 | (FLAG_N if message.timestamp else 0) | (FLAG_M if message.encoding else 0) | (FLAG_Z if message.put_extensions else 0)
    out.append(put)
    if message.timestamp:
        time, zid = message.timestamp
        out += leb128(time) + leb128(len(zid)) + zid
    if message.encoding:
        identifier, schema = message.encoding
        out += leb128(identifier)
        if schema is not None:
            out += leb128(len(schema)) + schema
    if message.put_extensions:
        out += encode_extensions(message.put_extensions)
    return bytes(out) + leb128(len(message.payload)) + message.payload


def encode(message: Message) -> bytes:
    """The canonical bytes of a network message, written from its fields and never from its source bytes."""
    if message.kind == "push":
        return _encode_push(message)
    kind = next(code for code, name in NAMES.items() if name == message.kind)
    wrapper = ID_DECLARE | (FLAG_N if message.interest is not None else 0) | (FLAG_Z if message.qos is not None else 0)
    out = bytearray([wrapper])
    if message.interest is not None:
        out += leb128(message.interest)
    if message.qos is not None:
        out += encode_extensions((Extension(EXT_QOS, False, ENC_Z64, message.qos),))
    if kind == D_FINAL:
        return bytes(out) + bytes([D_FINAL])
    assert message.ident is not None
    if kind == D_KEYEXPR:
        raw = (message.suffix or "").encode()
        return bytes(out) + bytes([kind | FLAG_N]) + leb128(message.ident) + leb128(0) + leb128(len(raw)) + raw
    flags = FLAG_Z if message.inner else 0
    if kind in WITH_KEY:
        raw = (message.suffix or "").encode()
        flags |= (FLAG_N if message.suffix is not None else 0) | (FLAG_M if message.sender else 0)
        body = leb128(message.ident) + leb128(message.scope or 0)
        if message.suffix is not None:
            body += leb128(len(raw)) + raw
    else:
        body = leb128(message.ident)
    return bytes(out) + bytes([kind | flags]) + body + (encode_extensions(message.inner) if message.inner else b"")


def rebuild(batch: bytes) -> bytes:
    """A FRAME written again from the fields `frame` read of it, a PUSH included."""
    sn, messages = frame(batch)
    return bytes([ID_FRAME | FLAG_N]) + leb128(sn) + b"".join(encode(message) for message in messages)


def summarize(batches: list[bytes]) -> dict[str, int]:
    """How many of each network message the peer sent in a session."""
    counts: dict[str, int] = {}
    for batch in batches:
        if batch[0] & 0x1F == ID_FRAME:
            for message in frame(batch)[1]:
                counts[message.kind] = counts.get(message.kind, 0) + 1
    return counts


def resolve(messages: list[Message], table: dict[int, str]) -> list[tuple[Message, str | None]]:
    """Each declaration with the full key it names: an alias id plus the suffix. `table` is updated."""
    out: list[tuple[Message, str | None]] = []
    for message in messages:
        if message.kind == "keyexpr":
            table[message.ident] = message.suffix or ""  # type: ignore[index]
        elif message.kind == "unkeyexpr":
            table.pop(message.ident, None)  # type: ignore[arg-type]
        if message.kind in WITH_KEY_NAMES:
            base = table.get(message.scope or 0, "") if message.scope else ""
            out.append((message, base + (message.suffix or "")))
        else:
            out.append((message, None))
    return out
