"""A Foxglove WebSocket client written against RFC 6455 and the protocol's message layouts.

Nothing here imports the bridge, the Foxglove SDK or a WebSocket library: it is the independent client
`scripts/lib/foxglove_bridge_exam.py` judges the bridge with. It reads what a server sent as a list of whole
messages, and holds the wire to the parts of RFC 6455 a server must obey:

* the opening handshake: status 101, `Upgrade: websocket`, `Connection: Upgrade`, the accept value
  derived from the client's key, and the one subprotocol offered;
* frames: no reserved bit, no mask from a server, a payload length in its shortest form, control frames
  of at most 125 bytes that are never fragmented, and continuations only inside a fragmented message;
* text messages that are UTF-8 JSON objects.

The protocol's layouts, as the Foxglove SDK serves them under `foxglove.sdk.v1`: a JSON message names its
operation in `op`, and a binary message starts with a one-byte opcode. Message Data is opcode 1, then the
subscription id as a little-endian u32, the log time as a little-endian u64 in nanoseconds, and the payload.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import time
from dataclasses import dataclass

SUBPROTOCOL = "foxglove.sdk.v1"
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONTINUATION, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA
MESSAGE_DATA = 1
MESSAGE_DATA_HEADER = struct.Struct("<BIQ")
# A message is at most one frame payload of the store's 16 MiB bound with its header; a handshake response
# is a few hundred bytes.
MAX_MESSAGE = 16 * 1024 * 1024 + 64
MAX_HANDSHAKE = 8192


class ProtocolError(ValueError):
    """What a server sent breaks RFC 6455 or the Foxglove message layouts."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise ProtocolError(reason)


@dataclass(frozen=True)
class Message:
    """One whole message: `text` for a JSON message, `data` for a binary one."""

    text: str | None = None
    data: bytes | None = None

    def json(self) -> dict:
        _need(self.text is not None, "a binary message where a JSON message was expected")
        try:
            value = json.loads(self.text)
        except json.JSONDecodeError as error:
            raise ProtocolError(f"a text message that is not JSON: {error}") from error
        _need(isinstance(value, dict) and isinstance(value.get("op"), str), "a JSON message that is not an object with an op")
        return value


def accept_value(key: str) -> str:
    return base64.b64encode(hashlib.sha1(key.encode("ascii") + GUID).digest()).decode("ascii")


def request(host: str, port: int, key: str) -> bytes:
    return (
        f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\r\n"
    ).encode("ascii")


def judge_handshake(response: bytes, key: str) -> None:
    """The server's opening handshake response, without the bytes after it."""
    try:
        text = response.decode("ascii")
    except UnicodeDecodeError as error:
        raise ProtocolError("a handshake response that is not ASCII") from error
    lines = text.split("\r\n")
    status = lines[0].split(" ", 2)
    _need(len(status) >= 2 and status[0] == "HTTP/1.1" and status[1] == "101", f"handshake status {lines[0]!r}, not 101")
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, separator, value = line.partition(":")
        _need(bool(separator), f"a handshake header line without a colon: {line!r}")
        headers.setdefault(name.strip().lower(), []).append(value.strip())

    def one(name: str) -> str:
        values = headers.get(name, [])
        _need(len(values) == 1, f"{len(values)} {name} headers, the handshake needs one")
        return values[0]

    _need(one("upgrade").lower() == "websocket", "the handshake does not upgrade to websocket")
    _need("upgrade" in [token.strip().lower() for token in one("connection").split(",")], "the handshake's Connection does not name Upgrade")
    _need(one("sec-websocket-accept") == accept_value(key), "the handshake's accept value is not derived from this client's key")
    _need(one("sec-websocket-protocol") == SUBPROTOCOL, f"the server selected subprotocol {headers.get('sec-websocket-protocol')}, not {SUBPROTOCOL}")


class Frames:
    """Reads frames from bytes as they arrive and joins them into messages."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.partial: tuple[int, bytearray] | None = None
        self.closed = False

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        """Every whole message and control frame `data` completes, as (opcode, payload)."""
        self.buffer += data
        out = []
        while True:
            frame = self._frame()
            if frame is None:
                return out
            fin, opcode, payload = frame
            if opcode >= OP_CLOSE:
                _need(opcode in (OP_CLOSE, OP_PING, OP_PONG), f"a control frame with reserved opcode {opcode:#x}")
                _need(fin, "a fragmented control frame")
                _need(len(payload) <= 125, f"a control frame of {len(payload)} bytes")
                out.append((opcode, payload))
                continue
            _need(opcode in (OP_CONTINUATION, OP_TEXT, OP_BINARY), f"a data frame with reserved opcode {opcode:#x}")
            if opcode == OP_CONTINUATION:
                _need(self.partial is not None, "a continuation frame outside a fragmented message")
                self.partial[1].extend(payload)
            else:
                _need(self.partial is None, "a new message inside a fragmented message")
                self.partial = (opcode, bytearray(payload))
            _need(len(self.partial[1]) <= MAX_MESSAGE, f"a message over {MAX_MESSAGE} bytes")
            if fin:
                out.append((self.partial[0], bytes(self.partial[1])))
                self.partial = None

    def _frame(self) -> tuple[bool, int, bytes] | None:
        buffer = self.buffer
        if len(buffer) < 2:
            return None
        first, second = buffer[0], buffer[1]
        _need(first & 0x70 == 0, "a frame with a reserved bit set")
        _need(not second & 0x80, "a masked frame from the server")
        length, at = second & 0x7F, 2
        if length == 126:
            if len(buffer) < 4:
                return None
            length, at = struct.unpack_from("!H", buffer, 2)[0], 4
            _need(length >= 126, "a 16-bit payload length that fits seven bits")
        elif length == 127:
            if len(buffer) < 10:
                return None
            length, at = struct.unpack_from("!Q", buffer, 2)[0], 10
            _need(length >= 1 << 16, "a 64-bit payload length that fits sixteen bits")
            _need(length < 1 << 63, "a 64-bit payload length with its top bit set")
        _need(length <= MAX_MESSAGE, f"a frame of {length} bytes")
        if len(buffer) < at + length:
            return None
        payload = bytes(buffer[at : at + length])
        del buffer[: at + length]
        return bool(first & 0x80), first & 0x0F, payload


def client_frame(opcode: int, payload: bytes) -> bytes:
    """One masked, unfragmented frame from the client."""
    mask = os.urandom(4)
    length = len(payload)
    if length < 126:
        header = bytes([0x80 | opcode, 0x80 | length])
    elif length < 1 << 16:
        header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack("!H", length)
    else:
        header = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack("!Q", length)
    return header + mask + bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))


def to_message(opcode: int, payload: bytes) -> Message:
    if opcode == OP_TEXT:
        try:
            return Message(text=payload.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise ProtocolError("a text message that is not UTF-8") from error
    return Message(data=payload)


def message_data(message: Message) -> tuple[int, int, bytes]:
    """(subscription id, log time, payload) of a Message Data message."""
    _need(message.data is not None, "a JSON message where Message Data was expected")
    data = message.data
    _need(len(data) >= MESSAGE_DATA_HEADER.size, f"a binary message of {len(data)} bytes, shorter than Message Data's header")
    opcode, subscription, log_time = MESSAGE_DATA_HEADER.unpack_from(data)
    _need(opcode == MESSAGE_DATA, f"a binary message with opcode {opcode}, not Message Data")
    return subscription, log_time, data[MESSAGE_DATA_HEADER.size :]


class Client:
    """A connected client: the handshake is judged on connect, and messages are read as they arrive."""

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.socket = socket.create_connection((host, port), timeout=timeout)
        self.frames = Frames()
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        self.socket.sendall(request(host, port, key))
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = self.socket.recv(4096)
            _need(bool(chunk), "the server closed during the handshake")
            response += chunk
            _need(len(response) <= MAX_HANDSHAKE, "a handshake response over its bound")
        head, _, rest = bytes(response).partition(b"\r\n\r\n")
        judge_handshake(head, key)
        self.pending: list[Message] = []
        self._take(rest)

    def _take(self, data: bytes) -> None:
        for opcode, payload in self.frames.feed(data):
            if opcode == OP_PING:
                self.socket.sendall(client_frame(OP_PONG, payload))
            elif opcode == OP_CLOSE:
                self.frames.closed = True
            elif opcode != OP_PONG:
                self.pending.append(to_message(opcode, payload))

    def send_json(self, value: dict) -> None:
        self.socket.sendall(client_frame(OP_TEXT, json.dumps(value).encode("utf-8")))

    def receive(self, deadline: float) -> Message | None:
        """The next message, or None once the server has closed or the deadline passed."""
        while not self.pending:
            if self.frames.closed:
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.socket.settimeout(remaining)
            try:
                chunk = self.socket.recv(1 << 20)
            except TimeoutError:
                return None
            if not chunk:
                self.frames.closed = True
                return None
            self._take(chunk)
        return self.pending.pop(0)

    def close(self) -> None:
        try:
            self.socket.sendall(client_frame(OP_CLOSE, struct.pack("!H", 1000)))
        except OSError:
            pass
        self.socket.close()
