"""Host reference for the z-serial frame, written independently of the Rust framer.

`zenoh-link-serial` 1.0.0 puts every message on a serial line as one z-serial frame: a COBS body ended by the sentinel
0x00. The body is a 2-byte little-endian length, the data and a 4-byte little-endian CRC. The CRC is not the standard
CRC-32. It runs the polynomial 0x04C11DB7 through a reflected loop and inverts the accumulator at both ends.

`zserial_vectors.txt` holds frames that `z-serial` 0.2.3 wrote and wires that its reader accepted or refused. `self_test`
proves this module against every one before any gate uses it to judge the Rust framer. Nothing here is derived from the
Rust framer.

The stock reader takes more than the stock writer writes. The writer refuses a payload over 1500 bytes. The reader decodes
frames of up to 1512 data bytes, because it bounds only the wire at 1516 bytes. This module pins both directions to the
writer's bound: `MAX_DATA` is 1500, and `decode` refuses a longer payload.
"""

from __future__ import annotations

from pathlib import Path

POLYNOMIAL = 0x04C11DB7
SENTINEL = 0
MAX_DATA = 1500
LENGTH_BYTES = 2
CRC_BYTES = 4
# The stock reader stops after this many bytes with no sentinel (`COBS_BUF_SIZE`).
MAX_WIRE = 1516
VECTORS = Path(__file__).with_name("zserial_vectors.txt")


class ZSerialError(Exception):
    """A refusal. `kind` is one of KINDS, so a judge can require the class the Rust framer names."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


KINDS = ("sentinel", "cobs", "short", "length", "crc", "size")


def _table() -> tuple[int, ...]:
    rows = []
    for n in range(256):
        remainder = n
        for _ in range(8):
            remainder = (POLYNOMIAL ^ (remainder >> 1)) if remainder & 1 else remainder >> 1
        rows.append(remainder)
    return tuple(rows)


_TABLE = _table()


def crc(data: bytes) -> int:
    accumulator = 0xFFFFFFFF
    for byte in data:
        accumulator = (accumulator >> 8) ^ _TABLE[(accumulator & 0xFF) ^ byte]
    return ~accumulator & 0xFFFFFFFF


def cobs_encode(source: bytes) -> bytes:
    out = bytearray()
    block = bytearray()
    for byte in source:
        if byte == 0:
            out.append(len(block) + 1)
            out += block
            block = bytearray()
        else:
            block.append(byte)
            if len(block) == 254:
                out.append(255)
                out += block
                block = bytearray()
    out.append(len(block) + 1)
    out += block
    return bytes(out)


def cobs_decode(encoded: bytes) -> bytes:
    """Decodes a COBS body that holds no sentinel. A zero code, a run past the end or a stray zero is refused."""
    out = bytearray()
    index = 0
    while index < len(encoded):
        code = encoded[index]
        if code == 0:
            raise ZSerialError("cobs", "cobs: a zero code byte")
        end = index + code
        if end > len(encoded):
            raise ZSerialError("cobs", "cobs: a run past the end")
        run = encoded[index + 1 : end]
        if 0 in run:
            raise ZSerialError("cobs", "cobs: a zero inside a run")
        out += run
        index = end
        if code != 255 and index < len(encoded):
            out.append(0)
    return bytes(out)


def encode(data: bytes) -> bytes:
    if len(data) > MAX_DATA:
        raise ZSerialError("size", f"write: {len(data)} data bytes, the writer takes at most {MAX_DATA}")
    body = len(data).to_bytes(LENGTH_BYTES, "little") + data + crc(data).to_bytes(CRC_BYTES, "little")
    return cobs_encode(body) + bytes([SENTINEL])


def decode(wire: bytes) -> bytes:
    """One whole frame: a COBS body and its one trailing sentinel. Returns the data."""
    if len(wire) > MAX_WIRE:
        raise ZSerialError("size", f"read: {len(wire)} wire bytes, the reader stops at {MAX_WIRE}")
    if not wire or wire[-1] != SENTINEL:
        raise ZSerialError("sentinel", "read: no trailing sentinel")
    if SENTINEL in wire[:-1]:
        raise ZSerialError("sentinel", "read: a sentinel inside the frame")
    body = cobs_decode(wire[:-1])
    if len(body) < LENGTH_BYTES + CRC_BYTES:
        raise ZSerialError("short", "read: a body smaller than a length and a CRC")
    length = int.from_bytes(body[:LENGTH_BYTES], "little")
    if LENGTH_BYTES + length + CRC_BYTES != len(body):
        raise ZSerialError("length", "read: the length does not match the body")
    if length > MAX_DATA:
        raise ZSerialError("size", f"read: {length} data bytes, the exam takes at most {MAX_DATA}")
    data = body[LENGTH_BYTES : LENGTH_BYTES + length]
    if int.from_bytes(body[LENGTH_BYTES + length :], "little") != crc(data):
        raise ZSerialError("crc", "read: the CRC does not match")
    return data


def _hex(text: str) -> bytes:
    return b"" if text == "-" else bytes.fromhex(text)


def read_vectors(path: Path = VECTORS) -> list[list[str]]:
    rows = []
    for line in path.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            rows.append(line.split())
    return rows


def self_test(path: Path = VECTORS) -> int:
    """Reproduces every stock frame, takes every wire the stock reader took, and refuses every one it refused."""
    return self_test_rows(read_vectors(path))


def self_test_rows(rows: list[list[str]]) -> int:
    count = 0
    for row in rows:
        kind = row[0]
        if kind == "frame":
            _, name, data, wire = row
            if encode(_hex(data)).hex() != wire:
                raise ZSerialError("vector", f"frame {name}: the reference writes other bytes than z-serial")
        elif kind == "decode" and row[3] == "ok":
            _, name, wire, _ok, data = row
            if len(_hex(data)) > MAX_DATA:
                # The stock reader takes these. The exam pins the writer's bound, so the reference refuses them.
                try:
                    decode(bytes.fromhex(wire))
                except ZSerialError:
                    count += 1
                    continue
                raise ZSerialError("vector", f"decode {name}: the reference took a payload over {MAX_DATA} bytes")
            if decode(bytes.fromhex(wire)) != _hex(data):
                raise ZSerialError("vector", f"decode {name}: the reference returns other data than z-serial")
        elif kind == "decode" and row[3] == "refused":
            _, name, wire, _refused = row
            try:
                decode(bytes.fromhex(wire))
            except ZSerialError:
                count += 1
                continue
            raise ZSerialError("vector", f"decode {name}: the reference took a wire that z-serial refused")
        elif kind == "limit":
            _, name, length, result = row
            try:
                encode(bytes(int(length)))
            except ZSerialError:
                count += 1
                continue
            raise ZSerialError("vector", f"limit {name}: the reference wrote a payload that z-serial refused")
        elif kind == "stream":
            continue
        else:
            raise ZSerialError("vector", f"an unknown vector line: {' '.join(row)[:60]}")
        count += 1
    return count


def stream(chunks: list[bytes]) -> tuple[list[bytes], int]:
    """What a receiver delivers and drops for bytes that arrive in these chunks, one byte at a time.

    A run that reaches the sentinel is one frame: it is delivered if it decodes and dropped, counted once, if it does not. A
    run of MAX_WIRE bytes with no sentinel is discarded up to and including the next sentinel, and counted once.
    """
    held = bytearray()
    discarding = False
    delivered: list[bytes] = []
    dropped = 0
    for chunk in chunks:
        for byte in chunk:
            if discarding:
                if byte == SENTINEL:
                    discarding = False
                    dropped += 1
                continue
            if byte == SENTINEL:
                wire = bytes(held) + bytes([SENTINEL])
                held.clear()
                try:
                    delivered.append(decode(wire))
                except ZSerialError:
                    dropped += 1
                continue
            held.append(byte)
            if len(held) >= MAX_WIRE:
                held.clear()
                discarding = True
    return delivered, dropped
