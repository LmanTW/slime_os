"""Host reference for the Zenoh Profile 0 wire, written independently of the Rust codec.

The bytes of a Zenoh message belong to eclipse-zenoh (wire version 0x09). This
module encodes the admitted subset from the values a decoder summary names, and
decodes the one shape the demo exchanges (a reliable FRAME carrying a PUSH with a
Put and the 33-byte attachment), so a gate can judge what a guest put on the wire
without trusting the guest's own codec. `self_test` proves the encoder against
the decoder corpus, whose accepted batches the upstream eclipse-zenoh 1.0.0
encoder produced; nothing here is derived from the Rust implementation.

Layouts, from the 1.0.0 codec as the corpus records them:

  INIT       <hdr><version><whatami|zidlen-1><zid>[<resolution><batch:u16le>]  (+ <cookie:leb128-prefixed> in ACK)
  OPEN       <hdr><lease:leb128><initial_sn:leb128>[<cookie:leb128-prefixed>]   (T flag: lease in seconds)
  CLOSE      <hdr><reason>
  FRAME      <hdr><sn:leb128><network message>*
  DECLARE    <hdr 0x1e><declaration>
  D_SUBSCR   <hdr><id:leb128><scope:leb128><keylen:leb128><key>
  U_SUBSCR   <hdr|Z><id:leb128><ext 0x5f><len:leb128><flags><scope:leb128><raw suffix>
  PUSH       <hdr><scope:leb128><keylen:leb128><key><PUT>
  PUT        <hdr|Z><ext 0x43><len:leb128><attachment><payload len:leb128><payload>
"""

from __future__ import annotations

import re
from pathlib import Path

PROTOCOL_VERSION = 9
DEFAULT_RESOLUTION = 10
DEFAULT_BATCH = 65535
WHATAMI_PEER = 1

ID_INIT, ID_OPEN, ID_CLOSE, ID_FRAME = 1, 2, 3, 5
ID_PUSH, ID_DECLARE = 29, 30
ID_D_SUBSCRIBER, ID_U_SUBSCRIBER, ID_PUT = 2, 3, 1
FLAG_A = FLAG_N = FLAG_R = 0x20
# Bit 6 means "size params" in INIT, "lease in seconds" in OPEN, and the sender
# key mapping in PUSH and D_SUBSCRIBER (contracts/zenoh-profile/v1 flagBit6).
FLAG_S = FLAG_T = FLAG_M = 0x40
FLAG_Z = 0x80
EXT_WIRE_EXPR = 0x5F
EXT_ATTACHMENT = 0x43

ATTACHMENT_BYTES = 33
GID_BYTES = 16


class WireError(ValueError):
    """Input the reference refuses to encode or decode."""


def leb128(value: int) -> bytes:
    if value < 0:
        raise WireError("negative LEB128 value")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def read_leb128(data: bytes, at: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if at >= len(data):
            raise WireError("truncated LEB128")
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, at
        shift += 7
        if shift > 35:
            raise WireError("LEB128 over 32 bits")


def prefixed(data: bytes) -> bytes:
    return leb128(len(data)) + data


def _zid(zid: bytes) -> bytes:
    if not 1 <= len(zid) <= 16:
        raise WireError("ZID must be 1 to 16 bytes")
    return bytes([((len(zid) - 1) << 4) | WHATAMI_PEER]) + zid


def init(zid: bytes, batch: int = DEFAULT_BATCH, cookie: bytes | None = None) -> bytes:
    """INIT_SYN, or INIT_ACK when `cookie` is given."""
    header = ID_INIT | (FLAG_A if cookie is not None else 0) | (FLAG_S if batch != DEFAULT_BATCH else 0)
    out = bytes([header, PROTOCOL_VERSION]) + _zid(zid)
    if batch != DEFAULT_BATCH:
        out += bytes([DEFAULT_RESOLUTION]) + batch.to_bytes(2, "little")
    if cookie is not None:
        out += prefixed(cookie)
    return out


def open_(lease_ms: int, initial_sn: int, cookie: bytes | None = None, ack: bool = False) -> bytes:
    seconds = lease_ms % 1000 == 0
    header = ID_OPEN | (FLAG_A if ack else 0) | (FLAG_T if seconds else 0)
    out = bytes([header]) + leb128(lease_ms // 1000 if seconds else lease_ms) + leb128(initial_sn)
    if not ack:
        out += prefixed(cookie or b"")
    return out


def close(reason: int, session: bool) -> bytes:
    return bytes([ID_CLOSE | (FLAG_A if session else 0), reason])


def declare_subscriber(sub_id: int, key: str, sender: bool) -> bytes:
    raw = key.encode()
    header = ID_D_SUBSCRIBER | FLAG_N | (FLAG_M if sender else 0)
    return bytes([ID_DECLARE, header]) + leb128(sub_id) + leb128(0) + prefixed(raw)


def undeclare_subscriber(sub_id: int, key: str, sender: bool) -> bytes:
    body = bytes([0x01 | (0x02 if sender else 0)]) + leb128(0) + key.encode()
    return bytes([ID_DECLARE, ID_U_SUBSCRIBER | FLAG_Z]) + leb128(sub_id) + bytes([EXT_WIRE_EXPR]) + prefixed(body)


def attachment(sequence: int, timestamp: int, gid: bytes) -> bytes:
    if len(gid) != GID_BYTES:
        raise WireError("the profile admits only a 16-byte GID")
    return sequence.to_bytes(8, "little", signed=True) + timestamp.to_bytes(8, "little", signed=True) + prefixed(gid)


def push_put(key: str, att: bytes, payload: bytes, sender: bool) -> bytes:
    if len(att) != ATTACHMENT_BYTES:
        raise WireError("the profile admits only the 33-byte attachment")
    raw = key.encode()
    header = ID_PUSH | FLAG_N | (FLAG_M if sender else 0)
    put = bytes([ID_PUT | FLAG_Z, EXT_ATTACHMENT]) + prefixed(att) + prefixed(payload)
    return bytes([header]) + leb128(0) + prefixed(raw) + put


def frame(sn: int, *messages: bytes) -> bytes:
    return bytes([ID_FRAME | FLAG_R]) + leb128(sn) + b"".join(messages)


def stream(batch: bytes) -> bytes:
    """A batch as it travels on the TCP link: a 2-byte little-endian length first."""
    return len(batch).to_bytes(2, "little") + batch


def decode_push_frame(batch: bytes) -> dict:
    """Decode a FRAME holding exactly one PUSH with a Put and the attachment."""
    if not batch or batch[0] != ID_FRAME | FLAG_R:
        raise WireError("not a reliable FRAME")
    sn, at = read_leb128(batch, 1)
    if at >= len(batch) or batch[at] != ID_PUSH | FLAG_N | FLAG_M:
        raise WireError("not a named sender-mapped PUSH")
    at += 1
    scope, at = read_leb128(batch, at)
    keylen, at = read_leb128(batch, at)
    if scope != 0 or at + keylen > len(batch):
        raise WireError("bad key expression")
    key = batch[at : at + keylen].decode()
    at += keylen
    if at + 2 > len(batch) or batch[at] != ID_PUT | FLAG_Z or batch[at + 1] != EXT_ATTACHMENT:
        raise WireError("PUT without the attachment extension")
    at += 2
    attlen, at = read_leb128(batch, at)
    if attlen != ATTACHMENT_BYTES or at + attlen > len(batch):
        raise WireError("attachment is not 33 bytes")
    att = batch[at : at + attlen]
    at += attlen
    paylen, at = read_leb128(batch, at)
    if at + paylen != len(batch):
        raise WireError("payload length disagrees with the batch")
    if att[16] != GID_BYTES:
        raise WireError("GID length prefix is not 16")
    return {
        "sn": sn,
        "key": key,
        "sequence": int.from_bytes(att[0:8], "little", signed=True),
        "timestamp": int.from_bytes(att[8:16], "little", signed=True),
        "gid": att[17:33],
        "payload": batch[at : at + paylen],
    }


def _fields(text: str) -> dict[str, str]:
    return dict(part.split("=", 1) for part in text.split(",") if part)


def _network(text: str) -> bytes:
    name, _, rest = text.partition(":")
    f = _fields(rest)
    sender = f.get("mapping") == "sender"
    if name == "DECLARE_SUBSCRIBER":
        return declare_subscriber(int(f["id"]), f["key"], sender)
    if name == "UNDECLARE_SUBSCRIBER":
        return undeclare_subscriber(int(f["id"]), f["key"], sender)
    if name == "PUSH_PUT":
        return push_put(f["key"], bytes.fromhex(f["att"]), bytes.fromhex(f["payload"]), sender)
    raise WireError(f"unknown network message {name}")


def encode_summary(summary: str) -> bytes:
    """Encode the batch a corpus summary describes, from the values it names."""
    head, *rest = summary.split(";", 2) if summary.startswith("FRAME;") else summary.split(";")
    if head == "FRAME":
        sn = int(rest[0].split("=", 1)[1])
        return frame(sn, *(_network(part) for part in rest[1].split("|")))
    f = dict(part.split("=", 1) for part in rest)
    if head == "INIT_SYN":
        return init(bytes.fromhex(f["zid"]), int(f["batch"]))
    if head == "INIT_ACK":
        return init(bytes.fromhex(f["zid"]), int(f["batch"]), bytes.fromhex(f["cookie"]))
    if head == "OPEN_SYN":
        return open_(int(f["lease_ms"]), int(f["sn"]), bytes.fromhex(f["cookie"]))
    if head == "OPEN_ACK":
        return open_(int(f["lease_ms"]), int(f["sn"]), ack=True)
    if head == "CLOSE":
        return close(int(f["reason"]), f["session"] == "1")
    raise WireError(f"unknown batch {head}")


def corpus_accepted(path: Path) -> list[tuple[str, str, str]]:
    """Every accepted batch in the corpus: (name, hex, summary)."""
    rows = []
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) == 5 and fields[0] == "batch" and fields[2] == "ok":
            rows.append((fields[1], fields[3], fields[4]))
    return rows


def self_test(corpus: Path) -> int:
    """Encode every accepted corpus batch from its summary and compare the bytes.

    Returns the number of batches matched. A mismatch raises WireError, so the
    reference is never used to judge a guest until it reproduces the upstream
    encoder's output.
    """
    rows = corpus_accepted(corpus)
    if not rows:
        raise WireError("the corpus holds no accepted batch")
    for name, expected, summary in rows:
        produced = encode_summary(summary).hex()
        if produced != expected:
            raise WireError(f"{name}: reference produced {produced}, upstream bytes are {expected}")
    pushes = [row for row in rows if "PUSH_PUT" in row[2] and "|" not in row[2]]
    for name, expected, _ in pushes:
        decoded = decode_push_frame(bytes.fromhex(expected))
        if encode_summary(_summary_of(decoded)).hex() != expected:
            raise WireError(f"{name}: decode then encode does not round-trip")
    return len(rows)


def _summary_of(decoded: dict) -> str:
    att = attachment(decoded["sequence"], decoded["timestamp"], decoded["gid"]).hex()
    return f"FRAME;sn={decoded['sn']};PUSH_PUT:mapping=sender,key={decoded['key']},att={att},payload={decoded['payload'].hex()}"


KEY_EXPRESSION = re.compile(r"[0-9A-Za-z_:/-]+")
