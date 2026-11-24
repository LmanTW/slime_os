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
  U_SUBSCR   (by id) DECLARE<hdr|Z><ext 0x21><qos:leb128> then <hdr 0x03><id:leb128>, no extension
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
EXT_QOS_NETWORK = 0x21
QOS_NETWORK_DEFAULT = 8

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


def undeclare_subscriber_by_id(sub_id: int) -> bytes:
    """What a stock peer sends: the DECLARE carries the network QoS extension and the undeclaration
    names the subscriber by id alone, because the codec leaves out the wire expression when it is null."""
    return bytes([ID_DECLARE | FLAG_Z, EXT_QOS_NETWORK, QOS_NETWORK_DEFAULT, ID_U_SUBSCRIBER]) + leb128(sub_id)


WHATAMI_ROUTER = 0
WHATAMI_CLIENT = 2
ID_D_TOKEN, ID_U_TOKEN, ID_D_FINAL, ID_INTEREST = 6, 7, 0x1A, 25
INTEREST_MODES = {"final": 0, "current": 1, "future": 2, "current-future": 3}
INTEREST_TOKENS = 0x08
QOS_DECLARE = bytes([EXT_QOS_NETWORK, QOS_NETWORK_DEFAULT])


def init_as(whatami: int, zid: bytes, batch: int = DEFAULT_BATCH) -> bytes:
    """INIT_SYN for any role: the role is the low two bits of the byte after the version."""
    if whatami not in (WHATAMI_ROUTER, WHATAMI_PEER, WHATAMI_CLIENT):
        raise WireError("0b11 is reserved")
    syn = init(zid, batch)
    at = 2
    return syn[:at] + bytes([(syn[at] & ~0x03) | whatami]) + syn[at + 1 :]


def _declare(body: bytes, interest_id: int | None) -> bytes:
    header = ID_DECLARE | FLAG_Z | (FLAG_A if interest_id is not None else 0)
    return bytes([header]) + (leb128(interest_id) if interest_id is not None else b"") + QOS_DECLARE + body


def declare_token(token_id: int, key: str, sender: bool, interest_id: int | None = None) -> bytes:
    """D_TKN as upstream 1.0.0 writes it: the network QoS extension on the DECLARE, and an interest id first
    when the declaration answers an INTEREST."""
    header = ID_D_TOKEN | FLAG_N | (FLAG_M if sender else 0)
    return _declare(bytes([header]) + leb128(token_id) + leb128(0) + prefixed(key.encode()), interest_id)


def undeclare_token(token_id: int, key: str | None = None, sender: bool = True) -> bytes:
    """U_TKN. Upstream always writes the wire-expression extension, with a null expression when it has no key."""
    if key is None:
        body = bytes([0x00]) + leb128(0)
    else:
        body = bytes([0x01 | (0x02 if sender else 0)]) + leb128(0) + key.encode()
    return _declare(bytes([ID_U_TOKEN | FLAG_Z]) + leb128(token_id) + bytes([EXT_WIRE_EXPR]) + prefixed(body), None)


def declare_final(interest_id: int) -> bytes:
    return _declare(bytes([ID_D_FINAL]), interest_id)


INTEREST_RESTRICTED = 0x70  # R, N and M: a named key of the sender's mapping follows the options byte


def interest(
    interest_id: int,
    mode: str,
    options: int = INTEREST_TOKENS,
    key: str | None = None,
    qos: bool = False,
) -> bytes:
    """INTEREST: the mode in bits 5 and 6, then the id and, but for Final, the options byte. A `key` restricts it
    and adds R, N and M to the options and the key after them. `qos` adds the network QoS extension upstream writes
    when the QoS is not the default, and sets the extension flag."""
    header = ID_INTEREST | (INTEREST_MODES[mode] << 5) | (FLAG_Z if qos else 0)
    out = bytes([header]) + leb128(interest_id)
    if mode != "final":
        out += bytes([options | (INTEREST_RESTRICTED if key is not None else 0)])
        if key is not None:
            out += leb128(0) + prefixed(key.encode())
    if qos:
        out += bytes([EXT_QOS_NETWORK, QOS_NETWORK_DEFAULT])
    return out


def undeclare_token_by_id(token_id: int) -> bytes:
    """The withdrawal the client-role link writes: a bare DECLARE, U_TKN with its extension flag, the id and the
    extension `5f 02 00 00` that `rmw_zenohd`'s own client sent (scripts/lib/zenoh_rmw_token_exam.py)."""
    return bytes([ID_DECLARE, ID_U_TOKEN | FLAG_Z]) + leb128(token_id) + bytes([EXT_WIRE_EXPR, 0x02, 0x00, 0x00])


KEY_LIVELINESS = "@/liveliness/slime/node"
KEY_ROS = "@ros2_lv/0"
INTEREST_KEYEXPRS = 0x01

# Bytes the upstream eclipse-zenoh 1.0.0 encoder produced for each message below (zenoh-protocol and
# zenoh-codec =1.0.0, a throwaway program that wrote them and read them back). `liveliness_self_test`
# reproduces every one, so this reference is trusted only after it matches upstream.
UPSTREAM_LIVELINESS = {
    "init_syn_peer_default": "01093111223344",
    "init_syn_client_default": "01093211223344",
    "init_syn_router_default": "01093011223344",
    "init_syn_client_512": "410932112233440a0002",
    "declare_token_sender_id1_sn5": "25059e210866010017402f6c6976656c696e6573732f736c696d652f6e6f6465",
    "declare_token_receiver_id1_sn5": "25059e210826010017402f6c6976656c696e6573732f736c696d652f6e6f6465",
    "declare_token_sender_id300_sn5": "25059e210866ac020017402f6c6976656c696e6573732f736c696d652f6e6f6465",
    "declare_token_for_interest7_sn5": "2505be07210866010017402f6c6976656c696e6573732f736c696d652f6e6f6465",
    "undeclare_token_by_id1_sn6": "25069e210887015f020000",
    "undeclare_token_with_key_id1_sn6": "25069e210887015f190300402f6c6976656c696e6573732f736c696d652f6e6f6465",
    "declare_final_interest7_sn9": "2509be0721081a",
    "interest_tokens_current_id7_sn2": "2502390708",
    "interest_tokens_future_id7_sn2": "2502590708",
    "interest_tokens_current_future_id7_sn2": "2502790708",
    "interest_final_id7_sn3": "25031907",
    "interest_subscribers_current_id7_sn2": "2502390702",
    "interest_tokens_qos_id7_sn2": "2502b907082108",
    "interest_restricted_exact_id7_sn2": "25023907780017402f6c6976656c696e6573732f736c696d652f6e6f6465",
    "interest_restricted_wildcard_id7_sn2": "25023907780015402f6c6976656c696e6573732f736c696d652f2a2a",
    "interest_keyexprs_tokens_restricted_wildcard_id7_sn2": "25023907790015402f6c6976656c696e6573732f736c696d652f2a2a",
    "interest_keyexprs_tokens_restricted_wildcard_qos_id7_sn2": "2502b907790015402f6c6976656c696e6573732f736c696d652f2a2a2108",
    "interest_keyexprs_tokens_restricted_ros_id7_sn2": "2502390779000d40726f73325f6c762f302f2a2a",
    "interest_keyexprs_tokens_unrestricted_id7_sn2": "2502390709",
}


def liveliness_reference() -> dict[str, str]:
    zid = bytes.fromhex("11223344")
    key = KEY_LIVELINESS
    return {
        "init_syn_peer_default": init_as(WHATAMI_PEER, zid).hex(),
        "init_syn_client_default": init_as(WHATAMI_CLIENT, zid).hex(),
        "init_syn_router_default": init_as(WHATAMI_ROUTER, zid).hex(),
        "init_syn_client_512": init_as(WHATAMI_CLIENT, zid, 512).hex(),
        "declare_token_sender_id1_sn5": frame(5, declare_token(1, key, True)).hex(),
        "declare_token_receiver_id1_sn5": frame(5, declare_token(1, key, False)).hex(),
        "declare_token_sender_id300_sn5": frame(5, declare_token(300, key, True)).hex(),
        "declare_token_for_interest7_sn5": frame(5, declare_token(1, key, True, 7)).hex(),
        "undeclare_token_by_id1_sn6": frame(6, undeclare_token(1)).hex(),
        "undeclare_token_with_key_id1_sn6": frame(6, undeclare_token(1, key)).hex(),
        "declare_final_interest7_sn9": frame(9, declare_final(7)).hex(),
        "interest_tokens_current_id7_sn2": frame(2, interest(7, "current")).hex(),
        "interest_tokens_future_id7_sn2": frame(2, interest(7, "future")).hex(),
        "interest_tokens_current_future_id7_sn2": frame(2, interest(7, "current-future")).hex(),
        "interest_final_id7_sn3": frame(3, interest(7, "final")).hex(),
        "interest_subscribers_current_id7_sn2": frame(2, interest(7, "current", 0x02)).hex(),
        "interest_tokens_qos_id7_sn2": frame(2, interest(7, "current", qos=True)).hex(),
        "interest_restricted_exact_id7_sn2": frame(2, interest(7, "current", key=key)).hex(),
        "interest_restricted_wildcard_id7_sn2": frame(2, interest(7, "current", key="@/liveliness/slime/**")).hex(),
        "interest_keyexprs_tokens_restricted_wildcard_id7_sn2": frame(
            2, interest(7, "current", INTEREST_TOKENS | INTEREST_KEYEXPRS, "@/liveliness/slime/**")
        ).hex(),
        "interest_keyexprs_tokens_restricted_wildcard_qos_id7_sn2": frame(
            2, interest(7, "current", INTEREST_TOKENS | INTEREST_KEYEXPRS, "@/liveliness/slime/**", qos=True)
        ).hex(),
        "interest_keyexprs_tokens_restricted_ros_id7_sn2": frame(
            2, interest(7, "current", INTEREST_TOKENS | INTEREST_KEYEXPRS, f"{KEY_ROS}/**")
        ).hex(),
        "interest_keyexprs_tokens_unrestricted_id7_sn2": frame(2, interest(7, "current", INTEREST_TOKENS | INTEREST_KEYEXPRS)).hex(),
    }


def liveliness_self_test() -> int:
    """Reproduce every upstream batch above; returns how many matched."""
    produced = liveliness_reference()
    if produced.keys() != UPSTREAM_LIVELINESS.keys():
        raise WireError("the liveliness reference and the upstream table name different batches")
    for name, expected in UPSTREAM_LIVELINESS.items():
        if produced[name] != expected:
            raise WireError(f"{name}: reference produced {produced[name]}, upstream bytes are {expected}")
    return len(produced)


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


QOS_PRIORITY_MASK = 0x07
QOS_BLOCK = 0x08
QOS_EXPRESS = 0x10
# eclipse-zenoh 1.0.0 QoSType::PUSH: Priority::Data (5), CongestionControl::Drop, not express. A PUSH
# whose QoS equals it carries no extension.
QOS_PUSH_DEFAULT = 5


def qos_value(priority: int, block: bool, express: bool) -> int:
    """The Z64 the network QoS extension carries: priority in bits 0 to 2, Block (upstream's D, don't drop) in bit 3, express in bit 4."""
    if not 0 <= priority <= QOS_PRIORITY_MASK:
        raise WireError("priority is 0 to 7")
    return priority | (QOS_BLOCK if block else 0) | (QOS_EXPRESS if express else 0)


def push_put_qos(key: str, att: bytes, payload: bytes, sender: bool, priority: int, block: bool, express: bool) -> bytes:
    """A PUSH as upstream's encoder writes it: the network QoS extension sits between the key expression
    and the Put, and is left out when the value is the PUSH default."""
    if len(att) != ATTACHMENT_BYTES:
        raise WireError("the profile admits only the 33-byte attachment")
    value = qos_value(priority, block, express)
    raw = key.encode()
    header = ID_PUSH | FLAG_N | (FLAG_M if sender else 0) | (FLAG_Z if value != QOS_PUSH_DEFAULT else 0)
    put = bytes([ID_PUT | FLAG_Z, EXT_ATTACHMENT]) + prefixed(att) + prefixed(payload)
    ext = bytes([EXT_QOS_NETWORK]) + leb128(value) if value != QOS_PUSH_DEFAULT else b""
    return bytes([header]) + leb128(0) + prefixed(raw) + ext + put


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
