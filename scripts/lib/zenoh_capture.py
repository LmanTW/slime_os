"""Judge a guest-to-host Zenoh Profile 0 exchange from a packet capture and a listener receipt.

`zenoh_exchange` judges what the nodes print. This judges what crossed the wire: one classic PCAP
taken at the guest's virtio-net device, reassembled into the two TCP byte streams, split into
Zenoh batches by their two-byte stream length, and held against the host wire reference
(`zenoh_wire`, written independently of the Rust codec), the guest's own report of what it sent,
and the record a stock eclipse-zenoh peer wrote about what its subscriber delivered.

Admitted on the wire: ARP, and TCP between the guest and the declared peer. Nothing else: no DNS,
no UDP (so no scouting), no ICMP, no second connection, no other address or port, no reset.

Every judge is a pure function over bytes and text. `synthesize` builds the capture an honest
guest would produce, `controls` mutates it, and a judge is trusted only after it refuses every
mutation and accepts the honest variants (reordered, retransmitted and re-segmented streams).

Limit: QEMU user networking is not a physical NIC, and a capture proves the packets it holds, not
that the peer's subscriber acted on them; that is what the receipt is for.
"""

from __future__ import annotations

import copy
import re
import shutil
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import http_capture
import zenoh_exchange
import zenoh_listener_peer
import zenoh_stock_peer
import zenoh_wire
import zutai_cli
from harness import ROOT

GUEST = http_capture.GUEST
PEER = "10.0.2.2"
PORT = 17447
LISTEN = f"tcp/127.0.0.1:{PORT}"
SAMPLES = 4
LEASE_MS = 2000
PUBLISHER = "ros2-demo-publisher"
SUBSCRIBER = "ros2-demo-subscriber"
DENIALS = ("undeclared-endpoint", "listen", "scouting")
MAX_STREAM = 1 << 20
# contracts/zenoh-profile/v1 maxBatchBytes: no batch, in either direction, is longer.
MAX_BATCH_BYTES = 512
U32 = 0xFFFFFFFF
# The attachment the publisher builds for sample `n` (components/lib/src/zenoh_node.rs): sequence n + 1,
# source timestamp 1000 + n, and one GID for every sample.
ATTACHMENT_SEQUENCE_BASE = 1
ATTACHMENT_TIMESTAMP_BASE = 1000
DEMO_GID = bytes(range(0xE0, 0xF0))
# contracts/zenoh-profile/v1 closeConnectionToSelf: the highest CLOSE reason the profile names.
MAX_CLOSE_REASON = 7

ID_KEEP_ALIVE = 4
TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 1, 2, 4, 16
TCP_PSH, TCP_URG = 8, 0x20


class CaptureError(ValueError):
    """Evidence the judge refuses."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise CaptureError(reason)


@dataclass(frozen=True)
class Segment:
    index: int
    outgoing: bool
    source_port: int
    destination_port: int
    seq: int
    ack: int
    flags: int
    payload: bytes
    window: int = 0
    options: tuple = ()
    time_ns: int = 0


# ------------------------------------------------------------------------------ capture


def _check_arp(frame: bytes) -> None:
    """An ARP request or reply between the guest and the declared peer, and nothing else.

    The sender and target protocol addresses are the two endpoints, one each, and the sender's
    hardware address is the Ethernet source; the guest's is the MAC the composition declares. A
    request is broadcast, with a target hardware address of zero (the standard form) or broadcast
    (what smoltcp 0.13 emits). A reply is addressed to the hardware address it names as its target.
    """
    _need(len(frame) >= 42, "short ARP frame")
    htype, ptype, hlen, plen, operation = struct.unpack_from("!HHBBH", frame, 14)
    _need((htype, ptype, hlen, plen) == (1, 0x0800, 6, 4), "ARP that is not Ethernet and IPv4")
    _need(operation in (1, 2), f"ARP operation {operation} is neither a request nor a reply")
    destination, source = frame[0:6], frame[6:12]
    sender_mac, target_mac = frame[22:28], frame[32:38]
    sender, target = (".".join(str(b) for b in frame[at : at + 4]) for at in (28, 38))
    _need({sender, target} == {GUEST, PEER}, f"ARP from {sender} for {target}: only {GUEST} and {PEER} may speak")
    _need(sender_mac == source, "the ARP sender hardware address is not the Ethernet source")
    _need((sender == GUEST) == (sender_mac == GUEST_MAC), f"the ARP sender {sender} has hardware address {sender_mac.hex()}")
    if operation == 1:
        _need(destination == BROADCAST, "an ARP request that is not sent to broadcast")
        _need(target_mac in (bytes(6), BROADCAST), "an ARP request whose target hardware address is neither zero nor broadcast")
    else:
        _need(target_mac == destination, "the ARP reply's target hardware address is not its Ethernet destination")
        _need((target == GUEST) == (target_mac == GUEST_MAC), f"the ARP reply for {target} is addressed to hardware address {target_mac.hex()}")


# TCP options whose value is a negotiation both ends keep, as (kind, value): the maximum segment size
# (2) and the window scale (3), plus SACK-permitted (4). Timestamps (8) vary on every packet and are
# the one option a retransmission may differ in.
VARIABLE_OPTIONS = (8,)
# The total length (kind and length bytes included) each fixed-format option must have: MSS 4
# (RFC 9293), window scale 3 and timestamps 10 (RFC 7323), SACK-permitted 2 (RFC 2018). SACK blocks
# (kind 5) and kinds the exam does not name are variable and only bounds-checked.
FIXED_OPTION_LENGTHS = {2: 4, 3: 3, 4: 2, 8: 10}


def _options(raw: bytes) -> tuple:
    """The TCP options of a header as sorted (kind, value) pairs, padding and end-of-list dropped.

    A malformed option list (a length that runs past the header, or under two) refuses the capture.
    """
    found, at = [], 0
    while at < len(raw):
        kind = raw[at]
        if kind == 0:
            _need(not any(raw[at:]), "bytes after the end-of-options marker")
            break
        if kind == 1:
            at += 1
            continue
        _need(at + 1 < len(raw) and raw[at + 1] >= 2 and at + raw[at + 1] <= len(raw), f"a malformed TCP option of kind {kind}")
        _need(kind not in FIXED_OPTION_LENGTHS or raw[at + 1] == FIXED_OPTION_LENGTHS[kind],
              f"a TCP option of kind {kind} with length {raw[at + 1]}, it is {FIXED_OPTION_LENGTHS.get(kind)}")
        found.append((kind, bytes(raw[at + 2 : at + raw[at + 1]])))
        at += raw[at + 1]
    return tuple(sorted(found))


def _negotiated(s: "Segment") -> tuple:
    return (s.seq, s.ack, s.flags, s.window, tuple(o for o in s.options if o[0] not in VARIABLE_OPTIONS))


def _record_times(data: bytes) -> list[int]:
    """Each record's capture time in whole nanoseconds, read from the PCAP header as integers.

    `http_capture._frames` yields a float, which cannot hold a microsecond exactly at an epoch
    timestamp, and a lease boundary is judged to the microsecond. The file is already validated.
    """
    unit = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000), b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}[data[:4]]
    endian, scale = unit
    times, at = [], 24
    while at < len(data):
        seconds, fraction, captured, _original = struct.unpack_from(endian + "IIII", data, at)
        times.append(seconds * 1_000_000_000 + fraction * scale)
        at += 16 + captured
    return times


def segments(data: bytes, max_capture: int = http_capture.MAX_CAPTURE, max_frames: int = http_capture.MAX_FRAMES) -> tuple[list[Segment], int]:
    """Every TCP segment in the capture, and the number of ARP frames. Anything else is refused.

    A capture over `max_capture` bytes or `max_frames` frames is refused."""
    found: list[Segment] = []
    arp = 0
    try:
        frames = list(http_capture._frames(data, max_bytes=max_capture, max_frames=max_frames))
        times = _record_times(data)
    except ValueError as error:
        raise CaptureError(str(error)) from error
    for position, (_, frame) in enumerate(frames):
        ethertype = int.from_bytes(frame[12:14], "big")
        if ethertype == 0x0806:
            _check_arp(frame)
            arp += 1
            continue
        _need(ethertype == 0x0800, f"Ethernet protocol {ethertype:#06x} is neither ARP nor IPv4")
        ip = frame[14:]
        _need(len(ip) >= 20 and ip[0] >> 4 == 4, "IPv4 header")
        header_len, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
        _need(20 <= header_len <= total <= len(ip), "IPv4 lengths")
        _need(http_capture._checksum(ip[:header_len]) == 0, "IPv4 checksum")
        _need(int.from_bytes(ip[6:8], "big") & 0xBFFF == 0, "fragmented or reserved IPv4")
        _need(ip[9] == 6, f"IP protocol {ip[9]} is not TCP: no DNS, UDP or ICMP is admitted")
        source = ".".join(str(b) for b in ip[12:16])
        destination = ".".join(str(b) for b in ip[16:20])
        _need((source, destination) in ((GUEST, PEER), (PEER, GUEST)), f"packet between {source} and {destination}")
        # The capture is taken at the guest's device, so a frame the guest sent carries its declared MAC
        # as source, and a frame for the guest is addressed to it. Anything else is not the guest's.
        if source == GUEST:
            _need(frame[6:12] == GUEST_MAC, f"a frame from {GUEST} sent from hardware address {frame[6:12].hex()}, not the guest's {GUEST_MAC.hex()}")
        else:
            _need(frame[0:6] == GUEST_MAC, f"a frame for {GUEST} addressed to hardware address {frame[0:6].hex()}, not the guest's {GUEST_MAC.hex()}")
        body = ip[header_len:total]
        _need(len(body) >= 20, "TCP header")
        offset = (body[12] >> 4) * 4
        _need(20 <= offset <= len(body) and body[12] & 15 == 0, "TCP data offset")
        pseudo = ip[12:20] + bytes((0, 6)) + len(body).to_bytes(2, "big")
        _need(http_capture._checksum(pseudo + body) == 0, "TCP checksum")
        sport, dport, seq, ack = struct.unpack_from("!HHII", body)
        window = int.from_bytes(body[14:16], "big")
        found.append(Segment(position, source == GUEST, sport, dport, seq, ack, body[13], body[offset:], window, _options(body[20:offset]), times[position]))
    return found, arp


class _Timing:
    """Where in the capture the bytes of one direction's stream were carried: (packet, start, end)."""

    def __init__(self, parts: list[tuple[int, int, int]], times: dict[int, int], fin: int) -> None:
        self.parts, self.times, self.fin = parts, times, fin

    def time_of(self, offset: int) -> int:
        """The capture time, in nanoseconds, of the first packet that carried the byte at `offset`."""
        return self.times[self.start(offset)]

    def start(self, offset: int) -> int:
        """The first packet that carried the byte at `offset`."""
        found = [index for index, begin, end in self.parts if begin <= offset < end]
        _need(bool(found), f"no packet carried stream byte {offset}")
        return min(found)

    def complete(self, end: int) -> int:
        """The packet by which every byte below `end` had been carried, whatever the order."""
        prefix, pending = 0, []
        for index, begin, finish in self.parts:
            pending.append((begin, finish))
            moved = True
            while moved:
                moved = False
                for low, high in pending:
                    if low <= prefix < high:
                        prefix, moved = high, True
            if prefix >= end:
                return index
        raise CaptureError(f"the stream never reached byte {end}")


def _reassemble(segs: list[Segment], isn: int, label: str, max_stream: int = MAX_STREAM) -> tuple[bytes, _Timing]:
    """One direction's byte stream, from the sender's own sequence numbers.

    Retransmission and reordering are allowed; a gap, a retransmission that differs, and a FIN
    that does not sit exactly at the end of the delivered bytes are refused.
    """
    pieces: list[tuple[int, bytes]] = []
    parts: list[tuple[int, int, int]] = []
    fin: int | None = None
    times = {s.index: s.time_ns for s in segs}
    for s in segs:
        if s.flags & TCP_SYN:
            _need(not s.payload, f"{label}: a SYN carries data")
            _need((s.seq & 0xFFFFFFFF) == isn, f"{label}: a SYN with sequence number {s.seq}, the handshake used {isn}")
            continue
        offset = (s.seq - isn - 1) & 0xFFFFFFFF
        _need(offset < 1 << 31, f"{label}: a segment before the connection's first byte")
        if s.payload:
            pieces.append((offset, s.payload))
            parts.append((s.index, offset, offset + len(s.payload)))
        if s.flags & TCP_FIN:
            end = offset + len(s.payload)
            _need(fin is None or fin == end, f"{label}: two different FINs")
            fin = end
    pieces.sort(key=lambda piece: piece[0])
    stream = bytearray()
    for offset, payload in pieces:
        _need(offset <= len(stream), f"{label}: a gap of {offset - len(stream)} bytes at offset {len(stream)}")
        overlap = bytes(stream[offset : offset + len(payload)])
        _need(payload[: len(overlap)] == overlap, f"{label}: a retransmission differs from the first bytes")
        stream += payload[len(overlap) :]
        _need(len(stream) <= max_stream, f"{label}: stream over {max_stream} bytes")
    _need(fin is not None, f"{label}: the stream was never closed with a FIN")
    _need(fin == len(stream), f"{label}: the FIN is at {fin} but {len(stream)} bytes were delivered")
    return bytes(stream), _Timing(parts, times, min(s.index for s in segs if s.flags & TCP_FIN))


def _check_acks(segs: list[Segment], guest_isn: int, peer_isn: int) -> None:
    """No segment acknowledges sequence space the other side had not yet sent.

    TCP discards a segment whose acknowledgement is beyond what its receiver has sent, so a payload
    carrying one never reached the guest (or the peer). The bound is the highest sequence number the
    other side had put in the capture by then, a SYN and a FIN each counting one. An acknowledgement
    below it is an ordinary lagging ACK and is admitted.
    """
    mask = 0xFFFFFFFF
    isn = {True: guest_isn, False: peer_isn}
    sent = {True: 0, False: 0}
    for s in segs:
        if s.flags & TCP_ACK:
            acknowledged = (s.ack - isn[not s.outgoing]) & mask
            _need(acknowledged < 1 << 31 and acknowledged <= sent[not s.outgoing],
                  f"a segment acknowledges {acknowledged} bytes of sequence space, the other side had sent {sent[not s.outgoing]}")
        relative = (s.seq - isn[s.outgoing]) & mask
        consumed = len(s.payload) + (1 if s.flags & (TCP_SYN | TCP_FIN) else 0)
        if consumed:
            if relative + consumed < 1 << 31:
                sent[s.outgoing] = max(sent[s.outgoing], relative + consumed)
        else:
            # An empty segment consumes no sequence space and so moves nothing; it can only carry the
            # sender's next number or an older one (a duplicate ACK, a keep-alive probe). One past it is
            # outside the receiver's window and is dropped before its acknowledgement is read.
            _need(relative <= sent[s.outgoing], f"an empty segment at sequence {relative}, the sender had used {sent[s.outgoing]}")


def _check_established(segs: list[Segment], peer_isn: int) -> None:
    """The peer's SYN is acknowledged before any application byte moves.

    The listener stays in SYN-RECEIVED until a segment acknowledges its SYN, and delivers no data and
    sends none until then. The segment that does may itself carry data (a guest segment with the ACK
    and a payload), but a guest payload before it, or a peer payload at or before it, never crossed.
    """
    mask = 0xFFFFFFFF
    acknowledging = [s.index for s in segs if s.outgoing and not s.flags & TCP_SYN and s.flags & TCP_ACK
                     and 1 <= ((s.ack - peer_isn) & mask) < 1 << 31]
    _need(bool(acknowledging), "no segment acknowledges the peer's SYN")
    first = min(acknowledging)
    for s in segs:
        if s.payload:
            _need(s.index >= first if s.outgoing else s.index > first,
                  f"a {'guest' if s.outgoing else 'peer'} payload recorded before the peer's SYN was acknowledged")


def streams(
    data: bytes, max_stream: int = MAX_STREAM, max_capture: int = http_capture.MAX_CAPTURE, max_frames: int = http_capture.MAX_FRAMES,
) -> tuple[bytes, bytes, int, _Timing, _Timing]:
    """The two streams of the capture's one connection, its ARP count, and where each was carried.

    Each direction is refused past `max_stream` bytes, and the capture past `max_capture` bytes or
    `max_frames` frames."""
    segs, arp = segments(data, max_capture, max_frames)
    syns = [s for s in segs if s.outgoing and s.flags & TCP_SYN and not s.flags & TCP_ACK]
    _need(len(syns) >= 1, "no connection attempt: the capture holds no guest SYN")
    _need(len({s.source_port for s in syns}) == 1, f"{len({s.source_port for s in syns})} connections, exactly one is admitted")
    _need(len({s.seq for s in syns}) == 1, "two SYNs with different sequence numbers")
    syn = syns[0]
    _need(syn.destination_port == PORT, f"the connection goes to port {syn.destination_port}, the exam declares {PORT}")
    for s in segs:
        _need(not s.flags & TCP_RST, "a reset: the connection did not close gracefully")
        ports = (s.source_port, s.destination_port)
        _need(ports == ((syn.source_port, PORT) if s.outgoing else (PORT, syn.source_port)), "a segment outside the one connection")
    synacks = [s for s in segs if not s.outgoing and s.flags & TCP_SYN and s.flags & TCP_ACK]
    for s in segs:
        if not s.flags & TCP_SYN:
            # An established endpoint discards a segment without ACK, so data or a FIN without it was
            # never received. PSH rides on data; no other flag is admitted.
            _need(s.flags & TCP_ACK, "a segment on the established connection without ACK")
            _need(s.flags & ~(TCP_ACK | TCP_PSH | TCP_FIN) == 0, f"a segment with flags {s.flags:#04x}, only ACK, PSH and FIN are admitted")
    for s in segs:
        if s.flags & TCP_SYN:
            _need(s.outgoing != bool(s.flags & TCP_ACK), "a SYN that is not the guest's SYN or the peer's SYN-ACK")
            _need(not s.flags & (TCP_FIN | TCP_RST), "a handshake packet that also carries a FIN or a reset")
            _need(s.flags & ~(TCP_SYN | TCP_ACK) == 0, f"a handshake packet with flags {s.flags:#04x}, only SYN and ACK are admitted")
    last_syn = max(i for i, s in enumerate(segs) if s.flags & TCP_SYN)
    first_data = next((i for i, s in enumerate(segs) if s.payload), len(segs))
    _need(last_syn < first_data, "a SYN after the connection carried data")
    _need(len({s.seq for s in synacks}) == 1, "the peer never accepted: no single SYN-ACK")
    # Nothing but the handshake itself may precede the handshake: a segment recorded before both the
    # guest's SYN and the peer's SYN-ACK belongs to no established connection, and a FIN is a close,
    # which needs the handshake to have finished.
    first_syn = min(i for i, s in enumerate(segs) if s.flags & TCP_SYN and not s.flags & TCP_ACK)
    first_synack = min(i for i, s in enumerate(segs) if s.flags & TCP_SYN and s.flags & TCP_ACK)
    for i, s in enumerate(segs):
        if not s.flags & TCP_SYN:
            _need(i > max(first_syn, first_synack), "a segment recorded before the handshake's SYN and SYN-ACK")
            _need(not s.flags & TCP_FIN or i > last_syn, "a FIN recorded before the handshake finished")
    _need(min(s.index for s in syns) < min(s.index for s in synacks), "the peer's SYN-ACK was recorded before the guest's SYN")
    expected_ack = (syn.seq + 1) & 0xFFFFFFFF
    for synack in synacks:
        _need(synack.ack == expected_ack, "a SYN-ACK acknowledges another sequence number")
    _need(len({_negotiated(s) for s in syns}) == 1, "a guest SYN retransmitted with another window or option")
    _need(len({_negotiated(s) for s in synacks}) == 1, "a peer SYN-ACK retransmitted with another window or option")
    _check_acks(segs, syn.seq, synacks[0].seq)
    _check_established(segs, synacks[0].seq)
    guest, guest_time = _reassemble([s for s in segs if s.outgoing], syn.seq, "guest stream", max_stream)
    peer, peer_time = _reassemble([s for s in segs if not s.outgoing], synacks[0].seq, "peer stream", max_stream)
    return guest, peer, arp, guest_time, peer_time


def split(stream: bytes, label: str, max_batch: int = MAX_BATCH_BYTES) -> tuple[list[bytes], list[tuple[int, int]]]:
    """Zenoh batches by their two-byte little-endian stream length, and where each one sits in the stream.

    A batch longer than `max_batch` bytes after its length prefix is refused."""
    batches, spans, at = [], [], 0
    while at < len(stream):
        _need(at + 2 <= len(stream), f"{label}: a stream length cut short")
        length = int.from_bytes(stream[at : at + 2], "little")
        _need(length > 0, f"{label}: an empty batch")
        _need(length <= max_batch, f"{label}: a batch of {length} bytes, the profile bounds a batch at {max_batch}")
        _need(at + 2 + length <= len(stream), f"{label}: a batch of {length} bytes with {len(stream) - at - 2} left")
        batches.append(stream[at + 2 : at + 2 + length])
        spans.append((at, at + 2 + length))
        at += 2 + length
    return batches, spans


# -------------------------------------------------------------------------------- wire


class _Reader:
    """Reads a batch the way `components/lib/src/zenoh_profile0.rs` does: canonical LEB128 within the
    bits a field allows, and every field present."""

    def __init__(self, data: bytes, at: int = 0) -> None:
        self.data, self.at = data, at

    def left(self) -> int:
        return len(self.data) - self.at

    def u8(self, label: str) -> int:
        _need(self.left() >= 1, f"{label}: truncated")
        self.at += 1
        return self.data[self.at - 1]

    def take(self, size: int, label: str) -> bytes:
        _need(0 <= size <= self.left(), f"{label}: {size} bytes with {self.left()} left")
        self.at += size
        return self.data[self.at - size : self.at]

    def leb(self, bits: int, label: str) -> int:
        maximum = -(-bits // 7)
        value = count = last = 0
        while True:
            byte = self.u8(label)
            last = byte & 0x7F
            value |= last << (7 * count)
            count += 1
            if not byte & 0x80:
                break
            _need(count != maximum, f"{label}: LEB128 over {bits} bits")
        _need(value >> bits == 0, f"{label}: LEB128 over {bits} bits")
        _need(not (count > 1 and last == 0), f"{label}: noncanonical LEB128")
        return value


LEB_LONG, LEB_SHORT = 32, 16
MAX_COOKIE, MAX_KEY, MAX_PAYLOAD_BYTES, MAX_ATTACHMENT = 64, 129, 12, 33
QOS_NETWORK_MAX = 0x1F
EXT_QOS_NETWORK, EXT_WIRE_EXPR, EXT_ATTACHMENT = 0x21, 0x5F, 0x43
ID_PUSH, ID_DECLARE, ID_OAM = 29, 30, 31
ID_D_KEYEXPR, ID_D_SUBSCRIBER, ID_U_SUBSCRIBER, ID_D_FINAL, ID_PUT = 0, 2, 3, 26, 1
FLAG_5, FLAG_6, FLAG_Z = 0x20, 0x40, 0x80
OAM_HEADER = FLAG_Z | FLAG_6 | ID_OAM


def _close(batch: bytes, who: str) -> None:
    """A session CLOSE is exactly `23 <reason>` with the reason one the profile names. The header's
    flag bits are the session flag and nothing else, and no extension follows."""
    _need(len(batch) == 2, f"a {who} CLOSE of {len(batch)} bytes")
    _need(batch[0] == zenoh_wire.ID_CLOSE | zenoh_wire.FLAG_A, f"a {who} CLOSE with header {batch[0]:#04x}, not a session close")
    _need(batch[1] <= MAX_CLOSE_REASON, f"a {who} CLOSE with reason {batch[1]}, the profile names 0 to {MAX_CLOSE_REASON}")


def _kind(batch: bytes) -> int:
    return batch[0] & 0x1F


def _cookie(reader: _Reader, label: str) -> bytes:
    size = reader.leb(LEB_SHORT, f"{label} cookie length")
    _need(size != 0, f"{label}: an empty cookie")
    _need(size <= MAX_COOKIE, f"{label}: a cookie of {size} bytes, the profile bounds it at {MAX_COOKIE}")
    return reader.take(size, f"{label} cookie")


def _init_fields(batch: bytes, label: str, ack: bool) -> bytes:
    """INIT: header, version 9, a peer, a canonical 1 to 16 byte ZID, optional size parameters (the
    default resolution and a non-zero batch size), and in an ACK a cookie. It ends exactly at the batch
    boundary. The header carries no extension flag: the exam names none. Returns the cookie, or b""."""
    reader = _Reader(batch, 1)
    _need(not batch[0] & zenoh_wire.FLAG_Z, f"{label}: an extension the exam does not name")
    _need(reader.u8(label) == zenoh_wire.PROTOCOL_VERSION, f"{label}: not wire version {zenoh_wire.PROTOCOL_VERSION}")
    packed = reader.u8(label)
    _need(not packed & 0x0C, f"{label}: reserved bits set in the ZID byte")
    _need(packed & 3 == zenoh_wire.WHATAMI_PEER, f"{label}: the peer is not in peer mode")
    zid = reader.take((packed >> 4) + 1, f"{label} ZID")
    _need(zid[-1] != 0, f"{label}: a ZID that ends in a zero byte is not canonical")
    if batch[0] & zenoh_wire.FLAG_S:
        resolution = reader.u8(f"{label} resolution")
        _need(not resolution & 0xF0, f"{label}: reserved bits set in the resolution")
        _need(resolution == zenoh_wire.DEFAULT_RESOLUTION, f"{label}: resolution {resolution}, the profile takes {zenoh_wire.DEFAULT_RESOLUTION}")
        size = int.from_bytes(reader.take(2, f"{label} batch size"), "little")
        _need(size != 0, f"{label}: a batch size of zero")
    cookie = _cookie(reader, label) if ack else b""
    _need(reader.left() == 0, f"{label}: {reader.left()} bytes after its fields")
    return cookie


def _open_fields(batch: bytes, label: str, ack: bool) -> tuple[int, int, bytes]:
    """OPEN: no extension, a non-zero lease (seconds with bit 6) and an initial sequence number, and in
    a SYN a cookie. Returns (lease_ms, initial_sn, cookie)."""
    _need(not batch[0] & zenoh_wire.FLAG_Z, f"{label}: an extension the exam does not name")
    reader = _Reader(batch, 1)
    lease = reader.leb(LEB_LONG, f"{label} lease")
    _need(lease > 0, f"{label}: a zero lease")
    initial_sn = reader.leb(LEB_LONG, f"{label} initial sequence number")
    cookie = b"" if ack else _cookie(reader, label)
    _need(reader.left() == 0, f"{label}: {reader.left()} bytes after its fields")
    return lease * (1000 if batch[0] & zenoh_wire.FLAG_T else 1), initial_sn, cookie


def _key(data: bytes, label: str) -> str:
    try:
        key = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CaptureError(f"{label}: a key that is not UTF-8") from error
    _need("*" not in key and "$" not in key, f"{label}: a wildcard key")
    _need(not any(ch in key for ch in "?#") and not key.startswith("/") and not key.endswith("/") and "//" not in key, f"{label}: an invalid key expression")
    return key


def _key_reference(reader: _Reader, named: bool, label: str) -> str:
    scope = reader.leb(LEB_SHORT, f"{label} scope")
    if not named:
        _need(scope != 0, f"{label}: an unnamed key in the global scope")
        return "alias"
    size = reader.leb(LEB_SHORT, f"{label} key length")
    _need(size <= MAX_KEY, f"{label}: a key of {size} bytes, the profile bounds it at {MAX_KEY}")
    _need(size != 0, f"{label}: an empty key")
    _key(reader.take(size, f"{label} key"), label)
    _need(scope == 0, f"{label}: a suffix after a non-zero scope")
    return "full"


def _qos(reader: _Reader, label: str) -> None:
    _need(reader.u8(label) == EXT_QOS_NETWORK, f"{label}: an extension the exam does not name")
    _need(reader.leb(LEB_LONG, f"{label} QoS value") <= QOS_NETWORK_MAX, f"{label}: a QoS value over {QOS_NETWORK_MAX}")


class _Seen:
    """What a peer's frames declared: the one alias it announced and the subscriber's resolved key."""

    def __init__(self) -> None:
        self.alias: tuple[int, str] | None = None
        self.subscriber: str | None = None
        self.subscriber_id: int | None = None
        self.active = False
        self.undeclared = False


def _declare(reader: _Reader, header: int, seen: "_Seen | None" = None) -> str:
    if header & FLAG_5:
        _need(not header & FLAG_6 and not header & FLAG_Z, "DECLARE with the interest flag: only the bare form is taken")
        reader.leb(LEB_LONG, "interest id")
        _need(reader.u8("declaration") == ID_D_FINAL, "DECLARE with the interest flag: not a DeclareFinal")
        return "final"
    _need(not header & FLAG_6, "DECLARE with bit 6 set")
    qos = bool(header & FLAG_Z)
    if qos:
        _qos(reader, "DECLARE")
    sub = reader.u8("declaration")
    kind = sub & 0x1F
    if kind == ID_D_KEYEXPR:
        _need(sub & FLAG_5, "DeclareKeyExpr that does not name its key")
        _need(not sub & FLAG_6 and not sub & FLAG_Z, "DeclareKeyExpr with a flag the exam does not name")
        alias_id = reader.leb(LEB_SHORT, "alias id")
        _need(alias_id != 0, "DeclareKeyExpr with alias id 0")
        start = reader.at
        _need(_key_reference(reader, True, "DeclareKeyExpr") == "full", "DeclareKeyExpr naming an alias")
        if seen is not None:
            _need(seen.alias is None, "a second alias, the profile holds one")
            seen.alias = (alias_id, _declared_key(reader.data, start))
        return "keyexpr"
    if kind == ID_D_SUBSCRIBER:
        _need(not sub & FLAG_Z, "DeclareSubscriber with an extension")
        subscriber_id = reader.leb(LEB_LONG, "subscriber id")
        start = reader.at
        named = bool(sub & FLAG_5)
        _key_reference(reader, named, "DeclareSubscriber")
        if seen is not None:
            _need(seen.subscriber is None, "a second subscriber, the profile holds one")
            if named:
                seen.subscriber = _declared_key(reader.data, start)
            else:
                scope = _Reader(reader.data, start).leb(LEB_SHORT, "subscriber alias")
                _need(sub & FLAG_6, "a subscriber alias in the receiver's mapping, which this side never declared")
                _need(seen.alias is not None and seen.alias[0] == scope, "a subscriber through an alias nobody declared")
                seen.subscriber = seen.alias[1]
            seen.subscriber_id, seen.active = subscriber_id, True
        return "subscriber"
    if kind == ID_U_SUBSCRIBER and qos:
        # What a stock peer sends: the QoS is the DECLARE's, and the undeclaration names the subscriber
        # by id alone, with no extension and so no key. The session removes the subscriber it holds
        # under that id; an id it does not hold is refused.
        _need(sub == ID_U_SUBSCRIBER, "UndeclareSubscriber by id with another header")
        undeclared_id = reader.leb(LEB_LONG, "subscriber id")
        if seen is not None:
            _need(seen.active and seen.subscriber_id == undeclared_id, "an UndeclareSubscriber that does not name the subscriber the peer holds")
            seen.active, seen.undeclared = False, True
        return "undeclare"
    if kind == ID_U_SUBSCRIBER:
        _need(sub == FLAG_Z | ID_U_SUBSCRIBER, "UndeclareSubscriber with another header")
        undeclared_id = reader.leb(LEB_LONG, "subscriber id")
        _need(reader.u8("UndeclareSubscriber") == EXT_WIRE_EXPR, "UndeclareSubscriber without its wire expression")
        size = reader.leb(LEB_LONG, "wire expression length")
        _need(size <= 2 + MAX_KEY, f"a wire expression of {size} bytes")
        inner = _Reader(reader.take(size, "wire expression"))
        flags = inner.u8("wire expression flags")
        _need(not flags & ~3, "wire expression flags the exam does not name")
        _need(inner.leb(LEB_SHORT, "wire expression scope") == 0 and flags & 1 and inner.left() != 0, "an invalid wire expression")
        undeclared_key = _key(inner.take(inner.left(), "wire expression"), "UndeclareSubscriber")
        if seen is not None:
            # The session clears its remote subscriber only for the one it holds, by id and by key.
            _need(seen.active and seen.subscriber_id == undeclared_id and seen.subscriber == undeclared_key,
                  "an UndeclareSubscriber that does not name the subscriber the peer holds")
            seen.active, seen.undeclared = False, True
        return "undeclare"
    raise CaptureError(f"a declaration of kind {kind} the exam does not name")


def _declared_key(data: bytes, start: int) -> str:
    """The key a wire expression at `start` names in full: scope, length, bytes."""
    reader = _Reader(data, start)
    reader.leb(LEB_SHORT, "scope")
    return reader.take(reader.leb(LEB_SHORT, "key length"), "key").decode("utf-8")


def _push(reader: _Reader, header: int) -> str:
    _need(not header & FLAG_Z, "PUSH with an extension")
    _key_reference(reader, bool(header & FLAG_5), "PUSH")
    body = reader.u8("PUSH body")
    _need(body & 0x1F == ID_PUT and not body & (FLAG_5 | FLAG_6), "PUSH that does not carry a plain Put")
    _need(body & FLAG_Z, "a Put without its attachment")
    _need(reader.u8("Put") == EXT_ATTACHMENT, "a Put extension the exam does not name")
    size = reader.leb(LEB_LONG, "attachment length")
    _need(size == MAX_ATTACHMENT, f"an attachment of {size} bytes, the profile takes {MAX_ATTACHMENT}")
    attachment = reader.take(size, "attachment")
    _need(attachment[16] == zenoh_wire.GID_BYTES, "an attachment whose GID length is not 16")
    payload = reader.leb(LEB_LONG, "payload length")
    _need(payload <= MAX_PAYLOAD_BYTES, f"a payload of {payload} bytes, the profile bounds it at {MAX_PAYLOAD_BYTES}")
    reader.take(payload, "payload")
    return "push"


def _oam(reader: _Reader, header: int) -> str:
    _need(header == OAM_HEADER, "an OAM with another header")
    _need(reader.leb(LEB_SHORT, "OAM id") == 1, "an OAM that is not the link-state one")
    _qos(reader, "OAM")
    reader.take(reader.leb(LEB_SHORT, "OAM body length"), "OAM body")
    return "oam"


def _frame_messages(batch: bytes, label: str, seen: "_Seen | None" = None) -> tuple[int, list[str]]:
    """A reliable FRAME: its sequence number, then whole network messages to the end of the batch.

    Returns the kinds in order. At least one message is required, and a trailing byte that is not
    the start of a message the profile names refuses the batch."""
    _need(batch[0] == zenoh_wire.ID_FRAME | zenoh_wire.FLAG_R, f"{label}: a FRAME header {batch[0]:#04x}, the profile takes only the reliable form 0x25")
    reader = _Reader(batch, 1)
    sequence = reader.leb(LEB_LONG, f"{label} sequence number")
    _need(reader.left() != 0, f"{label}: a FRAME that carries no message")
    kinds = []
    while reader.left():
        header = reader.u8(label)
        kind = header & 0x1F
        if kind == ID_DECLARE:
            kinds.append(_declare(reader, header, seen))
        elif kind == ID_PUSH:
            # The connector declares no subscriber, so a PUSH to it names a key it never declared:
            # `Session::on_frame` refuses it with UndeclaredKey and rolls back the whole frame.
            _need(seen is None, f"{label}: a PUSH to a connector that declared no subscriber")
            kinds.append(_push(reader, header))
        elif kind == ID_OAM:
            kinds.append(_oam(reader, header))
        else:
            raise CaptureError(f"{label}: a network message of kind {kind} the exam does not name")
    return sequence, kinds


def judge_guest(batches: list[bytes], reported: dict, contract: dict) -> dict:
    """The guest's batches: a connector's INIT_SYN and OPEN_SYN, the four samples, keep-alives, a close."""
    _need(len(batches) >= 2, "the guest sent fewer than an INIT_SYN and an OPEN_SYN")
    init, opened = batches[0], batches[1]
    _need(_kind(init) == zenoh_wire.ID_INIT and not init[0] & zenoh_wire.FLAG_A, "the first guest batch is not an INIT_SYN")
    _init_fields(init, "INIT_SYN", False)
    _need(_kind(opened) == zenoh_wire.ID_OPEN and not opened[0] & zenoh_wire.FLAG_A, "the second guest batch is not an OPEN_SYN")
    lease, initial_sn, cookie = _open_fields(opened, "OPEN_SYN", False)
    _need(lease == LEASE_MS, f"the guest announced a {lease} ms lease, the exam declares {LEASE_MS}")
    _need(initial_sn == reported["initial_sn"], f"the OPEN_SYN announces initial sequence number {initial_sn}, the connector reported {reported['initial_sn']}")
    frames: list[bytes] = []
    keep_alives = 0
    closed = False
    first_frame = last_frame = None
    keep_alive_batches = []
    for index, batch in enumerate(batches[2:], start=2):
        _need(not closed, "a batch after the guest's CLOSE")
        if batch == bytes([ID_KEEP_ALIVE]):
            keep_alives += 1
            keep_alive_batches.append(index)
        elif _kind(batch) == zenoh_wire.ID_CLOSE:
            _close(batch, "guest")
            closed = True
        elif batch[0] == zenoh_wire.ID_FRAME | zenoh_wire.FLAG_R:
            frames.append(batch)
            first_frame = index if first_frame is None else first_frame
            last_frame = index
        else:
            raise CaptureError(f"a guest batch the exam does not name: header {batch[0]:#04x}, {len(batch)} bytes")
    _need(len(frames) == SAMPLES, f"the guest put {len(frames)} frames on the wire, the demo has {SAMPLES} samples")
    _need(sorted(reported["sent"]) == list(range(SAMPLES)), "the guest reported its sent batches for the wrong samples")
    received = []
    for index, (sequence, _value, cdr) in enumerate(contract["samples"]):
        batch = frames[index]
        _need(batch.hex() == reported["sent"][sequence], f"sample {sequence}: the wire holds other bytes than the guest reported")
        try:
            decoded = zenoh_wire.decode_push_frame(batch)
        except zenoh_wire.WireError as error:
            raise CaptureError(f"sample {sequence}: {error}") from error
        _need(decoded["key"] == contract["key"], f"sample {sequence}: key expression {decoded['key']!r} is not the demo's")
        _need(decoded["sn"] <= U32, f"sample {sequence}: frame sn {decoded['sn']} does not fit 32 bits")
        _need(decoded["sn"] == (initial_sn + index) & U32, f"sample {sequence}: frame sn {decoded['sn']} is not {initial_sn} + {index} modulo 2**32")
        _need(decoded["payload"].hex() == cdr, f"sample {sequence}: the payload is not the contract's")
        _need(decoded["sequence"] == sequence + ATTACHMENT_SEQUENCE_BASE, f"sample {sequence}: attachment sequence {decoded['sequence']}, the publisher sends {sequence + ATTACHMENT_SEQUENCE_BASE}")
        _need(decoded["timestamp"] == ATTACHMENT_TIMESTAMP_BASE + sequence, f"sample {sequence}: attachment timestamp {decoded['timestamp']}, the publisher sends {ATTACHMENT_TIMESTAMP_BASE + sequence}")
        _need(decoded["gid"] == DEMO_GID, f"sample {sequence}: attachment GID {decoded['gid'].hex()}, the publisher sends {DEMO_GID.hex()}")
        attachment = zenoh_wire.attachment(decoded["sequence"], decoded["timestamp"], decoded["gid"])
        again = zenoh_wire.frame(decoded["sn"], zenoh_wire.push_put(decoded["key"], attachment, decoded["payload"], True))
        _need(again == batch, f"sample {sequence}: not the canonical encoding of its own fields")
        received.append((decoded["key"], decoded["payload"].hex(), attachment.hex()))
    return {
        "frames": len(frames), "bytes": sum(len(f) for f in frames), "keep_alives": keep_alives, "closed": closed,
        "samples": received, "cookie": cookie, "first_frame": first_frame, "last_frame": last_frame, "keep_alive_batches": keep_alive_batches,
    }


def judge_peer(batches: list[bytes], key: str) -> dict:
    """The peer's batches, each parsed to its fields: an INIT_ACK, an OPEN_ACK, then frames whose every
    message is parsed, keep-alives and at most one close, after which nothing."""
    _need(len(batches) >= 2, "the peer sent fewer than an INIT_ACK and an OPEN_ACK")
    _need(_kind(batches[0]) == zenoh_wire.ID_INIT and batches[0][0] & zenoh_wire.FLAG_A, "the first peer batch is not an INIT_ACK")
    cookie = _init_fields(batches[0], "INIT_ACK", True)
    _need(_kind(batches[1]) == zenoh_wire.ID_OPEN and batches[1][0] & zenoh_wire.FLAG_A, "the second peer batch is not an OPEN_ACK")
    peer_lease_ms, expected, _cookie_unused = _open_fields(batches[1], "OPEN_ACK", True)
    seen = _Seen()
    closed = False
    subscriber = undeclared = close_at = None
    for index, batch in enumerate(batches[2:], start=2):
        _need(not closed, "a peer batch after the peer's CLOSE")
        if batch == bytes([ID_KEEP_ALIVE]):
            continue
        if _kind(batch) == zenoh_wire.ID_CLOSE:
            _need(len(batch) == 2 and batch[0] in (zenoh_wire.ID_CLOSE, zenoh_wire.ID_CLOSE | zenoh_wire.FLAG_A), f"a peer CLOSE of {len(batch)} bytes with header {batch[0]:#04x}")
            _need(batch[1] <= MAX_CLOSE_REASON, f"a peer CLOSE with reason {batch[1]}, the profile names 0 to {MAX_CLOSE_REASON}")
            closed, close_at = True, index
        elif _kind(batch) == zenoh_wire.ID_FRAME:
            was_undeclared = seen.undeclared
            sequence, _kinds = _frame_messages(batch, "a peer FRAME", seen)
            _need(sequence == expected, f"a peer FRAME with sequence number {sequence}, the OPEN_ACK announced {expected}")
            expected = (expected + 1) & 0xFFFFFFFF
            # The subscription counts from the frame that leaves it declared: a declaration the same
            # frame undeclares never held.
            if subscriber is None and seen.active:
                subscriber = index
            if seen.undeclared and not was_undeclared:
                undeclared = index
        else:
            raise CaptureError(f"a peer batch the exam does not name: header {batch[0]:#04x}, {len(batch)} bytes")
    _need(seen.subscriber is None or seen.subscriber == key, f"the peer's subscriber is on {seen.subscriber!r}, not the demo key")
    return {"batches": len(batches), "cookie": cookie, "subscriber": subscriber, "undeclared": undeclared, "close": close_at, "lease_ms": peer_lease_ms}


def _silence(who: str, times_ns: list[int], lease_ms: int) -> None:
    for before, after_ in zip(times_ns, times_ns[1:], strict=False):
        gap = after_ - before
        _need(gap <= lease_ms * 1_000_000, f"{who} was silent for {gap} ns, over the {lease_ms} ms lease it announced ({lease_ms * 1_000_000} ns)")


def judge_capture(data: bytes, reported: dict, contract: dict) -> dict:
    guest, peer, arp, guest_time, peer_time = streams(data)
    guest_batches, guest_spans = split(guest, "guest stream")
    peer_batches, peer_spans = split(peer, "peer stream")
    result = judge_guest(guest_batches, reported, contract)
    seen = judge_peer(peer_batches, contract["key"])
    _need(result["cookie"] == seen["cookie"], "the OPEN_SYN does not echo the INIT_ACK's cookie")
    _need(seen["subscriber"] is not None, "the peer never declared a subscriber for the connector to match")
    # Cross-direction order, from the packet each stream's bytes were carried in. A session is built in
    # turns: INIT_SYN, INIT_ACK, OPEN_SYN, OPEN_ACK, the peer's declarations, and only then the samples.
    def after(first: int, then: int, what: str) -> None:
        _need(then > first, f"{what}: packet {then} does not follow packet {first}")

    after(guest_time.complete(guest_spans[0][1]), peer_time.start(peer_spans[0][0]), "the INIT_ACK came before the INIT_SYN was complete")
    after(peer_time.complete(peer_spans[0][1]), guest_time.start(guest_spans[1][0]), "the OPEN_SYN came before the INIT_ACK was complete")
    after(guest_time.complete(guest_spans[1][1]), peer_time.start(peer_spans[1][0]), "the OPEN_ACK came before the OPEN_SYN was complete")
    after(peer_time.complete(peer_spans[seen["subscriber"]][1]), guest_time.start(guest_spans[result["first_frame"]][0]), "the first sample was sent before the peer's subscriber declaration was complete")
    # A KEEP_ALIVE is traffic on an open session, and a connector is not open until the OPEN_ACK has arrived.
    open_ack_done = peer_time.complete(peer_spans[1][1])
    for index in result["keep_alive_batches"]:
        after(open_ack_done, guest_time.start(guest_spans[index][0]), "a guest KEEP_ALIVE was carried before the OPEN_ACK was complete")
    # End of stream is read as a close: `zenoh_link::fill` reports Closed once the peer's FIN is in and
    # nothing is pending, so the publisher fails if that comes before it has sent every sample.
    after(guest_time.complete(guest_spans[result["last_frame"]][1]), peer_time.fin, "the peer's FIN came before the last sample was sent")
    # An open session is closed by the other side after a lease of silence (`Session::expire`: strictly
    # more than the lease). The guest's silence is judged against the 2000 ms it announced, the peer's
    # against the lease its OPEN_ACK announced, from each side's OPEN to its last batch.
    _silence("the guest", [guest_time.time_of(start) for start, _end in guest_spans[1:]], LEASE_MS)
    _silence("the peer", [peer_time.time_of(start) for start, _end in peer_spans[1:]], seen["lease_ms"])
    if seen["undeclared"] is not None:
        after(guest_time.complete(guest_spans[result["last_frame"]][1]), peer_time.start(peer_spans[seen["undeclared"]][0]), "the peer undeclared its subscriber before the last sample was sent")
    if seen["close"] is None:
        # The end of the peer's stream is read by `Link::fill` as `LinkError::Closed`, which `pump`
        # propagates before the publisher can report success, so a stock listener's session ends in
        # a Zenoh CLOSE (`Notice::Closed`) ahead of its FIN, as the captured listens-08-close does.
        raise CaptureError("the peer's stream ends without a Zenoh CLOSE, so its end of stream is an error to the connector")
    if seen["close"] is not None:
        # The connector fails with PeerClosedEarly on a CLOSE before it has sent all four samples.
        after(guest_time.complete(guest_spans[result["last_frame"]][1]), peer_time.start(peer_spans[seen["close"]][0]), "the peer closed before the last sample was sent")
    result.update(peer_batches=seen["batches"], guest_stream=len(guest), peer_stream=len(peer), arp=arp)
    return result


# ---------------------------------------------------------------------------- transcript


def guest_lines(contract: dict, initial_sn: int = 0) -> list[str]:
    """What the connector prints when an honest guest runs against an external listener."""
    key = contract["key"]
    lines = [f"[{PUBLISHER}] denial class={cls} refused=1" for cls in DENIALS]
    lines += [f"[{PUBLISHER}] session open role=connector initial_sn={initial_sn} lease_ms={LEASE_MS}", f"[{PUBLISHER}] declaration matched key={key}"]
    for sequence, _value, cdr in contract["samples"]:
        att = zenoh_wire.attachment(sequence + ATTACHMENT_SEQUENCE_BASE, ATTACHMENT_TIMESTAMP_BASE + sequence, DEMO_GID)
        batch = zenoh_wire.frame((initial_sn + sequence) & U32, zenoh_wire.push_put(key, att, bytes.fromhex(cdr), True))
        lines.append(f"[{PUBLISHER}] wire sent sample={sequence} hex={batch.hex()}")
    lines.append(f"[{PUBLISHER}] session closed samples={SAMPLES}")
    return lines


def judge_guest_lines(lines: list[str], contract: dict) -> dict:
    """The connector's report: its denials, one session, one match, four sent batches, one close.

    Returns the hex of each batch it says it sent, by sample, and the initial sequence number it
    says it opened with, for the wire to be held against.
    """
    own = [line for line in lines if line.startswith(f"[{PUBLISHER}] ")]
    _need(len(own) == len(lines), "a line from a node other than the connector")
    key = re.escape(contract["key"])
    patterns = {
        "session": rf"\[{PUBLISHER}\] session open role=connector initial_sn=(\d+) lease_ms={LEASE_MS}",
        "match": rf"\[{PUBLISHER}\] declaration matched key={key}",
        "close": rf"\[{PUBLISHER}\] session closed samples={SAMPLES}",
    }
    for name, pattern in patterns.items():
        count = len([1 for line in lines if re.fullmatch(pattern, line)])
        _need(count == 1, f"{name}: {count} matching lines, expected exactly one")
    for cls in DENIALS:
        count = lines.count(f"[{PUBLISHER}] denial class={cls} refused=1")
        _need(count == 1, f"{cls} denial: {count} lines, expected exactly one")
    _need(len([1 for line in lines if " denial " in line]) == len(DENIALS), "a denial the exam does not name")
    sent = {}
    wire = [m for line in lines if (m := re.fullmatch(rf"\[{PUBLISHER}\] wire sent sample=(\d+) hex=([0-9a-f]+)", line))]
    _need(len(wire) == SAMPLES, f"{len(wire)} sent batches reported, expected {SAMPLES}")
    for m in wire:
        sent[int(m.group(1))] = m.group(2)
    _need(sorted(sent) == list(range(SAMPLES)), "the reported samples are not 0 to 3 once each")
    named = [
        re.compile(rf"\[{PUBLISHER}\] denial class=(?:{'|'.join(DENIALS)}) refused=1"),
        re.compile(patterns["session"]),
        re.compile(patterns["match"]),
        re.compile(rf"\[{PUBLISHER}\] wire sent sample=[0-3] hex=[0-9a-f]+"),
        re.compile(patterns["close"]),
    ]
    for line in lines:
        _need(any(pattern.fullmatch(line) for pattern in named), f"a connector line the exam does not name: {line[:80]!r}")
    position = {line: i for i, line in enumerate(lines)}
    opened = next(i for i, line in enumerate(lines) if re.fullmatch(patterns["session"], line))
    matched = next(i for i, line in enumerate(lines) if re.fullmatch(patterns["match"], line))
    where = [next(i for i, line in enumerate(lines) if f" wire sent sample={n} " in line) for n in range(SAMPLES)]
    closed = position[f"[{PUBLISHER}] session closed samples={SAMPLES}"]
    for cls in DENIALS:
        _need(position[f"[{PUBLISHER}] denial class={cls} refused=1"] < opened, f"the {cls} denial came after the session opened")
    _need(opened < matched < where[0], "the order is not session open, declaration matched, first sample")
    _need(where == sorted(where), f"the sent batches are reported in the order of samples {where}, not 0 to {SAMPLES - 1}")
    _need(closed == len(lines) - 1 and closed > where[-1], "the session did not close last")
    initial_sn = int(re.fullmatch(patterns["session"], lines[opened]).group(1))
    return {"sent": sent, "initial_sn": initial_sn}


# ------------------------------------------------------------------------------ receipt


def judge_receipt(listen: str, remote_peers: int, samples: list[tuple[str, str, str]], wire: list[tuple[str, str, str]]) -> int:
    """The stock listener's own account of what its subscriber delivered, against the wire."""
    _need(listen == LISTEN, f"the listener reports {listen!r}, the exam declares {LISTEN!r}")
    _need(1 <= remote_peers <= 8, f"the listener saw {remote_peers} remote peers")
    _need(len(samples) == SAMPLES, f"the listener delivered {len(samples)} samples, expected {SAMPLES}")
    for index, (got, sent) in enumerate(zip(samples, wire, strict=True)):
        _need(got[0] == sent[0], f"sample {index}: the listener matched key {got[0]!r}, the wire carried {sent[0]!r}")
        _need(got[1] == sent[1], f"sample {index}: the listener delivered payload {got[1]}, the wire carried {sent[1]}")
        _need(got[2] == sent[2], f"sample {index}: the listener delivered another attachment than the wire carried")
    return len(samples)


CLOSURE = "sel4-zenoh-external"
GENERATION = 169
INSTANCES = ("init", "network-service", "virtio-net-driver", PUBLISHER, SUBSCRIBER)
INTERFACE = {"holder": "network-service", "address": GUEST, "gateway": PEER, "mac": "52:54:00:53:4c:01", "prefixLen": 24}


def external_from_text(text: str) -> tuple:
    """Generation, instances, interfaces, destinations and applications of a derived manifest."""
    generation, instances, destinations, applications = zenoh_exchange.composition_from_text(text)
    return generation, instances, zenoh_exchange.parse_rows(text, "networkInterfaces"), destinations, applications


def check_external_rows(generation: int, instances: list[str], interfaces: list[dict], destinations: list[dict], applications: list[dict]) -> int:
    """Refuse a composition that grants the demo more or less than one outbound connection.

    Returns the number of authority facts verified.
    """
    facts = 0

    def need(condition: bool, message: str) -> None:
        nonlocal facts
        if not condition:
            raise CaptureError(message)
        facts += 1

    need(generation == GENERATION, f"generation {generation}, the exam pins {GENERATION}")
    need(sorted(instances) == sorted(INSTANCES), f"instances {sorted(instances)}, expected {sorted(INSTANCES)}")
    need(len(interfaces) == 1, f"{len(interfaces)} network interfaces, the exam declares one")
    need({k: interfaces[0].get(k) for k in INTERFACE} == INTERFACE, "the interface is not the user-network address, gateway and MAC the exam declares")
    need(len(destinations) == 1, f"{len(destinations)} destination rows, the exam declares one connect endpoint")
    row = destinations[0]
    need(row.get("holder") == PUBLISHER, "the destination is not held by the publisher")
    need((row.get("address"), row.get("port")) == (PEER, PORT), f"the destination is not {PEER}:{PORT}")
    need(row.get("transport") == "tcp" and row.get("addressKind") == "ipv4", "the destination is not exact IPv4 TCP")
    need(sorted(row.get("rights", [])) == ["connect", "recv", "send"], "the destination rights are not exactly connect, send, recv")
    need(row.get("listenerLimit") == 0 and row.get("dnsRecordLimit") == 0, "the destination grants listen or DNS authority")
    need(len(applications) == 1 and applications[0].get("holder") == PUBLISHER, "the only network application is not the publisher")
    publisher = applications[0]
    need(publisher.get("role") == "client" and publisher.get("rights") == [], "the publisher is not a rightless client")
    need(publisher.get("backend") == "external", "the publisher does not use the external backend")
    need(publisher.get("admittedPeer") == "" and publisher.get("admittedPeerAddress") == "", "the publisher admits a peer")
    need(all(r.get("holder") != SUBSCRIBER for r in destinations + applications), "the subscriber holds network authority")
    return facts


def good_external() -> tuple:
    interface = dict(INTERFACE)
    destination = {
        "holder": PUBLISHER, "transport": "tcp", "addressKind": "ipv4", "address": PEER, "port": PORT,
        "rights": ["connect", "send", "recv"], "listenerLimit": 0, "dnsRecordLimit": 0,
    }
    publisher = {"holder": PUBLISHER, "role": "client", "backend": "external", "rights": [], "admittedPeer": "", "admittedPeerAddress": ""}
    return (GENERATION, list(INSTANCES), [interface], [destination], [publisher])


def external_mutations() -> list[tuple[str, Callable[[list], None]]]:
    def interface(**c: object) -> Callable[[list], None]:
        return lambda v: v[2][0].update(c)

    def dest(**c: object) -> Callable[[list], None]:
        return lambda v: v[3][0].update(c)

    def publisher(**c: object) -> Callable[[list], None]:
        return lambda v: v[4][0].update(c)

    return [
        ("generation 168", lambda v: v.__setitem__(0, 168)),
        ("generation 170", lambda v: v.__setitem__(0, 170)),
        ("an extra instance", lambda v: v[1].append("zenoh-router")),
        ("the subscriber missing", lambda v: v[1].remove(SUBSCRIBER)),
        ("no driver", lambda v: v[1].remove("virtio-net-driver")),
        ("no interface", lambda v: v[2].clear()),
        ("two interfaces", lambda v: v[2].append(dict(v[2][0]))),
        ("another guest address", interface(address="10.0.2.16")),
        ("another gateway", interface(gateway="10.0.2.3")),
        ("another MAC", interface(mac="52:54:00:53:4c:02")),
        ("another prefix", interface(prefixLen=16)),
        ("no destination", lambda v: v[3].clear()),
        ("a second destination", lambda v: v[3].append(dict(v[3][0], port=PORT + 1))),
        ("a resolver row", lambda v: v[3].append(dict(v[3][0], holder="network-service", transport="udp", port=53))),
        ("port 17446, one under", dest(port=PORT - 1)),
        ("port 17448, one over", dest(port=PORT + 1)),
        ("the loopback address", dest(address="127.0.0.1")),
        ("a DNS name", dest(addressKind="dns", address="example.test")),
        ("a udp destination", dest(transport="udp")),
        ("a missing right", dest(rights=["connect", "send"])),
        ("an extra right", dest(rights=["connect", "send", "recv", "listen"])),
        ("a listen limit", dest(listenerLimit=1)),
        ("a resolver record", dest(dnsRecordLimit=1)),
        ("the destination held by the subscriber", dest(holder=SUBSCRIBER)),
        ("a loopback backend", publisher(backend="loopback")),
        ("a publisher with rights", publisher(rights=["listen"])),
        ("a listening publisher", publisher(role="listener")),
        ("a publisher admitting a peer", publisher(admittedPeer=SUBSCRIBER)),
        ("a subscriber application row", lambda v: v[4].append(dict(v[4][0], holder=SUBSCRIBER))),
        ("no application", lambda v: v[4].clear()),
    ]


def external_controls() -> tuple[int, int]:
    """Judge the honest composition, then refuse every mutation. Returns (facts, refused)."""
    good = good_external()
    facts = check_external_rows(*good)
    refused = 0
    for label, change in external_mutations():
        copy_ = copy.deepcopy(list(good))
        change(copy_)
        try:
            check_external_rows(*copy_)
        except CaptureError:
            refused += 1
            continue
        raise CaptureError(f"control: the composition judge accepted {label}")
    return facts, refused


def read_receipt(path: Path) -> tuple[str, int, list[tuple[str, str, str]]]:
    """Decode a listener record through contracts/zenoh-external-receipt/v1, then read its values.

    The contract's decoder refuses a closed-set violation, a wrong version and every bound; what is
    read afterwards is the decoder's own spelling of an accepted record.
    """
    scratch = ROOT / "build" / "zenoh-external" / "decoder"
    scratch.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "contracts" / "zenoh-external-receipt" / "v1" / "schema.zt", scratch / "schema.zt")
    (scratch / "decode.zt").write_text(
        's ::= import "schema.zt"; env ::= import stdlib.env; load ::= import stdlib.load; '
        "main :: { env : Env; load : Load; } -> Validation DecodeIssue s.Receipt ! { * env.GetEffects; * load.ZtiEffects; } "
        '= caps => [ path := env.get caps.env "SLIME_RECEIPT_PATH" ?? ""; s.decodeReceipt (load.zti caps.load path) ]; main\n',
        encoding="utf-8",
    )
    try:
        decoded = zutai_cli.evaluate("run", scratch / "decode.zt", input_path=path, env_var="SLIME_RECEIPT_PATH")
    except zutai_cli.ZutaiError as error:
        raise CaptureError(f"the listener record does not decode: {error}") from error
    _need(decoded.startswith("#valid"), f"the listener record is refused by its contract: {decoded[:160]}")
    listen = re.search(r'\blisten = "([^"]*)"', decoded)
    peers = re.search(r"\bmaxRemotePeers = (\d+)", decoded)
    _need(listen is not None and peers is not None, "the decoded record has no listen or maxRemotePeers")
    rows = re.findall(r'\{ attachmentHex = "([0-9a-f]*)";\s*key = "([^"]*)";\s*payloadHex = "([0-9a-f]*)" \}', decoded)
    _need(len(rows) == decoded.count("attachmentHex ="), "a sample the reader cannot parse")
    return listen.group(1), int(peers.group(1)), [(key, payload, attachment) for attachment, key, payload in rows]


def receipt_cases(contract: dict) -> list[tuple[str, str, bool]]:
    """(label, record text, accepted) for the listener record, on each boundary the contract fixes."""
    key = contract["key"]
    att = "00" * 8 + "e8030000" + "00" * 4 + "10" + "e0" * 16
    payload = contract["samples"][0][2]

    def sample(k: str = key, p: str = payload, a: str = att) -> str:
        return f'    {{ key = "{k}"; payloadHex = "{p}"; attachmentHex = "{a}"; }};\n'

    def record(version: int = 1, peer: str = "1.0.0", peers: int = 1, rows: list[str] | None = None, top: str = "", inner: str = "") -> str:
        body = "".join(rows if rows is not None else [sample() for _ in range(SAMPLES)])
        if inner:
            body = body.replace(" };\n", f" {inner} }};\n", 1)
        return f'{{\n  formatVersion = {version};\n  peerVersion = "{peer}";\n  listen = "{LISTEN}";\n  maxRemotePeers = {peers};\n{top}  samples = [\n{body}  ];\n}}\n'

    def with_first(first: str) -> list[str]:
        return [first] + [sample() for _ in range(SAMPLES - 1)]

    # The listener writes its record with its own writer. Decoding that output, rather than text
    # written here, is what makes the producer and the contract unable to drift unseen.
    written = zenoh_listener_peer.receipt_text(
        LISTEN, 1, [(key, bytes.fromhex(payload), bytes.fromhex(att)) for _ in range(SAMPLES)]
    )
    return [
        ("a record written by the listener's own writer", written, True),
        ("an honest record", record(), True),
        ("the shortest key, 1 byte", record(rows=with_first(sample(k="k"))), True),
        ("a key of 128 bytes, one under the longest", record(rows=with_first(sample(k="k" * 128))), True),
        ("the longest key, 129 bytes", record(rows=with_first(sample(k="k" * 129))), True),
        ("a payload of 11 bytes, one under the longest", record(rows=with_first(sample(p="00" * 11))), True),
        ("the longest payload, 12 bytes", record(rows=with_first(sample(p="00" * 12))), True),
        ("two remote peers, one over the fewest", record(peers=2), True),
        ("seven remote peers, one under the most", record(peers=7), True),
        ("eight remote peers", record(peers=8), True),
        ("three samples", record(rows=[sample() for _ in range(SAMPLES - 1)]), False),
        ("five samples", record(rows=[sample() for _ in range(SAMPLES + 1)]), False),
        ("format version 2", record(version=2), False),
        ("another peer version", record(peer="1.1.0"), False),
        ("no remote peer", record(peers=0), False),
        ("nine remote peers", record(peers=9), False),
        ("a key of 130 bytes", record(rows=with_first(sample(k="k" * 130))), False),
        ("an empty key", record(rows=with_first(sample(k=""))), False),
        ("a payload of 13 bytes", record(rows=with_first(sample(p="00" * 13))), False),
        ("uppercase payload hex", record(rows=with_first(sample(p="0A"))), False),
        ("odd-length payload hex", record(rows=with_first(sample(p="0"))), False),
        ("an attachment of 32 bytes", record(rows=with_first(sample(a=att[:-2]))), False),
        ("an attachment of 34 bytes", record(rows=with_first(sample(a=att + "00"))), False),
        ("a field the contract does not name", record(top='  note = "x";\n'), False),
        ("a sample field the contract does not name", record(inner='note = "x";'), False),
    ]


def receipt_controls(contract: dict) -> tuple[int, int]:
    """Run each record through the contract's decoder and the reader. Returns (accepted, refused)."""
    scratch = ROOT / "build" / "zenoh-external"
    scratch.mkdir(parents=True, exist_ok=True)
    path = scratch / "receipt-control.zti"
    accepted = refused = 0
    for label, text, should in receipt_cases(contract):
        path.write_text(text, encoding="utf-8")
        try:
            read_receipt(path)
            took = True
        except CaptureError:
            took = False
        _need(took == should, f"control: the receipt reader {'refused' if should else 'accepted'} {label}")
        accepted, refused = accepted + took, refused + (not took)
    return accepted, refused


def controls_refused(contract: dict) -> int:
    """Every corrupted record the three judges refuse: captures and reports, listener records, compositions."""
    _samples, _accepted, capture = controls(contract)
    return capture + receipt_controls(contract)[1] + external_controls()[1]


# What the admitted item fixes, held here as well so the gate stays correct after the item is
# completed and retired to .tasks/terminal. While the item is active its stored body is compared
# with these; once it is gone these still bind. The count is exact, not a floor.
PINNED_CASES = 4
PINNED_CONTROLS = 291
# The positive controls, pinned as the negative ones are: a judge that quietly loses an honest case
# keeps refusing everything it refused, so only a count of what it accepts shows the loss.
PINNED_HONEST_CAPTURES = 46
PINNED_ACCEPTED_RECEIPTS = 10
ADMISSION = "slime-zenoh-profile0-external-listener-"


def item_pins() -> tuple[int, int]:
    """The case count and control count the admitted item fixes, read from its stored body, or (0, 0)."""
    for path in sorted((ROOT / ".tasks" / "items").glob("*.md")):
        text = path.read_text(encoding="utf-8")
        if "zenoh_external_check" not in text or ADMISSION not in text or re.search(r"^state: cancelled$", text, re.M):
            continue
        cases = re.search(r'id = "all-cases-observed";.*?intValue = (\d+);', text, re.S)
        controls_ = re.search(r'id = "exactly-\d+-controls";.*?observation = "negativeControlsRefused";.*?intValue = (\d+);', text, re.S)
        if cases and controls_:
            return int(cases.group(1)), int(controls_.group(1))
    return 0, 0


def check_pins(contract: dict) -> int:
    """Refuse a checker whose counts moved from the pins, or from the admitted item while it is active."""
    total = controls_refused(contract)
    _need(total == PINNED_CONTROLS, f"the judges refuse {total} corrupted records, the checker pins {PINNED_CONTROLS}")
    _samples, honest, _refused = controls(contract)
    _need(honest == PINNED_HONEST_CAPTURES, f"the capture judge accepts {honest} honest variants, the checker pins {PINNED_HONEST_CAPTURES}")
    accepted, _refused_records = receipt_controls(contract)
    _need(accepted == PINNED_ACCEPTED_RECEIPTS, f"the receipt reader accepts {accepted} records, the checker pins {PINNED_ACCEPTED_RECEIPTS}")
    cases, controls_ = item_pins()
    _need(not cases or cases == PINNED_CASES, f"the admitted item fixes {cases} cases, the checker pins {PINNED_CASES}")
    _need(not controls_ or controls_ == PINNED_CONTROLS, f"the admitted item fixes {controls_} controls, the checker pins {PINNED_CONTROLS}")
    return total


# ---------------------------------------------------------------------------- building


GUEST_MAC = bytes.fromhex(INTERFACE["mac"].replace(":", ""))
PEER_MAC = bytes.fromhex("52550a000202")
BROADCAST = bytes.fromhex("ffffffffffff")
OTHER_MAC = bytes.fromhex("020000000009")
GUEST_PORT = 49200


def _ip(source: str, destination: str, protocol: int, body: bytes) -> bytes:
    src, dst = bytes(int(x) for x in source.split(".")), bytes(int(x) for x in destination.split("."))
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0x4000, 64, protocol, 0, src, dst)
    header = header[:10] + http_capture._checksum(header).to_bytes(2, "big") + header[12:]
    return header + body


def _tcp(source: str, destination: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"", window: int = 65535, options: bytes = b"") -> bytes:
    options += bytes(-len(options) % 4)
    body = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, (5 + len(options) // 4) << 4, flags, window, 0, 0)
    body += options + payload
    pseudo = bytes(int(x) for x in source.split(".")) + bytes(int(x) for x in destination.split(".")) + bytes((0, 6)) + len(body).to_bytes(2, "big")
    body = body[:16] + http_capture._checksum(pseudo + body).to_bytes(2, "big") + body[18:]
    return _ip(source, destination, 6, body)


MSS, WSCALE, SACK, TIMESTAMP_OPTION = 2, 3, 4, 8


def _option(kind: int, value: bytes = b"") -> bytes:
    return bytes([kind, 2 + len(value)]) + value


# What a guest and a peer negotiate honestly: the segment size, window scaling and SACK.
GUEST_OPTIONS = _option(MSS, (1460).to_bytes(2, "big")) + _option(SACK) + _option(WSCALE, b"\x07")
PEER_OPTIONS = _option(MSS, (1460).to_bytes(2, "big")) + _option(WSCALE, b"\x07")


def _udp(source: str, destination: str, sport: int, dport: int, payload: bytes) -> bytes:
    return _ip(source, destination, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)


def _icmp() -> bytes:
    body = bytes((8, 0, 0, 0, 0, 1, 0, 1))
    return _ip(GUEST, PEER, 1, body[:2] + http_capture._checksum(body).to_bytes(2, "big") + body[4:])


def _ethernet(packet: bytes, outgoing: bool, ethertype: int = 0x0800) -> bytes:
    pair = (PEER_MAC, GUEST_MAC) if outgoing else (GUEST_MAC, PEER_MAC)
    return pair[0] + pair[1] + ethertype.to_bytes(2, "big") + packet


def _arp() -> bytes:
    return _arp_frame()


def _arp_frame(
    sender: tuple = (10, 0, 2, 15), target: tuple = (10, 0, 2, 2), mac: bytes = GUEST_MAC, operation: int = 1,
    ptype: int = 0x0800, target_hw: bytes | None = None, dst: bytes | None = None,
) -> bytes:
    """A whole ARP frame. A request is broadcast with a broadcast target hardware address, as the
    guest's stack sends it; a reply goes to the other side's hardware address."""
    if target_hw is None:
        target_hw = BROADCAST if operation == 1 else (GUEST_MAC if mac == PEER_MAC else PEER_MAC)
    if dst is None:
        dst = BROADCAST if operation == 1 else target_hw
    body = struct.pack("!HHBBH", 1, ptype, 6, 4, operation) + mac + bytes(sender) + target_hw + bytes(target)
    return dst + mac + (0x0806).to_bytes(2, "big") + body


def pcap(frames: list[bytes], times_us: list[int] | None = None) -> bytes:
    """A classic PCAP of Ethernet frames. Without `times_us` the frames are one millisecond apart."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        at = 1_000_000 + (i * 1000 if times_us is None else times_us[i])
        out += struct.pack("<IIII", at // 1_000_000, at % 1_000_000, len(frame), len(frame)) + frame
    return out


def _turns(scenario: dict, guest_at: list[int], peer_at: list[int]) -> list[tuple[bool, int, int]]:
    """The honest order of a Zenoh session as (from_guest, first_byte, last_byte) turns over the two
    streams: INIT_SYN, INIT_ACK, OPEN_SYN, then the peer's OPEN_ACK and declarations, then the guest's
    samples and close, then whatever the peer sends last. `guest_at` and `peer_at` are the offset of
    each batch in its stream, with the stream's length as the last entry. A scenario may name another
    layout to put one step out of turn."""
    def span(offsets: list[int], first: int, last: int) -> tuple[int, int]:
        top = len(offsets) - 1
        return offsets[min(first, top)], offsets[min(last, top)]

    def g(first: int, last: int) -> tuple[bool, int, int]:
        return (True, *span(guest_at, first, last))

    def q(first: int, last: int) -> tuple[bool, int, int]:
        return (False, *span(peer_at, first, last))

    layout = scenario.get("layout", "honest")
    if layout == "honest":
        before = scenario.get("peer_first", 5)
        turns = [g(0, 1), q(0, 1), g(1, 2), q(1, before), g(2, 1 << 30), q(before, 1 << 30)]
    elif layout == "keepalive_with_open":
        turns = [g(0, 1), q(0, 1), g(1, 3), q(1, 5), g(3, 1 << 30), q(5, 1 << 30)]
    elif layout == "close_after_three_samples":
        turns = [g(0, 1), q(0, 1), g(1, 2), q(1, 5), g(2, 5), q(5, 1 << 30), g(5, 1 << 30)]
    elif layout == "close_after_four_samples":
        turns = [g(0, 1), q(0, 1), g(1, 2), q(1, 5), g(2, 6), q(5, 1 << 30), g(6, 1 << 30)]
    elif layout == "frames_early":
        turns = [g(0, 1), q(0, 1), g(1, 2), q(1, 2), g(2, 1 << 30), q(2, 1 << 30)]
    elif layout == "open_before_ack":
        turns = [g(0, 2), q(0, 5), g(2, 1 << 30), q(5, 1 << 30)]
    elif layout == "ack_before_init_done":
        half = guest_at[0] + (guest_at[1] - guest_at[0]) // 2
        turns = [(True, guest_at[0], half), q(0, 1), (True, half, guest_at[1]), g(1, 2), q(1, 5), g(2, 1 << 30), q(5, 1 << 30)]
    elif layout == "open_ack_before_open_done":
        mid = guest_at[1] + (guest_at[2] - guest_at[1]) // 2
        turns = [g(0, 1), q(0, 1), (True, guest_at[1], mid), q(1, 5), (True, mid, guest_at[2]), g(2, 1 << 30), q(5, 1 << 30)]
    else:
        raise ValueError(layout)
    return [turn for turn in turns if turn[2] > turn[1]]


def build(scenario: dict) -> bytes:
    """A capture of one connection carrying the scenario's streams, in the order a session runs.

    `chunk` is the segment size, `reorder` swaps the first two segments of the guest's last turn,
    `retransmit` repeats the first of them, `drop_segment` removes one of them, `layout` puts a step
    of the session out of turn, and `extra` appends frames the scenario wants on the wire.
    """
    gisn, pisn, sport = scenario.get("guest_isn", 1000), scenario.get("peer_isn", 700000), scenario.get("guest_port", GUEST_PORT)
    dport = scenario.get("port", PORT)
    chunk = scenario.get("chunk", 1400)
    guest_stream = b"".join(zenoh_wire.stream(b) for b in scenario["guest"])
    peer_stream = b"".join(zenoh_wire.stream(b) for b in scenario["peer"])

    def offsets(batches: list[bytes]) -> list[int]:
        at, found = 0, []
        for batch in batches:
            found.append(at)
            at += 2 + len(batch)
        return [*found, at]

    packets: list[tuple[bool, int, bytes]] = []
    last_guest_turn: list[int] = []
    guest_turn_starts: list[int] = []
    peer_turn_starts: list[int] = []
    for from_guest, first, last in _turns(scenario, offsets(scenario["guest"]), offsets(scenario["peer"])):
        data = guest_stream if from_guest else peer_stream
        group = []
        for at in range(first, last, chunk):
            group.append(len(packets))
            packets.append((from_guest, at, data[at : min(at + chunk, last)]))
        (guest_turn_starts if from_guest else peer_turn_starts).append(group[0])
        if from_guest:
            last_guest_turn = group
    if scenario.get("reorder") and len(last_guest_turn) > 1:
        i, j = last_guest_turn[0], last_guest_turn[1]
        packets[i], packets[j] = packets[j], packets[i]
    if scenario.get("retransmit") and len(last_guest_turn) > 1:
        packets.insert(last_guest_turn[1] + 1, packets[last_guest_turn[0]])
    if "drop_segment" in scenario and len(last_guest_turn) > scenario["drop_segment"]:
        del packets[last_guest_turn[scenario["drop_segment"]]]

    skew = dict(scenario.get("ack_skew", {}))
    lag = bool(scenario.get("ack_lag"))
    frames = [_arp()]
    if not scenario.get("no_syn"):
        frames.append(_ethernet(_tcp(GUEST, PEER, sport, dport, gisn, 0, TCP_SYN | scenario.get("syn_flags", 0), b"", 65535, scenario.get("guest_options", GUEST_OPTIONS)), True))
        if not scenario.get("no_synack"):
            frames.append(_ethernet(_tcp(PEER, GUEST, dport, sport, pisn, gisn + 1 + scenario.get("synack_skew", 0), TCP_SYN | TCP_ACK | scenario.get("synack_flags", 0), b"", 65535, scenario.get("peer_options", PEER_OPTIONS)), False))
        if not scenario.get("no_hs_ack"):
            frames.append(_ethernet(_tcp(GUEST, PEER, sport, dport, gisn + 1, pisn + 1 + skew.pop("hs_ack", 0), TCP_ACK), True))
    if "synack_again" in scenario:
        frames.append(_ethernet(_tcp(PEER, GUEST, dport, sport, pisn, gisn + 1 + scenario["synack_again"], TCP_SYN | TCP_ACK, b"", scenario.get("again_window", 65535), scenario.get("again_peer_options", scenario.get("peer_options", PEER_OPTIONS))), False))
    if "syn_again" in scenario:
        frames.append(_ethernet(_tcp(GUEST, PEER, sport, dport, gisn + scenario["syn_again"], 0, TCP_SYN, b"", scenario.get("again_window", 65535), scenario.get("again_guest_options", scenario.get("guest_options", GUEST_OPTIONS))), True))
    if scenario.get("synack_first") and len(frames) >= 3:
        frames[1], frames[2] = frames[2], frames[1]
    sent_guest = sent_peer = 0
    data_flags = TCP_ACK | (TCP_PSH if scenario.get("psh") else 0)
    noack = set(scenario.get("noack", ()))
    packet_frame: dict[int, int] = {}
    early_fin = scenario.get("peer_fin_after_data_packets")
    seen_data = 0

    def peer_fin() -> bytes:
        return _ethernet(_tcp(PEER, GUEST, dport, sport, pisn + 1 + len(peer_stream), gisn + 1 + sent_guest, TCP_FIN | TCP_ACK), False)

    if early_fin == 0:
        frames.append(peer_fin())
    for number, (from_guest, at, payload) in enumerate(packets):
        if scenario.get("stray_ack_before_packet") == number:
            frames.append(_ethernet(_tcp(GUEST, PEER, sport, dport, gisn + 1 + sent_guest + scenario.get("stray_ack_seq_skew", 0), pisn + 1 + sent_peer, TCP_ACK), True))
        packet_frame[number] = len(frames)
        if from_guest:
            flags = (data_flags & ~TCP_ACK if "guest_data" in noack else data_flags) | (TCP_URG if "guest_urg" in noack else 0)
            noack -= {"guest_data", "guest_urg"}
            ack = pisn + 1 + (0 if lag else sent_peer) + skew.pop("guest_data", 0)
            frames.append(_ethernet(_tcp(GUEST, PEER, sport, dport, gisn + 1 + at, ack, flags, payload), True))
            sent_guest = max(sent_guest, at + len(payload))
        else:
            flags = data_flags & ~TCP_ACK if "peer_data" in noack else data_flags
            noack -= {"peer_data"}
            ack = gisn + 1 + (0 if lag else sent_guest) + skew.pop("peer_data", 0)
            frames.append(_ethernet(_tcp(PEER, GUEST, dport, sport, pisn + 1 + at, ack, flags, payload), False))
            sent_peer = max(sent_peer, at + len(payload))
        if from_guest and number in last_guest_turn:
            seen_data += 1
            if early_fin == seen_data:
                frames.append(peer_fin())
    frames.extend(scenario.get("extra", []))
    guest_fin = gisn + 1 + len(guest_stream) + scenario.get("fin_skew", 0)
    closing = []
    if scenario.get("guest_fin", True):
        closing.append(_ethernet(_tcp(GUEST, PEER, sport, dport, guest_fin, pisn + 1 + len(peer_stream) + skew.pop("guest_fin", 0), TCP_FIN | (0 if "guest_fin_ack" in noack else TCP_ACK)), True))
    if early_fin is None:
        closing.append(_ethernet(_tcp(PEER, GUEST, dport, sport, pisn + 1 + len(peer_stream), guest_fin + 1, TCP_FIN | (0 if "peer_fin_ack" in noack else TCP_ACK)), False))
    closing.append(_ethernet(_tcp(GUEST, PEER, sport, dport, guest_fin + 1, pisn + 2 + len(peer_stream), 0 if "last_ack" in noack else TCP_ACK), True))
    where = scenario.get("closing", "end")
    if where == "before_syn":
        frames = [frames[0], *closing, *frames[1:]]
    elif where == "between_syn_and_synack":
        frames = [*frames[:2], *closing, *frames[2:]]
    else:
        frames.extend(closing)
    times = [i * 1000 for i in range(len(frames))]

    def shift_from(frame_index: int, delta_us: int) -> None:
        for i in range(frame_index, len(times)):
            times[i] += delta_us

    # `silence_us` is the time from the packet that opens the guest's OPEN_SYN turn to the packet that
    # opens its data turn; `peer_gap_us` is the time from the peer's declarations to its next turn.
    if "silence_us" in scenario and len(guest_turn_starts) >= 3:
        opened, data_turn = packet_frame[guest_turn_starts[1]], packet_frame[guest_turn_starts[2]]
        shift_from(data_turn, scenario["silence_us"] - (times[data_turn] - times[opened]))
    if "peer_gap_us" in scenario and len(peer_turn_starts) >= 3:
        declared, later = packet_frame[peer_turn_starts[1]], packet_frame[peer_turn_starts[2]]
        shift_from(later, scenario["peer_gap_us"] - (times[later] - times[declared]))
    return pcap(frames, times)


# What a stock eclipse-zenoh 1.0.0 listener sent after a connector reached it, as captured in
# `zenoh_stock_peer`: its INIT_ACK and OPEN_ACK, an OAM, its key alias and its subscriber declaration.
STOCK_LISTENER = [bytes.fromhex(hexed) for _name, hexed in zenoh_stock_peer.batches("listens")]


def _peer_cookie() -> bytes:
    """The cookie the stock listener's INIT_ACK carries, which the connector's OPEN_SYN must echo."""
    return _init_fields(STOCK_LISTENER[0], "INIT_ACK", True)


def synthesize(contract: dict, initial_sn: int = 0) -> dict:
    """The scenario an honest guest and a stock listener produce, from the host reference."""
    lines = guest_lines(contract, initial_sn)
    sent = judge_guest_lines(lines, contract)["sent"]
    frames = [bytes.fromhex(sent[i]) for i in range(SAMPLES)]
    zid = bytes(range(1, 9))
    peer = [*STOCK_LISTENER[:5], bytes([ID_KEEP_ALIVE]), STOCK_LISTENER[7]]
    guest = [zenoh_wire.init(zid, 512), zenoh_wire.open_(LEASE_MS, initial_sn, _peer_cookie()), *frames, zenoh_wire.close(0, True)]
    wire = [(contract["key"], f.hex() and zenoh_wire.decode_push_frame(f)["payload"].hex(), _attachment_hex(f)) for f in frames]
    return {"guest": guest, "peer": peer, "lines": lines, "listen": LISTEN, "remote_peers": 1, "receipt": wire}


def _attachment_hex(batch: bytes) -> str:
    d = zenoh_wire.decode_push_frame(batch)
    return zenoh_wire.attachment(d["sequence"], d["timestamp"], d["gid"]).hex()


def judge_run(pcap_bytes: bytes, lines: list[str], receipt: Path, contract: dict) -> dict:
    """The three witnesses of one real run: the connector's report, the capture, the listener's record."""
    reported = judge_guest_lines(lines, contract)
    result = judge_capture(pcap_bytes, reported, contract)
    listen, remote_peers, samples = read_receipt(receipt)
    result["receipt"] = judge_receipt(listen, remote_peers, samples, result["samples"])
    return result


def judge(scenario: dict, contract: dict) -> dict:
    """Every judge, over one scenario: its report, its capture and the listener's receipt."""
    reported = judge_guest_lines(scenario["lines"], contract)
    result = judge_capture(build(scenario), reported, contract)
    result["receipt"] = judge_receipt(scenario["listen"], scenario["remote_peers"], scenario["receipt"], result["samples"])
    return result


# ---------------------------------------------------------------------------- controls


OTHER_KEY = b"0/other/key/that/is/valid"


def _sn(batch: bytes) -> int:
    return zenoh_wire.read_leb128(batch, 1)[0]


def _with_sn(batch: bytes, sn: int) -> bytes:
    return batch[:1] + zenoh_wire.leb128(sn & 0xFFFFFFFF) + batch[zenoh_wire.read_leb128(batch, 1)[1] :]


def _other_key_alias(batch: bytes) -> bytes:
    """The captured key-alias declaration with the demo key replaced by another valid key."""
    key = zenoh_exchange.demo()["key"].encode()
    at = batch.index(key) - 2
    return batch[:at] + bytes([len(OTHER_KEY)]) + OTHER_KEY + batch[at + 2 + len(key) :]


def _other_key_subscriber(batch: bytes) -> bytes:
    """A DeclareSubscriber that names OTHER_KEY in full, in a FRAME with the same sequence number."""
    sn = _sn(batch)
    body = bytes([ID_DECLARE, 0x42 & ~FLAG_6 | FLAG_5 | 0x40 * 0]) + zenoh_wire.leb128(1) + zenoh_wire.leb128(0) + zenoh_wire.leb128(len(OTHER_KEY)) + OTHER_KEY
    return bytes([zenoh_wire.ID_FRAME | zenoh_wire.FLAG_R]) + zenoh_wire.leb128(sn) + body


def _push_body(scenario: dict) -> bytes:
    """The network message of a guest sample frame: a PUSH, as a peer would have to send one."""
    line = next(x for x in scenario["lines"] if " wire sent sample=0 " in x)
    batch = bytes.fromhex(line.split("hex=")[1])
    return batch[1 + len(zenoh_wire.leb128(_sn(batch))) :]


def _pad_peer_frame(frame: bytes, length: int) -> bytes:
    """A peer FRAME grown to `length` bytes by a valid OAM, so only the batch bound can refuse it."""
    extra = length - len(frame)
    for size in range(extra):
        if 4 + len(zenoh_wire.leb128(size)) + size == extra:
            return frame + bytes([OAM_HEADER, 1, EXT_QOS_NETWORK, 8]) + zenoh_wire.leb128(size) + bytes(size)
    raise CaptureError(f"control: no OAM body makes a frame of {length} bytes")


def K() -> str:
    return zenoh_exchange.demo()["key"]


def _undeclare_frame(scenario: dict, subscriber_id: int, key: str, skip: int = 0) -> bytes:
    """A peer FRAME that undeclares a subscriber, numbered after the last frame the scenario's peer sent."""
    last = max(_sn(b) for b in scenario["peer"][2:5])
    return bytes([zenoh_wire.ID_FRAME | zenoh_wire.FLAG_R]) + zenoh_wire.leb128(last + 1 + skip) + zenoh_wire.undeclare_subscriber(subscriber_id, key, True)


def _undeclare_by_id_frame(scenario: dict, subscriber_id: int, skip: int = 0) -> bytes:
    """A peer FRAME carrying the stock peer's undeclaration, which names the subscriber by id alone."""
    last = max(_sn(b) for b in scenario["peer"][2:5])
    return zenoh_wire.frame(last + 1 + skip, zenoh_wire.undeclare_subscriber_by_id(subscriber_id))


def _replace_sent(index: int, change: Callable[[bytes], bytes], both: bool) -> Callable[[dict], dict]:
    def run(s: dict) -> dict:
        at = 2 + index
        original = s["guest"][at]
        s["guest"][at] = change(original)
        if both:
            s["lines"] = [line.replace(original.hex(), s["guest"][at].hex()) for line in s["lines"]]
        return s

    return run


def mutations() -> list[tuple[str, Callable[[dict], dict]]]:
    def edit(change: Callable[[dict], None]) -> Callable[[dict], dict]:
        def run(s: dict) -> dict:
            change(s)
            return s

        return run

    def extra(*frames: bytes) -> Callable[[dict], dict]:
        return edit(lambda s: s.setdefault("extra", []).extend(_ethernet(f, True) for f in frames))

    def guest_at(index: int, change: Callable[[bytes], bytes]) -> Callable[[dict], dict]:
        def run(s: dict) -> dict:
            s["guest"][index] = change(s["guest"][index])
            return s

        return run

    def peer_at(index: int, change: Callable[[bytes], bytes]) -> Callable[[dict], dict]:
        def run(s: dict) -> dict:
            s["peer"][index] = change(s["peer"][index])
            return s

        return run

    def rebuild_attachments(sequence_of: Callable[[int], int], timestamp_of: Callable[[int], int], gid_of: Callable[[int], bytes]) -> Callable[[dict], dict]:
        """Samples whose attachment differs, with the guest's report, the wire and the listener's record
        all rebuilt to agree, so only the demo's own attachment values can refuse them."""

        def run(s: dict) -> dict:
            contract = zenoh_exchange.demo()
            frames = []
            for n, (_sequence, _value, cdr) in enumerate(contract["samples"]):
                att = zenoh_wire.attachment(sequence_of(n), timestamp_of(n), gid_of(n))
                frames.append(zenoh_wire.frame(n, zenoh_wire.push_put(contract["key"], att, bytes.fromhex(cdr), True)))
            s["guest"][2 : 2 + SAMPLES] = frames
            s["lines"] = [x for x in s["lines"] if " wire sent " not in x]
            at = next(i for i, x in enumerate(s["lines"]) if "declaration matched" in x)
            for n, frame in enumerate(frames):
                s["lines"].insert(at + 1 + n, f"[{PUBLISHER}] wire sent sample={n} hex={frame.hex()}")
            s["receipt"] = [(contract["key"], contract["samples"][n][2], _attachment_hex(frame)) for n, frame in enumerate(frames)]
            return s

        return run

    def wide_frame_numbers(initial: int = 0xFFFFFFFE, first_wide: int = 2) -> Callable[[dict], dict]:
        """A session that starts at `initial` whose frames from sample `first_wide` on carry the 33-bit
        value a non-wrapping count reaches, in the report and on the wire alike."""

        def run(s: dict) -> dict:
            base = synthesize(zenoh_exchange.demo(), initial)
            s.update(guest=base["guest"], lines=base["lines"])
            for n in range(first_wide, SAMPLES):
                old = s["guest"][2 + n]
                new = old[:1] + zenoh_wire.leb128(initial + n) + old[1 + len(zenoh_wire.leb128((initial + n) & U32)) :]
                s["guest"][2 + n] = new
                s["lines"] = [x.replace(old.hex(), new.hex()) for x in s["lines"]]
            return s

        return run

    def peer_sn(by: int) -> Callable[[dict], dict]:
        def run(s: dict) -> dict:
            for i in (2, 3, 4):
                s["peer"][i] = _with_sn(s["peer"][i], _sn(s["peer"][i]) + by)
            return s

        return run

    def late(frame: bytes) -> Callable[[dict], dict]:
        return edit(lambda s: s.setdefault("extra", []).append(frame))

    def c_syn_peer(offset: int) -> bytes:
        seq = 700000 if offset == 0 else offset
        return _ethernet(_tcp(PEER, GUEST, PORT, GUEST_PORT, seq, 0, TCP_SYN), False)

    def raw(*frames: bytes) -> Callable[[dict], dict]:
        return edit(lambda s: s.setdefault("extra", []).extend(frames))

    def flip(batch: bytes) -> bytes:
        return batch[:-1] + bytes([batch[-1] ^ 1])

    def wrong_sn(batch: bytes) -> bytes:
        return zenoh_wire.frame(zenoh_wire.read_leb128(batch, 1)[0] + 1, batch[1 + len(zenoh_wire.leb128(zenoh_wire.read_leb128(batch, 1)[0])) :])

    def pad(batch: bytes) -> bytes:
        return batch + b"\x00"

    def other_syn(port: int, address: str = PEER) -> bytes:
        return _tcp(GUEST, address, GUEST_PORT + 1, port, 5000, 0, TCP_SYN)

    def second_connection(s: dict) -> dict:
        s.setdefault("extra", []).append(_ethernet(other_syn(PORT), True))
        return s

    def drop_frame(s: dict) -> dict:
        s["guest"].pop(2 + SAMPLES - 1)
        return s

    def fifth_frame(s: dict) -> dict:
        s["guest"].insert(2 + SAMPLES, s["guest"][2 + SAMPLES - 1])
        return s

    def put_bytes(change: Callable[[list], None]) -> Callable[[dict], dict]:
        return edit(lambda s: change(s["guest"]))

    return [
        ("no connection at all", edit(lambda s: s.update(no_syn=True))),
        ("a second connection from another port", second_connection),
        ("a SYN to another port", extra(other_syn(PORT + 1))),
        ("a SYN to port 17446, one under", extra(other_syn(PORT - 1))),
        ("the only connection goes to port 17446, one under", edit(lambda s: s.update(port=PORT - 1))),
        ("a SYN to another address", extra(other_syn(PORT, "10.0.2.3"))),
        ("the connection goes to another port", edit(lambda s: s.update(port=PORT + 1))),
        ("a DNS query", extra(_udp(GUEST, "10.0.2.3", 49300, 53, b"\x00\x01\x01\x00\x00\x01"))),
        ("a scouting datagram", extra(_udp(GUEST, "224.0.0.224", 49301, 7446, b"\x01"))),
        ("an ICMP echo", extra(_icmp())),
        ("an ARP request for another address", raw(_arp_frame(target=(10, 0, 2, 99)))),
        ("an ARP request for the next address up, 10.0.2.3", raw(_arp_frame(target=(10, 0, 2, 3)))),
        ("an ARP request claiming another sender address", raw(_arp_frame(sender=(10, 0, 2, 16)))),
        ("an ARP request from another hardware address", raw(_arp_frame(mac=bytes.fromhex("525400000001")))),
        ("an ARP reply with a zero target hardware address", raw(_arp_frame(sender=(10, 0, 2, 2), target=(10, 0, 2, 15), mac=PEER_MAC, operation=2, target_hw=bytes(6), dst=GUEST_MAC))),
        ("an ARP reply for the guest naming a third party's hardware address", raw(_arp_frame(sender=(10, 0, 2, 2), target=(10, 0, 2, 15), mac=PEER_MAC, operation=2, target_hw=OTHER_MAC, dst=OTHER_MAC))),
        ("an ARP reply whose Ethernet destination is a third party", raw(_arp_frame(sender=(10, 0, 2, 2), target=(10, 0, 2, 15), mac=PEER_MAC, operation=2, target_hw=GUEST_MAC, dst=OTHER_MAC))),
        ("an ARP reply sent to broadcast", raw(_arp_frame(sender=(10, 0, 2, 2), target=(10, 0, 2, 15), mac=PEER_MAC, operation=2, target_hw=GUEST_MAC, dst=BROADCAST))),
        ("an ARP request that is unicast", raw(_arp_frame(dst=PEER_MAC))),
        ("an ARP request naming a third party's target hardware address", raw(_arp_frame(target_hw=OTHER_MAC))),
        ("an ARP frame whose Ethernet source is not its sender hardware address", raw((lambda f: f[:6] + OTHER_MAC + f[12:])(_arp_frame()))),
        ("an ARP operation that is neither request nor reply", raw(_arp_frame(operation=3))),
        ("an ARP request that is not Ethernet and IPv4", raw(_arp_frame(ptype=0x86DD))),
        ("a reset after the data", extra(_tcp(GUEST, PEER, GUEST_PORT, PORT, 9999, 0, TCP_RST))),
        ("a connection the peer never accepts", edit(lambda s: s.update(no_synack=True))),
        ("a SYN-ACK acknowledging one number too many", edit(lambda s: s.update(synack_skew=1))),
        ("a SYN-ACK acknowledging one number too few", edit(lambda s: s.update(synack_skew=-1))),
        ("a SYN-ACK retransmitted with the acknowledgement one too many", edit(lambda s: s.update(synack_again=1))),
        ("a SYN-ACK retransmitted with the acknowledgement one too few", edit(lambda s: s.update(synack_again=-1))),
        ("a bare SYN from the peer after the data", late(c_syn_peer(0))),
        ("a bare SYN from the peer after the data with another sequence number", late(c_syn_peer(123456))),
        ("a SYN-ACK from the guest", late(_ethernet(_tcp(GUEST, PEER, GUEST_PORT, PORT, 1000, 700001, TCP_SYN | TCP_ACK), True))),
        ("a guest SYN retransmitted after the data", late(_ethernet(_tcp(GUEST, PEER, GUEST_PORT, PORT, 1000, 0, TCP_SYN), True))),
        ("a peer SYN-ACK retransmitted after the data", late(_ethernet(_tcp(PEER, GUEST, PORT, GUEST_PORT, 700000, 1001, TCP_SYN | TCP_ACK), False))),
        ("a guest SYN retransmitted with another sequence number", edit(lambda s: s.update(syn_again=1))),
        ("a guest SYN retransmitted one number under", edit(lambda s: s.update(syn_again=-1))),
        ("a stream that never closes", edit(lambda s: s.update(guest_fin=False))),
        ("a FIN one byte past the data", edit(lambda s: s.update(fin_skew=1))),
        ("a FIN one byte short of the data", edit(lambda s: s.update(fin_skew=-1))),
        ("a missing segment", edit(lambda s: s.update(chunk=100, drop_segment=1))),
        ("a missing first segment", edit(lambda s: s.update(chunk=100, drop_segment=0))),
        ("a sample batch changed on the wire only", _replace_sent(1, flip, False)),
        ("a sample batch changed on the wire and in the report", _replace_sent(1, flip, True)),
        ("a sample batch one byte longer", _replace_sent(2, pad, True)),
        ("a frame sequence number one over", _replace_sent(0, wrong_sn, True)),
        ("three frames on the wire", drop_frame),
        ("five frames on the wire", fifth_frame),
        ("frames swapped on the wire", put_bytes(lambda g: g.__setitem__(slice(2, 4), [g[3], g[2]]))),
        ("no INIT_SYN first", put_bytes(lambda g: g.__setitem__(slice(0, 2), [g[1], g[0]]))),
        ("a keep-alive of two bytes", put_bytes(lambda g: g.insert(2, b"\x04\x00"))),
        ("a batch after the close", put_bytes(lambda g: g.append(bytes([ID_KEEP_ALIVE])))),
        ("a lease of 1999 ms", put_bytes(lambda g: g.__setitem__(1, zenoh_wire.open_(1999, 0, _peer_cookie())))),
        ("a lease of 2001 ms", put_bytes(lambda g: g.__setitem__(1, zenoh_wire.open_(2001, 0, _peer_cookie())))),
        ("a batch the exam does not name", put_bytes(lambda g: g.insert(2, bytes([zenoh_wire.ID_DECLARE])))),
        ("a peer that sends no INIT_ACK", edit(lambda s: s.update(peer=[bytes([ID_KEEP_ALIVE])]))),
        ("a peer batch the exam does not name", edit(lambda s: s["peer"].append(bytes([0x0D])))),
        ("a guest CLOSE with bit 6 set", guest_at(-1, lambda b: b"\x43\x00")),
        ("a guest CLOSE with an extension flag", guest_at(-1, lambda b: b"\x83\x00")),
        ("a guest CLOSE of the link only", guest_at(-1, lambda b: b"\x03\x00")),
        ("a guest CLOSE with reason 8, one over the last the profile names", guest_at(-1, lambda b: b"\x23\x08")),
        ("a guest CLOSE with reason 255", guest_at(-1, lambda b: b"\x23\xff")),
        ("a peer stream with no Zenoh CLOSE, its FIN after the last sample", edit(lambda s: s["peer"].pop())),
        ("a peer stream cut at its subscriber declaration, no CLOSE", edit(lambda s: s.update(peer=s["peer"][:5]))),
        ("a guest ACK one past its next sequence number", edit(lambda s: s.update(stray_ack_before_packet=1, stray_ack_seq_skew=1))),
        ("a guest ACK 10000 past its next sequence number, acknowledged by the peer's INIT_ACK", edit(lambda s: s.update(stray_ack_before_packet=1, stray_ack_seq_skew=10000, ack_skew={"peer_data": 10000}))),
        ("a guest ACK 10000 past its next sequence number alone", edit(lambda s: s.update(stray_ack_before_packet=1, stray_ack_seq_skew=10000))),
        ("a peer FRAME with a DeclareSubscriber and a PUSH", edit(lambda s: s["peer"].__setitem__(4, s["peer"][4] + _push_body(s)))),
        ("a peer FRAME with a PUSH alone", edit(lambda s: s["peer"].append(zenoh_wire.frame(_sn(s["peer"][4]) + 1, _push_body(s))))),
        ("a guest data segment without ACK", edit(lambda s: s.update(noack=["guest_data"]))),
        ("a peer data segment without ACK", edit(lambda s: s.update(noack=["peer_data"]))),
        ("a guest FIN without ACK", edit(lambda s: s.update(noack=["guest_fin_ack"]))),
        ("a peer FIN without ACK", edit(lambda s: s.update(noack=["peer_fin_ack"]))),
        ("the last guest segment without ACK", edit(lambda s: s.update(noack=["last_ack"]))),
        ("a guest data segment with the URG flag", edit(lambda s: s.update(noack=["guest_urg"]))),
        ("attachment sequences that are the sample number, one under", rebuild_attachments(lambda n: n, lambda n: 1000 + n, lambda n: DEMO_GID)),
        ("attachment sequences two over the sample number, one over", rebuild_attachments(lambda n: n + 2, lambda n: 1000 + n, lambda n: DEMO_GID)),
        ("attachment timestamps one over", rebuild_attachments(lambda n: n + 1, lambda n: 1001 + n, lambda n: DEMO_GID)),
        ("attachment timestamps one under", rebuild_attachments(lambda n: n + 1, lambda n: 999 + n, lambda n: DEMO_GID)),
        ("attachment timestamps that do not advance", rebuild_attachments(lambda n: n + 1, lambda n: 1000, lambda n: DEMO_GID)),
        ("attachment timestamps that go backwards", rebuild_attachments(lambda n: n + 1, lambda n: 1000 - n, lambda n: DEMO_GID)),
        ("an attachment GID with its last byte changed", rebuild_attachments(lambda n: n + 1, lambda n: 1000 + n, lambda n: DEMO_GID[:-1] + b"\xee")),
        ("an attachment GID that changes between samples", rebuild_attachments(lambda n: n + 1, lambda n: 1000 + n, lambda n: bytes([n]) * 16)),
        ("both FINs and the last ACK recorded before the SYN", edit(lambda s: s.update(closing="before_syn"))),
        ("both FINs and the last ACK recorded between the SYN and the SYN-ACK", edit(lambda s: s.update(closing="between_syn_and_synack"))),
        ("the handshake ACK and the INIT_SYN segment both acknowledging relative 0", edit(lambda s: s.update(ack_skew={"hs_ack": -1, "guest_data": -1}, ack_lag=True))),
        ("no handshake ACK and the INIT_SYN segment acknowledging relative 0", edit(lambda s: s.update(no_hs_ack=True, ack_skew={"guest_data": -1}, ack_lag=True))),
        ("the handshake ACK at relative 0 and the INIT_SYN segment at relative 0, lagging", edit(lambda s: s.update(ack_skew={"hs_ack": -1, "guest_data": -1}, ack_lag=True, chunk=100))),
        ("a peer data segment acknowledging 0x70000000", edit(lambda s: s.update(ack_skew={"peer_data": 0x70000000}))),
        ("a peer data segment acknowledging one byte the guest had not sent", edit(lambda s: s.update(ack_skew={"peer_data": 1}))),
        ("a guest data segment acknowledging one byte the peer had not sent", edit(lambda s: s.update(ack_skew={"guest_data": 1}))),
        ("a guest FIN acknowledging the peer's FIN before it was sent", edit(lambda s: s.update(ack_skew={"guest_fin": 1}))),
        ("the handshake ACK acknowledging one past the peer's SYN", edit(lambda s: s.update(ack_skew={"hs_ack": 1}))),
        ("a guest SYN retransmitted with another window", edit(lambda s: s.update(syn_again=0, again_window=1000))),
        ("a peer SYN-ACK retransmitted with another window", edit(lambda s: s.update(synack_again=0, again_window=1000))),
        ("a guest SYN retransmitted with another segment size", edit(lambda s: s.update(syn_again=0, again_guest_options=_option(MSS, (1400).to_bytes(2, "big")) + _option(SACK) + _option(WSCALE, b"\x07")))),
        ("a guest SYN retransmitted with another window scale", edit(lambda s: s.update(syn_again=0, again_guest_options=_option(MSS, (1460).to_bytes(2, "big")) + _option(SACK) + _option(WSCALE, b"\x08")))),
        ("a guest SYN retransmitted without SACK", edit(lambda s: s.update(syn_again=0, again_guest_options=_option(MSS, (1460).to_bytes(2, "big")) + _option(WSCALE, b"\x07")))),
        ("a peer SYN-ACK retransmitted with another segment size", edit(lambda s: s.update(synack_again=0, again_peer_options=_option(MSS, (1400).to_bytes(2, "big")) + _option(WSCALE, b"\x07")))),
        ("a peer SYN-ACK retransmitted with another window scale", edit(lambda s: s.update(synack_again=0, again_peer_options=_option(MSS, (1460).to_bytes(2, "big")) + _option(WSCALE, b"\x06")))),
        ("a peer subscriber FRAME of 513 bytes, one over the batch bound", edit(lambda s: s["peer"].__setitem__(4, _pad_peer_frame(s["peer"][4], 513)))),
        ("a peer subscriber FRAME of 620 bytes", edit(lambda s: s["peer"].__setitem__(4, _pad_peer_frame(s["peer"][4], 620)))),
        ("a guest batch of 513 bytes", edit(lambda s: s["guest"].insert(2, bytes([ID_KEEP_ALIVE]) + bytes(512)))),
        ("a guest MSS option of length 3", edit(lambda s: s.update(syn_again=0, again_guest_options=bytes([2, 3, 5])))),
        ("a guest MSS option of length 5", edit(lambda s: s.update(syn_again=0, again_guest_options=bytes([2, 5, 5, 0xB4, 0])))),
        ("a guest window scale option of length 2", edit(lambda s: s.update(syn_again=0, again_guest_options=bytes([3, 2])))),
        ("a guest window scale option of length 4", edit(lambda s: s.update(syn_again=0, again_guest_options=bytes([3, 4, 7, 0])))),
        ("a guest SACK-permitted option of length 3", edit(lambda s: s.update(syn_again=0, again_guest_options=bytes([4, 3, 0])))),
        ("a guest timestamps option of length 9", edit(lambda s: s.update(syn_again=0, again_guest_options=bytes([8, 9]) + bytes(7)))),
        ("a guest timestamps option of length 11", edit(lambda s: s.update(syn_again=0, again_guest_options=bytes([8, 11]) + bytes(9)))),
        ("a peer MSS option of length 3 on the SYN-ACK", edit(lambda s: s.update(peer_options=bytes([2, 3, 5])))),
        ("a peer window scale option of length 4 on the SYN-ACK", edit(lambda s: s.update(peer_options=bytes([3, 4, 7, 0])))),
        ("a guest SYN with a malformed option", edit(lambda s: s.update(syn_again=0, again_guest_options=b"\x02\x09\x05\xb4"))),
        ("a guest SYN that also carries a FIN", edit(lambda s: s.update(syn_flags=TCP_FIN))),
        ("a peer SYN-ACK that also carries a FIN", edit(lambda s: s.update(synack_flags=TCP_FIN))),
        ("a guest SYN that also carries an URG flag", edit(lambda s: s.update(syn_flags=0x20))),
        ("a peer SYN-ACK that also carries a PSH flag", edit(lambda s: s.update(synack_flags=0x08))),
        ("a peer alias for another valid key, the subscriber through it", peer_at(3, lambda b: _other_key_alias(b))),
        ("a peer subscriber declared by name on another key", peer_at(4, lambda b: _other_key_subscriber(b))),
        ("every peer FRAME sequence number one over the OPEN_ACK's", peer_sn(1)),
        ("every peer FRAME sequence number one under the OPEN_ACK's", peer_sn(-1)),
        ("a peer FRAME sequence number repeated", edit(lambda s: s["peer"].__setitem__(4, _with_sn(s["peer"][4], _sn(s["peer"][3]))))),
        ("a peer FRAME sequence number skipped", edit(lambda s: s["peer"].__setitem__(4, _with_sn(s["peer"][4], _sn(s["peer"][4]) + 5)))),
        ("frames numbered 0x100000000 and 0x100000001 after an initial 0xFFFFFFFE", wide_frame_numbers()),
        ("a frame number of 2**32 after an initial 0xFFFFFFFF", wide_frame_numbers(initial=0xFFFFFFFF, first_wide=1)),
        ("a guest KEEP_ALIVE carried with the OPEN_SYN, before the OPEN_ACK", edit(lambda s: s.update(layout="keepalive_with_open", guest=[s["guest"][0], s["guest"][1], bytes([ID_KEEP_ALIVE]), *s["guest"][2:]]))),
        ("the peer's FIN before the first guest frame", edit(lambda s: s.update(peer=s["peer"][:5], peer_fin_after_data_packets=0))),
        ("the peer's FIN after one of the guest's frames", edit(lambda s: s.update(peer=s["peer"][:5], peer_fin_after_data_packets=1, chunk=1))),
        ("a guest silent for 2000.001 ms before its first sample", edit(lambda s: s.update(silence_us=2_000_001))),
        ("a guest silent for 3 s before its first sample", edit(lambda s: s.update(silence_us=3_000_000))),
        ("a peer silent for 10000.001 ms after its declarations", edit(lambda s: s.update(peer_gap_us=10_000_001))),
        ("a peer subscriber declared and undeclared in one frame", edit(lambda s: s["peer"].__setitem__(4, s["peer"][4] + zenoh_wire.undeclare_subscriber(1, K(), True)))),
        ("a peer CLOSE before the first sample", edit(lambda s: s.update(peer=[*s["peer"][:5], zenoh_wire.close(0, True)], peer_first=6))),
        ("a peer CLOSE after three of the four samples", edit(lambda s: s.update(peer=[*s["peer"][:5], zenoh_wire.close(0, True)], layout="close_after_three_samples"))),
        ("a peer that undeclares its subscriber before the first sample", edit(lambda s: s.update(peer=[*s["peer"][:5], _undeclare_frame(s, 1, K())], peer_first=6))),
        ("a peer that undeclares a subscriber it does not hold, id 2", edit(lambda s: s.update(peer=[*s["peer"][:5], _undeclare_frame(s, 2, K())]))),
        ("a peer that undeclares its subscriber on another key", edit(lambda s: s.update(peer=[*s["peer"][:5], _undeclare_frame(s, 1, "0/other/key")]))),
        ("a peer that undeclares a subscriber twice", edit(lambda s: s.update(peer=[*s["peer"][:5], _undeclare_frame(s, 1, K()), _undeclare_frame(s, 1, K(), 1)]))),
        ("a peer that undeclares its subscriber by id before the first sample", edit(lambda s: s.update(peer=[*s["peer"][:5], _undeclare_by_id_frame(s, 1)], peer_first=6))),
        ("a peer that undeclares by id a subscriber it does not hold, id 2", edit(lambda s: s.update(peer=[*s["peer"][:5], _undeclare_by_id_frame(s, 2)]))),
        ("a peer that undeclares by id twice", edit(lambda s: s.update(peer=[*s["peer"][:5], _undeclare_by_id_frame(s, 1), _undeclare_by_id_frame(s, 1, 1)]))),
        ("a peer that undeclares by id and then in full", edit(lambda s: s.update(peer=[*s["peer"][:5], _undeclare_by_id_frame(s, 1), _undeclare_frame(s, 1, K(), 1)]))),
        ("a peer subscriber declared and undeclared by id in one frame", edit(lambda s: s["peer"].__setitem__(4, s["peer"][4] + zenoh_wire.undeclare_subscriber_by_id(1)))),
        ("a peer undeclaration by id without the QoS extension", edit(lambda s: s.update(peer=[*s["peer"][:5], zenoh_wire.frame(max(_sn(b) for b in s["peer"][2:5]) + 1, bytes([zenoh_wire.ID_DECLARE, zenoh_wire.ID_U_SUBSCRIBER, 1]))]))),
        ("a peer undeclaration by id with the extension flag and no extension", edit(lambda s: s.update(peer=[*s["peer"][:5], zenoh_wire.frame(max(_sn(b) for b in s["peer"][2:5]) + 1, bytes([zenoh_wire.ID_DECLARE | zenoh_wire.FLAG_Z, zenoh_wire.EXT_QOS_NETWORK, zenoh_wire.QOS_NETWORK_DEFAULT, zenoh_wire.ID_U_SUBSCRIBER | zenoh_wire.FLAG_Z, 1]))]))),
        ("a peer undeclaration by id with a reserved header bit", edit(lambda s: s.update(peer=[*s["peer"][:5], zenoh_wire.frame(max(_sn(b) for b in s["peer"][2:5]) + 1, bytes([zenoh_wire.ID_DECLARE | zenoh_wire.FLAG_Z, zenoh_wire.EXT_QOS_NETWORK, zenoh_wire.QOS_NETWORK_DEFAULT, zenoh_wire.ID_U_SUBSCRIBER | 0x20, 1]))]))),
        ("a peer undeclaration by id with no id", edit(lambda s: s.update(peer=[*s["peer"][:5], zenoh_wire.frame(max(_sn(b) for b in s["peer"][2:5]) + 1, bytes([zenoh_wire.ID_DECLARE | zenoh_wire.FLAG_Z, zenoh_wire.EXT_QOS_NETWORK, zenoh_wire.QOS_NETWORK_DEFAULT, zenoh_wire.ID_U_SUBSCRIBER]))]))),
        ("a peer undeclaration by id with a trailing byte", edit(lambda s: s.update(peer=[*s["peer"][:5], _undeclare_by_id_frame(s, 1) + b"\x00"]))),
        ("a peer undeclaration by id with a QoS value over the bound", edit(lambda s: s.update(peer=[*s["peer"][:5], zenoh_wire.frame(max(_sn(b) for b in s["peer"][2:5]) + 1, bytes([zenoh_wire.ID_DECLARE | zenoh_wire.FLAG_Z, zenoh_wire.EXT_QOS_NETWORK, QOS_NETWORK_MAX + 1, zenoh_wire.ID_U_SUBSCRIBER, 1]))]))),
        ("a peer undeclaration with the full form after the QoS extension", edit(lambda s: s.update(peer=[*s["peer"][:5], zenoh_wire.frame(max(_sn(b) for b in s["peer"][2:5]) + 1, bytes([zenoh_wire.ID_DECLARE | zenoh_wire.FLAG_Z, zenoh_wire.EXT_QOS_NETWORK, zenoh_wire.QOS_NETWORK_DEFAULT]) + zenoh_wire.undeclare_subscriber(1, K(), True)[1:])]))),
        ("an OPEN_SYN echoing another cookie", guest_at(1, lambda b: zenoh_wire.open_(LEASE_MS, 0, b"another-cookie-99"))),
        ("an OPEN_SYN echoing the cookie one byte short", guest_at(1, lambda b: zenoh_wire.open_(LEASE_MS, 0, _peer_cookie()[:-1]))),
        ("an OPEN_SYN echoing the cookie with a byte added", guest_at(1, lambda b: zenoh_wire.open_(LEASE_MS, 0, _peer_cookie() + b"\x00"))),
        ("an OPEN_SYN with an empty cookie", guest_at(1, lambda b: b[:1] + b[1:-len(_peer_cookie()) - 1] + b"\x00")),
        ("an OPEN_SYN with the extension flag and no extension", guest_at(1, lambda b: bytes([b[0] | 0x80]) + b[1:])),
        ("an OPEN_SYN with a zero lease", guest_at(1, lambda b: b[:1] + b"\x00" + b[2:])),
        ("an INIT_SYN with a batch size of zero", guest_at(0, lambda b: b[:-2] + b"\x00\x00")),
        ("an INIT_SYN with resolution 11, one over the default", guest_at(0, lambda b: b[:-3] + b"\x0b" + b[-2:])),
        ("an INIT_SYN with resolution 9, one under the default", guest_at(0, lambda b: b[:-3] + b"\x09" + b[-2:])),
        ("an INIT_SYN with reserved resolution bits", guest_at(0, lambda b: b[:-3] + b"\xfa" + b[-2:])),
        ("an INIT_SYN whose ZID ends in a zero byte", guest_at(0, lambda b: zenoh_wire.init(bytes(range(1, 8)) + b"\x00", 512))),
        ("an INIT_ACK with a batch size of zero", peer_at(0, lambda b: b[:-len(_peer_cookie()) - 1 - 2] + b"\x00\x00" + b[-len(_peer_cookie()) - 1:])),
        ("an INIT_ACK with resolution 11", peer_at(0, lambda b: b[:-len(_peer_cookie()) - 1 - 3] + b"\x0b" + b[-len(_peer_cookie()) - 1 - 2:])),
        ("an INIT_ACK with an empty cookie", peer_at(0, lambda b: b[: -len(_peer_cookie()) - 1] + b"\x00")),
        ("an INIT_ACK with a cookie of 65 bytes, one over the bound", peer_at(0, lambda b: b[: -len(_peer_cookie()) - 1] + bytes([65]) + b"c" * 65)),
        ("a peer FRAME whose message is one unsupported byte", edit(lambda s: s["peer"].append(b"\x25\x01\x00"))),
        ("a peer FRAME whose message header is 0xff", edit(lambda s: s["peer"].append(b"\x25\x01\xff\xff"))),
        ("a peer FRAME in the unreliable form", edit(lambda s: s["peer"].append(b"\x05\x01\x04"))),
        ("a peer FRAME with a whole message and a byte after it", edit(lambda s: s["peer"].append(_with_sn(s["peer"][2], _sn(s["peer"][4]) + 1) + b"\x00"))),
        ("a peer FRAME cut inside its last message", edit(lambda s: s["peer"].append(s["peer"][3][:-3]))),
        ("a peer OAM that is not the link-state one", edit(lambda s: s["peer"].__setitem__(2, s["peer"][2][:6] + b"\x02" + s["peer"][2][7:]))),
        ("a peer FRAME declaring a wildcard key", edit(lambda s: s["peer"].append(bytes.fromhex(next(h for n, h in zenoh_stock_peer.batches("refuse") if n == "refuse-wildcard")))))
        ,
        ("a peer FRAME with a QoS extension on its header", edit(lambda s: s["peer"].append(bytes.fromhex(next(h for n, h in zenoh_stock_peer.batches("refuse") if n == "refuse-qos-on-frame"))))),
        ("a peer that never declares a subscriber", edit(lambda s: s.update(peer=[*s["peer"][:3], s["peer"][5]]))),
        ("the SYN-ACK recorded before the SYN", edit(lambda s: s.update(synack_first=True))),
        ("the first sample sent before the peer's subscriber declaration", edit(lambda s: s.update(layout="frames_early"))),
        ("the OPEN_SYN sent before the INIT_ACK", edit(lambda s: s.update(layout="open_before_ack"))),
        ("the INIT_ACK sent before the INIT_SYN was complete", edit(lambda s: s.update(layout="ack_before_init_done", chunk=100))),
        ("the OPEN_ACK sent before the OPEN_SYN was complete", edit(lambda s: s.update(layout="open_ack_before_open_done", chunk=100))),
        ("a guest INIT_SYN of three bytes", guest_at(0, lambda b: b[:3])),
        ("a guest INIT_SYN cut inside its ZID", guest_at(0, lambda b: b[:6])),
        ("a guest INIT_SYN cut inside its size parameters", guest_at(0, lambda b: b[:-1])),
        ("a guest INIT_SYN with a byte after it", guest_at(0, lambda b: b + b"\x00")),
        ("a guest INIT_SYN with an extension flag", guest_at(0, lambda b: bytes([b[0] | 0x80]) + b[1:])),
        ("a guest INIT_SYN of another wire version", guest_at(0, lambda b: b[:1] + b"\x08" + b[2:])),
        ("a guest INIT_SYN as a client", guest_at(0, lambda b: b[:2] + bytes([(b[2] & 0xF0) | 2]) + b[3:])),
        ("a report whose initial sequence number is 999 against a wire of 0", edit(lambda s: s.update(lines=[x.replace("initial_sn=0", "initial_sn=999") for x in s["lines"]]))),
        ("a report whose initial sequence number is 1 against a wire of 0", edit(lambda s: s.update(lines=[x.replace("initial_sn=0", "initial_sn=1") for x in s["lines"]]))),
        ("a wire whose initial sequence number is 1 against a report of 0", guest_at(1, lambda b: zenoh_wire.open_(LEASE_MS, 1, _peer_cookie()))),
        ("a peer stream of three one-byte headers", edit(lambda s: s.update(peer=[b"\x21", b"\x22", b"\x03"]))),
        ("an INIT_ACK of another wire version", peer_at(0, lambda b: b[:1] + b"\x08" + b[2:])),
        ("an INIT_ACK from a client", peer_at(0, lambda b: b[:2] + bytes([(b[2] & 0xF0) | 2]) + b[3:])),
        ("an INIT_ACK with an extension flag", peer_at(0, lambda b: bytes([b[0] | 0x80]) + b[1:])),
        ("an INIT_ACK cut inside its ZID", peer_at(0, lambda b: b[:6])),
        ("an INIT_ACK whose cookie runs past the batch", peer_at(0, lambda b: b[:-1])),
        ("an INIT_ACK with a byte after the cookie", peer_at(0, lambda b: b + b"\x00")),
        ("an OPEN_ACK with a lease and no sequence number", peer_at(1, lambda b: b[:2])),
        ("an OPEN_ACK with a byte after the sequence number", peer_at(1, lambda b: b + b"\x00")),
        ("an OPEN_ACK with a zero lease", peer_at(1, lambda b: b[:1] + b"\x00" + b[2:])),
        ("a keep-alive with a byte after it", edit(lambda s: s["peer"].append(b"\x04\x00"))),
        ("a keep-alive with a flag set", edit(lambda s: s["peer"].append(b"\x24"))),
        ("a CLOSE of one byte", edit(lambda s: s["peer"].append(b"\x03"))),
        ("a peer CLOSE with reason 8", edit(lambda s: s["peer"].append(b"\x23\x08"))),
        ("a peer CLOSE with bit 6 set", edit(lambda s: s["peer"].append(b"\x63\x00"))),
        ("a CLOSE of three bytes", edit(lambda s: s["peer"].append(b"\x03\x00\x00"))),
        ("a FRAME with no sequence number", edit(lambda s: s["peer"].append(b"\x25"))),
        ("a FRAME with no message", edit(lambda s: s["peer"].append(b"\x25\x01"))),
        ("a keep-alive after the peer's CLOSE", edit(lambda s: s["peer"].extend([b"\x03\x00", b"\x04"]))),
        ("a FRAME after the peer's CLOSE", edit(lambda s: s["peer"].extend([b"\x03\x00", b"\x25\x01\x04"]))),
        ("a second CLOSE from the peer", edit(lambda s: s["peer"].extend([b"\x03\x00", b"\x03\x00"]))),
        ("a listener on another address", edit(lambda s: s.update(listen="tcp/0.0.0.0:17447"))),
        ("a listener on another port", edit(lambda s: s.update(listen="tcp/127.0.0.1:17448"))),
        ("a listener that saw no remote peer", edit(lambda s: s.update(remote_peers=0))),
        ("a listener that saw nine remote peers", edit(lambda s: s.update(remote_peers=9))),
        ("a receipt of three samples", edit(lambda s: s["receipt"].pop())),
        ("a receipt of five samples", edit(lambda s: s["receipt"].append(s["receipt"][-1]))),
        ("a receipt with another payload", edit(lambda s: s["receipt"].__setitem__(1, (s["receipt"][1][0], "00" * 12, s["receipt"][1][2])))),
        ("a receipt with another attachment", edit(lambda s: s["receipt"].__setitem__(2, (s["receipt"][2][0], s["receipt"][2][1], "00" * 33)))),
        ("a receipt with another key", edit(lambda s: s["receipt"].__setitem__(0, ("other/key", s["receipt"][0][1], s["receipt"][0][2])))),
        ("a receipt in another order", edit(lambda s: s["receipt"].reverse())),
        ("a report that drops a sent batch", edit(lambda s: s.update(lines=[x for x in s["lines"] if "wire sent sample=3 " not in x]))),
        ("a report that duplicates a sent batch", edit(lambda s: s["lines"].insert(-1, next(x for x in s["lines"] if "wire sent sample=0 " in x)))),
        ("a report without the scouting denial", edit(lambda s: s.update(lines=[x for x in s["lines"] if "scouting" not in x]))),
        ("a report with sample 1 before the session opens", edit(lambda s: s["lines"].insert(3, s["lines"].pop(next(n for n, x in enumerate(s["lines"]) if " wire sent sample=1 " in x))))),
        ("a report with sample 1 between the session and the match", edit(lambda s: s["lines"].insert(4, s["lines"].pop(next(n for n, x in enumerate(s["lines"]) if " wire sent sample=1 " in x))))),
        ("a report with samples 2 and 3 swapped", edit(lambda s: s["lines"].insert(8, s["lines"].pop(7)))),
        ("a report with sample 0 last", edit(lambda s: s["lines"].insert(8, s["lines"].pop(5)))),
        ("a report with a line that only contains a keyword", edit(lambda s: s["lines"].insert(-1, f"[{PUBLISHER}] unexpected session diagnostic"))),
        ("a report with a close line that has an extra field", edit(lambda s: s["lines"].__setitem__(-1, s["lines"][-1] + " extra=1"))),
        ("a report with the listen denial twice", edit(lambda s: s["lines"].insert(0, f"[{PUBLISHER}] denial class=listen refused=1"))),
        ("a report with the undeclared-port denial, which the publisher checks and never prints", edit(lambda s: s["lines"].insert(1, f"[{PUBLISHER}] denial class=undeclared-port refused=1"))),
        ("a report with a denial the exam does not name", edit(lambda s: s["lines"].insert(0, f"[{PUBLISHER}] denial class=invented refused=1"))),
        ("a report from the subscriber", edit(lambda s: s["lines"].insert(0, f"[{SUBSCRIBER}] session open role=listener initial_sn=0 lease_ms=2000"))),
        ("a report whose session closes before the last sample", edit(lambda s: s["lines"].insert(-3, s["lines"].pop()))),
        ("a report whose match precedes the session", edit(lambda s: s["lines"].insert(3, s["lines"].pop(4)))),
    ]


def _frame_starts(data: bytes) -> list[int]:
    """The file offset of each frame in a capture this module built."""
    starts, at = [], 24
    while at < len(data):
        length = int.from_bytes(data[at + 8 : at + 12], "little")
        starts.append(at + 16)
        at += 16 + length
    return starts


def _flip(data: bytes, at: int) -> bytes:
    return data[:at] + bytes([data[at] ^ 1]) + data[at + 1 :]


def _retarget(data: bytes, match: Callable[[bool, int, int], bool], at: int, mac: bytes) -> bytes:
    """Replace six bytes of the first TCP frame `match(outgoing, flags, payload_bytes)` accepts: the
    Ethernet destination (`at` 0) or source (`at` 6). No checksum covers them."""
    for start in _frame_starts(data):
        frame = data[start:]
        if int.from_bytes(frame[12:14], "big") != 0x0800 or frame[14 + 9] != 6:
            continue
        header = (frame[14] & 15) * 4
        total = int.from_bytes(frame[16:18], "big")
        offset = (frame[14 + header + 12] >> 4) * 4
        outgoing = ".".join(str(b) for b in frame[26:30]) == GUEST
        if match(outgoing, frame[14 + header + 13], total - header - offset):
            return data[: start + at] + mac + data[start + at + 6 :]
    raise CaptureError("control: no frame matched")


def byte_mutations() -> list[tuple[str, Callable[[bytes], bytes]]]:
    def first_data_frame(data: bytes) -> int:
        return next(s for s in _frame_starts(data) if int.from_bytes(data[s + 16 : s + 18], "big") > 40 and data[s + 14 + 9] == 6)

    return [
        ("an empty capture", lambda data: b""),
        ("a capture that is not a pcap", lambda data: b"\x00" * 64),
        ("a capture cut inside a record", lambda data: data[:-5]),
        ("a guest-bound data segment addressed to a third-party MAC", lambda data: _retarget(data, lambda o, f, n: not o and n > 0, 0, OTHER_MAC)),
        ("a guest-bound data segment addressed to broadcast", lambda data: _retarget(data, lambda o, f, n: not o and n > 0, 0, BROADCAST)),
        ("the peer's SYN-ACK addressed to a third-party MAC", lambda data: _retarget(data, lambda o, f, n: not o and f & TCP_SYN, 0, OTHER_MAC)),
        ("the peer's FIN addressed to a third-party MAC", lambda data: _retarget(data, lambda o, f, n: not o and f & TCP_FIN, 0, OTHER_MAC)),
        ("a guest SYN sent from a third-party MAC", lambda data: _retarget(data, lambda o, f, n: o and f & TCP_SYN, 6, OTHER_MAC)),
        ("a guest data segment sent from a third-party MAC", lambda data: _retarget(data, lambda o, f, n: o and n > 0, 6, OTHER_MAC)),
        ("a guest FIN sent from a third-party MAC", lambda data: _retarget(data, lambda o, f, n: o and f & TCP_FIN, 6, OTHER_MAC)),
        ("a flipped IPv4 header byte under a stale header checksum", lambda data: _flip(data, _frame_starts(data)[1] + 14 + 16)),
        ("a flipped TCP payload byte under a stale TCP checksum", lambda data: _flip(data, first_data_frame(data) + 14 + 20 + 20)),
    ]


def honest_variants(contract: dict) -> list[tuple[str, Callable[[dict], dict]]]:
    def update(**changes: object) -> Callable[[dict], dict]:
        def run(s: dict) -> dict:
            s.update(changes)
            return s

        return run

    return [
        ("segments of 100 bytes", update(chunk=100)),
        ("segments of 1 byte", update(chunk=1)),
        ("the first two guest segments reordered", update(chunk=100, reorder=True)),
        ("a retransmitted segment", update(chunk=100, retransmit=True)),
        ("a guest sequence number about to wrap", update(guest_isn=0xFFFFFF00)),
        ("a peer sequence number about to wrap", update(peer_isn=0xFFFFFFF0)),
        ("keep-alives from the guest", lambda s: {**s, "guest": s["guest"][:2] + [bytes([ID_KEEP_ALIVE])] * 3 + s["guest"][2:]}),
        ("a guest that never sends CLOSE", lambda s: {**s, "guest": s["guest"][:-1]}),
        ("a non-zero initial sequence number, reported and sent consistently", lambda s: synthesize(contract, 5)),
        ("an INIT_SYN without size parameters", lambda s: {**s, "guest": [zenoh_wire.init(bytes(range(1, 9)), zenoh_wire.DEFAULT_BATCH), *s["guest"][1:]]}),
        ("an INIT_SYN with the smallest batch size, 1", lambda s: {**s, "guest": [zenoh_wire.init(bytes(range(1, 9)), 1), *s["guest"][1:]]}),
        ("an INIT_SYN with the largest batch size, 65534", lambda s: {**s, "guest": [zenoh_wire.init(bytes(range(1, 9)), 65534), *s["guest"][1:]]}),
        ("an INIT_SYN with a 16 byte ZID", lambda s: {**s, "guest": [zenoh_wire.init(bytes(range(1, 17)), 512), *s["guest"][1:]]}),
        ("an INIT_SYN with a 1 byte ZID", lambda s: {**s, "guest": [zenoh_wire.init(b"\x01", 512), *s["guest"][1:]]}),
        ("the stock listener's whole session, as captured, with its two keep-alives and close", lambda s: {**s, "peer": list(STOCK_LISTENER)}),
        ("PSH on every data segment", update(psh=True)),
        ("a peer session CLOSE, 23 00, ending the stream", lambda s: {**s, "peer": [*s["peer"][:6], zenoh_wire.close(0, True)]}),
        ("a duplicate guest ACK at its next sequence number", update(stray_ack_before_packet=1, stray_ack_seq_skew=0)),
        ("a guest keep-alive probe one sequence number under", update(stray_ack_before_packet=1, stray_ack_seq_skew=-1)),
        ("a peer subscriber FRAME of exactly 512 bytes, the batch bound", lambda s: {**s, "peer": [*s["peer"][:4], _pad_peer_frame(s["peer"][4], 512), *s["peer"][5:]]}),
        ("a peer subscriber FRAME of 511 bytes, one under the bound", lambda s: {**s, "peer": [*s["peer"][:4], _pad_peer_frame(s["peer"][4], 511), *s["peer"][5:]]}),
        ("a guest SYN with MSS 4, window scale 3, SACK-permitted 2 and timestamps 10 bytes long", update(guest_options=_option(MSS, (1460).to_bytes(2, "big")) + _option(SACK) + _option(WSCALE, b"\x07") + _option(TIMESTAMP_OPTION, bytes(8)))),
        ("an initial sequence number of 0xFFFFFFFE, the frames wrapping through zero", lambda s: synthesize(contract, 0xFFFFFFFE)),
        ("an initial sequence number of 0xFFFFFFFF, the frames wrapping at once", lambda s: synthesize(contract, 0xFFFFFFFF)),
        ("a guest silent for exactly the 2000 ms lease before its first sample", update(silence_us=2_000_000)),
        ("a guest silent for 1999.999 ms before its first sample", update(silence_us=1_999_999)),
        ("a peer silent for exactly the 10 s lease it announced", update(peer_gap_us=10_000_000)),
        ("a guest KEEP_ALIVE carried with the first sample, after the OPEN_ACK", lambda s: {**s, "guest": [*s["guest"][:2], bytes([ID_KEEP_ALIVE]), *s["guest"][2:]]}),
        ("the peer's FIN after the last guest frame", update(peer_fin_after_data_packets=1, chunk=1400)),
        ("data segments that acknowledge less than the other side had sent", update(ack_lag=True)),
        ("the handshake ACK carried by the first data segment", update(no_hs_ack=True)),
        ("the handshake ACK at relative 0 and the first data segment acknowledging the SYN", update(ack_skew={"hs_ack": -1})),
        ("a peer data segment acknowledging one byte under what the guest had sent", update(ack_skew={"peer_data": -1})),
        ("a SYN-ACK retransmitted identically", update(synack_again=0)),
        ("a guest SYN retransmitted with only a timestamp option differing", update(syn_again=0, again_guest_options=GUEST_OPTIONS + _option(TIMESTAMP_OPTION, bytes(8)))),
        ("a handshake that negotiates no options, retransmitted", update(guest_options=b"", peer_options=b"", syn_again=0, synack_again=0)),
        ("a handshake that negotiates only a segment size", update(guest_options=_option(MSS, (1460).to_bytes(2, "big")), peer_options=_option(MSS, (1460).to_bytes(2, "big")))),
        ("a peer CLOSE right after the fourth sample, before the guest's own CLOSE", lambda s: {**s, "peer": [*s["peer"][:5], zenoh_wire.close(0, True)], "layout": "close_after_four_samples"}),
        ("the peer undeclares its subscriber after the last sample, then closes", lambda s: {**s, "peer": [*s["peer"][:5], _undeclare_frame(s, 1, K()), zenoh_wire.close(0, True)]}),
        ("the peer undeclares its subscriber by id after the last sample, then closes, as a stock peer does", lambda s: {**s, "peer": [*s["peer"][:5], _undeclare_by_id_frame(s, 1), zenoh_wire.close(0, True)]}),
        ("peer FRAME sequence numbers that wrap through 2**32", lambda s: {**s, "peer": [*s["peer"][:1], zenoh_wire.open_(10000, 0xFFFFFFFE, ack=True), *[_with_sn(b, 0xFFFFFFFE + i) for i, b in enumerate(s["peer"][2:5])], *s["peer"][5:]]}),
        ("a guest SYN retransmitted identically", update(syn_again=0)),
        ("a guest CLOSE with the last reason the profile names, 7", lambda s: {**s, "guest": [*s["guest"][:-1], zenoh_wire.close(7, True)]}),
        ("an ARP reply from the peer", lambda s: {**s, "extra": [*s.get("extra", []), _arp_frame(sender=(10, 0, 2, 2), target=(10, 0, 2, 15), mac=PEER_MAC, operation=2)]}),
        ("an ARP request with the standard zero target hardware address", lambda s: {**s, "extra": [*s.get("extra", []), _arp_frame(target_hw=bytes(6))]}),
        ("an ARP request from the peer", lambda s: {**s, "extra": [*s.get("extra", []), _arp_frame(sender=(10, 0, 2, 2), target=(10, 0, 2, 15), mac=PEER_MAC)]}),
    ]


def controls(contract: dict) -> tuple[int, int, int]:
    """Judge the honest scenario and its variants, then refuse every mutation.

    Returns (samples judged, honest variants accepted, mutations refused).
    """
    good = synthesize(contract)
    first = judge(copy.deepcopy(good), contract)
    _need(first["frames"] == SAMPLES and first["receipt"] == SAMPLES, "the honest scenario was not judged whole")
    accepted = 0
    distinct = {build(good)}
    for label, change in honest_variants(contract):
        capture = build(change(copy.deepcopy(good)))
        _need(capture not in distinct, f"control: the honest variant {label} builds a capture that another honest variant, or the base, already builds")
        distinct.add(capture)
        try:
            judge(change(copy.deepcopy(good)), contract)
        except (CaptureError, StopIteration) as error:
            raise CaptureError(f"control: the judge refused an honest capture with {label}: {error}") from error
        accepted += 1
    refused = 0
    for label, mutate in mutations():
        try:
            judge(mutate(copy.deepcopy(good)), contract)
        except (CaptureError, StopIteration):
            refused += 1
            continue
        raise CaptureError(f"control: the judge accepted {label}")
    honest = build(good)
    reported = judge_guest_lines(good["lines"], contract)
    for label, damage in byte_mutations():
        try:
            judge_capture(damage(honest), reported, contract)
        except CaptureError:
            refused += 1
            continue
        raise CaptureError(f"control: the judge accepted {label}")
    return first["frames"], accepted, refused
