"""The LiDAR publisher exam: what `sel4-lidar-external` must show a stock Zenoh peer and the wire.

Work item 01a19cdb-5986-7d5f-a948-0d23122f52e5. The exam owns five judgements, and none of them reads
the publisher's code, its link configuration or the Rust frame-store reader:

* the store: the frames the guest must send, read from a frame store the caller encoded from the
  hash-pinned bag with `frame_store_exam`;
* the composition: the derived manifest grants the publisher one outbound TCP connection and one
  block ring with read rights only, and its system spec declares an arrival ceiling above the root's
  default;
* the transcript: the root reports that ceiling before the publisher's first line, the publisher
  reports the store and a summary equal to it and then the closed session, and the graph ends healthy;
* the capture: one TCP connection to the host peer carries every Put as FRAGMENT batches of at most
  4096 bytes with their stream length, each reassembling to its frame byte for byte, and each Put
  starting at least the period less the tolerance after the one before;
* the receipt: the stock peer's `contracts/zenoh-digest-receipt/v1` record holds every frame's length
  and SHA-256 and attachment, in order, read only through the contract's decoder.

Each judgement is trusted only after it accepts the honest synthetic evidence in `controls()` and
refuses every corruption of it. The publisher's lines, each prefixed `[lidar-publisher] `, are exactly:

    store frames=F period=P digest=D         F frames, P the store's period in nanoseconds, D the SHA-256
                                             of the payloads concatenated in index order
    summary frames=F bytes=B late=L elapsed_ms=E
                                             B the payload bytes sent, L the frames handed over late,
                                             E the milliseconds from the first frame to the last
    session closed

The root's ceiling line is `SLIME_GRAPH arrival-ceiling=N`, and the system spec declares the same N
as `graphArrivalCeiling = N;`.
"""

from __future__ import annotations

import copy
import hashlib
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

import frame_store_exam as frames
import mcap_format
import zenoh_capture
import zenoh_exchange
import zenoh_fragment
import zenoh_listener_peer
import zenoh_wire
import zutai_cli
from harness import ROOT

ITEM = "01a19cdb-5986-7d5f-a948-0d23122f52e5"
CLOSURE = "sel4-lidar-external"
SYSTEM = ROOT / "contracts" / "system-spec" / "v1" / "systems" / f"{CLOSURE}.zti"
COMPOSITION = ROOT / "contracts" / "generation-manifest" / "v1" / "compositions" / f"{CLOSURE}.zti"
RECEIPT_SCHEMA = ROOT / "contracts" / "zenoh-digest-receipt" / "v1" / "schema.zt"
SCRATCH = ROOT / "build" / "lidar-publish"

PUBLISHER = "lidar-publisher"
TAG = f"[{PUBLISHER}] "
INSTANCES = ("init", "network-service", "virtio-net-driver", "virtio-blk-driver", PUBLISHER)
INTERFACE = dict(zenoh_capture.INTERFACE)
PEER, PORT, LISTEN = zenoh_capture.PEER, zenoh_capture.PORT, zenoh_capture.LISTEN
KEY = "0/velodyne_points/sensor_msgs::msg::dds_::PointCloud2_/" + frames.BAG_TYPE_HASH
GID = zenoh_capture.DEMO_GID
PERIOD_NS = 500_000_000
TOLERANCE_NS = 5_000_000
# A batch with its two-byte stream length, as network-service carries it in one data operation.
BATCH_BYTES = 4096
DEFAULT_CEILING = 131072
# A store is at most 128 MiB; each 4096-byte batch adds a length, a header and a sequence number.
MAX_STREAM = 160 * 1024 * 1024
# The capture holds both directions with their headers. 4096-byte operations become about three
# segments each, about 73,000 for the store, and the peer may acknowledge each one.
MAX_CAPTURE = 256 * 1024 * 1024
MAX_PACKETS = 1_000_000

FAILURES = re.compile(r"panic|PANIC|\] fail: |SLIME_GRAPH FAIL|SLIME_GRAPH exhausted|SLIME_ROOT .*refused launch")
CEILING_LINE = re.compile(r"SLIME_GRAPH arrival-ceiling=(\d+)")
HEALTHY_LINE = re.compile(r"SLIME_GRAPH HEALTHY generation=(\d+) required=(\d+) live=(\d+) completed=(\d+) failed=0")
STORE_LINE = re.compile(rf"{re.escape(TAG)}store frames=(\d+) period=(\d+) digest=([0-9a-f]{{64}})")
SUMMARY_LINE = re.compile(rf"{re.escape(TAG)}summary frames=(\d+) bytes=(\d+) late=(\d+) elapsed_ms=(\d+)")
CLOSED_LINE = f"{TAG}session closed"
DECLARED_CEILING = re.compile(r"^\s*graphArrivalCeiling\s*=\s*(\d+)\s*;", re.M)
TERMINAL = re.compile(HEALTHY_LINE.pattern + "|" + FAILURES.pattern)
# 200 frames one period apart take 100 s at least; an emulated stack moving 99 MB may take far longer.
# Neither bound is a rate target: a run that ends inside them is judged, one that does not fails.
QEMU_SECONDS = 3600
LISTENER_SECONDS = 3600


class ExamError(Exception):
    """The evidence does not meet the exam."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise ExamError(reason)


# ---------------------------------------------------------------------------------------- store


@dataclass(frozen=True)
class Expected:
    """The frames a run must deliver: each as (offset, length, log time) in `store`."""

    store: bytes
    frames: tuple[tuple[int, int, int], ...]
    period_ns: int
    digest: str
    total: int

    def payload(self, index: int) -> bytes:
        offset, length, _ = self.frames[index]
        return self.store[offset : offset + length]


def expected(store: bytes) -> Expected:
    """What a store obliges the publisher to send, read by the exam's own frame-store decoder."""
    try:
        reading = frames.decode(store)
    except frames.Refused as refusal:
        raise ExamError(f"the exam's store is refused: {refusal}") from refusal
    rows = tuple((f.offset, f.length, f.log_time) for f in reading.frames)
    digest = hashlib.sha256()
    for offset, length, _ in rows:
        digest.update(store[offset : offset + length])
    return Expected(store, rows, reading.period_ns, digest.hexdigest(), sum(length for _, length, _ in rows))


def store_from_bag(named: str | None) -> bytes:
    """The frame store of the pinned bag, encoded by the frame-store exam from its own MCAP reading.

    The bag is named by SLIME_LIDAR_BAG and never committed; anything but the pinned bytes is refused."""
    _need(bool(named), f"{frames.BAG_ENV} must name the LiDAR bag (SHA-256 {frames.BAG_SHA256})")
    path = Path(named).resolve()
    _need(path.is_file(), f"{frames.BAG_ENV}={named} is not a file")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    _need(len(data) == frames.BAG_BYTES and digest == frames.BAG_SHA256, f"{path} is not the pinned bag: {len(data)} bytes, SHA-256 {digest}")
    try:
        bag = mcap_format.read(data)
        frames.judge_bag(bag)
    except (mcap_format.McapError, frames.ExamError) as error:
        raise ExamError(f"the pinned bag is refused: {error}") from error
    store = frames.encode(frames.expected_store(bag, frames.BAG_CHANNEL, frames.BAG_PERIOD_NS))
    want = expected(store)
    _need(len(want.frames) == frames.BAG_FRAMES, f"the store holds {len(want.frames)} frames, the bag item pins {frames.BAG_FRAMES}")
    _need(all(length == frames.BAG_FRAME_BYTES for _, length, _ in want.frames), "a frame is not the pinned payload size")
    return store


def attachment_for(index: int, log_time: int) -> bytes:
    """The rmw_zenoh attachment of frame `index`: sequence index + 1, its log time, the demo GID."""
    return zenoh_wire.attachment(index + 1, log_time, GID)


# ---------------------------------------------------------------------------------- composition


def read_ceiling(text: str) -> int:
    """The arrival ceiling a system spec declares: exactly one, above the root's default."""
    found = DECLARED_CEILING.findall(text)
    _need(len(found) == 1, f"the system spec declares {len(found)} graphArrivalCeiling fields, the exam needs one")
    ceiling = int(found[0])
    _need(ceiling > DEFAULT_CEILING, f"the declared arrival ceiling {ceiling} is not above the default {DEFAULT_CEILING}")
    return ceiling


def composition_from_text(text: str) -> tuple:
    """Generation, instances, interfaces, destinations, applications and block rings of a derived manifest."""
    generation, instances, destinations, applications = zenoh_exchange.composition_from_text(text)
    interfaces = zenoh_exchange.parse_rows(text, "networkInterfaces")
    rings = zenoh_exchange.parse_rows(text, "blockRingAuthority")
    return generation, instances, interfaces, destinations, applications, rings


def check_rows(generation: int, instances: list[str], interfaces: list[dict], destinations: list[dict],
               applications: list[dict], rings: list[dict]) -> int:
    """Refuse a composition that grants the publisher more or less than one connection and one read ring.

    Returns the number of authority facts verified."""
    facts = 0

    def need(condition: bool, message: str) -> None:
        nonlocal facts
        _need(condition, message)
        facts += 1

    need(generation > 0, f"generation {generation} is not a generation number")
    need(sorted(instances) == sorted(INSTANCES), f"instances {sorted(instances)}, expected {sorted(INSTANCES)}")
    need(len(interfaces) == 1, f"{len(interfaces)} network interfaces, the exam declares one")
    need({k: interfaces[0].get(k) for k in INTERFACE} == INTERFACE, "the interface is not the user-network address, gateway and MAC sel4-zenoh-external declares")
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
    need(len(rings) == 1, f"{len(rings)} block ring rows, the exam declares one")
    ring = rings[0]
    need(ring.get("holder") == PUBLISHER, "the block ring is not held by the publisher")
    need(ring.get("rights") == ["blockRead"], f"the block ring grants {ring.get('rights')}, the exam declares read rights only")
    need((ring.get("device"), ring.get("ring")) == (0, 0), "the block ring is not ring 0 of device 0")
    return facts


def good_rows() -> tuple:
    destination = {
        "holder": PUBLISHER, "transport": "tcp", "addressKind": "ipv4", "address": PEER, "port": PORT,
        "rights": ["connect", "send", "recv"], "listenerLimit": 0, "dnsRecordLimit": 0,
    }
    publisher = {"holder": PUBLISHER, "role": "client", "backend": "external", "rights": [], "admittedPeer": "", "admittedPeerAddress": ""}
    ring = {"device": 0, "holder": PUBLISHER, "rights": ["blockRead"], "ring": 0, "sectorLimit": 200000}
    return (171, list(INSTANCES), [dict(INTERFACE)], [destination], [publisher], [ring])


def row_mutations() -> list[tuple[str, Callable[[list], None]]]:
    def interface(**c: object) -> Callable[[list], None]:
        return lambda v: v[2][0].update(c)

    def dest(**c: object) -> Callable[[list], None]:
        return lambda v: v[3][0].update(c)

    def publisher(**c: object) -> Callable[[list], None]:
        return lambda v: v[4][0].update(c)

    def ring(**c: object) -> Callable[[list], None]:
        return lambda v: v[5][0].update(c)

    return [
        ("generation 0", lambda v: v.__setitem__(0, 0)),
        ("an extra instance", lambda v: v[1].append("zenoh-router")),
        ("no block driver", lambda v: v[1].remove("virtio-blk-driver")),
        ("no network driver", lambda v: v[1].remove("virtio-net-driver")),
        ("no publisher", lambda v: v[1].remove(PUBLISHER)),
        ("no interface", lambda v: v[2].clear()),
        ("two interfaces", lambda v: v[2].append(dict(v[2][0]))),
        ("another guest address", interface(address="10.0.2.16")),
        ("another gateway", interface(gateway="10.0.2.3")),
        ("another MAC", interface(mac="52:54:00:53:4c:02")),
        ("another prefix", interface(prefixLen=16)),
        ("no destination", lambda v: v[3].clear()),
        ("a second destination", lambda v: v[3].append(dict(v[3][0], port=PORT + 1))),
        ("port 17446, one under", dest(port=PORT - 1)),
        ("port 17448, one over", dest(port=PORT + 1)),
        ("the loopback address", dest(address="127.0.0.1")),
        ("a DNS name", dest(addressKind="dns", address="example.test")),
        ("a udp destination", dest(transport="udp")),
        ("a missing right", dest(rights=["connect", "send"])),
        ("an extra right", dest(rights=["connect", "send", "recv", "listen"])),
        ("a listen limit", dest(listenerLimit=1)),
        ("a resolver record", dest(dnsRecordLimit=1)),
        ("the destination held by the block driver", dest(holder="virtio-blk-driver")),
        ("a loopback backend", publisher(backend="loopback")),
        ("a publisher with rights", publisher(rights=["listen"])),
        ("a listening publisher", publisher(role="listener")),
        ("a publisher admitting a peer", publisher(admittedPeer="init")),
        ("a second application row", lambda v: v[4].append(dict(v[4][0], holder="init"))),
        ("no application", lambda v: v[4].clear()),
        ("no block ring", lambda v: v[5].clear()),
        ("two block rings", lambda v: v[5].append(dict(v[5][0], ring=1))),
        ("a ring held by another instance", ring(holder="init")),
        ("a ring with write rights", ring(rights=["blockRead", "blockWrite"])),
        ("a ring with write rights only", ring(rights=["blockWrite"])),
        ("a ring with no rights", ring(rights=[])),
        ("ring 1", ring(ring=1)),
        ("device 1", ring(device=1)),
    ]


CEILING_CASES = (
    ("one ceiling above the default", "  graphArrivalCeiling = 4194304;\n", True),
    ("one ceiling one above the default", f"  graphArrivalCeiling = {DEFAULT_CEILING + 1};\n", True),
    ("no ceiling", "", False),
    ("the default ceiling", f"  graphArrivalCeiling = {DEFAULT_CEILING};\n", False),
    ("a ceiling below the default", "  graphArrivalCeiling = 4096;\n", False),
    ("two ceilings", "  graphArrivalCeiling = 4194304;\n  graphArrivalCeiling = 4194304;\n", False),
)


def composition_controls() -> tuple[int, int, int]:
    """Judge the honest rows and ceilings, then refuse every mutation. Returns (facts, accepted, refused)."""
    good = good_rows()
    facts = check_rows(*good)
    accepted = 1
    refused = 0
    for label, change in row_mutations():
        variant = copy.deepcopy(list(good))
        change(variant)
        try:
            check_rows(*variant)
        except ExamError:
            refused += 1
            continue
        raise ExamError(f"control: the composition judge accepted {label}")
    for label, text, should in CEILING_CASES:
        try:
            read_ceiling("{\n  name = \"sel4-lidar-external\";\n" + text + "}\n")
            took = True
        except ExamError:
            took = False
        _need(took == should, f"control: the ceiling reader {'refused' if should else 'accepted'} {label}")
        accepted, refused = accepted + took, refused + (not took)
    return facts, accepted, refused


# ----------------------------------------------------------------------------------- transcript


def judge_transcript(transcript: str, want: Expected, ceiling: int, generation: int) -> dict:
    """The root's ceiling, the publisher's three lines and the healthy end, in that order."""
    lines = [line.strip() for line in transcript.splitlines()]
    for line in lines:
        failure = FAILURES.search(line)
        _need(failure is None, f"a failure line: {line[:200]!r}")
    ceilings = [i for i, line in enumerate(lines) if CEILING_LINE.fullmatch(line)]
    _need(len(ceilings) == 1, f"the root reported its arrival ceiling {len(ceilings)} times, the exam needs once")
    reported = int(CEILING_LINE.fullmatch(lines[ceilings[0]]).group(1))
    _need(reported == ceiling, f"the root reports arrival ceiling {reported}, the system spec declares {ceiling}")
    mine = [(i, line) for i, line in enumerate(lines) if line.startswith(TAG)]
    _need(len(mine) == 3, f"the publisher printed {len(mine)} lines, the exam names exactly store, summary and session closed")
    _need(ceilings[0] < mine[0][0], "the root reported its arrival ceiling after the publisher's first line")
    store = STORE_LINE.fullmatch(mine[0][1])
    _need(store is not None, f"the publisher's first line is not its store line: {mine[0][1][:200]!r}")
    count, period, digest = int(store.group(1)), int(store.group(2)), store.group(3)
    _need(count == len(want.frames), f"the publisher reports {count} frames, the store holds {len(want.frames)}")
    _need(period == want.period_ns, f"the publisher reports period {period}, the store declares {want.period_ns}")
    _need(digest == want.digest, "the publisher reports another payload digest than the store's")
    summary = SUMMARY_LINE.fullmatch(mine[1][1])
    _need(summary is not None, f"the publisher's second line is not its summary: {mine[1][1][:200]!r}")
    sent, sent_bytes, late, elapsed = (int(summary.group(n)) for n in range(1, 5))
    _need(sent == len(want.frames), f"the summary reports {sent} frames, the store holds {len(want.frames)}")
    _need(sent_bytes == want.total, f"the summary reports {sent_bytes} bytes, the store's payloads are {want.total}")
    _need(late <= sent, f"the summary reports {late} late frames of {sent}")
    _need(mine[2][1] == CLOSED_LINE, f"the publisher's last line is not {CLOSED_LINE!r}: {mine[2][1][:200]!r}")
    healthy = [i for i, line in enumerate(lines) if HEALTHY_LINE.fullmatch(line)]
    _need(bool(healthy), "the graph never reported HEALTHY with failed=0")
    _need(healthy[0] > mine[2][0], "the graph reported HEALTHY before the publisher's session closed")
    found = int(HEALTHY_LINE.fullmatch(lines[healthy[0]]).group(1))
    _need(found == generation, f"HEALTHY names generation {found}, the composition declares {generation}")
    return {"ceiling": reported, "late": late, "elapsed_ms": elapsed}


def honest_transcript(want: Expected, ceiling: int, generation: int) -> list[str]:
    return [
        "SLIME_ROOT generation admitted",
        f"SLIME_GRAPH arrival-ceiling={ceiling}",
        "[virtio-blk-driver] authority rings=1 rights=read source=generation",
        f"{TAG}store frames={len(want.frames)} period={want.period_ns} digest={want.digest}",
        f"{TAG}summary frames={len(want.frames)} bytes={want.total} late=0 elapsed_ms=1000",
        CLOSED_LINE,
        f"SLIME_GRAPH HEALTHY generation={generation} required=5 live=0 completed=5 failed=0",
    ]


def transcript_mutations(want: Expected, ceiling: int, generation: int) -> list[tuple[str, Callable[[list[str]], list[str]]]]:
    def at(index: int, text: str) -> Callable[[list[str]], list[str]]:
        return lambda lines: [*lines[:index], text, *lines[index + 1 :]]

    count, total, digest = len(want.frames), want.total, want.digest
    store = f"{TAG}store frames={count} period={want.period_ns} digest={digest}"
    summary = f"{TAG}summary frames={count} bytes={total} late=0 elapsed_ms=1000"
    healthy = f"SLIME_GRAPH HEALTHY generation={generation} required=5 live=0 completed=5 failed=0"
    return [
        ("no ceiling line", lambda lines: [line for line in lines if not CEILING_LINE.fullmatch(line)]),
        ("two ceiling lines", lambda lines: [*lines[:2], lines[1], *lines[2:]]),
        ("another ceiling", at(1, f"SLIME_GRAPH arrival-ceiling={ceiling + 1}")),
        ("the default ceiling", at(1, f"SLIME_GRAPH arrival-ceiling={DEFAULT_CEILING}")),
        ("the ceiling after the store line", lambda lines: [lines[0], lines[2], lines[3], lines[1], *lines[4:]]),
        ("one frame fewer in the store line", at(3, store.replace(f"frames={count}", f"frames={count - 1}"))),
        ("another period in the store line", at(3, store.replace(f"period={want.period_ns}", f"period={want.period_ns + 1}"))),
        ("another digest in the store line", at(3, store.replace(digest, ("0" if digest[0] != "0" else "1") + digest[1:]))),
        ("one frame fewer in the summary", at(4, summary.replace(f"frames={count}", f"frames={count - 1}"))),
        ("one byte fewer in the summary", at(4, summary.replace(f"bytes={total}", f"bytes={total - 1}"))),
        ("more late frames than frames", at(4, summary.replace("late=0", f"late={count + 1}"))),
        ("no store line", lambda lines: [line for line in lines if line != store]),
        ("no summary", lambda lines: [line for line in lines if line != summary]),
        ("no session closed", lambda lines: [line for line in lines if line != CLOSED_LINE]),
        ("the summary before the store line", lambda lines: [*lines[:3], lines[4], lines[3], *lines[5:]]),
        ("an extra publisher line", lambda lines: [*lines[:4], f"{TAG}connected", *lines[4:]]),
        ("no HEALTHY", lambda lines: [line for line in lines if line != healthy]),
        ("HEALTHY with a failed instance", at(6, healthy.replace("failed=0", "failed=1"))),
        ("HEALTHY before the session closed", lambda lines: [*lines[:5], healthy, *lines[5:6]]),
        ("HEALTHY for another generation", at(6, healthy.replace(f"generation={generation}", f"generation={generation + 1}"))),
        ("a publisher failure", lambda lines: [*lines, f"{TAG}fail: link"]),
        ("an exhausted ceiling", lambda lines: [*lines, "SLIME_GRAPH exhausted live=3 iterations=4194304 certified=1"]),
        ("a graph failure", lambda lines: [*lines[:5], "SLIME_GRAPH FAIL graph iterations exhausted live=4", *lines[5:]]),
        ("a panic", lambda lines: [*lines[:5], "PANIC in lidar-publisher", *lines[5:]]),
    ]


def transcript_controls(want: Expected) -> tuple[int, int]:
    ceiling, generation = 4194304, 171
    honest = honest_transcript(want, ceiling, generation)
    judge_transcript("\n".join(honest), want, ceiling, generation)
    refused = 0
    for label, change in transcript_mutations(want, ceiling, generation):
        try:
            judge_transcript("\n".join(change(list(honest))), want, ceiling, generation)
        except ExamError:
            refused += 1
            continue
        raise ExamError(f"control: the transcript judge accepted {label}")
    return 1, refused


# -------------------------------------------------------------------------------------- capture


ID_FRAGMENT = zenoh_fragment.ID_FRAGMENT
ID_KEEP_ALIVE = zenoh_capture.ID_KEEP_ALIVE


def judge_capture(data: bytes, want: Expected) -> dict:
    """The one connection's guest stream: handshake, every Put as a run of fragments, then a CLOSE."""
    try:
        guest, _peer, arp, guest_time, _peer_time = zenoh_capture.streams(data, MAX_STREAM, MAX_CAPTURE, MAX_PACKETS)
        batches, spans = zenoh_capture.split(guest, "guest stream", BATCH_BYTES - zenoh_fragment.STREAM_LENGTH_BYTES)
        _need(len(batches) >= 3, "the guest sent fewer than an INIT_SYN, an OPEN_SYN and a CLOSE")
        init, opened = batches[0], batches[1]
        _need(zenoh_capture._kind(init) == zenoh_wire.ID_INIT and not init[0] & zenoh_wire.FLAG_A, "the first guest batch is not an INIT_SYN")
        zenoh_capture._init_fields(init, "INIT_SYN", False)
        _need(zenoh_capture._kind(opened) == zenoh_wire.ID_OPEN and not opened[0] & zenoh_wire.FLAG_A, "the second guest batch is not an OPEN_SYN")
        _lease, sn, _cookie = zenoh_capture._open_fields(opened, "OPEN_SYN", False)
        puts: list[tuple[int, bytes]] = []
        run: tuple[int, list[bytes]] | None = None
        closed = False
        for index, batch in enumerate(batches[2:], start=2):
            _need(not closed, "a guest batch after its CLOSE")
            if batch == bytes([ID_KEEP_ALIVE]):
                continue
            kind = zenoh_capture._kind(batch)
            if kind == zenoh_wire.ID_CLOSE:
                _need(run is None, "the guest closed inside a fragmented Put")
                zenoh_capture._close(batch, "guest")
                closed = True
            elif kind == zenoh_wire.ID_FRAME:
                _need(run is None, "a FRAME inside a fragmented Put")
                _need(batch[0] == zenoh_wire.ID_FRAME | zenoh_wire.FLAG_R, f"a guest FRAME header {batch[0]:#04x}, only the reliable form 0x25 is taken")
                sequence, at = zenoh_fragment.read_leb32(batch, 1)
                _need(sequence == sn, f"a guest FRAME with sequence number {sequence}, the session's next is {sn}")
                sn = (sn + 1) & 0xFFFFFFFF
                if at < len(batch) and batch[at] & 0x1F == zenoh_capture.ID_PUSH:
                    # A Put small enough to travel whole is still a Put the run accounts for. Its
                    # decoder refuses any byte after the payload, so the FRAME carries it alone.
                    puts.append((index, batch[at:]))
                else:
                    _sequence, kinds = zenoh_capture._frame_messages(batch, "a guest FRAME")
                    _need("push" not in kinds, "a guest FRAME carries a Put after another message")
            elif kind == ID_FRAGMENT:
                part = zenoh_fragment.decode_fragment(batch, BATCH_BYTES)
                _need(part.sn == sn, f"a FRAGMENT with sequence number {part.sn}, the session's next is {sn}")
                sn = (sn + 1) & 0xFFFFFFFF
                run = (index, []) if run is None else run
                run[1].append(part.data)
                if not part.more:
                    puts.append((run[0], b"".join(run[1])))
                    run = None
            else:
                raise ExamError(f"a guest batch the exam does not name: header {batch[0]:#04x}, {len(batch)} bytes")
        _need(run is None, "the guest stream ends inside a fragmented Put")
        _need(closed, "the guest never sent a CLOSE")
        _need(len(puts) == len(want.frames), f"the capture carries {len(puts)} Puts, the store holds {len(want.frames)} frames")
        for index, (_start, message) in enumerate(puts):
            decoded = zenoh_fragment.decode_message(message, max_key=256, subscribed=KEY)
            _need(decoded["key"] is not None, f"Put {index} names the key by an alias, not in full")
            _need(bytes(decoded["attachment"]) == attachment_for(index, want.frames[index][2]), f"Put {index} carries another attachment than sequence {index + 1}, its log time and the demo GID")
            _need(decoded["payload"] == want.payload(index), f"Put {index} carries another payload than frame {index}")
        starts = [guest_time.time_of(spans[first][0]) for first, _ in puts]
    except (zenoh_capture.CaptureError, zenoh_fragment.FragmentError) as error:
        raise ExamError(str(error)) from error
    gaps = [after - before for before, after in zip(starts, starts[1:], strict=False)]
    for index, gap in enumerate(gaps):
        _need(gap >= PERIOD_NS - TOLERANCE_NS, f"Put {index + 1} started {gap} ns after Put {index}, under the {PERIOD_NS} ns period less {TOLERANCE_NS} ns")
    return {
        "puts": len(puts), "batches": len(batches), "largest_batch": max(len(b) for b in batches) + zenoh_fragment.STREAM_LENGTH_BYTES,
        "guest_stream": len(guest), "arp": arp, "min_gap_ns": min(gaps, default=0),
        "span_ns": starts[-1] - starts[0] if starts else 0,
    }


INITIAL_SN = 0xFFFFFFFE
COOKIE = bytes(range(0x40, 0x50))


@dataclass(frozen=True)
class Wire:
    """A synthetic session: the guest's batches with the time each is sent, in microseconds, and the peer's."""

    guest: tuple[tuple[int, bytes], ...]
    peer: tuple[bytes, ...]
    second_connection: bool = False
    reset: bool = False
    udp: bool = False


def put_message(want: Expected, index: int, *, key: str = KEY, attachment: bytes | None = None,
                payload: bytes | None = None, alias: bool = False) -> bytes:
    """Frame `index` as the network message the publisher sends: a PUSH naming the key in full."""
    att = attachment_for(index, want.frames[index][2]) if attachment is None else attachment
    data = want.payload(index) if payload is None else payload
    if not alias:
        return zenoh_wire.push_put(key, att, data, True)
    put = bytes([zenoh_wire.ID_PUT | zenoh_wire.FLAG_Z, zenoh_wire.EXT_ATTACHMENT]) + zenoh_wire.prefixed(att) + zenoh_wire.prefixed(data)
    return bytes([zenoh_fragment.PUSH_ALIAS]) + zenoh_wire.leb128(1) + put


def session(want: Expected, *, order: tuple[int, ...] | None = None, gaps_us: tuple[int, ...] | None = None,
            batch: int = BATCH_BYTES, change: dict[int, dict] | None = None) -> Wire:
    """What a publisher and a stock peer put on the wire, from the host references alone.

    The honest session sends every frame in index order, one period apart, in batches of `batch`
    bytes. `order` sends other frames, `gaps_us` other spacings, and `change` replaces fields of the
    Put at a position, so a control breaks one claim and keeps the rest of the session honest."""
    order = tuple(range(len(want.frames))) if order is None else order
    change = change or {}
    guest = [(0, zenoh_wire.init(bytes(range(1, 9)), batch)), (1000, zenoh_wire.open_(10000, INITIAL_SN, COOKIE))]
    sn, at = INITIAL_SN, 10_000
    for position, index in enumerate(order):
        if position:
            at += PERIOD_NS // 1000 if gaps_us is None else gaps_us[position - 1]
        bodies = zenoh_fragment.reference_split(put_message(want, index, **change.get(position, {})), batch, sn)
        sn = zenoh_fragment.next_sn(sn, len(bodies))
        guest.extend((at + step, body) for step, body in enumerate(bodies))
    guest.append((guest[-1][0] + 1000, zenoh_wire.close(0, True)))
    peer = (
        zenoh_wire.init(bytes(range(9, 17)), batch, COOKIE),
        zenoh_wire.open_(10000, 7, ack=True),
        zenoh_wire.frame(7, zenoh_wire.declare_subscriber(1, KEY, True)),
        zenoh_wire.close(0, True),
    )
    return Wire(tuple(guest), peer)


GUEST, GUEST_PORT = zenoh_capture.GUEST, zenoh_capture.GUEST_PORT
TCP_SYN, TCP_ACK, TCP_FIN, TCP_RST = zenoh_capture.TCP_SYN, zenoh_capture.TCP_ACK, zenoh_capture.TCP_FIN, zenoh_capture.TCP_RST


def capture(wire: Wire, segment: int = 1400) -> bytes:
    """A PCAP of `wire` on one connection: the handshake, the INIT and OPEN exchange with the peer's
    declaration after its OPEN_ACK, the guest's batches at their times, the peer's CLOSE and both FINs."""
    tcp, eth = zenoh_capture._tcp, zenoh_capture._ethernet
    gisn, pisn = 1000, 700000
    packets: list[tuple[int, bytes]] = []
    sent = {True: 0, False: 0}
    batches = [batch for _, batch in wire.guest]
    guest_stream = b"".join(zenoh_wire.stream(b) for b in batches)
    peer_stream = b"".join(zenoh_wire.stream(b) for b in wire.peer)

    def offsets(items: list[bytes] | tuple[bytes, ...]) -> list[int]:
        found = [0]
        for item in items:
            found.append(found[-1] + 2 + len(item))
        return found

    guest_at, peer_at = offsets(batches), offsets(wire.peer)

    def send(outgoing: bool, start: int, end: int, time_us: int) -> None:
        data = guest_stream if outgoing else peer_stream
        for at in range(start, end, segment):
            chunk = data[at : min(at + segment, end)]
            if outgoing:
                frame = tcp(GUEST, PEER, GUEST_PORT, PORT, gisn + 1 + at, pisn + 1 + sent[False], TCP_ACK, chunk)
            else:
                frame = tcp(PEER, GUEST, PORT, GUEST_PORT, pisn + 1 + at, gisn + 1 + sent[True], TCP_ACK, chunk)
            sent[outgoing] = max(sent[outgoing], at + len(chunk))
            packets.append((time_us, eth(frame, outgoing)))

    def guest_batches(first: int, last: int) -> None:
        for index in range(first, min(last, len(batches))):
            send(True, guest_at[index], guest_at[index + 1], wire.guest[index][0])

    def peer_batches(first: int, last: int, time_us: int) -> None:
        last = min(last, len(wire.peer))
        if last > first:
            send(False, peer_at[first], peer_at[last], time_us)

    packets.append((0, zenoh_capture._arp()))
    packets.append((0, eth(tcp(GUEST, PEER, GUEST_PORT, PORT, gisn, 0, TCP_SYN, b"", 65535, zenoh_capture.GUEST_OPTIONS), True)))
    packets.append((0, eth(tcp(PEER, GUEST, PORT, GUEST_PORT, pisn, gisn + 1, TCP_SYN | TCP_ACK, b"", 65535, zenoh_capture.PEER_OPTIONS), False)))
    packets.append((0, eth(tcp(GUEST, PEER, GUEST_PORT, PORT, gisn + 1, pisn + 1, TCP_ACK), True)))
    guest_batches(0, 1)
    peer_batches(0, 1, wire.guest[0][0])
    guest_batches(1, 2)
    peer_batches(1, 3, wire.guest[1][0])
    guest_batches(2, len(batches))
    end = max(time for time, _ in wire.guest)
    peer_batches(3, len(wire.peer), end)
    if wire.udp:
        packets.append((end, eth(zenoh_capture._udp(GUEST, PEER, 49300, 53, bytes(12)), True)))
    if wire.second_connection:
        packets.append((end, eth(tcp(GUEST, PEER, GUEST_PORT + 1, PORT, 5000, 0, TCP_SYN, b"", 65535, zenoh_capture.GUEST_OPTIONS), True)))
    if wire.reset:
        packets.append((end, eth(tcp(PEER, GUEST, PORT, GUEST_PORT, pisn + 1 + sent[False], gisn + 1 + sent[True], TCP_RST | TCP_ACK), False)))
    gfin, pfin = gisn + 1 + len(guest_stream), pisn + 1 + len(peer_stream)
    packets.append((end + 1, eth(tcp(GUEST, PEER, GUEST_PORT, PORT, gfin, pfin, TCP_FIN | TCP_ACK), True)))
    packets.append((end + 2, eth(tcp(PEER, GUEST, PORT, GUEST_PORT, pfin, gfin + 1, TCP_FIN | TCP_ACK), False)))
    packets.append((end + 3, eth(tcp(GUEST, PEER, GUEST_PORT, PORT, gfin + 1, pfin + 1, TCP_ACK), True)))
    return zenoh_capture.pcap([frame for _, frame in packets], [time for time, _ in packets])


def control_store() -> bytes:
    """A small store whose frames need one, three and eight fragments at the exam's batch."""
    payloads = (bytes(range(256)) * 4, bytes((i * 7) % 251 for i in range(9000)), bytes((i * 13) % 241 for i in range(30000)))
    store = replace(frames.BASE, topic=frames.BAG_CHANNEL, period_ns=frames.BAG_PERIOD_NS,
                    frames=tuple((1_700_000_000_000_000_000 + i * frames.BAG_PERIOD_NS, p) for i, p in enumerate(payloads)))
    return frames.encode(store)


def large_control_store() -> bytes:
    """Three frames of 11.25 MiB: a session past the default capture bounds, built in seconds."""
    payloads = tuple(bytes(range(k, 256)) + bytes(range(k)) for k in (1, 2, 3))
    store = replace(frames.BASE, topic=frames.BAG_CHANNEL, period_ns=frames.BAG_PERIOD_NS,
                    frames=tuple((1_700_000_000_000_000_000 + i * frames.BAG_PERIOD_NS, p * 46080) for i, p in enumerate(payloads)))
    return frames.encode(store)


def _edit(wire: Wire, change: Callable[[list[tuple[int, bytes]]], list[tuple[int, bytes]]]) -> Wire:
    return replace(wire, guest=tuple(change(list(wire.guest))))


def _with_header(item: tuple[int, bytes], header: int) -> tuple[int, bytes]:
    return item[0], bytes([header]) + item[1][1:]


def _with_sn(item: tuple[int, bytes], sn: int) -> tuple[int, bytes]:
    _, at = zenoh_fragment.read_leb32(item[1], 1)
    return item[0], item[1][:1] + zenoh_wire.leb128(sn) + item[1][at:]


def capture_mutations(want: Expected) -> list[tuple[str, Callable[[], Wire]]]:
    """Each a synthetic session that breaks one claim of the capture judge."""
    honest = session(want)
    count = len(want.frames)
    log = want.frames[0][2]
    flipped = bytearray(want.payload(1))
    flipped[len(flipped) // 2] ^= 1
    under = (PERIOD_NS - TOLERANCE_NS) // 1000 - 1
    period = PERIOD_NS // 1000
    whole = zenoh_wire.frame(INITIAL_SN, zenoh_wire.push_put(KEY, attachment_for(0, log), b"\x00", True))
    return [
        ("the last Put missing", lambda: session(want, order=tuple(range(count - 1)))),
        ("the last Put twice", lambda: session(want, order=(*range(count), count - 1))),
        ("the first two Puts swapped", lambda: session(want, order=(1, 0, *range(2, count)))),
        ("one payload bit flipped", lambda: session(want, change={1: {"payload": bytes(flipped)}})),
        ("a payload one byte short", lambda: session(want, change={1: {"payload": want.payload(1)[:-1]}})),
        ("attachment sequence 0", lambda: session(want, change={0: {"attachment": zenoh_wire.attachment(0, log, GID)}})),
        ("attachment sequence 2 on the first Put", lambda: session(want, change={0: {"attachment": zenoh_wire.attachment(2, log, GID)}})),
        ("attachment timestamp one off", lambda: session(want, change={0: {"attachment": zenoh_wire.attachment(1, log + 1, GID)}})),
        ("another GID", lambda: session(want, change={0: {"attachment": zenoh_wire.attachment(1, log, bytes(16))}})),
        ("another key", lambda: session(want, change={0: {"key": KEY.replace("velodyne_points", "velodyne_point")}})),
        ("the key by alias", lambda: session(want, change={0: {"alias": True}})),
        ("a Put one microsecond under the period less the tolerance", lambda: session(want, gaps_us=(period, under))),
        ("a Put started at once", lambda: session(want, gaps_us=(0, period))),
        ("batches of 4097 bytes", lambda: session(want, batch=BATCH_BYTES + 1)),
        ("a skipped fragment sequence number", lambda: _edit(honest, lambda g: [*g[:3], _with_sn(g[3], zenoh_fragment.next_sn(INITIAL_SN, 2)), *g[4:]])),
        ("a last fragment that says more follows", lambda: _edit(honest, lambda g: [*g[:-2], _with_header(g[-2], g[-2][1][0] | zenoh_fragment.FLAG_M), g[-1]])),
        ("an unreliable fragment", lambda: _edit(honest, lambda g: [*g[:2], _with_header(g[2], g[2][1][0] & ~zenoh_fragment.FLAG_R), *g[3:]])),
        ("an extra Put in a whole FRAME", lambda: _edit(honest, lambda g: [*g[:2], (g[2][0], whole), *[_with_sn(item, zenoh_fragment.next_sn(INITIAL_SN, i + 1)) for i, item in enumerate(g[2:-1])], g[-1]])),
        ("a declaration and a Put on another key in one FRAME", lambda: _edit(honest, lambda g: [*g[:2], (g[2][0], zenoh_wire.frame(INITIAL_SN, zenoh_wire.declare_subscriber(1, "x", True), zenoh_wire.push_put("other", attachment_for(0, log), b"\x00", True))), *[_with_sn(item, zenoh_fragment.next_sn(INITIAL_SN, i + 1)) for i, item in enumerate(g[2:-1])], g[-1]])),
        ("the first Put twice in one whole FRAME", lambda: _edit(honest, lambda g: [*g[:2], (g[2][0], zenoh_wire.frame(INITIAL_SN, put_message(want, 0), put_message(want, 0))), *g[3:]])),
        ("no CLOSE", lambda: _edit(honest, lambda g: g[:-1])),
        ("a batch after the CLOSE", lambda: _edit(honest, lambda g: [*g, (g[-1][0], bytes([ID_KEEP_ALIVE]))])),
        ("a second TCP connection", lambda: replace(honest, second_connection=True)),
        ("a reset", lambda: replace(honest, reset=True)),
        ("a DNS datagram", lambda: replace(honest, udp=True)),
    ]


def capture_controls(want: Expected) -> tuple[int, int]:
    """The honest session, one with keep-alives and one at exactly the period less the tolerance
    pass; every mutation fails."""
    boundary = (PERIOD_NS - TOLERANCE_NS) // 1000
    keep_alive = _edit(session(want), lambda g: [*g[:2], (g[1][0], bytes([ID_KEEP_ALIVE])), *g[2:]])
    first = put_message(want, 0)
    _need(zenoh_fragment.fits_one_frame(first, BATCH_BYTES, INITIAL_SN), "control: the first control frame does not fit one batch")
    whole = _edit(session(want), lambda g: [*g[:2], (g[2][0], zenoh_wire.frame(INITIAL_SN, first)), *g[3:]])
    honest = (
        ("honest", session(want)), ("with a keep-alive", keep_alive), ("with the first Put in a whole FRAME", whole),
        ("at the period less the tolerance", session(want, gaps_us=(boundary, boundary))),
    )
    for label, wire in honest:
        try:
            judge_capture(capture(wire), want)
        except ExamError as error:
            raise ExamError(f"control: the capture judge refused {label}: {error}") from error
    # The run's capture is about 110 MB in some 150,000 frames, past the HTTP capture defaults
    # of 32 MiB and 100,000 frames that `zenoh_capture` inherits. An honest capture past both must pass.
    large = expected(large_control_store())
    data = capture(session(large), segment=320)
    _need(len(data) > zenoh_capture.http_capture.MAX_CAPTURE, "control: the large capture is not over the default byte bound")
    records = sum(1 for _ in zenoh_capture.http_capture._frames(data, max_bytes=MAX_CAPTURE, max_frames=MAX_PACKETS))
    _need(records > zenoh_capture.http_capture.MAX_FRAMES, "control: the large capture is not over the default frame bound")
    try:
        judge_capture(data, large)
    except ExamError as error:
        raise ExamError(f"control: the capture judge refused an honest capture over the default bounds: {error}") from error
    refused = 0
    for label, build in capture_mutations(want):
        try:
            judge_capture(capture(build()), want)
        except ExamError:
            refused += 1
            continue
        raise ExamError(f"control: the capture judge accepted {label}")
    return len(honest) + 1, refused


# -------------------------------------------------------------------------------------- receipt


ROW = re.compile(r'\{ attachmentHex = "([0-9a-f]*)";\s*key = "([^"]*)";\s*payloadBytes = (\d+);\s*payloadSha256 = "([0-9a-f]*)" \}')


def read_receipt(path: Path) -> tuple[str, int, list[tuple[str, int, str, str]]]:
    """Decode a listener record through contracts/zenoh-digest-receipt/v1, then read its values."""
    scratch = SCRATCH / "decoder"
    scratch.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(RECEIPT_SCHEMA, scratch / "schema.zt")
    (scratch / "decode.zt").write_text(
        's ::= import "schema.zt"; env ::= import stdlib.env; load ::= import stdlib.load; '
        "main :: { env : Env; load : Load; } -> Validation DecodeIssue s.Receipt ! { * env.GetEffects; * load.ZtiEffects; } "
        '= caps => [ path := env.get caps.env "SLIME_RECEIPT_PATH" ?? ""; s.decodeReceipt (load.zti caps.load path) ]; main\n',
        encoding="utf-8",
    )
    try:
        decoded = zutai_cli.evaluate("run", scratch / "decode.zt", input_path=path, env_var="SLIME_RECEIPT_PATH")
    except zutai_cli.ZutaiError as error:
        raise ExamError(f"the listener record does not decode: {error}") from error
    _need(decoded.startswith("#valid"), f"the listener record is refused by its contract: {decoded[:160]}")
    listen = re.search(r'\blisten = "([^"]*)"', decoded)
    peers = re.search(r"\bmaxRemotePeers = (\d+)", decoded)
    _need(listen is not None and peers is not None, "the decoded record has no listen or maxRemotePeers")
    rows = ROW.findall(decoded)
    _need(len(rows) == decoded.count("attachmentHex ="), "a sample the reader cannot parse")
    return listen.group(1), int(peers.group(1)), [(key, int(size), sha, att) for att, key, size, sha in rows]


def judge_receipt(listen: str, remote_peers: int, rows: list[tuple[str, int, str, str]], want: Expected) -> int:
    """The stock peer's own account of what its subscriber delivered, against the store."""
    _need(listen == LISTEN, f"the listener reports {listen!r}, the exam declares {LISTEN!r}")
    _need(remote_peers == 1, f"the listener saw {remote_peers} remote peers, the guest is one")
    _need(len(rows) == len(want.frames), f"the listener delivered {len(rows)} samples, the store holds {len(want.frames)} frames")
    for index, (key, size, sha, att) in enumerate(rows):
        payload = want.payload(index)
        _need(key == KEY, f"sample {index}: the listener matched key {key!r}, not the exam's")
        _need(size == len(payload), f"sample {index}: {size} payload bytes, frame {index} has {len(payload)}")
        _need(sha == hashlib.sha256(payload).hexdigest(), f"sample {index}: the payload's SHA-256 is not frame {index}'s")
        _need(att == attachment_for(index, want.frames[index][2]).hex(), f"sample {index}: another attachment than sequence {index + 1}, its log time and the demo GID")
    return len(rows)


def _record(rows: list[str], version: int = 1, peer: str = "1.0.0", peers: int = 1, top: str = "", listen: str = LISTEN) -> str:
    return f'{{\n  formatVersion = {version};\n  peerVersion = "{peer}";\n  listen = "{listen}";\n  maxRemotePeers = {peers};\n{top}  samples = [\n{"".join(rows)}  ];\n}}\n'


def _row(key: str, size: int, sha: str, att: str, inner: str = "") -> str:
    return f'    {{ key = "{key}"; payloadBytes = {size}; payloadSha256 = "{sha}"; attachmentHex = "{att}";{" " + inner if inner else ""} }};\n'


def receipt_cases(want: Expected) -> list[tuple[str, str, bool, bool]]:
    """(label, record text, the decoder accepts it, the judge accepts it)."""
    honest = [zenoh_listener_peer.digested(KEY, want.payload(i), attachment_for(i, want.frames[i][2])) for i in range(len(want.frames))]
    written = zenoh_listener_peer.digest_receipt_text(LISTEN, 1, honest)
    rows = [_row(k, n, s, a.hex()) for k, n, s, a in honest]
    _key, size, sha, att = rows and honest[0]
    att = att.hex()

    def first(row: str) -> list[str]:
        return [row, *rows[1:]]

    other_sha = ("0" if sha[0] != "0" else "1") + sha[1:]
    return [
        ("a record written by the listener's own writer", written, True, True),
        ("an honest record", _record(rows), True, True),
        ("the longest key, 256 bytes", _record(first(_row("k" * 256, size, sha, att))), True, False),
        ("the largest payload, 16 MiB", _record(first(_row(KEY, 16777216, sha, att))), True, False),
        ("an empty payload", _record(first(_row(KEY, 0, sha, att))), True, False),
        ("eight remote peers", _record(rows, peers=8), True, False),
        ("two remote peers", _record(rows, peers=2), True, False),
        ("one sample fewer", _record(rows[:-1]), True, False),
        ("one sample more", _record([*rows, rows[-1]]), True, False),
        ("two samples swapped", _record([rows[1], rows[0], *rows[2:]]), True, False),
        ("another payload digest", _record(first(_row(KEY, size, other_sha, att))), True, False),
        ("another payload length", _record(first(_row(KEY, size + 1, sha, att))), True, False),
        ("another attachment", _record(first(_row(KEY, size, sha, "00" + att[2:] if att[:2] != "00" else "01" + att[2:]))), True, False),
        ("another key", _record(first(_row(KEY + "x", size, sha, att))), True, False),
        ("another listen endpoint", _record(rows, listen="tcp/127.0.0.1:17448"), True, False),
        ("the most samples, 4096", _record([rows[0]] * 4096), True, False),
        ("4097 samples", _record([rows[0]] * 4097), False, False),
        ("a key of 257 bytes", _record(first(_row("k" * 257, size, sha, att))), False, False),
        ("an empty key", _record(first(_row("", size, sha, att))), False, False),
        ("a payload of 16 MiB and one byte", _record(first(_row(KEY, 16777217, sha, att))), False, False),
        ("a negative payload length", _record(first(_row(KEY, -1, sha, att))), False, False),
        ("a digest of 31 bytes", _record(first(_row(KEY, size, sha[:-2], att))), False, False),
        ("a digest of 33 bytes", _record(first(_row(KEY, size, sha + "00", att))), False, False),
        ("an uppercase digest", _record(first(_row(KEY, size, sha.upper(), att))), False, False),
        ("an attachment of 32 bytes", _record(first(_row(KEY, size, sha, att[:-2]))), False, False),
        ("an attachment of 34 bytes", _record(first(_row(KEY, size, sha, att + "00"))), False, False),
        ("format version 2", _record(rows, version=2), False, False),
        ("another peer version", _record(rows, peer="1.1.0"), False, False),
        ("no remote peer", _record(rows, peers=0), False, False),
        ("nine remote peers", _record(rows, peers=9), False, False),
        ("a field the contract does not name", _record(rows, top='  note = "x";\n'), False, False),
        ("a sample field the contract does not name", _record(first(_row(KEY, size, sha, att, 'note = "x";'))), False, False),
    ]


def receipt_controls(want: Expected) -> tuple[int, int]:
    """Run each record through the decoder and the judge. Returns (accepted, refused)."""
    SCRATCH.mkdir(parents=True, exist_ok=True)
    path = SCRATCH / "receipt-control.zti"
    accepted = refused = 0
    for label, text, decodes, judged in receipt_cases(want):
        path.write_text(text, encoding="utf-8")
        try:
            read = read_receipt(path)
            took_decoder = True
        except ExamError:
            took_decoder = False
        _need(took_decoder == decodes, f"control: the receipt decoder {'refused' if decodes else 'accepted'} {label}")
        took = False
        if took_decoder:
            try:
                judge_receipt(*read, want)
                took = True
            except ExamError:
                took = False
        _need(took == judged, f"control: the receipt judge {'refused' if judged else 'accepted'} {label}")
        accepted, refused = accepted + took, refused + (not took)
    return accepted, refused


# ------------------------------------------------------------------------------------- controls


# The counts the controls produce, pinned so a judge that quietly loses a case is seen: a judge that
# refuses fewer corruptions, or accepts fewer honest variants, fails the pin before it judges a run.
PINNED_ACCEPTED = 11
PINNED_REFUSED = 120


def controls() -> tuple[int, int]:
    """Every judge held to its honest synthetic evidence and to each corruption. Returns (accepted, refused)."""
    want = expected(control_store())
    _facts, composition_accepted, composition_refused = composition_controls()
    transcript_accepted, transcript_refused = transcript_controls(want)
    capture_accepted, capture_refused = capture_controls(want)
    receipt_accepted, receipt_refused = receipt_controls(want)
    accepted = composition_accepted + transcript_accepted + capture_accepted + receipt_accepted
    refused = composition_refused + transcript_refused + capture_refused + receipt_refused
    _need(accepted == PINNED_ACCEPTED, f"the judges accept {accepted} honest variants, the exam pins {PINNED_ACCEPTED}")
    _need(refused == PINNED_REFUSED, f"the judges refuse {refused} corruptions, the exam pins {PINNED_REFUSED}")
    return accepted, refused

