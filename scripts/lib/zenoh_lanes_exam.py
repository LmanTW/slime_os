"""Judge the Zenoh Profile 0 lanes exam: QoS-negotiated priorities, best-effort frames and fragments, and
several fragmented messages open at once.

A stock eclipse-zenoh peer keeps one sequence counter and one reassembly buffer for each pair of a priority
(0 to 7) and a reliability. A link that holds one reassembly run, as Profile 0 does today, refuses the traffic of a
second pair. This exam judges a link that holds `maxRuns` runs and takes that traffic.

A lane is a pair of a priority and a reliability. The rules the exam pins:

* A link with `maxRuns` of 2 or more offers the QoS unit extension on its INIT. A link with 1 writes the bytes it
  writes today and refuses every best-effort frame and fragment and every QoS extension, as it does today.
* Both sides must offer the extension for it to hold. A peer that did not offer it cannot select a priority.
* A FRAME or a FRAGMENT selects its lane with the mandatory transport QoS extension (`31 <priority>`), a priority
  of 0 to 7. An omitted extension and an explicit priority 5 are the same lane. Any other extension, a chain,
  a value above 7 and the non-mandatory form (`21`) are refused as `unsupported-extension`.
* Every lane counts from the sequence number the peer's OPEN announced. A reliable lane takes exactly its next
  number. A best-effort lane takes a number ahead of the last one by less than 2^31, sets its count past it, and
  drops anything else as stale.
* A reliable lane that breaks the rules above is refused, as today. A best-effort lane drops what it cannot take,
  counts the drop and stays open. A best-effort run that breaks makes the lane discard fragments through the next
  final fragment, because 1.0.0 fragments carry no message marker.
* At most `maxRuns` runs are open at once, one for each lane. A first fragment with no free run is refused on a
  reliable lane and dropped on a best-effort one.
* A reliable FRAME on a lane that has a run open is refused as `unexpected-message`. A best-effort FRAME there drops
  the run and is delivered, and the lost fragments are stale by their numbers. A stale FRAME leaves the run alone.

What upstream fixes, and what this exam does not take from upstream: the header bytes below are what `zenoh-codec`
1.0.0 writes, and the host reference here must write them again. The receive rules are read from the 1.10.1
`zenoh-transport` sources (`unicast/universal/rx.rs`, `common/priority.rs`, `common/defragmentation.rs`) and
were not observed against a live peer. Upstream is more lenient than this exam in three places: it accepts a
reliable frame that is ahead of the count, it ignores the higher bits of a QoS value, and it skips an unknown
non-mandatory extension. The judge refuses all three. Upstream is also less strict in one place: without fragment
markers it does not discard what follows a broken best-effort run, it joins the leftovers and fails at the decode.
This exam discards through the next final fragment, so a leftover never becomes a sample. That is this item's
choice and not a behaviour of the peer.

The Rust tests under `zenoh_lanes::` print one `[zenoh-exam] lanes ...` line for each step. This module builds the
whole transcript from the reference model below and the Rust must print it, line for line. A `fed` line carries the
length and the first 16 hexadecimal digits of the SHA-256 of the batch the test gave the link, so the test cannot
feed another batch than the reference builds.

The link under test is the listener on a heap configuration with a 2048-byte batch, a reassembly timeout of 5000 ms
and an initial sequence number of 7000. Its owner holds the one subscription on the demo key. Like the other
judges this one is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field

import zenoh_exchange
import zenoh_fragment as frag
import zenoh_links_exam as links
import zenoh_wire
from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-fragment-lanes.zt"
LIMITS_V2 = ROOT / "contracts" / "zenoh-link-limits" / "v2" / "schema.zt"

KEY = zenoh_exchange.demo()["key"]
OTHER_KEY = "0/slime_demo/other/Counter"
DEFAULT_PRIORITY = 5
SN0 = 7000
BATCH = 2048
TIMEOUT_MS = 5000
RUNS = 2
BIG = 4200
SMALL = 100
SN_MASK = 0xFFFFFFFF
HALF = 1 << 31

EXT_QOS = 0x31
EXT_QOS_OPTIONAL = 0x21
EXT_CHAIN = 0x80
ID_FRAME = 5
ID_FRAGMENT = 6
FLAG_R = 0x20
FLAG_M = 0x40
FLAG_Z = 0x80

CLASSES = frozenset(
    {
        "unsupported-extension", "unsupported-message", "unexpected-message", "malformed-message", "sequence-mismatch",
        "fragment-sequence", "reassembly-timeout", "lane-limit", "undeclared-key", "wildcard-keyexpr", "over-bound",
        "invalid-keyexpr", "trailing-bytes", "truncated",
    }
)


class LanesError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise LanesError(message)


# --------------------------------------------------------------------------- what upstream wrote
# Encoded with `zenoh-codec` 1.0.0 (`InitSyn`, `InitAck`, `FrameHeader`, `FragmentHeader`) in a scratch crate
# that depends on `zenoh-protocol = "=1.0.0"` and `zenoh-codec = "=1.0.0"`: ZID 112233, batch 2048, cookie aabbccdd.
UPSTREAM_INIT = {
    "syn": "4109211122330a0008",
    "syn-qos": "c109211122330a000801",
    "ack": "6109211122330a000804aabbccdd",
    "ack-qos": "e109211122330a000804aabbccdd01",
}
# (reliable, priority, sequence number, header bytes up to the payload)
UPSTREAM_FRAMES = (
    (1, 0, 5, "a5053100"), (1, 0, 7000, "a5d8363100"), (1, 2, 5, "a5053102"), (1, 2, 7000, "a5d8363102"),
    (1, 5, 5, "2505"), (1, 5, 7000, "25d836"), (1, 7, 5, "a5053107"), (1, 7, 7000, "a5d8363107"),
    (0, 0, 5, "85053100"), (0, 0, 7000, "85d8363100"), (0, 2, 5, "85053102"), (0, 2, 7000, "85d8363102"),
    (0, 5, 5, "0505"), (0, 5, 7000, "05d836"), (0, 7, 5, "85053107"), (0, 7, 7000, "85d8363107"),
)
# (reliable, priority, more, sequence number, header bytes up to the payload)
UPSTREAM_FRAGMENTS = (
    (1, 0, 1, 5, "e6053100"), (1, 0, 1, 300, "e6ac023100"), (1, 0, 0, 5, "a6053100"), (1, 0, 0, 300, "a6ac023100"),
    (1, 2, 1, 5, "e6053102"), (1, 2, 1, 300, "e6ac023102"), (1, 2, 0, 5, "a6053102"), (1, 2, 0, 300, "a6ac023102"),
    (1, 5, 1, 5, "6605"), (1, 5, 1, 300, "66ac02"), (1, 5, 0, 5, "2605"), (1, 5, 0, 300, "26ac02"),
    (1, 7, 1, 5, "e6053107"), (1, 7, 1, 300, "e6ac023107"), (1, 7, 0, 5, "a6053107"), (1, 7, 0, 300, "a6ac023107"),
    (0, 0, 1, 5, "c6053100"), (0, 0, 1, 300, "c6ac023100"), (0, 0, 0, 5, "86053100"), (0, 0, 0, 300, "86ac023100"),
    (0, 2, 1, 5, "c6053102"), (0, 2, 1, 300, "c6ac023102"), (0, 2, 0, 5, "86053102"), (0, 2, 0, 300, "86ac023102"),
    (0, 5, 1, 5, "4605"), (0, 5, 1, 300, "46ac02"), (0, 5, 0, 5, "0605"), (0, 5, 0, 300, "06ac02"),
    (0, 7, 1, 5, "c6053107"), (0, 7, 1, 300, "c6ac023107"), (0, 7, 0, 5, "86053107"), (0, 7, 0, 300, "86ac023107"),
)


# --------------------------------------------------------------------------------- the host reference


def leb(value: int) -> bytes:
    return zenoh_wire.leb128(value)


def qos_ext(priority: int, *, mandatory: bool = True, more: bool = False) -> bytes:
    return bytes([(EXT_QOS if mandatory else EXT_QOS_OPTIONAL) | (EXT_CHAIN if more else 0)]) + leb(priority)


def lane_ext(priority: int) -> bytes:
    """What a stock peer writes: nothing for the default priority, the mandatory QoS extension otherwise."""
    return b"" if priority == DEFAULT_PRIORITY else qos_ext(priority)


def frame_header(reliable: bool, priority: int, sn: int, ext: bytes | None = None) -> bytes:
    ext = lane_ext(priority) if ext is None else ext
    return bytes([ID_FRAME | (FLAG_R if reliable else 0) | (FLAG_Z if ext else 0)]) + leb(sn) + ext


def fragment_header(reliable: bool, priority: int, more: bool, sn: int, ext: bytes | None = None) -> bytes:
    ext = lane_ext(priority) if ext is None else ext
    flags = (FLAG_R if reliable else 0) | (FLAG_M if more else 0) | (FLAG_Z if ext else 0)
    return bytes([ID_FRAGMENT | flags]) + leb(sn) + ext


def init_message(zid: bytes, *, ack: bool, qos: bool) -> bytes:
    """INIT_SYN or INIT_ACK with the 2048-byte batch, the QoS unit extension last when `qos`."""
    raw = zenoh_wire.init(zid, BATCH, bytes.fromhex("aabbccdd") if ack else None)
    return bytes([raw[0] | (FLAG_Z if qos else 0)]) + raw[1:] + (b"\x01" if qos else b"")


def check_vectors(
    frames=frame_header, fragments=fragment_header, init=init_message, vectors=(UPSTREAM_INIT, UPSTREAM_FRAMES, UPSTREAM_FRAGMENTS)
) -> int:
    """The host reference writes every byte string `zenoh-codec` 1.0.0 wrote."""
    wanted_init, wanted_frames, wanted_fragments = vectors
    zid = bytes.fromhex("112233")
    for name, (ack, qos) in {"syn": (False, False), "syn-qos": (False, True), "ack": (True, False), "ack-qos": (True, True)}.items():
        _need(init(zid, ack=ack, qos=qos).hex() == wanted_init[name], f"the reference INIT {name} is not what upstream wrote")
    for reliable, priority, sn, hexed in wanted_frames:
        _need(frames(bool(reliable), priority, sn).hex() == hexed, f"the reference FRAME header {reliable}/{priority}/{sn} is not what upstream wrote")
    for reliable, priority, more, sn, hexed in wanted_fragments:
        _need(
            fragments(bool(reliable), priority, bool(more), sn).hex() == hexed,
            f"the reference FRAGMENT header {reliable}/{priority}/{more}/{sn} is not what upstream wrote",
        )
    return len(wanted_init) + len(wanted_frames) + len(wanted_fragments)


def put(seq: int, size: int, key: str = KEY) -> bytes:
    return zenoh_wire.push_put(key, zenoh_wire.attachment(seq, 1000 + seq, frag.GID), frag.payload_bytes(size), True)


def frame_of(sn: int, priority: int, reliable: bool, message: bytes, ext: bytes | None = None) -> bytes:
    return frame_header(reliable, priority, sn, ext) + message


def fragments_of(message: bytes, first_sn: int, priority: int, reliable: bool) -> list[bytes]:
    bodies: list[bytes] = []
    at, sn = 0, first_sn
    while at < len(message):
        ext = lane_ext(priority)
        room = BATCH - 2 - (1 + len(leb(sn)) + len(ext))
        chunk = message[at : at + room]
        at += len(chunk)
        bodies.append(fragment_header(reliable, priority, at < len(message), sn) + chunk)
        sn = (sn + 1) & SN_MASK
    return bodies


# --------------------------------------------------------------------------------- the reference model


class Refusal(Exception):
    def __init__(self, cls: str) -> None:
        super().__init__(cls)
        self.cls = cls


def _classed(error: frag.FragmentError) -> str:
    found = re.match(r"([a-z0-9-]+):", str(error))
    _need(found is not None and found.group(1) in CLASSES, f"the reference refused a message with no class: {error}")
    return found.group(1)  # type: ignore[union-attr]


def _lane_name(lane: tuple[int, bool]) -> str:
    return f"p{lane[0]}{'R' if lane[1] else 'B'}"


@dataclass
class Run:
    next_sn: int
    parts: bytearray
    started_ms: int


@dataclass
class Model:
    """The receive side of a link with `runs` reassembly runs, written from the rules in the module docstring."""

    runs: int
    negotiated: bool
    counters: dict[tuple[int, bool], int] = field(default_factory=dict)
    open_runs: dict[tuple[int, bool], Run] = field(default_factory=dict)
    discarding: set[tuple[int, bool]] = field(default_factory=set)
    touched: set[tuple[int, bool]] = field(default_factory=set)

    def next_of(self, lane: tuple[int, bool]) -> int:
        return self.counters.get(lane, SN0)

    def _ext(self, batch: bytes, at: int) -> tuple[int, int]:
        """The priority behind the extension at `at`, and where the body goes on."""
        if not self.negotiated:
            raise Refusal("unsupported-extension")
        _need(at < len(batch), "an extension flag with no extension")
        if batch[at] != EXT_QOS:
            raise Refusal("unsupported-extension")
        priority, after = frag.read_leb32(batch, at + 1)
        if priority > 7:
            raise Refusal("unsupported-extension")
        return priority, after

    def _ahead(self, lane: tuple[int, bool], sn: int) -> bool:
        # Upstream measures from the last number taken, which is one below the count held here: a gap from it
        # of 1 to 2^31 - 1 is ahead, so the count's own gap is 0 to 2^31 - 2.
        return ((sn - self.next_of(lane)) & SN_MASK) < HALF - 1

    def _sample(self, lane: tuple[int, bool], sn: int, message: bytes) -> str:
        decoded = frag.decode_message(message, subscribed=KEY)
        seq = int.from_bytes(decoded["attachment"][:8], "little", signed=True)
        return f"lanes sample p{lane[0]} {'R' if lane[1] else 'B'} sn={sn} payload={len(decoded['payload'])} seq={seq}"

    def tick(self, now: int) -> list[str]:
        out: list[str] = []
        for lane in sorted(self.open_runs):
            run = self.open_runs[lane]
            if now > run.started_ms + TIMEOUT_MS:
                if lane[1]:
                    raise Refusal("reassembly-timeout")
                del self.open_runs[lane]
                self.discarding.add(lane)
                out.append(f"lanes drop p{lane[0]} B cause=reassembly-timeout")
        return out

    def feed(self, batch: bytes, now: int) -> list[str]:
        header = batch[0]
        identifier = header & 0x1F
        if identifier == ID_FRAME:
            return self._frame(batch, now)
        if identifier == ID_FRAGMENT:
            return self._fragment(batch, now)
        raise LanesError(f"the reference was fed a batch that is neither a FRAME nor a FRAGMENT: {header:02x}")

    def _frame(self, batch: bytes, now: int) -> list[str]:
        header = batch[0]
        reliable = bool(header & FLAG_R)
        if self.runs < 2 and not reliable:
            raise Refusal("unsupported-message")
        sn, at = frag.read_leb32(batch, 1)
        priority = DEFAULT_PRIORITY
        if header & FLAG_Z:
            priority, at = self._ext(batch, at)
        lane = (priority, reliable)
        self.touched.add(lane)
        message = batch[at:]
        out: list[str] = []
        if reliable:
            if lane in self.open_runs:
                raise Refusal("unexpected-message")
            if sn != self.next_of(lane):
                raise Refusal("sequence-mismatch")
            self.counters[lane] = (sn + 1) & SN_MASK
        else:
            if not self._ahead(lane, sn):
                return [f"lanes drop p{priority} B cause=stale-sequence"]
            self.counters[lane] = (sn + 1) & SN_MASK
            if lane in self.open_runs:
                del self.open_runs[lane]
                out.append(f"lanes drop p{priority} B cause=frame-during-run")
        try:
            return [*out, self._sample(lane, sn, message)]
        except frag.FragmentError as error:
            if reliable:
                raise Refusal(_classed(error)) from error
            return [*out, f"lanes drop p{priority} B cause=completed:{_classed(error)}"]

    def _fragment(self, batch: bytes, now: int) -> list[str]:
        header = batch[0]
        reliable = bool(header & FLAG_R)
        more = bool(header & FLAG_M)
        if self.runs < 2 and not reliable:
            raise Refusal("unsupported-message")
        sn, at = frag.read_leb32(batch, 1)
        priority = DEFAULT_PRIORITY
        if header & FLAG_Z:
            priority, at = self._ext(batch, at)
        data = batch[at:]
        if not data:
            raise Refusal("malformed-message")
        lane = (priority, reliable)
        self.touched.add(lane)
        name = f"p{priority}"
        out: list[str] = []
        run = self.open_runs.get(lane)
        if run is not None and now > run.started_ms + TIMEOUT_MS:
            if reliable:
                raise Refusal("reassembly-timeout")
            del self.open_runs[lane]
            self.discarding.add(lane)
            out.append(f"lanes drop {name} B cause=reassembly-timeout")
            run = None
        if reliable:
            expected = run.next_sn if run is not None else self.next_of(lane)
            if run is None and sn != expected:
                raise Refusal("sequence-mismatch")
            if run is not None and sn != expected:
                raise Refusal("fragment-sequence")
            if run is None and len(self.open_runs) >= self.runs:
                raise Refusal("lane-limit")
        else:
            if not self._ahead(lane, sn):
                return [*out, f"lanes drop {name} B cause=stale-sequence"]
            self.counters[lane] = (sn + 1) & SN_MASK
            if lane in self.discarding:
                if not more:
                    self.discarding.discard(lane)
                return [*out, f"lanes drop {name} B cause=discarded"]
            if run is not None and sn != run.next_sn:
                del self.open_runs[lane]
                if more:
                    self.discarding.add(lane)
                return [*out, f"lanes drop {name} B cause=fragment-sequence"]
            if run is None and len(self.open_runs) >= self.runs:
                if more:
                    self.discarding.add(lane)
                return [*out, f"lanes drop {name} B cause=lane-limit"]
        if run is None:
            run = self.open_runs[lane] = Run(sn, bytearray(), now)
        run.parts += data
        run.next_sn = (sn + 1) & SN_MASK
        if reliable:
            self.counters[lane] = run.next_sn
        if more:
            return out
        del self.open_runs[lane]
        try:
            return [*out, self._sample(lane, sn, bytes(run.parts))]
        except frag.FragmentError as error:
            cls = _classed(error)
            if reliable:
                raise Refusal(cls) from error
            return [*out, f"lanes drop {name} B cause=completed:{cls}"]


# -------------------------------------------------------------------------------------- the scenarios


@dataclass(frozen=True)
class Scenario:
    name: str
    runs: int
    negotiated: bool
    events: tuple[tuple[int, str, bytes], ...]
    refused: str | None = None


def at_time(batches: list[bytes], start: int = 0) -> list[tuple[int, str, bytes]]:
    return [(start + index, "batch", batch) for index, batch in enumerate(batches)]


def interleave(*runs: list[bytes]) -> list[bytes]:
    out: list[bytes] = []
    for index in range(max(len(run) for run in runs)):
        out += [run[index] for run in runs if index < len(run)]
    return out


def scenarios() -> list[Scenario]:
    big = lambda seq, key=KEY: put(seq, BIG, key)  # noqa: E731
    small = lambda seq: put(seq, SMALL)  # noqa: E731
    one = lambda name, events, **kw: Scenario(name, kw.pop("runs", RUNS), kw.pop("negotiated", True), tuple(events), **kw)  # noqa: E731
    frames = lambda *items: at_time([frame_of(*item) for item in items])  # noqa: E731
    out = [
        one("reliable-lanes-interleaved", at_time(interleave(fragments_of(big(1), SN0, 2, True), fragments_of(big(2), SN0, 5, True)))),
        one("reliable-same-sn-on-two-lanes", frames((SN0, 0, True, small(3)), (SN0, 7, True, small(4)), (SN0 + 1, 0, True, small(5)))),
        one("best-effort-frame-delivered", frames((SN0, 5, False, small(6)))),
        one("best-effort-frame-gap", frames((SN0, 5, False, small(7)), (SN0 + 3, 5, False, small(8)))),
        one(
            "best-effort-frame-stale",
            frames((SN0, 5, False, small(9)), (SN0, 5, False, small(10)), (SN0 + 2, 5, False, small(11)), (SN0 + 1, 5, False, small(12))),
        ),
        one("best-effort-fragments", at_time(fragments_of(big(13), SN0, 3, False))),
        one(
            "best-effort-fragment-lost-middle",
            at_time([*(lambda f: [f[0], f[2]])(fragments_of(big(14), SN0, 3, False)), *fragments_of(big(15), SN0 + 3, 3, False)]),
        ),
        one("best-effort-fragment-lost-first", at_time(fragments_of(big(16), SN0, 3, False)[1:])),
        one(
            "best-effort-lost-final-discards-next",
            at_time([*fragments_of(big(17), SN0, 4, False)[:2], *fragments_of(big(18), SN0 + 3, 4, False), *fragments_of(big(19), SN0 + 6, 4, False)]),
        ),
        one(
            "best-effort-run-timeout",
            [
                (0, "batch", fragments_of(big(20), SN0, 4, False)[0]),
                (TIMEOUT_MS, "tick", b""),
                (TIMEOUT_MS + 1, "tick", b""),
                (TIMEOUT_MS + 2, "batch", fragments_of(big(20), SN0, 4, False)[1]),
                (TIMEOUT_MS + 3, "batch", fragments_of(big(20), SN0, 4, False)[2]),
                (TIMEOUT_MS + 4, "batch", frame_of(SN0 + 3, 4, False, small(21))),
            ],
        ),
        one(
            "best-effort-lane-limit",
            at_time(interleave(fragments_of(big(22), SN0, 1, False), fragments_of(big(23), SN0, 2, False), fragments_of(big(24), SN0, 3, False))),
        ),
        one(
            "frame-on-another-lane-during-a-run",
            at_time([*(lambda f: [f[0], frame_of(SN0, 5, True, small(29)), *f[1:]])(fragments_of(big(42), SN0, 2, True))]),
        ),
        one(
            "best-effort-frame-after-a-lost-final-fragment",
            at_time([*fragments_of(big(37), SN0, 3, False)[:2], frame_of(SN0 + 3, 3, False, small(47)), *fragments_of(big(50), SN0 + 4, 3, False)]),
        ),
        one(
            "best-effort-stale-frame-leaves-the-run",
            at_time([*fragments_of(big(48), SN0 + 1, 3, False)[:1], frame_of(SN0, 3, False, small(49)), *fragments_of(big(48), SN0 + 1, 3, False)[1:]]),
        ),
        one(
            "best-effort-half-window-edge",
            frames((SN0, 5, False, small(43)), (SN0 + HALF, 5, False, small(44)), (SN0 + HALF - 1, 5, False, small(45)), (SN0, 5, False, small(46))),
        ),
        one("reliable-and-best-effort-on-one-priority", at_time(interleave(fragments_of(big(25), SN0, 5, True), fragments_of(big(26), SN0, 5, False)))),
        one(
            "explicit-default-priority",
            at_time([frame_of(SN0, 5, True, small(27), ext=qos_ext(5)), frame_of(SN0 + 1, 5, True, small(28))]),
        ),
    ]
    refusals: list[Scenario] = []

    def refuse(name: str, cls: str, events: list[tuple[int, str, bytes]], **kw) -> None:
        refusals.append(one(name, events, refused=cls, **kw))

    f_big = lambda priority, reliable, first=SN0, seq=40: fragments_of(big(seq), first, priority, reliable)  # noqa: E731
    refuse("priority-8-on-frame", "unsupported-extension", frames((SN0, 0, True, small(30), qos_ext(8))))
    refuse(
        "priority-8-on-fragment",
        "unsupported-extension",
        at_time([fragment_header(True, 0, True, SN0, qos_ext(8)) + b"x"]),
    )
    refuse("qos-extension-not-mandatory", "unsupported-extension", frames((SN0, 2, True, small(31), qos_ext(2, mandatory=False))))
    refuse("qos-chain-continues", "unsupported-extension", frames((SN0, 2, True, small(32), qos_ext(2, more=True) + b"\x41\x00")))
    refuse("extension-id-2", "unsupported-extension", frames((SN0, 2, True, small(33), bytes([0x32, 2]))))
    refuse("qos-without-negotiation", "unsupported-extension", frames((SN0, 2, True, small(34))), negotiated=False)
    refuse("reliable-frame-gap", "sequence-mismatch", frames((SN0 + 1, 2, True, small(35))))
    refuse("reliable-fragment-gap", "fragment-sequence", at_time([f_big(2, True)[0], f_big(2, True)[2]]))
    refuse("reliable-first-fragment-wrong-sn", "sequence-mismatch", at_time(f_big(2, True, SN0 + 5)))
    refuse("reliable-frame-on-open-lane", "unexpected-message", at_time([f_big(2, True)[0], frame_of(SN0 + 1, 2, True, small(36))]))
    refuse("reliable-lane-limit", "lane-limit", at_time(interleave(f_big(1, True), f_big(2, True), f_big(3, True))))
    refuse("reliable-run-timeout", "reassembly-timeout", [(0, "batch", f_big(2, True)[0]), (TIMEOUT_MS + 1, "tick", b"")])
    refuse("reliable-completed-put-undeclared-key", "undeclared-key", at_time(fragments_of(big(38, OTHER_KEY), SN0, 2, True)))
    refuse("best-effort-fragment-empty", "malformed-message", at_time([fragment_header(False, 2, True, SN0)]))
    refuse("reliable-fragment-empty", "malformed-message", at_time([fragment_header(True, 2, True, SN0)]))
    refuse("single-run-best-effort-fragment", "unsupported-message", at_time([f_big(5, False)[0]]), runs=1, negotiated=False)
    refuse("single-run-best-effort-frame", "unsupported-message", frames((SN0, 5, False, small(39))), runs=1, negotiated=False)
    refuse("single-run-qos-fragment", "unsupported-extension", at_time([f_big(2, True)[0]]), runs=1, negotiated=False)
    refuse("single-run-qos-frame", "unsupported-extension", frames((SN0, 2, True, small(41))), runs=1, negotiated=False)
    return out + refusals


# The handshakes: (case, role, runs, whether the peer offered the extension). The link writes the INIT or the
# INIT_ACK named by the role, with the extension where it offers one.
HANDSHAKES = (
    ("connector-runs-2-peer-accepts", "connector", 2, True),
    ("connector-runs-2-peer-declines", "connector", 2, False),
    ("connector-runs-1", "connector", 1, False),
    ("listener-runs-2-peer-offers", "listener", 2, True),
    ("listener-runs-2-peer-silent", "listener", 2, False),
    ("listener-runs-1-peer-offers", "listener", 1, True),
)
HANDSHAKE_REFUSALS = (("connector-runs-1-peer-answers-with-qos", "unsupported-extension"),)
ZID = bytes.fromhex("112233")


PEER_ZID = bytes.fromhex("445566")


def peer_message(role: str, peer_qos: bool) -> bytes:
    """What the peer sends the link: an INIT_ACK to a connector, an INIT_SYN to a listener."""
    return init_message(PEER_ZID, ack=role == "connector", qos=peer_qos)


def handshake_line(case: str, role: str, runs: int, peer_qos: bool) -> str:
    ours = runs >= 2
    if role == "connector":
        sent = init_message(ZID, ack=False, qos=ours)
    else:
        sent = init_message(ZID, ack=True, qos=ours and peer_qos)
    negotiated = ours and peer_qos
    return f"lanes handshake {case} peer={peer_message(role, peer_qos).hex()} wrote={sent.hex()} negotiated={'yes' if negotiated else 'no'}"


# ------------------------------------------------------------------------------------ the transcript


def fed_line(name: str, index: int, now: int, batch: bytes) -> str:
    return f"lanes fed {name} {index} t={now} len={len(batch)} sha={hashlib.sha256(batch).hexdigest()[:16]}"


def run_scenario(scenario: Scenario) -> list[str]:
    model = Model(scenario.runs, scenario.negotiated)
    lines: list[str] = []
    for index, (now, kind, batch) in enumerate(scenario.events):
        try:
            if kind == "tick":
                lines.append(f"lanes tick {scenario.name} {index} t={now}")
                lines += model.tick(now)
            else:
                lines.append(fed_line(scenario.name, index, now, batch))
                lines += model.feed(batch, now)
        except Refusal as refusal:
            _need(refusal.cls == scenario.refused, f"scenario {scenario.name} was refused as {refusal.cls}, the exam names {scenario.refused}")
            return [*lines, f"lanes refused {scenario.name} {refusal.cls}"]
    _need(scenario.refused is None, f"scenario {scenario.name} was never refused, the exam names {scenario.refused}")
    counts = " ".join(f"{_lane_name(lane)}={model.next_of(lane)}" for lane in sorted(model.touched))
    return [*lines, f"lanes counters {scenario.name} {counts}", f"lanes ok {scenario.name}"]


def good_lines() -> list[str]:
    check_vectors()
    lines = [handshake_line(*case) for case in HANDSHAKES]
    lines += [f"lanes refused {name} {cls} peer={peer_message('connector', True).hex()}" for name, cls in HANDSHAKE_REFUSALS]
    for scenario in scenarios():
        lines += run_scenario(scenario)
    return lines


def judge(lines: list[str]) -> tuple[int, int]:
    """The printed transcript must equal the one built here, line for line. Returns (cases, refusals)."""
    wanted = good_lines()
    for line in lines:
        _need(line.startswith("lanes "), f"lanes: a record that is not a lanes exam line: {line!r}")
        _need(line == line.strip() and "  " not in line, f"lanes: a line with stray spaces: {line!r}")
    missing = [line for line in wanted if line not in lines]
    extra = [line for line in lines if line not in wanted]
    _need(not missing, f"lanes lines missing: {[m[:90] for m in missing[:3]]}")
    _need(not extra, f"lanes lines the exam does not build: {[e[:90] for e in extra[:3]]}")
    _need(len(lines) == len(wanted), f"lanes: {len(lines)} lines, the exam builds {len(wanted)}; a line is repeated")
    _need(lines == wanted, "lanes: the lines are not in the order the exam runs them")
    refusals = sum(1 for line in wanted if line.startswith("lanes refused "))
    cases = sum(1 for line in wanted if line.startswith(("lanes ok ", "lanes handshake ")))
    return cases, refusals


# ------------------------------------------------------------------------------- the limits contract
# `contracts/zenoh-link-limits/v2` adds `maxRuns` to a configuration: the reassembly runs a heap link holds at
# once. A fixed link has none (0). A heap link has 1 to 16, one for each lane that can have a message open. A heap
# link with 1 is the v1 configuration exactly. A link with 2 or more adds the lane counters to its stack, and a
# run to its stack and to its heap for each run beyond the first.

CONFIG_FIELDS_V2 = (*links.CONFIG_FIELDS, "maxRuns")
RUN_OVERHEAD_BYTES = 64
LANE_COUNTER_BYTES = 64
MAX_RUNS = 16


def v2_stack(config: dict) -> int:
    runs = config["maxRuns"]
    extra = (runs - 1) * RUN_OVERHEAD_BYTES + LANE_COUNTER_BYTES if runs > 1 else 0
    return links.required_stack(config) + extra


def v2_heap(config: dict) -> int:
    return (links.NOTICES * config["outstandingSamples"] + max(config["maxRuns"], 1)) * links.message_bytes(config)


def v2_config(base: dict, runs: int, **change: object) -> dict:
    config = dict(base, maxRuns=runs, **change)
    config["stackBytes"] = v2_stack(config)
    if config["mode"] == "heap":
        config["heapBytes"] = v2_heap(config)
    return config


def render_record(configs: list[dict], version: int = 2) -> str:
    rows = "".join(
        "    { " + " ".join(f'{k} = "{v}";' if isinstance(v, str) else f"{k} = {v};" for k, v in c.items()) + " };\n" for c in configs
    )
    return f"{{\n  formatVersion = {version};\n  configs = [\n{rows}  ];\n}}\n"


def contract_cases() -> list[tuple[str, list[dict], int, bool]]:
    demo, large, heap = links.pinned_configs()
    fixed_demo, fixed_large = dict(demo, maxRuns=0), dict(large, maxRuns=0)
    heap1 = dict(heap, maxRuns=1)
    heap2 = v2_config(heap, 2)

    def with_heap(config: dict) -> list[dict]:
        return [fixed_demo, fixed_large, config]

    return [
        ("the three v1 configurations with maxRuns 0, 0 and 1", with_heap(heap1), 2, True),
        ("a heap link with 2 runs, its stack and heap exact", with_heap(heap2), 2, True),
        ("a heap link with 2 runs and one byte too little stack", with_heap(dict(heap2, stackBytes=v2_stack(heap2) - 1)), 2, False),
        ("a heap link with 2 runs and one byte too little heap", with_heap(dict(heap2, heapBytes=v2_heap(heap2) - 1)), 2, False),
        ("a heap link with 2 runs and the heap of 1", with_heap(dict(heap2, heapBytes=v2_heap(heap1))), 2, False),
        ("a heap link with 2 runs and the stack of 1", with_heap(dict(heap2, stackBytes=links.required_stack(heap1))), 2, False),
        ("a heap link with 16 runs, exact", with_heap(v2_config(heap, 16)), 2, True),
        ("a heap link with 2 runs and a batch of 90, the largest INIT_ACK with the extension and its stream length", with_heap(v2_config(heap, 2, batchBytes=90, keyBytes=1)), 2, True),
        ("a heap link with 2 runs and a batch of 89, one byte short of it", with_heap(v2_config(heap, 2, batchBytes=89, keyBytes=1)), 2, False),
        ("a heap link with 1 run and a batch of 89, which writes no extension", with_heap(v2_config(heap, 1, batchBytes=89, keyBytes=1)), 2, True),
        ("a heap link with 16 runs and a batch of 89", with_heap(v2_config(heap, 16, batchBytes=89, keyBytes=1)), 2, False),
        ("a heap link with 16 runs and a batch of 90", with_heap(v2_config(heap, 16, batchBytes=90, keyBytes=1)), 2, True),
        ("a heap link with 17 runs, exact", with_heap(v2_config(heap, 17)), 2, False),
        ("a heap link with 0 runs", with_heap(dict(heap, maxRuns=0)), 2, False),
        ("a heap link with -1 runs", with_heap(dict(heap, maxRuns=-1)), 2, False),
        ("a fixed link with 1 run", [dict(fixed_demo, maxRuns=1), fixed_large, heap1], 2, False),
        ("a fixed link with 2 runs, exact", [fixed_demo, dict(fixed_large, maxRuns=2), heap1], 2, False),
        ("a record without maxRuns", [demo, large, heap], 2, False),
        ("a v1 record", with_heap(heap1), 1, False),
        ("a field the contract does not name", with_heap(dict(heap1, note="x")), 2, False),
        ("a heap link with 2 runs and 1 outstanding sample, exact", with_heap(v2_config(heap, 2, outstandingSamples=1)), 2, True),
        ("a heap link with 2 runs and 1 outstanding sample and one message of heap too little", with_heap(dict(v2_config(heap, 2, outstandingSamples=1), heapBytes=3 * links.message_bytes(heap))), 2, False),
    ]


def contract_decide(configs: list[dict], version: int) -> bool:
    """Whether the v2 contract's own decoder takes the record: the one place this exam runs the contract."""
    import shutil
    import tempfile
    from pathlib import Path

    import zutai_cli

    _need(LIMITS_V2.is_file(), f"{LIMITS_V2.relative_to(ROOT)} is missing: the implementation adds the contract")
    (ROOT / "build").mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="zenoh-lanes-limits-", dir=ROOT / "build"))
    try:
        shutil.copyfile(LIMITS_V2, scratch / "schema.zt")
        (scratch / "decode.zt").write_text(
            's ::= import "schema.zt"; env ::= import stdlib.env; load ::= import stdlib.load; '
            "main :: { env : Env; load : Load; } -> Validation DecodeIssue s.Limits ! { * env.GetEffects; * load.ZtiEffects; } "
            '= caps => [ path := env.get caps.env "SLIME_LIMITS_PATH" ?? ""; s.decodeLimits (load.zti caps.load path) ]; main\n'
        )
        record = scratch / "limits.zti"
        record.write_text(render_record(configs, version))
        return zutai_cli.evaluate("run", scratch / "decode.zt", input_path=record, env_var="SLIME_LIMITS_PATH").startswith("#valid")
    except zutai_cli.ZutaiError as error:
        raise LanesError(f"the limits contract could not decode a record: {error}") from error
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def judge_contract(decide: Callable[[list[dict], int], bool] = contract_decide) -> tuple[int, int]:
    """Returns (records the contract took, records it refused); each must be what the table says."""
    taken = refused = 0
    for label, configs, version, expected in contract_cases():
        got = decide(configs, version)
        _need(got == expected, f"lanes contract: {label} was {'taken' if got else 'refused'}, the exam requires it {'taken' if expected else 'refused'}")
        taken += expected
        refused += not expected
    return taken, refused


# ---------------------------------------------------------------------------------------- the controls


def _decider(*, flip: int | None = None, take: bool | None = None) -> Callable[[list[dict], int], bool]:
    """A stand-in for the contract: the table's own answer, except that it flips row `flip` or answers `take`."""
    answers = {render_record(configs, version): expected for _, configs, version, expected in contract_cases()}
    rows = [render_record(configs, version) for _, configs, version, _ in contract_cases()]

    def decide(configs: list[dict], version: int) -> bool:
        if take is not None:
            return take
        key = render_record(configs, version)
        return (not answers[key]) if flip is not None and key == rows[flip] else answers[key]

    return decide


def contract_controls() -> int:
    """A judge that sees the contract answer wrongly on any one row, or on every row, must refuse."""
    refused = 0
    table = contract_cases()
    _need(len({render_record(configs, version) for _, configs, version, _ in table}) == len(table), "the contract table holds two rows that are the same record")
    _need(judge_contract(_decider()) == (sum(1 for row in table if row[3]), sum(1 for row in table if not row[3])), "the table's own answers are not the table")
    stand_ins = [("a contract that takes every record", _decider(take=True)), ("a contract that refuses every record", _decider(take=False))]
    stand_ins += [(f"a contract that answers the opposite on: {label}", _decider(flip=index)) for index, (label, _, _, _) in enumerate(table)]
    for label, decide in stand_ins:
        try:
            judge_contract(decide)
        except LanesError:
            refused += 1
            continue
        raise LanesError(f"control: the contract judge accepted {label}")
    return refused


def reference_controls() -> int:
    def flipped(table: tuple, row: int, index: int) -> tuple:
        changed = list(table[row])
        changed[index] = changed[index][:-1] + ("0" if changed[index][-1] != "0" else "1")
        return (*table[:row], tuple(changed), *table[row + 1 :])

    cases: list[tuple[str, dict]] = [
        ("an upstream FRAME header changed", {"vectors": (UPSTREAM_INIT, flipped(UPSTREAM_FRAMES, 0, 3), UPSTREAM_FRAGMENTS)}),
        ("an upstream FRAME header of best-effort changed", {"vectors": (UPSTREAM_INIT, flipped(UPSTREAM_FRAMES, 12, 3), UPSTREAM_FRAGMENTS)}),
        ("an upstream FRAGMENT header changed", {"vectors": (UPSTREAM_INIT, UPSTREAM_FRAMES, flipped(UPSTREAM_FRAGMENTS, 0, 4))}),
        ("an upstream FRAGMENT header of best-effort changed", {"vectors": (UPSTREAM_INIT, UPSTREAM_FRAMES, flipped(UPSTREAM_FRAGMENTS, 16, 4))}),
        ("an upstream INIT_ACK changed", {"vectors": ({**UPSTREAM_INIT, "ack-qos": UPSTREAM_INIT["ack-qos"][:-2] + "00"}, UPSTREAM_FRAMES, UPSTREAM_FRAGMENTS)}),
        ("a frame writer that always writes the extension", {"frames": lambda reliable, priority, sn: frame_header(reliable, priority, sn, qos_ext(priority))}),
        ("a fragment writer that drops the extension", {"fragments": lambda reliable, priority, more, sn: fragment_header(reliable, priority, more, sn, b"")}),
        ("an INIT writer that never offers the extension", {"init": lambda zid, ack, qos: init_message(zid, ack=ack, qos=False)}),
    ]
    refused = 0
    check_vectors()
    for label, changes in cases:
        try:
            check_vectors(**changes)
        except LanesError:
            refused += 1
            continue
        raise LanesError(f"control: the reference check accepted {label}")
    return refused


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    kinds: dict[str, list[int]] = {}
    for index, line in enumerate(good):
        kinds.setdefault(line.split(" ")[1], []).append(index)
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a lanes exam line", [*good, "data ok peer-publishes-to-a-slime-subscriber"]),
        ("a line repeated", [*good, good[0]]),
        ("a line with a doubled space", [good[0].replace(" ", "  ", 1), *good[1:]]),
        ("a line with trailing space", [good[0] + " ", *good[1:]]),
        ("the first two lines swapped", swapped(0, 1)),
        ("the first and last lines swapped", swapped(0, len(good) - 1)),
        ("two samples swapped", swapped(kinds["sample"][0], kinds["sample"][1])),
        ("two handshakes swapped", swapped(kinds["handshake"][0], kinds["handshake"][1])),
        ("a drop moved ahead of its scenario", swapped(kinds["drop"][0], kinds["ok"][0])),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index} missing ({line[:44]})", [*good[:index], *good[index + 1 :]]))
    for kind in ("handshake", "fed", "sample", "drop", "tick", "counters", "refused"):
        for index in kinds[kind]:
            fields = good[index].split(" ")
            last = fields[-1]
            changed = last[:-1] + ("0" if last[-1] != "0" else "1")
            out.append((f"{kind} line {index} with a changed last field", [*good[:index], " ".join([*fields[:-1], changed]), *good[index + 1 :]]))
    for index in kinds["refused"]:
        fields = good[index].split(" ")
        other = "lane-limit" if fields[-1] != "lane-limit" else "sequence-mismatch"
        out.append((f"refusal {fields[2]} reported as {other}", [*good[:index], " ".join([*fields[:-1], other]), *good[index + 1 :]]))
    for index in kinds["drop"]:
        fields = good[index].split(" ")
        out.append((f"drop line {index} counted as a sample", [*good[:index], f"lanes sample {fields[2]} B sn=0 payload=0 seq=0", *good[index + 1 :]]))
    out.append(("a sample delivered after the last scenario", [*good, good[kinds["sample"][0]]]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (PINNED_TRANSCRIPT_CASES, PINNED_REFUSALS), f"lanes: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise LanesError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except LanesError:
            refused += 1
            continue
        raise LanesError(f"control: the lanes judge accepted {label}")
    return refused


def all_controls() -> int:
    return transcript_controls() + reference_controls() + contract_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_TRANSCRIPT_CASES = 23
PINNED_REFUSALS = 20
PINNED_CONTRACT = 22
PINNED_CASES = PINNED_TRANSCRIPT_CASES + PINNED_REFUSALS + PINNED_CONTRACT
PINNED_CONTROLS = 473


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
