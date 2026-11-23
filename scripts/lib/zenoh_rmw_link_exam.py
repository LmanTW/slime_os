"""Judge the rmw_zenoh graph link exam from what the Rust tests print.

`zenoh_rmw_exam` and `zenoh_rmw_graph_exam` judge a graph session and its graph on batches handed to them one
at a time. This exam judges the runtime around them: a graph link, one graph session over a byte stream that
reads length-prefixed batches in whatever chunks the stream gives, writes its own batches in whatever chunks the
stream takes, feeds the tokens it receives into a bounded graph, and ends itself when the stream or the session
refuses something.

The Rust tests under `zenoh_rmw_link::` replay the three captured sessions of `zenoh_rmw_peer` through a scripted
byte stream, in three ways: each batch written whole, every byte read alone, and every batch written at once. They
print one `[zenoh-exam] link ...` line for each thing they did. This module builds the whole transcript from the
captured bytes, `zenoh_rmw_graph` and `zenoh_wire`, and the Rust must print it, line for line:

* the bytes the listener wrote, which are exactly an INIT_ACK and an OPEN_ACK, and for a peer's CLOSE nothing more;
* the live entities of the graph before the peer's CLOSE, and none after it;
* three scenarios that stress the stream, one pumped on the schedule the lease sets, two that count a token the graph refuses and keep the link open, and six
  that end the link or refuse a call, each with the class it ends as and the bytes it wrote.

The listener is configured with `ZID`, `COOKIE`, a 30 s lease and initial sequence number 7, so the bytes it writes
are known to the byte. Like the other judges, this one is trusted only after it refuses a mutation of an honest
transcript.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import zenoh_rmw_exam as session_exam
import zenoh_rmw_graph_exam as graph_exam
import zenoh_rmw_wire as wire
import zenoh_wire
from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-link.zt"

GROUPS = graph_exam.GROUPS
MODES = ("whole", "bytewise", "coalesced")

ZID = bytes.fromhex("5110aa0bb0cc0dd0ee0ff00112233445")
COOKIE = b"slime-rmw-capture-cookie-01"
LEASE_MS = 30_000
INITIAL_SN = 7
ANNOUNCED_BATCH = 512
CLOSE_EXPIRED = 5
KEEP_ALIVE = b"\x04"
# A graph link of capacity 2 refuses the third entity of the talker's session.
SMALL_GRAPH = 2
# The clock the lease scenarios run at, in ms after the handshake finished at 0. Our listener announced
# `LEASE_MS`, so a keep-alive is due at a quarter of it; the peer announced `PEER_LEASE_MS` in its OPEN_SYN, and
# the link closes when it has heard nothing for longer than that. Each probe is a pump at that time, and the
# transcript says how many bytes the link wrote at it.
KEEP_ALIVE_AT = LEASE_MS // 4
PEER_LEASE_MS = 60_000

SCENARIOS = (
    "partial-writes-complete-the-handshake",
    "keep-alive-after-a-quarter-lease",
    "lease-expiry-closes-the-link",
)
# A token the graph refuses, or has no room for, is counted and dropped, and the link stays open: rmw_zenoh logs
# and ignores such a token, and one unreadable token must not end a session that may carry data.
COUNTED = ("token-of-an-unknown-entity", "graph-over-capacity")
REFUSALS = (
    ("send-stall", "retry-limit"),
    ("oversized-length-prefix", "length-exceeds-batch"),
    ("zero-length-prefix", "empty-batch"),
    ("stale-handle", "stale-handle"),
    ("send-after-close", "send-after-close"),
    ("end-of-stream-before-the-handshake", "link-closed"),
)


class LinkExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise LinkExamError(message)


# ------------------------------------------------------------------------------------- the bytes it writes


def framed(batch: bytes) -> bytes:
    return zenoh_wire.stream(batch)


def peer_cookie(group: str) -> bytes:
    return wire.open_syn_cookie(session_exam.captured(f"{group}-02-open-syn"))


def init_ack(cookie: bytes = COOKIE, batch: int = ANNOUNCED_BATCH) -> bytes:
    return zenoh_wire.init(ZID, batch=batch, cookie=cookie)


def open_ack(lease_ms: int = LEASE_MS, initial_sn: int = INITIAL_SN) -> bytes:
    return zenoh_wire.open_(lease_ms, initial_sn, ack=True)


def handshake_bytes() -> bytes:
    """What a listener writes to finish a handshake with any of the three peers."""
    return framed(init_ack()) + framed(open_ack())


def close_bytes(reason: int) -> bytes:
    return framed(zenoh_wire.close(reason, True))


def split_stream(data: bytes) -> list[bytes]:
    """The batches of a length-prefixed stream. A stream that does not end on a batch is refused."""
    out, at = [], 0
    while at < len(data):
        _need(at + 2 <= len(data), "a stream that ends inside a length prefix")
        length = int.from_bytes(data[at : at + 2], "little")
        _need(length > 0 and at + 2 + length <= len(data), "a stream that ends inside a batch")
        out.append(data[at + 2 : at + 2 + length])
        at += 2 + length
    return out


def check_outbound(group: str, data: bytes, tail: bytes) -> None:
    """The listener wrote a handshake the peer can take, then exactly `tail`. The INIT_ACK is read with the host
    reference: it announces 512 bytes, carries no extension and offers the cookie the peer echoed."""
    batches = split_stream(data)
    _need(len(batches) >= 2, "the listener wrote fewer than an INIT_ACK and an OPEN_ACK")
    ack = wire.init_ack(batches[0])
    _need(ack.batch == ANNOUNCED_BATCH, f"the INIT_ACK announces {ack.batch}, the item fixes {ANNOUNCED_BATCH}")
    _need(not ack.extensions, "the INIT_ACK carries an extension")
    _need(ack.cookie == peer_cookie(group), "the INIT_ACK offers a cookie the peer did not echo")
    _need(batches[1] == open_ack(), f"the OPEN_ACK is {batches[1].hex()}, the item fixes {open_ack().hex()}")
    _need(data == handshake_bytes() + tail, "the listener wrote bytes beyond the handshake and the pinned tail")


# ------------------------------------------------------------------------------------------ the transcript


def hexed(data: bytes) -> str:
    return data.hex() if data else "-"


def session_batches(group: str) -> list[bytes]:
    return [bytes.fromhex(h) for _n, h in dict(session_exam.GROUPS)[group]]


def unknown_entity_frame() -> bytes:
    """One frame of three tokens: a node `a`, a token of the unknown kind `XX`, and a node `c`, written by the
    host reference with the sequence number the talker's first frame carries. Each token names its alias in the
    sender's mapping, as all 29 captured tokens do. The link must count the middle
    one and still take the third, which is how the exam shows the link stayed open and useful."""
    zid = "77bf039722c084d5ddae7b5ba3647a11"
    messages: list[bytes] = []
    for number, (kind, node) in enumerate((("NN", "a"), ("XX", "b"), ("NN", "c"))):
        alias, ident = 90 + number, 91 + 2 * number
        key = f"@ros2_lv/0/{zid}/0/{60 + number}/{kind}/%/%/{node}"
        messages.append(wire.encode(wire.Message("keyexpr", alias, 0, key, qos=8)))
        messages.append(wire.encode(wire.Message("token", ident, alias, None, sender=True, qos=8)))
    sn = wire.frame(session_exam.captured("talker-03-frame"))[0]
    return bytes([wire.ID_FRAME | wire.FLAG_N]) + wire.leb128(sn) + b"".join(messages)


def counted(name: str) -> int:
    """How many tokens the graph refuses in the scenario, counted by the host reference."""
    refused = 0
    if name == "token-of-an-unknown-entity":
        state = graph_exam.graph.Graph(graph_exam.DOMAIN, graph_exam.CAPACITY)
        table: dict[int, str] = {}
        for message, full in wire.resolve(wire.frame(unknown_entity_frame())[1], table):
            if message.kind == "token" and full is not None:
                try:
                    state.declare(full)
                except graph_exam.graph.GraphError:
                    refused += 1
        return refused
    _need(name == "graph-over-capacity", f"no counted scenario named {name}")
    state = graph_exam.graph.Graph(graph_exam.DOMAIN, SMALL_GRAPH)
    for action, key in graph_exam.session_tokens("talker"):
        if action == "declare":
            try:
                state.declare(key)
            except graph_exam.graph.GraphError:
                refused += 1
    return refused


def keep_alive_probes() -> list[tuple[int, bytes]]:
    """(time, bytes written at it) for a link that has sent nothing since the handshake. Before a quarter of
    the lease it writes nothing, at the quarter it writes one KEEP_ALIVE, and right after, nothing more."""
    return [(KEEP_ALIVE_AT - 1, b""), (KEEP_ALIVE_AT, framed(KEEP_ALIVE)), (KEEP_ALIVE_AT + 1, b"")]


def expiry_ticks() -> list[int]:
    """When the scenario pumps a link that hears nothing after the handshake: every quarter of the lease the
    link announced, which is when it owes a KEEP_ALIVE, through the lease the peer announced. The peer is silent,
    so each pump writes one KEEP_ALIVE and the link must not close."""
    return list(range(KEEP_ALIVE_AT, PEER_LEASE_MS + 1, KEEP_ALIVE_AT))


def expiry_probes() -> list[tuple[int, bytes]]:
    """(time, bytes written at it) for that scenario. The link writes a KEEP_ALIVE at each tick, the last at the
    peer's lease, and does not close until one millisecond past it, when it writes a CLOSE of reason 5. The
    KEEP_ALIVEs are in the `sent` line too, because the stream is the whole of what the link wrote."""
    probes = [(at, framed(KEEP_ALIVE)) for at in expiry_ticks()]
    probes.append((PEER_LEASE_MS + 1, close_bytes(CLOSE_EXPIRED)))
    return probes


def expiry_stream() -> bytes:
    """The whole stream of the expiry scenario: the handshake, a KEEP_ALIVE at each tick, then the CLOSE."""
    return handshake_bytes() + framed(KEEP_ALIVE) * len(expiry_ticks()) + close_bytes(CLOSE_EXPIRED)


ENTITIES_AFTER_END = 0


def surviving(name: str) -> int:
    """How many entities the graph still holds after the scenario, counted by the host reference: the other
    tokens of the frame land, and a graph of capacity 2 holds exactly 2."""
    if name == "token-of-an-unknown-entity":
        state = graph_exam.graph.Graph(graph_exam.DOMAIN, graph_exam.CAPACITY)
        table: dict[int, str] = {}
        for message, full in wire.resolve(wire.frame(unknown_entity_frame())[1], table):
            if message.kind == "token" and full is not None:
                try:
                    state.declare(full)
                except graph_exam.graph.GraphError:
                    pass
        return len(state.live)
    _need(name == "graph-over-capacity", f"no counted scenario named {name}")
    return SMALL_GRAPH


def final_close(group: str) -> int:
    last = session_batches(group)[-1]
    _need(last[0] & 0x1F == wire.ID_CLOSE and len(last) == 2, f"{group} does not end in a CLOSE")
    return last[1]


def entity_lines(group: str) -> list[str]:
    """The entities the peer's tokens leave while its session is open, in the order the graph exam prints them."""
    return [entity.line() for entity in graph_exam.replay_group(group).entities()]


def ignored(group: str) -> int:
    return graph_exam.replay_group(group).ignored


def good_lines() -> list[str]:
    lines: list[str] = []
    for group in GROUPS:
        for mode in MODES:
            lines.append(f"link sent {group} {mode} {hexed(handshake_bytes())}")
            lines += [f"link entity {group} {mode} {line}" for line in entity_lines(group)]
            lines.append(f"link ignored {group} {mode} {ignored(group)}")
            lines.append(f"link closed {group} {mode} reason={final_close(group)} entities=0")
            lines.append(f"link ok {group}-{mode}")
    lines.append(f"link sent partial-writes {hexed(handshake_bytes())}")
    lines.append(f"link ok {SCENARIOS[0]}")
    for at, wrote in keep_alive_probes():
        lines.append(f"link probe keep-alive t={at} wrote={hexed(wrote)}")
    lines.append(f"link sent keep-alive {hexed(handshake_bytes() + framed(KEEP_ALIVE))}")
    lines.append(f"link ok {SCENARIOS[1]}")
    for at, wrote in expiry_probes():
        lines.append(f"link probe lease-expiry t={at} wrote={hexed(wrote)}")
    lines.append(f"link sent lease-expiry {hexed(expiry_stream())}")
    lines.append(f"link entities lease-expiry {ENTITIES_AFTER_END}")
    lines.append(f"link ok {SCENARIOS[2]}")
    for name in COUNTED:
        lines.append(f"link counted {name} {counted(name)} open={OPEN_AFTER_COUNTED} entities={surviving(name)}")
    for name, cls in REFUSALS:
        lines.append(f"link refused {name} {cls} {hexed(refusal_tail(name))}")
        if name in ENDS_THE_LINK:
            lines.append(f"link entities {name} {ENTITIES_AFTER_END}")
    lines.append(f"link close local {hexed(handshake_bytes() + close_bytes(0))}")
    lines.append(f"link entities local-close {ENTITIES_AFTER_END}")
    return lines


OPEN_AFTER_COUNTED = "true"
# The refusals that end the link; the others are refused calls and leave it as it was.
ENDS_THE_LINK = ("oversized-length-prefix", "zero-length-prefix")


def refusal_tail(name: str) -> bytes:
    """What the listener wrote when the scenario ended: the handshake, then a CLOSE of reason 0 once the link ended
    itself, nothing when it could not write, and nothing but the handshake when it did not end."""
    ends = ("oversized-length-prefix", "zero-length-prefix")
    if name in ends:
        return handshake_bytes() + close_bytes(0)
    if name == "send-after-close":
        return handshake_bytes() + close_bytes(0)
    if name == "stale-handle":
        return handshake_bytes()
    return b""


def judge(lines: list[str]) -> tuple[int, int]:
    """The printed transcript must equal the one built here, line for line. Returns (cases, refusals)."""
    wanted = good_lines()
    for line in lines:
        _need(line.startswith("link "), f"link: a record that is not a link exam line: {line!r}")
        _need(line == line.strip() and "  " not in line, f"link: a line with stray spaces: {line!r}")
    missing = [line for line in wanted if line not in lines]
    extra = [line for line in lines if line not in wanted]
    _need(not missing, f"link lines missing: {[m[:90] for m in missing[:3]]}")
    _need(not extra, f"link lines the exam does not build: {[e[:90] for e in extra[:3]]}")
    _need(len(lines) == len(wanted), f"link: {len(lines)} lines, the exam builds {len(wanted)}; a line is repeated")
    _need(lines == wanted, "link: the lines are not in the order the exam runs them")
    refusals = sum(1 for line in wanted if line.startswith("link refused "))
    return len(wanted) - refusals, refusals


def counted_agrees(unknown: int | None = None, full: int | None = None, survive: int | None = None) -> None:
    """The two counted scenarios are about what they say: one bad token, and the tokens a capacity of 2 cannot hold."""
    unknown = counted("token-of-an-unknown-entity") if unknown is None else unknown
    full = counted("graph-over-capacity") if full is None else full
    _need(unknown == 1, f"the unknown-entity scenario counts {unknown} refused tokens, it is about exactly one")
    survive = surviving("token-of-an-unknown-entity") if survive is None else survive
    _need(survive == 2, f"the unknown-entity scenario leaves {survive} entities, the frame's two good tokens land")

    declared = sum(1 for action, _key in graph_exam.session_tokens("talker") if action == "declare")
    in_space = sum(1 for action, key in graph_exam.session_tokens("talker") if action == "declare" and key.startswith("@ros2_lv/"))
    _need(full == in_space - SMALL_GRAPH, f"the full-graph scenario counts {full} refused tokens, a capacity of {SMALL_GRAPH} over {in_space} tokens refuses {in_space - SMALL_GRAPH}")
    _need(in_space < declared, "the talker declares no token outside the admin space, so the scenario would not show the link ignoring it")
    _need(in_space == 11, f"the talker declares {in_space} tokens in the admin space, the item says 11")


def outbound_agrees(
    handshake: Callable[[], bytes] = handshake_bytes,
    closer: Callable[[int], bytes] = close_bytes,
    announced: int = ANNOUNCED_BATCH,
) -> None:
    """Every outbound the exam expects is a stream the host reference reads as it describes it."""
    _need(announced == ANNOUNCED_BATCH, f"the exam announces {announced}, the item fixes {ANNOUNCED_BATCH}")
    for group in GROUPS:
        for tail in (b"", framed(KEEP_ALIVE), framed(KEEP_ALIVE) * len(expiry_ticks()) + closer(CLOSE_EXPIRED), closer(0)):
            data = handshake() + tail
            if handshake is handshake_bytes and closer is close_bytes:
                check_outbound(group, data, tail)
            batches = split_stream(data)
            _need(len(batches) == 2 + len(split_stream(tail)), f"{group}: an expected stream of {len(batches)} batches")
            _need(wire.init_ack(batches[0]).batch == ANNOUNCED_BATCH, f"{group}: the expected INIT_ACK announces another batch")
            _need(wire.init_ack(batches[0]).cookie == peer_cookie(group), f"{group}: the expected cookie is not the peer's")
            _need(batches[1][0] & 0x1F == wire.ID_OPEN and batches[1][0] & 0x20 != 0, f"{group}: the expected OPEN_ACK is not an OPEN_ACK")
    for name, _cls in REFUSALS:
        tail = refusal_tail(name)
        _need(tail == b"" or tail.startswith(handshake()), f"{name}: the expected outbound does not start with the handshake")
        _need(tail == b"" or len(split_stream(tail)) in (2, 3), f"{name}: the expected outbound is not a handshake and at most one batch")


def reference_controls() -> int:
    outbound_agrees()
    counted_agrees()
    cases: list[tuple[str, dict, str]] = [
        ("a handshake whose cookie is not the peer's", {"handshake": lambda: framed(init_ack(cookie=b"another-cookie")) + framed(open_ack())}, "cookie is not the peer's"),
        ("a handshake that announces 65535", {"handshake": lambda: framed(init_ack(batch=65535)) + framed(open_ack())}, "announces another batch"),
        ("an OPEN_SYN where the OPEN_ACK belongs", {"handshake": lambda: framed(init_ack()) + framed(zenoh_wire.open_(LEASE_MS, INITIAL_SN, cookie=COOKIE))}, "is not an OPEN_ACK"),
        ("a stream that ends inside a batch", {"handshake": lambda: handshake_bytes()[:-1]}, "ends inside a batch"),
        ("a close that is not a batch", {"closer": lambda _reason: b"\x01"}, "ends inside a length prefix"),
    ]
    counted_cases: list[tuple[str, dict, str]] = [
        ("an unknown-entity scenario that counts two tokens", {"unknown": 2}, "it is about exactly one"),
        ("an unknown-entity scenario that counts none", {"unknown": 0}, "it is about exactly one"),
        ("a full-graph scenario that counts one token", {"full": 1}, "a capacity of 2"),
        ("a full-graph scenario that counts all of them", {"full": 11}, "a capacity of 2"),
        ("an unknown-entity scenario that leaves one entity", {"survive": 1}, "the frame's two good tokens land"),
        ("an unknown-entity scenario that leaves none", {"survive": 0}, "the frame's two good tokens land"),
    ]
    refused = 0
    for label, changes, reason in counted_cases:
        try:
            counted_agrees(**changes)
        except LinkExamError as error:
            _need(reason in str(error), f"control: {label} was refused for another reason: {error}")
            refused += 1
            continue
        raise LinkExamError(f"control: the counted check accepted {label}")
    for label, changes, reason in cases:
        try:
            outbound_agrees(**changes)
        except (LinkExamError, wire.RmwWireError) as error:
            _need(reason in str(error), f"control: {label} was refused for another reason: {error}")
            refused += 1
            continue
        raise LinkExamError(f"control: the outbound check accepted {label}")
    return refused


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    kinds = {k: [i for i, line in enumerate(good) if line.startswith(f"link {k} ")] for k in ("sent", "entity", "ignored", "closed", "ok", "refused", "counted")}
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a link exam line", [*good, "graph ok talker-graph"]),
        ("a line repeated", [*good, good[0]]),
        ("a line with a doubled space", [good[0].replace(" ", "  ", 1), *good[1:]]),
        ("a line with trailing space", [good[0] + " ", *good[1:]]),
        ("the first two lines swapped", swapped(0, 1)),
        ("the first and last lines swapped", swapped(0, len(good) - 1)),
        ("the first two modes of a group swapped", swapped(kinds["ok"][0], kinds["ok"][1])),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index} missing ({line[:44]})", [*good[:index], *good[index + 1 :]]))
    for kind in ("sent", "entity", "ignored", "closed", "refused", "counted"):
        for index in kinds[kind][:12]:
            fields = good[index].split(" ")
            last = fields[-1]
            changed = last[:-1] + ("0" if last[-1] != "0" else "1") if last != "-" else "00"
            out.append((f"{kind} line {index} with a changed last field", [*good[:index], " ".join([*fields[:-1], changed]), *good[index + 1 :]]))
    # a listener that wrote one byte more, or one less, than a handshake
    first_sent = kinds["sent"][0]
    sent = good[first_sent].split(" ")
    out.append(("a listener that wrote a byte after the handshake", [*good[:first_sent], f"{good[first_sent]}00", *good[first_sent + 1 :]]))
    out.append(("a listener that wrote the handshake cut short", [*good[:first_sent], good[first_sent][:-2], *good[first_sent + 1 :]]))
    out.append(("a listener that wrote nothing", [*good[:first_sent], " ".join([*sent[:-1], "-"]), *good[first_sent + 1 :]]))
    classes = sorted({line.split(" ")[3] for line in good if line.startswith("link refused ")})
    for cls in classes:
        index = next(i for i in kinds["refused"] if good[i].split(" ")[3] == cls)
        other = next(c for c in classes if c != cls)
        out.append((f"the {good[index].split(' ')[2]} refusal reported as {other}", [*good[:index], good[index].replace(f" {cls} ", f" {other} ", 1), *good[index + 1 :]]))
    out.append(("the first two refusals swapped", swapped(kinds["refused"][0], kinds["refused"][1])))
    out.append(("a link that ended on a refused token", [line.replace("open=true", "open=false", 1) if line.startswith("link counted token-of-an-unknown-entity") else line for line in good]))
    out.append(("a link that ended on a full graph", [line.replace("open=true", "open=false", 1) if line.startswith("link counted graph-over-capacity") else line for line in good]))
    out.append(("a link that kept no entity after a counted token", [line.replace("entities=2", "entities=0", 1) if line.startswith("link counted token-of-an-unknown-entity") else line for line in good]))
    out.append(("a link that dropped the session after a counted token", [line.replace("entities=2", "entities=1", 1) if line.startswith("link counted token-of-an-unknown-entity") else line for line in good]))
    out.append(("a full graph that held three entities", [line.replace("entities=2", "entities=3", 1) if line.startswith("link counted graph-over-capacity") else line for line in good]))
    out.append(("a keep-alive one millisecond early", [line.replace("t=7500 wrote=010004", "t=7499 wrote=010004", 1) for line in good]))
    out.append(("a keep-alive missing at the quarter", [line.replace("t=7500 wrote=010004", "t=7500 wrote=-", 1) for line in good]))
    out.append(("a second keep-alive right after the first", [line.replace("t=7501 wrote=-", "t=7501 wrote=010004", 1) for line in good]))
    out.append(("a keep-alive written before the quarter", [line.replace("t=7499 wrote=-", "t=7499 wrote=010004", 1) for line in good]))
    out.append(("a link that closed at the lease and not past it", [line.replace("t=60000 wrote=010004", "t=60000 wrote=02002305", 1) for line in good]))
    out.append(("a link that never closed past the lease", [line.replace("t=60001 wrote=02002305", "t=60001 wrote=-", 1) for line in good]))
    out.append(("a link that skipped a keep-alive on the way", [line.replace("t=30000 wrote=010004", "t=30000 wrote=-", 1) for line in good]))
    out.append(("a link that wrote a keep-alive early on the way", [line.replace("t=30000 wrote=010004", "t=29999 wrote=010004", 1) for line in good]))
    out.append(("a link that wrote two keep-alives at one tick", [line.replace("t=45000 wrote=010004", "t=45000 wrote=010004010004", 1) for line in good]))
    out.append(("a link that closed with another reason", [line.replace("wrote=02002305", "wrote=02002300", 1) for line in good]))
    out.append(("a link that kept its graph after lease expiry", [line.replace("link entities lease-expiry 0", "link entities lease-expiry 11", 1) for line in good]))
    out.append(("a link that kept its graph after a stream fault", [line.replace("link entities oversized-length-prefix 0", "link entities oversized-length-prefix 4", 1) for line in good]))
    out.append(("a link that kept its graph after a zero prefix", [line.replace("link entities zero-length-prefix 0", "link entities zero-length-prefix 4", 1) for line in good]))
    out.append(("a local close that wrote another reason", [line.replace(close_bytes(0).hex(), close_bytes(7).hex(), 1) if line.startswith("link close local") else line for line in good]))
    out.append(("a local close that wrote nothing after the handshake", [line.replace(close_bytes(0).hex(), "", 1) if line.startswith("link close local") else line for line in good]))
    out.append(("a link that kept its graph after a local close", [line.replace("link entities local-close 0", "link entities local-close 11", 1) for line in good]))
    out.append(("a refused token not counted", [line.replace(f" {counted('token-of-an-unknown-entity')} open=", " 0 open=", 1) if line.startswith("link counted token-of-an-unknown-entity") else line for line in good]))
    out.append(("a full graph that counted one token", [line.replace(f" {counted('graph-over-capacity')} open=", " 1 open=", 1) if line.startswith("link counted graph-over-capacity") else line for line in good]))
    out.append(("a graph that kept its entities after the peer's CLOSE", [line.replace("entities=0", "entities=11", 1) if line.startswith("link closed talker whole") else line for line in good]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (PINNED_CASES - PINNED_REFUSALS, PINNED_REFUSALS), f"link: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise LinkExamError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except LinkExamError:
            refused += 1
            continue
        raise LinkExamError(f"control: the link judge accepted {label}")
    return refused


def all_controls() -> int:
    return transcript_controls() + reference_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 133
PINNED_REFUSALS = 6
PINNED_CONTROLS = 236


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
