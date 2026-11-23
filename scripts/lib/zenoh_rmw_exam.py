"""Judge the Zenoh Profile 0 exam for an rmw_zenoh peer's session, from what the Rust tests print.

An rmw_zenoh 0.6.10 peer (zenoh 1.10.1) connects to a Profile 0 listener and declares, before it
publishes anything, what the ROS 2 graph needs: key-expression aliases, queryables, one subscriber on its
own admin space, and one liveliness token for each node, publisher, subscriber and service. Profile 0
refused every one of those. `zenoh_rmw_peer` holds three whole sessions of that peer, captured once.

The Rust tests under `zenoh_rmw::` print one `[zenoh-exam] rmw ...` line for each thing they did. This
module owns what those lines must be, and nothing here reads the Rust:

* every batch the peer sent, replayed in order into a listener session configured for the graph;
* a count of each kind of message the session saw, equal to the count `zenoh_rmw_wire` reads from the
  bytes, so the session is not graded against itself;
* the decoder's properties on each captured batch;
* the variants the session must keep refusing, each with the class it is refused as, and the three the
  default configuration must refuse because the graph is opt-in.

`zenoh_rmw_wire.rebuild` writes every captured frame again from what it read, and the result must equal
the capture. Like the other judges, this one is trusted only after it refuses a mutation of an honest
transcript.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

import zenoh_rmw_peer
import zenoh_rmw_wire as wire
import zenoh_wire
import zutai_cli
from harness import ROOT

SCHEMA = ROOT / "contracts" / "zenoh-rmw-session" / "v1" / "schema.zt"
ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-session.zt"

GROUPS = (
    ("talker", zenoh_rmw_peer.TALKER),
    ("listener", zenoh_rmw_peer.LISTENER),
    ("lists", zenoh_rmw_peer.LISTS),
)
GROUP_SIZES = {name: len(rows) for name, rows in GROUPS}
BATCH_NAMES = tuple(name for _group, rows in GROUPS for name, _hex in rows)

OK_SCENARIOS = (
    "talker-session-opens-and-closes",
    "listener-session-holds-its-subscription",
    "lists-session-withdraws-what-it-declared",
    "graph-key-of-253-bytes-is-taken",
)

# The digest of every captured batch, name and bytes, in capture order. A round trip through the host
# reference cannot catch an edited capture, because `rebuild` writes back whatever it read, so the bytes
# are pinned here and the implementation cannot widen the exam by editing `zenoh_rmw_peer`.
CAPTURE_SHA256 = "70f17bb7bc85f061531b9bccb5faa736fa27f04313d28caeac7947ec9d7bd669"


def capture_digest(groups: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]) -> str:
    text = "\n".join(f"{name}:{hexed}" for _group, rows in groups for name, hexed in rows)
    return hashlib.sha256(text.encode()).hexdigest()


# The longest key the peer declared in any capture, an alias for a liveliness token. A graph
# configuration must bound keys at or above it; Profile 0's own bound is 129.
LONGEST_KEY_BYTES = 253

# What our listener sends. The Rust test prints the INIT_ACK it sent as hex, and the judge reads it with
# the host reference: it must announce `ANNOUNCED_BATCH`, carry no extension and offer a cookie the peer's
# OPEN_SYN echoes. The test also prints how many bytes the listener sent after the OPEN_ACK. The item says
# the session sends no reply, so that count is 0.
OUTBOUND_GROUPS = tuple(name for name, _rows in GROUPS)

# The batch our INIT_ACK announced. The peer announced 65480 and sent nothing over this.
ANNOUNCED_BATCH = 512
PEER_INIT_BATCH = 65480
PEER_INIT_EXTENSIONS = ((1, False, 0), (7, False, 1))


class RmwError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RmwError(message)


def captured(name: str) -> bytes:
    for _group, rows in GROUPS:
        for candidate, hexed in rows:
            if candidate == name:
                return bytes.fromhex(hexed)
    raise RmwError(f"the peer sent no batch named {name}")


def group_batches(group: str) -> list[bytes]:
    return [bytes.fromhex(hexed) for _name, hexed in dict(GROUPS)[group]]


def expected_counts() -> dict[str, dict[str, int]]:
    """What the peer declared, read from the bytes by the host reference."""
    return {group: wire.summarize(group_batches(group)) for group, _rows in GROUPS}


def _frame_of(name: str) -> tuple[int, list[wire.Message]]:
    return wire.frame(captured(name))


def _first(group: str, kind: str) -> tuple[str, wire.Message]:
    """The first message of `kind` the group's peer sent, with the name of the batch that carried it."""
    for name, hexed in dict(GROUPS)[group]:
        batch = bytes.fromhex(hexed)
        if batch[0] & 0x1F != wire.ID_FRAME:
            continue
        for message in wire.frame(batch)[1]:
            if message.kind == kind:
                return name, message
    raise RmwError(f"{group} sent no {kind}")


def _unsubscribed_push() -> bytes:
    """A Put on a key no session subscribed to, written by `zenoh_wire`: the form a default session takes
    to its subscriber check. The 114-byte key is inside Profile 0's 129-byte bound. It carries no timestamp
    and one extension, the attachment, because the decoder refuses a Put with a timestamp or any other
    extension before the session sees the key, and every push the three captured sessions hold carries a
    timestamp, so none of them can reach that check in a default session."""
    attachment = zenoh_wire.attachment(1, 0, bytes(range(0xE0, 0xF0)))
    key = "0/other_topic/std_msgs::msg::dds_::String_/RIHS01_" + "a" * 64
    return zenoh_wire.push_put(key, attachment, b"x" * 12, False)


def _frame(sn: int, *messages: bytes) -> bytes:
    return bytes([wire.ID_FRAME | wire.FLAG_N]) + wire.leb128(sn) + b"".join(messages)


def _declare(kind: str, ident: int, *, scope: int = 0, suffix: str | None = None, qos: int = 8, interest: int | None = None) -> bytes:
    return wire.encode(wire.Message(kind, ident, scope, suffix, qos=qos, interest=interest))


def _refusals() -> tuple[tuple[str, str, str, str], ...]:
    """(name, batch hex, class, configuration): a variant of what the peer sent, and the class it is refused as.

    Each variant goes to a session that finished the handshake and has taken no frame, so every FRAME
    carries the sequence number of the first frame the talker sent. `default` is the Profile 0 session as
    it stands, which must keep refusing the graph because the graph is an opt-in; `graph` is a session
    configured for it. The INIT_SYN variants go to the listener's handshake.
    """
    base = _frame_of("talker-03-frame")[0]
    _name, token = _first("talker", "token")
    _name, query = _first("talker", "queryable")
    push = _unsubscribed_push()
    init = captured("talker-01-init-syn")
    first_extension = len(init) - 3
    mandatory = init[:first_extension] + bytes([init[first_extension] | 0x10]) + init[first_extension + 1 :]
    unknown = init[:first_extension] + bytes([(init[first_extension] & 0xF0) | 0x09]) + init[first_extension + 1 :]
    qos = bytes([wire.ID_DECLARE | wire.FLAG_Z, wire.EXT_QOS | (wire.ENC_Z64 << 5), 8])
    scoped_alias = qos + bytes([wire.D_KEYEXPR | wire.FLAG_N]) + wire.leb128(94) + wire.leb128(1) + wire.leb128(1) + b"x"
    return (
        ("refuse-rmw-default-queryable", _frame(base, _declare("queryable", 99, scope=query.scope or 0)).hex(), "unsupported-message", "default"),
        ("refuse-rmw-default-token", _frame(base, _declare("token", 98, scope=token.scope or 0)).hex(), "unsupported-message", "default"),
        ("refuse-rmw-default-push-undeclared", _frame(base, push).hex(), "undeclared-key", "default"),
        ("refuse-rmw-init-extension-mandatory", mandatory.hex(), "unsupported-extension", "graph"),
        ("refuse-rmw-init-extension-unknown", unknown.hex(), "unsupported-extension", "graph"),
        ("refuse-rmw-token-wildcard", _frame(base, _declare("keyexpr", 97, suffix="@ros2_lv/0/*/0/0/NN/%/%/x")).hex(), "wildcard-keyexpr", "graph"),
        ("refuse-rmw-token-unknown-alias", _frame(base, _declare("token", 95, scope=60000)).hex(), "invalid-keyexpr", "graph"),
        ("refuse-rmw-alias-with-scope", _frame(base, scoped_alias).hex(), "invalid-keyexpr", "graph"),
        ("refuse-rmw-alias-repeated", _frame(base, _declare("keyexpr", 93, suffix="a"), _declare("keyexpr", 93, suffix="a")).hex(), "invalid-keyexpr", "graph"),
        ("refuse-rmw-untoken-unknown", _frame(base, _declare("untoken", 4000)).hex(), "unknown-declaration", "graph"),
        ("refuse-rmw-graph-key-of-254-bytes", _frame(base, _declare("keyexpr", 92, suffix="k" * (LONGEST_KEY_BYTES + 1))).hex(), "over-bound", "graph"),
    )


REFUSED_SCENARIOS = tuple((name, cls, config) for name, _batch, cls, config in _refusals())


def refuse() -> tuple[tuple[str, str], ...]:
    return tuple((name, batch) for name, batch, _cls, _config in _refusals())


def reference_agrees(
    groups: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = GROUPS,
    refused: tuple[tuple[str, str], ...] | None = None,
    read: Callable[[bytes], bytes] = wire.rebuild,
) -> None:
    """The host reference writes every captured frame again byte for byte, and reads the INIT as the peer sent it.

    The inputs are parameters so that `reference_controls` can corrupt each one in turn.
    """
    refused = refuse() if refused is None else refused
    names = [name for _group, rows in groups for name, _hex in rows]
    _need(len(set(names)) == len(names), "a captured batch name is used twice")
    _need(len({name for name, _ in refused}) == len(refused), "a refused variant name is used twice")
    sent = {hexed for _group, rows in groups for _name, hexed in rows}
    for name, batch in refused:
        _need(batch not in sent, f"{name} is a batch the peer sent")
    for group, rows in groups:
        _need(rows[0][0] == f"{group}-01-init-syn" and rows[1][0] == f"{group}-02-open-syn", f"{group} does not open with INIT_SYN and OPEN_SYN")
        init = wire.init_syn(bytes.fromhex(rows[0][1]))
        _need(init.batch == PEER_INIT_BATCH, f"{group}: the INIT_SYN announces {init.batch}, the exam fixes {PEER_INIT_BATCH}")
        found = tuple((e.ident, e.mandatory, e.encoding) for e in init.extensions)
        _need(found == PEER_INIT_EXTENSIONS, f"{group}: the INIT_SYN extensions are {found}, the exam fixes {PEER_INIT_EXTENSIONS}")
        for name, hexed in rows[2:]:
            batch = bytes.fromhex(hexed)
            if batch[0] & 0x1F == wire.ID_CLOSE:
                continue
            _need(len(batch) <= ANNOUNCED_BATCH, f"{name} is {len(batch)} bytes, over the {ANNOUNCED_BATCH} our INIT_ACK announced")
            _need(read(batch) == batch, f"the host reference writes {name} as {read(batch).hex()[:60]}, the peer sent {hexed[:60]}")
    _need(capture_digest(groups) == CAPTURE_SHA256, "the captured batches are not the ones the exam pins")


def _without_timestamp(batch: bytes) -> bytes:
    """`rebuild` with every PUSH timestamp forgotten, as a writer that ignored a field would."""
    import dataclasses

    sn, messages = wire.frame(batch)
    return bytes([wire.ID_FRAME | wire.FLAG_N]) + wire.leb128(sn) + b"".join(wire.encode(dataclasses.replace(m, timestamp=None)) if m.kind == "push" else wire.encode(m) for m in messages)


def _with_payload_flipped(batch: bytes) -> bytes:
    """`rebuild` with the last payload byte of every PUSH changed, as a writer that mis-encoded a field would."""
    import dataclasses

    sn, messages = wire.frame(batch)
    changed = [dataclasses.replace(m, payload=m.payload[:-1] + bytes([m.payload[-1] ^ 1])) if m.kind == "push" and m.payload else m for m in messages]
    return bytes([wire.ID_FRAME | wire.FLAG_N]) + wire.leb128(sn) + b"".join(wire.encode(m) for m in changed)


def reference_controls() -> int:
    """Each input `reference_agrees` guards is corrupted in turn, and must be refused for its own reason."""
    reference_agrees()
    honest = refuse()

    def corrupt(group: str, index: int, change: Callable[[str], str]) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
        out = []
        for name, rows in GROUPS:
            if name == group:
                changed = tuple((n, change(h) if i == index else h) for i, (n, h) in enumerate(rows))
                _need(changed != rows, "control: a corruption changed nothing")
                rows = changed
            out.append((name, rows))
        return tuple(out)

    first_frame = next(i for i, (n, _h) in enumerate(dict(GROUPS)["talker"]) if n.endswith("-frame"))
    cases: list[tuple[str, dict, str]] = [
        ("a host reference that writes another sequence number", {"read": lambda b: wire.rebuild(b[:1] + bytes([b[1] ^ 1]) + b[2:])}, "the host reference writes"),
        ("a captured frame with a key byte changed", {"groups": corrupt("talker", first_frame, lambda h: h.replace("706565722f", "706565722e", 1))}, "are not the ones the exam pins"),
        ("an INIT_SYN announcing another batch size", {"groups": corrupt("talker", 0, lambda h: h.replace("c8ff", "c0ff", 1))}, "the INIT_SYN announces"),
        ("an INIT_SYN with another extension", {"groups": corrupt("talker", 0, lambda h: h.replace("8127", "8227", 1))}, "the INIT_SYN extensions are"),
        ("a captured batch name used twice", {"groups": tuple((n, tuple((rows[2][0] if i == 3 else a, b) for i, (a, b) in enumerate(rows))) if n == "talker" else (n, rows) for n, rows in GROUPS)}, "used twice"),
        ("a refused variant name used twice", {"refused": (honest[0], honest[0], *honest[2:])}, "a refused variant name is used twice"),
        ("a refused variant that is a batch the peer sent", {"refused": ((honest[0][0], dict(GROUPS)["talker"][3][1]), *honest[1:])}, "is a batch the peer sent"),
        ("a host reference that writes a PUSH payload with one byte changed", {"read": _with_payload_flipped}, "the host reference writes"),
        ("a host reference that drops a PUSH timestamp", {"read": _without_timestamp}, "the host reference writes"),
        ("a captured batch over the announced size", {"groups": corrupt("talker", first_frame, lambda h: h + "00" * 600)}, "over the"),
    ]
    for label, changes, reason in cases:
        try:
            reference_agrees(**changes)
        except (RmwError, wire.RmwWireError) as error:
            _need(reason in str(error), f"control: {label} was refused for another reason: {error}")
            continue
        raise RmwError(f"control: the reference check accepted {label}")
    return len(cases)


def honest_init_ack(group: str, batch: int = ANNOUNCED_BATCH, extension: bool = False, cookie: bytes | None = None) -> bytes:
    """An INIT_ACK like the one our listener sends the group's peer, written by `zenoh_wire`: it echoes
    nothing of the peer's ZID, announces `batch` and offers a cookie. The Rust listener picks its own ZID
    and cookie, so the judge checks these fields and never the exact bytes."""
    peer_cookie = wire.open_syn_cookie(bytes.fromhex(dict(dict(GROUPS)[group])[f"{group}-02-open-syn"]))
    ack = zenoh_wire.init(bytes.fromhex("5110aa0bb0cc0dd0ee0ff00112233445"), batch=batch, cookie=peer_cookie if cookie is None else cookie)
    if extension:
        ack = bytes([ack[0] | wire.FLAG_Z]) + ack[1:] + bytes([wire.EXT_QOS])
    return ack


def good_lines() -> list[str]:
    reference_agrees()
    lines = [f"rmw replay {name} ok" for name in BATCH_NAMES]
    for group in OUTBOUND_GROUPS:
        lines += [f"rmw sent {group} init-ack {honest_init_ack(group).hex()}", f"rmw sent {group} after-handshake 0"]
    lines += [f"rmw ok {name}" for name in OK_SCENARIOS]
    for group, counts in expected_counts().items():
        lines += [f"rmw count {group} {kind} {counts[kind]}" for kind in sorted(counts)]
    lines += [f"rmw property {name} ok" for name in BATCH_NAMES]
    lines += [f"rmw refused {name} {cls}" for name, cls, _config in REFUSED_SCENARIOS]
    return lines


def _exactly(label: str, wanted: tuple[str, ...], seen: list[str]) -> None:
    missing = [name for name in wanted if name not in seen]
    extra = [name for name in seen if name not in wanted]
    repeated = sorted({name for name in seen if seen.count(name) > 1})
    _need(not missing, f"rmw {label} missing: {', '.join(missing[:4])}")
    _need(not extra, f"rmw {label} not in the exam: {', '.join(extra[:4])}")
    _need(not repeated, f"rmw {label} reported more than once: {', '.join(repeated[:4])}")


def judge(lines: list[str]) -> tuple[int, int]:
    """Check a transcript against the exam; returns (cases, refusals), a case being a scenario or a replay."""
    shapes = {("rmw", "ok"): 3, ("rmw", "replay"): 4, ("rmw", "property"): 4, ("rmw", "refused"): 4, ("rmw", "count"): 5, ("rmw", "sent"): 5}
    split = [line.split() for line in lines]
    for line, fields in zip(lines, split, strict=True):
        _need(fields[:1] == ["rmw"], f"rmw: a record that is not an rmw exam line: {line!r}")
        kind = tuple(fields[:2])
        _need(kind in shapes, f"rmw: unrecognised line: {line}")
        _need(len(fields) == shapes[kind], f"rmw: a {kind[1]} line has {len(fields)} fields, expected {shapes[kind]}: {line}")
        if kind in (("rmw", "replay"), ("rmw", "property")):
            _need(fields[3] == "ok", f"rmw: a {kind[1]} line must end in ok: {line}")
        if kind == ("rmw", "count"):
            _need(fields[4].isdigit() and str(int(fields[4])) == fields[4], f"rmw: a count that is not a canonical number: {line}")
    done = [f[2] for f in split if f[:2] == ["rmw", "ok"]]
    replays = [f[2] for f in split if f[:2] == ["rmw", "replay"]]
    properties = [f[2] for f in split if f[:2] == ["rmw", "property"]]
    refused = [(f[2], f[3]) for f in split if f[:2] == ["rmw", "refused"]]
    counts = [(f[2], f[3], f[4]) for f in split if f[:2] == ["rmw", "count"]]
    sent = [(f[2], f[3], f[4]) for f in split if f[:2] == ["rmw", "sent"]]
    _need([(group, kind) for group, kind, _value in sent] == [(g, k) for g in OUTBOUND_GROUPS for k in ("init-ack", "after-handshake")], f"rmw sent lines are not one init-ack and one after-handshake for each of {list(OUTBOUND_GROUPS)} in order")
    for group, kind, value in sent:
        if kind == "after-handshake":
            _need(value == "0", f"rmw: the {group} listener sent {value} bytes after the handshake, the item says it replies to nothing")
            continue
        _need(re.fullmatch(r"(?:[0-9a-f]{2})+", value) is not None, f"rmw: the {group} init-ack is not lowercase hexadecimal")
        try:
            ack = wire.init_ack(bytes.fromhex(value))
        except wire.RmwWireError as error:
            raise RmwError(f"rmw: the {group} listener's INIT_ACK does not parse: {error}") from error
        _need(ack.batch == ANNOUNCED_BATCH, f"rmw: the {group} listener announced a batch of {ack.batch}, the item fixes {ANNOUNCED_BATCH}")
        _need(not ack.extensions, f"rmw: the {group} listener's INIT_ACK carries an extension")
        echoed = wire.open_syn_cookie(bytes.fromhex(dict(dict(GROUPS)[group])[f"{group}-02-open-syn"]))
        _need(ack.cookie == echoed, f"rmw: the {group} listener's cookie is not the one the peer echoed")
    _exactly("scenarios", OK_SCENARIOS, done)
    _need(done == list(OK_SCENARIOS), f"rmw scenarios are out of order: {done}")
    _exactly("replays", BATCH_NAMES, replays)
    _need(replays == list(BATCH_NAMES), "rmw replays are out of order: the peer sent them in capture order")
    _exactly("properties", BATCH_NAMES, properties)
    _need(properties == list(BATCH_NAMES), "rmw properties did not hold for every captured batch in capture order")
    wanted = [(group, kind, str(n)) for group, group_counts in expected_counts().items() for kind, n in sorted(group_counts.items())]
    _need(counts == wanted, f"rmw counts differ from what the host reference reads from the bytes: {[c for c in counts if c not in wanted][:3]}; missing {[c for c in wanted if c not in counts][:3]}")
    _exactly("refusals", tuple(name for name, _cls, _config in REFUSED_SCENARIOS), [name for name, _ in refused])
    classes = {name: cls for name, cls, _config in REFUSED_SCENARIOS}
    wrong = [f"{name}={cls} (expected {classes[name]})" for name, cls in refused if cls != classes[name]]
    _need(not wrong, f"rmw refusal classes differ: {', '.join(wrong)}")
    _need([name for name, _ in refused] == [name for name, _cls, _config in REFUSED_SCENARIOS], "rmw refusals are out of order")
    return len(done) + len(replays), len(refused)


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    first_replay = good.index(f"rmw replay {BATCH_NAMES[0]} ok")

    def without(line: str) -> list[str]:
        return [other for other in good if other != line]

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    first_count = next(i for i, line in enumerate(good) if line.startswith("rmw count "))
    refusal_lines = [i for i, line in enumerate(good) if line.startswith("rmw refused ")]
    talker_ack = good.index(f"rmw sent talker init-ack {honest_init_ack('talker').hex()}")
    talker_after = good.index("rmw sent talker after-handshake 0")
    first_property = good.index(f"rmw property {BATCH_NAMES[0]} ok")
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not an rmw exam line", [*good, "undeclare ok stock-undeclares-by-id"]),
        ("an unrecognised kind of line", [*good, "rmw delivered 1 00"]),
        ("a replay line with an extra field", [good[first_replay] + " extra", *good[first_replay + 1 :]]),
        ("a replay of a batch the peer did not send", [*good, "rmw replay talker-99-frame ok"]),
        ("the last replay twice", [*good, f"rmw replay {BATCH_NAMES[-1]} ok"]),
        ("the first two replays swapped", swapped(first_replay, first_replay + 1)),
        ("the first and last replays swapped", swapped(first_replay, first_replay + len(BATCH_NAMES) - 1)),
        ("a replay that did not end in ok", [*good[:first_replay], good[first_replay].replace(" ok", " failed"), *good[first_replay + 1 :]]),
        ("the scenarios swapped", swapped(good.index(f"rmw ok {OK_SCENARIOS[0]}"), good.index(f"rmw ok {OK_SCENARIOS[1]}"))),
        ("a property that failed", [line.replace(f"property {BATCH_NAMES[7]} ok", f"property {BATCH_NAMES[7]} FAILED") for line in good]),
        ("the first two properties swapped", swapped(first_property, first_property + 1)),
        ("the first two refusals swapped", swapped(refusal_lines[0], refusal_lines[1])),
        ("the first and last refusals swapped", swapped(refusal_lines[0], refusal_lines[-1])),
        ("a listener announcing a batch of 65535", [*good[:talker_ack], f"rmw sent talker init-ack {honest_init_ack('talker', batch=65535).hex()}", *good[talker_ack + 1 :]]),
        ("a listener announcing a batch of 511", [*good[:talker_ack], f"rmw sent talker init-ack {honest_init_ack('talker', batch=511).hex()}", *good[talker_ack + 1 :]]),
        ("a listener announcing a batch of 513", [*good[:talker_ack], f"rmw sent talker init-ack {honest_init_ack('talker', batch=513).hex()}", *good[talker_ack + 1 :]]),
        ("an INIT_ACK that carries an extension", [*good[:talker_ack], f"rmw sent talker init-ack {honest_init_ack('talker', extension=True).hex()}", *good[talker_ack + 1 :]]),
        ("an INIT_ACK offering another cookie", [*good[:talker_ack], f"rmw sent talker init-ack {honest_init_ack('talker', cookie=b'another-cookie').hex()}", *good[talker_ack + 1 :]]),
        ("an INIT_ACK cut short", [*good[:talker_ack], f"rmw sent talker init-ack {honest_init_ack('talker').hex()[:-4]}", *good[talker_ack + 1 :]]),
        ("an INIT_ACK in capitals", [*good[:talker_ack], f"rmw sent talker init-ack {honest_init_ack('talker').hex().upper()}", *good[talker_ack + 1 :]]),
        ("an INIT_SYN sent where the INIT_ACK belongs", [*good[:talker_ack], f"rmw sent talker init-ack {dict(GROUPS)['talker'][0][1]}", *good[talker_ack + 1 :]]),
        ("a listener that sent one byte after the handshake", [*good[:talker_after], "rmw sent talker after-handshake 1", *good[talker_after + 1 :]]),
        ("a listener that sent a declaration reply of 12 bytes", [*good[:talker_after], "rmw sent talker after-handshake 12", *good[talker_after + 1 :]]),
        ("the talker's sent lines missing", [line for line in good if not line.startswith("rmw sent talker ")]),
        ("the listener's sent lines swapped with the talker's", swapped(talker_ack, talker_ack + 2)),
        ("a sent line with an extra field", [*good[:talker_after], good[talker_after] + " extra", *good[talker_after + 1 :]]),
        ("a count that is not a number", [*good[:first_count], good[first_count].rsplit(" ", 1)[0] + " many", *good[first_count + 1 :]]),
        ("a count with a leading zero", [*good[:first_count], good[first_count].rsplit(" ", 1)[0] + " 0" + good[first_count].rsplit(" ", 1)[1], *good[first_count + 1 :]]),
        ("a count of a kind the peer did not send", [*good, "rmw count talker unqueryable 1"]),
        ("a refusal reported twice", [*good, good[-1]]),
        ("a refusal reported with a class it does not have", [*good, "rmw refused refuse-rmw-elsewhere truncated"]),
    ]
    for name in BATCH_NAMES:
        out.append((f"the replay of {name} missing", without(f"rmw replay {name} ok")))
    for name in OK_SCENARIOS:
        out.append((f"the scenario {name} missing", without(f"rmw ok {name}")))
    for line in good:
        if line.startswith("rmw count "):
            group, kind, number = line.split()[2:]
            out.append((f"the {group} {kind} count missing", without(line)))
            out.append((f"the {group} {kind} count one over", [x.replace(line, f"rmw count {group} {kind} {int(number) + 1}") if x == line else x for x in good]))
    for name in (BATCH_NAMES[2], BATCH_NAMES[-1]):
        out.append((f"the property of {name} missing", without(f"rmw property {name} ok")))
    classes = sorted({cls for _name, cls, _config in REFUSED_SCENARIOS})
    for name, cls, _config in REFUSED_SCENARIOS:
        out.append((f"{name} missing", without(f"rmw refused {name} {cls}")))
        other = next(candidate for candidate in classes if candidate != cls)
        out.append((f"{name} refused as {other}", [line.replace(f"refused {name} {cls}", f"refused {name} {other}") for line in good]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (len(OK_SCENARIOS) + len(BATCH_NAMES), len(REFUSED_SCENARIOS)), f"rmw: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise RmwError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except RmwError:
            refused += 1
            continue
        raise RmwError(f"control: the rmw judge accepted {label}")
    return refused


# ---------------------------------------------------------------------------- the hand-off record

DECODED_ENTRY = re.compile(r'\s*\{ hex = "([^"\\]*)";\s+name = "([^"\\]*)" \}\s*')


def fixture_zti() -> str:
    """The captured batches and the refused variants as one `contracts/zenoh-rmw-session/v1` record."""

    def rows(group: tuple[tuple[str, str], ...]) -> str:
        return "".join(f'    {{ name = "{name}"; hex = "{hexed}"; }};\n' for name, hexed in group)

    body = "".join(f"  {group} = [\n{rows(rows_)}  ];\n" for group, rows_ in GROUPS)
    return f"{{\n  formatVersion = 1;\n{body}  refuse = [\n{rows(refuse())}  ];\n}}\n"


def _decoded_rows(decoded: str, group: str) -> list[tuple[str, str]]:
    start = re.search(rf"\b{group} = \[", decoded)
    _need(start is not None, f"rmw hand-off: the decoded record has no {group} group")
    assert start is not None
    position, rows = start.end(), []
    if decoded[position : position + 1] == "]":
        return rows
    while True:
        entry = DECODED_ENTRY.match(decoded, position)
        _need(entry is not None, f"rmw hand-off: {group} holds an entry the checker cannot read at offset {position}")
        assert entry is not None
        rows.append((entry.group(2), entry.group(1)))
        position = entry.end()
        if decoded[position : position + 1] == "]":
            return rows
        _need(decoded[position : position + 1] == ";", f"rmw hand-off: {group} is not a list of entries at offset {position}")
        position += 1


def validate_handoff(text: str) -> None:
    """Decode a hand-off with the contract's own decoder, then hold the values the schema names."""
    (ROOT / "build").mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="zenoh-rmw-", dir=ROOT / "build"))
    try:
        shutil.copyfile(SCHEMA, scratch / "schema.zt")
        (scratch / "decode.zt").write_text(
            's ::= import "schema.zt"; env ::= import stdlib.env; load ::= import stdlib.load; '
            "main :: { env : Env; load : Load; } -> Validation DecodeIssue s.Session ! { * env.GetEffects; * load.ZtiEffects; } "
            '= caps => [ path := env.get caps.env "SLIME_ZENOH_RMW_FIXTURES_PATH" ?? ""; s.decodeSession (load.zti caps.load path) ]; main\n'
        )
        record = scratch / "fixtures.zti"
        record.write_text(text)
        try:
            decoded = zutai_cli.evaluate("run", scratch / "decode.zt", input_path=record, env_var="SLIME_ZENOH_RMW_FIXTURES_PATH")
        except zutai_cli.ZutaiError as error:
            raise RmwError(f"rmw hand-off does not decode under contracts/zenoh-rmw-session/v1: {error}") from error
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    _need(decoded.startswith("#valid"), f"rmw hand-off is refused by contracts/zenoh-rmw-session/v1: {decoded[:200]}")
    version = re.search(r"\bformatVersion = (\d+)", decoded)
    _need(version is not None and int(version.group(1)) == 1, "rmw hand-off: formatVersion is not 1")
    sizes = {**GROUP_SIZES, "refuse": len(REFUSED_SCENARIOS)}
    for group, count in sizes.items():
        rows = _decoded_rows(decoded, group)
        _need(len(rows) == count, f"rmw hand-off: {group} has {len(rows)} rows, the contract fixes {count}")
        for name, hexed in rows:
            _need(
                len(name.encode("utf-8")) <= 64 and len(hexed) % 2 == 0 and len(hexed) // 2 <= 512 and re.fullmatch(r"[0-9a-f]*", hexed) is not None,
                f"rmw hand-off: {group}/{name} breaks the contract's bounds or is not lowercase hexadecimal",
            )


def handoff_controls() -> int:
    """The contract's decoder accepts the honest hand-off, spelled either way, and refuses each corrupted one."""
    honest = fixture_zti()
    last_name, last_hex = GROUPS[2][1][-1]
    last = f'    {{ name = "{last_name}"; hex = "{last_hex}"; }};\n'
    respelled = honest.replace(last, f'    {{\n      name = "{last_name}";\n      hex = "{last_hex}";\n    }};\n', 1).replace("formatVersion = 1;", "formatVersion =\n    1;", 1)
    _need(respelled != honest, "control: the respelled honest hand-off equals the original")
    validate_handoff(honest)
    validate_handoff(respelled)
    first_refuse = refuse()[0]
    mutations = [
        ("a missing group", honest.replace("  refuse = [", "  refuze = [")),
        ("a wrong format version", honest.replace("formatVersion = 1;", "formatVersion = 2;")),
        ("a lists group of the wrong size", honest.replace(last, "", 1)),
        ("a refuse group of the wrong size", honest.replace(f'    {{ name = "{first_refuse[0]}"; hex = "{first_refuse[1]}"; }};\n', "", 1)),
        ("a name of 64 two-byte characters, 128 bytes", honest.replace(f'"{last_name}"', '"' + "\u00e9" * 64 + '"', 1)),
        ("a hex string with an odd length", honest.replace(f'hex = "{last_hex}"', f'hex = "{last_hex[:-1]}"', 1)),
        ("a hex string in capitals", honest.replace(f'hex = "{last_hex}"', 'hex = "03AB"', 1)),
        ("a batch of 513 bytes", honest.replace(f'hex = "{last_hex}"', 'hex = "' + "00" * 513 + '"', 1)),
        ("a row with no hex", honest.replace('hex = "', 'hxx = "', 1)),
        ("an unknown extra field", honest.replace("formatVersion = 1;", "formatVersion = 1;\n  surprise = 1;")),
        ("an unknown extra field on the same line as a known one", honest.replace("formatVersion = 1;", "formatVersion = 1; surprise = 1;", 1)),
        ("an unknown extra field inside an entry", honest.replace(last, f'    {{ name = "{last_name}"; hex = "{last_hex}"; extra = 1; }};\n', 1)),
        ("a wrong format version written over several lines", honest.replace("formatVersion = 1;", "formatVersion =\n    2;", 1)),
        ("an extra lists entry written over several lines", honest.replace("  lists = [\n", '  lists = [\n    {\n      name = "extra";\n      hex = "00";\n    };\n', 1)),
    ]
    for label, text in mutations:
        if text == honest:
            raise RmwError(f"control: {label} did not change the hand-off")
        try:
            validate_handoff(text)
        except RmwError:
            continue
        raise RmwError(f"control: {label} was accepted by the rmw fixture contract")
    return len(mutations)


def all_controls() -> int:
    return transcript_controls() + handoff_controls() + reference_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 75
PINNED_CONTROLS = 182


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
