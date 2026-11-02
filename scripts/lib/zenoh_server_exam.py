"""Judge the server half of the Zenoh service client protocol from what the Rust test prints.

`zenoh_service_client.rs` is the client half. The server half answers it: it takes a holder's request and the payload that
travels with it, asks the service core, and returns the completion the client checks. The server half is plain Rust in
`components/lib` with no `slime_rt` call, so a host test can drive it. The test `the_server_exam` sends the requests this
module lists, plays the clock, and prints one `[zenoh-exam] server ...` line for each answer. This module owns what the
lines must be, and nothing here reads the Rust:

* every request and every completion, written with `struct` from the schema's layout;
* the sample header the server writes to the data page, written the same way;
* the rule that no completion the exam lists is one the client would refuse, restated here from the protocol and not
  read from the adapter;
* what the server must refuse, by status, and that a refusal reaches no ring.

Like the other judges it is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re
import struct

import zenoh_client_exam as client
import zenoh_client_wire_exam as wire_exam

TEST = "zenoh_service_server::tests::the_server_exam"
FILTER = "zenoh_service_server::"
LINE = re.compile(r"\[zenoh-exam\] (server .*)$")

OP = {"attach": 1, "publish": 2, "take": 3, "detach": 4, "abort": 5}
OK, DENIED, MALFORMED, UNSUPPORTED, TOO_LARGE, LINK_CLOSED = 0, -1, -2, -3, -4, -5
ITEM_NONE, ITEM_SAMPLE, ITEM_LOSS = 0, 1, 2
FLAG_PEER_SENT = 1
STATUS_NAMES = {OK: "ok", DENIED: "denied", MALFORMED: "malformed", UNSUPPORTED: "unsupported", TOO_LARGE: "too-large", LINK_CLOSED: "link-closed"}
HEADER_BYTES = 16
# The test's holders, rows and ring. Holder 0 publishes on the first key and both publishes and subscribes on the
# second. Holder 1 subscribes to both. Holder 2 has no row. A ring holds two samples of up to sixteen bytes.
ROWS = {0: 2, 1: 2}
RING_SLOTS = 2
RING_PAYLOAD = 16
CLOCK_START = 100


class ServerExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ServerExamError(message)


def request(op: int, row: int = 0, sequence: int = 0, text: str | None = None, **change: object) -> bytes:
    values: dict[str, object] = {
        "magic": client.PINNED["serviceMagic"], "version": 1, "op": op, "flags": 0, "row": row,
        "reserved": bytes(2), "sequence": sequence, "reserved2": bytes(12),
    }
    values.update(change)
    return wire_exam.pack("ServiceRequest", values, text=text)


def completion(op: int, status: int = OK, item: int = ITEM_NONE, row: int = 0, length: int = 0, flags: int = 0, text: str | None = None) -> bytes:
    values: dict[str, object] = {
        "magic": client.PINNED["serviceMagic"], "version": 1, "op": op, "item": item, "status": status, "row": row,
        "reserved": bytes(2), "length": length, "flags": flags,
    }
    return wire_exam.pack("ServiceCompletion", values, text=text)


def header(sequence: int, timestamp: int, text: str | None = None) -> bytes:
    return wire_exam.pack("SampleHeader", {"sequence": sequence, "timestamp": timestamp}, text=text)


def unpack_completion(data: bytes, text: str | None = None) -> dict[str, int]:
    """A completion's fields, read with `struct` from the schema's layout."""
    text = client.SCHEMA.read_text(encoding="utf-8") if text is None else text
    layout = client.layout(text, "completionLayout")
    code = {1: "b", 2: "h", 4: "i", 8: "q"}
    fmt = "<" + "".join(f"{width}s" if array else (code[width] if signed else code[width].upper()) for _, width, signed, array in layout)
    _need(struct.calcsize(fmt) == len(data), f"a completion is {len(data)} bytes, the layout says {struct.calcsize(fmt)}")
    values = struct.unpack(fmt, data)
    return {name: value for (name, _, _, array), value in zip(layout, values, strict=True) if not array} | {
        "reserved": 0 if all(value == bytes(len(value)) for (_, _, _, array), value in zip(layout, values, strict=True) if array) else 1
    }


def client_accepts(data: bytes, op: int, rows: int | None = None) -> bool:
    """Whether a client of the protocol takes this completion as an answer to `op`. This restates the protocol's
    rules and does not read the adapter: the magic and version, the operation echoed, reserved bytes zero, only the
    known flag, a status in the set, and a failure that carries nothing but its status."""
    fields = unpack_completion(data)
    if fields["magic"] != client.PINNED["serviceMagic"] or fields["version"] != 1 or fields["op"] != op or fields["reserved"] != 0:
        return False
    if fields["flags"] & ~FLAG_PEER_SENT or not LINK_CLOSED <= fields["status"] <= OK:
        return False
    if fields["status"] != OK:
        return fields["item"] == ITEM_NONE and fields["length"] == 0 and fields["flags"] == 0
    if op == OP["publish"]:
        return fields["item"] == ITEM_NONE
    if op == OP["take"]:
        return fields["flags"] == 0 and fields["item"] in (ITEM_NONE, ITEM_SAMPLE, ITEM_LOSS)
    return fields["item"] == ITEM_NONE and fields["flags"] == 0 and fields["row"] == 0 and (op == OP["attach"] or fields["length"] == 0)


def _status(status: int) -> str:
    return STATUS_NAMES[status]


def good_lines(text: str | None = None) -> list[str]:
    """The honest transcript, in the order the Rust test prints it, for the layouts in `text`."""
    out: list[str] = []

    def line(*words: object) -> None:
        out.append("server " + " ".join(str(word) for word in words))

    def answer(kind: str, who: str, op: int, sent: bytes, reply: bytes, *words: object, rows: int | None = None) -> None:
        _need(client_accepts(reply, op, rows), f"the exam lists a completion the client would refuse: {kind} {who}")
        line(kind, who, *words, "request", sent.hex(), "completion", reply.hex())

    def refused(kind: str, who: str, op: int, sent: bytes, status: int) -> None:
        answer(kind, who, op, sent, completion(op, status, text=text), "refused", _status(status))

    # Attach. A holder with rows gets the count of its rows. A holder with none, and a holder that is attached
    # already, is denied.
    for holder, rows in ROWS.items():
        sent = request(OP["attach"], text=text)
        answer("attach", holder, OP["attach"], sent, completion(OP["attach"], length=rows, text=text), "rows", rows, rows=rows)
    refused("attach", 2, OP["attach"], request(OP["attach"], text=text), DENIED)
    refused("attach-again", 0, OP["attach"], request(OP["attach"], text=text), DENIED)

    # A publication on the first key reaches the one holder that subscribes to it. The service stamps the time.
    clock = CLOCK_START
    sent = request(OP["publish"], 0, 5, text)
    answer("publish", 0, OP["publish"], sent, completion(OP["publish"], row=0, length=1, text=text), "row", 0, "sequence", 5, "length", 3, "reached", 1, "peer", "none")
    page = header(5, clock, text) + bytes([1, 2, 3])
    answer("take", 1, OP["take"], request(OP["take"], text=text), completion(OP["take"], item=ITEM_SAMPLE, row=0, length=3, text=text), "sample", "row", 0, "sequence", 5, "timestamp", clock, "page", page.hex())
    answer("take", 1, OP["take"], request(OP["take"], text=text), completion(OP["take"], text=text), "none")

    # A publication on the second key reaches its publisher too, as the decision record says.
    clock += 1
    sent = request(OP["publish"], 1, 6, text)
    answer("publish", 0, OP["publish"], sent, completion(OP["publish"], row=1, length=2, text=text), "row", 1, "sequence", 6, "length", 2, "reached", 2, "peer", "none")
    page = header(6, clock, text) + bytes([9, 8])
    for holder in (0, 1):
        answer("take", holder, OP["take"], request(OP["take"], text=text), completion(OP["take"], item=ITEM_SAMPLE, row=1, length=2, text=text), "sample", "row", 1, "sequence", 6, "timestamp", clock, "page", page.hex())

    # A publication the peer subscribed to is sent to it, and the completion says so.
    clock += 1
    sent = request(OP["publish"], 1, 7, text)
    answer("publish", 0, OP["publish"], sent, completion(OP["publish"], row=1, length=2, flags=FLAG_PEER_SENT, text=text), "row", 1, "sequence", 7, "length", 1, "reached", 2, "peer", "sent")
    page = header(7, clock, text) + bytes([4])
    for holder in (0, 1):
        answer("take", holder, OP["take"], request(OP["take"], text=text), completion(OP["take"], item=ITEM_SAMPLE, row=1, length=1, text=text), "sample", "row", 1, "sequence", 7, "timestamp", clock, "page", page.hex())

    # A refused publication reaches no ring and sends nothing.
    refused("publish", 1, OP["publish"], request(OP["publish"], 0, 8, text), DENIED)
    refused("publish", 0, OP["publish"], request(OP["publish"], 9, 8, text), MALFORMED)
    refused("publish", 2, OP["publish"], request(OP["publish"], 0, 8, text), DENIED)
    refused("publish-too-large", 0, OP["publish"], request(OP["publish"], 0, 8, text), TOO_LARGE)
    answer("take", 1, OP["take"], request(OP["take"], text=text), completion(OP["take"], text=text), "none")

    # A full ring drops its oldest sample and says so once, before the samples that remain.
    for seq in (10, 11, 12):
        clock += 1
        answer("publish", 0, OP["publish"], request(OP["publish"], 0, seq, text), completion(OP["publish"], row=0, length=1, text=text), "row", 0, "sequence", seq, "length", 1, "reached", 1, "peer", "none")
    answer("take", 1, OP["take"], request(OP["take"], text=text), completion(OP["take"], item=ITEM_LOSS, length=1, text=text), "loss", 1)
    for seq in (11, 12):
        stamp = CLOCK_START + 3 + (seq - 9)
        page = header(seq, stamp, text) + bytes([seq])
        answer("take", 1, OP["take"], request(OP["take"], text=text), completion(OP["take"], item=ITEM_SAMPLE, row=0, length=1, text=text), "sample", "row", 0, "sequence", seq, "timestamp", stamp, "page", page.hex())

    # A take whose buffer is smaller than the next sample is refused, and the sample stays in the ring.
    clock += 1
    answer("publish", 0, OP["publish"], request(OP["publish"], 0, 13, text), completion(OP["publish"], row=0, length=1, text=text), "row", 0, "sequence", 13, "length", 4, "reached", 1, "peer", "none")
    refused("take-small-buffer", 1, OP["take"], request(OP["take"], text=text), TOO_LARGE)
    page = header(13, CLOCK_START + 3 + 4, text) + bytes([1, 1, 1, 1])
    answer("take", 1, OP["take"], request(OP["take"], text=text), completion(OP["take"], item=ITEM_SAMPLE, row=0, length=4, text=text), "sample", "row", 0, "sequence", 13, "timestamp", CLOCK_START + 3 + 4, "page", page.hex())

    # A request outside the protocol is answered with the operation it names, and changes nothing.
    for name, sent, status in (
        ("wrong-magic", request(OP["publish"], 0, 1, text, magic=0), MALFORMED),
        ("wrong-version", request(OP["publish"], 0, 1, text, version=2), MALFORMED),
        ("nonzero-reserved", request(OP["publish"], 0, 1, text, reserved=bytes([1, 0])), MALFORMED),
        ("nonzero-flags", request(OP["publish"], 0, 1, text, flags=1), MALFORMED),
        ("unsupported-operation", request(9, 0, 1, text), UNSUPPORTED),
    ):
        op = 9 if name == "unsupported-operation" else OP["publish"]
        _need(unpack_completion(completion(op, status, text=text))["op"] == op, "the exam's own completion does not echo the operation")
        line("malformed", name, "request", sent.hex(), "completion", completion(op, status, text=text).hex())

    # A publication while the link is closed is answered as such, and the local copies are not delivered.
    refused("publish-link-closed", 0, OP["publish"], request(OP["publish"], 1, 14, text), LINK_CLOSED)
    answer("take", 1, OP["take"], request(OP["take"], text=text), completion(OP["take"], text=text), "none")

    # Teardown. A holder that detached has no session, and a holder that aborted has none either.
    for holder, kind in ((1, "detach"), (0, "abort")):
        answer(kind, holder, OP[kind], request(OP[kind], text=text), completion(OP[kind], text=text), "ok")
    refused("take-after-detach", 1, OP["take"], request(OP["take"], text=text), DENIED)
    refused("publish-after-abort", 0, OP["publish"], request(OP["publish"], 0, 15, text), DENIED)
    line("ok", "every-request-is-answered-and-no-grant-is-widened")
    return out


def shapes() -> dict[str, set[int]]:
    """The field counts each kind of line has in the honest transcript. A line of another count is not a line of
    the exam, whatever its words say, and is refused before the transcript is compared."""
    found: dict[str, set[int]] = {}
    for line in good_lines():
        fields = line.split()
        found.setdefault(fields[1], set()).add(len(fields))
    return found


def judge(lines: list[str], text: str | None = None) -> tuple[int, int]:
    """Check a transcript against the exam for the layouts in `text`; returns (cases, refusals). A refusal is a line
    that names a status the server refused with."""
    known = shapes()
    for line in lines:
        fields = line.split()
        _need(fields[:1] == ["server"], f"server: a record that is not a server exam line: {line!r}")
        _need(len(fields) > 1 and fields[1] in known, f"server: unrecognised line: {line}")
        _need(len(fields) in known[fields[1]], f"server: a {fields[1]} line has {len(fields)} fields: {line}")
    wanted = good_lines(text)
    for index, (seen, want) in enumerate(zip(lines, wanted, strict=False)):
        _need(seen == want, f"server line {index + 1} is {seen!r}, the exam requires {want!r}")
    if len(lines) < len(wanted):
        raise ServerExamError(f"server: the transcript stops after {len(lines)} of {len(wanted)} lines; the next is {wanted[len(lines)]!r}")
    if len(lines) > len(wanted):
        raise ServerExamError(f"server: {len(lines) - len(wanted)} lines beyond the exam, the first {lines[len(wanted)]!r}")
    refusals = sum(1 for line in lines if " refused " in line or line.startswith("server malformed "))
    return len(lines) - refusals, refusals


def _change_last(line: str) -> str:
    head, last = line.rsplit(" ", 1)
    if re.fullmatch(r"[0-9a-f]+", last) and len(last) > 4:
        return f"{head} {last[:-1]}{'0' if last[-1] != '0' else '1'}"
    return f"{head} {last}x"


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a server exam line", [*good, "service ok static-declaration-at-open"]),
        ("an unrecognised kind of line", [*good, "server dropped request"]),
        ("a line with an extra field", [*good[:-1], good[-1] + " extra"]),
        ("a line repeated", [*good, good[-1]]),
        ("the last line missing", good[:-1]),
        ("the first two lines swapped", [good[1], good[0], *good[2:]]),
    ]
    for index, line in enumerate(good):
        label = f"line {index + 1} ({line[7:50]})"
        out.append((f"{label} missing", good[:index] + good[index + 1 :]))
        out.append((f"{label} with its last field changed", [*good[:index], _change_last(line), *good[index + 1 :]]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    judge(good)
    refused = 0
    for label, lines in transcript_mutations():
        _need(lines != good, f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except ServerExamError:
            refused += 1
            continue
        raise ServerExamError(f"control: the server judge accepted {label}")
    return refused


def acceptance_controls() -> int:
    """The client's rules refuse a completion that breaks one of them, and accept the honest one."""
    _need(client_accepts(completion(OP["publish"], length=1), OP["publish"]), "control: an honest publish completion was refused")
    cases = (
        ("the wrong operation", completion(OP["take"]), OP["publish"]),
        ("a failure that carries an item", completion(OP["publish"], DENIED, item=ITEM_SAMPLE), OP["publish"]),
        ("a failure that carries a length", completion(OP["publish"], DENIED, length=1), OP["publish"]),
        ("a failure that carries a flag", completion(OP["publish"], DENIED, flags=FLAG_PEER_SENT), OP["publish"]),
        ("a status below the set", completion(OP["publish"], -6), OP["publish"]),
        ("a status above success", completion(OP["publish"], 1), OP["publish"]),
        ("an unknown flag", completion(OP["publish"], flags=2), OP["publish"]),
        ("a flag on a take", completion(OP["take"], flags=FLAG_PEER_SENT), OP["take"]),
        ("an unknown take item", completion(OP["take"], item=3), OP["take"]),
        ("an item on a publish", completion(OP["publish"], item=ITEM_SAMPLE), OP["publish"]),
        ("a row on a detach", completion(OP["detach"], row=1), OP["detach"]),
        ("a length on an abort", completion(OP["abort"], length=1), OP["abort"]),
        ("a wrong magic", completion(OP["publish"]).replace(bytes([0x5a, 0x53, 0x56, 0x43]), bytes(4), 1), OP["publish"]),
    )
    refused = 0
    for label, data, op in cases:
        _need(not client_accepts(data, op), f"control: the client rules accepted {label}")
        refused += 1
    return refused


def reference_controls() -> int:
    """The bytes come from the schema's layout. For each corrupted layout of the completion, the transcript of a
    server of the real layout is refused, because the judge now requires the bytes of the corrupted one."""
    text = client.SCHEMA.read_text(encoding="utf-8")
    honest = good_lines()
    edits = [
        ("the completion status made unsigned", '{ name = "status"; width = 4; signed = true; byteArray = false; };', '{ name = "status"; width = 4; signed = false; byteArray = false; };'),
        ("the completion length narrowed", '{ name = "length"; width = 4; signed = false; byteArray = false; };\n  { name = "flags"; width = 4', '{ name = "length"; width = 2; signed = false; byteArray = false; };\n  { name = "flags"; width = 4'),
        ("the completion row moved after the length", '{ name = "row"; width = 2; signed = false; byteArray = false; };\n  { name = "reserved"; width = 2; signed = false; byteArray = true; };\n  { name = "length"; width = 4; signed = false; byteArray = false; };', '{ name = "reserved"; width = 2; signed = false; byteArray = true; };\n  { name = "length"; width = 4; signed = false; byteArray = false; };\n  { name = "row"; width = 2; signed = false; byteArray = false; };'),
        ("the sample timestamp narrowed", '{ name = "timestamp"; width = 8; signed = true; byteArray = false; };\n};\n\nloanLayout', '{ name = "timestamp"; width = 4; signed = true; byteArray = false; };\n};\n\nloanLayout'),
    ]
    refused = 0
    for label, old, new in edits:
        _need(text.count(old) == 1, f"control: {label} anchor is not in the schema exactly once")
        try:
            judge(honest, text.replace(old, new, 1))
        except (ServerExamError, wire_exam.WireError, KeyError, struct.error):
            refused += 1
            continue
        raise ServerExamError(f"control: the server judge accepted the honest transcript under a schema with {label}")
    return refused


def all_controls() -> int:
    return transcript_controls() + acceptance_controls() + reference_controls()


def exam_lines(stdout: str) -> list[str]:
    return [match.group(1).strip() for line in stdout.splitlines() if (match := LINE.search(line))]
