"""Judge three cases of the Zenoh service server half that the booted run does not show, from what the Rust test prints.

The booted composition shows one run in which two holders attach, exchange four samples and detach. This module judges
three more cases on the host, where the server half, the core and the link build:

* a second run: the same exchange on a fresh server, core and link gives the same bytes as the first;
* a malformed request: the server refuses it with the status and the echoes the protocol gives, and no ring, no
  session and no stream byte changes;
* a stalled link: a publication that the link cannot flush within the bound is answered `link-closed` and reaches no
  ring when it is answered.

The test `the_grading_exam` drives the server and prints one `[zenoh-exam] grading ...` line for each request and for the
state after it. This module writes every request and completion again with `struct` from the schema's layout, and it
owns every state the lines must show. Nothing here reads the Rust.

The judge is held to the client's rules for every request the client can send. A malformed take that names a row is
answered with that row, and the client refuses a failed take that carries one. The client sends row 0 only, so the exam
lists that one answer as a request the client never sends. Like the other judges it is trusted only after it refuses a
mutation of an honest transcript.
"""

from __future__ import annotations

import re
import struct

import zenoh_client_exam as client
import zenoh_client_wire_exam as wire_exam
import zenoh_server_exam as server

TEST = "zenoh_service_server::tests::the_grading_exam"
LINE = re.compile(r"\[zenoh-exam\] (grading .*)$")
OP = server.OP
OK, DENIED, MALFORMED, UNSUPPORTED, LINK_CLOSED = server.OK, server.DENIED, server.MALFORMED, server.UNSUPPORTED, server.LINK_CLOSED
ITEM_NONE, ITEM_SAMPLE = server.ITEM_NONE, server.ITEM_SAMPLE
FLAG_PEER_SENT = server.FLAG_PEER_SENT
# The bound the server half pumps the link, and the retries the link allows, as `zenoh-transport.md` states them.
PUMP_BOUND = 8
MAX_RETRIES = 3
HOLDER_ROWS = {0: 2, 1: 2}
CLOCK_START = 100
CONSTANTS = f"grading constants pump-bound {PUMP_BOUND} max-retries {MAX_RETRIES}"
CLOSE = "grading {phase} link-close - service request - completion - page - {state}"
FINAL = "grading ok second-boot-malformed-and-stall"
FIELDS = re.compile(
    r"grading (?P<phase>\S+) (?P<label>\S+) (?P<holder>\S+) (?P<path>ring|control|service) request (?P<request>\S+) "
    r"completion (?P<completion>\S+) page (?P<page>\S+) rings (?P<r0>\d+)/(?P<l0>\d+),(?P<r1>\d+)/(?P<l1>\d+) "
    r"wrote (?P<wrote>[01]) peer (?P<peer>[01]) refused (?P<refused>\d+) link (?P<link>open|closed) attached (?P<attached>\d+)"
)
GOOD_PUBLISH = dict(op=OP["publish"], row=1, sequence=9)


class GradingExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise GradingExamError(message)


def _hex(data: bytes) -> str:
    return data.hex() if data else "-"


def state(rings: tuple[int, int, int, int] = (0, 0, 0, 0), wrote: int = 0, peer: int = 0, refused: int = 0, link: str = "open", attached: int = 0) -> str:
    return f"rings {rings[0]}/{rings[1]},{rings[2]}/{rings[3]} wrote {wrote} peer {peer} refused {refused} link {link} attached {attached}"


def answer_line(phase: str, label: str, holder: int, path: str, sent: bytes, reply: bytes, page: bytes, after: str) -> str:
    return f"grading {phase} {label} {holder} {path} request {_hex(sent)} completion {_hex(reply)} page {_hex(page)} {after}"


def client_accepts(data: bytes, op: int, request_row: int | None = None) -> bool:
    """The server exam's restatement of the client's rules, with the one rule that exam leaves out: a failed take carries
    no row. `ClientIo::take` treats a failure status with a nonzero row as a malformed completion."""
    if not server.client_accepts(data, op, None, request_row):
        return False
    fields = server.unpack_completion(data)
    return not (op == OP["take"] and fields["status"] != OK and fields["row"] != 0)


def boot_lines(phase: str, text: str | None = None) -> list[str]:
    """One run of two holders: attach, one publication on the holder's second row, a take by each holder, detach, the
    refusals after detach, and the link's close."""
    out: list[str] = []

    def say(label: str, holder: int, path: str, op: int, sent: bytes, reply: bytes, after: str, page: bytes = b"", row: int | None = None) -> None:
        _need(client_accepts(reply, op, row), f"the exam lists a completion the client would refuse: {phase} {label} {holder}")
        out.append(answer_line(phase, label, holder, path, sent, reply, page, after))

    attach = server.request(OP["attach"], text=text)
    for holder, mask in ((0, 1), (1, 3)):
        say("attach", holder, "control", OP["attach"], attach, server.completion(OP["attach"], length=HOLDER_ROWS[holder], text=text), state(attached=mask))
    publish = server.request(OP["publish"], 1, 5, text)
    say("publish", 0, "ring", OP["publish"], publish, server.completion(OP["publish"], row=1, length=2, flags=FLAG_PEER_SENT, text=text), state((1, 0, 1, 0), wrote=1, peer=1, attached=3), row=1)
    page = server.header(5, CLOCK_START, text) + bytes([9, 8])
    take = server.request(OP["take"], text=text)
    sample = server.completion(OP["take"], item=ITEM_SAMPLE, row=1, length=2, text=text)
    say("take", 0, "ring", OP["take"], take, sample, state((0, 0, 1, 0), attached=3), page)
    say("take", 1, "ring", OP["take"], take, sample, state(attached=3), page)
    detach = server.request(OP["detach"], text=text)
    for holder, mask in ((1, 1), (0, 0)):
        say("detach", holder, "control", OP["detach"], detach, server.completion(OP["detach"], text=text), state(attached=mask))
    say("attach-after-detach", 0, "control", OP["attach"], attach, server.completion(OP["attach"], DENIED, text=text), state())
    say("take-after-detach", 1, "ring", OP["take"], take, server.completion(OP["take"], DENIED, text=text), state())
    out.append(CLOSE.format(phase=phase, state=state(wrote=1, link="closed")))
    return out


def malformed_lines(text: str | None = None) -> list[str]:
    """Requests outside the protocol, on the ring and on the control endpoint, after one publication sits in both rings.
    Every refusal leaves the rings, the stream and the sessions as they were."""
    out: list[str] = []
    held = state((1, 0, 1, 0), attached=3)

    def say(label: str, holder: int, path: str, op: int, sent: bytes, status: int, row: int, after: str = held, request_row: int | None = None, sendable: bool = True) -> None:
        reply = server.completion(op, status, row=row, text=text)
        _need(not sendable or client_accepts(reply, op, request_row), f"the exam lists a completion the client would refuse: malformed {label}")
        out.append(answer_line("malformed", label, holder, path, sent, reply, b"", after))

    preload = server.request(OP["publish"], 1, 5, text)
    reply = server.completion(OP["publish"], row=1, length=2, flags=FLAG_PEER_SENT, text=text)
    _need(client_accepts(reply, OP["publish"], 1), "the exam lists a completion the client would refuse: malformed preload")
    out.append(answer_line("malformed", "preload", 0, "ring", preload, reply, b"", state((1, 0, 1, 0), wrote=1, peer=1, attached=3)))

    good = server.request(OP["publish"], 1, 9, text)
    attach = server.request(OP["attach"], text=text)

    def patched(data: bytes, at: int, value: int) -> bytes:
        return data[:at] + bytes([value]) + data[at + 1 :]

    # A request that is not 32 bytes names no operation, so its completion names operation 0.
    say("publish-short", 0, "ring", 0, good[:31], MALFORMED, 0)
    say("publish-long", 0, "ring", 0, good + b"\x00", MALFORMED, 0)
    say("publish-empty", 0, "ring", 0, b"", MALFORMED, 0)
    # A request of 32 bytes that breaks a field rule is answered with its operation and, for a publish, its row.
    for label, at, value in (("publish-magic", 0, 0), ("publish-version", 4, 2), ("publish-flags", 7, 1), ("publish-reserved", 10, 1), ("publish-reserved2", 20, 1)):
        say(label, 0, "ring", OP["publish"], patched(good, at, value), MALFORMED, 1, request_row=1)
    say("publish-row-past-rows", 0, "ring", OP["publish"], server.request(OP["publish"], 2, 9, text), MALFORMED, 2, request_row=2)
    say("publish-row-far-past-rows", 0, "ring", OP["publish"], server.request(OP["publish"], 9, 9, text), MALFORMED, 9, request_row=9)
    # A take names no row. The server echoes the row of a malformed take. `ClientIo::take` refuses a failed take that
    # carries a row, and the client only sends row 0, so the client never reads that completion.
    say("take-row", 1, "ring", OP["take"], server.request(OP["take"], 2, 0, text), MALFORMED, 2, sendable=False)
    say("take-sequence", 1, "ring", OP["take"], server.request(OP["take"], 0, 5, text), MALFORMED, 0)
    for label, op in (("operation-zero", 0), ("operation-six", 6), ("operation-255", 255)):
        say(label, 0, "ring", op, patched(good, 6, op), UNSUPPORTED, 1, request_row=1)
    say("attach-on-the-ring", 0, "ring", OP["attach"], attach, UNSUPPORTED, 0)
    say("detach-on-the-ring", 0, "ring", OP["detach"], server.request(OP["detach"], text=text), UNSUPPORTED, 0)
    say("publish-magic-unattached", 2, "ring", OP["publish"], patched(good, 0, 0), MALFORMED, 1, request_row=1)
    say("attach-short", 1, "control", 0, attach[:31], MALFORMED, 0)
    say("attach-long", 1, "control", 0, attach + b"\x00", MALFORMED, 0)
    say("attach-magic", 1, "control", OP["attach"], patched(attach, 0, 0), MALFORMED, 0)
    say("attach-flags", 1, "control", OP["attach"], patched(attach, 7, 1), MALFORMED, 0)
    say("attach-sequence", 1, "control", OP["attach"], server.request(OP["attach"], 0, 7, text), MALFORMED, 0)
    say("attach-row", 1, "control", OP["attach"], server.request(OP["attach"], 1, 0, text), MALFORMED, 1)
    say("detach-sequence", 0, "control", OP["detach"], server.request(OP["detach"], 0, 3, text), MALFORMED, 0)
    say("abort-row", 0, "control", OP["abort"], server.request(OP["abort"], 2, 0, text), MALFORMED, 2)
    say("publish-on-control", 0, "control", OP["publish"], good, UNSUPPORTED, 0)
    say("take-on-control", 0, "control", OP["take"], server.request(OP["take"], text=text), UNSUPPORTED, 0)

    # The sample the refusals found in both rings is still there, and a publication after them is served.
    take = server.request(OP["take"], text=text)
    sample = server.completion(OP["take"], item=ITEM_SAMPLE, row=1, length=2, text=text)
    page = server.header(5, CLOCK_START, text) + bytes([9, 8])
    out.append(answer_line("malformed", "take-after", 0, "ring", take, sample, page, state((0, 0, 1, 0), attached=3)))
    out.append(answer_line("malformed", "take-after", 1, "ring", take, sample, page, state(attached=3)))
    after = server.request(OP["publish"], 1, 9, text)
    reply = server.completion(OP["publish"], row=1, length=2, flags=FLAG_PEER_SENT, text=text)
    out.append(answer_line("malformed", "publish-after", 0, "ring", after, reply, b"", state((1, 0, 1, 0), wrote=1, peer=1, attached=3)))
    return out


def stall_lines(dead: bool, text: str | None = None) -> list[str]:
    """A publication the stream does not take. A stream that takes nothing ends the link after its retries. A stream that
    takes one byte for each two offers leaves the link open. Either way the holder is told `link-closed`, and no ring and
    no peer holds the sample when it is told. The test prints the stall as the refusals the stream counted."""
    phase = "stall-dead" if dead else "stall-slow"
    out: list[str] = []
    attach = server.request(OP["attach"], text=text)
    for holder, mask in ((0, 1), (1, 3)):
        out.append(answer_line(phase, "attach", holder, "control", attach, server.completion(OP["attach"], length=HOLDER_ROWS[holder], text=text), b"", state(attached=mask)))
    sent = server.request(OP["publish"], 1, 20, text)
    reply = server.completion(OP["publish"], LINK_CLOSED, row=1, text=text)
    _need(client_accepts(reply, OP["publish"], 1), f"the exam lists a completion the client would refuse: {phase} publish")
    if dead:
        after = state(refused=MAX_RETRIES + 1, link="closed", attached=3)
    else:
        after = state(wrote=1, refused=2 * PUMP_BOUND, attached=3)
    out.append(answer_line(phase, "publish", 0, "ring", sent, reply, b"", after))
    take = server.request(OP["take"], text=text)
    out.append(answer_line(phase, "take", 1, "ring", take, server.completion(OP["take"], text=text), b"", state(refused=after_refused(after), link="closed" if dead else "open", attached=3)))
    detach = server.request(OP["detach"], text=text)
    out.append(answer_line(phase, "detach", 0, "control", detach, server.completion(OP["detach"], text=text), b"", state(refused=after_refused(after), link="closed" if dead else "open", attached=2)))
    return out


def after_refused(after: str) -> int:
    return int(re.search(r"refused (\d+)", after).group(1))  # type: ignore[union-attr]


def good_lines(text: str | None = None) -> list[str]:
    """The honest transcript in the order the Rust test prints it, for the layouts in `text`."""
    return [
        CONSTANTS,
        *boot_lines("boot-1", text),
        *malformed_lines(text),
        *stall_lines(True, text),
        *stall_lines(False, text),
        *boot_lines("boot-2", text),
        FINAL,
    ]


def judge(lines: list[str], text: str | None = None) -> tuple[int, int]:
    """Check a transcript against the exam for the layouts in `text`; returns (answers, refusals). A refusal is an
    answer whose completion carries a failure status."""
    for line in lines:
        _need(line.startswith("grading "), f"grading: a record that is not a grading exam line: {line!r}")
        _need(line in (CONSTANTS, FINAL) or FIELDS.fullmatch(line) is not None or re.fullmatch(r"grading \S+ link-close - service request - completion - page - rings .*", line) is not None, f"grading: unrecognised line: {line}")
    wanted = good_lines(text)
    for index, (seen, want) in enumerate(zip(lines, wanted, strict=False)):
        _need(seen == want, f"grading line {index + 1} is {seen!r}, the exam requires {want!r}")
    if len(lines) < len(wanted):
        raise GradingExamError(f"grading: the transcript stops after {len(lines)} of {len(wanted)} lines; the next is {wanted[len(lines)]!r}")
    if len(lines) > len(wanted):
        raise GradingExamError(f"grading: {len(lines) - len(wanted)} lines beyond the exam, the first {lines[len(wanted)]!r}")
    boots = [[re.sub(r"boot-\d", "boot-N", line) for line in lines if re.match(rf"grading boot-{n} ", line)] for n in (1, 2)]
    _need(boots[0] == boots[1] and boots[0], "grading: the second run is not the first run's lines")
    answers = 0
    refusals = 0
    for line in lines:
        found = FIELDS.fullmatch(line)
        if not found or found["completion"] == "-":
            continue
        answers += 1
        if server.unpack_completion(bytes.fromhex(found["completion"]), text)["status"] != OK:
            refusals += 1
    return answers - refusals, refusals


def _change_last(line: str) -> str:
    head, last = line.rsplit(" ", 1)
    return f"{head} {int(last) + 1}" if last.isdigit() else f"{head} {last}x"


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a grading line", [*good, "server ok every-request-is-answered-and-no-grant-is-widened"]),
        ("an unrecognised grading line", [*good, "grading dropped request"]),
        ("a line repeated", [*good, good[-2]]),
        ("the first two lines swapped", [good[1], good[0], *good[2:]]),
        ("the second run's attach on the first run's phase", [good[0], good[1].replace("boot-1", "boot-2"), *good[2:]]),
    ]
    for index, line in enumerate(good):
        label = f"line {index + 1} ({line[8:60]})"
        out.append((f"{label} missing", good[:index] + good[index + 1 :]))
        out.append((f"{label} with its last field changed", [*good[:index], _change_last(line), *good[index + 1 :]]))
    return out


def state_mutations() -> list[tuple[str, list[str]]]:
    """A refusal that changes what it must not, written as a transcript the judge must refuse."""
    good = good_lines()
    held = state((1, 0, 1, 0), attached=3)

    def at(label: str, after: str) -> list[str]:
        index = next(i for i, line in enumerate(good) if f" malformed {label} " in line and line.endswith(held))
        return [*good[:index], good[index].removesuffix(held) + after, *good[index + 1 :]]

    return [
        ("a malformed publish that left a ring empty", at("publish-magic", state((0, 0, 1, 0), attached=3))),
        ("a malformed publish that wrote to the stream", at("publish-magic", state((1, 0, 1, 0), wrote=1, attached=3))),
        ("a malformed publish that reached the peer", at("publish-flags", state((1, 0, 1, 0), peer=1, attached=3))),
        ("a malformed publish that filled a ring", at("publish-reserved", state((2, 0, 1, 0), attached=3))),
        ("a malformed attach that ended a session", at("attach-magic", state((1, 0, 1, 0), attached=1))),
        ("a malformed attach that began a session", at("attach-short", state((1, 0, 1, 0), attached=7))),
        ("a refused request that closed the link", at("operation-six", state((1, 0, 1, 0), attached=3, link="closed"))),
        ("a refused request that counted a lost sample", at("take-row", state((1, 1, 1, 0), attached=3))),
    ]


def field_mutations() -> list[tuple[str, list[str]]]:
    """Each claim the requirements make about a stall and about a refusal, changed on its own line.

    `state_mutations` changes the state suffix of a malformed line and `_change_last` changes the last field of a line. Neither
    reaches the refused-offer count and the link of a stall, or the status and echoed row of a malformed completion."""
    good = good_lines()
    out: list[tuple[str, list[str]]] = []

    def line_of(phase: str, label: str) -> int:
        return next(i for i, line in enumerate(good) if f"grading {phase} {label} " in line)

    def edited(index: int, old: str, new: str) -> list[str]:
        _need(old in good[index], f"the exam has no {old!r} on line {index + 1}")
        return [*good[:index], good[index].replace(old, new, 1), *good[index + 1 :]]

    dead, slow = line_of("stall-dead", "publish"), line_of("stall-slow", "publish")
    out.append(("a stream that takes nothing, left open", edited(dead, "link closed", "link open")))
    out.append(("a stream that takes nothing, closed after another count of refused offers", edited(dead, f"refused {MAX_RETRIES + 1}", f"refused {MAX_RETRIES + 2}")))
    out.append(("a slow stream, closed", edited(slow, "link open", "link closed")))
    out.append(("a slow stream that stopped at another count of refused offers", edited(slow, f"refused {2 * PUMP_BOUND}", f"refused {2 * PUMP_BOUND - 1}")))

    def completion_of(index: int) -> str:
        return FIELDS.fullmatch(good[index])["completion"]

    # A completion's status is at bytes 8 to 12 and its row at bytes 12 to 14, as the schema's layout gives them.
    take_row = line_of("malformed", "take-row")
    comp = completion_of(take_row)
    out.append(("a take with a row answered with row 0", edited(take_row, comp, comp[:24] + "0000" + comp[28:])))
    operation_six = line_of("malformed", "operation-six")
    comp = completion_of(operation_six)
    out.append(("an unsupported operation answered as malformed", edited(operation_six, comp, comp[:16] + "feffffff" + comp[24:])))
    publish_row = line_of("malformed", "publish-row-past-rows")
    comp = completion_of(publish_row)
    out.append(("a publish past the rows that does not echo its row", edited(publish_row, comp, comp[:24] + "0000" + comp[28:])))
    magic = line_of("malformed", "publish-magic")
    comp = completion_of(magic)
    out.append(("a malformed publish answered as the operation it did not name", edited(magic, comp, comp[:12] + "03" + comp[14:])))
    return out


def run_mutations() -> list[tuple[str, list[str]]]:
    """Transcripts that break the run or the stall rules without a field change of one line."""
    good = good_lines()
    second = [line for line in good if line.startswith("grading boot-2 ")]
    start = good.index(second[0])
    swapped = [re.sub(r"boot-2", "boot-1", line) for line in second]
    out = [("a second run whose publish line has another sequence", [line.replace("0100020001000000050000", "0100020001000000060000") if "boot-2 publish" in line else line for line in good])]
    out.append(("a second run that shows a holder still attached", [line.replace("attached 1", "attached 3", 1) if "boot-2 attach 0" in line else line for line in good]))
    out.append(("a second run labelled as the first", [*good[:start], *swapped, *good[start + len(second) :]]))
    stall = [i for i, line in enumerate(good) if " publish " in line and "stall-" in line]
    for index in stall:
        out.append(("a stalled publication answered ok", [*good[:index], good[index].replace("completion 5a53564301000200fbffffff01000000", "completion 5a5356430100020000000000010000000200000000000000"), *good[index + 1 :]]))
        out.append(("a stalled publication whose copies reached a ring", [*good[:index], good[index].replace("rings 0/0,0/0", "rings 1/0,1/0"), *good[index + 1 :]]))
        out.append(("a stalled publication that reached the peer", [*good[:index], good[index].replace("peer 0", "peer 1"), *good[index + 1 :]]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    judge(good)
    refused = 0
    seen: dict[tuple[str, ...], str] = {}
    for label, lines in [*transcript_mutations(), *state_mutations(), *field_mutations(), *run_mutations()]:
        _need(lines != good, f"control: {label} did not change the transcript")
        # Two controls that build one transcript are one control, and the pin counts distinct ones.
        _need(tuple(lines) not in seen, f"control: {label} repeats {seen.get(tuple(lines))}")
        seen[tuple(lines)] = label
        try:
            judge(lines)
        except (GradingExamError, KeyError):
            refused += 1
            continue
        raise GradingExamError(f"control: the grading judge accepted {label}")
    return refused


def acceptance_controls() -> int:
    """The client's rules, as this judge applies them, accept the honest completions and refuse one that breaks a rule."""
    _need(client_accepts(server.completion(OP["take"], MALFORMED), OP["take"]), "control: an honest failed take was refused")
    _need(client_accepts(server.completion(OP["publish"], MALFORMED, row=2), OP["publish"], 2), "control: an honest failed publish was refused")
    cases = (
        ("a failed take that carries a row", server.completion(OP["take"], MALFORMED, row=2), OP["take"], None),
        ("a failed take that carries a row on a denial", server.completion(OP["take"], DENIED, row=1), OP["take"], None),
        ("a failed publish that does not echo its row", server.completion(OP["publish"], MALFORMED, row=0), OP["publish"], 2),
        ("a failure that carries a length", server.completion(OP["publish"], LINK_CLOSED, row=1, length=1), OP["publish"], 1),
        ("a failure that carries a flag", server.completion(OP["publish"], LINK_CLOSED, row=1, flags=FLAG_PEER_SENT), OP["publish"], 1),
        ("a completion for another operation", server.completion(OP["attach"], MALFORMED), OP["take"], None),
    )
    refused = 0
    for label, data, op, row in cases:
        _need(not client_accepts(data, op, row), f"control: the grading rules accepted {label}")
        refused += 1
    return refused


def reference_controls() -> int:
    """The bytes come from the schema's layout. A corrupted layout makes the honest transcript fail, because the judge
    then requires the bytes of the corrupted one."""
    text = client.SCHEMA.read_text(encoding="utf-8")
    honest = good_lines()
    edits = [
        ("the completion status made unsigned", '{ name = "status"; width = 4; signed = true; byteArray = false; };', '{ name = "status"; width = 4; signed = false; byteArray = false; };'),
        ("the completion length narrowed", '{ name = "length"; width = 4; signed = false; byteArray = false; };\n  { name = "flags"; width = 4', '{ name = "length"; width = 2; signed = false; byteArray = false; };\n  { name = "flags"; width = 4'),
        ("the sample timestamp narrowed", '{ name = "timestamp"; width = 8; signed = true; byteArray = false; };\n};\n\nloanLayout', '{ name = "timestamp"; width = 4; signed = true; byteArray = false; };\n};\n\nloanLayout'),
        ("the request sequence narrowed", '{ name = "sequence"; width = 8; signed = true; byteArray = false; };\n  { name = "reserved2"; width = 12', '{ name = "sequence"; width = 4; signed = true; byteArray = false; };\n  { name = "reserved2"; width = 12'),
    ]
    refused = 0
    for label, old, new in edits:
        _need(text.count(old) == 1, f"control: {label} anchor is not in the schema exactly once")
        try:
            judge(honest, text.replace(old, new, 1))
        except (GradingExamError, server.ServerExamError, wire_exam.WireError, KeyError, struct.error):
            refused += 1
            continue
        raise GradingExamError(f"control: the grading judge accepted the honest transcript under a schema with {label}")
    return refused


def all_controls() -> int:
    return transcript_controls() + acceptance_controls() + reference_controls()


def exam_lines(stdout: str) -> list[str]:
    return [match.group(1).strip() for line in stdout.splitlines() if (match := LINE.search(line))]
