"""Judge the rmw_zenoh data exam from what the Rust tests print.

The graph session and the graph link take an rmw_zenoh peer's declarations and read its tokens, and they hold
no subscription of their own, so every push is dropped and counted. This exam judges the step that makes a
topic cross: a graph session that holds one subscription of its own, delivers a peer's Put on that key to its
owner, and sends a Put on a key the peer declared a subscriber for.

`zenoh_rmw_data_peer` holds two sessions of an rmw_zenoh peer, captured once against a Slime-side peer built on
`zenoh_wire`:

* `PEERPUB`: a talker published `chatter` to a Slime subscriber, seven samples among 27 pushes;
* `SLIMEPUB`: a listener subscribed to `chatter`, and Slime wrote six Puts on the key the listener declared.

The Rust tests under `zenoh_rmw_data::` print one `[zenoh-exam] data ...` line for each thing they did. This
module builds the whole transcript from the captured bytes and `zenoh_wire`, and the Rust must print it, line
for line:

* every captured batch of both sessions replayed into a graph session, the peer's INTEREST included;
* the samples the subscriber delivered, as sequence number, timestamp and payload, and how many pushes were
  dropped for a key nobody subscribed to;
* the bytes the session wrote: the subscriber declaration and the six Puts, equal to what `zenoh_wire` writes;
* the refusals, each as the class the exam pins.

`zenoh_wire` writes the bytes the session must write, so the Rust is not graded against itself. Like the other
judges, this one is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

import zenoh_rmw_data_peer as peer
import zenoh_rmw_exam
import zenoh_rmw_graph_exam
import zenoh_rmw_link_exam
import zenoh_rmw_wire as wire
import zenoh_wire
import zutai_cli
from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-data.zt"
SCHEMA = ROOT / "contracts" / "zenoh-rmw-data" / "v1" / "schema.zt"

KEY = "0/chatter/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18"
SUBSCRIPTION_ID = 1
GID = bytes(range(0xE0, 0xF0))
DOMAIN = 0
ZID = zenoh_rmw_link_exam.ZID
COOKIE = zenoh_rmw_link_exam.COOKIE
# The sequence number our listener's OPEN_ACK announces. Our first frame carries it.
FIRST_SN = 7
SENT = 8
TALKER_SAMPLES = 11
INTEREST_MODE = 1
INTEREST_OPTIONS = 0x79
INTEREST_ID = 3
INTEREST_KEY = "@ros2_lv/0/**"

# The digest of every captured batch, name and bytes, in order. A round trip through the host reference cannot
# catch an edited capture, so the bytes are pinned here and the implementation cannot widen the exam by
# editing `zenoh_rmw_data_peer`.
CAPTURE_SHA256 = peer.CAPTURE_SHA256


class DataExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise DataExamError(message)


def capture_digest(groups: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]) -> str:
    text = "\n".join(f"{name}:{hexed}" for _label, rows in groups for name, hexed in rows)
    return hashlib.sha256(text.encode()).hexdigest()


GROUPS = (
    ("PEERPUB", peer.PEERPUB),
    ("PEERPUB_OURS", peer.PEERPUB_OURS),
    ("SLIMEPUB", peer.SLIMEPUB),
    ("SLIMEPUB_OURS", peer.SLIMEPUB_OURS),
)


# ------------------------------------------------------------------------------------------ the hand-off


def fixture_zti() -> str:
    """The captured batches of the peer, as one `contracts/zenoh-rmw-data/v1` record for the Rust tests."""

    def rows(items: tuple[tuple[str, str], ...]) -> str:
        return "".join(f'    {{ name = "{name}"; bytes = "{hexed}"; }};\n' for name, hexed in items)

    return f"{{\n  formatVersion = 1;\n  peerpub = [\n{rows(peer.PEERPUB)}  ];\n  slimepub = [\n{rows(peer.SLIMEPUB)}  ];\n}}\n"


DECODED_ENTRY = re.compile(r'\s*\{ bytes = "([0-9a-f]*)";\s+name = "([^"\\]*)" \}\s*')


def _decoded_rows(decoded: str, group: str) -> list[tuple[str, str]]:
    start = re.search(rf"\b{group} = \[", decoded)
    _need(start is not None, f"data hand-off: the decoded record has no {group} group")
    assert start is not None
    position, rows = start.end(), []
    while True:
        entry = DECODED_ENTRY.match(decoded, position)
        _need(entry is not None, f"data hand-off: {group} holds an entry the checker cannot read at offset {position}")
        assert entry is not None
        rows.append((entry.group(2), entry.group(1)))
        position = entry.end()
        if decoded[position : position + 1] == "]":
            return rows
        _need(decoded[position : position + 1] == ";", f"data hand-off: {group} is not a list of entries at offset {position}")
        position += 1


def validate_handoff(text: str) -> None:
    """The record decodes under the contract and holds exactly the pinned batches, each within 512 bytes."""
    (ROOT / "build").mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="zenoh-rmw-data-", dir=ROOT / "build"))
    try:
        shutil.copyfile(SCHEMA, scratch / "schema.zt")
        (scratch / "decode.zt").write_text(
            's ::= import "schema.zt"; env ::= import stdlib.env; load ::= import stdlib.load; '
            "main :: { env : Env; load : Load; } -> Validation DecodeIssue s.Capture ! { * env.GetEffects; * load.ZtiEffects; } "
            '= caps => [ path := env.get caps.env "SLIME_ZENOH_RMW_DATA_FIXTURES_PATH" ?? ""; s.decodeCapture (load.zti caps.load path) ]; main\n'
        )
        record = scratch / "fixtures.zti"
        record.write_text(text)
        try:
            decoded = zutai_cli.evaluate("run", scratch / "decode.zt", input_path=record, env_var="SLIME_ZENOH_RMW_DATA_FIXTURES_PATH")
        except zutai_cli.ZutaiError as error:
            raise DataExamError(f"data hand-off does not decode under contracts/zenoh-rmw-data/v1: {error}") from error
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    _need(decoded.startswith("#valid"), f"data hand-off is refused by contracts/zenoh-rmw-data/v1: {decoded[:200]}")
    version = re.search(r"\bformatVersion = (\d+)", decoded)
    _need(version is not None and int(version.group(1)) == 1, "data hand-off: formatVersion is not 1")
    for group, expected in (("peerpub", peer.PEERPUB), ("slimepub", peer.SLIMEPUB)):
        rows = _decoded_rows(decoded, group)
        _need(rows == list(expected), f"data hand-off: {group} is not the {len(expected)} batches the exam pins")
        _need(all(len(hexed) <= 1024 for _name, hexed in rows), f"data hand-off: {group} holds a batch over 512 bytes")


def handoff_controls() -> int:
    honest = fixture_zti()
    first_name, first_hex = peer.PEERPUB[0]
    first = f'    {{ name = "{first_name}"; bytes = "{first_hex}"; }};\n'
    respelled = honest.replace(first, f'    {{\n      name = "{first_name}";\n      bytes = "{first_hex}";\n    }};\n', 1).replace("formatVersion = 1;", "formatVersion =\n    1;", 1)
    _need(respelled != honest, "control: the respelled honest hand-off equals the original")
    validate_handoff(honest)
    validate_handoff(respelled)
    last_name, last_hex = peer.SLIMEPUB[-1]
    last = f'    {{ name = "{last_name}"; bytes = "{last_hex}"; }};\n'
    mutations = [
        ("a missing group", honest.replace("  slimepub = [", "  slimepux = [")),
        ("a wrong format version", honest.replace("formatVersion = 1;", "formatVersion = 2;")),
        ("a peerpub batch missing", honest.replace(first, "", 1)),
        ("a slimepub batch missing", honest.replace(last, "", 1)),
        ("a batch with a byte changed", honest.replace(f'bytes = "{first_hex}"', f'bytes = "{first_hex[:-2]}{"00" if first_hex[-2:] != "00" else "01"}"', 1)),
        ("a batch of 513 bytes", honest.replace(f'bytes = "{first_hex}"', 'bytes = "' + "00" * 513 + '"', 1)),
        ("a row with no bytes", honest.replace('bytes = "', 'bytex = "', 1)),
        ("a row with an extra field", honest.replace(first, first.replace(" }", ' extra = "x"; }'), 1)),
        ("a record with an extra field", honest.replace("formatVersion = 1;", 'formatVersion = 1;\n  extra = [];', 1)),
        ("an empty record", "{}\n"),
    ]
    refused = 0
    for label, text in mutations:
        _need(text != honest, f"control: {label} did not change the hand-off")
        try:
            validate_handoff(text)
        except DataExamError:
            refused += 1
            continue
        raise DataExamError(f"control: the data hand-off check accepted {label}")
    return refused

# --------------------------------------------------------------------------------------- read the peer


def cdr_string(text: str) -> bytes:
    """Classic CDR_LE for `std_msgs/String`: the encapsulation header, a 4-byte length and the NUL-ended text."""
    raw = text.encode() + b"\x00"
    return b"\x00\x01\x00\x00" + len(raw).to_bytes(4, "little") + raw


def read_string(payload: bytes) -> str:
    _need(payload[:4] == b"\x00\x01\x00\x00", "a CDR header that is not CDR_LE with no options")
    length = int.from_bytes(payload[4:8], "little")
    _need(len(payload) == 8 + length and payload[-1] == 0, "a CDR string whose length does not match its bytes")
    return payload[8:-1].decode()


def _interest(reader: wire.Reader, aliases: dict[int, str]) -> tuple[int, int, int, str]:
    """INTEREST: <hdr: Z, mode in bits 6:5, id 0x19><id><options><scope><key length><suffix><ext>.

    The options byte is A M N R T Q S K from bit 7 to bit 0. The capture's header is `0xb9`, mode 1 (current),
    and its options are `0x79`: keyexprs, tokens, restricted, named, the sender's mapping. The key is the alias
    the peer declared just before it, `@ros2_lv/0`, plus the suffix `/**`.
    """
    header = reader.u8()
    _need(header & 0x1F == 0x19, "not an INTEREST")
    mode = (header >> 5) & 3
    _need(mode != 0, "a final INTEREST, which carries no options byte")
    ident = reader.leb()
    options = reader.u8()
    _need(options & 0x10 and options & 0x20, "an INTEREST that is not restricted to a named key")
    scope = reader.leb()
    _need(scope in aliases, "an INTEREST that names an alias the peer did not declare")
    suffix = reader.take(reader.leb()).decode()
    if header & 0x80:
        wire.extensions(reader)
    return ident, mode, options, aliases[scope] + suffix


def walk(batch: bytes, aliases: dict[int, str]):
    """The network messages of a FRAME, with an INTEREST as ('interest', id, options, key)."""
    reader = wire.Reader(batch)
    header = reader.u8()
    _need(header == wire.ID_FRAME | wire.FLAG_N, "a FRAME that is not reliable with no extension")
    reader.leb()
    out = []
    while reader.left():
        if reader.data[reader.at] & 0x1F == 0x19:
            out.append(("interest", *_interest(reader, aliases)))
        else:
            message = wire.network(reader)
            if message.kind == "keyexpr":
                aliases[message.ident] = message.suffix or ""
            out.append(message)
    return out


class Samples:
    """What a reference session would deliver and drop for one captured session."""

    def __init__(self) -> None:
        self.delivered: list[tuple[int, int, str]] = []
        self.dropped = 0
        self.interests: list[tuple[int, int, int, str]] = []
        self.aliases: dict[int, str] = {}
        self.peer_subscribers: dict[int, str] = {}

    def feed(self, batch: bytes) -> None:
        if batch[0] & 0x1F != wire.ID_FRAME:
            return
        for message in walk(batch, self.aliases):
            if isinstance(message, tuple):
                self.interests.append(message[1:])
            elif message.kind == "keyexpr":
                self.aliases[message.ident] = message.suffix or ""
            elif message.kind == "subscriber":
                self.peer_subscribers[message.ident] = self._full(message)
            elif message.kind == "push":
                full = self._full(message)
                if full == KEY:
                    self.delivered.append(_sample(message))
                else:
                    self.dropped += 1

    def _full(self, message: wire.Message) -> str:
        base = self.aliases.get(message.scope or 0, "") if message.scope else ""
        return base + (message.suffix or "")


def _sample(message: wire.Message) -> tuple[int, int, str]:
    attachment = next(extension for extension in message.put_extensions if extension.ident == 3)
    raw = attachment.value
    assert isinstance(raw, bytes)
    return (
        int.from_bytes(raw[:8], "little", signed=True),
        int.from_bytes(raw[8:16], "little", signed=True),
        read_string(message.payload),
    )


def replay(label: str) -> Samples:
    samples = Samples()
    for _name, hexed in dict(GROUPS)[label]:
        samples.feed(bytes.fromhex(hexed))
    return samples


# ------------------------------------------------------------------------------------ what we write


def subscriber_frame() -> bytes:
    return zenoh_wire.frame(FIRST_SN, zenoh_wire.declare_subscriber(SUBSCRIPTION_ID, KEY, True))


def final_frame(sn: int) -> bytes:
    """A DECLARE with the interest flag, the interest id and a DeclareFinal: the answer to the peer's INTEREST."""
    declare = bytes([zenoh_wire.ID_DECLARE | 0x20, INTEREST_ID, 0x1A])
    return zenoh_wire.frame(sn, declare)


# Where each side's frames fall in the sequence. A talker session writes its subscriber, then the answer. A
# listener session writes the answer, then a Put for each of the peer's chatter subscriptions.
PEERPUB_FINAL_SN = FIRST_SN + 1
SLIMEPUB_FINAL_SN = FIRST_SN
FIRST_PUT_SN = FIRST_SN + 1


def put_frame(number: int) -> bytes:
    attachment = zenoh_wire.attachment(number + 1, 1_000_000_000 + number, GID)
    return zenoh_wire.frame(FIRST_PUT_SN + number, zenoh_wire.push_put(KEY, attachment, cdr_string(f"Hello Slime {number}"), True))


def check_written() -> None:
    """The frames our side wrote in the captures are the ones `zenoh_wire` writes, so the reference is the
    independent source of what the session must write."""
    ours = dict(peer.PEERPUB_OURS)
    _need(bytes.fromhex(ours["peerpub-ours-03"]) == subscriber_frame(), "the captured subscriber frame is not what zenoh_wire writes")
    _need(bytes.fromhex(ours["peerpub-ours-04"]) == final_frame(PEERPUB_FINAL_SN), "the captured answer is not the DeclareFinal the exam builds")
    slime = dict(peer.SLIMEPUB_OURS)
    _need(bytes.fromhex(slime["slimepub-ours-03"]) == final_frame(SLIMEPUB_FINAL_SN), "the captured answer is not the DeclareFinal the exam builds")
    _need(len(peer.SLIMEPUB_OURS) == 3 + SENT and len(peer.PEERPUB_OURS) == 4, "a captured side wrote a number of batches the exam does not pin")
    for number in range(SENT):
        name = f"slimepub-ours-{number + 4:02d}"
        _need(bytes.fromhex(slime[name]) == put_frame(number), f"{name} is not what zenoh_wire writes")
    _need(bytes.fromhex(dict(peer.PEERPUB_OURS)["peerpub-ours-01"]) == zenoh_rmw_link_exam.init_ack(), "the captured INIT_ACK is not the link exam's")


# --------------------------------------------------------------------------------------- the transcript

REFUSALS = (
    ("put-with-a-second-subscription", "subscriber-limit"),
    ("send-before-the-peer-declares", "undeclared-key"),
    ("send-to-another-key", "undeclared-key"),
    ("send-over-the-payload-bound", "over-bound"),
    ("interest-with-a-second-key", "unsupported-message"),
    ("interest-for-subscribers", "unsupported-message"),
    ("interest-future-mode", "unsupported-message"),
)

# The payload bound of the exam's session, in CDR bytes. `Hello Slime 0` is 13 characters and 22 bytes with its
# 4-byte header, 4-byte length and NUL, and it fits. `Hello Slime 00` is 23 bytes and does not.
PAYLOAD_BYTES = 22
SCENARIOS = ("peer-publishes-to-a-slime-subscriber", "slime-publishes-to-a-peer-subscriber")


def good_lines() -> list[str]:
    check_written()
    lines: list[str] = []
    for label, _rows in GROUPS:
        if label.endswith("_OURS"):
            continue
        lines += [f"data replay {name} ok" for name, _hex in dict(GROUPS)[label]]
    peerpub, slimepub = replay("PEERPUB"), replay("SLIMEPUB")
    for sample in peerpub.delivered:
        lines.append(f"data delivered {SUBSCRIPTION_ID} {sample[0]} {sample[1]} {sample[2].replace(' ', '_')}")
    lines.append(f"data dropped peerpub {peerpub.dropped}")
    lines.append(f"data delivered-none slimepub {len(slimepub.delivered)}")
    lines.append(f"data dropped slimepub {slimepub.dropped}")
    lines.append(f"data replay-wrote peerpub {final_frame(PEERPUB_FINAL_SN).hex()}")
    lines.append(f"data replay-wrote slimepub {final_frame(SLIMEPUB_FINAL_SN).hex()}")
    lines.append(f"data interest {INTEREST_ID} {INTEREST_MODE} {INTEREST_OPTIONS:#04x} {INTEREST_KEY}")
    lines.append(f"data wrote subscriber {subscriber_frame().hex()}")
    for number in range(SENT):
        lines.append(f"data wrote put-{number} {put_frame(number).hex()}")
    lines.append(f"data ok {SCENARIOS[0]}")
    lines.append(f"data ok {SCENARIOS[1]}")
    for name, cls in REFUSALS:
        lines.append(f"data refused {name} {cls}")
    return lines


def judge(lines: list[str]) -> tuple[int, int]:
    """The printed transcript must equal the one built here, line for line. Returns (cases, refusals)."""
    wanted = good_lines()
    for line in lines:
        _need(line.startswith("data "), f"data: a record that is not a data exam line: {line!r}")
        _need(line == line.strip() and "  " not in line, f"data: a line with stray spaces: {line!r}")
    missing = [line for line in wanted if line not in lines]
    extra = [line for line in lines if line not in wanted]
    _need(not missing, f"data lines missing: {[m[:90] for m in missing[:3]]}")
    _need(not extra, f"data lines the exam does not build: {[e[:90] for e in extra[:3]]}")
    _need(len(lines) == len(wanted), f"data: {len(lines)} lines, the exam builds {len(wanted)}; a line is repeated")
    _need(lines == wanted, "data: the lines are not in the order the exam runs them")
    refusals = sum(1 for line in wanted if line.startswith("data refused "))
    return len(wanted) - refusals, refusals


def reference_agrees(
    groups: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = GROUPS,
    interest: tuple[int, int, int, str] = (INTEREST_ID, INTEREST_MODE, INTEREST_OPTIONS, INTEREST_KEY),
    write: Callable[[int], bytes] = put_frame,
    delivered: int | None = None,
) -> None:
    """The captured bytes are the ones the exam pins, the peer sent exactly the one INTEREST the exam names, and
    the host reference reads eleven samples from the talker and none from the listener."""
    _need(capture_digest(groups) == CAPTURE_SHA256, "the captured batches are not the ones the exam pins")
    peerpub, slimepub = replay("PEERPUB"), replay("SLIMEPUB")
    _need(peerpub.interests == [interest] and slimepub.interests == [interest], f"the peers' INTERESTs are {peerpub.interests} and {slimepub.interests}, the exam names {interest}")
    count = len(peerpub.delivered) if delivered is None else delivered
    _need(count == TALKER_SAMPLES, f"the host reference reads {count} samples from the talker, the item says {TALKER_SAMPLES}")
    _need([s[0] for s in peerpub.delivered] == list(range(1, TALKER_SAMPLES + 1)), f"the talker's samples do not carry sequence numbers 1 to {TALKER_SAMPLES}")
    _need(not slimepub.delivered, "the listener pushed a chatter sample, so the exam's second session is not a subscriber's")
    _need(slimepub.peer_subscribers.get(23) == KEY, "the listener's subscriber on the chatter key is not id 23")
    for number in range(SENT):
        _need(write(number) == put_frame(number), f"the written Put {number} is not what zenoh_wire writes")
    _need(len(cdr_string("Hello Slime 0")) <= PAYLOAD_BYTES < len(cdr_string("Hello Slime 00")), "the exam's payload bound does not split the 13 and 14 character strings")


def reference_controls() -> int:
    reference_agrees()

    def corrupt(label: str, index: int, change: Callable[[str], str]):
        out = []
        for name, rows in GROUPS:
            if name == label:
                rows = tuple((n, change(h) if i == index else h) for i, (n, h) in enumerate(rows))
            out.append((name, rows))
        return tuple(out)

    cases: list[tuple[str, dict, str]] = [
        ("a captured batch with a byte changed", {"groups": corrupt("PEERPUB", 5, lambda h: h[:-2] + ("00" if h[-2:] != "00" else "01"))}, "not the ones the exam pins"),
        ("an INTEREST with another id", {"interest": (4, INTEREST_MODE, INTEREST_OPTIONS, INTEREST_KEY)}, "the exam names"),
        ("an INTEREST with other options", {"interest": (INTEREST_ID, INTEREST_MODE, 0x73, INTEREST_KEY)}, "the exam names"),
        ("an INTEREST over another key", {"interest": (INTEREST_ID, INTEREST_MODE, INTEREST_OPTIONS, "@ros2_lv/1/**")}, "the exam names"),
        ("an INTEREST of another mode", {"interest": (INTEREST_ID, 3, INTEREST_OPTIONS, INTEREST_KEY)}, "the exam names"),
        ("a talker that gave ten samples", {"delivered": 10}, "the item says 11"),
        ("a talker that gave twelve samples", {"delivered": 12}, "the item says 11"),
        ("a written Put with a sample number off by one", {"write": lambda number: put_frame(number + 1)}, "is not what zenoh_wire writes"),
    ]
    refused = 0
    for label, changes, reason in cases:
        try:
            reference_agrees(**changes)
        except (DataExamError, wire.RmwWireError) as error:
            _need(reason in str(error), f"control: {label} was refused for another reason: {error}")
            refused += 1
            continue
        raise DataExamError(f"control: the reference check accepted {label}")
    return refused


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    kinds = {k: [i for i, line in enumerate(good) if line.startswith(f"data {k} ")] for k in ("replay", "delivered", "dropped", "wrote", "refused", "ok", "interest", "replay-wrote")}
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a data exam line", [*good, "link ok talker-whole"]),
        ("a line repeated", [*good, good[0]]),
        ("a line with a doubled space", [good[0].replace(" ", "  ", 1), *good[1:]]),
        ("a line with trailing space", [good[0] + " ", *good[1:]]),
        ("the first two lines swapped", swapped(0, 1)),
        ("the first and last lines swapped", swapped(0, len(good) - 1)),
        ("two delivered samples swapped", swapped(kinds["delivered"][0], kinds["delivered"][1])),
        ("two written Puts swapped", swapped(kinds["wrote"][1], kinds["wrote"][2])),
        ("the two scenarios swapped", swapped(kinds["ok"][0], kinds["ok"][1])),
        ("the first two refusals swapped", swapped(kinds["refused"][0], kinds["refused"][1])),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index} missing ({line[:44]})", [*good[:index], *good[index + 1 :]]))
    for kind in ("delivered", "dropped", "wrote", "refused", "interest", "replay-wrote"):
        for index in kinds[kind][:10]:
            fields = good[index].split(" ")
            last = fields[-1]
            changed = last[:-1] + ("0" if last[-1] != "0" else "1")
            out.append((f"{kind} line {index} with a changed last field", [*good[:index], " ".join([*fields[:-1], changed]), *good[index + 1 :]]))
    classes = sorted({line.split(" ")[3] for line in good if line.startswith("data refused ")})
    for cls in classes:
        index = next(i for i in kinds["refused"] if good[i].split(" ")[3] == cls)
        other = next(c for c in classes if c != cls)
        out.append((f"the {good[index].split(' ')[2]} refusal reported as {other}", [*good[:index], good[index].replace(f" {cls}", f" {other}", 1), *good[index + 1 :]]))
    out.append(("a Put delivered that nobody subscribed to", [*good, "data delivered 1 99 99 Hello_Other"]))
    out.append(("a sample delivered to another subscription", [good[i].replace("delivered 1 ", "delivered 2 ", 1) if i == kinds["delivered"][0] else good[i] for i in range(len(good))]))
    out.append(("a sample with another payload", [good[i].replace("Hello_World:_1", "Hello_World:_2", 1) if i == kinds["delivered"][0] else good[i] for i in range(len(good))]))
    sender_put = put_frame(0).hex()
    receiver_put = sender_put.replace("25087d00", "25083d00", 1)
    out.append(("a Put written with the receiver mapping", [good[i].replace(sender_put, receiver_put, 1) if i == kinds["wrote"][1] else good[i] for i in range(len(good))]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (PINNED_CASES - PINNED_REFUSALS, PINNED_REFUSALS), f"data: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise DataExamError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except DataExamError:
            refused += 1
            continue
        raise DataExamError(f"control: the data judge accepted {label}")
    return refused


def all_controls() -> int:
    return transcript_controls() + reference_controls() + handoff_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 140
PINNED_REFUSALS = 7
PINNED_CONTROLS = 208


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)


# Kept imported so the neighbours' judges are one `all_controls` away for the checker slice.
_NEIGHBOURS = (zenoh_rmw_exam, zenoh_rmw_graph_exam, zenoh_rmw_link_exam)
