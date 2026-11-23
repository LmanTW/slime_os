"""Judge the rmw_zenoh data link exam from what the Rust tests print.

`zenoh_rmw_data_exam` judges a graph session that holds one subscription of its own, on batches handed to it one
at a time. `zenoh_rmw_link_exam` judges a graph link, which carries a graph session over a byte stream but
delivers no sample and writes no declaration or Put. This exam judges the link that does both: it declares the
owner's one subscription, writes the owner's Puts, and holds the samples it receives in a bounded queue the
owner drains.

The Rust tests under `zenoh_rmw_data_link::` write the two captured data sessions of `zenoh_rmw_data_peer` to a
link through a scripted byte stream, in three ways: each batch written whole, every byte read alone, and every
batch written at once. They print one `[zenoh-exam] datalink ...` line for each thing they did. This module
builds the whole transcript from the captured bytes, `zenoh_rmw_data_exam` and `zenoh_wire`, and the Rust must
print it, line for line:

* the bytes the link wrote: the handshake, then the subscriber frame and the answer to the peer's INTEREST for a
  talker's session, and the answer and eight Puts for a listener's. Each captured session ends in a FRAME and not
  a CLOSE, because the capture stopped the peer, so the exam closes the link locally and judges the CLOSE it writes;
* the samples a talker's session left in the queue, in the order the owner drained them, and the pushes dropped
  for a key nobody subscribed to;
* three scenarios on the queue: a queue of four slots that the owner does not drain, a payload over the slot, and
  a link that ends with samples in the queue;
* eight refusals, each with the class it is refused as and the bytes the link wrote.

The link is configured as the link exam configures it: `ZID`, `COOKIE`, a 30 s lease and initial sequence number 7.
Like the other judges, this one is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import zenoh_rmw_data_exam as data
import zenoh_rmw_data_peer as peer
import zenoh_rmw_link_exam as link
import zenoh_rmw_wire as wire
import zenoh_wire
from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-data-link.zt"

GROUP_NAMES = ("peerpub", "slimepub")
MODES = link.MODES
KEY = data.KEY
OTHER_KEY = "0/other/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18"
SUBSCRIPTION_ID = 1
SECOND_SUBSCRIPTION_ID = 2
PEER_SUBSCRIBER_ID = 23
# The slots of the queue the main scenarios use, the slots of the small queue, and the payload bytes of a slot. A
# talker's 11 samples fit the first queue, the small queue holds the newest four, and the longest captured string
# is 24 bytes, so a slot of 32 holds every captured sample.
QUEUE_SLOTS = 16
SMALL_QUEUE_SLOTS = 4
SLOT_BYTES = 32
# The payload bound of the link that refuses a 23-byte CDR string, as the data exam's session does.
PAYLOAD_BOUND = data.PAYLOAD_BYTES
HANDSHAKE_BATCHES = 2

REFUSALS = (
    ("second-subscription", "subscriber-limit"),
    ("subscribe-while-the-slot-is-busy", "send-busy"),
    ("put-before-the-peer-subscribes", "undeclared-key"),
    ("put-on-another-key", "undeclared-key"),
    ("put-over-the-payload-bound", "over-bound"),
    ("put-while-the-slot-is-busy", "send-busy"),
    ("stale-handle", "stale-handle"),
    ("send-after-close", "send-after-close"),
)


class DataLinkExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise DataLinkExamError(message)


# ----------------------------------------------------------------------------------- the bytes it writes


def framed(batch: bytes) -> bytes:
    return link.framed(batch)


def hexed(data_bytes: bytes) -> str:
    return data_bytes.hex() if data_bytes else "-"


def subscriber_bytes() -> bytes:
    return framed(data.subscriber_frame())


def put_bytes(number: int) -> bytes:
    return framed(data.put_frame(number))


def written(group: str) -> bytes:
    """Everything the link wrote in a session before it closed: the handshake, and what each side's capture shows."""
    if group == "peerpub":
        return link.handshake_bytes() + subscriber_bytes() + framed(data.final_frame(data.PEERPUB_FINAL_SN))
    _need(group == "slimepub", f"no data session named {group}")
    return link.handshake_bytes() + framed(data.final_frame(data.SLIMEPUB_FINAL_SN)) + b"".join(put_bytes(n) for n in range(data.SENT))


def check_written() -> None:
    """The bytes the link must write are what the data exam builds, and the data exam pins them to the captures."""
    data.check_written()
    ours = dict(peer.PEERPUB_OURS)
    expected = [bytes.fromhex(ours[f"peerpub-ours-{n:02d}"]) for n in (1, 2, 3, 4)]
    _need(written("peerpub") == b"".join(framed(batch) for batch in expected), "the expected talker stream is not what the capture's Slime side wrote")
    slime = dict(peer.SLIMEPUB_OURS)
    batches = [bytes.fromhex(slime[f"slimepub-ours-{n:02d}"]) for n in range(1, 4 + data.SENT)]
    _need(written("slimepub") == b"".join(framed(batch) for batch in batches), "the expected listener stream is not what the capture's Slime side wrote")


# --------------------------------------------------------------------------------------- the samples


def first_sn(group: str) -> int:
    """The sequence number of the peer's first FRAME, which is what its OPEN_SYN announced."""
    name = {"peerpub": "peerpub-03-frame", "slimepub": "slimepub-03-frame"}[group]
    return wire.frame(bytes.fromhex(dict(data.GROUPS)[group.upper()][int(name.rsplit("-", 2)[1]) - 1][1]))[0]


def talker_samples() -> list[tuple[int, int, str]]:
    return data.replay("PEERPUB").delivered


def dropped(group: str) -> int:
    return data.replay(group.upper()).dropped


def sample_line(group: str, mode: str, sample: tuple[int, int, str]) -> str:
    return f"datalink sample {group} {mode} {data.SUBSCRIPTION_ID} {sample[0]} {sample[1]} {sample[2].replace(' ', '_')}"


def small_queue() -> tuple[int, int, list[int]]:
    """(held, dropped, sequence numbers held): the queue keeps the newest samples and counts what it dropped."""
    samples = talker_samples()
    kept = samples[-SMALL_QUEUE_SLOTS:]
    return len(kept), len(samples) - len(kept), [sample[0] for sample in kept]


def oversize_frames() -> tuple[bytes, bytes]:
    """Two FRAMEs a talker's peer could send after the subscription: a Put whose payload is over the slot, then one
    that fits. The link must count the first, keep the second and stay open."""
    sn = first_sn("peerpub")
    long_text = "x" * SLOT_BYTES
    long_payload = data.cdr_string(long_text)
    _need(len(long_payload) > SLOT_BYTES, "the oversize payload fits a slot")
    short_payload = data.cdr_string("Hello World: 2")
    _need(len(short_payload) <= SLOT_BYTES, "the short payload does not fit a slot")
    first = zenoh_wire.frame(sn, zenoh_wire.push_put(KEY, zenoh_wire.attachment(1, 1_000, data.GID), long_payload, True))
    second = zenoh_wire.frame(sn + 1, zenoh_wire.push_put(KEY, zenoh_wire.attachment(2, 2_000, data.GID), short_payload, True))
    return first, second


def oversize_outcome() -> tuple[int, int, int]:
    """(held, dropped, sequence number of the sample held) after the two frames above."""
    return 1, 1, 2


def ended_queue() -> tuple[int, int]:
    """(held before a local close, held after it): a link that ends holds no sample and no subscription."""
    return len(talker_samples()), 0


# ------------------------------------------------------------------------------------------ the refusals


def refusal_tail(name: str) -> bytes:
    """What the link wrote when the scenario ended. Each scenario starts from a finished handshake with the listener
    capture's peer, and the link is configured as the link exam configures it.

    * `second-subscription`: the owner declared subscription 1 and the stream took it, so the tail is the
      subscriber frame, and a second declaration was refused.
    * `subscribe-while-the-slot-is-busy`: the stream took no byte after the handshake, so subscription 1 stayed in
      the send slot and a second declaration found the slot busy before the session was asked.
    * `put-before-the-peer-subscribes` and `stale-handle`: the link had written only the handshake.
    * `put-on-another-key` and `put-over-the-payload-bound`: the peer's INTEREST and subscriber arrived, and the
      stream took the answer, so the tail is the answer.
    * `put-while-the-slot-is-busy`: the peer's INTEREST and subscriber arrived, the stream took no byte after the
      handshake, so the answer stayed in the send slot and the Put found it busy.
    * `send-after-close`: a local close wrote a CLOSE of reason 0.
    """
    handshake = link.handshake_bytes()
    if name == "second-subscription":
        return handshake + subscriber_bytes()
    if name in ("put-on-another-key", "put-over-the-payload-bound"):
        return handshake + framed(data.final_frame(data.SLIMEPUB_FINAL_SN))
    if name == "send-after-close":
        return handshake + link.close_bytes(0)
    _need(name in {n for n, _ in REFUSALS}, f"no refusal named {name}")
    return handshake


# -------------------------------------------------------------------------------------- the transcript


def good_lines() -> list[str]:
    check_written()
    lines: list[str] = []
    samples = talker_samples()
    _need(len(samples) == data.TALKER_SAMPLES, f"the talker gives {len(samples)} samples, the item says {data.TALKER_SAMPLES}")
    for group in GROUP_NAMES:
        for mode in MODES:
            lines.append(f"datalink sent {group} {mode} {hexed(written(group))}")
            if group == "peerpub":
                lines += [sample_line(group, mode, sample) for sample in samples]
            else:
                lines.append(f"datalink sample-none {group} {mode} 0")
            lines.append(f"datalink pushes {group} {mode} dropped={dropped(group)} queue-dropped=0")
            lines.append(f"datalink closed {group} {mode} reason=0 wrote={hexed(link.close_bytes(0))} queue=0 subscription=none")
            lines.append(f"datalink ok {group}-{mode}")
    held, lost, kept = small_queue()
    lines.append(f"datalink queue small held={held} dropped={lost} sequences={','.join(str(s) for s in kept)}")
    oversize_held, oversize_lost, oversize_seq = oversize_outcome()
    lines.append(f"datalink queue oversize held={oversize_held} dropped={oversize_lost} sequence={oversize_seq} open=true")
    before, after = ended_queue()
    lines.append(f"datalink queue ended before={before} after={after}")
    for name, cls in REFUSALS:
        lines.append(f"datalink refused {name} {cls} {hexed(refusal_tail(name))}")
    return lines


def judge(lines: list[str]) -> tuple[int, int]:
    """The printed transcript must equal the one built here, line for line. Returns (cases, refusals)."""
    wanted = good_lines()
    for line in lines:
        _need(line.startswith("datalink "), f"datalink: a record that is not a data link exam line: {line!r}")
        _need(line == line.strip() and "  " not in line, f"datalink: a line with stray spaces: {line!r}")
    missing = [line for line in wanted if line not in lines]
    extra = [line for line in lines if line not in wanted]
    _need(not missing, f"datalink lines missing: {[m[:90] for m in missing[:3]]}")
    _need(not extra, f"datalink lines the exam does not build: {[e[:90] for e in extra[:3]]}")
    _need(len(lines) == len(wanted), f"datalink: {len(lines)} lines, the exam builds {len(wanted)}; a line is repeated")
    _need(lines == wanted, "datalink: the lines are not in the order the exam runs them")
    refusals = sum(1 for line in wanted if line.startswith("datalink refused "))
    return len(wanted) - refusals, refusals


# ---------------------------------------------------------------------------------------- the controls


def reference_agrees(
    stream: Callable[[str], bytes] = written,
    small: tuple[int, int, list[int]] | None = None,
    oversize: tuple[int, int, int] | None = None,
    slot_bytes: int = SLOT_BYTES,
) -> None:
    """The expected streams are the captures' own, and the queue scenarios are about what they say."""
    check_written()
    for group in GROUP_NAMES:
        _need(stream(group) == written(group), f"the expected {group} stream is not the capture's")
    held, lost, kept = small_queue() if small is None else small
    _need(held == SMALL_QUEUE_SLOTS, f"the small queue holds {held} samples, its slots are {SMALL_QUEUE_SLOTS}")
    _need(lost == data.TALKER_SAMPLES - SMALL_QUEUE_SLOTS, f"the small queue drops {lost} samples, the talker's {data.TALKER_SAMPLES} less {SMALL_QUEUE_SLOTS} are lost")
    _need(kept == list(range(data.TALKER_SAMPLES - SMALL_QUEUE_SLOTS + 1, data.TALKER_SAMPLES + 1)), f"the small queue keeps sequences {kept}, the newest four are kept")
    held, lost, sequence = oversize_outcome() if oversize is None else oversize
    _need((held, lost, sequence) == (1, 1, 2), f"the oversize scenario ends with {(held, lost, sequence)}, it holds sample 2 and drops one")
    first, second = oversize_frames()
    _need(len(data.cdr_string("x" * SLOT_BYTES)) > slot_bytes, f"a slot of {slot_bytes} bytes holds the oversize payload")
    _need(max(len(data.cdr_string(f"Hello World: {n}")) for n in range(1, data.TALKER_SAMPLES + 1)) <= slot_bytes, f"a slot of {slot_bytes} bytes does not hold every captured sample")
    _need(first[0] == second[0] and wire.frame(first)[0] + 1 == wire.frame(second)[0], "the two oversize frames do not carry consecutive sequence numbers")
    _need(QUEUE_SLOTS >= data.TALKER_SAMPLES, f"a queue of {QUEUE_SLOTS} slots does not hold the talker's {data.TALKER_SAMPLES} samples")
    before, after = ended_queue()
    _need((before, after) == (data.TALKER_SAMPLES, 0), "the ended scenario does not start with the talker's samples and end empty")


def reference_controls() -> int:
    reference_agrees()
    cases: list[tuple[str, dict, str]] = [
        ("a talker stream that omits the answer", {"stream": lambda group: written(group)[:-8] if group == "peerpub" else written(group)}, "is not the capture's"),
        ("a listener stream with seven Puts", {"stream": lambda group: written(group)[: -len(put_bytes(7))] if group == "slimepub" else written(group)}, "is not the capture's"),
        ("a small queue that holds five", {"small": (5, 6, [7, 8, 9, 10, 11])}, "its slots are"),
        ("a small queue that drops six", {"small": (4, 6, [8, 9, 10, 11])}, "less"),
        ("a small queue that keeps the oldest", {"small": (4, 7, [1, 2, 3, 4])}, "the newest four are kept"),
        ("an oversize scenario that holds nothing", {"oversize": (0, 1, 0)}, "holds sample 2"),
        ("a slot of 23 bytes", {"slot_bytes": 23}, "does not hold every captured sample"),
        ("a slot of 41 bytes that would hold the oversize payload", {"slot_bytes": 41}, "holds the oversize payload"),
    ]
    refused = 0
    for label, changes, reason in cases:
        try:
            reference_agrees(**changes)
        except (DataLinkExamError, wire.RmwWireError) as error:
            _need(reason in str(error), f"control: {label} was refused for another reason: {error}")
            refused += 1
            continue
        raise DataLinkExamError(f"control: the reference check accepted {label}")
    return refused


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    kinds = {
        kind: [i for i, line in enumerate(good) if line.startswith(f"datalink {kind} ")]
        for kind in ("sent", "sample", "sample-none", "pushes", "closed", "ok", "queue", "refused")
    }
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a data link exam line", [*good, "data ok peer-publishes-to-a-slime-subscriber"]),
        ("a line repeated", [*good, good[0]]),
        ("a line with a doubled space", [good[0].replace(" ", "  ", 1), *good[1:]]),
        ("a line with trailing space", [good[0] + " ", *good[1:]]),
        ("the first two lines swapped", swapped(0, 1)),
        ("the first and last lines swapped", swapped(0, len(good) - 1)),
        ("two samples swapped", swapped(kinds["sample"][0], kinds["sample"][1])),
        ("two modes of one session swapped", swapped(kinds["sent"][0], kinds["sent"][1])),
        ("the first two refusals swapped", swapped(kinds["refused"][0], kinds["refused"][1])),
        ("a refusal moved ahead of the queue scenarios", swapped(kinds["queue"][0], kinds["refused"][0])),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index} missing ({line[:44]})", [*good[:index], *good[index + 1 :]]))
    for kind in ("sent", "sample", "pushes", "closed", "queue", "refused"):
        for index in kinds[kind][:12]:
            fields = good[index].split(" ")
            last = fields[-1]
            changed = last[:-1] + ("0" if last[-1] != "0" else "1")
            out.append((f"{kind} line {index} with a changed last field", [*good[:index], " ".join([*fields[:-1], changed]), *good[index + 1 :]]))
    classes = sorted({line.split(" ")[3] for line in good if line.startswith("datalink refused ")})
    for cls in classes:
        index = next(i for i in kinds["refused"] if good[i].split(" ")[3] == cls)
        other = next(c for c in classes if c != cls)
        out.append((f"the {good[index].split(' ')[2]} refusal reported as {other}", [*good[:index], good[index].replace(f" {cls} ", f" {other} ", 1), *good[index + 1 :]]))
    out.append(("a sample delivered after the session closed", [*good, "datalink sample peerpub whole 1 12 0 Hello_World:_12"]))
    out.append(("a talker session that dropped nothing", [good[i].replace("dropped=28", "dropped=0") if i == kinds["pushes"][0] else good[i] for i in range(len(good))]))
    out.append(("a sample queue left full after the close", [good[i].replace("queue=0", "queue=4", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]))
    out.append(("a local close that wrote nothing", [good[i].replace("wrote=02002300", "wrote=-", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]))
    out.append(("a subscription kept after the close", [good[i].replace("subscription=none", "subscription=1", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]))
    out.append(("a Put written with the receiver mapping", [good[i].replace("7d00", "3d00", 1) if i == kinds["sent"][3] else good[i] for i in range(len(good))]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (PINNED_CASES - PINNED_REFUSALS, PINNED_REFUSALS), f"datalink: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise DataLinkExamError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except DataLinkExamError:
            refused += 1
            continue
        raise DataLinkExamError(f"control: the data link judge accepted {label}")
    return refused


def all_controls() -> int:
    return transcript_controls() + reference_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 71
PINNED_REFUSALS = 8
PINNED_CONTROLS = 143


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
