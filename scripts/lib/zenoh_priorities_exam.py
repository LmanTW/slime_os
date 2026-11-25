"""Judge the Zenoh Profile 0 exam for sending by priority: a send counter for each lane and a queue for each priority.

A Profile 0 link sends every publication on the default lane, with one sequence counter, in the order it was
called. This item adds two things:

* Lanes. When both INITs offered the QoS unit extension (`Session::lanes`), a publication of priority `p` is sent
  in a FRAME of lane `(p, reliable)`. The FRAME header carries the mandatory transport QoS extension `31 <p>` for
  any priority but 5, and each lane counts its own sequence numbers from the number the connector's OPEN
  announced. Without lanes every FRAME is on the default lane and the priority travels only in the PUSH.
* A queue. `PriorityQueue` holds a bounded number of publications for each priority and `drain` writes them into
  the link's one send slot, the lowest priority number first and first in first out within a priority. The
  sequence number is given when a publication leaves the queue, so a link without lanes still sends consecutive
  numbers.

The Rust tests under `zenoh_priorities::` print one `[zenoh-exam] priorities ...` line for each thing they did.
This module owns what those lines must be, and nothing here reads the Rust. The FRAME header comes from
`zenoh_lanes_exam.frame_header`, which is proved against the bytes `zenoh-codec` 1.0.0 wrote, and the PUSH from
`zenoh_wire.push_put_qos`. Like the other judges it is trusted only after it refuses a mutation of an honest
transcript.
"""

from __future__ import annotations

import re

import zenoh_exchange
import zenoh_lanes_exam
import zenoh_wire

# The number the connector's OPEN announces: every lane counts from it.
FIRST_SN = 9000
KEY = zenoh_exchange.demo()["key"]
GID = bytes(range(0xE0, 0xF0))
PAYLOAD = bytes(range(1, 13))
DEPTH = 2

OK_SCENARIOS = (
    "lanes-write-the-priority",
    "each-lane-counts-its-own-numbers",
    "a-link-without-lanes-keeps-one-counter",
    "express-is-its-own-frame",
    "drain-takes-the-highest-priority-first",
    "drain-keeps-first-in-first-out-within-a-priority",
    "sequence-numbers-follow-the-drain-order",
    "a-full-queue-drops-or-refuses",
    "a-full-queue-leaves-other-priorities-open",
    "drain-stops-at-a-busy-slot",
)

# (name, priority of the lane the FRAME is on, its sequence number, attachment sequence, priority the PUSH
# states, Block, express). The first five are on a link that negotiated lanes, the next two on one that did not,
# and the last two leave a queue on a link that did not. Their attachment sequences are 12 and 11: the priority 7
# publication was queued first, as 11, and the priority 0 one after it, as 12, and the lower number leaves first.
FRAMES = (
    ("lane-0", 0, FIRST_SN, 1, 0, False, False),
    ("lane-2-first", 2, FIRST_SN, 1, 2, False, False),
    ("lane-2-second", 2, FIRST_SN + 1, 1, 2, True, False),
    ("lane-5", 5, FIRST_SN, 1, 5, False, False),
    ("lane-7-express", 7, FIRST_SN, 1, 7, False, True),
    ("single-p2", 5, FIRST_SN, 1, 2, False, False),
    ("single-p7", 5, FIRST_SN + 1, 1, 7, False, False),
    ("queued-p0-first", 5, FIRST_SN, 12, 0, False, False),
    ("queued-p7-second", 5, FIRST_SN + 1, 11, 7, False, False),
)


def attachment(sequence: int) -> bytes:
    return zenoh_wire.attachment(sequence, 1000 + sequence, GID)


def frame_hex(lane_priority: int, sn: int, sequence: int, priority: int, block: bool, express: bool) -> str:
    push = zenoh_wire.push_put_qos(KEY, attachment(sequence), PAYLOAD, True, priority, block, express)
    return (zenoh_lanes_exam.frame_header(True, lane_priority, sn) + push).hex()


FRAME_HEX = tuple((name, frame_hex(lane, sn, seq, prio, block, express)) for name, lane, sn, seq, prio, block, express in FRAMES)

# (label, the attachment sequences in the order they were written). The first queues five publications, ids 1 to 5, of
# priorities 5, 2, 2, 0 and 7 in that order. The lowest priority number leaves first and a priority keeps its queue
# order, so they leave as 4 (p0), 2 and 3 (p2), 1 (p5) and 5 (p7). The second is the two that leave the queue of a
# link without lanes.
ORDERS = (
    ("drain-order", "4,2,3,1,5"),
    ("no-lanes-drain-order", "12,11"),
)

# (label, the count the exam read after the step).
COUNTS = (
    ("queue-drops-after-a-full-drop", 1),
    ("queue-drops-after-a-full-block", 1),
)

REFUSED_SCENARIOS = (
    ("block-on-a-full-queue", "queue-full"),
    ("drain-on-a-busy-slot", "send-busy"),
    ("drain-after-close", "send-after-close"),
)

SHAPES = {
    ("priorities", "ok"): 3,
    ("priorities", "frame"): 6,
    ("priorities", "order"): 4,
    ("priorities", "count"): 4,
    ("priorities", "refused"): 4,
}


class PrioritiesError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise PrioritiesError(message)


def good_lines() -> list[str]:
    return (
        [f"priorities ok {name}" for name in OK_SCENARIOS]
        + [f"priorities frame {name} {lane} {sn} {hexed}" for (name, lane, sn, *_), (_, hexed) in zip(FRAMES, FRAME_HEX, strict=True)]
        + [f"priorities order {label} {ids}" for label, ids in ORDERS]
        + [f"priorities count {label} {count}" for label, count in COUNTS]
        + [f"priorities refused {name} {cls}" for name, cls in REFUSED_SCENARIOS]
    )


def _exactly(label: str, wanted: tuple[str, ...], seen: list[str]) -> None:
    missing = [name for name in wanted if name not in seen]
    extra = [name for name in seen if name not in wanted]
    repeated = sorted({name for name in seen if seen.count(name) > 1})
    _need(not missing, f"priorities {label} missing: {', '.join(missing[:4])}")
    _need(not extra, f"priorities {label} not in the exam: {', '.join(extra[:4])}")
    _need(not repeated, f"priorities {label} reported more than once: {', '.join(repeated[:4])}")


def judge(lines: list[str]) -> tuple[int, int]:
    """Check a transcript against the exam; returns (cases, refusals), a case being a scenario, a frame, an order or a count."""
    split = [line.split() for line in lines]
    for line, fields in zip(lines, split, strict=True):
        _need(fields[:1] == ["priorities"], f"priorities: a record that is not a priorities exam line: {line!r}")
        kind = tuple(fields[:2])
        _need(kind in SHAPES, f"priorities: unrecognised line: {line}")
        _need(len(fields) == SHAPES[kind], f"priorities: a {kind[1]} line has {len(fields)} fields, expected {SHAPES[kind]}: {line}")

    done = [f[2] for f in split if f[:2] == ["priorities", "ok"]]
    _exactly("scenarios", OK_SCENARIOS, done)
    _need(done == list(OK_SCENARIOS), f"priorities scenarios are out of order: {done}")

    frames = [(f[2], f[3], f[4], f[5]) for f in split if f[:2] == ["priorities", "frame"]]
    _exactly("frames", tuple(name for name, *_ in FRAMES), [name for name, *_ in frames])
    _need([name for name, *_ in frames] == [name for name, *_ in FRAMES], "priorities frames are out of order")
    for (name, lane, sn, hexed), (_, wanted_lane, wanted_sn, *_), (_, wanted) in zip(frames, FRAMES, FRAME_HEX, strict=True):
        _need(re.fullmatch(r"[0-9a-f]+", hexed) is not None, f"priorities frame {name} is not lowercase hexadecimal")
        _need(lane == str(wanted_lane), f"priorities frame {name} is on lane {lane}, the exam requires {wanted_lane}")
        _need(sn == str(wanted_sn), f"priorities frame {name} carries sequence number {sn}, the exam requires {wanted_sn}")
        _need(hexed == wanted, f"priorities frame {name} is {hexed}, the host reference writes {wanted}")

    orders = [(f[2], f[3]) for f in split if f[:2] == ["priorities", "order"]]
    _exactly("orders", tuple(label for label, _ in ORDERS), [label for label, _ in orders])
    _need([label for label, _ in orders] == [label for label, _ in ORDERS], "priorities orders are out of order")
    for (label, seen), (_, wanted) in zip(orders, ORDERS, strict=True):
        _need(seen == wanted, f"priorities order {label} is {seen}, the exam requires {wanted}")

    counts = [(f[2], f[3]) for f in split if f[:2] == ["priorities", "count"]]
    _exactly("counts", tuple(label for label, _ in COUNTS), [label for label, _ in counts])
    _need([label for label, _ in counts] == [label for label, _ in COUNTS], "priorities counts are out of order")
    for (label, seen), (_, wanted) in zip(counts, COUNTS, strict=True):
        _need(seen == str(wanted), f"priorities count {label} is {seen}, the exam requires {wanted}")

    refused = [(f[2], f[3]) for f in split if f[:2] == ["priorities", "refused"]]
    _exactly("refusals", tuple(name for name, _ in REFUSED_SCENARIOS), [name for name, _ in refused])
    _need([name for name, _ in refused] == [name for name, _ in REFUSED_SCENARIOS], "priorities refusals are out of order")
    wrong = [f"{name}={cls} (expected {dict(REFUSED_SCENARIOS)[name]})" for name, cls in refused if cls != dict(REFUSED_SCENARIOS)[name]]
    _need(not wrong, f"priorities refusal classes differ: {', '.join(wrong)}")
    return len(done) + len(frames) + len(orders) + len(counts), len(refused)


def _replaced(good: list[str], old: str, new: str) -> list[str]:
    _need(old in good, f"control: {old!r} is not in the honest transcript")
    return [new if line == old else line for line in good]


def _flip(hexed: str) -> str:
    return hexed[:-1] + ("0" if hexed[-1] != "0" else "1")


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a priorities exam line", [*good, "congestion ok drop-sends-when-the-slot-is-free"]),
        ("an unrecognised kind of line", [*good, "priorities lost 1 2"]),
        ("a scenario line with an extra field", [*good[:-1], good[-1] + " extra"]),
        ("the first two scenarios swapped", [good[1], good[0], *good[2:]]),
    ]
    for index, line in enumerate(good):
        out.append((f"the line {' '.join(line.split()[1:3])} missing", good[:index] + good[index + 1 :]))
    for name in OK_SCENARIOS:
        out.append((f"the scenario {name} reported twice", [*good, f"priorities ok {name}"]))
    for (name, lane, sn, *_), (_, hexed) in zip(FRAMES, FRAME_HEX, strict=True):
        line = f"priorities frame {name} {lane} {sn} {hexed}"
        out.append((f"the frame {name} with its last digit changed", _replaced(good, line, f"priorities frame {name} {lane} {sn} {_flip(hexed)}")))
        out.append((f"the frame {name} in capitals", _replaced(good, line, f"priorities frame {name} {lane} {sn} {hexed.upper()}")))
        out.append((f"the frame {name} one sequence number on", _replaced(good, line, f"priorities frame {name} {lane} {sn + 1} {hexed}")))
        out.append((f"the frame {name} on lane {(lane + 1) % 8}", _replaced(good, line, f"priorities frame {name} {(lane + 1) % 8} {sn} {hexed}")))
    for label, ids in ORDERS:
        line = f"priorities order {label} {ids}"
        parts = ids.split(",")
        out.append((f"{label} reversed", _replaced(good, line, f"priorities order {label} {','.join(reversed(parts))}")))
        out.append((f"{label} with one id dropped", _replaced(good, line, f"priorities order {label} {','.join(parts[:-1])}")))
    for label, count in COUNTS:
        line = f"priorities count {label} {count}"
        out.append((f"{label} one over", _replaced(good, line, f"priorities count {label} {count + 1}")))
        out.append((f"{label} one under", _replaced(good, line, f"priorities count {label} {count - 1}")))
    classes = sorted({cls for _, cls in REFUSED_SCENARIOS})
    for name, cls in REFUSED_SCENARIOS:
        other = next(candidate for candidate in classes if candidate != cls)
        out.append((f"{name} refused as {other}", _replaced(good, f"priorities refused {name} {cls}", f"priorities refused {name} {other}")))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    wanted = (len(OK_SCENARIOS) + len(FRAMES) + len(ORDERS) + len(COUNTS), len(REFUSED_SCENARIOS))
    _need((cases, refusals) == wanted, f"priorities: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise PrioritiesError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except PrioritiesError:
            refused += 1
            continue
        raise PrioritiesError(f"control: the priorities judge accepted {label}")
    return refused


def reference_agrees() -> None:
    """The lane header is the one `zenoh_lanes_exam` proves, the default lane writes none, and the numbers are consecutive."""
    _need(len({hexed for _, hexed in FRAME_HEX}) == len(FRAME_HEX), "two frames are the same bytes")
    _need(len({name for name, *_ in FRAMES}) == len(FRAMES), "a frame name is used twice")
    _need(zenoh_lanes_exam.frame_header(True, 5, FIRST_SN) == zenoh_wire.frame(FIRST_SN), "the default lane wrote an extension")
    _need(zenoh_lanes_exam.frame_header(True, 2, FIRST_SN)[-2:] == bytes([0x31, 2]), "a lane header does not end in the mandatory QoS extension")
    _need(FRAMES[2][2] == FRAMES[1][2] + 1, "the second frame of lane 2 does not follow the first by one")
    _need(FRAMES[8][2] == FRAMES[7][2] + 1, "the frames that leave the queue are not consecutive")
    _need({lane for _, lane, *_ in FRAMES[:5]} == {0, 2, 5, 7}, "the lanes link does not cover priorities 0, 2, 5 and 7")
    _need(all(lane == 5 for _, lane, *_ in FRAMES[5:]), "a link without lanes wrote a lane header")
    _need(len({name for name, _ in COUNTS}) == len(COUNTS), "a count label is used twice")
    _need(len({name for name, _ in REFUSED_SCENARIOS}) == len(REFUSED_SCENARIOS), "a refused scenario name is used twice")


def all_controls() -> int:
    reference_agrees()
    return transcript_controls()


# Held here as well as in the item, so the gate stays correct once the item is retired. Both are exact.
PINNED_CASES = 26
PINNED_CONTROLS = 88
