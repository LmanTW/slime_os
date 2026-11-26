"""Judge the Zenoh Profile 0 exam for sending on a best-effort lane.

A Profile 0 link with lanes (`Session::lanes`) sends a reliable publication in a FRAME of lane `(p, reliable)`
(zenoh-qos-priorities). This item adds the best-effort FRAME: `Link::publish_best_effort` writes a FRAME of lane
`(p, best-effort)`, which is the same header with the reliable flag clear. Each best-effort lane counts its own
sequence numbers from the number the connector's OPEN announced, apart from the reliable lane of the same priority.
A link without lanes refuses it, because a peer that did not negotiate the QoS unit extension reads no best-effort
FRAME. The congestion rule is the one of `Link::publish_qos`: with the send slot busy a Drop publication is
discarded and counted, and spends no number, and a Block one is refused as `send-busy`.

The Rust tests under `zenoh_best_effort::` print one `[zenoh-exam] besteffort ...` line for each thing they did.
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

OK_SCENARIOS = (
    "best-effort-lane-header",
    "best-effort-lanes-count-apart",
    "reliable-lane-unmoved",
    "drop-spends-no-number",
    "a-link-without-lanes-refuses",
)

# (name, reliable, priority of the lane the FRAME is on, its sequence number, attachment sequence, Block). The PUSH
# states the priority of its lane. The first, second, third and fifth are on best-effort lanes 2 and 5, and the
# fourth is the reliable lane 2, which the two best-effort frames before it did not move.
FRAMES = (
    ("be-lane-2-first", False, 2, FIRST_SN, 1, False),
    ("be-lane-2-second", False, 2, FIRST_SN + 1, 2, True),
    ("be-lane-5", False, 5, FIRST_SN, 3, False),
    ("reliable-lane-2", True, 2, FIRST_SN, 4, False),
    ("be-lane-2-after-a-drop", False, 2, FIRST_SN + 2, 6, False),
)

# (label, the count the exam read after the step).
COUNTS = (
    ("best-effort-drops-after-a-busy-drop", 1),
    ("best-effort-drops-after-a-busy-block", 1),
)

REFUSED_SCENARIOS = (
    ("best-effort-block-on-a-busy-slot", "send-busy"),
    ("best-effort-without-lanes", "unexpected-message"),
    ("best-effort-after-close", "send-after-close"),
    ("best-effort-needs-fragments", "needs-fragments"),
)

SHAPES = {
    ("besteffort", "ok"): 3,
    ("besteffort", "frame"): 6,
    ("besteffort", "count"): 4,
    ("besteffort", "refused"): 4,
}


class BestEffortError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise BestEffortError(message)


def attachment(sequence: int) -> bytes:
    return zenoh_wire.attachment(sequence, 1000 + sequence, GID)


def frame_hex(reliable: bool, lane_priority: int, sn: int, sequence: int, block: bool) -> str:
    push = zenoh_wire.push_put_qos(KEY, attachment(sequence), PAYLOAD, True, lane_priority, block, False)
    return (zenoh_lanes_exam.frame_header(reliable, lane_priority, sn) + push).hex()


FRAME_HEX = tuple((name, frame_hex(reliable, lane, sn, seq, block)) for name, reliable, lane, sn, seq, block in FRAMES)


def good_lines() -> list[str]:
    return (
        [f"besteffort ok {name}" for name in OK_SCENARIOS]
        + [f"besteffort frame {name} {lane} {sn} {hexed}" for (name, _, lane, sn, *_), (_, hexed) in zip(FRAMES, FRAME_HEX, strict=True)]
        + [f"besteffort count {label} {count}" for label, count in COUNTS]
        + [f"besteffort refused {name} {cls}" for name, cls in REFUSED_SCENARIOS]
    )


def _exactly(label: str, wanted: tuple[str, ...], seen: list[str]) -> None:
    missing = [name for name in wanted if name not in seen]
    extra = [name for name in seen if name not in wanted]
    repeated = sorted({name for name in seen if seen.count(name) > 1})
    _need(not missing, f"besteffort {label} missing: {', '.join(missing[:4])}")
    _need(not extra, f"besteffort {label} not in the exam: {', '.join(extra[:4])}")
    _need(not repeated, f"besteffort {label} reported more than once: {', '.join(repeated[:4])}")


def judge(lines: list[str]) -> tuple[int, int]:
    """Check a transcript against the exam; returns (cases, refusals), a case being a scenario, a frame or a count."""
    split = [line.split() for line in lines]
    for line, fields in zip(lines, split, strict=True):
        _need(fields[:1] == ["besteffort"], f"besteffort: a record that is not a besteffort exam line: {line!r}")
        kind = tuple(fields[:2])
        _need(kind in SHAPES, f"besteffort: unrecognised line: {line}")
        _need(len(fields) == SHAPES[kind], f"besteffort: a {kind[1]} line has {len(fields)} fields, expected {SHAPES[kind]}: {line}")

    done = [f[2] for f in split if f[:2] == ["besteffort", "ok"]]
    _exactly("scenarios", OK_SCENARIOS, done)
    _need(done == list(OK_SCENARIOS), f"besteffort scenarios are out of order: {done}")

    frames = [(f[2], f[3], f[4], f[5]) for f in split if f[:2] == ["besteffort", "frame"]]
    _exactly("frames", tuple(name for name, *_ in FRAMES), [name for name, *_ in frames])
    _need([name for name, *_ in frames] == [name for name, *_ in FRAMES], "besteffort frames are out of order")
    for (name, lane, sn, hexed), (_, _, wanted_lane, wanted_sn, *_), (_, wanted) in zip(frames, FRAMES, FRAME_HEX, strict=True):
        _need(re.fullmatch(r"[0-9a-f]+", hexed) is not None, f"besteffort frame {name} is not lowercase hexadecimal")
        _need(lane == str(wanted_lane), f"besteffort frame {name} is on lane {lane}, the exam requires {wanted_lane}")
        _need(sn == str(wanted_sn), f"besteffort frame {name} carries sequence number {sn}, the exam requires {wanted_sn}")
        _need(hexed == wanted, f"besteffort frame {name} is {hexed}, the host reference writes {wanted}")

    counts = [(f[2], f[3]) for f in split if f[:2] == ["besteffort", "count"]]
    _exactly("counts", tuple(label for label, _ in COUNTS), [label for label, _ in counts])
    _need([label for label, _ in counts] == [label for label, _ in COUNTS], "besteffort counts are out of order")
    for (label, seen), (_, wanted) in zip(counts, COUNTS, strict=True):
        _need(seen == str(wanted), f"besteffort count {label} is {seen}, the exam requires {wanted}")

    refused = [(f[2], f[3]) for f in split if f[:2] == ["besteffort", "refused"]]
    _exactly("refusals", tuple(name for name, _ in REFUSED_SCENARIOS), [name for name, _ in refused])
    _need([name for name, _ in refused] == [name for name, _ in REFUSED_SCENARIOS], "besteffort refusals are out of order")
    wrong = [f"{name}={cls} (expected {dict(REFUSED_SCENARIOS)[name]})" for name, cls in refused if cls != dict(REFUSED_SCENARIOS)[name]]
    _need(not wrong, f"besteffort refusal classes differ: {', '.join(wrong)}")
    return len(done) + len(frames) + len(counts), len(refused)


def _replaced(good: list[str], old: str, new: str) -> list[str]:
    _need(old in good, f"control: {old!r} is not in the honest transcript")
    return [new if line == old else line for line in good]


def _flip(hexed: str) -> str:
    return hexed[:-1] + ("0" if hexed[-1] != "0" else "1")


def _reliable_header(hexed: str) -> str:
    """The same frame with the reliable flag (bit 5 of the FRAME header) toggled."""
    return f"{int(hexed[:2], 16) ^ 0x20:02x}" + hexed[2:]


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a besteffort exam line", [*good, "priorities ok lanes-write-the-priority"]),
        ("an unrecognised kind of line", [*good, "besteffort lost 1 2"]),
        ("a scenario line with an extra field", [*good[:-1], good[-1] + " extra"]),
        ("the first two scenarios swapped", [good[1], good[0], *good[2:]]),
    ]
    for index, line in enumerate(good):
        out.append((f"the line {' '.join(line.split()[1:3])} missing", good[:index] + good[index + 1 :]))
    for name in OK_SCENARIOS:
        out.append((f"the scenario {name} reported twice", [*good, f"besteffort ok {name}"]))
    for (name, _, lane, sn, *_), (_, hexed) in zip(FRAMES, FRAME_HEX, strict=True):
        line = f"besteffort frame {name} {lane} {sn} {hexed}"
        out.append((f"the frame {name} with its last digit changed", _replaced(good, line, f"besteffort frame {name} {lane} {sn} {_flip(hexed)}")))
        out.append((f"the frame {name} in capitals", _replaced(good, line, f"besteffort frame {name} {lane} {sn} {hexed.upper()}")))
        out.append((f"the frame {name} one sequence number on", _replaced(good, line, f"besteffort frame {name} {lane} {sn + 1} {hexed}")))
        out.append((f"the frame {name} on lane {(lane + 1) % 8}", _replaced(good, line, f"besteffort frame {name} {(lane + 1) % 8} {sn} {hexed}")))
        out.append((f"the frame {name} with the reliable flag toggled", _replaced(good, line, f"besteffort frame {name} {lane} {sn} {_reliable_header(hexed)}")))
    for label, count in COUNTS:
        line = f"besteffort count {label} {count}"
        out.append((f"{label} one over", _replaced(good, line, f"besteffort count {label} {count + 1}")))
        out.append((f"{label} one under", _replaced(good, line, f"besteffort count {label} {count - 1}")))
    classes = sorted({cls for _, cls in REFUSED_SCENARIOS})
    for name, cls in REFUSED_SCENARIOS:
        other = next(candidate for candidate in classes if candidate != cls)
        out.append((f"{name} refused as {other}", _replaced(good, f"besteffort refused {name} {cls}", f"besteffort refused {name} {other}")))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    wanted = (len(OK_SCENARIOS) + len(FRAMES) + len(COUNTS), len(REFUSED_SCENARIOS))
    _need((cases, refusals) == wanted, f"besteffort: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise BestEffortError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except BestEffortError:
            refused += 1
            continue
        raise BestEffortError(f"control: the besteffort judge accepted {label}")
    return refused


def reference_agrees() -> None:
    """The best-effort header is the reliable one with its flag clear, and each lane counts from the same number."""
    _need(len({hexed for _, hexed in FRAME_HEX}) == len(FRAME_HEX), "two frames are the same bytes")
    _need(len({name for name, *_ in FRAMES}) == len(FRAMES), "a frame name is used twice")
    for reliable in (True, False):
        for priority in (2, 5):
            header = zenoh_lanes_exam.frame_header(reliable, priority, FIRST_SN)
            _need(bool(header[0] & 0x20) == reliable, "the reliable flag is not bit 5 of the FRAME header")
    _need(
        zenoh_lanes_exam.frame_header(False, 5, FIRST_SN) == bytes([0x05]) + zenoh_wire.frame(FIRST_SN)[1:],
        "the default best-effort header is not the reliable one with its flag clear",
    )
    _need(FRAMES[1][3] == FRAMES[0][3] + 1, "the second frame of best-effort lane 2 does not follow the first by one")
    _need(FRAMES[4][3] == FRAMES[1][3] + 1, "the frame after the discard does not follow the second by one")
    _need(FRAMES[3][3] == FRAMES[0][3], "the reliable lane 2 does not count from the same number")
    _need([name for name, reliable, *_ in FRAMES if reliable] == ["reliable-lane-2"], "a best-effort frame is marked reliable")
    _need(len({name for name, _ in COUNTS}) == len(COUNTS), "a count label is used twice")
    _need(len({name for name, _ in REFUSED_SCENARIOS}) == len(REFUSED_SCENARIOS), "a refused scenario name is used twice")


def all_controls() -> int:
    reference_agrees()
    return transcript_controls()


# Held here as well as in the item, so the gate stays correct once the item is retired. Both are exact.
PINNED_CASES = 16
PINNED_CONTROLS = 59
