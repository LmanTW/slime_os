"""Judge the Zenoh Profile 0 exam for congestion control on a publication.

A PUSH states Drop or Block (`Qos::block`). `Link::publish` refuses every publication with `SendBusy` while
the link's one send slot holds a batch, whatever the value says. The change adds `Link::publish_qos`:

* Drop, with the slot busy, discards the publication, counts it in `Link::dropped` and returns `Dropped`.
  It builds no frame, so the session spends no sequence number and the next frame follows the last one sent.
* Block, with the slot busy, returns `SendBusy` as today. It leaves the stall count alone: against a peer that
  accepts nothing, the link ends with `RetryLimit` on the pump that follows `MAX_RETRIES` stalled ones, with
  refused Block publications between the pumps.
* With the slot free both queue the frame the host reference `zenoh_wire.push_put_qos` writes.

The Rust tests under `zenoh_congestion::` print one `[zenoh-exam] congestion ...` line for each thing they
did. This module owns what those lines must be, and nothing here reads the Rust. Like the other judges it
is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re

import zenoh_exchange
import zenoh_wire

FIRST_SN = 9000
KEY = zenoh_exchange.demo()["key"]
ATTACHMENT = zenoh_wire.attachment(1, 1000, bytes(range(0xE0, 0xF0)))
PAYLOAD = bytes(range(1, 13))

OK_SCENARIOS = (
    "drop-sends-when-the-slot-is-free",
    "drop-discards-when-the-slot-is-busy",
    "drop-spends-no-sequence-number",
    "block-keeps-send-busy",
    "block-sends-after-the-flush",
    "dropped-count-is-reported",
)

# (name, sequence number, priority, block): the two frames the link sent. The first has the default QoS and
# so no extension; the second follows three dropped publications and must carry the next number.
FRAMES = (
    ("first", FIRST_SN, 5, False),
    ("after-drops", FIRST_SN + 1, 2, True),
)
FRAME_HEX = tuple((name, zenoh_wire.frame(sn, zenoh_wire.push_put_qos(KEY, ATTACHMENT, PAYLOAD, True, priority, block, False)).hex()) for name, sn, priority, block in FRAMES)

# (label, the count Link::dropped reports after the step).
COUNTS = (
    ("after-one-drop", 1),
    ("after-three-drops", 3),
    ("block-leaves-the-count", 3),
    ("after-the-flush-and-a-send", 3),
    # The pump on which a link that stalls reports RetryLimit, one past MAX_RETRIES (3), with a Block
    # publication refused between every two pumps.
    ("retry-limit-on-pump", 4),
)

REFUSED_SCENARIOS = (
    ("block-on-a-busy-slot", "send-busy"),
    ("drop-after-close", "send-after-close"),
    ("stale-handle", "stale-handle"),
    ("block-stalled-past-the-limit", "retry-limit"),
)

SHAPES = {
    ("congestion", "ok"): 3,
    ("congestion", "frame"): 5,
    ("congestion", "count"): 4,
    ("congestion", "refused"): 4,
}


class CongestionError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise CongestionError(message)


def good_lines() -> list[str]:
    return (
        [f"congestion ok {name}" for name in OK_SCENARIOS]
        + [f"congestion frame {name} {sn} {hexed}" for (name, sn, _, _), (_, hexed) in zip(FRAMES, FRAME_HEX, strict=True)]
        + [f"congestion count {label} {count}" for label, count in COUNTS]
        + [f"congestion refused {name} {cls}" for name, cls in REFUSED_SCENARIOS]
    )


def _exactly(label: str, wanted: tuple[str, ...], seen: list[str]) -> None:
    missing = [name for name in wanted if name not in seen]
    extra = [name for name in seen if name not in wanted]
    repeated = sorted({name for name in seen if seen.count(name) > 1})
    _need(not missing, f"congestion {label} missing: {', '.join(missing[:4])}")
    _need(not extra, f"congestion {label} not in the exam: {', '.join(extra[:4])}")
    _need(not repeated, f"congestion {label} reported more than once: {', '.join(repeated[:4])}")


def judge(lines: list[str]) -> tuple[int, int]:
    """Check a transcript against the exam; returns (cases, refusals), a case being a scenario, a frame or a count."""
    split = [line.split() for line in lines]
    for line, fields in zip(lines, split, strict=True):
        _need(fields[:1] == ["congestion"], f"congestion: a record that is not a congestion exam line: {line!r}")
        kind = tuple(fields[:2])
        _need(kind in SHAPES, f"congestion: unrecognised line: {line}")
        _need(len(fields) == SHAPES[kind], f"congestion: a {kind[1]} line has {len(fields)} fields, expected {SHAPES[kind]}: {line}")

    done = [f[2] for f in split if f[:2] == ["congestion", "ok"]]
    _exactly("scenarios", OK_SCENARIOS, done)
    _need(done == list(OK_SCENARIOS), f"congestion scenarios are out of order: {done}")

    frames = [(f[2], f[3], f[4]) for f in split if f[:2] == ["congestion", "frame"]]
    _exactly("frames", tuple(name for name, *_ in FRAMES), [name for name, *_ in frames])
    _need([name for name, *_ in frames] == [name for name, *_ in FRAMES], "congestion frames are out of order")
    for (name, sn, hexed), (_, wanted_sn, _, _), (_, wanted) in zip(frames, FRAMES, FRAME_HEX, strict=True):
        _need(re.fullmatch(r"[0-9a-f]+", hexed) is not None, f"congestion frame {name} is not lowercase hexadecimal")
        _need(sn == str(wanted_sn), f"congestion frame {name} carries sequence number {sn}, the exam requires {wanted_sn}")
        _need(hexed == wanted, f"congestion frame {name} is {hexed}, the host reference writes {wanted}")

    counts = [(f[2], f[3]) for f in split if f[:2] == ["congestion", "count"]]
    _exactly("counts", tuple(label for label, _ in COUNTS), [label for label, _ in counts])
    _need([label for label, _ in counts] == [label for label, _ in COUNTS], "congestion counts are out of order")
    for (label, seen), (_, wanted) in zip(counts, COUNTS, strict=True):
        _need(seen == str(wanted), f"congestion count {label} is {seen}, the exam requires {wanted}")

    refused = [(f[2], f[3]) for f in split if f[:2] == ["congestion", "refused"]]
    _exactly("refusals", tuple(name for name, _ in REFUSED_SCENARIOS), [name for name, _ in refused])
    _need([name for name, _ in refused] == [name for name, _ in REFUSED_SCENARIOS], "congestion refusals are out of order")
    wrong = [f"{name}={cls} (expected {dict(REFUSED_SCENARIOS)[name]})" for name, cls in refused if cls != dict(REFUSED_SCENARIOS)[name]]
    _need(not wrong, f"congestion refusal classes differ: {', '.join(wrong)}")
    return len(done) + len(frames) + len(counts), len(refused)


def _replaced(good: list[str], old: str, new: str) -> list[str]:
    _need(old in good, f"control: {old!r} is not in the honest transcript")
    return [new if line == old else line for line in good]


def _flip(hexed: str) -> str:
    return hexed[:-1] + ("0" if hexed[-1] != "0" else "1")


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a congestion exam line", [*good, "qos ok every-priority-round-trips"]),
        ("an unrecognised kind of line", [*good, "congestion lost 1 2"]),
        ("a scenario line with an extra field", [*good[:-1], good[-1] + " extra"]),
        ("the first two scenarios swapped", [good[1], good[0], *good[2:]]),
    ]
    for index, line in enumerate(good):
        out.append((f"the line {' '.join(line.split()[1:3])} missing", good[:index] + good[index + 1 :]))
    for name in OK_SCENARIOS:
        out.append((f"the scenario {name} reported twice", [*good, f"congestion ok {name}"]))
    for (name, sn, _, _), (_, hexed) in zip(FRAMES, FRAME_HEX, strict=True):
        line = f"congestion frame {name} {sn} {hexed}"
        out.append((f"the frame {name} with its last digit changed", _replaced(good, line, f"congestion frame {name} {sn} {_flip(hexed)}")))
        out.append((f"the frame {name} in capitals", _replaced(good, line, f"congestion frame {name} {sn} {hexed.upper()}")))
        out.append((f"the frame {name} one sequence number on", _replaced(good, line, f"congestion frame {name} {sn + 1} {hexed}")))
        out.append((f"the frame {name} one sequence number back", _replaced(good, line, f"congestion frame {name} {sn - 1} {hexed}")))
    for label, count in COUNTS:
        line = f"congestion count {label} {count}"
        out.append((f"{label} one over", _replaced(good, line, f"congestion count {label} {count + 1}")))
        out.append((f"{label} one under", _replaced(good, line, f"congestion count {label} {count - 1}")))
    classes = sorted({cls for _, cls in REFUSED_SCENARIOS})
    for name, cls in REFUSED_SCENARIOS:
        other = next(candidate for candidate in classes if candidate != cls)
        out.append((f"{name} refused as {other}", _replaced(good, f"congestion refused {name} {cls}", f"congestion refused {name} {other}")))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (len(OK_SCENARIOS) + len(FRAMES) + len(COUNTS), len(REFUSED_SCENARIOS)), f"congestion: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise CongestionError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except CongestionError:
            refused += 1
            continue
        raise CongestionError(f"control: the congestion judge accepted {label}")
    return refused


def reference_agrees() -> None:
    """The two frames differ, the first carries no extension and the second states Block."""
    _need(len({hexed for _, hexed in FRAME_HEX}) == len(FRAME_HEX), "two frames are the same bytes")
    _need(FRAMES[1][1] == FRAMES[0][1] + 1, "the frame after the drops does not follow the first by one sequence number")
    first = zenoh_wire.push_put(KEY, ATTACHMENT, PAYLOAD, True)
    _need(FRAME_HEX[0][1] == zenoh_wire.frame(FIRST_SN, first).hex(), "the default frame wrote an extension")
    _need(len({name for name, _ in COUNTS}) == len(COUNTS), "a count label is used twice")
    _need(len({name for name, _ in REFUSED_SCENARIOS}) == len(REFUSED_SCENARIOS), "a refused scenario name is used twice")


def all_controls() -> int:
    reference_agrees()
    return transcript_controls()


# Held here as well as in the item, so the gate stays correct once the item is retired. Both are exact.
PINNED_CASES = 17
PINNED_CONTROLS = 50
