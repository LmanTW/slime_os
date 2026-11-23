"""Judge the Zenoh Profile 0 exam for the QoS a PUSH carries: priority, congestion control and express.

Profile 0 reads the network QoS extension and discards its value, and its encoder never writes one. The
change keeps the value on a published sample and writes it back as eclipse-zenoh 1.0.0 does: priority in
bits 0 to 2, Block in bit 3, express in bit 4, and no extension at all when the value is the PUSH default
(priority 5, drop, not express).

The Rust tests under `zenoh_qos::` print one `[zenoh-exam] qos ...` line for each thing they did. This
module owns what those lines must be, and nothing here reads the Rust:

* the scenarios, each printed once and in order;
* the FRAME the encoder wrote for each QoS value, which the host reference `zenoh_wire` must reproduce
  byte for byte;
* the QoS the decoder read back from each of those frames;
* every refused input, with the bytes the test fed in and the class it was refused with.

Like the other judges it is trusted only after it refuses a mutation of an honest transcript.
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
    "encode-writes-the-upstream-layout",
    "default-qos-writes-no-extension",
    "decode-keeps-the-qos-value",
    "every-priority-round-trips",
)

# (name, priority, block, express). The first eight hold every priority at drop and not express; the rest
# set each flag alone and together, and the last is the largest value the extension carries, 0x1F.
QOS_CASES = (
    *((f"priority-{n}", n, False, False) for n in range(8)),
    ("block-at-5", 5, True, False),
    ("express-at-5", 5, False, True),
    ("block-express-at-0", 0, True, True),
    ("block-express-at-7", 7, True, True),
)


def qos_frame(index: int) -> bytes:
    _, priority, block, express = QOS_CASES[index]
    return zenoh_wire.frame(FIRST_SN + index, zenoh_wire.push_put_qos(KEY, ATTACHMENT, PAYLOAD, True, priority, block, express))


FRAMES = tuple((case[0], qos_frame(index).hex()) for index, case in enumerate(QOS_CASES))
DECODED = tuple((name, priority, int(block), int(express)) for name, priority, block, express in QOS_CASES)


def _refused_frame(extension: bytes) -> bytes:
    header = zenoh_wire.ID_PUSH | zenoh_wire.FLAG_N | zenoh_wire.FLAG_M | zenoh_wire.FLAG_Z
    put = bytes([zenoh_wire.ID_PUT | zenoh_wire.FLAG_Z, zenoh_wire.EXT_ATTACHMENT]) + zenoh_wire.prefixed(ATTACHMENT) + zenoh_wire.prefixed(PAYLOAD)
    body = bytes([header]) + zenoh_wire.leb128(0) + zenoh_wire.prefixed(KEY.encode()) + extension
    return zenoh_wire.frame(FIRST_SN, body + put)


# (name, class, bytes the test feeds the decoder). The classes are the ones the decoder already gives the
# same inputs behind a DECLARE or an OAM: a value over 0x1F is malformed, an extension id other than the
# optional network QoS is unsupported.
REFUSED = (
    ("value-over-0x1f", "malformed-message", _refused_frame(bytes([zenoh_wire.EXT_QOS_NETWORK, 0x20]))),
    ("qos-marked-mandatory", "unsupported-extension", _refused_frame(bytes([zenoh_wire.EXT_QOS_NETWORK | 0x10, 8]))),
    ("extension-other-than-qos", "unsupported-extension", _refused_frame(bytes([0x22, 8]))),
)
REFUSED_CASES = tuple((name, cls, data.hex()) for name, cls, data in REFUSED)

SHAPES = {
    ("qos", "ok"): 3,
    ("qos", "frame"): 4,
    ("qos", "decoded"): 6,
    ("qos", "refused"): 5,
}


class QosError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise QosError(message)


def good_lines() -> list[str]:
    return (
        [f"qos ok {name}" for name in OK_SCENARIOS]
        + [f"qos frame {name} {hexed}" for name, hexed in FRAMES]
        + [f"qos decoded {name} {priority} {block} {express}" for name, priority, block, express in DECODED]
        + [f"qos refused {name} {cls} {hexed}" for name, cls, hexed in REFUSED_CASES]
    )


def _exactly(label: str, wanted: tuple[str, ...], seen: list[str]) -> None:
    missing = [name for name in wanted if name not in seen]
    extra = [name for name in seen if name not in wanted]
    repeated = sorted({name for name in seen if seen.count(name) > 1})
    _need(not missing, f"qos {label} missing: {', '.join(missing[:4])}")
    _need(not extra, f"qos {label} not in the exam: {', '.join(extra[:4])}")
    _need(not repeated, f"qos {label} reported more than once: {', '.join(repeated[:4])}")


def judge(lines: list[str]) -> tuple[int, int]:
    """Check a transcript against the exam; returns (cases, refusals), a case being a scenario or a decoded value."""
    split = [line.split() for line in lines]
    for line, fields in zip(lines, split, strict=True):
        _need(fields[:1] == ["qos"], f"qos: a record that is not a qos exam line: {line!r}")
        kind = tuple(fields[:2])
        _need(kind in SHAPES, f"qos: unrecognised line: {line}")
        _need(len(fields) == SHAPES[kind], f"qos: a {kind[1]} line has {len(fields)} fields, expected {SHAPES[kind]}: {line}")

    done = [f[2] for f in split if f[:2] == ["qos", "ok"]]
    _exactly("scenarios", OK_SCENARIOS, done)
    _need(done == list(OK_SCENARIOS), f"qos scenarios are out of order: {done}")

    frames = [(f[2], f[3]) for f in split if f[:2] == ["qos", "frame"]]
    _exactly("frames", tuple(name for name, _ in FRAMES), [name for name, _ in frames])
    _need([name for name, _ in frames] == [name for name, _ in FRAMES], "qos frames are out of order")
    for (name, hexed), (_, wanted) in zip(frames, FRAMES, strict=True):
        _need(re.fullmatch(r"[0-9a-f]+", hexed) is not None, f"qos frame {name} is not lowercase hexadecimal")
        _need(hexed == wanted, f"qos frame {name} is {hexed}, the host reference writes {wanted}")

    decoded = [tuple(f[2:]) for f in split if f[:2] == ["qos", "decoded"]]
    _exactly("decoded values", tuple(name for name, *_ in DECODED), [d[0] for d in decoded])
    _need([d[0] for d in decoded] == [d[0] for d in DECODED], "qos decoded values are out of order")
    for seen, wanted in zip(decoded, DECODED, strict=True):
        _need(seen == tuple(str(v) for v in wanted), f"qos decoded {wanted[0]}: {' '.join(seen[1:])}, the frame carries {' '.join(str(v) for v in wanted[1:])}")

    refused = [tuple(f[2:]) for f in split if f[:2] == ["qos", "refused"]]
    _exactly("refusals", tuple(name for name, *_ in REFUSED_CASES), [r[0] for r in refused])
    _need([r[0] for r in refused] == [r[0] for r in REFUSED_CASES], "qos refusals are out of order")
    for seen, wanted in zip(refused, REFUSED_CASES, strict=True):
        _need(seen[2] == wanted[2], f"qos refusal {wanted[0]} was fed {seen[2]}, the host reference builds {wanted[2]}")
        _need(seen[1] == wanted[1], f"qos refusal {wanted[0]} was refused as {seen[1]}, the exam requires {wanted[1]}")
    return len(done) + len(decoded), len(refused)


def _replaced(good: list[str], old: str, new: str) -> list[str]:
    _need(old in good, f"control: {old!r} is not in the honest transcript")
    return [new if line == old else line for line in good]


def _flip(hexed: str) -> str:
    return hexed[:-1] + ("0" if hexed[-1] != "0" else "1")


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a qos exam line", [*good, "subscribers ok declare-several-own-subscribers"]),
        ("an unrecognised kind of line", [*good, "qos dropped 1 2"]),
        ("a scenario line with an extra field", [*good[:-1], good[-1] + " extra"]),
        ("the first two scenarios swapped", [good[1], good[0], *good[2:]]),
    ]
    for index, line in enumerate(good):
        out.append((f"the line {' '.join(line.split()[1:3])} missing", good[:index] + good[index + 1 :]))
    for name in OK_SCENARIOS:
        out.append((f"the scenario {name} reported twice", [*good, f"qos ok {name}"]))
    for name, hexed in FRAMES:
        line = f"qos frame {name} {hexed}"
        out.append((f"the frame {name} with its last digit changed", _replaced(good, line, f"qos frame {name} {_flip(hexed)}")))
        out.append((f"the frame {name} in capitals", _replaced(good, line, f"qos frame {name} {hexed.upper()}")))
    for name, priority, block, express in DECODED:
        line = f"qos decoded {name} {priority} {block} {express}"
        out.append((f"{name} decoded at priority {(priority + 1) % 8}", _replaced(good, line, f"qos decoded {name} {(priority + 1) % 8} {block} {express}")))
        out.append((f"{name} decoded with block flipped", _replaced(good, line, f"qos decoded {name} {priority} {1 - block} {express}")))
        out.append((f"{name} decoded with express flipped", _replaced(good, line, f"qos decoded {name} {priority} {block} {1 - express}")))
    classes = sorted({cls for _, cls, _ in REFUSED_CASES})
    for name, cls, hexed in REFUSED_CASES:
        line = f"qos refused {name} {cls} {hexed}"
        other = next(candidate for candidate in classes if candidate != cls)
        out.append((f"{name} refused as {other}", _replaced(good, line, f"qos refused {name} {other} {hexed}")))
        out.append((f"{name} fed other bytes", _replaced(good, line, f"qos refused {name} {cls} {_flip(hexed)}")))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (len(OK_SCENARIOS) + len(DECODED), len(REFUSED_CASES)), f"qos: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise QosError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except QosError:
            refused += 1
            continue
        raise QosError(f"control: the qos judge accepted {label}")
    return refused


def reference_agrees() -> None:
    """The host reference writes a distinct frame for each value, and the default value writes no extension."""
    _need(len({name for name, _ in FRAMES}) == len(FRAMES), "a frame name is used twice")
    _need(len({hexed for _, hexed in FRAMES}) == len(FRAMES), "two QoS values wrote the same bytes")
    default = zenoh_wire.push_put_qos(KEY, ATTACHMENT, PAYLOAD, True, 5, False, False)
    _need(default == zenoh_wire.push_put(KEY, ATTACHMENT, PAYLOAD, True), "the default QoS value wrote an extension")
    for name, priority, block, express in QOS_CASES:
        value = zenoh_wire.qos_value(priority, block, express)
        _need(value <= 0x1F, f"{name} is {value:#x}, over the 0x1F the extension carries")


def all_controls() -> int:
    reference_agrees()
    return transcript_controls()


# Held here as well as in the item, so the gate stays correct once the item is retired. Both are exact.
PINNED_CASES = 19
PINNED_CONTROLS = 106
