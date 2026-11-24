"""Judge the Rust z-serial framer against frames that `z-serial` 0.2.3 wrote.

The serial link of `docs/decisions/zenoh-link-transports.md` frames every Zenoh batch as one z-serial frame. The Rust test under
the module path `zenoh_serial::` reads `scripts/lib/zserial_vectors.txt` and prints one `[zenoh-exam] zserial ...` line for each
thing it did. This module owns what those lines must be. Nothing here reads the Rust of the framer.

* Each frame the stock writer produced is the frame the Rust writer produces for the same data.
* The Rust reader takes each wire the stock reader took, and returns the same data.
* The Rust reader refuses each wire the stock reader refused, with the class `zserial_wire` names for it.
* The Rust writer refuses a payload over 1500 bytes, and the Rust reader refuses a frame whose length field names more.
* A receiver that is fed bytes in chunks delivers the frames and counts the drops that `zserial_wire.stream` gives.

The expectation is derived from `zserial_wire`, which reproduces every stock frame before it is used. The judge is trusted
only after it refuses a corrupted transcript, so the controls run before the test does.
"""

from __future__ import annotations

import re

import zserial_wire as wire
from harness import ROOT

LIB = "components/lib/src/lib.rs"
ITEM = ROOT / ".tasks" / "items" / "zenoh-serial-frame.zt"
FACTS = (("serial-module", LIB, r"^pub mod zenoh_serial;$", "pub mod zenoh_serial;"),)

# Receive scenarios: a name and the chunks, in hex. The first scenario feeds one frame whole.
_GOOD = wire.encode(bytes([0x11, 0x22, 0x00, 0x33]))
_OTHER = wire.encode(bytes([0x00, 0x11, 0x00]))
_BAD_CRC = bytearray(_GOOD)
_BAD_CRC[-2] ^= 0x01
STREAMS = (
    ("whole", [_GOOD]),
    ("byte-at-a-time", [bytes([b]) for b in _GOOD]),
    ("two-in-one-chunk", [_GOOD + _OTHER]),
    ("split-inside-a-run", [_GOOD[:3], _GOOD[3:7], _GOOD[7:]]),
    ("garbage-then-frame", [b"\x07\x07\x00" + _GOOD]),
    ("overrun-then-frame", [bytes([1]) * 1600 + b"\x00" + _GOOD]),
    ("leading-sentinels", [b"\x00\x00" + _GOOD]),
    ("bad-crc-then-good", [bytes(_BAD_CRC) + _GOOD]),
)


class FrameError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise FrameError(message)


def read_file(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        raise FrameError(f"{path} cannot be read: {error}") from error


def check_facts() -> int:
    for name, path, pattern, _example in FACTS:
        _need(re.search(pattern, read_file(path), re.MULTILINE) is not None, f"{name}: {path} does not match {pattern}")
    return len(FACTS)


def _hex(data: bytes) -> str:
    return data.hex() if data else "-"


def good_lines(vectors: list[list[str]] | None = None, streams: tuple = STREAMS) -> list[str]:
    """What an honest run prints: the writer, the reader and the receiver, in the order of the vector file and the scenarios."""
    rows = wire.read_vectors() if vectors is None else vectors
    out: list[str] = []
    for row in rows:
        if row[0] == "frame":
            _, name, data, _stock = row
            out.append(f"frame {name} {wire.encode(b'' if data == '-' else bytes.fromhex(data)).hex()}")
        elif row[0] == "decode":
            name, hexed = row[1], row[2]
            try:
                data = wire.decode(bytes.fromhex(hexed))
                out.append(f"decode {name} ok {_hex(data)}")
            except wire.ZSerialError as error:
                out.append(f"decode {name} refused {error.kind}")
        elif row[0] == "limit":
            out.append(f"limit {row[1]} refused size")
    for name, chunks in streams:
        delivered, dropped = wire.stream(list(chunks))
        out.append(f"stream {name} {len(delivered)} {dropped} {','.join(_hex(d) for d in delivered) or '-'}")
    return out


def judge(lines: list[str], vectors: list[list[str]] | None = None, streams: tuple = STREAMS) -> int:
    """Returns the number of lines that hold. Any line that does not raises, naming it."""
    expected = good_lines(vectors, streams)
    _need(len(lines) == len(expected), f"zserial: the test printed {len(lines)} lines, the exam requires {len(expected)}")
    for index, (line, want) in enumerate(zip(lines, expected, strict=True)):
        _need(line == want, f"zserial: line {index} is {line[:90]!r}, the exam requires {want[:90]!r}")
    return len(expected)


def fact_controls() -> int:
    refused = 0
    for name, _path, pattern, example in FACTS:
        _need(re.search(pattern, example, re.MULTILINE) is not None, f"{name}: its example does not match its own pattern")
        _need(re.search(pattern, "pub mod zenoh_serial_other;", re.MULTILINE) is None, f"{name}: its pattern matches another module")
        refused += 1
    return refused


def _refused(label: str, lines: list[str]) -> int:
    try:
        judge(lines)
    except FrameError:
        return 1
    raise FrameError(f"control: the judge accepted {label}")


def _flip(hexed: str, index: int = 0) -> str:
    digit = "0" if hexed[index] != "0" else "1"
    return hexed[:index] + digit + hexed[index + 1 :]


def transcript_controls() -> int:
    good = good_lines()
    _need(judge(good) == len(good), "control: an honest transcript was not judged in full")
    refused = 0
    for index in range(len(good)):
        refused += _refused(f"line {index} missing", good[:index] + good[index + 1 :])
        refused += _refused(f"line {index} repeated", good[: index + 1] + good[index:])
    for index, line in enumerate(good):
        kind, name = line.split()[:2]
        if kind == "frame":
            fields = line.split()
            changed = [*good]
            changed[index] = f"frame {name} {_flip(fields[2], len(fields[2]) // 2)}"
            refused += _refused(f"frame {name} with one nibble changed", changed)
        elif kind == "decode" and line.split()[2] == "ok":
            changed = [*good]
            changed[index] = f"decode {name} refused crc"
            refused += _refused(f"decode {name} reported refused", changed)
        elif kind == "decode":
            fields = line.split()
            changed = [*good]
            changed[index] = f"decode {name} ok -"
            refused += _refused(f"decode {name} reported ok", changed)
            other = next(k for k in wire.KINDS if k != fields[3])
            changed = [*good]
            changed[index] = f"decode {name} refused {other}"
            refused += _refused(f"decode {name} refused as {other}", changed)
    streams = [i for i, line in enumerate(good) if line.startswith("stream ")]
    for index in streams:
        fields = good[index].split()
        changed = [*good]
        changed[index] = f"stream {fields[1]} {int(fields[2]) + 1} {fields[3]} {fields[4]}"
        refused += _refused(f"stream {fields[1]} with one more frame delivered", changed)
        changed = [*good]
        changed[index] = f"stream {fields[1]} {fields[2]} {int(fields[3]) + 1} {fields[4]}"
        refused += _refused(f"stream {fields[1]} with one more drop", changed)
    for label, lines in (
        ("the 1501-byte write accepted", [line.replace("limit write-1501 refused size", "limit write-1501 ok -") for line in good]),
        ("a limit refused under another class", [line.replace("limit write-1501 refused size", "limit write-1501 refused crc") for line in good]),
        ("an empty transcript", []),
        ("a transcript of one honest line", good[:1]),
        ("a transcript with a line from another marker", [*good[:-1], "linkv3 config service fixed"]),
        ("a transcript with an empty line", [*good[:-1], ""]),
    ):
        refused += _refused(label, lines)
    return refused


def _refused_with(label: str, vectors: list[list[str]], streams: tuple = STREAMS) -> int:
    """Honest lines for vectors or scenarios the judge must not take: only the reference can refuse them."""
    try:
        wire.self_test_rows(vectors)
        judge(good_lines(vectors, streams), vectors, streams)
    except (FrameError, wire.ZSerialError):
        return 1
    raise FrameError(f"control: the judge accepted {label}")


def vector_controls() -> int:
    rows = wire.read_vectors()
    _need(wire.self_test_rows(rows) == len(rows), "control: the honest vectors were not held in full")
    refused = 0
    frames = [i for i, row in enumerate(rows) if row[0] == "frame"]
    first = frames[0]
    for label, edit in (
        ("a stock frame with one nibble changed", lambda r: r[first].__setitem__(3, _flip(r[first][3], 6))),
        ("a stock frame whose data changed", lambda r: r[first].__setitem__(2, "ff" if r[first][2] == "-" else _flip(r[first][2]))),
        ("a decode refused by the stock reader, marked ok", None),
    ):
        changed = [list(row) for row in rows]
        if edit is None:
            index = next(i for i, row in enumerate(rows) if row[0] == "decode" and row[3] == "refused")
            changed[index] = [changed[index][0], changed[index][1], changed[index][2], "ok", "-"]
        else:
            edit(changed)
        refused += _refused_with(label, changed)
    changed = [list(row) for row in rows]
    index = next(i for i, row in enumerate(rows) if row[0] == "decode" and row[3] == "ok" and len(row[4]) < 20)
    changed[index][4] = "aa"
    refused += _refused_with("a decode that took a wire and returned other data", changed)
    changed = [list(row) for row in rows]
    changed.append(["frame", "extra", "00", "0000"])
    refused += _refused_with("a vector file with a frame the reference does not write", changed)
    changed = [list(row) for row in rows]
    changed.append(["tcp", "x"])
    refused += _refused_with("a vector line of an unknown kind", changed)
    return refused


def all_controls() -> int:
    return transcript_controls() + vector_controls() + fact_controls()


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptance fixes, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    refused = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(refused.group(1)) if refused else 0)
