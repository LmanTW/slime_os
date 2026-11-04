"""Encode the Zenoh service limits record of `contracts/zenoh-service-limits/v1`.

The generation builder calls `encode` with the six limits a system spec declares and stores the bytes as a resource
object. The layout comes from the contract's schema text, so no offset is written here.
`scripts/lib/zenoh_limits_exam.py` writes the same bytes again with `struct` and compares them, and refuses the same
inputs.

This module imports the standard library only. The closure identity pins this file, the schema and the builder's helper
module, and an import of another repository file would put that file's bytes outside the pin. The exam refuses any other
import. The schema is parsed here for the same reason, so the exam's parser and this one are two statements of one rule.

The encoder checks each limit against its own bound. Whether the declared stack covers the rows is the arithmetic of
`zenoh-service-grants/v1` (`requiredStack`), and the builder evaluates that contract on the rows and the limits
together. This module does not restate it.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

SCHEMA = Path(__file__).resolve().parents[2] / "contracts" / "zenoh-service-limits" / "v1" / "schema.zt"

# The fields of `Limits` in `zenoh-service-grants/v1`, in the order the record holds them.
LIMIT_FIELDS = ("holders", "ring_slots", "sample_bytes", "key_bytes", "local_subscriptions", "stack_bytes")


class LimitsError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise LimitsError(message)


def constants(text: str) -> dict[str, int]:
    """Every `name :: Int = n;` at the start of a line. A name stated twice is refused."""
    found: dict[str, int] = {}
    for match in re.finditer(r"^(\w+) :: Int = (-?\d+);", text, re.M):
        name = match.group(1)
        _need(name not in found, f"limits: {name} is stated twice")
        found[name] = int(match.group(2))
    return found


def layout(text: str, name: str) -> list[tuple[str, int, bool, bool]]:
    """The fields of the list `name`: (field, width in bytes, signed, byte array). A line that is not a field is refused."""
    block = re.search(rf"^{name} :: List WireField = \{{\n(.*?)^\}};", text, re.M | re.S)
    _need(block is not None, f"limits: the schema does not state {name}")
    fields = []
    for line in block.group(1).splitlines():
        entry = re.fullmatch(r'\s*\{ name = "(\w+)"; width = (\d+); signed = (true|false); byteArray = (true|false); \};', line)
        _need(entry is not None, f"limits: {name} has a line that is not a field: {line.strip()!r}")
        fields.append((entry.group(1), int(entry.group(2)), entry.group(3) == "true", entry.group(4) == "true"))
    return fields


def read_schema(text: str | None = None) -> tuple[dict[str, int], list[tuple[str, int, bool, bool]]]:
    text = SCHEMA.read_text(encoding="utf-8") if text is None else text
    return constants(text), layout(text, "recordLayout")


def bounds(found: dict[str, int]) -> dict[str, tuple[int, int]]:
    """The inclusive range of each limit, from the schema's constants."""
    return {
        "holders": (1, found["maxCount"]),
        "ring_slots": (1, found["maxCount"]),
        "sample_bytes": (1, found["maxSampleBytes"]),
        "key_bytes": (1, found["maxKeyBytes"]),
        "local_subscriptions": (1, found["maxCount"]),
        "stack_bytes": (1, found["maxStackBytes"]),
    }


def _pack(fields: list[tuple[str, int, bool, bool]], values: dict[str, object]) -> bytes:
    out = b""
    for name, width, signed, array in fields:
        value = values[name]
        if array:
            data = bytes(value)
            _need(len(data) == width, f"limits: {name} is {len(data)} bytes, the layout says {width}")
            out += data
        else:
            code = {1: "b", 2: "h", 4: "i", 8: "q"}[width]
            try:
                out += struct.pack("<" + (code if signed else code.upper()), value)
            except struct.error as error:
                raise LimitsError(f"limits: {name} does not fit {width} bytes: {error}") from error
    return out


def validate(limits: dict[str, object], found: dict[str, int]) -> None:
    _need(set(limits) == set(LIMIT_FIELDS), f"limits: the record holds the fields {sorted(limits)}, the contract names {sorted(LIMIT_FIELDS)}")
    for name, (low, high) in bounds(found).items():
        value = limits[name]
        _need(isinstance(value, int) and not isinstance(value, bool), f"limits: {name} is not an integer")
        _need(low <= value <= high, f"limits: {name} is {value}, the contract allows {low} to {high}")


def encode(limits: dict[str, object], text: str | None = None) -> bytes:
    """The record for `limits`, each of the six fields of `LIMIT_FIELDS`."""
    found, fields = read_schema(text)
    validate(limits, found)
    out = _pack(fields, {
        "magic": int(found["recordMagic"]).to_bytes(8, "little"), "format_version": found["formatVersion"],
        "record_size": found["recordBytes"], "required_flags": 0, **{name: limits[name] for name in LIMIT_FIELDS},
    })
    _need(len(out) == found["recordBytes"], "limits: the record is not the size the schema says")
    return out
