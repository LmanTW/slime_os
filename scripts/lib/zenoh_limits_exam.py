"""Judge the Zenoh service limits record, `contracts/zenoh-service-limits/v1`, and the places that must carry it.

Two kinds of fact, and neither reads the encoder's own constants:

* the encoder `zenoh_limits.encode`. The schema's layout adds up to the record size it states and equals a copy held
  here, and for a set of honest limits the encoder's bytes equal bytes written again here with `struct`. The encoder
  refuses each input the contract forbids, and a decoder written here refuses each corruption of an honest record;
* declarations the files must hold, read by pattern: the system spec and manifest fields, the builder, the root's read of
  the record, the service's use of the limits and the host tests. A pattern shows that code exists. What the code does is
  graded by the host tests it names and by the booted composition.

Like the other judges it is trusted only after it refuses a mutation of an honest input.
"""

from __future__ import annotations

import struct

import zenoh_client_exam as client
import zenoh_facts as facts
import zenoh_limits as limits
from harness import ROOT

RECORD_PIN = [
    ("magic", 8, False, True), ("format_version", 4, False, False), ("record_size", 4, False, False),
    ("required_flags", 8, False, False), ("holders", 4, False, False), ("ring_slots", 4, False, False),
    ("sample_bytes", 4, False, False), ("key_bytes", 4, False, False), ("local_subscriptions", 4, False, False),
    ("stack_bytes", 4, False, False),
]
PINNED = {
    "formatVersion": 1, "recordMagic": int.from_bytes(b"SLIMEZL\0", "little"), "recordBytes": 48, "maxCount": 65535,
    "maxSampleBytes": 1048576, "maxKeyBytes": 129, "maxStackBytes": 4294967295, "limitsCursor": 4294967295,
}
MAGIC = b"SLIMEZL\0"
# Every value differs, so a layout with two limits swapped writes different bytes and the encoder controls can tell.
HONEST_LIMITS = {"holders": 4, "ring_slots": 5, "sample_bytes": 12, "key_bytes": 129, "local_subscriptions": 3, "stack_bytes": 65536}


class LimitsExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise LimitsExamError(message)


def schema_facts(text: str | None = None) -> list[str]:
    """The facts about the schema, one line each; raises for the first that does not hold."""
    text = limits.SCHEMA.read_text(encoding="utf-8") if text is None else text
    try:
        found = client.constants(text)
        layout = client.layout(text, "recordLayout")
        names = client.record_fields(text, "LimitsRecord")
    except client.ClientError as error:
        raise LimitsExamError(str(error)) from error
    out = []
    for name, wanted in PINNED.items():
        _need(found.get(name) == wanted, f"limits: {name} is {found.get(name)}, this version requires {wanted}")
        out.append(f"constant {name} {wanted}")
    _need([name for name, *_ in layout] == names, "limits: the layout does not list the fields of its record in order")
    _need(sum(width for _, width, _, _ in layout) == found["recordBytes"], "limits: the layout does not add up to recordBytes")
    _need(layout == RECORD_PIN, "limits: the layout differs from the pinned layout")
    _need([name for name, *_ in layout][4:] == list(limits.LIMIT_FIELDS), "limits: the six limits are not the fields of `Limits` in order")
    out.append(f"layout record {found['recordBytes']}")
    return out


def reference(values: dict[str, int], text: str | None = None) -> bytes:
    """The record written again with `struct` from the pinned layout."""
    found = client.constants(limits.SCHEMA.read_text(encoding="utf-8") if text is None else text)
    return struct.pack(
        "<8sIIQIIIIII", MAGIC, found["formatVersion"], found["recordBytes"], 0,
        *(values[name] for name in limits.LIMIT_FIELDS),
    )


def decode(data: bytes) -> dict[str, int]:
    """The limits a record holds. Every field is checked."""
    _need(len(data) == 48, "record: not 48 bytes")
    magic, version, size, flags, *values = struct.unpack("<8sIIQIIIIII", data)
    _need(magic == MAGIC, "record: wrong magic")
    _need(version == 1, "record: unknown format version")
    _need(size == 48, "record: size is not 48")
    _need(flags == 0, "record: a required flag is set")
    found = dict(zip(limits.LIMIT_FIELDS, values, strict=True))
    for name, (low, high) in limits.bounds(PINNED).items():
        _need(low <= found[name] <= high, f"record: {name} outside {low} to {high}")
    return found


HONEST = (
    ("the sample limits", HONEST_LIMITS),
    ("every limit at its lowest", {name: 1 for name in limits.LIMIT_FIELDS}),
    ("every count at its highest", {**HONEST_LIMITS, "holders": 65535, "ring_slots": 65535, "local_subscriptions": 65535}),
    ("the longest sample", {**HONEST_LIMITS, "sample_bytes": 1048576}),
    ("the longest key", {**HONEST_LIMITS, "key_bytes": 129}),
    ("the largest stack", {**HONEST_LIMITS, "stack_bytes": 4294967295}),
    ("two holders and two rows", {"holders": 2, "ring_slots": 4, "sample_bytes": 12, "key_bytes": 129, "local_subscriptions": 3, "stack_bytes": 32768}),
)


def honest_cases() -> int:
    for name, values in HONEST:
        written = limits.encode(values)
        _need(written == reference(values), f"limits: the encoder's bytes for {name} differ from the reference")
        _need(decode(written) == values, f"limits: the bytes for {name} do not decode back to the limits")
    return len(HONEST)


def _edit(old: str, new: str):
    def apply(text: str) -> str:
        _need(text.count(old) == 1, f"control: {old!r} found {text.count(old)} times, expected 1")
        return text.replace(old, new)
    return apply


def _field(name: str, width: int, signed: str = "false", array: str = "false") -> str:
    return f'{{ name = "{name}"; width = {width}; signed = {signed}; byteArray = {array}; }};'


SCHEMA_EDITS = (
    ("the magic changed", _edit("recordMagic :: Int = 21491351925902419;", "recordMagic :: Int = 21491351925902418;")),
    ("the version raised", _edit("formatVersion :: Int = 1;", "formatVersion :: Int = 2;")),
    ("the record size changed", _edit("recordBytes :: Int = 48;", "recordBytes :: Int = 49;")),
    ("the count bound raised", _edit("maxCount :: Int = 65535;", "maxCount :: Int = 65536;")),
    ("the sample bound raised", _edit("maxSampleBytes :: Int = 1048576;", "maxSampleBytes :: Int = 1048577;")),
    ("the key bound raised", _edit("maxKeyBytes :: Int = 129;", "maxKeyBytes :: Int = 130;")),
    ("the stack bound lowered", _edit("maxStackBytes :: Int = 4294967295;", "maxStackBytes :: Int = 4294967294;")),
    ("the cursor changed", _edit("limitsCursor :: Int = 4294967295;", "limitsCursor :: Int = 4294967294;")),
    ("a field widened", _edit(_field("holders", 4), _field("holders", 8))),
    ("a field made signed", _edit(_field("stack_bytes", 4), _field("stack_bytes", 4, "true"))),
    ("the magic made a number", _edit(_field("magic", 8, array="true"), _field("magic", 8))),
    ("a limit renamed", _edit(_field("key_bytes", 4), _field("key_size", 4))),
    ("a limit dropped from the layout", _edit("  " + _field("stack_bytes", 4) + "\n};", "};")),
    ("a limit dropped from the record", _edit("  stack_bytes : Int;\n", "")),
    ("a field added to the record only", _edit("  holders : Int;\n", "  holders : Int;\n  extra : Int;\n")),
    ("a constant stated twice", _edit("maxCount :: Int = 65535;", "maxCount :: Int = 65535;\nmaxCount :: Int = 65535;")),
    ("a line that is not a field", _edit(_field("stack_bytes", 4), "not a field")),
)


def schema_controls() -> int:
    schema_facts()
    refused = 0
    for label, edit in SCHEMA_EDITS:
        try:
            schema_facts(edit(limits.SCHEMA.read_text(encoding="utf-8")))
        except LimitsExamError:
            refused += 1
            continue
        raise LimitsExamError(f"control: the schema facts accepted {label}")
    return refused


def _try(values: dict[str, object]) -> bool:
    try:
        limits.encode(values)
    except limits.LimitsError:
        return False
    return True


def _with(**changes: object) -> dict[str, object]:
    return {**HONEST_LIMITS, **changes}


REFUSED_INPUTS = tuple(
    [(f"{name} of zero", _with(**{name: 0})) for name in limits.LIMIT_FIELDS]
    + [
        ("holders above the count bound", _with(holders=65536)),
        ("ring slots above the count bound", _with(ring_slots=65536)),
        ("local subscriptions above the count bound", _with(local_subscriptions=65536)),
        ("a sample above its bound", _with(sample_bytes=1048577)),
        ("a key above its bound", _with(key_bytes=130)),
        ("a stack above 32 bits", _with(stack_bytes=4294967296)),
        ("a negative limit", _with(holders=-1)),
        ("a limit that is a boolean", _with(holders=True)),
        ("a limit that is text", _with(holders="4")),
        ("a limit that is a float", _with(holders=4.0)),
        ("a missing limit", {k: v for k, v in HONEST_LIMITS.items() if k != "stack_bytes"}),
        ("an extra field", {**HONEST_LIMITS, "future_limit": 1}),
        ("no fields", {}),
    ]
)


def input_controls() -> int:
    refused = 0
    for label, values in REFUSED_INPUTS:
        if _try(values):
            raise LimitsExamError(f"control: the encoder accepted {label}")
        refused += 1
    return refused


def _flip(offset: int, value: int):
    def apply(data: bytes) -> bytes:
        return data[:offset] + bytes([value]) + data[offset + 1 :]
    return apply


def _put(offset: int, value: int):
    def apply(data: bytes) -> bytes:
        return data[:offset] + value.to_bytes(4, "little") + data[offset + 4 :]
    return apply


CORRUPTIONS = (
    ("a record shorter than itself", lambda data: data[:47]),
    ("a record with a byte added", lambda data: data + b"\0"),
    ("an empty record", lambda data: b""),
    ("a wrong magic", _flip(0, ord("X"))),
    ("a wrong version", _flip(8, 2)),
    ("a zero version", _flip(8, 0)),
    ("a wrong size", _flip(12, 49)),
    ("a required flag set", _flip(16, 1)),
    ("a required flag set in the high word", _flip(23, 1)),
    ("a record with holders of zero", _put(24, 0)),
    ("a record with holders above the bound", _put(24, 65536)),
    ("a record with ring slots of zero", _put(28, 0)),
    ("a record with ring slots above the bound", _put(28, 65536)),
    ("a record with a sample of zero bytes", _put(32, 0)),
    ("a record with a sample above the bound", _put(32, 1048577)),
    ("a record with a key of zero bytes", _put(36, 0)),
    ("a record with a key above the bound", _put(36, 130)),
    ("a record with local subscriptions of zero", _put(40, 0)),
    ("a record with local subscriptions above the bound", _put(40, 65536)),
    ("a record with a stack of zero bytes", _put(44, 0)),
)


def table_controls() -> int:
    honest = limits.encode(HONEST_LIMITS)
    _need(decode(honest) == HONEST_LIMITS, "control: the honest record does not decode back to its limits")
    refused = 0
    for label, corrupt in CORRUPTIONS:
        mutated = corrupt(honest)
        _need(mutated != honest, f"control: {label} did not change the record")
        try:
            decode(mutated)
        except LimitsExamError:
            refused += 1
            continue
        raise LimitsExamError(f"control: the decoder accepted {label}")
    return refused


ENCODER_EDITS = (
    ("two limits swapped in the layout", _edit(_field("holders", 4) + "\n  " + _field("ring_slots", 4), _field("ring_slots", 4) + "\n  " + _field("holders", 4))),
    ("the version widened", _edit(_field("format_version", 4), _field("format_version", 8))),
    ("the size and the flags swapped", _edit(_field("record_size", 4) + "\n  " + _field("required_flags", 8), _field("required_flags", 8) + "\n  " + _field("record_size", 4))),
)


def encoder_controls() -> int:
    text = limits.SCHEMA.read_text(encoding="utf-8")
    want = reference(HONEST_LIMITS)
    refused = 0
    for label, edit in ENCODER_EDITS:
        try:
            got = limits.encode(HONEST_LIMITS, edit(text))
        except (limits.LimitsError, KeyError, client.ClientError):
            refused += 1
            continue
        if got == want:
            raise LimitsExamError(f"control: the encoder wrote the reference bytes under a schema with {label}")
        refused += 1
    return refused


def distinct_controls() -> None:
    """No two controls share a label, and none corrupts the same input the same way as another."""
    text = limits.SCHEMA.read_text(encoding="utf-8")
    honest = limits.encode(HONEST_LIMITS)
    items: list[tuple[str, str, str, object]] = []
    items += [("schema edit", "schema", label, edit(text)) for label, edit in SCHEMA_EDITS]
    items += [("encoder edit", "schema", label, edit(text)) for label, edit in ENCODER_EDITS]
    items += [("refused input", "limits", label, repr(sorted(values.items(), key=str))) for label, values in REFUSED_INPUTS]
    items += [("record corruption", "record", label, corrupt(honest)) for label, corrupt in CORRUPTIONS]
    labels: dict[str, str] = {}
    values: dict[tuple[str, object], tuple[str, str]] = {}
    for family, base, label, value in items:
        _need(label not in labels, f"control: the label {label!r} is used by a {labels.get(label)} and a {family}")
        labels[label] = family
        key = (base, value)
        _need(key not in values, f"control: {family} {label!r} corrupts {base} the same way as {values.get(key, ('', ''))[0]} {values.get(key, ('', ''))[1]!r}")
        values[key] = (family, label)


def encoder_all_controls() -> int:
    distinct_controls()
    return schema_controls() + input_controls() + table_controls() + encoder_controls()


# Where the limits must be declared and carried. Each is read by pattern from the files, and checked first on a synthetic
# file set. A pattern shows that code exists. The host tests the facts name, and the booted composition, show what it does.
SPEC = "contracts/system-spec/v1/schema.zt"
MANIFEST = "contracts/generation-manifest/v1/schema.zt"
SERVICE = "components/services/zenoh-service/src/main.rs"
CORE = "components/lib/src/zenoh_service.rs"
ROOT_IPC = "slime-root/src/ipc.rs"
ROOT_GENERATION = "slime-root/src/generation.rs"
BUILDER = "scripts/build/generation_resources.py"

FACTS: tuple[facts.Fact, ...] = (
    ("spec-type", SPEC, r"^SystemZenohLimits :: type \{$", "SystemZenohLimits :: type {"),
    ("spec-field", SPEC, r"^\s*zenohLimits\? : SystemZenohLimits;$", "  zenohLimits? : SystemZenohLimits;"),
    ("manifest-type", MANIFEST, r"^ZenohLimitsEntry :: type \{$", "ZenohLimitsEntry :: type {"),
    ("manifest-field", MANIFEST, r"^\s*zenohLimits\? : ZenohLimitsEntry;$", "  zenohLimits? : ZenohLimitsEntry;"),
    ("builder-function", BUILDER, r"^def build_zenoh_limits\(", "def build_zenoh_limits(manifest: dict) -> bytes:"),
    ("builder-encoder", BUILDER, r"zenoh_limits\.encode\(", "        return zenoh_limits.encode(limits)"),
    ("builder-contract", BUILDER, r"zenoh-service-grants/v1", "    # the stack is checked against the rows by zenoh-service-grants/v1"),
    ("object-id", "scripts/lib/system_spec.py", r'"zenoh-limits"', '        ("zenohLimitsObject", "zenoh-limits"),'),
    ("root-locates", ROOT_GENERATION, r"^pub\(crate\) fn zenoh_limits_object<", "pub(crate) fn zenoh_limits_object<'a>("),
    ("root-serves", ROOT_IPC, r"\bLIMITS_CURSOR\b", "const LIMITS_CURSOR: usize = 0xFFFF_FFFF;"),
    ("root-test", ROOT_IPC, r"^\s*fn the_limits_cursor_returns_the_record\(\)", "    fn the_limits_cursor_returns_the_record() {"),
    ("service-reads", SERVICE, r"\bLIMITS_CURSOR\b", "    let record = zenoh_grants_read(LIMITS_CURSOR, &mut limits_page)?;"),
    ("service-decodes", SERVICE, r"\bLimits::decode\(", "    let limits = Limits::decode(&limits_page[..read])?;"),
    ("service-checks", SERVICE, r"\bfn within_ceilings\(", "fn within_ceilings(limits: &Limits) -> bool {"),
    ("core-rows", CORE, r"rows\.is_empty\(\) \|\| rows\.len\(\) > R", "        if rows.is_empty() || rows.len() > R || P != params.bounds.payload || params.fragments {"),
    ("core-test", CORE, r"^\s*fn a_table_with_fewer_rows_than_the_ceiling_is_served\(\)", "    fn a_table_with_fewer_rows_than_the_ceiling_is_served() {"),
    ("recipe", "just/hardware.just", r"^zenoh_service_limits_check:$", "zenoh_service_limits_check:"),
)


def check_facts() -> int:
    def read(path: str) -> str:
        try:
            return (ROOT / path).read_text(encoding="utf-8")
        except OSError as error:
            raise LimitsExamError(f"{path} cannot be read: {error}") from error
    try:
        return facts.check(FACTS, read)
    except facts.FactsError as error:
        raise LimitsExamError(str(error)) from error


def fact_controls() -> int:
    try:
        return facts.controls(FACTS)
    except facts.FactsError as error:
        raise LimitsExamError(str(error)) from error
