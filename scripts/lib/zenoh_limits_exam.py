"""Judge the Zenoh service limits record, `contracts/zenoh-service-limits/v1`, and the places that must carry it.

Four kinds of check:

* the encoder `zenoh_limits.encode`. The schema's layout adds up to the record size it states and equals a copy held
  here, and for a set of honest limits the encoder's bytes equal bytes written again here with `struct`. The encoder
  refuses each input the contract forbids, and a decoder written here refuses each corruption of an honest record;
* the encoder's imports. It imports the standard library only, so the closure pin covers every file that decides its
  bytes. The encoder parses its own schema, and this exam parses it with `zenoh_client_exam`. No control compares the
  two parsers;
* the generated Rust binding, which must equal the renderer's output byte for byte;
* declarations the files must hold, read by pattern: the system spec and manifest fields, the builder and its dispatch,
  the closure release inputs, the root's locate and dispatch, and the service's read of the record.

A pattern shows that code exists and does not show what it does. This exam runs no Rust, no builder and no service. The
implementation review checks their behaviour against the code, and the booted composition shows the rest.

Like the other judges it is trusted only after it refuses a mutation of an honest input.
"""

from __future__ import annotations

import re
import struct
import subprocess

import zenoh_client_exam as client
import zenoh_client_wire_exam as wire
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


# The generated file holds the layout: lengths, offsets and the record with `encode` and `decode`. Nothing is written by
# hand, and the decoder that checks the bounds is written beside it and reads these offsets.
GENERATED = ROOT / "components" / "proto" / "src" / "zenoh_service_limits_wire.rs"
GENERATED_HEADER = (
    "// @generated by scripts/generate/generate-zenoh-service-limits.py; do not edit.\n"
    "// Source contract: contracts/zenoh-service-limits/v1/schema.zt\n"
)


def render_raw(text: str | None = None) -> str:
    """The Rust file before rustfmt: the constants, then one struct for the record with offsets taken from the layout."""
    text = limits.SCHEMA.read_text(encoding="utf-8") if text is None else text
    found = client.constants(text)
    layout = client.layout(text, "recordLayout")
    out = [GENERATED_HEADER, "\n"]
    for name in ("formatVersion", "recordBytes", "maxCount", "maxSampleBytes", "maxKeyBytes", "maxStackBytes", "limitsCursor"):
        rust = re.sub(r"([A-Z])", r"_\1", name).upper()
        kind = "usize" if name in ("recordBytes", "limitsCursor") else "u32"
        out.append(f"pub const {rust}: {kind} = {found[name]};\n")
    magic = found["recordMagic"].to_bytes(8, "little")
    out.append("pub const RECORD_MAGIC: [u8; 8] = [" + ", ".join(f"0x{byte:02x}" for byte in magic) + "];\n\n")
    out.append(f"pub const RECORD_LEN: usize = {sum(width for _, width, _, _ in layout)};\n")
    offset = 0
    for name, width, _, _ in layout:
        out.append(f"pub const OFF_RECORD_{name.upper()}: usize = {offset};\n")
        offset += width
    out.append("\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct WireLimitsRecord {\n")
    for name, width, signed, array in layout:
        out.append(f"    pub {name}: {wire.rust_type(width, signed, array)},\n")
    out.append("}\n\nimpl WireLimitsRecord {\n")
    out.append("    pub fn decode(buf: &[u8]) -> Option<Self> {\n        if buf.len() < RECORD_LEN {\n            return None;\n        }\n        Some(Self {\n")
    for name, width, signed, array in layout:
        out.append(f"            {name}: {wire._decode_expr('RECORD', name, width, signed, array)},\n")
    out.append("        })\n    }\n\n")
    out.append("    pub fn encode(self) -> [u8; RECORD_LEN] {\n        let mut buf = [0u8; RECORD_LEN];\n")
    for name, width, signed, array in layout:
        out.append(f"        {wire._encode_stmt('RECORD', name, width, signed, array)}\n")
    out.append("        buf\n    }\n}\n")
    return "".join(out)


def render_bindings(text: str | None = None) -> str:
    raw = render_raw(text)
    process = subprocess.run(["rustfmt", "--edition", "2024", "--emit", "stdout"], input=raw, text=True, capture_output=True, check=False)
    _need(process.returncode == 0, f"limits: rustfmt refused the rendered Rust: {process.stderr[:200]}")
    start = process.stdout.find("// @generated")
    _need(start >= 0, "limits: rustfmt output has no generated header")
    return process.stdout[start:]


def check_generated_text(text: str, name: str) -> None:
    expected = render_bindings()
    if text != expected:
        seen, wanted = text.splitlines(keepends=True), expected.splitlines(keepends=True)
        for number in range(max(len(seen), len(wanted))):
            have = seen[number] if number < len(seen) else ""
            want = wanted[number] if number < len(wanted) else ""
            if have != want:
                raise LimitsExamError(f"limits: {name} differs from the renderer's output at line {number + 1}: has {have.rstrip()[:50]!r}, wants {want.rstrip()[:50]!r}")
        raise LimitsExamError(f"limits: {name} differs from the renderer's output")


def check_generated() -> None:
    if not GENERATED.is_file():
        raise LimitsExamError(f"{GENERATED.relative_to(ROOT)} does not exist; the limits record has not landed, run `just zenoh_service_limits_gen`")
    try:
        text = GENERATED.read_bytes().decode("utf-8")
    except UnicodeDecodeError as error:
        raise LimitsExamError(f"{GENERATED.name} is not UTF-8 text: {error.reason}") from error
    check_generated_text(text, GENERATED.name)


def generated_edits(honest: str) -> tuple[tuple[str, str], ...]:
    return (
        ("an offset moved", honest.replace("OFF_RECORD_HOLDERS: usize = 24", "OFF_RECORD_HOLDERS: usize = 23", 1)),
        ("a length changed", honest.replace("RECORD_LEN: usize = 48", "RECORD_LEN: usize = 49", 1)),
        ("the count bound raised in the generated file", honest.replace("MAX_COUNT: u32 = 65535", "MAX_COUNT: u32 = 65536", 1)),
        ("the magic changed in the generated file", honest.replace("0x53, 0x4c", "0x54, 0x4c", 1)),
        ("a field type narrowed", honest.replace("pub holders: u32", "pub holders: u16", 1)),
        ("a decode length check dropped", honest.replace("if buf.len() < RECORD_LEN {", "if false {", 1)),
        ("an encode statement dropped", honest.replace("        buf[OFF_RECORD_HOLDERS..OFF_RECORD_HOLDERS + 4]\n            .copy_from_slice(&self.holders.to_le_bytes());\n", "", 1)),
        ("the header comment removed", honest.replace("// @generated", "// generated", 1)),
        ("a trailing newline removed", honest.rstrip("\n")),
        ("a line added", honest + "// extra\n"),
        ("an empty file", ""),
    )


def generated_controls() -> int:
    """A generated file that differs from the renderer's output by one edit is refused."""
    honest = render_bindings()
    refused = 0
    for label, text in generated_edits(honest):
        if text == honest:
            raise LimitsExamError(f"control: {label} did not change the file")
        try:
            check_generated_text(text, "the file")
        except LimitsExamError:
            refused += 1
            continue
        raise LimitsExamError(f"control: the generated-file check accepted {label}")
    return refused


# Where the limits must be declared and carried. Each is read by pattern from the files, and checked first on a synthetic
# file set. A pattern shows that code exists and not what it does. The implementation review checks behaviour against the
# code, and the booted composition shows the rest.
SPEC = "contracts/system-spec/v1/schema.zt"
MANIFEST = "contracts/generation-manifest/v1/schema.zt"
SERVICE = "components/services/zenoh-service/src/main.rs"
CORE = "components/lib/src/zenoh_service.rs"
ROOT_IPC = "slime-root/src/ipc.rs"
ROOT_GENERATION = "slime-root/src/generation.rs"
ROOT_DISPATCH = "slime-root/src/graph_runtime/services.rs"
BUILDER = "scripts/build/generation_resources.py"
GENERATION_BUILDER = "scripts/build/build-generation.py"
SYSTEM_SPEC = "scripts/lib/system_spec.py"
CLOSURES = "scripts/generate/generate-system-image-closures.py"
CLOSURE_SCHEMA = "scripts/lib/system_image_closure.py"
PROTO_LIB = "components/proto/src/lib.rs"
PROTO_LIMITS = "components/proto/src/zenoh_service_limits.rs"

_LIMIT_NAMES = ("holders", "ringSlots", "sampleBytes", "keyBytes", "localSubscriptions", "stackBytes")


def _record(name: str) -> str:
    """A pattern that matches the whole record type: its header, each of the six limits in order, and its close."""
    fields = r"".join(rf"\n  {field} : Int;" for field in _LIMIT_NAMES)
    return rf"^{name} :: type \{{{fields}\n\}};$"


def _record_example(name: str) -> str:
    return f"{name} :: type {{" + "".join(f"\n  {field} : Int;" for field in _LIMIT_NAMES) + "\n};"


def _nested(record: str, entry: str) -> str:
    """A pattern that matches the field only inside `record`. A field of the same name on another record does not match, because
    the body of the record may hold no closing brace before the field."""
    return rf"^{record} :: type \{{[^}}]*\n  zenohLimits\? : {entry};\n[^}}]*\}};$"


def _nested_example(record: str, entry: str) -> str:
    return f"{record} :: type {{\n  name : Text;\n  zenohLimits? : {entry};\n}};"


def _only_nested(top: str, record: str, entry: str) -> str:
    """`_nested`, and the top-level record `top` holds no field whose name starts with `zenohLimits`. That covers the limits field
    and the object flag, each of which the schema check pays for in memory when it sits on the top-level record."""
    return rf"\A(?![\s\S]*^{top} :: type \{{[^}}]*zenohLimits)[\s\S]*{_nested(record, entry)[0:]}"


def _only_nested_example(top: str, record: str, entry: str) -> str:
    return f"{top} :: type {{\n  name : Text;\n}};\n" + _nested_example(record, entry)


FACTS: tuple[facts.Fact, ...] = (
    ("spec-record", SPEC, _record("SystemZenohLimits"), _record_example("SystemZenohLimits")),
    ("spec-field", SPEC, _only_nested("SystemSpec", "SystemInstance", "SystemZenohLimits"), _only_nested_example("SystemSpec", "SystemInstance", "SystemZenohLimits")),
    ("spec-derives-flag", SYSTEM_SPEC, r'"zenohLimitsObject": any\(', '    flags = {**spec, "zenohLimitsObject": any(entry.get("zenohLimits") is not None for entry in resolved_instances(spec))}'),
    ("manifest-record", MANIFEST, _record("ZenohLimitsEntry"), _record_example("ZenohLimitsEntry")),
    ("manifest-field", MANIFEST, _only_nested("GenerationManifest", "Instance", "ZenohLimitsEntry"), _only_nested_example("GenerationManifest", "Instance", "ZenohLimitsEntry")),
    ("builder-function", BUILDER, r"^def build_zenoh_limits\(", "def build_zenoh_limits(manifest: dict) -> bytes:"),
    ("builder-encoder", BUILDER, r"\bzenoh_limits\.encode\(", "        return zenoh_limits.encode(limits)"),
    ("builder-import", GENERATION_BUILDER, r"^\s*build_zenoh_limits,$", "    build_zenoh_limits,"),
    ("builder-payload", GENERATION_BUILDER, r'payloads\["zenoh-limits"\] = build_zenoh_limits\(manifest\)', '        payloads["zenoh-limits"] = build_zenoh_limits(manifest)'),
    ("object-id", SYSTEM_SPEC, r'\("zenohLimitsObject", "zenoh-limits"\),', '        ("zenohLimitsObject", "zenoh-limits"),'),
    ("release-input-schema", CLOSURES, r'^\s*\("zenoh-limits-contract", "contracts/zenoh-service-limits/v1", "tree"\),$', '    ("zenoh-limits-contract", "contracts/zenoh-service-limits/v1", "tree"),'),
    ("release-input-encoder", CLOSURES, r'^\s*\("zenoh-limits-encoder", "scripts/lib/zenoh_limits\.py", "file"\),$', '    ("zenoh-limits-encoder", "scripts/lib/zenoh_limits.py", "file"),'),
    ("release-input-builder", CLOSURES, r'^\s*\("generation-resources", "scripts/build/generation_resources\.py", "file"\),$', '    ("generation-resources", "scripts/build/generation_resources.py", "file"),'),
    ("closure-schema-limits", CLOSURE_SCHEMA, r'"zenoh-limits-contract",\n\s*"zenoh-limits-encoder",\n\s*"generation-resources",', '        "zenoh-limits-contract",\n        "zenoh-limits-encoder",\n        "generation-resources",'),
    ("spec-refuses-stray-limits", SYSTEM_SPEC, r"only the zenoh-service instance reads the limits record", '        _fail("zenohLimits: only the zenoh-service instance reads the limits record")'),
    ("spec-requires-limits", SYSTEM_SPEC, r"an instance named zenoh-service reads the limits record", '        _fail("zenohLimits: an instance named zenoh-service reads the limits record, so the composition must declare it")'),
    ("spec-carries-limits", SYSTEM_SPEC, r'"workerPriority", "zenohLimits"\):', '        for field in ("priority", "extraThreads", "workerPriority", "zenohLimits"):'),
    ("root-dispatch", ROOT_DISPATCH, r"\bZENOH_LIMITS_CURSOR\b", "                    if cursor == ipc::ZENOH_LIMITS_CURSOR {"),
    ("proto-export", PROTO_LIB, r"^pub mod zenoh_service_limits_wire;$", "pub mod zenoh_service_limits_wire;"),
    ("proto-decoder", PROTO_LIMITS, r"\bWireLimitsRecord::decode\(", "        let record = WireLimitsRecord::decode(bytes).ok_or(DecodeError::Short)?;"),
    ("root-locates", ROOT_GENERATION, r"^pub\(crate\) fn zenoh_limits_object<", "pub(crate) fn zenoh_limits_object<'a>("),
    ("root-serves", ROOT_IPC, r"\bZENOH_LIMITS_CURSOR\b", "const ZENOH_LIMITS_CURSOR: usize = 0xFFFF_FFFF;"),
    ("service-reads", SERVICE, r"\bzenoh_grants_read\(ZENOH_LIMITS_CURSOR,", "    let read = zenoh_grants_read(ZENOH_LIMITS_CURSOR, &mut record)?;"),
    ("recipe", "just/hardware.just", r"^zenoh_service_limits_check:$", "zenoh_service_limits_check:"),
    ("generate-recipe", "just/generate.just", r"^zenoh_service_limits_gen:$", "zenoh_service_limits_gen:"),
)


STDLIB_ONLY = {"__future__", "re", "struct", "pathlib"}


def import_names(text: str) -> set[str]:
    """The top-level modules a file imports, from its import statements."""
    import ast

    found: set[str] = set()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Import):
            found |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            _need(node.level == 0, "limits: the encoder uses a relative import")
            found.add((node.module or "").split(".")[0])
    return found


def check_encoder_imports(text: str | None = None) -> int:
    """The encoder imports only the modules it is allowed. Any other import is a file the closure does not pin."""
    text = (ROOT / "scripts" / "lib" / "zenoh_limits.py").read_text(encoding="utf-8") if text is None else text
    extra = import_names(text) - STDLIB_ONLY
    _need(not extra, f"limits: the encoder imports {sorted(extra)}, which the closure does not pin")
    _need("importlib" not in text and "__import__" not in text and "exec(" not in text, "limits: the encoder loads a module by a path the import check cannot see")
    return len(STDLIB_ONLY)


IMPORT_EDITS = (
    ("a repository module imported", "import zenoh_client_exam as client\n"),
    ("harness imported", "from harness import ROOT\n"),
    ("a module imported from a package", "from slime_tools.paths import ROOT\n"),
    ("a second import on one line", "import os, zenoh_client_exam\n"),
    ("an import inside a function", "def helper():\n    import zenoh_client_exam\n"),
    ("a relative import", "from . import zenoh_client_exam\n"),
    ("a module loaded by a path", "import importlib.util\n"),
    ("a module loaded by __import__", "x = __import__('harness')\n"),
)


def import_controls() -> int:
    text = (ROOT / "scripts" / "lib" / "zenoh_limits.py").read_text(encoding="utf-8")
    check_encoder_imports(text)
    refused = 0
    for label, line in IMPORT_EDITS:
        mutated = text.replace("import struct\n", "import struct\n" + line, 1)
        _need(mutated != text, f"control: {label} did not change the file")
        try:
            check_encoder_imports(mutated)
        except LimitsExamError:
            refused += 1
            continue
        raise LimitsExamError(f"control: the import check accepted {label}")
    return refused


# The release-input names the closure validator requires, written here from `system_image_closure.py`. A tuple with a
# name the validator does not list is an extra release input, and `resolve_closure` refuses every closure that has one.
CANONICAL_RELEASE_NAMES = ("zenoh-limits-contract", "zenoh-limits-encoder", "generation-resources")


def check_facts() -> int:
    def read(path: str) -> str:
        try:
            return (ROOT / path).read_text(encoding="utf-8")
        except OSError as error:
            raise LimitsExamError(f"{path} cannot be read: {error}") from error
    try:
        check_encoder_imports()
        return facts.check(FACTS, read)
    except facts.FactsError as error:
        raise LimitsExamError(str(error)) from error


def fact_controls() -> int:
    try:
        return facts.controls(FACTS)
    except facts.FactsError as error:
        raise LimitsExamError(str(error)) from error


def all_controls() -> int:
    return encoder_all_controls() + generated_controls() + import_controls() + fact_controls()
