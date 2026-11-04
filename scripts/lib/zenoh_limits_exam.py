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
# file set. A pattern shows that code exists. The tests the facts name, and the booted composition, show what it does.
SPEC = "contracts/system-spec/v1/schema.zt"
MANIFEST = "contracts/generation-manifest/v1/schema.zt"
SERVICE = "components/services/zenoh-service/src/main.rs"
CORE = "components/lib/src/zenoh_service.rs"
ROOT_IPC = "slime-root/src/ipc.rs"
ROOT_GENERATION = "slime-root/src/generation.rs"
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


FACTS: tuple[facts.Fact, ...] = (
    ("spec-record", SPEC, _record("SystemZenohLimits"), _record_example("SystemZenohLimits")),
    ("spec-field", SPEC, r"^\s*zenohLimits\? : SystemZenohLimits;$", "  zenohLimits? : SystemZenohLimits;"),
    ("spec-object-flag", SPEC, r"^\s*zenohLimitsObject\? : Bool;$", "  zenohLimitsObject? : Bool;"),
    ("manifest-record", MANIFEST, _record("ZenohLimitsEntry"), _record_example("ZenohLimitsEntry")),
    ("manifest-field", MANIFEST, r"^\s*zenohLimits\? : ZenohLimitsEntry;$", "  zenohLimits? : ZenohLimitsEntry;"),
    ("builder-function", BUILDER, r"^def build_zenoh_limits\(", "def build_zenoh_limits(manifest: dict) -> bytes:"),
    ("builder-encoder", BUILDER, r"\bzenoh_limits\.encode\(", "        return zenoh_limits.encode(limits)"),
    ("builder-import", GENERATION_BUILDER, r"^\s*build_zenoh_limits,$", "    build_zenoh_limits,"),
    ("builder-payload", GENERATION_BUILDER, r'payloads\["zenoh-limits"\] = build_zenoh_limits\(manifest\)', '        payloads["zenoh-limits"] = build_zenoh_limits(manifest)'),
    ("object-id", SYSTEM_SPEC, r'\("zenohLimitsObject", "zenoh-limits"\),', '        ("zenohLimitsObject", "zenoh-limits"),'),
    ("release-input-schema", CLOSURES, r'^\s*\("[\w-]+", "contracts/zenoh-service-limits/v1", "tree"\),$', '    ("zenoh-limits-contract", "contracts/zenoh-service-limits/v1", "tree"),'),
    ("release-input-encoder", CLOSURES, r'^\s*\("[\w-]+", "scripts/lib/zenoh_limits\.py", "file"\),$', '    ("zenoh-limits-encoder", "scripts/lib/zenoh_limits.py", "file"),'),
    ("release-input-builder", CLOSURES, r'^\s*\("[\w-]+", "scripts/build/generation_resources\.py", "file"\),$', '    ("generation-resources", "scripts/build/generation_resources.py", "file"),'),
    ("closure-schema-limits", CLOSURE_SCHEMA, r'"zenoh-limits-contract",\n\s*"zenoh-limits-encoder",', '        "zenoh-limits-contract",\n        "zenoh-limits-encoder",'),
    ("proto-export", PROTO_LIB, r"^pub mod zenoh_service_limits_wire;$", "pub mod zenoh_service_limits_wire;"),
    ("proto-decoder", PROTO_LIMITS, r"\bWireLimitsRecord::decode\(", "        let record = WireLimitsRecord::decode(bytes).ok_or(DecodeError::Short)?;"),
    ("root-locates", ROOT_GENERATION, r"^pub\(crate\) fn zenoh_limits_object<", "pub(crate) fn zenoh_limits_object<'a>("),
    ("root-serves", ROOT_IPC, r"\bZENOH_LIMITS_CURSOR\b", "const ZENOH_LIMITS_CURSOR: usize = 0xFFFF_FFFF;"),
    ("proto-ceilings", PROTO_LIMITS, r"^\s*pub fn within\(&self, ceilings: &Ceilings\) -> bool \{$", "    pub fn within(&self, ceilings: &Ceilings) -> bool {"),
    ("proto-test", "components/proto/tests/zenoh_service_limits.rs", r"^fn every_record_decodes_or_is_refused_and_ceilings_hold\(\) \{$", "fn every_record_decodes_or_is_refused_and_ceilings_hold() {"),
    ("core-rows", CORE, r"rows\.is_empty\(\) \|\| rows\.len\(\) > R\b", "        if rows.is_empty() || rows.len() > R || P != params.bounds.payload || params.fragments {"),
    ("core-test", CORE, r"^\s*fn a_table_with_fewer_rows_than_the_ceiling_is_served\(\)", "    fn a_table_with_fewer_rows_than_the_ceiling_is_served() {"),
    ("service-reads", SERVICE, r"\bzenoh_grants_read\(ZENOH_LIMITS_CURSOR,", "    let read = zenoh_grants_read(ZENOH_LIMITS_CURSOR, &mut record)?;"),
    ("service-checks", SERVICE, r"\blimits\.within\(&CEILINGS\)", "    if !limits.within(&CEILINGS) {"),
    ("recipe", "just/hardware.just", r"^zenoh_service_limits_check:$", "zenoh_service_limits_check:"),
    ("generate-recipe", "just/generate.just", r"^zenoh_service_limits_gen:$", "zenoh_service_limits_gen:"),
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


# What a fact cannot show, two runs show. The proto crate's test decodes records the judge writes and reports whether each is
# within the ceilings the line names. The generation builder is called on manifests the judge writes. Both are judged
# against a reference written here, and both are trusted only after they refuse a wrong implementation.
import zenoh_grants_exam as grants  # noqa: E402

CEILING_TEST = "every_record_decodes_or_is_refused_and_ceilings_hold"
# holders, ring slots, sample bytes, key bytes, local subscriptions, stack bytes. The key ceiling is below the contract's
# bound of 129, so a key one byte over it is still a record the contract allows and only the service refuses.
CEILINGS = (2, 4, 12, 64, 3, 32768)


def within(values: dict[str, int], ceilings: tuple[int, ...]) -> bool:
    return all(values[name] <= ceiling for name, ceiling in zip(limits.LIMIT_FIELDS, ceilings, strict=True))


def _line(values: dict[str, int], ceilings: tuple[int, ...]) -> str:
    return "limits " + ",".join(str(values[name]) for name in limits.LIMIT_FIELDS) + (" within" if within(values, ceilings) else " over")


def records() -> list[tuple[str, bytes, tuple[int, ...], dict[str, int] | None]]:
    """Every record the Rust test decodes: its name, its bytes, the ceilings and the limits it must read, or None to be refused."""
    out = []
    at = CEILINGS
    cases = (
        ("at-every-ceiling", dict(zip(limits.LIMIT_FIELDS, at, strict=True))),
        ("below-every-ceiling", {"holders": 1, "ring_slots": 1, "sample_bytes": 1, "key_bytes": 1, "local_subscriptions": 1, "stack_bytes": 1}),
        ("one-holder-over", {**dict(zip(limits.LIMIT_FIELDS, at, strict=True)), "holders": at[0] + 1}),
        ("one-ring-slot-over", {**dict(zip(limits.LIMIT_FIELDS, at, strict=True)), "ring_slots": at[1] + 1}),
        ("one-sample-byte-over", {**dict(zip(limits.LIMIT_FIELDS, at, strict=True)), "sample_bytes": at[2] + 1}),
        ("one-key-byte-over", {**dict(zip(limits.LIMIT_FIELDS, at, strict=True)), "key_bytes": at[3] + 1}),
        ("one-subscription-over", {**dict(zip(limits.LIMIT_FIELDS, at, strict=True)), "local_subscriptions": at[4] + 1}),
        ("one-stack-byte-over", {**dict(zip(limits.LIMIT_FIELDS, at, strict=True)), "stack_bytes": at[5] + 1}),
        ("every-limit-at-its-contract-bound", {"holders": 65535, "ring_slots": 65535, "sample_bytes": 1048576, "key_bytes": 129, "local_subscriptions": 65535, "stack_bytes": 4294967295}),
    )
    for name, values in cases:
        data = limits.encode(values)
        _need(data == reference(values), f"limits: the encoder's bytes for {name} differ from the reference")
        out.append((f"honest-{name}", data, at, values))
    honest = limits.encode(dict(zip(limits.LIMIT_FIELDS, at, strict=True)))
    for label, corrupt in CORRUPTIONS:
        out.append((f"corrupt-{label.replace(' ', '-')}", corrupt(honest), at, None))
    return out


def verdict(data: bytes, ceilings: tuple[int, ...], values: dict[str, int] | None) -> str:
    try:
        found = decode(data)
    except LimitsExamError:
        return "refused"
    _need(values is not None and found == values, "limits: the decoder accepted a record the exam expects it to refuse")
    return _line(found, ceilings)


def input_file_text() -> str:
    """What the Rust test reads: a name, the record's bytes in hex and the ceilings, a line each."""
    return "".join(f"{name} {data.hex()} {','.join(map(str, ceilings))}\n" for name, data, ceilings, _ in records())


def good_lines() -> list[str]:
    out = [f"limitsrecord {name} {data.hex()} {verdict(data, ceilings, values)}" for name, data, ceilings, values in records()]
    out.append(f"limitsrecord ok {CEILING_TEST.replace('_', '-')}")
    return out


PROBE_NAME = "honest-the-probe"
PROBE_VALUES = {"holders": 2, "ring_slots": 2, "sample_bytes": 7, "key_bytes": 9, "local_subscriptions": 1, "stack_bytes": 4096}


def probe_replaces() -> str:
    return "honest-below-every-ceiling"


def probe_file_text() -> str:
    """The second run's file: the first with one honest record replaced, so a test that prints constants cannot match."""
    out = []
    for name, data, ceilings, _ in records():
        if name == probe_replaces():
            out.append(f"{PROBE_NAME} {limits.encode(PROBE_VALUES).hex()} {','.join(map(str, CEILINGS))}\n")
        else:
            out.append(f"{name} {data.hex()} {','.join(map(str, ceilings))}\n")
    return "".join(out)


def probe_lines() -> list[str]:
    data = limits.encode(PROBE_VALUES)
    out = []
    for line in good_lines():
        fields = line.split(" ")
        if len(fields) > 1 and fields[1] == probe_replaces():
            out.append(f"limitsrecord {PROBE_NAME} {data.hex()} {verdict(data, CEILINGS, PROBE_VALUES)}")
        else:
            out.append(line)
    return out


def judge_probe(lines: list[str]) -> None:
    wanted, first = probe_lines(), good_lines()
    changed = [index for index, (a, b) in enumerate(zip(wanted, first, strict=True)) if a != b]
    _need(len(changed) == 1, f"limits: the probe must change exactly one line, it changes {len(changed)}")
    for index, (seen, want) in enumerate(zip(lines, wanted, strict=False)):
        _need(seen == want, f"limits probe line {index + 1} is {seen[:90]!r}, the probe requires {want[:90]!r}")
    _need(len(lines) == len(wanted), f"limits: the probe run printed {len(lines)} lines, the probe requires {len(wanted)}")


def judge(lines: list[str]) -> tuple[int, int]:
    """Check a transcript against the exam; returns (cases, refusals)."""
    wanted = good_lines()
    for line in lines:
        _need(line.split()[:1] == ["limitsrecord"], f"limits: a record that is not a limitsrecord exam line: {line[:60]!r}")
    for index, (seen, want) in enumerate(zip(lines, wanted, strict=False)):
        _need(seen == want, f"limits line {index + 1} is {seen[:90]!r}, the exam requires {want[:90]!r}")
    _need(len(lines) >= len(wanted), f"limits: the transcript stops after {len(lines)} of {len(wanted)} lines")
    _need(len(lines) <= len(wanted), f"limits: {len(lines) - len(wanted)} lines beyond the exam")
    refusals = sum(1 for line in lines if line.endswith(" refused"))
    return len(lines) - refusals, refusals


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a limitsrecord line", [*good, "tablerow ok x"]),
        ("a line repeated", [*good, good[-1]]),
        ("the last two lines swapped", [*good[:-2], good[-1], good[-2]]),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index + 1} ({line[13:46]}) missing", good[:index] + good[index + 1 :]))
    over = next(i for i, line in enumerate(good) if line.endswith(" over"))
    inside = next(i for i, line in enumerate(good) if line.endswith(" within"))
    corrupt = next(i for i, line in enumerate(good) if " corrupt-" in line)
    out.append(("an over-ceiling record reported within", [*good[:over], good[over][:-5] + "within", *good[over + 1 :]]))
    out.append(("a within-ceiling record reported over", [*good[:inside], good[inside][:-6] + "over", *good[inside + 1 :]]))
    out.append(("a corrupted record accepted", [*good[:corrupt], good[corrupt].rsplit(" ", 1)[0] + " limits 2,4,12,129,3,32768 within", *good[corrupt + 1 :]]))
    out.append(("an honest record refused", [*good[:inside], good[inside].split(" limits ")[0] + " refused", *good[inside + 1 :]]))
    out.append(("every record reported within", [line[:-5] + "within" if line.endswith(" over") else line for line in good]))
    out.append(("every record reported over", [line[:-6] + "over" if line.endswith(" within") else line for line in good]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    judge(good)
    refused, seen = 0, {}
    for label, lines in transcript_mutations():
        if lines == good:
            raise LimitsExamError(f"control: {label} did not change the transcript")
        if tuple(lines) in seen:
            raise LimitsExamError(f"control: {label} repeats {seen[tuple(lines)]}")
        seen[tuple(lines)] = label
        try:
            judge(lines)
        except LimitsExamError:
            refused += 1
            continue
        raise LimitsExamError(f"control: the limits judge accepted {label}")
    return refused


def probe_mutations() -> list[tuple[str, list[str]]]:
    probe, first = probe_lines(), good_lines()
    changed = next(i for i, (a, b) in enumerate(zip(probe, first, strict=True)) if a != b)
    return [
        ("a test that prints constants", first),
        ("an empty second run", []),
        ("a second run that stops early", probe[:-1]),
        ("a second run with a line added", [*probe, probe[-1]]),
        ("a second run with the probe line missing", probe[:changed] + probe[changed + 1 :]),
        ("a second run that prints the probe line with a wrong verdict", [*probe[:changed], probe[changed].rsplit(" ", 1)[0] + " over", *probe[changed + 1 :]]),
        ("a second run that prints the probe line under the replaced name", [*probe[:changed], probe[changed].replace(PROBE_NAME, probe_replaces(), 1), *probe[changed + 1 :]]),
    ]


def probe_controls() -> int:
    judge_probe(probe_lines())
    refused = 0
    for label, lines in probe_mutations():
        if lines == probe_lines():
            raise LimitsExamError(f"control: {label} did not change the probe lines")
        try:
            judge_probe(lines)
        except LimitsExamError:
            refused += 1
            continue
        raise LimitsExamError(f"control: the probe judge accepted {label}")
    return refused


# The generation builder, called on manifests the judge writes. `build` is `generation_resources.build_zenoh_limits`. The
# stack is judged against the arithmetic of `zenoh-service-grants/v1`, written again in `zenoh_grants_exam` from its
# comments, so a builder that calls the encoder and skips the contract is refused.
ROWS = [
    {"holder": "alpha", "key": "0/slime_service/exchange", "publish": True, "subscribe": False},
    {"holder": "beta", "key": "0/slime_service/exchange", "publish": False, "subscribe": True},
]


def _manifest(stack: int | None = None, **changes: object) -> dict[str, object]:
    base = {"holders": 2, "ringSlots": 4, "sampleBytes": 12, "keyBytes": 129, "localSubscriptions": 1}
    base.update({key: value for key, value in changes.items() if key in base})
    need = grants.required_stack(base["holders"], base["ringSlots"], base["sampleBytes"], base["keyBytes"], len(ROWS))
    base["stackBytes"] = need if stack is None else stack
    manifest: dict[str, object] = {
        "instances": [{"name": "zenoh-service"}, {"name": "alpha"}, {"name": "beta"}, {"name": "network-service"}],
        "zenohGrants": changes.get("rows", ROWS), "zenohLimits": base,
    }
    if changes.get("no_limits"):
        del manifest["zenohLimits"]
    return manifest


def _need_stack(**changes: int) -> int:
    base = {"holders": 2, "ringSlots": 4, "sampleBytes": 12, "keyBytes": 129}
    base.update(changes)
    return grants.required_stack(base["holders"], base["ringSlots"], base["sampleBytes"], base["keyBytes"], len(ROWS))


def _encoded(manifest: dict[str, object]) -> bytes:
    values = manifest["zenohLimits"]
    return limits.encode({
        "holders": values["holders"], "ring_slots": values["ringSlots"], "sample_bytes": values["sampleBytes"],
        "key_bytes": values["keyBytes"], "local_subscriptions": values["localSubscriptions"], "stack_bytes": values["stackBytes"],
    })


def builder_cases() -> tuple[list[tuple[str, dict[str, object], bool]], int]:
    """(label, manifest, whether the builder accepts it)."""
    need = _need_stack()
    cases = [
        ("the honest manifest", _manifest(), True),
        ("a stack of exactly what the declaration needs", _manifest(stack=need), True),
        ("a stack of one byte more than it needs", _manifest(stack=need + 1), True),
        ("a stack of one byte under what the declaration needs", _manifest(stack=need - 1), False),
        ("a stack of one byte", _manifest(stack=1), False),
        ("more rows than the stack holds at a larger key", _manifest(stack=_need_stack(), keyBytes=129, rows=[*ROWS, {"holder": "alpha", "key": "0/a", "publish": True, "subscribe": False}] * 60), False),
        ("fewer holders declared than the rows name", _manifest(holders=1), False),
        ("fewer local subscriptions than subscribe keys", _manifest(localSubscriptions=0), False),
        ("a key longer than the declared key bytes", _manifest(keyBytes=8), False),
        ("holders of zero", _manifest(holders=0), False),
        ("no limits in the manifest", _manifest(no_limits=True), False),
    ]
    return cases, len(cases)


def judge_builder(build) -> int:
    """`build(manifest)` returns the record's bytes or raises SystemExit. Returns the number of cases that held."""
    cases, count = builder_cases()
    for label, manifest, accepted in cases:
        try:
            got = build(manifest)
        except SystemExit:
            _need(not accepted, f"limits: the builder refused {label}")
            continue
        _need(accepted, f"limits: the builder accepted {label}")
        _need(got == _encoded(manifest), f"limits: the builder's bytes for {label} differ from the reference")
    return count


def _reference_builder(manifest: dict[str, object]) -> bytes:
    """A builder that does what the item requires, written here so the controls have one honest case to compare."""
    values = manifest.get("zenohLimits")
    if values is None:
        raise SystemExit("no limits")
    rows = manifest["zenohGrants"]
    holders = {row["holder"] for row in rows}
    keys = {row["key"] for row in rows if row["subscribe"]}
    ok = (
        values["holders"] >= 1 and len(holders) <= values["holders"] and len(keys) <= values["localSubscriptions"]
        and all(len(row["key"]) <= values["keyBytes"] for row in rows)
        and values["stackBytes"] >= grants.required_stack(values["holders"], values["ringSlots"], values["sampleBytes"], values["keyBytes"], len(rows))
    )
    if not ok:
        raise SystemExit("refused")
    return _encoded(manifest)


def _skips_the_contract(manifest: dict[str, object]) -> bytes:
    if manifest.get("zenohLimits") is None:
        raise SystemExit("no limits")
    return _encoded(manifest)


def _writes_other_bytes(manifest: dict[str, object]) -> bytes:
    data = bytearray(_reference_builder(manifest))
    data[24] ^= 0xFF
    return bytes(data)


def _accepts_everything(manifest: dict[str, object]) -> bytes:
    return b""


def _refuses_everything(manifest: dict[str, object]) -> bytes:
    raise SystemExit("refused")


def builder_controls() -> int:
    judge_builder(_reference_builder)
    refused = 0
    for label, wrong in (
        ("a builder that calls the encoder and skips the contract", _skips_the_contract),
        ("a builder that writes other bytes", _writes_other_bytes),
        ("a builder that accepts everything", _accepts_everything),
        ("a builder that refuses everything", _refuses_everything),
    ):
        try:
            judge_builder(wrong)
        except LimitsExamError:
            refused += 1
            continue
        raise LimitsExamError(f"control: the builder judge accepted {label}")
    return refused


def all_controls() -> int:
    return encoder_all_controls() + generated_controls() + fact_controls() + transcript_controls() + probe_controls() + builder_controls()
