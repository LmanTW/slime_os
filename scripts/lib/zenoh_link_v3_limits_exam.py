"""Judge `contracts/zenoh-link-limits/v3`: a link configuration that declares its local subscriptions and its runs.

Version 1 of the contract has no field for the subscriptions this side of a session may declare, so every link
built from it holds one (`Params::from_limits`). Version 3 adds `localSubscriptions`. It also carries `maxRuns`,
the field that version 2 adds (`.tasks/items/zenoh-fragment-lanes.zt`), so that one record declares both.

The contract is judged by its own decoder, as `zenoh_grants_exam` judges the grants contract: a record is written as
Zutai text, handed to the schema's `decodeLimits`, and must come out valid or invalid as this module says.
Every boundary is held on both sides, each check is removed in turn and the weakened contract must then take the
record that check refuses, and the stack arithmetic is written again here from the schema's comments. The `maxRuns`
rules are not judged here from their own source. They are tied to `zenoh_lanes_exam`, so a v3 that drifts from the
v2 the lanes item planned fails this exam.

The schema of version 2 exists. This exam does not run it. It reads the lanes exam's values, which that schema states too.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from itertools import zip_longest
from pathlib import Path

import zenoh_lanes_exam as lanes
import zenoh_links_exam as links
import zutai_cli
from harness import ROOT

SCHEMA = ROOT / "contracts" / "zenoh-link-limits" / "v3" / "schema.zt"
GENERATED = ROOT / "components" / "proto" / "src" / "zenoh_link_v3_limits.rs"
ITEM = ROOT / ".tasks" / "items" / "zenoh-link-limits-v3.zt"
FORMAT_VERSION = 3
MAX_LOCAL = 65535
# The byte a link with several runs adds to its INIT_ACK, as version 2 and the lanes exam hold it: the extension of the
# handshake is the only edge the batch bound has.
QOS_OFFER = 1
MAX_RUNS = 16
LOCAL_FIELDS = ("localSubscriptions", "maxRuns")


class LinkV3Error(Exception):
    pass


def need(condition: bool, message: str) -> None:
    if not condition:
        raise LinkV3Error(message)


def stack_v3(config: dict) -> int:
    """The v1 stack, the slots of the local subscriptions beyond the first, and what the runs beyond the first add."""
    runs = config["maxRuns"]
    runs_extra = (runs - 1) * lanes.RUN_OVERHEAD_BYTES + lanes.LANE_COUNTER_BYTES if runs > 1 else 0
    local_extra = (config["localSubscriptions"] - 1) * (config["keyBytes"] + links.SLOT)
    return links.required_stack(config) + local_extra + runs_extra


def heap_v3(config: dict) -> int:
    return (links.NOTICES * config["outstandingSamples"] + config["maxRuns"]) * links.message_bytes(config)


def config_v3(base: dict, local: int, runs: int, **change: object) -> dict:
    """`base` with the two new fields and the stack and heap that the arithmetic requires, exactly."""
    config = dict(base, localSubscriptions=local, maxRuns=runs, **change)
    config["stackBytes"] = stack_v3(config)
    if config["mode"] == "heap":
        config["heapBytes"] = heap_v3(config)
    return config


def render_record(configs: list[dict], version: int = FORMAT_VERSION, top: str = "") -> str:
    rows = "".join(
        "    { " + " ".join(f'{k} = "{v}";' if isinstance(v, str) else f"{k} = {v};" for k, v in c.items()) + " };\n" for c in configs
    )
    return f"{{\n  formatVersion = {version};{top}\n  configs = [\n{rows}  ];\n}}\n"


def contract_accepts(text: str, schema: str | None = None) -> bool:
    """Whether the contract's decoder takes `text` as a valid limits record, under `schema` if one is given."""
    need(SCHEMA.is_file(), f"{SCHEMA.relative_to(ROOT)} is missing")
    (ROOT / "build").mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="zenoh-link-v3-", dir=ROOT / "build"))
    try:
        if schema is None:
            shutil.copyfile(SCHEMA, scratch / "schema.zt")
        else:
            (scratch / "schema.zt").write_text(schema, encoding="utf-8")
        (scratch / "decode.zt").write_text(
            's ::= import "schema.zt"; env ::= import stdlib.env; load ::= import stdlib.load; '
            "main :: { env : Env; load : Load; } -> Validation DecodeIssue s.Limits ! { * env.GetEffects; * load.ZtiEffects; } "
            '= caps => [ path := env.get caps.env "SLIME_LIMITS_PATH" ?? ""; s.decodeLimits (load.zti caps.load path) ]; main\n'
        )
        path = scratch / "limits.zti"
        path.write_text(text)
        try:
            out = zutai_cli.evaluate("run", scratch / "decode.zt", input_path=path, env_var="SLIME_LIMITS_PATH")
        except zutai_cli.ZutaiError as error:
            raise LinkV3Error(f"the v3 contract could not decode a record: {error}") from error
        return out.startswith("#valid")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def cases() -> list[tuple[str, str, bool]]:
    """(label, record, whether the contract takes it). Each bound is held on both sides."""
    demo, large, heap = links.pinned_configs()
    fixed_demo, fixed_large = config_v3(demo, 1, 0), config_v3(large, 1, 0)
    heap1 = config_v3(heap, 1, 1)

    def rec(*configs: dict, **extra: object) -> str:
        return render_record(list(configs), **extra)

    def with_heap(config: dict) -> str:
        return rec(fixed_demo, fixed_large, config)

    heap3 = config_v3(heap, 3, 1)
    heap32 = config_v3(heap, 3, 2)
    fixed3 = config_v3(demo, 3, 0)
    one_stack = {"stackBytes": links.required_stack(heap)}
    without = lambda config, field: {k: v for k, v in config.items() if k != field}  # noqa: E731
    out: list[tuple[str, str, bool]] = [
        ("the three configurations with one local subscription and 0, 0 and 1 runs", with_heap(heap1), True),
        ("their stacks are the v1 stacks, so v1 records lift without change", rec(dict(demo, localSubscriptions=1, maxRuns=0), dict(large, localSubscriptions=1, maxRuns=0), dict(heap, localSubscriptions=1, maxRuns=1)), True),
        ("a fixed link with 3 local subscriptions, its stack exact", rec(fixed3, fixed_large, heap1), True),
        ("a heap link with 3 local subscriptions and 1 run, the service's count", with_heap(heap3), True),
        ("a heap link with 3 local subscriptions and 2 runs, both fields, exact", with_heap(heap32), True),
        ("a heap link with 3 local subscriptions and 16 runs, exact", with_heap(config_v3(heap, 3, 16)), True),
        ("a heap link with 65535 local subscriptions, exact", with_heap(config_v3(heap, 65535, 1)), True),
        ("a fixed link with 65535 local subscriptions, exact", rec(config_v3(demo, 65535, 0), fixed_large, heap1), True),
        ("a stack one byte over what 3 local subscriptions need", with_heap(dict(heap3, stackBytes=heap3["stackBytes"] + 1)), True),
        ("a heap link with 3 local subscriptions, 2 runs and 1 outstanding sample, exact", with_heap(config_v3(heap, 3, 2, outstandingSamples=1)), True),
        ("a heap link with 2 runs and 1 local subscription, exact", with_heap(config_v3(heap, 1, 2)), True),
        ("a heap link with 2 runs and a batch of 90, the largest INIT_ACK with the extension and its stream length", with_heap(config_v3(heap, 1, 2, batchBytes=90, keyBytes=1)), True),
        ("a heap link with 16 runs and a batch of 90", with_heap(config_v3(heap, 1, 16, batchBytes=90, keyBytes=1)), True),
        ("a heap link with 1 run and a batch of 89, which writes no extension", with_heap(config_v3(heap, 1, 1, batchBytes=89, keyBytes=1)), True),
        ("a heap link with 2 runs and a batch of 89, one byte short of it", with_heap(config_v3(heap, 1, 2, batchBytes=89, keyBytes=1)), False),
        ("a heap link with 16 runs and a batch of 89", with_heap(config_v3(heap, 1, 16, batchBytes=89, keyBytes=1)), False),
        ("a heap link with 3 local subscriptions and one byte too little stack", with_heap(dict(heap3, stackBytes=heap3["stackBytes"] - 1)), False),
        ("a fixed link with 3 local subscriptions and one byte too little stack", rec(dict(fixed3, stackBytes=fixed3["stackBytes"] - 1), fixed_large, heap1), False),
        ("a heap link with 3 local subscriptions and the stack of 1", with_heap(dict(heap3, **one_stack)), False),
        ("a heap link with 2 runs and one byte too little stack", with_heap(dict(config_v3(heap, 1, 2), stackBytes=stack_v3(config_v3(heap, 1, 2)) - 1)), False),
        ("a heap link with 2 runs and the stack of 1 run", with_heap(dict(config_v3(heap, 1, 2), **one_stack)), False),
        ("a heap link with 3 local subscriptions, 2 runs and the stack of 3 local subscriptions with 1 run", with_heap(dict(heap32, stackBytes=heap3["stackBytes"])), False),
        ("a heap link with 2 runs and one byte too little heap", with_heap(dict(heap32, heapBytes=heap32["heapBytes"] - 1)), False),
        ("a heap link with 2 runs and the heap of 1", with_heap(dict(heap32, heapBytes=heap3["heapBytes"])), False),
        ("zero local subscriptions", with_heap(config_v3(heap, 0, 1)), False),
        ("-1 local subscriptions", with_heap(config_v3(heap, -1, 1)), False),
        ("a fixed link with zero local subscriptions", rec(config_v3(demo, 0, 0), fixed_large, heap1), False),
        ("65536 local subscriptions", with_heap(config_v3(heap, 65536, 1)), False),
        ("a heap link with 17 runs, exact", with_heap(config_v3(heap, 1, 17)), False),
        ("a heap link with 0 runs", with_heap(config_v3(heap, 1, 0)), False),
        ("a heap link with -1 runs", with_heap(config_v3(heap, 1, -1)), False),
        ("a fixed link with 1 run", rec(config_v3(demo, 1, 1), fixed_large, heap1), False),
        ("a fixed link with 2 runs, exact", rec(fixed_demo, config_v3(large, 1, 2), heap1), False),
        ("a record with no localSubscriptions", with_heap(without(heap1, "localSubscriptions")), False),
        ("a record with no maxRuns", with_heap(without(heap1, "maxRuns")), False),
        ("a v1 record with no new field", rec(*links.pinned_configs(), version=1), False),
        ("a v2 record that carries maxRuns alone", rec(*(without(c, "localSubscriptions") for c in (fixed_demo, fixed_large, heap1)), version=2), False),
        ("a v1 record that carries both fields", rec(fixed_demo, fixed_large, heap1, version=1), False),
        ("a v2 record that carries both fields", rec(fixed_demo, fixed_large, heap1, version=2), False),
        ("format version 4", rec(fixed_demo, fixed_large, heap1, version=4), False),
        ("format version 0", rec(fixed_demo, fixed_large, heap1, version=0), False),
        ("a field the configuration does not name", with_heap(dict(heap1, note="x")), False),
        ("a field the record does not name", rec(fixed_demo, fixed_large, heap1, top="\n  surprise = 1;"), False),
        ("no configuration", rec(), False),
        ("two configurations with one name", rec(fixed_demo, dict(fixed_large, name="demo"), heap1), False),
        ("a local subscription count written as text", with_heap(dict(heap1, localSubscriptions="1")), False),
        ("a v1 rule still refused: a stack one byte under", with_heap(dict(heap1, stackBytes=heap1["stackBytes"] - 1)), False),
        ("a v1 rule still refused: a fixed link with a heap", rec(dict(fixed_demo, heapBytes=1), fixed_large, heap1), False),
    ]
    return out


# A contract with one check removed. Each runs on the record that check exists to refuse, and the decoder must then
# take it. (label, text removed, text put in its place, the case that must flip). Each text appears once.
SCHEMA_MUTATIONS = (
    ("a contract with no lower bound on local subscriptions", "c.localSubscriptions >= 1 && ", "", "zero local subscriptions"),
    ("a contract with no lower bound on local subscriptions, for a negative count", "c.localSubscriptions >= 1 && ", "", "-1 local subscriptions"),
    ("a contract with no upper bound on local subscriptions", " && c.localSubscriptions <= maxLocalSubscriptions", "", "65536 local subscriptions"),
    ("a contract that leaves local subscriptions out of the stack", " + localBytes c + runBytes c", " + runBytes c", "a heap link with 3 local subscriptions and the stack of 1"),
    ("a contract that leaves runs out of the stack", " + localBytes c + runBytes c", " + localBytes c", "a heap link with 2 runs and the stack of 1 run"),
    ("a contract that adds the lane counters only from 3 runs", "runBytes :: Config -> Int\n  = c => if c.maxRuns > 1 then", "runBytes :: Config -> Int\n  = c => if c.maxRuns > 2 then", "a heap link with 2 runs and the stack of 1 run"),
    ("a contract with no upper bound on runs", "c.maxRuns >= 1 && c.maxRuns <= maxRunsPerLink", "c.maxRuns >= 1", "a heap link with 17 runs, exact"),
    ("a contract with no lower bound on a heap link's runs", "c.maxRuns >= 1 && c.maxRuns <= maxRunsPerLink", "c.maxRuns <= maxRunsPerLink", "a heap link with 0 runs"),
    ("a contract that lets a fixed link hold a run", "c.maxRuns == 0 && c.reassemblyTimeoutMs == 0", "c.reassemblyTimeoutMs == 0", "a fixed link with 1 run"),
    ("a contract whose heap holds one run", "c.outstandingSamples + c.maxRuns) * messageBytes c", "c.outstandingSamples + 1) * messageBytes c", "a heap link with 2 runs and the heap of 1"),
    ("a contract that reads a field it does not name", "if closedLimits data then", "if true then", "a field the configuration does not name"),
    ("a contract that ignores the format version", "rec.formatVersion == formatVersion", "true", "format version 4"),
    ("a contract that holds no batch to the INIT_ACK with the extension", " + offerBytes c && c.batchBytes <= dataBytes", " && c.batchBytes <= dataBytes", "a heap link with 2 runs and a batch of 89, one byte short of it"),
    ("a contract that offers the extension from 3 runs", "offerBytes :: Config -> Int\n  = c => if c.maxRuns > 1 then", "offerBytes :: Config -> Int\n  = c => if c.maxRuns > 2 then", "a heap link with 2 runs and a batch of 89, one byte short of it"),
    ("a contract that takes the v2 version number", "formatVersion :: Int = 3;", "formatVersion :: Int = 2;", "a v2 record that carries both fields"),
)

# A contract with an upper bound or a count made one off. The weakened contract must refuse the record at the bound, which the
# real contract takes. (label, text removed, text put in its place, the case that flips). Each text appears once.
BOUND_MUTATIONS = (
    ("a contract whose local subscriptions bound is exclusive", "c.localSubscriptions <= maxLocalSubscriptions", "c.localSubscriptions < maxLocalSubscriptions", "a heap link with 65535 local subscriptions, exact"),
    ("a contract whose runs bound is exclusive", "c.maxRuns <= maxRunsPerLink", "c.maxRuns < maxRunsPerLink", "a heap link with 3 local subscriptions and 16 runs, exact"),
    ("a contract that charges every local subscription a slot", "(c.localSubscriptions - 1) * (c.keyBytes", "c.localSubscriptions * (c.keyBytes", "a heap link with 3 local subscriptions and 1 run, the service's count"),
    ("a contract that charges every run a header", "(c.maxRuns - 1) * runOverheadBytes", "c.maxRuns * runOverheadBytes", "a heap link with 3 local subscriptions and 2 runs, both fields, exact"),
    ("a contract that charges a lane counter twice", "+ laneCounterBytes else 0", "+ 2 * laneCounterBytes else 0", "a heap link with 2 runs and 1 local subscription, exact"),
)


def _by_label() -> dict[str, tuple[str, bool]]:
    table = {label: (text, wanted) for label, text, wanted in cases()}
    need(len(table) == len(cases()), "the exam holds two cases with one label")
    return table


def _once(text: str, old: str, label: str) -> None:
    need(text.count(old) == 1, f"control: {label}: the text it changes appears {text.count(old)} times in the schema, not once")


def mutation_controls() -> int:
    """Each weakened contract takes the record its removed check refuses, where the real contract does not."""
    text = SCHEMA.read_text(encoding="utf-8")
    by_label = _by_label()
    caught = 0
    for label, old, new, case in SCHEMA_MUTATIONS:
        _once(text, old, label)
        record_text, wanted = by_label[case]
        need(not wanted, f"control: {label}: the case {case!r} is one the contract takes")
        need(contract_accepts(record_text, text.replace(old, new)) != wanted, f"control: {label} was not seen: the weakened contract still refused {case!r}")
        caught += 1
    return caught


def bound_controls() -> int:
    """Each bound is held from the accepting side: made exclusive or one off, the contract refuses the record at it."""
    text = SCHEMA.read_text(encoding="utf-8")
    by_label = _by_label()
    caught = 0
    for label, old, new, case in BOUND_MUTATIONS:
        _once(text, old, label)
        record_text, wanted = by_label[case]
        need(wanted, f"control: {label}: the case {case!r} is one the contract refuses")
        need(contract_accepts(record_text, text.replace(old, new)) != wanted, f"control: {label} was not seen: the weakened contract still took {case!r}")
        caught += 1
    return caught


def record_counts() -> tuple[int, int]:
    """(records the contract must take and does, records it must refuse and does)."""
    taken = refused = 0
    for label, text, wanted in cases():
        need(contract_accepts(text) == wanted, f"the v3 contract {'refused' if wanted else 'took'}: {label}")
        taken, refused = taken + wanted, refused + (not wanted)
    return taken, refused


# What the contract's source states, held here and in the generated Rust constants.
CONSTANTS = {
    "FORMAT_VERSION": "formatVersion",
    "MAX_LOCAL_SUBSCRIPTIONS": "maxLocalSubscriptions",
    "MAX_RUNS_PER_LINK": "maxRunsPerLink",
    "RUN_OVERHEAD_BYTES": "runOverheadBytes",
    "LANE_COUNTER_BYTES": "laneCounterBytes",
    "QOS_OFFER_BYTES": "qosOfferBytes",
    "SLOT_OVERHEAD_BYTES": "slotOverheadBytes",
}
RESTATED = {
    "FORMAT_VERSION": FORMAT_VERSION,
    "MAX_LOCAL_SUBSCRIPTIONS": MAX_LOCAL,
    "MAX_RUNS_PER_LINK": lanes.MAX_RUNS,
    "RUN_OVERHEAD_BYTES": lanes.RUN_OVERHEAD_BYTES,
    "LANE_COUNTER_BYTES": lanes.LANE_COUNTER_BYTES,
    "QOS_OFFER_BYTES": QOS_OFFER,
    "SLOT_OVERHEAD_BYTES": links.SLOT,
}


def schema_constants() -> dict[str, int]:
    text = SCHEMA.read_text(encoding="utf-8")
    found = {}
    for rust, zutai in CONSTANTS.items():
        match = re.search(rf"^{zutai} :: Int = (\d+);", text, re.M)
        need(match is not None, f"the schema does not state {zutai}")
        found[rust] = int(match.group(1))
    return found


def check_constants(constants: dict[str, int]) -> None:
    """The schema's constants equal the values restated here, which are the lanes exam's and the links exam's."""
    for name, expected in RESTATED.items():
        need(constants[name] == expected, f"the schema states {name} = {constants[name]}, the exam and the lanes exam restate {expected}")
    need(MAX_RUNS == lanes.MAX_RUNS, "the exam and the lanes exam disagree on the runs bound")


def arithmetic_controls() -> int:
    """The schema's constants pass `check_constants`, and each constant drifted by one is refused by it."""
    constants = schema_constants()
    check_constants(constants)
    refused = 0
    for label, name, delta in (("a run header that drifts", "RUN_OVERHEAD_BYTES", 1), ("a lane counter that drifts", "LANE_COUNTER_BYTES", -1), ("a QoS offer that drifts", "QOS_OFFER_BYTES", 1), ("a runs bound that drifts", "MAX_RUNS_PER_LINK", 1), ("a slot overhead that drifts", "SLOT_OVERHEAD_BYTES", 1)):
        changed = {**constants, name: constants[name] + delta}
        try:
            check_constants(changed)
        except LinkV3Error as error:
            need(name in str(error), f"control: {label} was refused for another constant: {error}")
            refused += 1
            continue
        raise LinkV3Error(f"control: the constants check took {label}")
    return refused


def check_lifting(runs: int, stack_of, heap_of) -> None:
    """At one local subscription the stack and the heap that `stack_of` and `heap_of` give a heap link of `runs` runs
    equal the lanes exam's version 2 values."""
    heap = links.pinned_configs()[2]
    v2 = lanes.v2_config(heap, runs)
    v3 = config_v3(heap, 1, runs)
    need(v2["stackBytes"] == stack_of(v3), f"v3 and v2 declare different stacks for {runs} runs: {stack_of(v3)} and {v2['stackBytes']}")
    need(v2["heapBytes"] == heap_of(v3), f"v3 and v2 declare different heaps for {runs} runs: {heap_of(v3)} and {v2['heapBytes']}")


def lifting_controls() -> int:
    """A record at one local subscription needs the stack and the heap that the lanes exam's v2 arithmetic gives.

    The v3 stack at one local subscription must equal the lanes exam's v2 stack for every run count, and the heap too, so
    the two versions cannot declare different memory for the same link. Each equality is one fact, and a changed
    restatement is refused.
    """
    for runs in (1, 2, 3, 16):
        check_lifting(runs, stack_v3, heap_v3)
    refused = 0
    for label, stack, heap_of in (
        ("a stack that drops one run header", lambda c: stack_v3(c) - lanes.RUN_OVERHEAD_BYTES, heap_v3),
        ("a stack that adds one slot", lambda c: stack_v3(c) + links.SLOT, heap_v3),
        ("a heap that holds one run too few", stack_v3, lambda c: heap_v3(c) - links.message_bytes(c)),
    ):
        try:
            check_lifting(2, stack, heap_of)
        except LinkV3Error:
            refused += 1
            continue
        raise LinkV3Error(f"control: the lifting check took {label}")
    return refused


GENERATED_HEADER = (
    "// @generated by scripts/generate/generate-zenoh-link-v3-limits-bindings.py; do not edit.\n"
    "// Source contract: contracts/zenoh-link-limits/v3/schema.zt\n"
)


def render_bindings() -> str:
    """The generated Rust constants file, from the schema's constants."""
    return GENERATED_HEADER + "\n" + "".join(f"pub const {rust}: u32 = {value};\n" for rust, value in schema_constants().items())


def read_exact(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as error:
        raise LinkV3Error(f"{path.name} is not UTF-8 text: {error.reason}") from error


def check_generated_text(text: str, name: str) -> int:
    """The file equals the generator's output byte for byte; returns the number of constants it holds."""
    expected = render_bindings()
    if text == expected:
        return len(CONSTANTS)
    seen, wanted = text.splitlines(keepends=True), expected.splitlines(keepends=True)
    for number, (have, want) in enumerate(zip_longest(seen, wanted, fillvalue=""), 1):
        if have != want:
            raise LinkV3Error(f"{name} differs from the generator's output at line {number}: has {have.rstrip()[:60]!r}, wants {want.rstrip()[:60]!r}")
    raise LinkV3Error(f"{name} differs from the generator's output")


def check_generated() -> int:
    need(GENERATED.is_file(), f"{GENERATED.relative_to(ROOT)} does not exist; the v3 bindings have not landed, run `just zenoh_link_v3_limits_gen`")
    return check_generated_text(read_exact(GENERATED), GENERATED.name)


def generated_controls() -> int:
    """The generator's output is taken, and a file that differs from it by one edit is refused."""
    honest = render_bindings()
    need(check_generated_text(honest, "the honest file") == len(CONSTANTS), "control: the honest generated file was not taken")
    constants = [line for line in honest.splitlines(keepends=True) if line.startswith("pub const ")]
    first = constants[0]
    bad = (
        ("every constant behind a cfg that compiles it out", "".join("#[cfg(any())]\n" + line if line in constants else line for line in honest.splitlines(keepends=True))),
        ("every constant in a line comment", "".join("// " + line if line in constants else line for line in honest.splitlines(keepends=True))),
        ("every constant in a block comment", GENERATED_HEADER + "\n/*\n" + "".join(constants) + "*/\n"),
        ("every constant inside a raw string holding a quote", GENERATED_HEADER + '\nconst S: &str = r#"a " b\n' + "".join(constants) + '"#;\n'),
        ("a constant declared twice", honest + first),
        ("a function after the constants", honest + "fn f() {}\n"),
        ("the first constant with another value", honest.replace(first, first.rstrip("\n")[:-1] + "9;\n", 1)),
        ("the first constant with another type", honest.replace(first, first.replace(": u32", ": u64"), 1)),
        ("the header missing", honest[len(GENERATED_HEADER) :]),
        ("CRLF line endings", honest.replace("\n", "\r\n")),
        ("no newline at the end", honest[:-1]),
        ("two constants swapped", honest.replace(constants[0] + constants[1], constants[1] + constants[0], 1)),
        ("the last constant missing", honest[: honest.rindex(constants[-1])]),
    )
    for label, text in bad:
        need(text != honest, f"control: {label} did not change the file")
        try:
            check_generated_text(text, label)
        except LinkV3Error:
            continue
        raise LinkV3Error(f"control: the generated-file check took {label}")
    return len(bad) + bytes_controls(honest)


def bytes_controls(honest: str) -> int:
    """The same check on a file written to disk, so a newline that a text read would translate is still seen."""
    with tempfile.TemporaryDirectory(prefix="zenoh-link-v3-bytes-") as scratch:
        path = Path(scratch) / GENERATED.name
        path.write_bytes(honest.encode("utf-8"))
        need(check_generated_text(read_exact(path), path.name) == len(CONSTANTS), "control: the honest bytes were not taken")
        bad = (
            ("CRLF line endings on disk", honest.replace("\n", "\r\n").encode("utf-8")),
            ("one lone carriage return on disk", honest.replace("\n", "\r", 1).encode("utf-8")),
            ("a UTF-8 byte order mark on disk", b"\xef\xbb\xbf" + honest.encode("utf-8")),
            ("bytes that are not UTF-8 on disk", honest.encode("utf-8") + b"\xff"),
        )
        for label, data in bad:
            path.write_bytes(data)
            try:
                check_generated_text(read_exact(path), path.name)
            except LinkV3Error:
                continue
            raise LinkV3Error(f"control: the generated-file check took {label}")
    return len(bad)


def judge_cases() -> int:
    """The records judged against the contract and the constants checked against the generated Rust."""
    taken, refused = record_counts()
    return taken + refused + len(CONSTANTS)


def all_controls() -> int:
    """Every refused record, weakened contract, drifted constant and corrupted file: the corruptions refused."""
    _taken, refused = record_counts()
    return refused + mutation_controls() + bound_controls() + arithmetic_controls() + lifting_controls() + generated_controls()


# What the item fixes, held here as well so the gate stays correct after the item moves to .tasks/terminal.
PINNED_CASES = 55
PINNED_CONTROLS = 79


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases_ = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases_.group(1)) if cases_ else 0, int(controls.group(1)) if controls else 0)
