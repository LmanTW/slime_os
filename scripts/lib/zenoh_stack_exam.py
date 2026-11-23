"""Judge the stack the Zenoh service needs at a stated size, from what a Rust test prints.

The component declares a stack (`STACK_BYTES` in `components/services/zenoh-service/src/main.rs`). The grants contract
bounds the arrays the core stores. It does not cover the link, the tables in the main frame or the call path.
The Rust test `zenoh_service_stack::the_stack_exam` prints, for two sizes, the `size_of` of each part and the depth of
the call path, which it measures by painting free stack. This module owns what those lines must be. Nothing here
reads the Rust:

* the two sizes: the built size of the component and the stated size;
* the four overheads of the grants contract, which no printed part size may exceed, and the contract's bound on the
  core's arrays;
* the stack need of a size, which is its printed frames plus its measured depth, and which the declared stack must cover;
* the declared stack, which may not exceed the stack the runtime reserves;
* the buffers, pages, loans and mappings a holder takes, from the client contract, against the system spec at the
  built size.

Like the other judges it is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re

import zenoh_grants_exam as grants
from harness import ROOT

MAIN = ROOT / "components" / "services" / "zenoh-service" / "src" / "main.rs"
RUNTIME = ROOT / "components" / "runtime" / "src" / "runtime.rs"
SPEC = ROOT / "contracts" / "system-spec" / "v1" / "systems" / "sel4-zenoh-service-four.zti"
CLIENT = ROOT / "contracts" / "zenoh-service-client" / "v1" / "schema.zt"
ITEM = ROOT / ".tasks" / "items" / "zenoh-stack-four.zt"

# label, holders, ring slots, payload bytes, rows. The built size is the component's, 4 holders and 6 rows, the size the
# composition `sel4-zenoh-service-four` runs. The stated size is the four
# components of the `sel4-robot-runtime` composition, with the 64-byte bound of its `TelemetrySample`.
CONFIGS = (
    ("built", 4, 4, 12, 6),
    ("stated", 4, 4, 64, 6),
)
PARTS = ("slot", "row", "holder", "fixed")
FRAMES = ("core", "link", "over", "server", "locals")
NAMES = (*PARTS, *FRAMES)
HEADER = 3
BLOCK = 3 + len(NAMES) + 1
SIZES_AT = 3
ARCHES = ("x86_64", "aarch64")
CALIBRATION_BYTES = 8192
CALIBRATION_TOLERANCE = 64
KEY_BYTES = 129
NUMBER = r"(0|[1-9][0-9]*)"

# The stated size's rows: (holder, key index, publish, subscribe). The sensor publishes telemetry. The controller
# subscribes to it and publishes a command. The actuator subscribes to the command. The supervisor subscribes to both.
STATED_HOLDERS = ("sensor", "controller", "actuator", "supervisor")
STATED_ROWS = (
    (0, 0, True, False),
    (1, 0, False, True),
    (1, 1, True, False),
    (2, 1, False, True),
    (3, 0, False, True),
    (3, 1, False, True),
)


class StackError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise StackError(message)


def _read(path, text: str | None) -> str:
    return path.read_text(encoding="utf-8") if text is None else text


def declared_stack(text: str | None = None) -> int:
    """`STACK_BYTES`, the stack the component declares."""
    found = re.search(r"^const STACK_BYTES: u32 = (\d+);$", _read(MAIN, text), re.M)
    _need(
        found is not None,
        "the component does not declare STACK_BYTES as `const STACK_BYTES: u32 = <n>;`",
    )
    return int(found.group(1))


LINK_ALIAS = "pub type Link<'a, 'b> = LinkOf<Stream<Wire<'a, 'b>>, 514, 2, 5, 129, PAYLOAD, 8, 4>;"
FRAME_ARRAYS = (
    "let mut record = [0u8; limits_wire::RECORD_LEN];",
    "let mut object = [0u8; TABLE_BYTES];",
    "let mut names = [[0u8; grants::HOLDER_NAME_BYTES]; HOLDERS];",
    "let mut name_lens = [0usize; HOLDERS];",
    "let mut keys = [[0u8; grants::MAX_KEY_BYTES]; ROWS];",
    "let mut key_lens = [0usize; ROWS];",
    "let mut stored: [(usize, bool, bool); ROWS] = [(0, false, false); ROWS];",
    "let mut page = [0u8; PAGE_ROWS * grants::ENTRY_BYTES];",
)


def link_line(label: str, payload: int) -> str:
    """The `Link` parameters the component builds, as the test must print them, from the alias in `main.rs`."""
    found = re.search(r"LinkOf<Stream<Wire<'a, 'b>>, ([^>]*)>;", LINK_ALIAS)
    parameters = found.group(1).replace("PAYLOAD", str(payload))
    return f"stack link {label} {parameters}"


def frame_line(label: str) -> str:
    """The arrays of the main frame, in order, as the test must print them."""
    names = [re.match(r"let mut ([a-z_]+)", array).group(1) for array in FRAME_ARRAYS]
    return f"stack frame {label} {' '.join(names)}"


def built_binding(text: str | None = None) -> None:
    """The built size and the tables the test restates, read from the component.

    The test restates the `Link` type and the arrays of the main frame. This binds each to `main.rs`, so a change to
    the component that the restatement does not follow is refused.
    """
    body = _read(MAIN, text)
    _, holders, slots, payload, rows = CONFIGS[0]
    for name, value in (("HOLDERS", holders), ("ROWS", rows), ("SLOTS", slots), ("PAYLOAD", payload), ("PAGE_ROWS", 6)):
        found = re.search(rf"^(?:pub )?const {name}: usize = (\d+);$", body, re.M)
        _need(found is not None, f"the component does not declare {name} as `const {name}: usize = <n>;`")
        _need(
            int(found.group(1)) == value,
            f"stack: the component declares {name} = {found.group(1)}, the exam measured {value}",
        )
    _need(
        body.count(LINK_ALIAS) == 1,
        "stack: the component's `Link` type is not the one the exam measured",
    )
    arrays = re.findall(r"^\s*(let mut [a-z_]+(?:: [^=]+)? = \[.*\];)$", body, re.M)
    _need(
        tuple(arrays) == FRAME_ARRAYS,
        f"stack: the arrays in the component's main frame are {arrays}, the exam measured {list(FRAME_ARRAYS)}",
    )


def runtime_stack(text: str | None = None) -> int:
    """`STACK_SIZE`, the stack the runtime reserves for one component thread."""
    found = re.search(r"^pub const STACK_SIZE: usize = (\d+) \* 1024;$", _read(RUNTIME, text), re.M)
    _need(
        found is not None,
        "the runtime does not declare STACK_SIZE as `pub const STACK_SIZE: usize = <n> * 1024;`",
    )
    return int(found.group(1)) * 1024


def spec_pages(text: str | None = None) -> tuple[int, int, int, int]:
    """The buffers, byte pages, loans and mappings the system spec declares for the instance `zenoh-service`."""
    for line in _read(SPEC, text).splitlines():
        if 'name = "zenoh-service";' not in line:
            continue
        found = re.search(
            r"bufferBytePages = (\d+); bufferCount = (\d+); mappingCount = (\d+); loanCount = (\d+);",
            line,
        )
        _need(
            found is not None,
            "the instance `zenoh-service` declares no buffer, mapping and loan counts",
        )
        pages, buffers, mappings, loans = (int(found.group(n)) for n in (1, 2, 3, 4))
        return buffers, pages, loans, mappings
    raise StackError("the system spec declares no instance named `zenoh-service`")


def holder_pages(text: str | None = None) -> tuple[int, int]:
    """The ring pages and data pages one holder takes, from the client contract."""
    body = _read(CLIENT, text)
    found = []
    for name in ("ringPages", "dataPages"):
        match = re.search(rf"^{name} :: Int = (\d+);$", body, re.M)
        _need(match is not None, f"the client contract does not state {name}")
        found.append(int(match.group(1)))
    return found[0], found[1]


def pages_for(holders: int, client: str | None = None) -> tuple[int, int, int, int]:
    """Buffers, byte pages, loans and mappings of a service with `holders` holders.

    A holder takes a ring buffer and a data buffer, each lent as one loan and mapped once. The service also maps the
    two regions of its attachment to the network service, which it imports and does not create.
    """
    ring, data = holder_pages(client)
    return holders * 2, holders * (ring + data), holders * 2, holders * 2 + 2


def bounds() -> dict[str, int]:
    constants = grants.schema_constants()
    return {
        "slot": constants["SLOT_OVERHEAD_BYTES"],
        "row": constants["ROW_OVERHEAD_BYTES"],
        "holder": constants["HOLDER_OVERHEAD_BYTES"],
        "fixed": constants["SERVICE_FIXED_BYTES"],
    }


def core_bound(holders: int, slots: int, payload: int, rows: int) -> int:
    """The contract's bound on the core. The core stores each key as a reference, so the bound has no key bytes."""
    b = bounds()
    return (
        b["fixed"]
        + holders * b["holder"]
        + holders * slots * (payload + b["slot"])
        + rows * b["row"]
    )


# The honest transcript, as a debug build on x86_64 printed it. The judge bounds each value and pins none.
HONEST = {
    "built": {
        "slot": 28,
        "row": 40,
        "holder": 8,
        "fixed": 120,
        "core": 936,
        "link": 3840,
        "over": 56,
        "server": 4,
        "locals": 3174,
        "depth": 16922,
    },
    "stated": {
        "slot": 24,
        "row": 40,
        "holder": 8,
        "fixed": 120,
        "core": 1704,
        "link": 4216,
        "over": 104,
        "server": 4,
        "locals": 2310,
        "depth": 16178,
    },
}


def good_lines() -> list[str]:
    out = [
        "stack arch x86_64",
        "stack profile debug",
        f"stack calibration {CALIBRATION_BYTES} 8200",
    ]
    for label, holders, slots, payload, rows in CONFIGS:
        value = HONEST[label]
        out.append(f"stack config {label} {holders} {slots} {payload} {rows}")
        out.append(link_line(label, payload))
        out.append(frame_line(label))
        out += [f"stack size {label} {name} {value[name]}" for name in NAMES]
        out.append(f"stack depth {label} {value['depth']}")
    return out


def _shapes() -> list[re.Pattern[str]]:
    shapes = [
        re.compile("stack arch (" + "|".join(ARCHES) + ")"),
        re.compile("stack profile debug"),
        re.compile(rf"stack calibration {CALIBRATION_BYTES} {NUMBER}"),
    ]
    for label, holders, slots, payload, rows in CONFIGS:
        shapes.append(re.compile(f"stack config {label} {holders} {slots} {payload} {rows}"))
        shapes.append(re.compile(re.escape(link_line(label, payload))))
        shapes.append(re.compile(re.escape(frame_line(label))))
        shapes += [re.compile(f"stack size {label} {name} {NUMBER}") for name in NAMES]
        shapes.append(re.compile(f"stack depth {label} {NUMBER}"))
    return shapes


def need_of(value: dict[str, int]) -> int:
    """The stack a size needs: the frames the main thread holds and the deepest call below them."""
    return sum(value[name] for name in FRAMES) + value["depth"]


def judge(
    lines: list[str],
    *,
    main: str | None = None,
    runtime: str | None = None,
    spec: str | None = None,
    client: str | None = None,
) -> int:
    """Returns the number of cases that hold. Any case that fails raises."""
    shapes = _shapes()
    _need(
        len(lines) == len(shapes),
        f"stack: the test printed {len(lines)} lines, the exam requires {len(shapes)}",
    )
    matches = []
    for index, (line, shape) in enumerate(zip(lines, shapes, strict=True)):
        found = shape.fullmatch(line)
        _need(found is not None, f"stack: line {index} is {line!r}, which is not {shape.pattern!r}")
        matches.append(found)
    declared = declared_stack(main)
    real = runtime_stack(runtime)
    built_binding(main)
    cases = 0
    calibration = int(matches[2].group(1))
    _need(
        CALIBRATION_BYTES <= calibration <= CALIBRATION_BYTES + CALIBRATION_TOLERANCE,
        f"stack: a frame of {CALIBRATION_BYTES} bytes measured {calibration}, outside {CALIBRATION_TOLERANCE} bytes",
    )
    cases += 1
    _need(
        declared <= real,
        f"stack: the declared stack {declared} is above the {real} bytes the runtime reserves",
    )
    cases += 1
    limit = bounds()
    for number, (label, holders, slots, payload, rows) in enumerate(CONFIGS):
        start = HEADER + number * BLOCK + SIZES_AT
        value = {name: int(matches[start + offset].group(1)) for offset, name in enumerate(NAMES)}
        value["depth"] = int(matches[start + len(NAMES)].group(1))
        for name in PARTS:
            _need(
                value[name] <= limit[name],
                f"stack: the {label} {name} size {value[name]} exceeds the contract's {limit[name]}",
            )
        cases += 1
        bound = core_bound(holders, slots, payload, rows)
        _need(
            value["core"] <= bound,
            f"stack: the {label} core is {value['core']} bytes, the contract bounds it at {bound}",
        )
        cases += 1
        _need(value["depth"] > 0, f"stack: the {label} call path measured no depth")
        cases += 1
        need = need_of(value)
        _need(
            need <= declared,
            f"stack: the {label} size needs {need} bytes, the declared stack is {declared}",
        )
        cases += 1
    built = pages_for(CONFIGS[0][1], client)
    found = spec_pages(spec)
    _need(
        found == built,
        f"stack: the system spec declares {found}, a service of {CONFIGS[0][1]} holders takes {built}",
    )
    cases += 1
    return cases


def stated_record(*, stack: int, holders: int | None = None) -> str:
    label, stated_holders, slots, payload, rows = CONFIGS[1]
    chosen = [(STATED_HOLDERS[h], grants.KEYS[k], p, s) for h, k, p, s in STATED_ROWS][:rows]
    return grants.record(
        holders=stated_holders if holders is None else holders,
        slots=slots,
        sample=payload,
        key_bytes=KEY_BYTES,
        local=3,
        stack=stack,
        rows=chosen,
    )


def contract_cases() -> int:
    """The grants contract accepts the stated size at the declared stack. It runs once, apart from `judge`."""
    declared = declared_stack()
    _need(
        grants.contract_accepts(stated_record(stack=declared)),
        f"stack: the grants contract refuses the stated size at the declared stack {declared}",
    )
    return 1


def _replace(lines: list[str], index: int, text: str) -> list[str]:
    changed = list(lines)
    changed[index] = text
    return changed


def _refused(label: str, lines: list[str], **sources: str) -> int:
    try:
        judge(lines, **sources)
    except StackError:
        return 1
    raise StackError(f"control: the stack judge accepted {label}")


def transcript_controls() -> int:
    good = good_lines()
    judge(good)
    refused = 0
    for index in range(len(good)):
        refused += _refused(f"line {index} missing", good[:index] + good[index + 1 :])
        refused += _refused(f"line {index} repeated", good[: index + 1] + good[index:])
    limit = bounds()
    declared = declared_stack()
    for number, (label, holders, slots, payload, rows) in enumerate(CONFIGS):
        base = HEADER + number * BLOCK
        sizes = base + SIZES_AT
        depth_at = sizes + len(NAMES)
        for offset, name in enumerate(PARTS):
            refused += _refused(
                f"a {label} {name} size one byte over the contract's {limit[name]}",
                _replace(good, sizes + offset, f"stack size {label} {name} {limit[name] + 1}"),
            )
        refused += _refused(
            f"a {label} core one byte over the contract's bound",
            _replace(
                good,
                sizes + NAMES.index("core"),
                f"stack size {label} core {core_bound(holders, slots, payload, rows) + 1}",
            ),
        )
        refused += _refused(
            f"a {label} depth of zero", _replace(good, depth_at, f"stack depth {label} 0")
        )
        refused += _refused(
            f"a {label} depth in hexadecimal", _replace(good, depth_at, f"stack depth {label} 0x10")
        )
        refused += _refused(
            f"a {label} depth with a leading zero",
            _replace(good, depth_at, f"stack depth {label} 016"),
        )
        refused += _refused(
            f"a {label} depth that is negative", _replace(good, depth_at, f"stack depth {label} -1")
        )
        link_at, frame_at = base + 1, base + 2
        refused += _refused(
            f"a {label} link with a smaller batch",
            _replace(good, link_at, good[link_at].replace("514", "256")),
        )
        refused += _refused(
            f"a {label} link with another payload",
            _replace(good, link_at, good[link_at].replace(f" {payload},", f" {payload + 1},")),
        )
        refused += _refused(f"a {label} link line missing", good[:link_at] + good[link_at + 1 :])
        for array in FRAME_ARRAYS:
            name = re.match(r"let mut ([a-z_]+)", array).group(1)
            refused += _refused(
                f"a {label} frame without {name}",
                _replace(good, frame_at, good[frame_at].replace(f" {name}", "", 1)),
            )
        refused += _refused(
            f"a {label} frame with an array more",
            _replace(good, frame_at, good[frame_at] + " extra"),
        )
        refused += _refused(
            f"a {label} frame in another order",
            _replace(good, frame_at, "stack frame " + label + " " + " ".join(reversed(good[frame_at].split()[3:]))),
        )
        refused += _refused(
            f"a {label} config of another size",
            _replace(good, base, f"stack config {label} {holders + 1} {slots} {payload} {rows}"),
        )
        value = dict(HONEST[label])
        value["depth"] = 0
        over = declared - need_of(value) + 1
        refused += _refused(
            f"a {label} depth that puts the need one byte over the declared stack",
            _replace(good, depth_at, f"stack depth {label} {over}"),
        )
        at_bound = declared - need_of(value)
        judge(_replace(good, depth_at, f"stack depth {label} {at_bound}"))
    refused += _refused(
        "a calibration frame read 1 byte short",
        _replace(good, 2, f"stack calibration {CALIBRATION_BYTES} {CALIBRATION_BYTES - 1}"),
    )
    refused += _refused(
        "a calibration frame read past the tolerance",
        _replace(
            good,
            2,
            f"stack calibration {CALIBRATION_BYTES} {CALIBRATION_BYTES + CALIBRATION_TOLERANCE + 1}",
        ),
    )
    judge(
        _replace(
            good,
            2,
            f"stack calibration {CALIBRATION_BYTES} {CALIBRATION_BYTES + CALIBRATION_TOLERANCE}",
        )
    )
    refused += _refused("a release build", _replace(good, 1, "stack profile release"))
    refused += _refused("an unknown architecture", _replace(good, 0, "stack arch riscv64"))
    swapped = list(good)
    swapped[HEADER + SIZES_AT], swapped[HEADER + SIZES_AT + 1] = swapped[HEADER + SIZES_AT + 1], swapped[HEADER + SIZES_AT]
    refused += _refused("two size lines swapped", swapped)
    blocks = list(good)
    blocks[HEADER : HEADER + BLOCK], blocks[HEADER + BLOCK :] = (
        good[HEADER + BLOCK :],
        good[HEADER : HEADER + BLOCK],
    )
    refused += _refused("the built and stated blocks swapped", blocks)
    return refused


def source_controls() -> int:
    """The declared stack, the runtime's stack, the system spec and the client contract are read from their files."""
    good = good_lines()
    main, runtime, spec, client = (
        path.read_text(encoding="utf-8") for path in (MAIN, RUNTIME, SPEC, CLIENT)
    )
    declared = declared_stack(main)
    refused = 0
    need = max(need_of({**HONEST[label]}) for label, *_ in CONFIGS)
    refused += _refused(
        "a declared stack one byte below the largest need",
        good,
        main=re.sub(r"STACK_BYTES: u32 = \d+;", f"STACK_BYTES: u32 = {need - 1};", main),
    )
    judge(good, main=re.sub(r"STACK_BYTES: u32 = \d+;", f"STACK_BYTES: u32 = {need};", main))
    refused += _refused(
        "a declared stack above the runtime's",
        good,
        main=re.sub(
            r"STACK_BYTES: u32 = \d+;", f"STACK_BYTES: u32 = {runtime_stack(runtime) + 1};", main
        ),
    )
    refused += _refused(
        "a component with no STACK_BYTES",
        good,
        main=main.replace("const STACK_BYTES", "const STACK_BYTE"),
    )
    refused += _refused(
        "a runtime with no STACK_SIZE",
        good,
        runtime=runtime.replace("pub const STACK_SIZE", "pub const STACK_SIZES"),
    )
    refused += _refused(
        "a runtime stack below the declared stack",
        good,
        runtime=re.sub(
            r"STACK_SIZE: usize = \d+ \* 1024;",
            f"STACK_SIZE: usize = {declared // 1024 - 1} * 1024;",
            runtime,
        ),
    )
    for name in ("HOLDERS", "ROWS", "SLOTS", "PAYLOAD", "PAGE_ROWS"):
        refused += _refused(
            f"a component with another {name}",
            good,
            main=re.sub(rf"(const {name}: usize = )(\d+);", lambda m: f"{m.group(1)}{int(m.group(2)) + 1};", main),
        )
        refused += _refused(
            f"a component with no {name}",
            good,
            main=main.replace(f"const {name}: usize", f"const {name}S: usize"),
        )
    refused += _refused(
        "a component with another Link type",
        good,
        main=main.replace(LINK_ALIAS, LINK_ALIAS.replace("514, 2, 5, 129", "514, 2, 5, 130")),
    )
    refused += _refused(
        "a component with no Link alias",
        good,
        main=main.replace(LINK_ALIAS, ""),
    )
    for array in FRAME_ARRAYS:
        refused += _refused(f"a component without `{array}`", good, main=main.replace(array, ""))
    refused += _refused(
        "a component with one more array in its main frame",
        good,
        main=main.replace(
            FRAME_ARRAYS[0], FRAME_ARRAYS[0] + "\n    let mut extra = [0u8; 4096];"
        ),
    )
    service_line = next(line for line in spec.splitlines() if 'name = "zenoh-service";' in line)

    def edited(old: str, new: str) -> str:
        return spec.replace(service_line, service_line.replace(old, new, 1))

    for old, new in (
        ("bufferCount = 8;", "bufferCount = 9;"),
        ("bufferBytePages = 8;", "bufferBytePages = 9;"),
        ("loanCount = 8;", "loanCount = 9;"),
        ("mappingCount = 10;", "mappingCount = 9;"),
    ):
        refused += _refused(f"a spec with `{new}` for the service", good, spec=edited(old, new))
    judge(good, spec=spec)
    refused += _refused(
        "a spec with no zenoh-service instance",
        good,
        spec=spec.replace('name = "zenoh-service";', 'name = "zenoh-services";'),
    )
    refused += _refused(
        "a client contract with two ring pages",
        good,
        client=client.replace("ringPages :: Int = 1;", "ringPages :: Int = 2;"),
    )
    refused += _refused(
        "a client contract with no data pages",
        good,
        client=client.replace("dataPages :: Int = 1;", ""),
    )
    return refused


def record_controls() -> int:
    """The stated record is the one the contract accepts. The contract refuses each fault the exam names."""
    declared = declared_stack()
    _, holders, slots, payload, rows = CONFIGS[1]
    required = grants.required_stack(holders, slots, payload, KEY_BYTES, rows)
    _need(
        grants.contract_accepts(stated_record(stack=required)),
        "control: the grants contract refuses the stated size at its own formula",
    )
    refused = 0
    for label, text in (
        (
            "a stated record with the stack one byte under the contract's formula",
            stated_record(stack=required - 1),
        ),
        (
            "a stated record with three holders for four names",
            stated_record(stack=declared, holders=3),
        ),
    ):
        _need(not grants.contract_accepts(text), f"control: the grants contract accepted {label}")
        refused += 1
    return refused


def all_controls() -> int:
    return transcript_controls() + source_controls() + record_controls()


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptance fixes, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
