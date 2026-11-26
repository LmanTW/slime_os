"""Judge the stack depth the Zenoh service measures on seL4 and prints at the end of the four-holder boot.

The service paints the free part of its stack with a known byte before it does any work. At exit it reads the lowest painted byte
the run changed and prints one line:

    [zenoh-service] stack used=<bytes> span=<bytes> above=<bytes> declared=<bytes>

`used` counts from the top of the runtime's stack down to the lowest changed byte. `span` is how far the paint reaches below the
top. `above` is the part of the stack the paint does not cover: the frame of `main` and the frames above the painted region.
`declared` is the stack the component declares. This module owns what that line must say, and nothing here reads the Rust beyond
the facts below:

* the line appears once, after every other line of the service;
* `declared` is the `stackBytes` of the component spec and the `STACK_BYTES` of the service;
* `span` is the depth the service paints, 61440 bytes. The `runtime-stack` fact pins the 65536 bytes the runtime reserves;
* `used` is above `above`, so the run changed a painted byte, and at most `declared`. `declared` is below `span`, so the run did
  not reach the end of the paint, and `used` is a measurement and not a bound.

The number is one build profile on one composition. The host exam in `zenoh_stack_exam` measures a debug build on x86_64. This
line measures the image the composition boots. Neither covers a run with more holders or a longer path.

The lines come from the guest, so the judge is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import zenoh_facts as facts
import zenoh_service_arm as arm
from harness import ROOT

COMPONENT = "components/services/zenoh-service"
MAIN = f"{COMPONENT}/src/main.rs"
STACK = f"{COMPONENT}/src/stack.rs"
RUNTIME = "components/runtime/src/runtime.rs"
SPEC = "contracts/component-spec/v1/components/zenoh-service.zti"
SERVICE = arm.SERVICE
PAINT_DEPTH = 60 * 1024

LINE = arm.STACK

FACTS: tuple[facts.Fact, ...] = (
    ("stack-module", MAIN, r"^mod stack;$", "mod stack;"),
    ("main-paints", MAIN, r"\bstack::paint\(stack::PAINT_DEPTH\);", "    let painted = stack::paint(stack::PAINT_DEPTH);"),
    ("main-prints", MAIN, r'\.bytes\(b"\[zenoh-service\] stack used="\)', '        .bytes(b"[zenoh-service] stack used=")'),
    ("main-declares", MAIN, r"^const STACK_BYTES: u32 = 32768;$", "const STACK_BYTES: u32 = 32768;"),
    ("paint-depth", STACK, r"^pub const PAINT_DEPTH: usize = 60 \* 1024;$", "pub const PAINT_DEPTH: usize = 60 * 1024;"),
    ("paint-byte", STACK, r"^const PAINT: u8 = 0xa5;$", "const PAINT: u8 = 0xa5;"),
    # The entry code loads the symbol's contents into the stack pointer. Its address is not the top of the stack.
    ("top-is-a-value", STACK, r"core::ptr::read\(core::ptr::addr_of!\(__sel4_runtime_common__stack_bottom\)\)",
     "    let top = unsafe { core::ptr::read(core::ptr::addr_of!(__sel4_runtime_common__stack_bottom)) };"),
    ("runtime-stack", RUNTIME, r"^pub const STACK_SIZE: usize = 64 \* 1024;$", "pub const STACK_SIZE: usize = 64 * 1024;"),
    ("spec-stack", SPEC, r"^\s*stackBytes = 32768;$", "      stackBytes = 32768;"),
)


class StackBootError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise StackBootError(message)


def read_file(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        raise StackBootError(f"{path} cannot be read: {error}") from error


def check_facts() -> int:
    try:
        return facts.check(FACTS, read_file)
    except facts.FactsError as error:
        raise StackBootError(str(error)) from error


def fact_controls() -> int:
    try:
        return facts.controls(FACTS)
    except facts.FactsError as error:
        raise StackBootError(str(error)) from error


def honest_line(used: int = 19840, span: int = PAINT_DEPTH, above: int = 14177, declared: int = 32768) -> str:
    return f"[{SERVICE}] stack used={used} span={span} above={above} declared={declared}"


def synthesize() -> list[str]:
    """The lines of the service in an honest run of the four-holder composition, with the stack line last."""
    return [*arm.synthesize(), honest_line()]


def judge(service: list[str]) -> tuple[int, int, int]:
    """Check the stack line among the service's lines. Returns (used, span, declared)."""
    stack = [line for line in service if line.startswith(f"[{SERVICE}] stack")]
    _need(len(stack) == 1, f"{SERVICE}: {len(stack)} stack lines, expected exactly one")
    _need(service[-1] == stack[0], f"{SERVICE}: the stack line is not the last line of the service")
    match = LINE.fullmatch(stack[0])
    _need(match is not None, f"{SERVICE}: a stack line that is not the exam's line: {stack[0]!r}")
    used, span, above, declared = (int(match.group(n)) for n in range(1, 5))
    _need(declared == 32768, f"{SERVICE}: the stack line declares {declared} bytes, the component spec declares 32768")
    _need(span == PAINT_DEPTH, f"{SERVICE}: the paint spans {span} bytes, the service paints {PAINT_DEPTH}")
    _need(used > above, f"{SERVICE}: used {used} does not exceed the {above} bytes the paint does not cover, so the run changed no painted byte")
    _need(used <= declared, f"{SERVICE}: the run used {used} bytes of stack and the component declares {declared}")
    return used, span, declared


def mutations() -> list[tuple[str, list[str]]]:
    good = synthesize()
    body = good[:-1]

    def with_line(line: str) -> list[str]:
        return [*body, line]

    return [
        ("an empty transcript", []),
        ("no stack line", body),
        ("two stack lines", [*good, good[-1]]),
        ("the stack line before the last detach", [*body[:-1], good[-1], body[-1]]),
        ("the stack line first", [good[-1], *body]),
        ("used equal to the span", with_line(honest_line(used=PAINT_DEPTH))),
        ("used above the span", with_line(honest_line(used=PAINT_DEPTH + 1))),
        ("used one byte above the declared stack", with_line(honest_line(used=32769))),
        ("used below the unpainted part", with_line(honest_line(used=14176))),
        ("used equal to the unpainted part", with_line(honest_line(used=14177))),
        ("used zero", with_line(honest_line(used=0))),
        ("a declared stack of 65536", with_line(honest_line(declared=65536))),
        ("a declared stack of 24576", with_line(honest_line(declared=24576))),
        ("a span of 40448", with_line(honest_line(span=40448))),
        ("a span above the runtime stack", with_line(honest_line(span=65536 + 4096))),
        ("an unpainted part equal to the span", with_line(honest_line(above=PAINT_DEPTH))),
        ("a field missing", with_line(f"[{SERVICE}] stack used=19840 span=61440 above=14177")),
        ("fields out of order", with_line(f"[{SERVICE}] stack span=61440 used=19840 above=14177 declared=32768")),
        ("a value that is not decimal", with_line(f"[{SERVICE}] stack used=0x4d80 span=61440 above=14177 declared=32768")),
        ("a field added", with_line(honest_line() + " extra=1")),
        ("the stack line of another component", with_line(honest_line().replace(f"[{SERVICE}]", "[zenoh-peer]"))),
    ]


def controls() -> int:
    """The honest transcript is accepted and every mutation of it is refused. Returns the number refused."""
    good = synthesize()
    _need(judge(good) == (19840, PAINT_DEPTH, 32768), "zenoh-service stack: the honest transcript was not accepted")
    refused = 0
    seen: dict[tuple[str, ...], str] = {}
    for label, lines in mutations():
        _need(lines != good, f"control: {label} did not change the transcript")
        _need(tuple(lines) not in seen, f"control: {label} repeats {seen.get(tuple(lines))}")
        seen[tuple(lines)] = label
        service = [line for line in lines if line.startswith(f"[{SERVICE}]") or line.startswith("[zenoh-peer]")]
        try:
            judge(service)
        except StackBootError:
            refused += 1
            continue
        raise StackBootError(f"control: the zenoh-service stack judge accepted {label}")
    return refused
