#!/usr/bin/env python3
"""Interrupt wait-source gate: a driver waits on its declared interrupt through the root.

A testkit probe drives one QEMU virtio-rng device through three requests. For
each request the root takes the device's interrupt, signals the probe's
declared `interrupt` wait-set badge, and acknowledges the line only when the
probe acknowledges that arrival's sequence.

The judge trusts no line the guest prints about the device. Three records
come from QEMU itself:

* QEMU's trace events, written with `-D`, state each queue kick, each buffer
  the device filled, each level change of the transport's interrupt line at
  the GIC, each acknowledgement of that line by the CPU, and each register
  access of the transport;
* the QEMU monitor, after the guest finishes, reads every virtio-mmio
  transport, so the judge finds the transport that holds the device;
* the pinned machine's device tree states each transport's interrupt.

The builder is judged as well: it accepts the composition's interrupt row and
refuses rows that name no interrupt source, share one, or collide with a
declared signaller.

The file name stays outside `check-sel4-*` and the closure name outside a
top-level `CLOSURE` constant until the `sel4-io-interrupt` closure exists,
because the test-run inventory and the devloop closure digest both resolve
those names.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import devloop_observations  # noqa: E402
from closure_image import ClosureImageError, build as build_closure_image  # noqa: E402
from harness import GENERATION_COMPOSITIONS, load_qemu_profile, sha256_file  # noqa: E402
from qemu_monitor import MONITOR_BANNER, MonitorRead, dump_device_tree, monitor_input, read_words  # noqa: E402
from sel4_plane import run_plane  # noqa: E402
from zutai_cli import STDLIB, binary  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PINS = ROOT / "sel4" / "pins.toml"
INTERRUPT_CLOSURE = "sel4-io-interrupt"
MANIFEST = GENERATION_COMPOSITIONS / "sel4-io-interrupt.zti"
TIMEOUT = 240
PROBE = "irq-wait-probe"
CYCLES = 3
HARDWARE_KINDS = ("device", "mmioRegion", "interruptSource", "dmaAccount")
# contracts/wait-set/v3: the root-signalled `interrupt` kind.
KIND_INTERRUPT = 8
GIC_SPI_BASE = 32

RNG_DEVICE: tuple[str, ...] = ("-object", "rng-random,id=slimerng,filename=/dev/urandom", "-device", "virtio-rng-device,rng=slimerng")
# virtio-mmio registers (virtio 1.2, section 4.2.2) the judge reads.
VIRTIO_MAGIC = 0x74726976
VIRTIO_DEVICE_RNG = 4
TRANSPORT_WORDS = 29  # MagicValue at 0x000 through Status at 0x070
DEVICE_ID_WORD = 0x008 // 4
INTERRUPT_STATUS = 0x060
INTERRUPT_ACK = 0x064
STATUS_WORD = 0x070 // 4
STATUS_DRIVER_OK = 0x4
USED_BUFFER = 0x1

TRACE_EVENTS: tuple[str, ...] = (
    "virtio_queue_notify",
    "virtio_rng_pushed",
    "virtio_set_status",
    "virtio_mmio_read",
    "virtio_mmio_write_offset",
    # The GIC traces the line with the seL4 IRQ number (32 + SPI).
    "gic_set_irq",
    "gic_acknowledge_irq",
)
HEX = r"[0-9a-f]"

DISPATCH = re.compile(r"^SLIME_IO irq dispatch task=(?P<task>\d+) irq=(?P<irq>\d+) badge=0x(?P<badge>[0-9a-f]+)$", re.M)
SUMMARY = re.compile(r"^SLIME_IO irq summary task=(?P<task>\d+) arrived=(?P<arrived>\d+) acked=(?P<acked>\d+) refused=(?P<refused>\d+)$", re.M)
BOUND = re.compile(rf"^\[{PROBE}\] interrupt bound epoch=(?P<epoch>\d+)$", re.M)
EARLY = re.compile(rf"^\[{PROBE}\] early ack refused sequence=(?P<sequence>\d+)$", re.M)
INTERRUPT = re.compile(rf"^\[{PROBE}\] interrupt sequence=(?P<sequence>\d+) status=0x(?P<status>{HEX}+) bytes=(?P<bytes>\d+)$", re.M)
DUPLICATE = re.compile(rf"^\[{PROBE}\] duplicate ack refused sequence=(?P<sequence>\d+)$", re.M)
COMPLETE = re.compile(rf"^\[{PROBE}\] interrupt wait plane complete cycles=(?P<cycles>\d+)$", re.M)
FAULT = re.compile(r"^SLIME_GRAPH component fault task=(?P<task>\d+) ", re.M)
RECLAIM = re.compile(r"^SLIME_IO reclaim task=(?P<task>\d+) (?P<fields>.*)$", re.M)
HEALTHY = re.compile(r"^SLIME_GRAPH HEALTHY generation=\d+ required=\d+ live=0 completed=\d+ failed=0$", re.M)
TRACE_LINE = re.compile(r"^(?P<event>(?:virtio|gic)_\w+)(?: (?P<arguments>.*))?$")
GIC_LEVEL = re.compile(r"^irq (?P<irq>\d+) level (?P<level>[01]) cpumask 0x[0-9a-f]+ target 0x[0-9a-f]+$")
GIC_ACK = re.compile(r"^v?cpu \d+ acknowledged irq (?P<irq>\d+)$")
QUEUE_NOTIFY = re.compile(r"^vdev \S+ n (?P<queue>\d+) vq \S+$")
PUSHED = re.compile(r"^rng \S+: (?P<bytes>\d+) bytes pushed$")
SET_STATUS = re.compile(r"^vdev \S+ val (?P<value>\d+)$")
MMIO_READ = re.compile(r"^virtio_mmio_read offset 0x(?P<offset>[0-9a-f]+)$")
MMIO_WRITE = re.compile(r"^virtio_mmio_write offset 0x(?P<offset>[0-9a-f]+) value 0x(?P<value>[0-9a-f]+)$")
TRANSPORT_NODE = re.compile(r"^\tvirtio_mmio@(?P<base>[0-9a-f]+) \{\n(?P<body>.*?)^\t\};$", re.M | re.S)

FAILURE_MARKERS: tuple[str, ...] = (
    r"SLIME_ROOT FATAL",
    r"SLIME_GRAPH FAIL",
    r"SLIME_IO FAIL",
    rf"\[{PROBE}\] fail: ",
    r"Caught cap fault",
    r"Caught vm fault",
    r"panicked at ",
)


class Refusal(Exception):
    """The judge refused an input."""


def fail(message: str) -> NoReturn:
    raise SystemExit(f"seL4 interrupt wait-source check: {message}")


def refuse(message: str) -> NoReturn:
    raise Refusal(message)


# --------------------------------------------------------------------------- QEMU records


@dataclass(frozen=True)
class Boot:
    """Everything one boot leaves behind: serial and monitor text, and trace text."""

    transcript: str
    trace: str


@dataclass(frozen=True)
class Transport:
    base: int
    irq: int


def parse_transports(dts: str) -> tuple[Transport, ...]:
    """Each virtio-mmio transport the device tree declares, with its seL4 IRQ number."""
    transports: list[Transport] = []
    for node in TRANSPORT_NODE.finditer(dts):
        body = node.group("body")
        if 'compatible = "virtio,mmio";' not in body:
            refuse(f"virtio_mmio@{node.group('base')} is not compatible with virtio,mmio")
        reg = re.search(r"^\s*reg = <(?P<cells>[^>]*)>;$", body, re.M)
        interrupts = re.search(r"^\s*interrupts = <(?P<cells>[^>]*)>;$", body, re.M)
        if reg is None or interrupts is None:
            refuse(f"virtio_mmio@{node.group('base')} lacks reg or interrupts")
        cells = [int(token, 16) for token in re.findall(r"0x[0-9a-f]+", reg.group("cells"))]
        spi = [int(token, 16) for token in re.findall(r"0x[0-9a-f]+", interrupts.group("cells"))]
        if len(cells) != 4 or len(spi) != 3 or spi[0] != 0:
            refuse(f"virtio_mmio@{node.group('base')} has reg {cells} interrupts {spi}")
        base = cells[0] << 32 | cells[1]
        if base != int(node.group("base"), 16):
            refuse(f"virtio_mmio@{node.group('base')} has reg base {base:#x}")
        transports.append(Transport(base, GIC_SPI_BASE + spi[1]))
    if not transports:
        refuse("the device tree declares no virtio-mmio transport")
    return tuple(sorted(transports, key=lambda transport: transport.base))


def monitor_reads(transports: tuple[Transport, ...]) -> tuple[MonitorRead, ...]:
    return tuple(MonitorRead(f"transport {transport.base:#x}", transport.base, TRANSPORT_WORDS) for transport in transports)


@dataclass(frozen=True)
class TraceEvent:
    index: int
    event: str
    arguments: str


def parse_trace(text: str) -> list[TraceEvent]:
    """Every line is one enabled trace event; anything else is refused."""
    events: list[TraceEvent] = []
    for index, line in enumerate(text.splitlines()):
        match = TRACE_LINE.match(line)
        if match is None or match.group("event") not in TRACE_EVENTS:
            refuse(f"trace line {index + 1} is not an enabled trace event: {line!r}")
        events.append(TraceEvent(index, match.group("event"), (match.group("arguments") or "").strip()))
    return events


def argument(pattern: re.Pattern[str], event: TraceEvent) -> re.Match[str]:
    match = pattern.match(event.arguments)
    if match is None:
        refuse(f"malformed {event.event} event: {event.arguments!r}")
    return match


# --------------------------------------------------------------------------- judges


class Tally:
    """Counts the assertions a judge made, so the record states what it checked."""

    def __init__(self) -> None:
        self.cases = 0

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            refuse(message)
        self.cases += 1


def single(pattern: re.Pattern[str], transcript: str, label: str, start: int = 0) -> re.Match[str]:
    found = list(pattern.finditer(transcript, start))
    if len(found) != 1:
        refuse(f"{label}: expected one line after position {start}, found {len(found)}")
    return found[0]


def reject_failures(transcript: str) -> None:
    for marker in FAILURE_MARKERS:
        found = re.search(marker, transcript)
        if found is not None:
            refuse(f"failure marker in serial transcript: {found.group(0)!r}")


def reclaim_fields(line: re.Match[str]) -> dict[str, int]:
    return {key: int(value) for key, value in re.findall(r"(\w+)=(\d+)", line.group("fields"))}


@dataclass(frozen=True)
class Declared:
    """What the derived manifest declares about the probe's interrupt source."""

    badge_bit: int
    interrupt_slot: int
    dma_slot: int
    notification: str


def judge_manifest(manifest: dict) -> tuple[int, Declared]:
    """The probe alone holds the hardware, and waits on its interrupt through one declared row."""
    tally = Tally()
    probes = [instance for instance in manifest.get("instances", []) if instance.get("executable") == PROBE]
    tally.require(len(probes) == 1, f"the composition runs {len(probes)} {PROBE} instances")
    probe = probes[0]
    name = probe["name"]
    hardware = [grant for grant in manifest.get("grants", []) if grant.get("capabilityKind") in HARDWARE_KINDS]
    kinds = sorted(grant["capabilityKind"] for grant in hardware)
    tally.require(kinds == sorted(HARDWARE_KINDS), f"the composition declares hardware grants {kinds}")
    tally.require(all(grant.get("target") == name for grant in hardware), f"a hardware grant targets another instance than {name}")
    budgets = [entry for entry in manifest.get("ioResourceBudget", []) if entry.get("holder") == name]
    tally.require(len(budgets) == 1, f"{name} has {len(budgets)} io-resource budgets")
    budget = budgets[0]
    tally.require(budget.get("irqSources") == 1, f"the budget declares {budget.get('irqSources')} interrupt sources")
    tally.require(budget.get("dmaPages", 0) > 0 and budget.get("dmaMappings", 0) > 0, "the budget declares no DMA")
    tally.require(budget.get("pciFunction") is None, "the budget declares a PCI function")

    slots = {binding["grant"]: binding["slot"] for binding in probe.get("bindings", [])}
    by_kind = {grant["capabilityKind"]: grant["name"] for grant in hardware}
    interrupt_slot = slots.get(by_kind["interruptSource"])
    dma_slot = slots.get(by_kind["dmaAccount"])
    tally.require(interrupt_slot is not None and dma_slot is not None, f"{name} binds no interrupt or DMA slot")

    rows = [row for row in manifest.get("waitSet") or [] if row.get("kind") == "interrupt"]
    tally.require(len(rows) == 1, f"the composition declares {len(rows)} interrupt wait-set rows")
    row = rows[0]
    tally.require(row.get("waiter") == name, f"the interrupt row's waiter is {row.get('waiter')}")
    tally.require(row.get("drainSlot") == interrupt_slot, f"the interrupt row drains slot {row.get('drainSlot')}, the interrupt source is at {interrupt_slot}")
    notification = row.get("notification")
    grants = [grant for grant in manifest.get("notificationGrants", []) if grant.get("name") == notification]
    tally.require(len(grants) == 1 and grants[0].get("target") == name, f"{notification} is not a notification granted to {name}")
    bindings = [binding for binding in manifest.get("notificationBindings", []) if binding.get("grant") == notification]
    waits = [binding for binding in bindings if binding.get("role") == "wait"]
    tally.require(len(waits) == 1 and waits[0].get("holder") == name, f"{name} does not alone wait on {notification}")
    badge_bit = row.get("badgeBit")
    tally.require(isinstance(badge_bit, int) and 0 <= badge_bit < 63, f"badge bit {badge_bit}")
    producers = [binding for binding in bindings if binding.get("role") == "signal" and binding.get("slot", -1) % 63 == badge_bit]
    tally.require(not producers, f"a declared signaller also produces badge bit {badge_bit}")
    return tally.cases, Declared(badge_bit, interrupt_slot, dma_slot, notification)


Encoder = Callable[[dict], list[tuple[bytes, int, int, int, int, int]]]


def builder_encoder() -> Encoder:
    import generation_resources

    return generation_resources.validated_wait_set


def judge_builder(manifest: dict, declared: Declared, encode: Encoder) -> int:
    """The builder encodes the interrupt row and refuses rows the root could not dispatch."""
    tally = Tally()
    name = next(instance["name"] for instance in manifest["instances"] if instance.get("executable") == PROBE)

    def builds(value: dict) -> list[tuple[bytes, int, int, int, int, int]] | None:
        try:
            return encode(value)
        except SystemExit:
            return None

    def copy() -> dict:
        return json.loads(json.dumps(manifest))

    def row(value: dict) -> dict:
        return next(entry for entry in value["waitSet"] if entry.get("kind") == "interrupt")

    entries = builds(manifest)
    tally.require(entries is not None, "the builder refuses the composition's wait set")
    interrupts = [entry for entry in entries or [] if entry[3] == KIND_INTERRUPT]
    tally.require(len(interrupts) == 1, f"the builder encodes {len(interrupts)} interrupt entries")
    entry = interrupts[0]
    tally.require(entry[1] == 1 << declared.badge_bit and entry[4] == declared.interrupt_slot, f"the builder encodes badge {entry[1]:#x} and drain slot {entry[4]}")

    other_slot = copy()
    row(other_slot)["drainSlot"] = declared.dma_slot
    tally.require(builds(other_slot) is None, "the builder accepts an interrupt row that drains the DMA account's slot")
    no_slot = copy()
    del row(no_slot)["drainSlot"]
    tally.require(builds(no_slot) is None, "the builder accepts an interrupt row without a drain slot")
    shared = copy()
    used = {entry.get("badgeBit") for entry in shared["waitSet"] if entry.get("waiter") == name}
    free = next(bit for bit in range(63) if bit not in used)
    shared["waitSet"].append({**row(shared), "badgeBit": free})
    tally.require(builds(shared) is None, "the builder accepts two interrupt rows on one interrupt source")
    collision = copy()
    collision["notificationBindings"].append({"grant": declared.notification, "holder": "init", "role": "signal", "slot": declared.badge_bit})
    tally.require(builds(collision) is None, "the builder accepts an interrupt badge that a declared signaller also produces")
    return tally.cases


def judge_boot(boot: Boot, transports: tuple[Transport, ...], declared: Declared, version: str) -> int:
    tally = Tally()
    transcript = boot.transcript
    reject_failures(transcript)
    healthy = single(HEALTHY, transcript, "graph health")
    guest = transcript[: healthy.end()]

    # QEMU places the device on one transport; its interrupt is the route.
    words = read_words(transcript, healthy.end(), monitor_reads(transports), version, refuse)
    holding = [transport for transport in transports if words[f"transport {transport.base:#x}"][DEVICE_ID_WORD] == VIRTIO_DEVICE_RNG]
    tally.require(len(holding) == 1, f"QEMU holds virtio-rng on {len(holding)} transports")
    transport = holding[0]
    registers = words[f"transport {transport.base:#x}"]
    tally.require(registers[0] == VIRTIO_MAGIC, f"transport {transport.base:#x} reads magic {registers[0]:#x}")
    tally.require(registers[INTERRUPT_STATUS // 4] == 0, f"the device still asserts interrupt status {registers[INTERRUPT_STATUS // 4]:#x}")
    tally.require(registers[STATUS_WORD] == 0, f"the device was left with status {registers[STATUS_WORD]:#x}, not reset")
    route = transport.irq

    # The root's record: one dispatch route, then one summary at the probe's exit.
    dispatch = single(DISPATCH, guest, "root interrupt dispatch")
    task = dispatch.group("task")
    tally.require(int(dispatch.group("irq")) == route, f"the root dispatches IRQ {dispatch.group('irq')}, the device tree routes {route}")
    tally.require(int(dispatch.group("badge"), 16) == 1 << declared.badge_bit, f"the root signals badge {dispatch.group('badge')}, the row declares bit {declared.badge_bit}")

    # The probe's report, in order.
    bound = single(BOUND, guest, "interrupt bound")
    tally.require(int(bound.group("epoch")) == 1, f"the probe runs at epoch {bound.group('epoch')}")
    tally.require(dispatch.end() < bound.start(), "the root dispatches the source after the probe reports it bound")
    early = single(EARLY, guest, "early acknowledgement", bound.end())
    tally.require(int(early.group("sequence")) == 1, f"the early acknowledgement names sequence {early.group('sequence')}")
    cycles = list(INTERRUPT.finditer(guest))
    tally.require(len(cycles) == CYCLES, f"the probe reports {len(cycles)} interrupts, expected {CYCLES}")
    tally.require(cycles[0].start() > early.end(), "an interrupt is reported before the early acknowledgement was refused")
    tally.require([int(cycle.group("sequence")) for cycle in cycles] == list(range(1, CYCLES + 1)), f"sequences {[c.group('sequence') for c in cycles]}")
    tally.require(all(int(cycle.group("status"), 16) == USED_BUFFER for cycle in cycles), f"interrupt status {[c.group('status') for c in cycles]}")
    reported = [int(cycle.group("bytes")) for cycle in cycles]
    tally.require(all(count > 0 for count in reported), f"the probe reports {reported} bytes")
    duplicate = single(DUPLICATE, guest, "duplicate acknowledgement", cycles[-1].end())
    tally.require(int(duplicate.group("sequence")) == CYCLES, f"the duplicate acknowledgement names sequence {duplicate.group('sequence')}")
    complete = single(COMPLETE, guest, "probe completion", duplicate.end())
    tally.require(int(complete.group("cycles")) == CYCLES, f"the probe completes {complete.group('cycles')} cycles")
    tally.require(not FAULT.search(guest), "a component faulted")

    summary = single(SUMMARY, guest, "root interrupt summary")
    tally.require(summary.group("task") == task, f"the summary names task {summary.group('task')}, the dispatch task {task}")
    tally.require(summary.start() > complete.end(), "the root summarised the source before the probe completed")
    counts = (int(summary.group("arrived")), int(summary.group("acked")), int(summary.group("refused")))
    tally.require(counts == (CYCLES, CYCLES, 2), f"the root counts arrived, acked, refused {counts}, expected {(CYCLES, CYCLES, 2)}")
    reclaim = single(RECLAIM, guest, "probe reclaim")
    tally.require(reclaim.group("task") == task and complete.end() <= reclaim.start(), "the reclaim names another task or precedes the completion")
    fields = reclaim_fields(reclaim)
    tally.require(fields.get("pre_irq_sources") == 1 and fields.get("pre_dma_mappings", 0) >= 1, "the probe did not hold the interrupt and a DMA mapping")
    for key in ("post_mmio_bytes", "post_mmio_mappings", "post_irq_sources", "post_dma_pages", "post_dma_mappings", "post_requests"):
        tally.require(fields.get(key) == 0, f"the exit reclaim leaves {key}={fields.get(key)}")

    # QEMU's own record of the device and the line.
    events = parse_trace(boot.trace)
    ready = [event for event in events if event.event == "virtio_set_status" and int(argument(SET_STATUS, event).group("value")) & STATUS_DRIVER_OK]
    tally.require(len(ready) == 1, f"the device was set ready {len(ready)} times")
    start = ready[0].index
    pushes = [event for event in events if event.event == "virtio_rng_pushed"]
    tally.require(len(pushes) == CYCLES and pushes[0].index > start, f"the device filled {len(pushes)} buffers after it was set ready")
    resets = [event for event in events if event.event == "virtio_set_status" and event.index > pushes[-1].index and argument(SET_STATUS, event).group("value") == "0"]
    tally.require(bool(resets), "the device was not reset after its last buffer")
    end = resets[0].index

    marks: list[tuple[str, int, int]] = []
    for event in events:
        if event.event == "gic_set_irq":
            level = argument(GIC_LEVEL, event)
            if int(level.group("irq")) == route:
                marks.append(("raise" if level.group("level") == "1" else "lower", 0, event.index))
        elif event.event == "gic_acknowledge_irq":
            if int(argument(GIC_ACK, event).group("irq")) == route:
                marks.append(("take", 0, event.index))
        elif not start < event.index < end:
            continue
        elif event.event == "virtio_queue_notify":
            marks.append(("kick", int(argument(QUEUE_NOTIFY, event).group("queue")), event.index))
        elif event.event == "virtio_rng_pushed":
            marks.append(("fill", int(argument(PUSHED, event).group("bytes")), event.index))
        elif event.event == "virtio_mmio_write_offset":
            write = argument(MMIO_WRITE, event)
            if int(write.group("offset"), 16) == INTERRUPT_ACK:
                marks.append(("clear", int(write.group("value"), 16), event.index))
        elif event.event == "virtio_mmio_read":
            if int(argument(MMIO_READ, event).group("offset"), 16) == INTERRUPT_STATUS:
                marks.append(("status", 0, event.index))
    tally.require(all(start < index < end for kind, _value, index in marks if kind in ("raise", "take", "lower")), f"IRQ {route} changed outside the probe's use of the device")
    sequence = [(kind, value) for kind, value, _index in marks if kind != "status"]
    expected = [step for count in reported for step in (("kick", 0), ("fill", count), ("raise", 0), ("take", 0), ("clear", USED_BUFFER), ("lower", 0))]
    tally.require(sequence == expected, f"the device and the line recorded {sequence}, expected {expected}")
    # Each interrupt status read sits between the CPU taking the line and the probe clearing it.
    takes = [index for kind, _value, index in marks if kind == "take"]
    clears = [index for kind, _value, index in marks if kind == "clear"]
    reads = [index for kind, _value, index in marks if kind == "status"]
    tally.require(
        all(any(taken < read < cleared for read in reads) for taken, cleared in zip(takes, clears, strict=True)),
        "the probe cleared an interrupt without reading its status after the CPU took it",
    )
    return tally.cases


# --------------------------------------------------------------------------- controls


def edit(text: str, pattern: re.Pattern[str], change: Callable[[re.Match[str]], str], index: int = 0) -> str:
    found = list(pattern.finditer(text))
    if len(found) <= index:
        fail(f"control needs line {index} matching {pattern.pattern!r}")
    match = found[index]
    return text[: match.start()] + change(match) + text[match.end() :]


def replace_group(match: re.Match[str], group: str, value: str) -> str:
    line = match.group(0)
    start, end = match.start(group) - match.start(), match.end(group) - match.start()
    return line[:start] + value + line[end:]


def insert_before(text: str, pattern: re.Pattern[str], line: str) -> str:
    match = pattern.search(text)
    if match is None:
        fail(f"control needs a line matching {pattern.pattern!r}")
    return text[: match.start()] + line + "\n" + text[match.start() :]


def move_line_before(text: str, pattern: re.Pattern[str], anchor: re.Pattern[str]) -> str:
    match = pattern.search(text)
    if match is None:
        fail(f"control needs a line matching {pattern.pattern!r}")
    removed = text[: match.start()] + text[match.end() + 1 :]
    return insert_before(removed, anchor, match.group(0))


def drop_line(text: str, pattern: re.Pattern[str], index: int = 0) -> str:
    found = list(pattern.finditer(text))
    if len(found) <= index:
        fail(f"control needs line {index} matching {pattern.pattern!r}")
    match = found[index]
    return text[: match.start()] + text[match.end() + 1 :]


def set_field(line: str, key: str, value: int) -> str:
    changed, made = re.subn(rf"\b{key}=\d+", f"{key}={value}", line)
    if made != 1:
        fail(f"control needs one {key} field")
    return changed


def set_word(transcript: str, read: MonitorRead, index: int, value: int) -> str:
    """Replace one word of one `xp` reply, keeping the reply's length."""
    pattern = re.compile(rf"^0*{read.address + 16 * (index // 4):x}: (?P<words>(?:0x[0-9a-f]{{8}} ?)+)$", re.M)

    def change(match: re.Match[str]) -> str:
        values = match.group("words").split()
        if index % 4 >= len(values):
            fail(f"control needs word {index} of {read.command()!r}")
        values[index % 4] = f"0x{value:08x}"
        return replace_group(match, "words", " ".join(values))

    return edit(transcript, pattern, change)


def trace_lines(trace: str, event: str, pattern: re.Pattern[str] | None = None) -> list[int]:
    """Indices of the lines that record `event`, optionally with arguments matching `pattern`."""
    lines = trace.splitlines()
    found = []
    for index, line in enumerate(lines):
        name, _, arguments = line.partition(" ")
        if name == event and (pattern is None or pattern.match(arguments)):
            found.append(index)
    return found


def drop_trace(trace: str, event: str, occurrence: int, pattern: re.Pattern[str] | None = None) -> str:
    lines = trace.splitlines(keepends=True)
    found = trace_lines(trace, event, pattern)
    if len(found) <= occurrence:
        fail(f"trace control needs {occurrence + 1} {event} lines")
    del lines[found[occurrence]]
    return "".join(lines)


def duplicate_trace(trace: str, event: str, occurrence: int, pattern: re.Pattern[str] | None = None) -> str:
    lines = trace.splitlines(keepends=True)
    found = trace_lines(trace, event, pattern)
    if len(found) <= occurrence:
        fail(f"trace control needs {occurrence + 1} {event} lines")
    lines.insert(found[occurrence] + 1, lines[found[occurrence]])
    return "".join(lines)


def swap_trace(trace: str, first: tuple[str, int, re.Pattern[str] | None], second: tuple[str, int, re.Pattern[str] | None]) -> str:
    """Exchange two trace lines, each named by event, occurrence and argument pattern."""
    lines = trace.splitlines(keepends=True)
    picked = []
    for event, occurrence, pattern in (first, second):
        found = trace_lines(trace, event, pattern)
        if len(found) <= occurrence:
            fail(f"trace control needs {occurrence + 1} {event} lines")
        picked.append(found[occurrence])
    a, b = picked
    lines[a], lines[b] = lines[b], lines[a]
    return "".join(lines)


def trace_edit(trace: str, pattern: str, replacement: str, count: int = 1) -> str:
    changed, made = re.subn(pattern, replacement, trace, count=count, flags=re.M)
    if not made:
        fail(f"trace control needs a line matching {pattern!r}")
    return changed


def spoof_reply(transcript: str, read: MonitorRead) -> str:
    """Guest output after the switch prints its own echo and reply for one read."""
    banner = MONITOR_BANNER.search(transcript)
    if banner is None:
        fail("control needs the monitor banner")
    spoofed = f"\n(qemu) {read.command()}\n{read.address:x}: 0x00000000"
    return transcript[: banner.end()] + spoofed + transcript[banner.end() :]


def run_controls(mutations: tuple[tuple[str, Callable[[], object]], ...]) -> int:
    refused = 0
    for label, judge in mutations:
        try:
            judge()
        except Refusal:
            refused += 1
            continue
        fail(f"control accepted: {label}")
    return refused


def holding_transport(boot: Boot, transports: tuple[Transport, ...], version: str) -> Transport:
    healthy = HEALTHY.search(boot.transcript)
    if healthy is None:
        fail("control needs graph health")
    words = read_words(boot.transcript, healthy.end(), monitor_reads(transports), version, fail)
    return next(transport for transport in transports if words[f"transport {transport.base:#x}"][DEVICE_ID_WORD] == VIRTIO_DEVICE_RNG)


def boot_controls(boot: Boot, transports: tuple[Transport, ...], declared: Declared, version: str) -> int:
    transcript, trace = boot.transcript, boot.trace
    transport = holding_transport(boot, transports, version)
    reads = {read.label: read for read in monitor_reads(transports)}
    read = reads[f"transport {transport.base:#x}"]
    other = next(candidate for candidate in transports if candidate != transport)
    route = transport.irq
    raise_line = re.compile(rf"^irq {route} level 1 ")
    lower_line = re.compile(rf"^irq {route} level 0 ")
    take_line = re.compile(rf"^v?cpu \d+ acknowledged irq {route}$")
    clear_line = re.compile(rf"^virtio_mmio_write offset 0x{INTERRUPT_ACK:x} ")
    status_line = re.compile(rf"^virtio_mmio_read offset 0x{INTERRUPT_STATUS:x}$")

    def text(mutated: str) -> Boot:
        if mutated == transcript:
            fail("a transcript control did not change the transcript")
        return Boot(mutated, trace)

    def traced(mutated: str) -> Boot:
        if mutated == trace:
            fail("a trace control did not change the trace")
        return Boot(transcript, mutated)

    def plus(value: str, step: int) -> str:
        return str(int(value) + step)

    def summary(key: str, step: int) -> Boot:
        return text(edit(transcript, SUMMARY, lambda m: replace_group(m, key, plus(m.group(key), step))))

    cases: tuple[tuple[str, Boot], ...] = (
        ("root dispatches another IRQ", text(edit(transcript, DISPATCH, lambda m: replace_group(m, "irq", plus(m.group("irq"), 1))))),
        ("root signals another badge", text(edit(transcript, DISPATCH, lambda m: replace_group(m, "badge", f"{(1 << declared.badge_bit) << 1:x}")))),
        ("root never dispatches", text(drop_line(transcript, DISPATCH))),
        ("root dispatches twice", text(insert_before(transcript, BOUND, DISPATCH.search(transcript).group(0)))),
        ("root dispatches after the probe is bound", text(move_line_before(transcript, DISPATCH, EARLY))),
        ("probe runs at another epoch", text(edit(transcript, BOUND, lambda m: replace_group(m, "epoch", "2")))),
        ("early acknowledgement never refused", text(drop_line(transcript, EARLY))),
        ("early acknowledgement names sequence 0", text(edit(transcript, EARLY, lambda m: replace_group(m, "sequence", "0")))),
        ("interrupt reported before the early acknowledgement", text(move_line_before(transcript, INTERRUPT, EARLY))),
        ("probe reports two interrupts", text(drop_line(transcript, INTERRUPT, CYCLES - 1))),
        ("probe repeats a sequence", text(edit(transcript, INTERRUPT, lambda m: replace_group(m, "sequence", "1"), 1))),
        ("interrupt status names no used buffer", text(edit(transcript, INTERRUPT, lambda m: replace_group(m, "status", "2"), 0))),
        ("probe reports zero bytes", text(edit(transcript, INTERRUPT, lambda m: replace_group(m, "bytes", "0"), 2))),
        ("probe reports bytes the device did not fill", text(edit(transcript, INTERRUPT, lambda m: replace_group(m, "bytes", plus(m.group("bytes"), 1)), 1))),
        ("duplicate acknowledgement never refused", text(drop_line(transcript, DUPLICATE))),
        ("duplicate acknowledgement names another sequence", text(edit(transcript, DUPLICATE, lambda m: replace_group(m, "sequence", "1")))),
        ("probe completes another cycle count", text(edit(transcript, COMPLETE, lambda m: replace_group(m, "cycles", plus(m.group("cycles"), 1))))),
        ("probe faults", text(insert_before(transcript, HEALTHY, "SLIME_GRAPH component fault task=1 kind=vm"))),
        ("probe reports a failure", text(insert_before(transcript, HEALTHY, f"[{PROBE}] fail: wait"))),
        ("root counts an extra arrival", summary("arrived", 1)),
        ("root counts a missing acknowledgement", summary("acked", -1)),
        ("root refused an acknowledgement the probe polled", summary("refused", 1)),
        ("summary names another task", summary("task", 1)),
        ("summary precedes the completion", text(move_line_before(transcript, SUMMARY, BOUND))),
        ("exit reclaim leaves the interrupt", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "post_irq_sources", 1)))),
        ("probe held no interrupt", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "pre_irq_sources", 0)))),
        ("probe held no DMA mapping", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "pre_dma_mappings", 0)))),
        ("exit reclaim leaves DMA pages", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "post_dma_pages", 1)))),
        ("exit reclaim leaves MMIO bytes", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "post_mmio_bytes", 4096)))),
        ("exit reclaim leaves an MMIO mapping", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "post_mmio_mappings", 1)))),
        ("exit reclaim leaves a DMA mapping", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "post_dma_mappings", 1)))),
        ("exit reclaim leaves a request", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "post_requests", 1)))),
        ("reclaim names another task", text(edit(transcript, RECLAIM, lambda m: replace_group(m, "task", plus(m.group("task"), 1))))),
        ("graph reports a failed instance", text(edit(transcript, HEALTHY, lambda m: m.group(0).replace("failed=0", "failed=1")))),
        ("device left asserting its interrupt", text(set_word(transcript, read, INTERRUPT_STATUS // 4, USED_BUFFER))),
        ("device left running", text(set_word(transcript, read, STATUS_WORD, 0x7))),
        ("transport reads another magic", text(set_word(transcript, read, 0, 0x74726975))),
        ("QEMU holds the device on another transport", text(set_word(set_word(transcript, read, DEVICE_ID_WORD, 0), reads[f"transport {other.base:#x}"], DEVICE_ID_WORD, VIRTIO_DEVICE_RNG))),
        ("QEMU holds the device on two transports", text(set_word(transcript, reads[f"transport {other.base:#x}"], DEVICE_ID_WORD, VIRTIO_DEVICE_RNG))),
        ("guest spoofs a monitor reply", text(spoof_reply(transcript, read))),
        ("device filled one buffer fewer", traced(drop_trace(trace, "virtio_rng_pushed", CYCLES - 1))),
        ("device filled another byte count", traced(trace_edit(trace, r"^(virtio_rng_pushed rng \S+: )(\d+)", lambda m: f"{m.group(1)}{int(m.group(2)) + 1}"))),
        ("line never raised for the second request", traced(drop_trace(trace, "gic_set_irq", 1, raise_line))),
        ("CPU never took the first interrupt", traced(drop_trace(trace, "gic_acknowledge_irq", 0, take_line))),
        ("CPU took an interrupt twice", traced(duplicate_trace(trace, "gic_acknowledge_irq", 1, take_line))),
        ("line never lowered after the last request", traced(drop_trace(trace, "gic_set_irq", CYCLES - 1, lower_line))),
        ("probe cleared the interrupt before the CPU took it", traced(swap_trace(trace, ("gic_acknowledge_irq", 0, take_line), ("virtio_mmio_write_offset", 0, clear_line)))),
        ("probe never cleared the second interrupt", traced(drop_trace(trace, "virtio_mmio_write_offset", 1, clear_line))),
        ("probe cleared another status bit", traced(trace_edit(trace, rf"^(virtio_mmio_write_offset virtio_mmio_write offset 0x{INTERRUPT_ACK:x} value 0x)1$", r"\g<1>3"))),
        ("probe never read the last interrupt's status", traced(drop_status_reads(trace, take_line, clear_line, status_line))),
        ("probe kicked twice for one request", traced(duplicate_trace(trace, "virtio_queue_notify", 0))),
        ("device never set ready", traced(clear_ready(trace))),
        ("device set ready twice", traced(duplicate_trace(trace, "virtio_set_status", 0, READY_STATUS))),
        ("device never reset after its last buffer", traced(drop_reset(trace))),
        ("line raised after the reset", traced(append_copy(trace, "gic_set_irq", raise_line))),
    )
    mutations = [(label, lambda mutated=mutated: judge_boot(mutated, transports, declared, version)) for label, mutated in cases]
    moved = tuple(Transport(candidate.base, candidate.irq + 1) for candidate in transports)
    mutations.append(("judge model with another transport route", lambda: judge_boot(boot, moved, declared, version)))
    mutations.append(("judge model with another badge", lambda: judge_boot(boot, transports, Declared(declared.badge_bit + 1, declared.interrupt_slot, declared.dma_slot, declared.notification), version)))
    return run_controls(tuple(mutations))


class _ReadyStatus:
    """Matches a status write's arguments when the value sets DRIVER_OK."""

    def match(self, arguments: str) -> re.Match[str] | None:
        found = SET_STATUS.match(arguments)
        return found if found is not None and int(found.group("value")) & STATUS_DRIVER_OK else None


READY_STATUS = _ReadyStatus()


def clear_ready(trace: str) -> str:
    """Clear DRIVER_OK from every status write that sets it."""

    def change(match: re.Match[str]) -> str:
        return f"{match.group(1)}{int(match.group(2)) & ~STATUS_DRIVER_OK}"

    changed, made = re.subn(r"^(virtio_set_status vdev \S+ val )(\d+)$", change, trace, flags=re.M)
    if changed == trace or not made:
        fail("trace control needs a status write that sets DRIVER_OK")
    return changed


def append_copy(trace: str, event: str, pattern: re.Pattern[str]) -> str:
    """Append a copy of the first `event` line whose arguments match `pattern`."""
    found = trace_lines(trace, event, pattern)
    if not found:
        fail(f"trace control needs a {event} line")
    return trace + trace.splitlines()[found[0]] + "\n"


def drop_status_reads(trace: str, take: re.Pattern[str], clear: re.Pattern[str], status: re.Pattern[str]) -> str:
    """Remove the interrupt status reads between the CPU's last take and the last clear."""
    taken = trace_lines(trace, "gic_acknowledge_irq", take)
    cleared = trace_lines(trace, "virtio_mmio_write_offset", clear)
    if not taken or not cleared:
        fail("trace control needs a take and a clear")
    reads = {index for index in trace_lines(trace, "virtio_mmio_read", status) if taken[-1] < index < cleared[-1]}
    if not reads:
        fail("trace control needs a status read before the last clear")
    return "".join(line for index, line in enumerate(trace.splitlines(keepends=True)) if index not in reads)


def drop_reset(trace: str) -> str:
    """Remove every status reset after the device's last filled buffer."""
    lines = trace.splitlines(keepends=True)
    last = trace_lines(trace, "virtio_rng_pushed")[-1]
    kept = [line for index, line in enumerate(lines) if not (index > last and line.rstrip("\n").startswith("virtio_set_status ") and line.rstrip("\n").endswith(" val 0"))]
    return "".join(kept)


def builder_controls(manifest: dict, declared: Declared, encode: Encoder) -> int:
    """Encoders that accept what the builder must refuse, or encode what it must not."""

    def lenient(repair: Callable[[dict], None]) -> Encoder:
        """An encoder that repairs one defect before encoding, so it accepts that defect."""

        def encoder(value: dict) -> list[tuple[bytes, int, int, int, int, int]]:
            copy = json.loads(json.dumps(value))
            repair(copy)
            return encode(copy)

        return encoder

    def interrupt_rows(value: dict) -> list[dict]:
        return [entry for entry in value["waitSet"] if entry.get("kind") == "interrupt"]

    def restore_slot(value: dict) -> None:
        for entry in interrupt_rows(value):
            if entry.get("drainSlot") == declared.dma_slot:
                entry["drainSlot"] = declared.interrupt_slot

    def fill_slot(value: dict) -> None:
        for entry in interrupt_rows(value):
            entry.setdefault("drainSlot", declared.interrupt_slot)

    def drop_shared(value: dict) -> None:
        for entry in interrupt_rows(value)[1:]:
            value["waitSet"].remove(entry)

    def drop_collision(value: dict) -> None:
        value["notificationBindings"] = [
            binding
            for binding in value["notificationBindings"]
            if not (binding.get("grant") == declared.notification and binding.get("role") == "signal" and binding.get("slot", -1) % 63 == declared.badge_bit)
        ]

    def refuses_everything(_value: dict) -> list[tuple[bytes, int, int, int, int, int]]:
        raise SystemExit("refused")

    def drains(slot: int) -> Encoder:
        return lambda value: [(*entry[:4], slot, entry[5]) if entry[3] == KIND_INTERRUPT else entry for entry in encode(value)]

    def as_kind(kind: int) -> Encoder:
        return lambda value: [(*entry[:3], kind, *entry[4:]) if entry[3] == KIND_INTERRUPT else entry for entry in encode(value)]

    def badge(shift: int) -> Encoder:
        return lambda value: [(entry[0], entry[1] << shift, *entry[2:]) if entry[3] == KIND_INTERRUPT else entry for entry in encode(value)]

    cases: tuple[tuple[str, Encoder], ...] = (
        ("builder accepts a row on the DMA slot", lenient(restore_slot)),
        ("builder accepts a row without a drain slot", lenient(fill_slot)),
        ("builder accepts two rows on one source", lenient(drop_shared)),
        ("builder accepts a colliding signaller", lenient(drop_collision)),
        ("builder refuses the composition", refuses_everything),
        ("builder encodes the DMA slot", drains(declared.dma_slot)),
        ("builder encodes the row as a device source", as_kind(7)),
        ("builder encodes another badge", badge(1)),
    )
    return run_controls(tuple((label, lambda value=value: judge_builder(manifest, declared, value)) for label, value in cases))


def manifest_controls(manifest: dict) -> int:
    def mutated(change: Callable[[dict], None]) -> dict:
        copy = json.loads(json.dumps(manifest))
        change(copy)
        return copy

    def hardware(copy: dict, kind: str) -> dict:
        return next(grant for grant in copy["grants"] if grant.get("capabilityKind") == kind)

    def row(copy: dict) -> dict:
        return next(entry for entry in copy["waitSet"] if entry.get("kind") == "interrupt")

    def probe(copy: dict) -> dict:
        return next(instance for instance in copy["instances"] if instance.get("executable") == PROBE)

    def budget(copy: dict) -> dict:
        return next(entry for entry in copy["ioResourceBudget"] if entry.get("holder") == probe(copy)["name"])

    def signaller(copy: dict) -> None:
        copy["notificationBindings"].append({"grant": row(copy)["notification"], "holder": "init", "role": "signal", "slot": row(copy)["badgeBit"]})

    cases: tuple[tuple[str, dict], ...] = (
        ("a second probe instance", mutated(lambda c: c["instances"].append({**probe(c), "name": f"{PROBE}-b"}))),
        ("probe holds no interrupt source", mutated(lambda c: c["grants"].remove(hardware(c, "interruptSource")))),
        ("a hardware grant targets init", mutated(lambda c: hardware(c, "dmaAccount").update(target="init"))),
        ("probe holds two io-resource budgets", mutated(lambda c: c["ioResourceBudget"].append(dict(budget(c))))),
        ("budget declares two interrupt sources", mutated(lambda c: budget(c).update(irqSources=2))),
        ("budget declares no DMA", mutated(lambda c: budget(c).update(dmaPages=0))),
        ("budget declares a PCI function", mutated(lambda c: budget(c).update(pciFunction={"bus": 0, "device": 3, "function": 0, "vendor": 0x1B36, "deviceId": 0x000D}))),
        ("probe binds no interrupt slot", mutated(lambda c: probe(c)["bindings"].remove(next(b for b in probe(c)["bindings"] if b["grant"] == hardware(c, "interruptSource")["name"])))),
        ("interrupt row on badge bit 63", mutated(lambda c: row(c).update(badgeBit=63))),
        ("no interrupt row", mutated(lambda c: c["waitSet"].remove(row(c)))),
        ("interrupt row waits for init", mutated(lambda c: row(c).update(waiter="init"))),
        ("interrupt row drains the DMA slot", mutated(lambda c: row(c).update(drainSlot=next(b["slot"] for b in probe(c)["bindings"] if b["grant"] == hardware(c, "dmaAccount")["name"])))),
        ("interrupt row names an undeclared notification", mutated(lambda c: row(c).update(notification="undeclared"))),
        ("init also waits on the notification", mutated(lambda c: c["notificationBindings"].append({"grant": row(c)["notification"], "holder": "init", "role": "wait", "slot": 0}))),
        ("a declared signaller produces the interrupt badge", mutated(signaller)),
    )
    return run_controls(tuple((label, lambda value=value: judge_manifest(value)) for label, value in cases))


# --------------------------------------------------------------------------- driver


def read_manifest() -> dict:
    if not MANIFEST.is_file():
        fail(f"{MANIFEST.relative_to(ROOT)} does not exist; the {INTERRUPT_CLOSURE} composition has not landed")
    environment = dict(os.environ)
    environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
    decoded = subprocess.run(
        [str(binary()), "json", str(MANIFEST)],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if decoded.returncode:
        fail(f"cannot decode {MANIFEST.relative_to(ROOT)}: {decoded.stderr.strip()}")
    try:
        return json.loads(decoded.stdout)
    except json.JSONDecodeError as error:
        fail(f"cannot parse decoded {MANIFEST.relative_to(ROOT)}: {error}")


def build_image() -> Path:
    try:
        built = build_closure_image(INTERRUPT_CLOSURE)
    except ClosureImageError as error:
        fail(str(error))
    if sha256_file(built.image, fail) != built.digest():
        fail(f"{built.image} changed after it was built")
    return built.image


def boot(image: Path, reads: tuple[MonitorRead, ...], version: str) -> Boot:
    with tempfile.TemporaryDirectory(prefix="slime-interrupt-") as directory:
        trace_path = Path(directory) / "trace.log"
        tracing: list[str] = []
        for event in TRACE_EVENTS:
            tracing += ["-trace", event]
        terminal = re.compile(rf"^{re.escape(version)}$|" + "|".join(FAILURE_MARKERS))
        transcript = run_plane(
            image=image,
            timeout=TIMEOUT,
            terminal_condition=terminal,
            fail=fail,
            pins_path=PINS,
            additional_arguments=(*RNG_DEVICE, *tracing, "-D", str(trace_path)),
            input_steps=(((HEALTHY,), monitor_input(tuple(read.command() for read in reads))),),
        )
        if not trace_path.is_file():
            fail("the boot left no trace")
        return Boot(transcript, trace_path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser(description="Boot and check the seL4 interrupt wait-source plane")
    parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    profile = load_qemu_profile(fail, PINS)
    version = str(profile["qemu_version"])
    try:
        transports = parse_transports(dump_device_tree(profile, fail))
    except Refusal as error:
        fail(str(error))
    manifest = read_manifest()
    image = build_image()
    result = boot(image, monitor_reads(transports), version)
    try:
        cases, declared = judge_manifest(manifest)
        encode = builder_encoder()
        cases += judge_builder(manifest, declared, encode)
        cases += judge_boot(result, transports, declared, version)
    except Refusal as error:
        fail(str(error))
    refused = manifest_controls(manifest)
    refused += builder_controls(manifest, declared, encode)
    refused += boot_controls(result, transports, declared, version)
    devloop_observations.record(casesObserved=cases, negativeControlsRefused=refused)
    print(
        "seL4 interrupt wait-source check: the root dispatched each of the device's interrupts to the "
        f"probe's declared wait-set badge and re-armed the line on its acknowledgement; cases={cases} controls-refused={refused}"
    )


if __name__ == "__main__":
    main()
