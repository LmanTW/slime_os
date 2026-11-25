#!/usr/bin/env python3
"""xHCI device-descriptor gate: a userspace driver reads one USB device descriptor under QEMU.

The judge trusts no line the guest prints about the controller or the device.
Three records come from QEMU itself:

* QEMU's trace events, written with `-D`, state what the controller
  executed (resets, run and stop, port reset, Enable Slot, Address Device,
  endpoint 0 kicks and the transfer result) and what the interrupt controller
  saw: every level change of the function's INTx line and every
  acknowledgement by the CPU;
* the device's `pcap=` capture states every control transfer the device saw
  and the bytes it returned;
* the QEMU monitor, after the guest finishes, reads the PCI command register
  and the xHCI capability, operational, port and interrupter registers.

The judge pins the device descriptor of each attached QEMU device model from
the pinned QEMU 11.0.1 source. Two boots of one image run with different
devices on different root ports, so a driver that prints a constant fails
one of them:

* the keyboard arm attaches a full-speed `usb-kbd` to physical port 2;
* the tablet arm attaches a high-speed `usb-tablet` to physical port 4.

With `p2=4,p3=4` QEMU numbers the USB3 ports 1 to 4 and the USB2 ports 5 to 8,
so physical port N is xHCI port N + 4 for a full- or high-speed device.

The file name stays outside `check-sel4-*` and the closure name outside a
top-level `CLOSURE` constant until the `sel4-usb-xhci` closure exists, because
the test-run inventory and the devloop closure digest both resolve those names.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import devloop_observations  # noqa: E402
from closure_image import ClosureImageError, build as build_closure_image  # noqa: E402
from harness import GENERATION_COMPOSITIONS, load_qemu_profile, sha256_file  # noqa: E402
from qemu_monitor import MONITOR_BANNER, MonitorRead, PcieHost, dump_device_tree, monitor_input, parse_pcie_host, read_words  # noqa: E402
from sel4_plane import run_plane  # noqa: E402
from zutai_cli import STDLIB, binary  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PINS = ROOT / "sel4" / "pins.toml"
XHCI_CLOSURE = "sel4-usb-xhci"
MANIFEST = GENERATION_COMPOSITIONS / "sel4-usb-xhci.zti"
TIMEOUT = 240
DRIVER = "xhci-driver"

DECLARED_SLOT = 3
DECLARED_ID = "1b36:000d"
XHCI_WORD = 0x000D1B36
XHCI_VENDOR = 0x1B36
XHCI_DEVICE = 0x000D
BAR_BYTES = 0x4000
PCI_COMMAND_MEMORY_MASTER = 0x0006
USB3_PORTS = 4
USB2_PORTS = 4
PORTS = USB3_PORTS + USB2_PORTS
HARDWARE_KINDS = ("device", "mmioRegion", "interruptSource", "dmaAccount")

# qemu-xhci register layout in QEMU 11.0.1 (hw/usb/hcd-xhci.c): LEN_CAP, OFF_RUNTIME.
CAP_LENGTH = 0x40
RUNTIME_OFFSET = 0x1000
PORT_REGISTERS = CAP_LENGTH + 0x400
INTERRUPTER_0 = RUNTIME_OFFSET + 0x20

# USB 2.0 GET_DESCRIPTOR(DEVICE) for 18 bytes, device-to-host.
GET_DEVICE_DESCRIPTOR = bytes((0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00))
PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_USB_LINUX_MMAPPED = 220
USBMON = struct.Struct("<QBBBBHbbqiiII8siiII")
PCAP_RECORD = struct.Struct("<IIII")


@dataclass(frozen=True)
class Arm:
    name: str
    model: str
    physical_port: int
    speed: int
    descriptor: bytes

    @property
    def xhci_port(self) -> int:
        return self.physical_port + USB3_PORTS

    def device_arguments(self, capture: Path) -> tuple[str, ...]:
        return (
            "-device",
            f"{self.model},bus=xhci.0,port={self.physical_port},pcap={capture}",
        )


# Device descriptors of the QEMU 11.0.1 HID models (hw/usb/dev-hid.c, hw/usb/desc.c).
# `msos-desc=off` keeps bcdUSB as the model declares it.
KEYBOARD = Arm(
    name="keyboard",
    model="usb-kbd,usb_version=1,msos-desc=off",
    physical_port=2,
    speed=1,
    descriptor=bytes.fromhex("120100010000000827060100000001040b01"),
)
TABLET = Arm(
    name="tablet",
    model="usb-tablet,usb_version=2,msos-desc=off",
    physical_port=4,
    speed=3,
    descriptor=bytes.fromhex("120100020000004027060100000001030a01"),
)
ARMS = (KEYBOARD, TABLET)

CONTROLLER: tuple[str, ...] = ("-device", f"qemu-xhci,id=xhci,addr={DECLARED_SLOT:#x},p2={USB2_PORTS},p3={USB3_PORTS}")
TRACE_EVENTS: tuple[str, ...] = (
    "usb_xhci_reset",
    "usb_xhci_run",
    "usb_xhci_stop",
    "usb_xhci_port_reset",
    "usb_xhci_slot_enable",
    "usb_xhci_slot_address",
    "usb_xhci_ep_kick",
    "usb_xhci_xfer_success",
    "usb_xhci_xfer_error",
    # qemu-xhci 11.0.1 declares `usb_xhci_irq_*` but never calls them; the GIC
    # traces the line instead, with the seL4 IRQ number (32 + SPI).
    "gic_set_irq",
    "gic_acknowledge_irq",
)
HEX = r"[0-9a-f]"

BIND = re.compile(
    rf"^SLIME_PCI bind function=00:0{DECLARED_SLOT}\.0 id={DECLARED_ID} bar=0 type=mem64 "
    rf"size=0x(?P<size>{HEX}+) address=0x(?P<address>{HEX}+) command=0x(?P<command>{HEX}{{4}}) "
    r"irq=(?P<irq>\d+)$",
    re.M,
)
RUNNING = re.compile(rf"^\[{DRIVER}\] controller running slots=(?P<slots>\d+) ports=(?P<ports>\d+) epoch=(?P<epoch>\d+)$", re.M)
CONNECTED = re.compile(rf"^\[{DRIVER}\] port=(?P<port>\d+) connected speed=(?P<speed>\d+)$", re.M)
ADDRESSED = re.compile(rf"^\[{DRIVER}\] slot=(?P<slot>\d+) port=(?P<port>\d+) address=(?P<address>\d+)$", re.M)
DESCRIPTOR = re.compile(
    rf"^\[{DRIVER}\] device descriptor port=(?P<port>\d+) address=(?P<address>\d+) bytes=(?P<bytes>{HEX}{{36}})$",
    re.M,
)
HALTED = re.compile(rf"^\[{DRIVER}\] controller halted interrupts=(?P<interrupts>\d+)$", re.M)
COMPLETE = re.compile(rf"^\[{DRIVER}\] xhci descriptor plane complete$", re.M)
FAULT = re.compile(r"^SLIME_GRAPH component fault task=(?P<task>\d+) ", re.M)
RECLAIM = re.compile(r"^SLIME_IO reclaim task=(?P<task>\d+) (?P<fields>.*)$", re.M)
HEALTHY = re.compile(r"^SLIME_GRAPH HEALTHY generation=\d+ required=\d+ live=0 completed=\d+ failed=0$", re.M)
TRACE_LINE = re.compile(r"^(?P<event>(?:usb_xhci|gic)_\w+)(?: (?P<arguments>.*))?$")
GIC_LEVEL = re.compile(r"^irq (?P<irq>\d+) level (?P<level>[01]) cpumask 0x[0-9a-f]+ target 0x[0-9a-f]+$")
GIC_ACK = re.compile(r"^v?cpu \d+ acknowledged irq (?P<irq>\d+)$")

FAILURE_MARKERS: tuple[str, ...] = (
    r"SLIME_ROOT FATAL",
    r"SLIME_GRAPH FAIL",
    r"SLIME_IO FAIL",
    rf"\[{DRIVER}\] fail: ",
    r"Caught cap fault",
    r"Caught vm fault",
    r"panicked at ",
)


class Refusal(Exception):
    """The judge refused an input."""


def fail(message: str) -> NoReturn:
    raise SystemExit(f"seL4 xHCI descriptor plane check: {message}")


def refuse(message: str) -> NoReturn:
    raise Refusal(message)


# --------------------------------------------------------------------------- QEMU records


@dataclass(frozen=True)
class Boot:
    """Everything one boot leaves behind: serial and monitor text, trace text, capture bytes."""

    transcript: str
    trace: str
    capture: bytes


def monitor_reads(host: PcieHost) -> tuple[MonitorRead, ...]:
    # The root places BAR 0 at the window base; `judge_boot` checks the binding says so.
    bar = host.mem32_base
    return (
        MonitorRead("declared id", host.config(DECLARED_SLOT, 0x00, fail), 1),
        MonitorRead("declared command", host.config(DECLARED_SLOT, 0x04, fail), 1),
        MonitorRead("declared interrupt", host.config(DECLARED_SLOT, 0x3C, fail), 1),
        MonitorRead("capability", bar, 8),
        # USBCMD at 0x00 through CONFIG at 0x38 of the operational registers.
        MonitorRead("operational", bar + CAP_LENGTH, 15),
        # PORTSC, PORTPMSC, PORTLI, PORTHLPMC of every port.
        MonitorRead("ports", bar + PORT_REGISTERS, 4 * PORTS),
        # IMAN, IMOD, ERSTSZ, reserved, ERSTBA, ERDP of interrupter 0.
        MonitorRead("interrupter", bar + INTERRUPTER_0, 8),
    )


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


@dataclass(frozen=True)
class ControlRecord:
    kind: str
    epnum: int
    devnum: int
    flag_setup: int
    status: int
    length: int
    setup: bytes
    data: bytes


def parse_capture(blob: bytes) -> list[ControlRecord]:
    """Read QEMU's usbmon capture: a pcap file of 64-byte usbmon headers and their data."""
    if len(blob) < 24:
        refuse("the device capture has no pcap header")
    magic, major, minor, _zone, _sigfigs, _snaplen, network = struct.unpack_from("<IHHiIII", blob, 0)
    if (magic, major, minor, network) != (PCAP_MAGIC, 2, 4, LINKTYPE_USB_LINUX_MMAPPED):
        refuse(f"the device capture is not a little-endian usbmon pcap: {magic:#x} {major}.{minor} link {network}")
    records: list[ControlRecord] = []
    offset = 24
    while offset < len(blob):
        if offset + PCAP_RECORD.size + USBMON.size > len(blob):
            refuse(f"the device capture ends inside a record at byte {offset}")
        _sec, _usec, included, _original = PCAP_RECORD.unpack_from(blob, offset)
        offset += PCAP_RECORD.size
        if included < USBMON.size or offset + included > len(blob):
            refuse(f"capture record at byte {offset} claims {included} bytes")
        fields = USBMON.unpack_from(blob, offset)
        kind = chr(fields[1])
        xfer_type, epnum, devnum, flag_setup = fields[2], fields[3], fields[4], fields[6]
        status, length, captured, setup = fields[10], fields[11], fields[12], fields[13]
        if xfer_type != 2:
            refuse(f"the device capture holds a non-control transfer (type {xfer_type})")
        if captured != included:
            refuse(f"capture record at byte {offset} disagrees on its own length")
        data = blob[offset + USBMON.size : offset + included]
        records.append(ControlRecord(kind, epnum, devnum, flag_setup, status, length, setup, data))
        offset += included
    return records


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
class Budget:
    dma_pages: int
    dma_mappings: int


def judge_manifest(manifest: dict) -> tuple[int, Budget]:
    """The driver alone holds one device, MMIO region, interrupt and DMA account, and declares the function."""
    tally = Tally()
    drivers = [instance for instance in manifest.get("instances", []) if instance.get("executable") == DRIVER]
    tally.require(len(drivers) == 1, f"the composition runs {len(drivers)} {DRIVER} instances")
    driver = drivers[0]["name"]
    hardware = [grant for grant in manifest.get("grants", []) if grant.get("capabilityKind") in HARDWARE_KINDS]
    kinds = sorted(grant["capabilityKind"] for grant in hardware)
    tally.require(kinds == sorted(HARDWARE_KINDS), f"the composition declares hardware grants {kinds}")
    tally.require(all(grant.get("target") == driver for grant in hardware), f"a hardware grant targets another instance than {driver}")
    declared = [entry for entry in manifest.get("ioResourceBudget", []) if entry.get("pciFunction") is not None]
    tally.require(len(declared) == 1, f"the composition declares {len(declared)} PCI functions")
    entry = declared[0]
    function = entry["pciFunction"]
    tally.require(entry.get("holder") == driver, f"the PCI function's budget belongs to {entry.get('holder')}")
    tally.require(
        (function.get("bus"), function.get("device"), function.get("function"), function.get("vendor"), function.get("deviceId"))
        == (0, DECLARED_SLOT, 0, XHCI_VENDOR, XHCI_DEVICE),
        f"the budget declares PCI function {function}",
    )
    tally.require(entry.get("mmioBytes") == BAR_BYTES and entry.get("irqSources") == 1, "the budget is not one BAR and one interrupt")
    budget = Budget(dma_pages=int(entry.get("dmaPages", 0)), dma_mappings=int(entry.get("dmaMappings", 0)))
    tally.require(budget.dma_pages > 0 and budget.dma_mappings > 0, "the budget declares no DMA")
    return tally.cases, budget


def judge_boot(arm: Arm, boot: Boot, host: PcieHost, budget: Budget, version: str) -> int:
    tally = Tally()
    transcript = boot.transcript
    reject_failures(transcript)
    healthy = single(HEALTHY, transcript, "graph health")
    guest = transcript[: healthy.end()]

    # The root binds the function with bus mastering, because its budget declares DMA.
    bind = single(BIND, guest, "root binding")
    tally.require(bind.group("command") == f"{PCI_COMMAND_MEMORY_MASTER:04x}", f"the root wrote command {bind.group('command')}")
    tally.require(int(bind.group("size"), 16) == BAR_BYTES, f"BAR 0 size {bind.group('size')}")
    tally.require(int(bind.group("address"), 16) == host.mem32_base, "BAR 0 is not at the window base")

    # The driver's report, in order.
    running = single(RUNNING, guest, "controller running", bind.end())
    tally.require(int(running.group("epoch")) == 1, f"the driver runs at epoch {running.group('epoch')}")
    connected_lines = list(CONNECTED.finditer(guest))
    tally.require(len(connected_lines) == 1, f"the driver reports {len(connected_lines)} connected ports")
    connected = connected_lines[0]
    tally.require(connected.start() > running.end(), "a port is reported before the controller runs")
    tally.require(int(connected.group("port")) == arm.xhci_port, f"the driver reports port {connected.group('port')}, the device is on {arm.xhci_port}")
    tally.require(int(connected.group("speed")) == arm.speed, f"the driver reports speed {connected.group('speed')}, expected {arm.speed}")
    addressed = single(ADDRESSED, guest, "addressed device", connected.end())
    slot, address = int(addressed.group("slot")), int(addressed.group("address"))
    tally.require(int(addressed.group("port")) == arm.xhci_port, "the addressed port differs from the connected port")
    tally.require(slot > 0 and address > 0, f"slot {slot} address {address}")
    described = single(DESCRIPTOR, guest, "device descriptor", addressed.end())
    tally.require(int(described.group("port")) == arm.xhci_port and int(described.group("address")) == address, "the descriptor names another device")
    reported = bytes.fromhex(described.group("bytes"))
    tally.require(reported == arm.descriptor, f"the driver reports {reported.hex()}, the {arm.name} model holds {arm.descriptor.hex()}")
    halted = single(HALTED, guest, "controller halted", described.end())
    interrupts = int(halted.group("interrupts"))
    tally.require(interrupts >= 1, "the driver received no interrupt")
    complete = single(COMPLETE, guest, "driver completion", halted.end())
    tally.require(not FAULT.search(guest), "a component faulted")
    reclaim = single(RECLAIM, guest, "driver reclaim")
    tally.require(complete.end() <= reclaim.start(), "the reclaim precedes the driver's completion")
    fields = reclaim_fields(reclaim)
    tally.require(fields.get("pre_mmio_bytes") == BAR_BYTES and fields.get("pre_irq_sources") == 1, "the driver did not hold the BAR and the interrupt")
    tally.require(1 <= fields.get("pre_dma_pages", 0) <= budget.dma_pages, f"the driver held {fields.get('pre_dma_pages')} DMA pages")
    tally.require(1 <= fields.get("pre_dma_mappings", 0) <= budget.dma_mappings, f"the driver held {fields.get('pre_dma_mappings')} DMA mappings")
    for key in ("post_mmio_bytes", "post_mmio_mappings", "post_irq_sources", "post_dma_pages", "post_dma_mappings", "post_requests"):
        tally.require(fields.get(key) == 0, f"the exit reclaim leaves {key}={fields.get(key)}")

    # QEMU's registers after the guest finished.
    words = read_words(transcript, healthy.end(), monitor_reads(host), version, refuse)
    tally.require(words["declared id"] == (XHCI_WORD,), "QEMU does not place qemu-xhci at the declared slot")
    command = words["declared command"][0] & 0xFFFF
    tally.require(command == PCI_COMMAND_MEMORY_MASTER, f"command register {command:#06x}: expected memory decoding and bus mastering only")
    # The root's route must be the one QEMU's interrupt-map states for the function's pin.
    pin = (words["declared interrupt"][0] >> 8) & 0xFF
    tally.require(pin == 1, f"the declared function reports interrupt pin {pin}, expected INTA")
    route = host.irq(DECLARED_SLOT, pin, refuse)
    tally.require(int(bind.group("irq")) == route, f"the root routed IRQ {bind.group('irq')}, the device tree routes {route}")
    capability = words["capability"]
    tally.require(capability[0] & 0xFF == CAP_LENGTH and capability[6] == RUNTIME_OFFSET, "the controller's register layout is not the pinned one")
    max_slots, max_ports = capability[1] & 0xFF, capability[1] >> 24
    tally.require(max_ports == PORTS == int(running.group("ports")), f"the driver reports {running.group('ports')} ports, HCSPARAMS1 holds {max_ports}")
    slots = int(running.group("slots"))
    operational = words["operational"]
    usbcmd, usbsts, config = operational[0], operational[1], operational[14]
    tally.require(1 <= slots <= max_slots and config & 0xFF == slots, f"the driver enabled {slots} slots, CONFIG holds {config & 0xFF}")
    tally.require(usbcmd & 0x1 == 0 and usbsts & 0x1 == 1, f"the controller still runs: USBCMD {usbcmd:#x} USBSTS {usbsts:#x}")
    tally.require(usbcmd & 0x4 != 0, "USBCMD has interrupts disabled")
    tally.require(usbsts & 0x1004 == 0, f"USBSTS reports a host system or controller error: {usbsts:#x}")
    dcbaap = operational[12] | operational[13] << 32
    tally.require(dcbaap != 0 and dcbaap & 0x3F == 0, f"DCBAAP {dcbaap:#x}")
    ports = words["ports"]
    for port in range(1, PORTS + 1):
        portsc = ports[4 * (port - 1)]
        if port == arm.xhci_port:
            tally.require(portsc & 0x3 == 0x3 and (portsc >> 5) & 0xF == 0, f"port {port} is not connected, enabled and in U0: {portsc:#x}")
            tally.require((portsc >> 10) & 0xF == arm.speed, f"port {port} runs at speed {(portsc >> 10) & 0xF}")
        else:
            tally.require(portsc & 0x3 == 0, f"empty port {port} reports connected or enabled: {portsc:#x}")
    interrupter = words["interrupter"]
    iman, erstsz = interrupter[0], interrupter[2]
    erstba = interrupter[4] | interrupter[5] << 32
    erdp = interrupter[6] | interrupter[7] << 32
    tally.require(iman & 0x3 == 0x2, f"IMAN {iman:#x}: expected interrupts enabled and none pending")
    tally.require(erstsz & 0xFFFF == 1 and erstba != 0 and erstba & 0x3F == 0, f"event ring segment table {erstba:#x} size {erstsz}")
    tally.require(erdp & ~0xF != 0 and erdp & 0x8 == 0, f"ERDP {erdp:#x}: the driver left the event handler busy or never consumed")

    # The controller's own record of what it executed.
    events = parse_trace(boot.trace)
    resets = [event for event in events if event.event == "usb_xhci_reset"]
    tally.require(len(resets) == 2, f"the controller reset {len(resets)} times, expected the machine's and the driver's")
    runs = [event for event in events if event.event == "usb_xhci_run"]
    stops = [event for event in events if event.event == "usb_xhci_stop"]
    tally.require(len(runs) == 1 and runs[0].index > resets[1].index, "the controller did not run once after the driver's reset")
    tally.require(len(stops) == 1 and stops[0].index > runs[0].index, "the controller did not stop once after it ran")
    run, stop = runs[0].index, stops[0].index

    def between(name: str) -> list[TraceEvent]:
        return [event for event in events if event.event == name and run < event.index < stop]

    def outside(name: str) -> list[TraceEvent]:
        return [event for event in events if event.event == name and not run < event.index < stop]

    for name in ("usb_xhci_port_reset", "usb_xhci_slot_enable", "usb_xhci_slot_address", "usb_xhci_ep_kick", "usb_xhci_xfer_success"):
        tally.require(not outside(name), f"{name} outside the run")
    port_resets = between("usb_xhci_port_reset")
    tally.require([event.arguments for event in port_resets] == [f"port {arm.xhci_port}, warm 0"], f"port resets {[e.arguments for e in port_resets]}")
    enables = between("usb_xhci_slot_enable")
    tally.require([event.arguments for event in enables] == [f"slotid {slot}"], f"slot enables {[e.arguments for e in enables]}, the driver names slot {slot}")
    tally.require(enables[0].index > port_resets[0].index, "a slot is enabled before the port reset")
    addresses = between("usb_xhci_slot_address")
    tally.require(
        [event.arguments for event in addresses] == [f"slotid {slot}, port {arm.physical_port}"],
        f"address commands {[e.arguments for e in addresses]}",
    )
    tally.require(addresses[0].index > enables[0].index, "Address Device precedes Enable Slot")
    kicks = between("usb_xhci_ep_kick")
    tally.require(kicks and all(event.arguments == f"slotid {slot}, epid 1, streamid 0" for event in kicks), "a doorbell names another endpoint")
    tally.require(kicks[0].index > addresses[0].index, "endpoint 0 rang before Address Device")
    transfers = between("usb_xhci_xfer_success")
    tally.require(len(transfers) == 1 and transfers[0].arguments.endswith(": len 18"), f"transfers {[e.arguments for e in transfers]}")
    tally.require(not [event for event in events if event.event == "usb_xhci_xfer_error"], "a transfer failed")

    # The function's INTx line at the GIC: raised, taken by the CPU, lowered.
    # qemu-xhci raises INTx only while MSI and MSI-X are off.
    line: list[tuple[str, int]] = []
    for event in events:
        if not run < event.index < stop:
            continue
        if event.event == "gic_set_irq":
            level = GIC_LEVEL.match(event.arguments)
            if level is None:
                refuse(f"malformed GIC level event: {event.arguments!r}")
            if int(level.group("irq")) == route:
                line.append(("raised" if level.group("level") == "1" else "lowered", event.index))
        elif event.event == "gic_acknowledge_irq":
            acknowledged = GIC_ACK.match(event.arguments)
            if acknowledged is None:
                refuse(f"malformed GIC acknowledgement: {event.arguments!r}")
            if int(acknowledged.group("irq")) == route:
                line.append(("acknowledged", event.index))
    kinds = [kind for kind, _index in line]
    tally.require("raised" in kinds, f"the controller never raised IRQ {route} while running")
    first = kinds.index("raised")
    tally.require("acknowledged" in kinds[first:], f"the CPU never acknowledged IRQ {route} after it was raised")
    taken = first + kinds[first:].index("acknowledged")
    tally.require("lowered" in kinds[taken:], f"IRQ {route} was never lowered after the CPU took it")

    # The device's own record of the transfer.
    records = parse_capture(boot.capture)
    tally.require(len(records) == 2, f"the device saw {len(records)} control records, expected one request and its completion")
    request, completion = records
    tally.require(request.kind == "S" and request.flag_setup == 0 and request.setup == GET_DEVICE_DESCRIPTOR, f"the request is {request.kind} {request.setup.hex()}")
    tally.require(completion.kind == "C" and completion.status == 0, f"the completion is {completion.kind} status {completion.status}")
    tally.require(request.epnum == completion.epnum == 0x80, "the transfer is not an IN on endpoint 0")
    tally.require(request.devnum == completion.devnum == address, f"the device answered at address {request.devnum}, the driver reports {address}")
    tally.require(completion.length == len(completion.data) == 18, f"the device returned {len(completion.data)} bytes")
    # The driver's bytes already equal the model, so this makes them equal the device's too.
    tally.require(completion.data == arm.descriptor, f"the device returned {completion.data.hex()}, the pinned {arm.name} model holds {arm.descriptor.hex()}")
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


def set_word(transcript: str, read: MonitorRead, index: int, value: int) -> str:
    """Replace one word of one `xp` reply, keeping the reply's length."""
    pattern = re.compile(rf"^{read.address + 16 * (index // 4):x}: (?P<words>(?:0x[0-9a-f]{{8}} ?)+)$", re.M)

    def change(match: re.Match[str]) -> str:
        values = match.group("words").split()
        if index % 4 >= len(values):
            fail(f"control needs word {index} of {read.command()!r}")
        values[index % 4] = f"0x{value:08x}"
        return replace_group(match, "words", " ".join(values))

    return edit(transcript, pattern, change)


def get_word(transcript: str, read: MonitorRead, index: int) -> int:
    pattern = re.compile(rf"^{read.address + 16 * (index // 4):x}: (?P<words>(?:0x[0-9a-f]{{8}} ?)+)$", re.M)
    match = pattern.search(transcript)
    if match is None:
        fail(f"control needs word {index} of {read.command()!r}")
    return int(match.group("words").split()[index % 4], 16)


def spoof_reply(transcript: str, read: MonitorRead) -> str:
    """Guest output after the switch prints its own echo and reply for one read."""
    banner = MONITOR_BANNER.search(transcript)
    if banner is None:
        fail("control needs the monitor banner")
    spoofed = f"\n(qemu) {read.command()}\n{read.address:x}: 0x00000000"
    return transcript[: banner.end()] + spoofed + transcript[banner.end() :]


def trace_edit(trace: str, pattern: str, replacement: str, count: int = 1) -> str:
    changed, made = re.subn(pattern, replacement, trace, count=count, flags=re.M)
    if not made:
        fail(f"trace control needs a line matching {pattern!r}")
    return changed


def drop_event(trace: str, event: str, occurrence: int) -> str:
    """Remove the `occurrence`-th line (from 0) that records `event`."""
    lines = trace.splitlines(keepends=True)
    matching = [index for index, line in enumerate(lines) if line.split(" ", 1)[0].rstrip("\n") == event]
    if len(matching) <= occurrence:
        fail(f"trace control needs {occurrence + 1} {event} lines")
    del lines[matching[occurrence]]
    return "".join(lines)


def move_event(trace: str, event: str, anchor: str, after: bool) -> str:
    """Move the first `event` line next to the first `anchor` line: before it, or after it."""
    lines = trace.splitlines(keepends=True)

    def first(name: str) -> int:
        for index, line in enumerate(lines):
            if line.split(" ", 1)[0].rstrip("\n") == name:
                return index
        fail(f"trace control needs a {name} line")

    moved = lines.pop(first(event))
    target = first(anchor)
    lines.insert(target + 1 if after else target, moved)
    return "".join(lines)


def move_line_before(text: str, pattern: re.Pattern[str], anchor: re.Pattern[str]) -> str:
    """Move the first line matching `pattern` to just before the first line matching `anchor`."""
    match = pattern.search(text)
    if match is None:
        fail(f"control needs a line matching {pattern.pattern!r}")
    removed = text[: match.start()] + text[match.end() + 1 :]
    return insert_before(removed, anchor, match.group(0))


def set_field(line: str, key: str, value: int) -> str:
    changed, made = re.subn(rf"\b{key}=\d+", f"{key}={value}", line)
    if made != 1:
        fail(f"control needs one {key} field")
    return changed


def capture_edit(blob: bytes, record: int, change: Callable[[bytearray, int], None]) -> bytes:
    """Edit record `record` of the capture in place; `change` receives the usbmon header offset."""
    data = bytearray(blob)
    offset = 24
    for _ in range(record):
        included = PCAP_RECORD.unpack_from(data, offset)[2]
        offset += PCAP_RECORD.size + included
    change(data, offset + PCAP_RECORD.size)
    return bytes(data)


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


def boot_controls(arm: Arm, boot: Boot, host: PcieHost, budget: Budget, version: str) -> int:
    reads = {read.label: read for read in monitor_reads(host)}
    transcript, trace, capture = boot.transcript, boot.trace, boot.capture
    port_index = 4 * (arm.xhci_port - 1)
    route = host.irq(DECLARED_SLOT, 1, refuse)
    empty_index = 4 * (arm.xhci_port - 2)

    def text(mutated: str) -> Boot:
        if mutated == transcript:
            fail("a transcript control did not change the transcript")
        return Boot(mutated, trace, capture)

    def word(label: str, index: int, change: Callable[[int], int]) -> Boot:
        return text(set_word(transcript, reads[label], index, change(get_word(transcript, reads[label], index))))

    def traced(pattern: str, replacement: str, count: int = 1) -> Boot:
        return Boot(transcript, trace_edit(trace, pattern, replacement, count), capture)

    def captured(record: int, change: Callable[[bytearray, int], None]) -> Boot:
        mutated = capture_edit(capture, record, change)
        if mutated == capture:
            fail("a capture control did not change the capture")
        return Boot(transcript, trace, mutated)

    def plus(value: str, step: int) -> str:
        return str(int(value) + step)

    def setup_byte(index: int, value: int) -> Callable[[bytearray, int], None]:
        return lambda data, header: data.__setitem__(header + 40 + index, value)

    def flip_last_data_byte(data: bytearray, header: int) -> None:
        included = PCAP_RECORD.unpack_from(data, header - PCAP_RECORD.size)[2]
        data[header + included - 1] ^= 0x01

    def duplicate_records(blob: bytes) -> bytes:
        return blob + blob[24:]

    def other_descriptor(match: re.Match[str]) -> str:
        other = TABLET if arm is KEYBOARD else KEYBOARD
        return replace_group(match, "bytes", other.descriptor.hex())

    cases: tuple[tuple[str, Boot], ...] = (
        ("binding without bus mastering", text(edit(transcript, BIND, lambda m: replace_group(m, "command", "0002")))),
        ("binding with another BAR size", text(edit(transcript, BIND, lambda m: replace_group(m, "size", f"{BAR_BYTES * 2:x}")))),
        ("binding off the window base", text(edit(transcript, BIND, lambda m: replace_group(m, "address", f"{host.mem32_base + 0x1000:x}")))),
        ("binding names another interrupt", text(edit(transcript, BIND, lambda m: replace_group(m, "irq", plus(m.group("irq"), 1))))),
        ("driver runs at another epoch", text(edit(transcript, RUNNING, lambda m: replace_group(m, "epoch", "2")))),
        ("port reported before the controller runs", text(move_line_before(transcript, CONNECTED, RUNNING))),
        ("addressed port differs from the connected port", text(edit(transcript, ADDRESSED, lambda m: replace_group(m, "port", plus(m.group("port"), -1))))),
        ("descriptor names another port", text(edit(transcript, DESCRIPTOR, lambda m: replace_group(m, "port", plus(m.group("port"), -1))))),
        ("completion reported after the reclaim", text(move_line_before(transcript, COMPLETE, HEALTHY))),
        ("driver held no interrupt", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "pre_irq_sources", 0)))),
        ("driver held no DMA mapping", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "pre_dma_mappings", 0)))),
        ("exit reclaim left the interrupt", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "post_irq_sources", 1)))),
        ("QEMU holds another function at the slot", word("declared id", 0, lambda _value: 0x00051B36)),
        ("declared function interrupts on INTB", word("declared interrupt", 0, lambda value: (value & ~0xFF00) | 0x0200)),
        ("controller register layout differs", word("capability", 6, lambda value: value + 0x1000)),
        ("controller error", word("operational", 1, lambda value: value | 0x1000)),
        ("device port at another speed", word("ports", port_index, lambda value: value ^ (0x2 << 10))),
        ("two event ring segments", word("interrupter", 2, lambda _value: 2)),
        ("event ring segment table never programmed", text(set_word(set_word(transcript, reads["interrupter"], 4, 0), reads["interrupter"], 5, 0))),
        ("event ring never consumed", text(set_word(set_word(transcript, reads["interrupter"], 6, 0), reads["interrupter"], 7, 0))),
        ("doorbell for another endpoint", traced(r"^(usb_xhci_ep_kick slotid \d+, epid )1", r"\g<1>2")),
        ("Enable Slot before the port reset", Boot(transcript, move_event(trace, "usb_xhci_slot_enable", "usb_xhci_port_reset", after=False), capture)),
        ("Address Device before Enable Slot", Boot(transcript, move_event(trace, "usb_xhci_slot_address", "usb_xhci_slot_enable", after=False), capture)),
        ("doorbell before Address Device", Boot(transcript, move_event(trace, "usb_xhci_ep_kick", "usb_xhci_slot_address", after=False), capture)),
        ("transfer after the stop", Boot(transcript, move_event(trace, "usb_xhci_xfer_success", "usb_xhci_stop", after=True), capture)),
        ("request on another endpoint direction", captured(0, lambda data, header: data.__setitem__(header + 10, 0x00))),
        ("completion claims 8 bytes", captured(1, lambda data, header: struct.pack_into("<I", data, header + 32, 8))),
        ("function decodes memory only", word("declared command", 0, lambda value: value & ~0x4)),
        ("driver reports another port count", text(edit(transcript, RUNNING, lambda m: replace_group(m, "ports", plus(m.group("ports"), -1))))),
        ("CONFIG holds another slot count", word("operational", 14, lambda value: value + 1)),
        ("driver reports a second connected port", text(insert_before(transcript, ADDRESSED, f"[{DRIVER}] port={arm.xhci_port - 1} connected speed={arm.speed}"))),
        ("driver reports the USB3 twin port", text(edit(transcript, CONNECTED, lambda m: replace_group(m, "port", str(arm.physical_port))))),
        ("driver reports another speed", text(edit(transcript, CONNECTED, lambda m: replace_group(m, "speed", plus(m.group("speed"), 1))))),
        ("driver names another slot", text(edit(transcript, ADDRESSED, lambda m: replace_group(m, "slot", plus(m.group("slot"), 1))))),
        (
            "driver names another address on both lines",
            text(
                edit(
                    edit(transcript, ADDRESSED, lambda m: replace_group(m, "address", plus(m.group("address"), 1))),
                    DESCRIPTOR,
                    lambda m: replace_group(m, "address", plus(m.group("address"), 1)),
                )
            ),
        ),
        (
            "driver reports address 0 on both lines",
            text(
                edit(
                    edit(transcript, ADDRESSED, lambda m: replace_group(m, "address", "0")),
                    DESCRIPTOR,
                    lambda m: replace_group(m, "address", "0"),
                )
            ),
        ),
        ("driver reports the other model's descriptor", text(edit(transcript, DESCRIPTOR, other_descriptor))),
        ("driver never halted", text(edit(transcript, HALTED, lambda _m: ""))),
        ("driver received no interrupt", text(edit(transcript, HALTED, lambda m: replace_group(m, "interrupts", "0")))),
        ("driver faulted", text(insert_before(transcript, RECLAIM, "SLIME_GRAPH component fault task=9 kind=VmFault address=Some(0)"))),
        ("explicit driver failure", text(insert_before(transcript, HEALTHY, f"[{DRIVER}] fail: injected control"))),
        ("driver held no DMA", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "pre_dma_pages", 0)))),
        ("DMA held past the budget", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "pre_dma_pages", budget.dma_pages + 1)))),
        ("exit reclaim left DMA pages", text(edit(transcript, RECLAIM, lambda m: set_field(m.group(0), "post_dma_pages", 1)))),
        ("exit reclaim missing", text(edit(transcript, RECLAIM, lambda _m: ""))),
        ("controller still running", word("operational", 1, lambda value: value & ~0x1)),
        ("controller interrupts disabled", word("operational", 0, lambda value: value & ~0x4)),
        ("host system error", word("operational", 1, lambda value: value | 0x4)),
        ("DCBAAP never programmed", text(set_word(set_word(transcript, reads["operational"], 12, 0), reads["operational"], 13, 0))),
        ("device port not enabled", word("ports", port_index, lambda value: value & ~0x2)),
        ("device port in another link state", word("ports", port_index, lambda value: value | (3 << 5))),
        ("empty port reports a device", word("ports", empty_index, lambda value: value | 0x1)),
        ("interrupter disabled", word("interrupter", 0, lambda value: value & ~0x2)),
        ("interrupt left pending", word("interrupter", 0, lambda value: value | 0x1)),
        ("event handler left busy", word("interrupter", 6, lambda value: value | 0x8)),
        ("guest output repeats a monitor command", text(spoof_reply(transcript, reads["declared command"]))),
        ("driver never reset the controller", Boot(transcript, drop_event(trace, "usb_xhci_reset", 1), capture)),
        ("controller never ran", traced(r"^usb_xhci_run.*\n", "")),
        ("controller never stopped", traced(r"^usb_xhci_stop.*\n", "")),
        ("another port reset", traced(r"^(usb_xhci_port_reset port )\d+", rf"\g<1>{arm.xhci_port - 1}")),
        ("Enable Slot missing", traced(r"^usb_xhci_slot_enable .*\n", "")),
        ("Address Device names another port", traced(r"^(usb_xhci_slot_address slotid \d+, port )\d+", rf"\g<1>{arm.physical_port + 1}")),
        ("transfer returned 8 bytes", traced(r"^(usb_xhci_xfer_success .*: len )18", r"\g<1>8")),
        ("a transfer failed", traced(r"^(usb_xhci_xfer_success .*)$", r"\1\nusb_xhci_xfer_error 0x1: ret -3")),
        ("line never raised", traced(rf"^gic_set_irq irq {route} level 1 .*\n", "", 0)),
        ("CPU never acknowledged the line", traced(rf"^gic_acknowledge_irq v?cpu \d+ acknowledged irq {route}\n", "", 0)),
        ("line never lowered", traced(rf"^gic_set_irq irq {route} level 0 .*\n", "", 0)),
        ("interrupt arrives on another line", traced(rf"^(gic_\w+ .*irq ){route}\b", rf"\g<1>{route + 1}", 0)),
        ("trace holds a foreign line", traced(r"^(usb_xhci_run.*)$", r"\1\nusb_xhci_port_link port 6, pls 0")),
        ("request at the default address", captured(0, lambda data, header: data.__setitem__(header + 11, 0))),
        ("request for another descriptor", captured(0, setup_byte(3, 0x02))),
        ("completion carries an error", captured(1, lambda data, header: struct.pack_into("<i", data, header + 28, -121))),
        ("device returned other bytes", captured(1, flip_last_data_byte)),
        ("device saw a second transfer", Boot(transcript, trace, duplicate_records(capture))),
    )
    mutations = [(label, lambda mutated=mutated: judge_boot(arm, mutated, host, budget, version)) for label, mutated in cases]
    rotated = replace(host, interrupt_map=tuple((device, pin, (spi - 3 + 1) % 4 + 3) for device, pin, spi in host.interrupt_map))
    mutations.append(("judge model with another INTx route", lambda: judge_boot(arm, boot, rotated, budget, version)))
    return run_controls(tuple(mutations))


def manifest_controls(manifest: dict) -> int:
    def mutated(change: Callable[[dict], None]) -> dict:
        copy = json.loads(json.dumps(manifest))
        change(copy)
        return copy

    def hardware(copy: dict, kind: str) -> dict:
        return next(grant for grant in copy["grants"] if grant.get("capabilityKind") == kind)

    def declared(copy: dict) -> dict:
        return next(entry for entry in copy["ioResourceBudget"] if entry.get("pciFunction") is not None)

    cases: tuple[tuple[str, dict], ...] = (
        ("driver holds no DMA account", mutated(lambda c: c["grants"].remove(hardware(c, "dmaAccount")))),
        ("a hardware grant targets init", mutated(lambda c: hardware(c, "mmioRegion").update(target="init"))),
        ("budget declares no DMA pages", mutated(lambda c: declared(c).update(dmaPages=0))),
        ("budget declares another function", mutated(lambda c: declared(c)["pciFunction"].update(device=4))),
        ("a second declared function", mutated(lambda c: c["ioResourceBudget"].append(json.loads(json.dumps(declared(c)))))),
        ("a second driver instance", mutated(lambda c: c["instances"].append({**next(i for i in c["instances"] if i.get("executable") == DRIVER), "name": "xhci-driver-b"}))),
        ("the function's budget belongs to init", mutated(lambda c: declared(c).update(holder="init"))),
        ("the budget grants a 4 KiB BAR", mutated(lambda c: declared(c).update(mmioBytes=4096))),
    )
    return run_controls(tuple((label, lambda value=value: judge_manifest(value)) for label, value in cases))


# --------------------------------------------------------------------------- driver


def read_manifest() -> dict:
    if not MANIFEST.is_file():
        fail(f"{MANIFEST.relative_to(ROOT)} does not exist; the {XHCI_CLOSURE} composition has not landed")
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
        built = build_closure_image(XHCI_CLOSURE)
    except ClosureImageError as error:
        fail(str(error))
    if sha256_file(built.image, fail) != built.digest():
        fail(f"{built.image} changed after it was built")
    return built.image


def boot(image: Path, arm: Arm, reads: tuple[MonitorRead, ...], version: str) -> Boot:
    with tempfile.TemporaryDirectory(prefix=f"slime-xhci-{arm.name}-") as directory:
        trace_path = Path(directory) / "trace.log"
        capture_path = Path(directory) / "device.pcap"
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
            additional_arguments=(*CONTROLLER, *arm.device_arguments(capture_path), *tracing, "-D", str(trace_path)),
            input_steps=(((HEALTHY,), monitor_input(tuple(read.command() for read in reads))),),
        )
        if not trace_path.is_file() or not capture_path.is_file():
            fail(f"the {arm.name} boot left no trace or no device capture")
        return Boot(transcript, trace_path.read_text(), capture_path.read_bytes())


def main() -> None:
    parser = argparse.ArgumentParser(description="Boot and check the seL4 xHCI device-descriptor plane")
    parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    profile = load_qemu_profile(fail, PINS)
    version = str(profile["qemu_version"])
    host = parse_pcie_host(dump_device_tree(profile, fail), fail)
    manifest = read_manifest()
    image = build_image()
    reads = monitor_reads(host)
    boots = [(arm, boot(image, arm, reads, version)) for arm in ARMS]
    try:
        cases, budget = judge_manifest(manifest)
        for arm, result in boots:
            cases += judge_boot(arm, result, host, budget, version)
    except Refusal as error:
        fail(str(error))
    refused = manifest_controls(manifest)
    for arm, result in boots:
        refused += boot_controls(arm, result, host, budget, version)
    devloop_observations.record(casesObserved=cases, negativeControlsRefused=refused)
    print(
        "seL4 xHCI descriptor plane check: a userspace driver addressed one device per boot and read "
        f"the descriptor its QEMU model holds, under interrupts and with DMA; cases={cases} controls-refused={refused}"
    )


if __name__ == "__main__":
    main()
