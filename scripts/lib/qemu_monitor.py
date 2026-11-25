"""Read QEMU's own view of a finished guest through the human monitor.

A plane exam that must not trust the guest's report of the machine switches
the `-serial mon:stdio` mux to the monitor after the guest's last required
line, issues `xp` reads and `info` queries, and ends with `info version`. The
guest shares that serial stream, so each reply counts only on the line
directly after the echo of its own command, and a command echoed twice is
refused.

The module also dumps the pinned machine's device tree and reads the
qemu-arm-virt PCIe host from it, so an exam takes ECAM and window addresses
and INTx routes from QEMU rather than from the root's pinned constants.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NoReturn

MONITOR_BANNER = re.compile(r"^QEMU \d+\.\d+\.\d+ monitor - type 'help' for more information$", re.M)
XP_REPLY = re.compile(r"^(?P<address>[0-9a-f]+): (?P<words>(?:0x[0-9a-f]{8} ?)+)$")

Reject = Callable[[str], NoReturn]


@dataclass(frozen=True)
class MonitorRead:
    """One `xp` read of `words` 32-bit words starting at a physical address."""

    label: str
    address: int
    words: int

    def command(self) -> str:
        return f"xp /{self.words}wx {self.address:#x}"


def monitor_input(commands: tuple[str, ...]) -> str:
    """Ctrl-A c moves the mux to the monitor; `info version` is the last reply."""
    return "\x01c" + "".join(f"{command}\n" for command in (*commands, "info version"))


def strip_echo(line: str) -> str:
    """The monitor's line editor redraws each keystroke; keep the prompt and the final text."""
    if not line.startswith("(qemu) "):
        return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line).strip()
    final = re.split(r"\x1b\[D", line[len("(qemu) ") :])[-1]
    return "(qemu) " + re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", final).strip()


def read_words(transcript: str, after: int, reads: tuple[MonitorRead, ...], version: str, refuse: Reject) -> dict[str, tuple[int, ...]]:
    """Return each read's words from the monitor replies after position `after`.

    `xp` prints at most four words per line; each further line starts at the
    next address. The pinned QEMU version must be the last reply.
    """
    tail = transcript[after:]
    banner = MONITOR_BANNER.search(tail)
    if banner is None:
        refuse("the monitor never answered after the guest's last required line")
    lines = tail[banner.end() :].split("\n")
    echoes = [strip_echo(line) for line in lines]
    words: dict[str, tuple[int, ...]] = {}
    for read in reads:
        expected = f"(qemu) {read.command()}"
        indices = [index for index, echo in enumerate(echoes) if echo == expected]
        if len(indices) != 1:
            refuse(f"monitor command {read.command()!r} echoed {len(indices)} times")
        values: list[int] = []
        line = indices[0] + 1
        while len(values) < read.words:
            if line >= len(lines):
                refuse(f"no complete reply to {read.command()!r}")
            reply = XP_REPLY.match(lines[line].strip())
            if reply is None or int(reply.group("address"), 16) != read.address + 4 * len(values):
                refuse(f"malformed reply to {read.command()!r}: {lines[line]!r}")
            values.extend(int(word, 16) for word in reply.group("words").split())
            line += 1
        if len(values) != read.words:
            refuse(f"{read.label}: expected {read.words} words, read {len(values)}")
        words[read.label] = tuple(values)
    if not re.search(rf"^{re.escape(version)}$", tail[banner.end() :], re.M):
        refuse("the monitor did not report the pinned QEMU version last")
    return words


@dataclass(frozen=True)
class PcieHost:
    """The qemu-arm-virt PCIe host facts QEMU states in its own device tree."""

    ecam_base: int
    ecam_size: int
    mem32_base: int
    mem32_size: int
    # (device bits & mask, pin & mask, SPI number) of every interrupt-map entry
    interrupt_map: tuple[tuple[int, int, int], ...]
    device_mask: int
    pin_mask: int
    gic_spi_base: int = 32

    def config(self, slot: int, offset: int, fail: Reject) -> int:
        """ECAM address of one register of function 00:<slot>.0."""
        address = self.ecam_base + (slot << 15) + offset
        if not self.ecam_base <= address < self.ecam_base + self.ecam_size:
            fail(f"slot {slot} offset {offset:#x} lies outside ECAM")
        return address

    def irq(self, slot: int, pin: int, refuse: Reject) -> int:
        """seL4 IRQ number of the INTx route of function 00:<slot>.0 on `pin` (1 = INTA)."""
        key = ((slot << 11) & self.device_mask, pin & self.pin_mask)
        for device, mapped_pin, spi in self.interrupt_map:
            if (device, mapped_pin) == key:
                return self.gic_spi_base + spi
        refuse(f"the device tree maps no INTx route for slot {slot} pin {pin}")


def _cells(text: str) -> list[int]:
    return [int(token, 16) for token in re.findall(r"0x[0-9a-f]+", text)]


def _node_property(node: str, name: str, fail: Reject) -> list[int]:
    match = re.search(rf"^\s*{re.escape(name)} = <(?P<cells>[^>]*)>;$", node, re.M)
    if match is None:
        fail(f"the PCIe host node has no {name} property")
    return _cells(match.group("cells"))


def dump_device_tree(profile: dict[str, object], fail: Reject) -> str:
    """Dump the pinned machine's device tree as source text."""
    qemu = shutil.which("qemu-system-aarch64")
    dtc = shutil.which("dtc")
    if qemu is None or dtc is None:
        fail("qemu-system-aarch64 and dtc must be on PATH")
    with tempfile.TemporaryDirectory(prefix="slime-dtb-") as directory:
        blob = Path(directory) / "virt.dtb"
        dumped = subprocess.run(
            [
                qemu,
                "-machine",
                f"{profile['machine']},dumpdtb={blob}",
                "-cpu",
                str(profile["cpu"]),
                "-smp",
                str(profile["cpus"]),
                "-m",
                f"size={profile['memory_mib']}M",
                "-nographic",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if dumped.returncode != 0 or not blob.is_file():
            fail(f"QEMU did not dump the device tree: {dumped.stdout.strip()}")
        source = subprocess.run(
            [dtc, "-q", "-I", "dtb", "-O", "dts", str(blob)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if source.returncode != 0:
            fail(f"dtc cannot decode the dumped device tree: {source.stderr.strip()}")
    return source.stdout


def parse_pcie_host(dts: str, fail: Reject) -> PcieHost:
    nodes = re.findall(r"^\tpcie@[0-9a-f]+ \{\n(.*?)^\t\};$", dts, re.M | re.S)
    if len(nodes) != 1:
        fail(f"the device tree declares {len(nodes)} PCIe host nodes, expected 1")
    node = nodes[0]
    if 'compatible = "pci-host-ecam-generic";' not in node:
        fail("the PCIe host is not pci-host-ecam-generic")
    reg = _node_property(node, "reg", fail)
    if len(reg) != 4:
        fail(f"unexpected PCIe reg cells: {reg}")
    ranges = _node_property(node, "ranges", fail)
    if len(ranges) % 7:
        fail("PCIe ranges is not a list of 7-cell entries")
    mem32 = [ranges[index : index + 7] for index in range(0, len(ranges), 7) if ranges[index] & 0x0300_0000 == 0x0200_0000]
    if len(mem32) != 1:
        fail(f"expected one 32-bit memory window, found {len(mem32)}")
    window = mem32[0]
    pci_address = (window[1] << 32) | window[2]
    cpu_address = (window[3] << 32) | window[4]
    if pci_address != cpu_address:
        fail("the 32-bit memory window translates addresses; the judge assumes identity")
    mask = _node_property(node, "interrupt-map-mask", fail)
    if len(mask) != 4:
        fail(f"unexpected interrupt-map-mask cells: {mask}")
    raw_map = _node_property(node, "interrupt-map", fail)
    if len(raw_map) % 10:
        fail("interrupt-map is not a list of 10-cell entries")
    entries = []
    for index in range(0, len(raw_map), 10):
        entry = raw_map[index : index + 10]
        # child address (3) + pin (1) + GIC phandle + parent address (2) + type, number, flags
        if entry[7] != 0:
            fail("interrupt-map routes INTx to a non-SPI interrupt")
        entries.append((entry[0] & mask[0], entry[3] & mask[3], entry[8]))
    return PcieHost(
        ecam_base=(reg[0] << 32) | reg[1],
        ecam_size=(reg[2] << 32) | reg[3],
        mem32_base=cpu_address,
        mem32_size=(window[5] << 32) | window[6],
        interrupt_map=tuple(entries),
        device_mask=mask[0],
        pin_mask=mask[3],
    )
