#!/usr/bin/env python3
"""B38 gate: exceed old task CSlot/untyped lifetime watermarks with bounded live use.

The default `unwind` arm boots `sel4-reclamation-unwind`. The `large-image` arm
boots `sel4-large-image` on aarch64-sel4-qemu-virt and judges the large
component image work item (01a0fa78-cfc0-7dc0-976e-3ff092b908a4): a synthetic
probe far beyond the former 512-page and 8/16 MiB bounds is launched four
times, verifies its own pages from inside the child, and is reclaimed to the
same root watermarks each time, while every image ceiling fails closed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from closure_image import ClosureImageError, build as build_closure_image  # noqa: E402

import boot_contracts  # noqa: E402
import devloop_observations  # noqa: E402
from component_paths import source_path  # noqa: E402
from harness import GENERATION_COMPOSITIONS, load_script, sha256_file  # noqa: E402
from zutai_cli import STDLIB, binary  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
# CP15: the closure identity names the build's inputs and is re-resolved from
# repository state before the build, so stale input is refused rather than
# silently producing a different image. This checker exercises the forced
# construction-unwind arm carried by the reclamation-unwind root role.
CLOSURE = "sel4-reclamation-unwind"
IMAGE: Path | None = None
PINS = ROOT / "sel4" / "pins.toml"
INIT = source_path("init")
TIMEOUT = 180

# ---- large-image arm --------------------------------------------------------

LARGE_CLOSURE = "sel4-large-image"
LARGE_FIXTURE = GENERATION_COMPOSITIONS / "sel4-large-image.zti"
LARGE_GENERATION = 168
LARGE_TIMEOUT = 1800
LARGE_LOG = ROOT / "build" / "large-image.serial.log"
LARGE_TARGET = "aarch64-sel4-qemu-virt"
# Targets the item leaves on the conservative envelope.
CONSERVATIVE_TARGETS = ("riscv64-sel4-qemu-virt", "x86_64-sel4-qemu-pc99")
CONSERVATIVE_PAGES = 512
IMAGE_CEILING_PAGES = 32_768
MIN_FOOTPRINT_PAGES = 24_576
MIN_ELF_BYTES = 72 * 1024 * 1024
MAX_IMAGE_BYTES = 128 * 1024 * 1024
MAX_OBJECT_PAYLOAD_BYTES = 128 * 1024 * 1024
MAX_GENERATION_BYTES = 256 * 1024 * 1024
INCARNATIONS = 4
# 1-based; the incarnation after it must still verify.
FAULT_INCARNATION = 3

PROBE = "large-image-probe"
OWNER = "large-image-owner"
WITNESS = "large-image-witness"

# The probe's generated regions, each in its own output section so the checker
# can measure them in the ELF the generation actually carries.
SHT_PROGBITS = 1
SHT_NOBITS = 8
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
PROBE_SECTIONS = {
    "rodata": (".large_image_rodata", SHT_PROGBITS, SHF_ALLOC),
    "data": (".large_image_data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE),
    "bss": (".large_image_bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE),
}

# slime-root host tests that must run and pass, one per root-side refusal of a
# generation forged past the builder. Matched by final path segment.
ROOT_REFUSAL_TESTS = (
    "large_image_quota_above_ceiling_refused",
    "large_image_aggregate_above_ceiling_refused",
    "generation_object_above_bound_refused",
    "generation_above_bound_refused",
)

_WATERMARKS = r"live_slots=(\d+) live_objects=(\d+) live_bytes=(\d+) allocation_descriptors_free=(\d+)"
# Printed by the root immediately before it constructs the probe, with the
# root's allocator watermarks as they stand before construction.
LAUNCH = re.compile(
    rf"SLIME_ROOT image launch task=(\d+) instance={PROBE} pages=(\d+) declared=(\d+) {_WATERMARKS}"
)
# Printed by the root once the probe task is fully reclaimed.
RECLAIMED = re.compile(rf"SLIME_ROOT image reclaimed task=(\d+) instance={PROBE} {_WATERMARKS}")
# The co-resident witness's own accounting, printed after each reclamation.
PEER = re.compile(rf"SLIME_ROOT image peer task=(\d+) instance={WITNESS} slots=(\d+) objects=(\d+) bytes=(\d+)")
VERIFIED = re.compile(
    rf"\[{PROBE}\] verified text_calls=3 rodata=(\d+) data=(\d+) bss=(\d+)"
)
OWNER_OUTCOME = re.compile(rf"\[{OWNER}\] incarnation=(\d+) outcome=(exit|fault)")
OWNER_COMPLETE = f"[{OWNER}] complete incarnations={INCARNATIONS} faults=1"
HEALTHY = re.compile(rf"SLIME_GRAPH HEALTHY generation={LARGE_GENERATION} ")
LARGE_FAILURES = (
    r"SLIME_ROOT FATAL",
    r"SLIME_GRAPH FAIL",
    rf"\[{PROBE}\] FAIL",
    rf"\[{OWNER}\] FAIL",
    rf"\[{WITNESS}\] FAIL",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"seL4 reclamation plane check: {message}")


def build_image(closure: str = CLOSURE):
    global IMAGE
    try:
        built = build_closure_image(closure)
    except ClosureImageError as error:
        fail(str(error))
    actual = sha256_file(built.image, fail)
    if actual != built.digest():
        fail(
            f"{built.image} SHA-256 is {actual}, but the build result records "
            f"{built.digest()}; the image changed after it was built"
        )
    if closure == CLOSURE:
        IMAGE = built.image
    return built


def boot(
    profile: dict[str, object],
    image: Path | None = None,
    terminal: re.Pattern[str] | None = None,
    timeout: int = TIMEOUT,
) -> str:
    image = image if image is not None else IMAGE
    if image is None:
        fail("no image was built")
    if terminal is None:
        terminal = re.compile(
            r"SLIME_ROOT allocator live_slots=|SLIME_ROOT FATAL|reclamation plane fail"
        )
    qemu = shutil.which("qemu-system-aarch64")
    if qemu is None:
        fail("qemu-system-aarch64 is not on PATH")
    command = [
        qemu,
        "-machine",
        str(profile["machine"]),
        "-cpu",
        str(profile["cpu"]),
        "-smp",
        str(profile["cpus"]),
        "-m",
        f"size={profile['memory_mib']}M",
        "-nographic",
        "-serial",
        "mon:stdio",
        "-kernel",
        str(image),
    ]
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    watchdog = threading.Timer(timeout, process.kill)
    watchdog.start()
    lines: list[str] = []
    try:
        assert process.stdout is not None
        for line in process.stdout:
            lines.append(line.rstrip("\n"))
            if terminal.search(line):
                break
    finally:
        timed_out = not watchdog.is_alive()
        watchdog.cancel()
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    if timed_out:
        fail("QEMU timed out")
    return "\n".join(lines)


def run_unwind_arm(profile: dict[str, object]) -> None:
    source = INIT.read_text(encoding="utf-8")
    match = re.search(r"const RECLAMATION_LOOP_CHILDREN: u32 = (\d+);", source)
    if match is None or int(match.group(1)) <= 64:
        fail("lifetime loop does not exceed the old monotonic ceiling")
    build_image()
    transcript = boot(profile)
    required = (
        r"\[init\] reclamation construction unwind returned",
        r"SLIME_GRAPH component exit task=\d+ status=0",
        r"\[init\] reclamation lifetime bound crossed",
        r"SLIME_GRAPH component fault task=\d+ kind=",
        r"\[init\] reclamation fault path reused",
        r"\[init\] reclamation plane complete",
        r"SLIME_ROOT allocator quiescent live_slots=(\d+) live_objects=(\d+) live_bytes=(\d+)",
        r"SLIME_ROOT allocator live_slots=(\d+) free_slots=(\d+) live_objects=(\d+) live_bytes=(\d+) "
        r"mapped_ram=(\d+) reusable_ram=([1-9]\d*) reusable_private_ram=([1-9]\d*) "
        r"allocation_descriptors_free=(\d+) extent_descriptors_free=(\d+) "
        r"slot_reuses=([1-9]\d*) extent_reuses=([1-9]\d*)",
    )
    cursor = 0
    for marker in required:
        match = re.search(marker, transcript[cursor:])
        if match is None:
            fail(f"missing ordered marker {marker!r}\n{transcript}")
        cursor += match.end()
    quiescent = re.search(
        r"SLIME_ROOT allocator quiescent live_slots=(\d+) live_objects=(\d+) live_bytes=(\d+)",
        transcript,
    )
    terminal = re.search(required[-1], transcript)
    if quiescent is None or terminal is None:
        fail("allocator quiescent or terminal accounting missing")
    if quiescent.groups() != (terminal.group(1), terminal.group(3), terminal.group(4)):
        fail(
            f"allocator live accounting drifted: quiescent={quiescent.groups()} "
            f"terminal={(terminal.group(1), terminal.group(3), terminal.group(4))}"
        )
    if terminal.group(5) != "0":
        fail(f"private mapped RAM survived reclamation: {terminal.group(5)}")
    if int(terminal.group(6)) == 0:
        fail("no reclaimable backing extent was retained for reuse")
    # Unrestricted `reusable_ram` is satisfied by any inactive extent,
    # including the one every task carries for its static construction --
    # `reclamation-fault`'s own declared quota is what makes this composition
    # exercise a private extent at all, and this is the kind-scoped assertion
    # that it specifically was reclaimed rather than leaked.
    if int(terminal.group(7)) == 0:
        fail("no private-backing extent was retained for reuse")
    # The plane ends with no live task, so the exact law holds: every
    # allocation descriptor the pool declares must be free again. The liveness
    # and reuse assertions above cannot stand in for it — they are satisfied by
    # a release that returns slots, extents, and the page charge while
    # stranding an `AllocationRecord`.
    capacity = re.search(
        r"SLIME_ROOT allocator baseline live_slots=\d+ live_objects=\d+ live_bytes=\d+ "
        r"allocation_descriptor_capacity=(\d+) extent_descriptor_capacity=(\d+)",
        transcript,
    )
    if capacity is None:
        fail("the root reported no allocator descriptor capacity")
    if terminal.group(8) != capacity.group(1):
        fail(
            f"{int(capacity.group(1)) - int(terminal.group(8))} allocation "
            "descriptor(s) survived reclamation of every task: "
            f"{terminal.group(8)} free of {capacity.group(1)}"
        )
    # Extent descriptors are deliberately *not* returned: `release_task_arena`
    # deactivates a record rather than clearing it, so `provision_extent` can
    # re-retype into it. Retention is therefore proved by reuse dominating new
    # records, not by the free count returning: were retention to break, every
    # provision would take a fresh record and `extent_reuses` would collapse.
    extent_growth = int(capacity.group(2)) - int(terminal.group(9))
    if extent_growth >= int(terminal.group(11)):
        fail(
            f"extent descriptors grew by {extent_growth} against "
            f"{terminal.group(11)} reuse(s): released records are not being "
            "retained for reuse"
        )
    if re.search(r"SLIME_ROOT FATAL|reclamation plane fail|spawn unwound", transcript):
        fail("failure marker present")
    print(
        "seL4 reclamation plane check: segmented task extents and root CSlots were reclaimed and reused"
    )


# ---- large-image arm: fixture and probe image --------------------------------


class LargeImageRefusal(Exception):
    """A judged transcript was refused; raised instead of exiting so controls can count it."""


def _reject(message: str) -> NoReturn:
    raise LargeImageRefusal(message)


def fixture_manifest(fixture: Path) -> dict[str, object]:
    environment = os.environ.copy()
    environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
    process = subprocess.run(
        [str(binary()), "json", str(fixture)],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if process.returncode != 0:
        fail(f"could not decode {fixture.name}: {process.stdout.strip()}")
    return json.loads(process.stdout)


def check_large_fixture() -> str:
    """Require the composition's declared shape; return the probe's object id."""
    if not LARGE_FIXTURE.is_file():
        fail(
            f"{LARGE_FIXTURE.relative_to(ROOT)} does not exist; "
            "the large-image composition has not landed"
        )
    manifest = fixture_manifest(LARGE_FIXTURE)
    if manifest.get("generation") != LARGE_GENERATION:
        fail(f"{LARGE_FIXTURE.name} declares generation {manifest.get('generation')!r}, expected {LARGE_GENERATION}")
    executables = {entry["name"]: entry for entry in manifest["executables"]}
    if PROBE not in executables:
        fail(f"{LARGE_FIXTURE.name} declares no {PROBE} executable")
    instances = {entry["name"]: entry for entry in manifest["instances"]}
    # (owner, autostart, health) as the arm's judgement assumes them: the owner
    # and the witness run from boot, and the probe is a spawned optional child
    # whose deliberate fault must not end the graph.
    declared = {
        OWNER: ("root", True, "required"),
        WITNESS: ("root", True, None),
        PROBE: (OWNER, False, "optional"),
    }
    for name, (owner, autostart, health) in declared.items():
        entry = instances.get(name)
        if entry is None:
            fail(f"{LARGE_FIXTURE.name} declares no {name} instance")
        if entry.get("owner") != owner or entry.get("autostart") != autostart:
            fail(f"{LARGE_FIXTURE.name} declares {name} with owner={entry.get('owner')!r} autostart={entry.get('autostart')!r}")
        if health is not None and entry.get("health") != health:
            fail(f"{LARGE_FIXTURE.name} declares {name} with health={entry.get('health')!r}, expected {health!r}")
    if instances[PROBE].get("executable") != PROBE:
        fail(f"{LARGE_FIXTURE.name}'s {PROBE} instance does not run the {PROBE} executable")
    users = sorted(name for name, entry in instances.items() if entry.get("executable") == PROBE)
    if users != [PROBE]:
        fail(f"the {PROBE} executable is run by {users!r}; only the {PROBE} instance may run it")
    return str(executables[PROBE]["object"])


def object_payload(generation: bytes, object_id: str) -> bytes:
    count = struct.unpack_from("<I", generation, boot_contracts.GENERATION_HEADER_OBJECT_COUNT_OFFSET)[0]
    objects = struct.unpack_from("<Q", generation, boot_contracts.GENERATION_HEADER_OBJECT_OFFSET_OFFSET)[0]
    strings = struct.unpack_from("<Q", generation, boot_contracts.GENERATION_HEADER_STRING_OFFSET_OFFSET)[0]
    for index in range(count):
        name_offset, _kind, payload_offset, payload_len, _digest = boot_contracts.GENERATION_OBJECT.unpack_from(
            generation, objects + index * boot_contracts.GENERATION_OBJECT.size
        )
        name_len = struct.unpack_from("<H", generation, strings + name_offset)[0]
        start = strings + name_offset + 2
        if generation[start : start + name_len].decode() == object_id:
            return generation[payload_offset : payload_offset + payload_len]
    fail(f"the built generation carries no object {object_id!r}")


class ProbeImage:
    """What the checker measures in the probe ELF the generation carries."""

    def __init__(self, elf: bytes, page_bytes: int) -> None:
        if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
            fail(f"the {PROBE} payload is not a 64-bit little-endian ELF")
        self.length = len(elf)
        phoff = struct.unpack_from("<Q", elf, 32)[0]
        shoff = struct.unpack_from("<Q", elf, 40)[0]
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", elf, 54)
        start: int | None = None
        end = 0
        for index in range(phnum):
            header = phoff + index * phentsize
            p_type = struct.unpack_from("<I", elf, header)[0]
            p_vaddr = struct.unpack_from("<Q", elf, header + 16)[0]
            p_memsz = struct.unpack_from("<Q", elf, header + 40)[0]
            if p_type == 1 and p_memsz:
                start = p_vaddr if start is None else min(start, p_vaddr)
                end = max(end, p_vaddr + p_memsz)
        if start is None:
            fail(f"the {PROBE} ELF has no loadable segment")
        first = start - start % page_bytes
        last = -(-end // page_bytes) * page_bytes
        # The root's footprint: the loaded span plus the IPC-buffer and
        # transfer-window pages.
        self.pages = (last - first) // page_bytes + 2
        if shoff == 0 or shnum == 0 or shentsize != 64:
            fail(f"the {PROBE} ELF carries no section headers to measure")
        sections: dict[str, tuple[int, int, int, int]] = {}
        names_offset = struct.unpack_from("<Q", elf, shoff + shstrndx * shentsize + 24)[0]
        for index in range(shnum):
            header = shoff + index * shentsize
            name, kind, flags, address, _offset, size = struct.unpack_from("<IIQQQQ", elf, header)
            terminator = elf.index(b"\0", names_offset + name)
            sections[elf[names_offset + name : terminator].decode()] = (kind, flags, address, size)
        self.regions: dict[str, tuple[int, int]] = {}
        for region, (section, kind, flags) in PROBE_SECTIONS.items():
            found = sections.get(section)
            if found is None:
                fail(f"the {PROBE} ELF has no {section} section")
            found_kind, found_flags, address, size = found
            if found_kind != kind or found_flags & (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR) != flags:
                fail(f"{section} has type {found_kind} flags {found_flags:#x}, expected type {kind} flags {flags:#x}")
            if size == 0:
                fail(f"{section} is empty")
            self.regions[region] = (address, size)

    def judge(self) -> None:
        if self.length < MIN_ELF_BYTES:
            fail(f"the {PROBE} ELF is {self.length} bytes, below the {MIN_ELF_BYTES}-byte floor")
        if not MIN_FOOTPRINT_PAGES <= self.pages <= IMAGE_CEILING_PAGES:
            fail(f"the {PROBE} footprint is {self.pages} pages, outside {MIN_FOOTPRINT_PAGES}..{IMAGE_CEILING_PAGES}")

    def verified_bytes(self) -> int:
        return sum(size for _address, size in self.regions.values())


def probe_image(built) -> ProbeImage:
    object_id = check_large_fixture()
    generation = Path(built.generation).read_bytes()
    payload = object_payload(generation, object_id)
    if payload[:4] != b"\x7fELF":
        payload = payload[boot_contracts.COMPONENT_IMAGE_ELF_HEADER_LEN :]
    profile = boot_contracts.TARGET_PROFILES_BY_NAME[LARGE_TARGET]
    return ProbeImage(payload, profile.page_bytes)


# ---- large-image arm: builder and root refusals ------------------------------


def synthetic_elf(profile, pages: int, length: int = 0) -> bytes:
    """A minimal static executable whose footprint is exactly `pages` pages.

    One executable page holds the entry; one writable zero-fill segment makes
    up the rest of the span, so the footprint costs no file bytes. `length`
    pads the file to exercise the byte bound without changing the footprint.
    """
    page = profile.page_bytes
    base = profile.component_base
    span = pages - 2
    header = struct.pack(
        "<4sBBBB8xHHIQQQIHHHHHH",
        b"\x7fELF", 2, 1, 1, 0,
        2, profile.elf_machine, 1, base, 64, 0, 0, 64, 56, 2, 64, 0, 0,
    )
    text = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, 0, page, page)
    data = struct.pack("<IIQQQQQQ", 1, 6, 0, base + page, base + page, 0, (span - 1) * page, page)
    elf = header + text + data
    return elf + bytes(max(0, length - len(elf)))


def builder_controls() -> int:
    """Run both builder-side validators at and past every ceiling; return refusals."""
    for name, actual, expected in (
        ("MAX_COMPONENT_IMAGE_BYTES", boot_contracts.MAX_COMPONENT_IMAGE_BYTES, MAX_IMAGE_BYTES),
        ("MAX_OBJECT_PAYLOAD_BYTES", boot_contracts.MAX_OBJECT_PAYLOAD_BYTES, MAX_OBJECT_PAYLOAD_BYTES),
        ("MAX_GENERATION_BYTES", boot_contracts.MAX_GENERATION_BYTES, MAX_GENERATION_BYTES),
    ):
        if actual != expected:
            fail(f"the generated {name} is {actual}, expected {expected}")
    builder = load_script("large_image_builder", "build/build-generation.py")
    checker = load_script("large_image_generation_check", "check/check-generation.py")

    def admitted(tool: str, profile, elf: bytes) -> bool:
        try:
            if tool == "builder":
                builder._validate_sel4_elf(PROBE, elf, profile)
            else:
                checker.check_component_elf(elf, profile, PROBE)
        except (SystemExit, checker.CheckError):
            return False
        return True

    large = boot_contracts.TARGET_PROFILES_BY_NAME[LARGE_TARGET]
    accepted = [
        (large, synthetic_elf(large, IMAGE_CEILING_PAGES), f"{IMAGE_CEILING_PAGES} pages on {LARGE_TARGET}"),
        (large, synthetic_elf(large, CONSERVATIVE_PAGES + 1), f"{CONSERVATIVE_PAGES + 1} pages on {LARGE_TARGET}"),
    ]
    refused_cases = [
        (large, synthetic_elf(large, IMAGE_CEILING_PAGES + 1), f"{IMAGE_CEILING_PAGES + 1} pages on {LARGE_TARGET}"),
        (large, synthetic_elf(large, 16, MAX_IMAGE_BYTES + 1), f"a {MAX_IMAGE_BYTES + 1}-byte ELF on {LARGE_TARGET}"),
    ]
    for target in CONSERVATIVE_TARGETS:
        profile = boot_contracts.TARGET_PROFILES_BY_NAME[target]
        accepted.append((profile, synthetic_elf(profile, CONSERVATIVE_PAGES), f"{CONSERVATIVE_PAGES} pages on {target}"))
        refused_cases.append((profile, synthetic_elf(profile, CONSERVATIVE_PAGES + 1), f"{CONSERVATIVE_PAGES + 1} pages on {target}"))
    refused = 0
    for tool in ("builder", "checker"):
        for profile, elf, label in accepted:
            if not admitted(tool, profile, elf):
                fail(f"the generation {tool} refused {label}, which is within the ceiling")
        for profile, elf, label in refused_cases:
            if admitted(tool, profile, elf):
                fail(f"the generation {tool} admitted {label}, which is past the ceiling")
            refused += 1
    return refused


def root_refusal_tests() -> int:
    """Run slime-root's host tests and require each named refusal test to pass."""
    just = shutil.which("just")
    if just is None:
        fail("just is not on PATH")
    process = subprocess.run(
        [just, "test_sel4_root"],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if process.returncode != 0:
        tail = "\n".join(process.stdout.strip().splitlines()[-20:])
        fail(f"slime-root host tests failed:\n{tail}")
    passed = {
        match.group(1).rsplit("::", 1)[-1]
        for match in re.finditer(r"^test (\S+) \.\.\. ok$", process.stdout, re.MULTILINE)
    }
    missing = [name for name in ROOT_REFUSAL_TESTS if name not in passed]
    if missing:
        fail(f"slime-root host tests did not run and pass {missing!r}")
    return len(ROOT_REFUSAL_TESTS)


# ---- large-image arm: transcript judgement -----------------------------------


def _only(pattern: re.Pattern[str] | str, text: str, what: str, reject: Callable[[str], NoReturn]) -> re.Match[str]:
    found = list(re.finditer(pattern, text))
    if len(found) != 1:
        reject(f"expected exactly one {what}, observed {len(found)}")
    return found[0]


def _fault_address(match: re.Match[str]) -> int:
    value = match.group(1)
    return int(value, 16) if value.startswith("0x") else int(value)


def judge_large_image(transcript: str, probe: ProbeImage, reject: Callable[[str], NoReturn]) -> dict[str, int]:
    """Return the arm's observations, or reject the transcript."""
    for marker in LARGE_FAILURES:
        if re.search(marker, transcript):
            reject(f"failure marker present: {marker}")
    healthy = _only(HEALTHY, transcript, f"generation {LARGE_GENERATION} certification", reject)
    complete = _only(re.escape(OWNER_COMPLETE), transcript, "owner completion", reject)
    if complete.start() > healthy.start():
        reject("the graph certified before the owner completed its incarnations")
    launches = list(LAUNCH.finditer(transcript))
    if len(launches) != INCARNATIONS:
        reject(f"the root launched the probe {len(launches)} time(s), expected {INCARNATIONS}")
    baseline: tuple[str, ...] | None = None
    peer_accounting: tuple[str, ...] | None = None
    cases = reclaimed_count = faults = 0
    rodata_start, rodata_size = probe.regions["rodata"]
    expected_bytes = tuple(str(probe.regions[region][1]) for region in ("rodata", "data", "bss"))
    for index, launch in enumerate(launches):
        incarnation = index + 1
        end = launches[index + 1].start() if index + 1 < len(launches) else complete.start()
        if end < launch.end():
            reject("an incarnation ended before its launch")
        segment = transcript[launch.start() : end]
        task, pages, declared = launch.group(1), int(launch.group(2)), int(launch.group(3))
        before = launch.groups()[3:]
        if pages != declared:
            reject(f"incarnation {incarnation} installed {pages} image pages against {declared} declared")
        if pages != probe.pages:
            reject(f"incarnation {incarnation} installed {pages} pages; the probe ELF spans {probe.pages}")
        if baseline is None:
            baseline = before
        elif before != baseline:
            reject(f"incarnation {incarnation} launched from watermarks {before} instead of {baseline}")
        verified = _only(VERIFIED, segment, f"verification in incarnation {incarnation}", reject)
        if verified.groups() != expected_bytes:
            reject(f"incarnation {incarnation} verified {verified.groups()} bytes; the probe's sections are {expected_bytes}")
        exits = list(re.finditer(rf"SLIME_GRAPH component exit task={task} status=(\d+)", segment))
        fault_lines = list(
            re.finditer(
                rf"SLIME_GRAPH component fault task={task} kind=VirtualMemory address=Some\((0x[0-9a-fA-F]+|\d+)\)",
                segment,
            )
        )
        if incarnation == FAULT_INCARNATION:
            if exits or len(fault_lines) != 1:
                reject(f"incarnation {incarnation} did not end in exactly one VirtualMemory fault")
            ended = fault_lines[0]
            address = _fault_address(ended)
            if not rodata_start <= address < rodata_start + rodata_size:
                reject(f"the deliberate fault at {address:#x} is outside the probe's read-only data")
            outcome = "fault"
        else:
            if fault_lines or len(exits) != 1 or exits[0].group(1) != "0":
                reject(f"incarnation {incarnation} did not exit 0 exactly once")
            ended = exits[0]
            outcome = "exit"
        reclaimed = _only(
            re.compile(rf"SLIME_ROOT image reclaimed task={task} instance={PROBE} {_WATERMARKS}"),
            segment,
            f"reclamation of incarnation {incarnation}",
            reject,
        )
        peer = _only(PEER, segment, f"witness accounting after incarnation {incarnation}", reject)
        if not verified.start() < ended.start() < reclaimed.start() < peer.start():
            reject(f"incarnation {incarnation} is out of order: launch, verification, end, reclamation, witness")
        if reclaimed.groups() != before:
            reject(f"incarnation {incarnation} reclaimed to {reclaimed.groups()} from {before}")
        if peer_accounting is None:
            peer_accounting = peer.groups()
        elif peer.groups() != peer_accounting:
            reject(f"the witness's accounting moved from {peer_accounting} to {peer.groups()}")
        owner = _only(OWNER_OUTCOME, segment, f"owner outcome for incarnation {incarnation}", reject)
        if owner.groups() != (str(incarnation), outcome):
            reject(f"the owner reported {owner.groups()} for incarnation {incarnation}, expected {outcome}")
        cases += 1
        reclaimed_count += 1
        faults += outcome == "fault"
    return {
        "casesObserved": cases,
        "bytesObserved": probe.verified_bytes(),
        "resourcesReclaimed": reclaimed_count,
        "faultsIsolated": faults,
    }


def transcript_controls(transcript: str, probe: ProbeImage) -> int:
    """Mutate the accepted transcript and require every mutation to be refused."""
    launches = list(LAUNCH.finditer(transcript))
    verified = VERIFIED.search(transcript)
    reclaimed = RECLAIMED.search(transcript)
    peers = list(PEER.finditer(transcript))
    faults = re.search(r"SLIME_GRAPH component fault task=(\d+) kind=VirtualMemory address=Some\(([^)]*)\)", transcript)
    if len(launches) < 2 or verified is None or reclaimed is None or len(peers) < 2 or faults is None:
        fail("transcript controls need the accepted launch, verification, reclamation, witness and fault evidence")
    first, second = launches[0], launches[1]
    complete = transcript.index(OWNER_COMPLETE)

    def bump(match: re.Match[str], group: int) -> str:
        line = match.group(0)
        start, end = match.start(group) - match.start(), match.end(group) - match.start()
        changed = line[:start] + str(int(match.group(group)) + 1) + line[end:]
        return transcript[: match.start()] + changed + transcript[match.end() :]

    fault_task = faults.group(1)
    mutations = (
        ("missing verification", transcript[: verified.start()] + transcript[verified.end() :]),
        ("installed pages differ from declared", bump(first, 3)),
        ("reclamation left a slot behind", bump(reclaimed, 2)),
        ("launch watermarks drifted between incarnations", bump(second, 5)),
        ("witness accounting moved", bump(peers[1], 2)),
        (
            "the fault became a clean exit",
            transcript.replace(faults.group(0), f"SLIME_GRAPH component exit task={fault_task} status=0"),
        ),
        (
            "the fault landed outside read-only data",
            transcript.replace(faults.group(0), f"SLIME_GRAPH component fault task={fault_task} kind=VirtualMemory address=Some(0x8)"),
        ),
        (
            "reclamation reordered before verification",
            transcript[: first.end()]
            + "\n"
            + reclaimed.group(0)
            + transcript[first.end() : reclaimed.start()]
            + transcript[reclaimed.end() :],
        ),
        (
            "an extra incarnation",
            transcript[:complete] + transcript[first.start() : second.start()] + transcript[complete:],
        ),
        ("explicit failure", transcript + f"\n[{PROBE}] FAIL injected control"),
    )
    refused = 0
    for label, mutated in mutations:
        if mutated == transcript:
            fail(f"transcript control {label!r} did not change the transcript")
        try:
            judge_large_image(mutated, probe, _reject)
        except LargeImageRefusal:
            refused += 1
            continue
        fail(f"transcript control accepted a mutated transcript: {label}")
    return refused


def run_large_image_arm(profile: dict[str, object]) -> None:
    check_large_fixture()
    refused = builder_controls()
    refused += root_refusal_tests()
    built = build_image(LARGE_CLOSURE)
    probe = probe_image(built)
    probe.judge()
    failures = "|".join(LARGE_FAILURES)
    transcript = boot(
        profile,
        built.image,
        re.compile(HEALTHY.pattern + "|" + failures),
        LARGE_TIMEOUT,
    )
    LARGE_LOG.parent.mkdir(parents=True, exist_ok=True)
    LARGE_LOG.write_text(transcript + "\n", encoding="utf-8")
    try:
        observed = judge_large_image(transcript, probe, _reject)
    except LargeImageRefusal as error:
        fail(f"{error}; transcript: {LARGE_LOG.relative_to(ROOT)}")
    refused += transcript_controls(transcript, probe)
    print(
        f"[large-image] pages={probe.pages} elf_bytes={probe.length} "
        f"cases={observed['casesObserved']} bytes={observed['bytesObserved']} "
        f"reclaimed={observed['resourcesReclaimed']} faults={observed['faultsIsolated']} "
        f"controls-refused={refused}"
    )
    devloop_observations.record(negativeControlsRefused=refused, **observed)
    print(
        "seL4 large-image check: a component image past every former bound was admitted, verified "
        "its own pages from inside the child, faulted once on its read-only data, and was reclaimed "
        "to the same root watermarks each time, while every image ceiling refused"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Boot and check the seL4 reclamation planes")
    parser.add_argument("--arm", choices=("unwind", "large-image"), default="unwind")
    arguments = parser.parse_args()
    pins = tomllib.loads(PINS.read_text(encoding="utf-8"))
    profile = pins.get("qemu_arm_virt")
    if not isinstance(profile, dict):
        fail("missing qemu profile")
    if arguments.arm == "large-image":
        run_large_image_arm(profile)
        return
    run_unwind_arm(profile)


if __name__ == "__main__":
    main()
