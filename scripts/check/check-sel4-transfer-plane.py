#!/usr/bin/env python3

"""P5.4.3 gate: M6.7's generation transfer (M6.7).

A generation crosses a persistence boundary. Two devices are attached: a
*source* the component may only read, carrying the transfer manifest, and a
*receiver* it may write, holding the BootState.

The separation is the milestone. M6.7 requires that a transfer "leave every
ungranted device byte-identical", and here the source is granted — read-only —
so the claim is sharper: a device granted `blockRead` alone is byte-identical
even though the component reached it, repeatedly, and wanted to write it.

The arms:

* the source refuses a write, checked before anything else;
* the manifest decodes, which validates bounds, ordering, and a self-excluding
  SHA-256 over the whole record;
* a tampered byte fails that digest specifically, not some field it landed in;
* the object closure re-hashes to the identities the manifest declares, before
  any BootState write — so an incomplete transfer costs the receiver nothing;
* state travels only where the source declared it may;
* the generation stages **pending**, leaving the known-good root intact, and
  only health confirmation promotes it.

This plane exists because B29 was fixed: two QEMU virtio transports share one
4 KiB granule, and the root now maps that granule once and hands each driver a
borrowed view at its own offset.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import tomllib
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from closure_image import ClosureImageError, build as build_closure_image  # noqa: E402
from harness import GENERATION_COMPOSITIONS, profile_text, profile_integer, sha256_file  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PINS_PATH = ROOT / "sel4" / "pins.toml"
FIXTURE_SCRIPT = ROOT / "scripts" / "build" / "build-store-fixture.py"
# CP15: the closure identity names the build's inputs and is re-resolved from
# repository state before the build, so a stale input is refused rather than
# silently producing a different image.
CLOSURE = "sel4-transfer"
IMAGE: Path | None = None
FIXTURE = GENERATION_COMPOSITIONS / "sel4-transfer.zti"
BOOT_TIMEOUT_SECONDS = 240

# The receiver's BootState slots, partition-relative.
STATE_SLOT_A = 1024

# Sequence 2 is the higher of the two slots recovery writes, so it is what a
# fresh boot selects. Release 3 is the fixture's accepted release sequence.
RECONSTRUCTED_SEQUENCE = 2
RECONSTRUCTED_RELEASE = 3
# The fixture's state closure: the store's seeded object.
CLOSURE_OBJECTS = 1

REQUIRED_MARKERS: tuple[tuple[str, str], ...] = (
    (
        "init spawned the probe",
        r"\[init\] transfer probe spawned",
    ),
    (
        # The write crossed IO0 and the source driver's generation-declared
        # authority table answered STATUS_BAD_RIGHTS before virtio saw it.
        "the source driver refused a write outside its ring authority",
        r"\[sel4-transfer-probe\] source write refused by driver rights",
    ),
    (
        # Checked before anything else: every later claim about the source
        # being untouched rests on the driver's ring authority refusing the write.
        "the source device refuses writes",
        r"\[sel4-transfer-probe\] the source device refuses writes",
    ),
    (
        "the receiver starts from a known-good root",
        r"\[sel4-transfer-probe\] receiver holds a known-good root",
    ),
    (
        "the manifest decoded with its declared closure",
        r"\[sel4-transfer-probe\] manifest objects=1 states=1",
    ),
    (
        # On the digest specifically. A flip in the metadata is covered by no
        # bound, so only the self-excluding hash catches it.
        "a tampered manifest was refused on its digest",
        r"\[sel4-transfer-probe\] tampered manifest refused",
    ),
    (
        # Before any BootState write, so an incomplete transfer consumes no
        # attempt and leaves the receiver as it was.
        "every object in the closure re-hashed to its declared identity",
        r"\[sel4-transfer-probe\] closure verified objects=1 of=1",
    ),
    (
        # `ephemeral` state does not travel; `immutable` travels read-only.
        "state travelled only where the source declared it may",
        r"\[sel4-transfer-probe\] source-state travel entries=1 read-only=1",
    ),
    (
        # Pending, not promoted: the known-good root is intact, which is what
        # makes a failed activation recoverable.
        "the transferred generation staged pending",
        r"\[sel4-transfer-probe\] staged seq=2 pending=1 release=1",
    ),
    (
        # Only now does the known-good root become the transferred generation,
        # and the accepted release advances to the manifest's.
        "health confirmation promoted it and advanced the release",
        r"\[sel4-transfer-probe\] promoted seq=3 pending=0 release=5",
    ),
    (
        "the probe ran every arm and exited cleanly",
        r"\[sel4-transfer-probe\] transfer plane complete",
    ),
    (
        "init observed the clean exit",
        r"\[init\] transfer plane complete",
    ),
)

TERMINAL_MARKER = r"\[init\] transfer plane complete"

FAILURE_MARKERS: tuple[str, ...] = (
    r"SLIME_ROOT FATAL",
    r"SLIME_ROOT FAIL",
    r"SLIME_GRAPH FAIL",
    r"SLIME_GRAPH wedged waiter",
    r"\[init\] transfer plane fail: .*",
    r"\[sel4-transfer-probe\] fail: .*",
    r"\[virtio-blk-driver\] fail: .*",
    r"Caught cap fault",
    r"Caught vm fault",
    r"Caught user exception",
    r"panicked at ",
    r"aborted at ",
    r"\(aborted\)",
)

def fail(message: str) -> NoReturn:
    raise SystemExit(f"seL4 transfer plane check: {message}")


def load_pins() -> dict[str, object]:
    if not PINS_PATH.is_file():
        fail(f"missing pin manifest: {PINS_PATH.relative_to(ROOT)}")
    try:
        pins = tomllib.loads(PINS_PATH.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse {PINS_PATH.relative_to(ROOT)}: {error}")
    if pins.get("schema") != 1:
        fail("unsupported sel4/pins.toml schema (expected 1)")
    if not isinstance(pins.get("qemu_arm_virt"), dict):
        fail("sel4/pins.toml is missing [qemu_arm_virt]")
    return pins


def build_image() -> None:
    global IMAGE
    try:
        built = build_closure_image(CLOSURE)
    except ClosureImageError as error:
        fail(str(error))
    IMAGE = built.image
    actual = sha256_file(IMAGE, fail)
    if actual != built.digest():
        fail(
            f"{IMAGE} SHA-256 is {actual}, but the build result records "
            f"{built.digest()}; the image changed after it was built"
        )


def build_fixture(disk: Path, variant: str) -> None:
    """One of the two fixtures: `happy` for the receiver, `transfer` for the
    source — the same image plus a transfer manifest above the record area."""
    command = [sys.executable, str(FIXTURE_SCRIPT), str(disk), variant]
    try:
        process = subprocess.run(command, cwd=ROOT, check=False, capture_output=True)
    except OSError as error:
        fail(f"cannot build the store fixture: {error}")
    if process.returncode != 0:
        fail(f"store fixture build failed: {process.stderr.decode()}")


def boot(profile: dict[str, object], receiver: Path, source: Path) -> str:
    qemu = shutil.which("qemu-system-aarch64")
    if qemu is None:
        fail("qemu-system-aarch64 is not on PATH")
    command = [
        qemu,
        "-machine",
        profile_text(profile, "machine", fail),
        "-cpu",
        profile_text(profile, "cpu", fail),
        "-smp",
        str(profile_integer(profile, "cpus", fail)),
        "-m",
        f"size={profile_integer(profile, 'memory_mib', fail)}M",
        "-nographic",
        "-serial",
        "mon:stdio",
        "-kernel",
        str(IMAGE),
        "-drive",
        f"if=none,id=slimedisk,format=raw,file={receiver}",
        "-device",
        "virtio-blk-device,drive=slimedisk",
        # The source, attached second so QEMU gives it the lower transport —
        # the root sorts highest-address-first, so device 0 is the receiver.
        "-drive",
        f"if=none,id=sourcedisk,format=raw,file={source}",
        "-device",
        "virtio-blk-device,drive=sourcedisk",
    ]
    print(f"[boot] {' '.join(command)}", flush=True)
    failures = re.compile("|".join(FAILURE_MARKERS))
    terminal = re.compile(TERMINAL_MARKER)
    lines: list[str] = []
    reached = False
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as error:
        fail(f"cannot run QEMU: {error}")
    watchdog = threading.Timer(BOOT_TIMEOUT_SECONDS, process.kill)
    watchdog.start()
    try:
        assert process.stdout is not None
        # The root-owned idle instance runs concurrently with init and reports
        # holding no run token only after a bounded wait, so its line can land
        # before or after init's completion marker. Stop once *both* facts have
        # been observed rather than at the terminal alone.
        idle_seen = False
        for line in process.stdout:
            lines.append(line.rstrip("\r\n"))
            if failures.search(line):
                break
            idle_seen |= "[sel4-transfer-probe] idle without a run token" in line
            reached |= terminal.search(line) is not None
            if reached and idle_seen:
                break
    finally:
        watchdog.cancel()
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    transcript = "\n".join(lines)
    if not reached:
        report_transcript(transcript)
        fail(f"boot exceeded {BOOT_TIMEOUT_SECONDS}s without completing the plane")
    return transcript




def report_transcript(transcript: str) -> None:
    tail = transcript.splitlines()[-40:]
    if tail:
        sys.stdout.write("--- serial transcript (tail) ---\n")
        sys.stdout.write("\n".join(tail) + "\n")
        sys.stdout.write("--- end transcript ---\n")
        sys.stdout.flush()


def check_transcript(transcript: str) -> None:
    for pattern in FAILURE_MARKERS:
        match = re.search(pattern, transcript)
        if match is not None:
            report_transcript(transcript)
            fail(f"failure marker in serial transcript: {match.group(0)!r}")
    position = 0
    for label, pattern in REQUIRED_MARKERS:
        match = re.compile(pattern).search(transcript, position)
        if match is None:
            report_transcript(transcript)
            if re.search(pattern, transcript) is not None:
                fail(f"marker out of order: {label} ({pattern})")
            fail(f"missing marker: {label} ({pattern})")
        position = match.end()
    # Asserted by presence, not by position: the idle instance concludes it
    # holds no run token only after a bounded wait, so its line lands wherever
    # the scheduler puts it. Ordering it would assert a scheduling accident.
    if "[sel4-transfer-probe] idle without a run token" not in transcript:
        report_transcript(transcript)
        fail("the unconfigured instance did not report parking without a run token")
    completions = transcript.count("[sel4-transfer-probe] transfer plane complete")
    if completions != 1:
        report_transcript(transcript)
        fail(f"{completions} instances ran the scenario, expected 1")
    # Two independently declared driver quotas tie the composition's device 0
    # and device 1 budget rows to distinct runtime instances. Together with the
    # two distinct authority tables and two ready announcements above, this is
    # the userspace replacement for the root's old per-request device numbers.
    for instance in ("virtio-blk-receiver", "virtio-blk-source"):
        if not re.search(
            rf"SLIME_IO quota task=\d+ instance={instance}\b",
            transcript,
        ):
            report_transcript(transcript)
            fail(f"the root recorded no distinct IO quota for {instance}")
    # Driver output is scheduler-independent, so assert presence/count here
    # rather than forcing either instance ahead of the probe in the marker chain.
    # Each driver reports the rights its own ring holds: device 0's ring is read-write and
    # device 1's is read-only, so one of each must appear.
    authority = re.findall(
        r"\[virtio-blk-driver\] authority rings=1 rights=(read,write|read) source=generation",
        transcript,
    )
    if sorted(authority) != ["read", "read,write"]:
        report_transcript(transcript)
        fail(f"the driver instances read authority {authority}, expected one read,write and one read")
    ready = re.findall(r"\[virtio-blk-driver\] ready capacity=\d+ epoch=\d+", transcript)
    if len(ready) != 2:
        report_transcript(transcript)
        fail(f"{len(ready)} userspace block transports came up, expected 2")
    exits = transcript.count("[virtio-blk-driver] peer complete, exiting")
    if exits != 2:
        report_transcript(transcript)
        fail(f"{exits} userspace block drivers exited cleanly, expected 2")

    # Root-side corroboration after the block data path left the root. Both DMA
    # directions are indispensable: DeviceWrite carried source and receiver
    # reads into client memory, while DeviceRead carried receiver writes out.
    payload_dma = re.findall(
        r"SLIME_IO payload dma pages=\d+ frames=\d+ writable=\w+ direction=(\w+)",
        transcript,
    )
    for direction in ("DeviceRead", "DeviceWrite"):
        if direction not in payload_dma:
            report_transcript(transcript)
            fail(f"the root mediated no {direction} payload DMA for the userspace drivers")

    reclaims = re.findall(
        r"SLIME_IO reclaim task=\d+ .*pre_dma_pages=(\d+) pre_dma_mappings=(\d+) .*"
        r"reclaimed_dma_pages=(\d+) reclaimed_dma_mappings=(\d+) .*"
        r"post_dma_pages=(\d+) post_dma_mappings=(\d+) post_requests=(\d+)",
        transcript,
    )
    if len(reclaims) != 2:
        report_transcript(transcript)
        fail(f"the root recorded {len(reclaims)} IO-resource reclaims, expected 2")
    for index, groups in enumerate(reclaims, 1):
        pre_pages, pre_mappings, back_pages, back_mappings, post_pages, post_mappings, post_requests = (
            int(value) for value in groups
        )
        if pre_pages == 0 or pre_mappings == 0:
            report_transcript(transcript)
            fail(f"driver {index} held no DMA pages or mappings, so it moved no bytes")
        if (back_pages, back_mappings) != (pre_pages, pre_mappings):
            report_transcript(transcript)
            fail(
                f"driver {index}: the root reclaimed {back_pages}/{back_mappings} of "
                f"{pre_pages}/{pre_mappings} DMA pages/mappings"
            )
        if (post_pages, post_mappings, post_requests) != (0, 0, 0):
            report_transcript(transcript)
            fail(
                f"driver {index} left {post_pages} DMA pages, {post_mappings} mappings, "
                f"and {post_requests} requests outstanding"
            )
    print(
        f"transcript: {len(REQUIRED_MARKERS)} markers observed; both devices came "
        "up from one shared granule and each answered under its own index, the "
        "read-only source refused a write, a "
        "tampered manifest failed its digest, and the transferred generation "
        "staged pending before health confirmation promoted it",
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Boot the seL4 transfer-plane image and assert M6.7"
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="boot the already-built image instead of rebuilding it first",
    )
    arguments = parser.parse_args()

    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    if not FIXTURE.is_file():
        fail(f"missing generation fixture {FIXTURE.relative_to(ROOT)}")
    pins = load_pins()
    if not arguments.no_build:
        build_image()
    profile = pins["qemu_arm_virt"]
    assert isinstance(profile, dict)

    with tempfile.TemporaryDirectory() as directory:
        receiver = Path(directory) / "receiver.img"
        source = Path(directory) / "source.img"
        build_fixture(receiver, "happy")
        build_fixture(source, "transfer")
        source_before = source.read_bytes()
        receiver_before = receiver.read_bytes()
        transcript = boot(profile, receiver, source)
        check_transcript(transcript)
        # M6.7's central claim, checked from the host: the source is granted
        # `blockRead` and nothing else, and it is byte-identical even though the
        # component read it repeatedly and tried to write it.
        if source.read_bytes() != source_before:
            fail("the read-only source device changed during the transfer")
        # The receiver changed, and only in its BootState slots: the transfer
        # installs a root, and nothing else on that device is its business.
        after = receiver.read_bytes()
        if after == receiver_before:
            fail("the receiver was not written, so nothing was transferred")
        slot_a = (40 + STATE_SLOT_A) * 512
        for name, start, end in (
            ("the GPT and protective MBR", 0, 40 * 512),
            ("the object store region", 40 * 512, slot_a),
            ("the disk beyond the BootState slots", slot_a + 1024, len(after)),
        ):
            if after[start:end] != receiver_before[start:end]:
                fail(f"the transfer modified {name} on the receiver")

    print(
        "seL4 transfer plane check: a generation crossed from a read-only "
        "source device to a writable receiver — manifest digest, object "
        "closure, and travel policy all verified before any write — staged "
        "pending without disturbing the known-good root, and was promoted only "
        "on health confirmation, leaving the source byte-identical"
    )


if __name__ == "__main__":
    main()
