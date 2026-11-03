#!/usr/bin/env python3

"""B10 on seL4: init's resolved capability layout, per plane, against fixtures.

The boot layout is a contract between three readers -- the root task that fills
init's capability table, the component images that address slots by number, and
the gates that assert on what those components do. Nothing else fails when the
three disagree: a component reads whatever landed at the number it compiled
against, and the symptom surfaces as unrelated behaviour somewhere downstream.

`just boot_layout_check` freezes that layout for nineteen x86 profiles by
booting the retired kernel and diffing its `[layout]` block against a recorded
fixture. No seL4 equivalent existed. P5.4.1's inventory recorded B10 as covered
only *obliquely* on this side -- three gates assert specific slot numbers in
passing (`slot=0 kind=endpoint-factory`, `slot=4 component=sysinfo`) -- which
catches a layout that moved *those* slots and nothing else.

This gate closes that. `slime-root` now emits the same `[layout]` block the
oracle does, and every seL4 plane's is frozen here, so a layout change is a
reviewable diff rather than a silent renumbering.

# Why every plane rather than one

Each plane boots a different generation, and `layout_for` prunes the base table
by which components that generation declares. The pruning is the interesting
part -- it renumbers -- so freezing one plane would leave every other
composition unguarded against exactly the change most likely to break it.

# Relationship to the boot itself

This is a *layout* gate, not a behaviour one: it boots each image and reads one
block. The planes' own gates assert what their components do. Kept separate for
the reason `boot_layout_check` is separate on x86 -- a layout diff should be
readable as a layout diff, not inferred from a component failing.

Regenerate with `--bless`; the resulting diff is the evidence that a layout
change was intended.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import threading
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from closure_image import ClosureImageError, build as build_closure_image  # noqa: E402
from harness import load_qemu_profile, profile_integer, profile_text, qemu_kernel_arguments  # noqa: E402
from sel4_boot import (  # noqa: E402
    PLATFORMS,
    artifact_paths,
    boot_command,
    verify_identity,
)

ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / "scripts" / "build" / "build-sel4.py"
PINS_PATH = ROOT / "sel4" / "pins.toml"
FIXTURES = ROOT / "contracts" / "boot-layout" / "v1" / "fixtures"

BOOT_TIMEOUT_SECONDS = 180

# Every seL4 plane, by the image it produces. The fixture stem is prefixed
# `sel4-` so these sort beside the x86 ones without colliding: `default.layout`
# is the oracle's, `sel4.layout` this root's for the component-graph
# generation.
#
# `fixture` (P5.1) is absent deliberately: it embeds the retained x86 generation
# and launches no component graph, so it has no init and emits no block.
PLANES: tuple[tuple[str, str], ...] = (
    ("sel4", "slime-sel4-graph.elf"),
    # RP2's demo-scoped slice: the only generation declaring the product graph,
    # the C7 data-path pair, and the C8 fabric six in one layout.
    ("sel4-demo", "slime-sel4-demo.elf"),
    ("sel4-channel", "slime-sel4-channel.elf"),
    ("sel4-loan", "slime-sel4-loan.elf"),
    ("sel4-spawn", "slime-sel4-spawn.elf"),
    ("sel4-sample", "slime-sel4-sample.elf"),
    ("sel4-stream", "slime-sel4-stream.elf"),
    ("sel4-qos", "slime-sel4-qos.elf"),
    ("sel4-supervision", "slime-sel4-supervision.elf"),
    ("sel4-crossing", "slime-sel4-crossing.elf"),
    # P5.4.6. The layout is emitted between channel materialization and
    # activation, so it is complete and observable well before any scenario
    # outcome. What this guards is exactly what B10 exists for — that the table
    # `SEL4_CALL_LAYOUT` declares is the table the root fills.
    ("sel4-call", "slime-sel4-call.elf"),
    # P5.4.7, on the same rule. Six executables: the operation graph declares a
    # restart replacement as its own identity.
    ("sel4-operation", "slime-sel4-operation.elf"),
    # P5.4.8, on the same rule. Six executables, the stream set with
    # `fabric-intruder` as the declared proxy rather than an unauthorized probe.
    ("sel4-visibility", "slime-sel4-visibility.elf"),
    # C8.12. Nine rows: init's eight child executables plus its own buffer
    # factory, in one disjoint layout. The ungranted probe and the declared
    # proxy are distinct rows, which is the half of C8.12 a layout can state.
    ("sel4-matrix", "slime-sel4-matrix.elf"),
    # P5.4.9. Twenty-one rows: every C8 role's executable in disjoint slots,
    # which is the half of C8.10 a boot layout can state.
    ("sel4-boot", "slime-sel4-boot.elf"),
    # P5.4.2c. Two rows: init holds an endpoint factory and the probe's
    # executable. The block capability is *not* here — it is granted to the
    # probe, so the root places it in the probe's own table.
    ("sel4-storage", "slime-sel4-storage.elf"),
    # Generation 24, the store plane. Same two rows and the same reason: the
    # block capability is the probe's, not init's.
    ("sel4-store", "slime-sel4-store.elf"),
    ("sel4-rollback", "slime-sel4-rollback.elf"),
    ("sel4-recovery", "slime-sel4-recovery.elf"),
    ("sel4-generation", "slime-sel4-generation.elf"),
    ("sel4-directory", "slime-sel4-directory.elf"),
    ("sel4-filesystem", "slime-sel4-filesystem.elf"),
    ("sel4-input", "slime-sel4-input.elf"),
    ("sel4-powerbox", "slime-sel4-powerbox.elf"),
    ("sel4-transfer", "slime-sel4-transfer.elf"),
    # C9.1. Init holds the one probe executable and no clock authority slot:
    # clock operations use the already-reserved badged root-service endpoint.
    ("sel4-clock-authority", "slime-sel4-clock-authority.elf"),
    # C9.2. Init holds nothing either: the waiter resolves its own wake
    # notification through CP2 and spawns the peer it supervises, because a
    # supervision source must name a handle its own holder obtained.
    ("sel4-wait-set", "slime-sel4-wait-set.elf"),
    ("sel4-scheduling-class", "slime-sel4-scheduling-class.elf"),
    ("sel4-lifecycle-restart", "slime-sel4-lifecycle-restart.elf"),
    # C9.5. Init holds nothing here either: the recorder and replayer hold their
    # declared endpoint and factory directly, on the same rule as the two planes
    # above.
    ("sel4-replay", "slime-sel4-replay.elf"),
    # C9.6. Init holds seven executables and its own factory here, and nothing
    # else: every participant including both brokers is root-autostart, and the
    # one spawn in the plane is the supervisor's over the controller it restarts.
    ("sel4-robot-runtime", "slime-sel4-robot-runtime.elf"),
    # IO8. The product graph plus the pwm driver: init holds one more
    # executable, the driver its endpoint, device, and region, and slisp the
    # driver's endpoint at slot 3. QEMU has no PWM block, so this gate is also
    # where the plane's boot is observed at all.
    ("sel4-pwm", "slime-sel4-pwm.elf"),
    # IO9. The product graph plus the serial driver and the heartbeat producer:
    # init holds two more executables and signals the producer's tick; the
    # driver holds its endpoint, device, and region, the producer the endpoint.
    ("sel4-mavlink", "slime-sel4-mavlink.elf"),
    # The Zenoh Profile 0 demo. Init holds nothing: both nodes and the network service are
    # root-autostart and every grant is between them, so the block states that init's own table is
    # empty rather than listing authority the nodes hold.
    ("sel4-zenoh", "slime-sel4-zenoh.elf"),
    # The same demo with its publisher dialling a stock peer through a virtio NIC. Init holds nothing
    # here either: the nodes, the network service and the driver are all root-autostart.
    ("sel4-zenoh-external", "slime-sel4-zenoh-external.elf"),
    # The shared Zenoh service with its two holders and a peer. Init holds only the two buffer factories.
    ("sel4-zenoh-service", "slime-sel4-zenoh-service.elf"),
)

# The subset P6.4 replays on x86-64: the resident product graph plus the two
# corpus planes that milestone builds for this platform. Deliberately not the
# whole table — a plane whose generation this platform does not build would
# fail here for a build reason rather than a layout one, and the planes it does
# not yet build are owned by later milestones.
#
# Each fixture is architecture-qualified (`x86_64/<stem>.layout`) and recorded
# separately even though the observed x86-64 blocks are currently byte-identical
# to the AArch64 ones. That identity is the *result* this gate exists to
# observe — init's resolved capability layout is architecture-neutral — not a
# reason to share one file. Blessing both architectures into one name would let
# whichever ran last overwrite the other's evidence, and a future divergence
# would then be invisible rather than a failure.
X86_64_PLANES: frozenset[str] = frozenset({"sel4", "sel4-sample", "sel4-wait-set"})


def fail(message: str) -> NoReturn:
    raise SystemExit(f"seL4 boot layout check: {message}")


PC99_FLAGS = {
    "sel4": "--component-graph",
    "sel4-sample": "--sample-plane",
    "sel4-wait-set": "--wait-set-plane",
}


def build(name: str, platform: str) -> Path:
    """Build by closure identity on main's lane and directly for Multiboot2 pc99."""
    if platform == "qemu-pc99":
        # pc99 has no loader image, so closure packaging cannot yet represent it.
        command = [
            sys.executable,
            str(BUILD_SCRIPT),
            PC99_FLAGS[name],
            "--platform",
            platform,
            "--skip-pin-check",
        ]
        process = subprocess.run(command, cwd=ROOT, check=False)
        if process.returncode != 0:
            fail(f"image build failed for {PC99_FLAGS[name]}")
        return artifact_paths(Path(dict(PLANES)[name]).stem, platform)[0]
    try:
        return build_closure_image(name).image
    except ClosureImageError as error:
        fail(str(error))


def capture(name: str, image: Path, platform: str, manifest_path: Path) -> str:
    """Boot one image and return its `[layout]` block."""
    if platform == "qemu-pc99":
        manifest = verify_identity(
            manifest_path,
            platform=platform,
            variant=None,
            image_path=image,
            fail=fail,
        )
        command = boot_command(manifest, platform=platform, image_path=image, fail=fail)
    else:
        section, qemu_binary = PLATFORMS[platform]
        profile = load_qemu_profile(fail, PINS_PATH, section)
        command = [
            qemu_binary,
            "-machine",
            profile_text(profile, "machine", fail, section),
            "-cpu",
            profile_text(profile, "cpu", fail, section),
            "-smp",
            str(profile_integer(profile, "cpus", fail, section)),
            "-m",
            f"size={profile_integer(profile, 'memory_mib', fail, section)}M",
            "-nographic",
            "-serial",
            "mon:stdio",
            *qemu_kernel_arguments(qemu_binary, image, fail),
        ]
    lines: list[str] = []
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
    # The block is emitted before activation, so the boot is stopped as soon as
    # it closes rather than run to completion: this gate reads a layout, and the
    # planes' own gates own their behaviour.
    watchdog = threading.Timer(BOOT_TIMEOUT_SECONDS, process.kill)
    watchdog.start()
    try:
        assert process.stdout is not None
        for line in process.stdout:
            stripped = line.strip()
            lines.append(stripped)
            if stripped == "[layout] end":
                break
    finally:
        watchdog.cancel()
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith("[layout] path="))
        end = next(i for i, line in enumerate(lines[start:], start) if line == "[layout] end")
    except StopIteration:
        sys.stdout.write("\n".join(lines[-40:]) + "\n")
        fail(f"{name}: boot emitted no complete layout block")
    return "\n".join(lines[start : end + 1]) + "\n"


# Every line a layout block may carry. Anchored so a malformed line is a
# failure rather than something the diff silently accepts.
#
# The optional `declared=` tail is B26's: a bootstrap row whose *layout* rights
# differ from the *grant* rights installed at that slot reports both, because
# the two are related by containment rather than equality and a row carrying
# only the installed value cannot show a layout that declares more authority
# than anything uses. Three fixtures carry such a row today — `sel4-loan`,
# `sel4-sample`, and `sel4-stream`, each on its shared-buffer-factory. Every
# other row keeps the retired kernel's exact four fields, so the two dumps stay
# comparable slot for slot.
HEADER = re.compile(r"^\[layout\] path=\S+ slots=\d+ max=\d+$")
ENTRY = re.compile(
    r"^\[layout\] \d+ [a-z-]+ \S+ 0x[0-9a-f]+( declared=0x[0-9a-f]+)?$"
)


def check_shape(name: str, block: str) -> None:
    """The block is well formed and its declared count matches its rows."""
    lines = block.splitlines()
    # Independently total rather than depending on `capture`'s StopIteration
    # path thirty lines away: a block too short to index is a malformed block.
    if len(lines) < 2:
        fail(f"{name}: layout block has no header and terminator")
    if not HEADER.match(lines[0]):
        fail(f"{name}: malformed header {lines[0]!r}")
    if lines[-1] != "[layout] end":
        fail(f"{name}: block does not end with the terminator")
    rows = lines[1:-1]
    for row in rows:
        if not ENTRY.match(row):
            fail(f"{name}: malformed entry {row!r}")
    declared = int(lines[0].rsplit("slots=", 1)[1].split()[0])
    if declared != len(rows):
        fail(f"{name}: header declares {declared} slots, block carries {len(rows)}")
    # Slot numbers strictly ascending: the layout is an ordered table, and a
    # repeated or out-of-order number would mean two grants resolved to one
    # slot -- exactly the collision B10 exists to make visible.
    numbers = [int(row.split()[1]) for row in rows]
    if numbers != sorted(set(numbers)):
        fail(f"{name}: slot numbers are not strictly ascending: {numbers}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze each seL4 plane's boot layout")
    parser.add_argument(
        "--bless",
        action="store_true",
        help="rewrite the fixtures from the observed layouts",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="boot the already-built images instead of rebuilding each first",
    )
    parser.add_argument(
        "--platform",
        choices=sorted(PLATFORMS),
        default="qemu-arm-virt",
        help="the pinned QEMU profile whose layouts are frozen",
    )
    arguments = parser.parse_args()

    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")

    # AArch64 keeps the original flat fixture names so its frozen evidence is
    # untouched; every other architecture records under its own directory.
    fixtures = FIXTURES if arguments.platform == "qemu-arm-virt" else FIXTURES / "x86_64"
    planes = [
        plane
        for plane in PLANES
        if arguments.platform == "qemu-arm-virt" or plane[0] in X86_64_PLANES
    ]
    if not planes:
        fail(f"no boot-layout planes are declared for {arguments.platform}")

    failures: list[str] = []
    for name, image_name in planes:
        if arguments.no_build:
            image, manifest_path = artifact_paths(Path(image_name).stem, arguments.platform)
        else:
            image = build(name, arguments.platform)
            manifest_path = artifact_paths(Path(image_name).stem, arguments.platform)[1]
        # The Multiboot2 route packages no single image: the bootloader supplies
        # the kernel and root task as separate modules from the EFI tree, and
        # `verify_identity` recomputes that tree's digests instead. Requiring a
        # packaged ELF here would fail a boot route that correctly has none.
        if arguments.platform == "qemu-pc99":
            if not manifest_path.is_file():
                fail(f"{name}: missing identity manifest for {arguments.platform}")
        elif not image.is_file():
            fail(f"{name}: missing image for {arguments.platform}")
        observed = capture(name, image, arguments.platform, manifest_path)
        check_shape(name, observed)
        fixtures.mkdir(parents=True, exist_ok=True)
        fixture = fixtures / f"{name}.layout"
        if arguments.bless:
            fixture.write_text(observed)
            print(f"blessed {name}: {len(observed.splitlines()) - 2} slots")
            continue
        if not fixture.exists():
            failures.append(f"{name}: no fixture; run with --bless to record it")
            continue
        expected = fixture.read_text()
        if observed == expected:
            print(f"{name}: {len(observed.splitlines()) - 2} slots match")
            continue
        failures.append(f"{name}: layout differs from {fixture.relative_to(ROOT)}")
        expected_lines = expected.splitlines()
        observed_lines = observed.splitlines()
        for index in range(max(len(expected_lines), len(observed_lines))):
            was = expected_lines[index] if index < len(expected_lines) else "<absent>"
            now = observed_lines[index] if index < len(observed_lines) else "<absent>"
            if was != now:
                failures.append(f"    was: {was}")
                failures.append(f"    now: {now}")

    if failures:
        for line in failures:
            print(line)
        raise SystemExit("seL4 boot layout check: layouts moved")
    if arguments.bless:
        print("seL4 boot layout check: blessed")
        return
    print(f"seL4 boot layout check: {len(planes)} plane layouts match their fixtures")


if __name__ == "__main__":
    main()
