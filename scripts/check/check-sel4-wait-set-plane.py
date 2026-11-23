#!/usr/bin/env python3
"""C9.2 gate: one wake per ready set, recovered from one badge word, in order."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from closure_image import ClosureImageError, build as build_closure_image  # noqa: E402

from harness import GENERATION_COMPOSITIONS, sha256_file  # noqa: E402
from sel4_boot import (  # noqa: E402
    artifact_paths as platform_artifact_paths,
    boot_command,
    run as run_boot,
    verify_identity,
)
from sel4_gate_markers import match_marker_contract  # noqa: E402
from zutai_cli import STDLIB, binary  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PINS = ROOT / "sel4" / "pins.toml"
BUILD_SCRIPT = ROOT / "scripts" / "build" / "build-sel4.py"
FIXTURE = GENERATION_COMPOSITIONS / "sel4-wait-set.zti"
# The closure identity names the build's inputs and is re-resolved from repository
# state before the build, so stale input is refused instead of silently changing the image.
CLOSURE = "sel4-wait-set"
# The closure names this platform, and a closure cannot describe a build for a
# platform it does not name. Every other arm builds by plane flag: no RISC-V
# closure exists for this plane, and pc99's Multiboot2 media has no loader
# image for closure packaging. `--platform` admits these platforms only, so a
# platform with no build route is refused before a boot.
CLOSURE_PLATFORM = "qemu-arm-virt"
FLAG_PLATFORMS = ("qemu-pc99", "qemu-riscv-virt")
IMAGE: Path | None = None
IMAGE_VARIANT = "wait-set"
TIMEOUT = 240


def artifact_paths(platform: str) -> tuple[Path, Path]:
    return platform_artifact_paths("slime-sel4-wait-set", platform)




# The three declared sources, by the badge bit each names and the kind it is
# declared as. Read from the fixture too (`check_fixture_shape`), so a mutation
# that renumbers one fails here rather than passing against whatever it became.
DECLARED_SOURCES = (("stream", 3), ("timer", 9), ("supervision", 17))
# `stream | timer | supervision` as the waiter's registered mask.
EXPECTED_MASK = sum(1 << bit for _, bit in DECLARED_SOURCES)
# How wide the one coalesced wake must be: every declared source except the
# timer, which the probe arms only after that wake is dispatched. Derived from
# the declaration rather than written as a literal, so removing a source or
# converting one to a timer moves this number instead of leaving the assertion
# satisfied by whatever the probe happened to print.
EXPECTED_COALESCED = sum(1 for kind, _ in DECLARED_SOURCES if kind != "timer")

CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "bounded registration and refused ceilings",
        (
            r"SLIME_WAIT sources declared=3 resource=1",
            rf"\[wait-set:waiter\] registered=3 mask=0x{EXPECTED_MASK:x}",
            r"\[wait-set:waiter\] ceilings duplicate=1 undeclared=1 callbacks=1 usable=1",
        ),
    ),
    (
        "every declared source observed through one wait set",
        (
            # The root's death signal is first: the waiter spawns its peer before
            # anything else, so the supervision badge is pending before the
            # coalesced pass that dispatches it.
            r"SLIME_WAIT death task=(\d+) woken=1",
            r"\[wait-set:waiter\] sources stream=1 timer=1 supervision=1 waits=(\d+) wakes=(\d+)",
            r"\[wait-set:waiter\] retired supervision registered=2",
        ),
    ),
    (
        "the peer that signalled the stream source",
        (
            r"\[wait-set:signaller\] message=1 signal=1",
            r"SLIME_GRAPH component exit task=\d+ status=0",
        ),
    ),
    (
        "deny by default",
        (
            r"\[wait-set:denied\] declared=0 badge=-1 slot=-1 timer=-1 queued=0",
            r"SLIME_GRAPH component exit task=\d+ status=0",
        ),
    ),
    (
        "terminal cleanup",
        (
            r"\[init\] wait set plane is root-launched",
            r"SLIME_GRAPH HEALTHY generation=42 required=4 live=0 completed=4 failed=0",
        ),
    ),
)

EXPECTED_UNORDERED: tuple[str, ...] = (
    # The waiter's supervision source is root-installed, so the root's own
    # accounting must agree that exactly one waiter declared one.
    r"SLIME_WAIT supervision task=(\d+) instance=wait-set-waiter sources=1",
    # C9.1's timer authority for the same holder, since the timer source is that
    # badge and nothing else may claim it.
    r"SLIME_CLOCK authority task=(\d+) instance=wait-set-waiter flags=0x8000000 timers=2 badge=0x200",
    # The one coalesced wake carried every non-timer declared source and
    # dispatched exactly those. Both numbers are the probe's live counts read
    # after dispatch, and the width is the fixture's, so this is the property a
    # hand-rolled sweep cannot demonstrate rather than a constant compared to
    # itself.
    rf"\[wait-set:waiter\] wake ready={EXPECTED_COALESCED} dispatched={EXPECTED_COALESCED}",
)

FAILURE_MARKERS: tuple[str, ...] = (
    r"SLIME_ROOT FATAL",
    r"SLIME_WAIT FAIL",
    r"\[wait-set\] FAIL",
    r"SLIME_GRAPH FAIL required instance",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"seL4 wait-set plane check: {message}")


def build_image(platform: str, image_path: Path) -> None:
    global IMAGE
    if platform != CLOSURE_PLATFORM:
        command = [
            sys.executable,
            str(BUILD_SCRIPT),
            "--wait-set-plane",
            "--platform",
            platform,
        ]
        process = subprocess.run(command, cwd=ROOT, check=False)
        if process.returncode != 0:
            fail("image build failed")
        return
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


def boot(manifest: dict[str, object], platform: str, image_path: Path) -> str:
    return run_boot(
        boot_command(manifest, platform=platform, image_path=image_path, fail=fail),
        terminal=re.compile(
            r"SLIME_GRAPH HEALTHY generation=42 required=4 live=0 completed=4 failed=0"
            r"|SLIME_ROOT FATAL|SLIME_WAIT FAIL|\[wait-set\] FAIL"
        ),
        timeout=TIMEOUT,
        fail=fail,
    )


def fixture_manifest() -> dict[str, object]:
    """Decode the exercised source table and notification shape through Zutai."""
    environment = os.environ.copy()
    environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
    process = subprocess.run(
        [str(binary()), "json", str(FIXTURE)],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if process.returncode != 0:
        fail(f"could not decode the fixture: {process.stdout.strip()}")
    return json.loads(process.stdout)


def check_fixture_shape() -> None:
    """The declarations the transcript is read against, from the fixture itself.

    Not a restatement of the probe's output: every number the marker contract
    above pins — the badge bits, the kinds, the mask — is checked here against
    the manifest, so a fixture mutation that renumbers a source fails rather than
    passing against whatever it became.
    """
    manifest = fixture_manifest()
    sources = manifest.get("waitSet") or []
    if not isinstance(sources, list):
        fail("fixture waitSet is not a list")
    waiters = {entry["waiter"] for entry in sources}
    if waiters != {"wait-set-waiter"}:
        fail(f"fixture declares wait-set waiters {sorted(waiters)}, expected one")
    declared = {(entry["kind"], entry["badgeBit"]) for entry in sources}
    if declared != set(DECLARED_SOURCES):
        fail(f"fixture declares sources {sorted(declared)}, expected {sorted(DECLARED_SOURCES)}")
    # Every source is on the one notification the waiter waits on. That is the
    # whole mechanism — one `seL4_Wait`, one badge word — so a fixture spreading
    # them across objects would make the plane assert something else.
    if {entry["notification"] for entry in sources} != {"wait-set-wake"}:
        fail("fixture sources are not all on the waiter's one declared notification")
    timer = next(entry for entry in sources if entry["kind"] == "timer")
    if "drainSlot" in timer:
        fail("fixture timer source declares a drain slot")
    for entry in sources:
        if entry["kind"] != "timer" and "drainSlot" not in entry:
            fail(f"fixture {entry['kind']} source declares no drain slot")
    # The timer badge is C9.1's, so the clock authority must name the same bit.
    clocks = {entry["holder"]: entry for entry in manifest.get("clockAuthority") or []}
    clock = clocks.get("wait-set-waiter")
    if clock is None or clock["timerBadgeBit"] != timer["badgeBit"]:
        fail("fixture timer source does not name the waiter's declared C9.1 badge")
    # And the stream badge is a declared peer's, derived from its own slot.
    stream = next(entry for entry in sources if entry["kind"] == "stream")
    signallers = [
        binding
        for binding in manifest.get("notificationBindings") or []
        if binding["role"] == "signal" and binding["slot"] % 63 == stream["badgeBit"]
    ]
    if len(signallers) != 1:
        fail("fixture stream source is not the badge of exactly one declared signaller")
    instances = {entry["name"] for entry in manifest["instances"]}
    if "wait-set-denied" not in instances or "wait-set-denied" in waiters:
        fail("fixture has no instance omitted from the wait-set declaration")


def check_semantics(transcript: str) -> None:
    """Bind the probe's observations to the root's own accounting."""
    waiter = re.search(
        r"SLIME_WAIT supervision task=(\d+) instance=wait-set-waiter sources=1",
        transcript,
    )
    if waiter is None:
        fail("root installed no supervision source for the waiter")
    waiter_task = waiter.group(1)

    # Exactly one waiter declares a supervision source, and it is that one. A
    # second would mean the resource reached an instance it does not name.
    installs = re.findall(r"SLIME_WAIT supervision task=(\d+) instance=(\S+) sources=", transcript)
    if len(installs) != 1 or installs[0][1] != "wait-set-waiter":
        fail(f"unexpected supervision-source installs: {installs}")

    # The death wake is the root's, and it woke exactly the waiter's one
    # declared source. `woken=1` is the load-bearing number: a supervisor whose
    # slot no longer named the dead task would be `woken=0`, and the badge would
    # never arrive.
    death = re.search(r"SLIME_WAIT death task=(\d+) woken=1", transcript)
    if death is None:
        fail("no peer death was delivered through a declared supervision source")
    if death.group(1) == waiter_task:
        fail("the waiter was woken for its own death")

    # The waiter read its own sources and nothing else did. `WAIT_SOURCES` is
    # self-scoped, so a non-empty answer to any other task would be a disclosure.
    reads = re.findall(
        r"SLIME_WAIT sources task=(\d+) instance=(\S+) cursor=\d+ rows=(\d+)", transcript
    )
    if not reads:
        fail("no component read its declared sources")
    for task, instance, rows in reads:
        if instance != "wait-set-waiter" and int(rows) != 0:
            fail(f"{instance} (task {task}) read {rows} sources it does not declare")
    if not any(instance == "wait-set-waiter" and int(rows) == 3 for _, instance, rows in reads):
        fail("the waiter did not read its three declared sources")

    # Every wake dispatched exactly what it queued, and the widest carried the
    # fixture's own coalesced width. Both numbers the probe prints are live
    # counts read after dispatch, so the equality rules out a queue that
    # silently dropped readiness, and the width is derived from the declaration
    # rather than accepted from the transcript.
    wakes = re.findall(r"\[wait-set:waiter\] wake ready=(\d+) dispatched=(\d+)", transcript)
    if not wakes:
        fail("the waiter reported no wake")
    if any(ready != dispatched for ready, dispatched in wakes):
        fail(f"a wake dispatched fewer sources than it queued: {wakes}")
    widest = max(int(ready) for ready, _ in wakes)
    if widest != EXPECTED_COALESCED:
        fail(
            f"the widest wake carried {widest} ready sources, expected the "
            f"{EXPECTED_COALESCED} the fixture declares outside its timer"
        )

    # Three sources over strictly fewer than three passes. The point of a wait
    # set is that one pass answers for a whole ready set, so a run needing one
    # per source would not have demonstrated it — and because the probe arms the
    # timer only after dispatching the coalesced pair, the count is determined by
    # control flow rather than by scheduling luck.
    totals = re.search(
        r"\[wait-set:waiter\] sources stream=1 timer=1 supervision=1 waits=(\d+) wakes=(\d+)",
        transcript,
    )
    if totals is None:
        fail("the waiter did not observe all three declared sources")
    waits = int(totals.group(1))
    if waits >= len(DECLARED_SOURCES):
        fail(f"three sources took {waits} passes; a wait set must coalesce at least one pair")
    # Every pass is a real wake: the first is the coalesced poll, the rest are
    # blocks. A count below the pass count would mean a pass invented readiness.
    if int(totals.group(2)) < waits:
        fail("the waiter reported fewer wakes than passes")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Boot the seL4 wait-set plane on one pinned QEMU profile"
    )
    parser.add_argument(
        "--platform",
        choices=sorted((CLOSURE_PLATFORM, *FLAG_PLATFORMS)),
        default=CLOSURE_PLATFORM,
    )
    arguments = parser.parse_args()
    check_fixture_shape()
    image_path, manifest_path = artifact_paths(arguments.platform)
    build_image(arguments.platform, image_path)
    if arguments.platform != CLOSURE_PLATFORM:
        manifest = verify_identity(
            manifest_path,
            platform=arguments.platform,
            variant=IMAGE_VARIANT,
            image_path=image_path,
            fail=fail,
        )
    else:
        assert IMAGE is not None
        image_path = IMAGE
        manifest = {}
    transcript = boot(manifest, arguments.platform, image_path)
    match_marker_contract(transcript, CHAINS, FAILURE_MARKERS, fail)
    for pattern in EXPECTED_UNORDERED:
        if re.search(pattern, transcript) is None:
            fail(f"missing order-independent marker: {pattern}")
    check_semantics(transcript)
    print(
        "seL4 wait-set plane check: bounded registration, one-wake badge "
        "demultiplexing, deterministic dispatch, refused ceilings, and "
        f"declared peer-death delivery observed on {arguments.platform}"
    )


if __name__ == "__main__":
    main()
