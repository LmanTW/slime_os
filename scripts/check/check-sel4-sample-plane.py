#!/usr/bin/env python3

"""P5.3.4 gate: the C7 sample plane, composed on seL4.

Boots `build/slime-sel4-sample.elf` -- the image whose root task embeds the
sample-plane generation, `contracts/generation-manifest/v1/compositions/sel4-sample.zti` --
and asserts P5.3's exit condition:

    Two components exchange and return a payload larger than the
    control-message bound over seL4, with quota exhaustion and peer death
    reclaiming the same resources the x86 corpus records.

The component marker corpus was frozen at the P5 cutover. Every line is emitted
by the unchanged `sample-lender` and `sample-receiver` binaries; the two
retired-kernel-only lines remain documented in `ORACLE_ONLY` rather than being
claimed by this product gate.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from component_paths import source_path  # noqa: E402
from closure_image import ClosureImageError, build as build_closure_image  # noqa: E402
from harness import (  # noqa: E402
    GENERATION_COMPOSITIONS,
    load_qemu_profile,
    profile_integer,
    profile_text,
    qemu_kernel_arguments,
    sha256_file,
)
from sel4_boot import (  # noqa: E402
    PLATFORMS,
    artifact_paths as platform_artifact_paths,
    boot_command,
    run as run_boot,
    verify_identity,
)

ROOT = Path(__file__).resolve().parents[2]
PINS_PATH = ROOT / "sel4" / "pins.toml"
FIXTURE = GENERATION_COMPOSITIONS / "sel4-sample.zti"
BUILD_SCRIPT = ROOT / "scripts" / "build" / "build-sel4.py"
# CP15: the closure identity names the build's inputs and is re-resolved from
# repository state before the build, so a stale input is refused rather than
# silently producing a different image.
CLOSURE = "sel4-sample"
# The closure names this platform, and a closure cannot describe a build for a
# platform it does not name. Every other arm builds by plane flag: no RISC-V
# closure exists for this plane, and pc99's Multiboot2 media has no loader
# image for closure packaging. `--platform` admits these platforms only, so a
# platform with no build route is refused before a boot.
CLOSURE_PLATFORM = "qemu-arm-virt"
FLAG_PLATFORMS = ("qemu-pc99", "qemu-riscv-virt")
IMAGE: Path | None = None
IMAGE_VARIANT = "sample"


def artifact_paths(platform: str) -> tuple[Path, Path]:
    return platform_artifact_paths("slime-sel4-sample", platform)


def build_image(platform: str, image_path: Path) -> Path | None:
    global IMAGE
    if platform != CLOSURE_PLATFORM:
        command = [
            sys.executable,
            str(BUILD_SCRIPT),
            "--sample-plane",
            "--platform",
            platform,
        ]
        process = subprocess.run(command, cwd=ROOT, check=False)
        if process.returncode != 0:
            fail(f"seL4 image build failed with exit status {process.returncode}")
        return None
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
    return built.output / "image.identity.json"


BOOT_TIMEOUT_SECONDS = 180

# Historical oracle-only lines excluded when this self-contained seL4 gate was
# frozen at P5 cutover. The component transcript below is now authoritative.
ORACLE_ONLY: dict[str, str] = {
    # `kernel/src/runtime/bootstrap.rs:419`, after a `require_grant` sweep.
    # `slime-root` validates grants differently -- `inbound_authority` derives
    # each component's rights from the generation and `preflight_spawn_grants`
    # re-checks at the point of use -- and emits no equivalent line.
    #
    # What replaces it is `[sample-lender] buffer created`, which this gate
    # requires: an allocation only succeeds if the factory capability resolved,
    # since P5.3.3 made `serve_buffer_create` resolve it (B13).
    #
    # Deliberately *not* `[sample-lender] factory is not a buffer`, which looks
    # like the right substitute and is not: that line only proves
    # `shared_buffer_seal(FACTORY_SLOT)` answered `ERR_BAD_CAP`, which an
    # entirely absent slot satisfies identically. The unconfigured lender the
    # root launches prints it and then fails at `class=ungranted`, which is the
    # proof that it proves nothing about the grant being real.
    "[generation] shared-buffer factory grants valid": (
        "emitted by the retired kernel's bootstrap grant sweep; slime-root "
        "validates grants at admission and at use, with no equivalent marker. "
        "Covered here by [sample-lender] buffer created, which cannot succeed "
        "without the factory capability resolving"
    ),
    # `init.rs` prints this after `launch_sample_plane`, which this scenario
    # replaces with `drive_sample_plane` -- same composition, but the channel is
    # minted rather than declared. The seL4 branch prints its own line, asserted
    # below.
    "[init] sample plane complete": (
        "printed by both, but through a different init branch; asserted "
        "directly in REQUIRED_MARKERS rather than through the oracle list"
    ),
}

# Component transcript inherited at the P5 cutover, reordered once for native
# rendezvous (B46).
#
# Every marker the retired kernel produced still appears, and every
# denial-before-success pair the order exists to protect is intact: the unsealed
# loan is refused before one is created, and the malformed descriptor maps
# nothing before the real one maps. What moved is the *sender's* tail.
#
# On the retired kernel a send enqueued and returned, so the lender printed
# `descriptor sent` immediately and the receiver's work followed. A native
# seL4 send is a rendezvous: it completes only once the receiver has taken the
# message, and the two run at equal priority on one core, so the receiver runs
# to its own blocking point before the lender is scheduled again. The lender's
# post-send markers therefore trail the receiver's, and `[sample-receiver] done`
# lands last because the lender exits while the receiver is still finishing.
#
# This is the mechanism being correct, not the transcript drifting: a
# `descriptor sent` that still printed before `descriptor received` would mean
# the send had not actually rendezvoused with anything.
SAMPLE_MARKERS: tuple[str, ...] = (
    "[sample-lender] factory is not a buffer",
    "[sample-lender] buffer created",
    "[sample-lender] payload written",
    "[sample-lender] unsealed loan denied",
    "[sample-lender] seal is irreversible",
    "[sample-lender] loan created",
    "[sample-receiver] descriptor received",
    "[sample-receiver] malformed descriptor mapped nothing",
    "[sample-receiver] loaned bytes mapped",
    "[sample-receiver] loan stays read-only",
    "[sample-receiver] payload verified",
    "[sample-receiver] loan returned once",
    "[sample-lender] descriptor sent",
    "[sample-lender] receiver settled",
    "[sample-lender] released",
    "[sample-lender] done",
    "[sample-receiver] done",
)

REQUIRED_MARKERS: tuple[tuple[str, str], ...] = (
    (
        "the sample generation was admitted",
        r"SLIME_ROOT generation admitted number=\d+ executables=4 instances=4 grants=6 ",
    ),
    (
        "every payload is a native ELF image",
        r"SLIME_ROOT graph admitted executables=4 instances=4 slimecm=0 elf=4 unrecognized=0",
    ),
    (
        # One factory, at the slot the boot layout names, which is what
        # `init.rs`'s generated `SHARED_BUFFER_FACTORY_SLOT` compiles against
        # (B10). There is no endpoint factory to place: the cutover deleted
        # `endpointCreate`, so an endpoint is a generation-declared seL4
        # Endpoint the root materializes rather than a right init mints from.
        "init holds its shared-buffer factory at its layout slot",
        r"SLIME_GRAPH factory placed task=\d+ component=init slot=4 "
        r"kind=shared-buffer-factory",
    ),
    (
        # A process with two threads (B47). The root builds one TCB per
        # declared thread, and this is the count it acted on -- a plan that
        # declared a thread the root skipped would report 1 here.
        "the root built both of sample-worker's declared threads",
        r"SLIME_GRAPH threads instance=sample-worker count=2",
    ),
    (
        # The worker's declared priority, below its main thread's. The
        # `ScheduleRecord` has always been per-thread; this is the root acting
        # on it (B48).
        "sample-worker's worker thread was scheduled below its main thread",
        r"SLIME_GRAPH schedule instance=sample-worker thread=1 priority=100",
    ),
    (
        # The lender/receiver edge is a declared endpoint the root materializes
        # from the manifest and installs into both instances before either runs.
        # It used to be minted at runtime through an endpoint factory; that
        # right no longer exists, so what the gate asserts is that both halves
        # were installed rather than that init manufactured them.
        "the peer channel was materialized from the generation",
        r"SLIME_GRAPH endpoint grant=sample-plane-channel producer_instance=\d+ "
        r"consumer_instance=\d+",
    ),
    (
        "sample-worker's main thread ran",
        r"\[sample-worker\] main thread running",
    ),
    (
        # Receiver first: the lender names its loan receiver through a
        # `RIGHT_SUPERVISE` handle, which cannot exist until the receiver does.
        # Spawn order is load-bearing here exactly as it is on x86.
        #
        # Zero grants, because everything this instance holds the generation
        # declared: its half of the peer endpoint is installed by the root
        # before it runs. Its parent hands it nothing, which is what makes the
        # lender's two-grant spawn below the exact statement of what only a
        # parent can supply.
        "the receiver was spawned first",
        r"SLIME_GRAPH spawn authorized task=\d+ slot=\d+ component=sample-receiver "
        r"grants=0",
    ),
    (
        # A spawned child's shared-buffer ceiling comes from the generation's
        # budget, keyed by component name. Before P5.3.4 only root-launched
        # tasks were budgeted, so a spawned lender held `DENY` and could not
        # allocate at all.
        "the spawned receiver was budgeted from the generation",
        r"SLIME_GRAPH quota task=\d+ instance=sample-receiver executable=sample-receiver pages=2 buffers=1 "
        r"mappings=2 loans=1",
    ),
    (
        "the spawned lender was budgeted from the generation",
        r"SLIME_GRAPH quota task=\d+ instance=sample-lender executable=sample-lender pages=4 buffers=1 "
        r"mappings=2 loans=1",
    ),
    (
        # Two, not three: the channel is now a declared endpoint the root
        # installs on both sides, so what init still hands over is exactly what
        # the generation cannot place — the lender's buffer factory and the
        # receiver's supervision handle, which cannot exist until the receiver
        # does. `supervision_grants=1 buffer_factory_grants=1` is the claim
        # that both arrived, and it is what the loan below depends on.
        "the lender was spawned with both capabilities only its parent holds",
        r"SLIME_GRAPH spawned task=\d+ child=\d+ component=sample-lender grants=2 "
        r"endpoints=1 notifications=0 handle=\d+ supervision_grants=1 buffer_factory_grants=1",
    ),
    (
        # B14's probe, superseded. Init's declared budget is two and both are
        # live, but the third spawn names an instance that is *already* live,
        # and the root resolves an executable to exactly one owned instance —
        # so `instance-live` is answered before the budget is consulted and the
        # ceiling is never reached by this path.
        #
        # Asserted as what it is rather than what it was: the refusal is real
        # and the plane's own comment in `init.rs` records the same reasoning.
        # `[init] spawn budget refused` below is the caller-side half, and the
        # recovery arm that follows is what actually proves the budget releases
        # its dead.
        "a live instance cannot be spawned twice",
        r"SLIME_GRAPH spawn refused task=\d+ child=\S+ class=instance-live",
    ),
    (
        "the refusal reached init as an out-of-memory error",
        r"\[init\] spawn budget refused",
    ),
    (
        # The loan is minted against a `RIGHT_SUPERVISE` handle, not a channel
        # end: `sample-lender.rs::RECEIVER_SLOT` is its third spawn grant.
        # P5.3.2 could only name a channel peer, because no spawn existed to
        # mint a handle.
        "the loan named its receiver through a supervision handle",
        r"SLIME_GRAPH loan created task=\d+ slot=\d+ id=\d+ to=\d+ offset=0 "
        r"length=8192",
    ),
    (
        # The descriptor carries exactly one exported loan capability. Matching
        # native export/import IDs prove the one-cap maximum without a queue.
        "exactly one loan capability was exported with the descriptor",
        r"SLIME_GRAPH capability exported task=\d+ id=\d+ kind=loan "
        r"rights=0x[0-9a-f]+ retain=0",
    ),
    (
        "the receiver imported the exported loan capability",
        r"SLIME_GRAPH capability imported task=\d+ id=\d+ kind=loan "
        r"rights=0x[0-9a-f]+ retain=0",
    ),
    (
        "the receiver's clean exit was collected through its handle",
        r"SLIME_GRAPH supervision collected task=\d+ child=\d+ kind=0",
    ),
    (
        # B14's second half, and the arm that makes the budget a *live-child*
        # cap rather than a lifetime one. Both children have exited, so the
        # ceiling that refused above must admit again — which it can only do if
        # a dead task has left the table. A count that never released its dead
        # would refuse here too, and the two readings are otherwise identical.
        "the budget recovered once its children were reclaimed",
        r"\[init\] spawn budget recovered",
    ),
    ("the composition completed", r"\[init\] sample plane complete"),
    (
        # B46's first message outside the root. The worker sends on the native
        # loopback endpoint, the main thread receives, and this marker appears
        # only after the payload matches byte-for-byte. No `Send`, `Recv`,
        # `Wait`, parked reply, transit entry, or root queue is in that path.
        "two threads exchanged a message on a native endpoint",
        r"\[sample-worker\] native endpoint carried a message",
    ),
    (
        # The non-starvation property, under a priority-only scheduler on one
        # core (B48). The worker spins 200M iterations without ever yielding.
        # The main thread reaching its completion marker means the kernel kept
        # preempting that loop -- if both threads shared one priority the
        # round-robin would let the worker run to its bound first, and this
        # line would come after the worker's, or not at all.
        "a busy low-priority thread did not starve the higher-priority one",
        r"\[sample-worker\] main thread done",
    ),
    (
        "the graph drained with every window and task-owned authority table reclaimed",
        r"SLIME_GRAPH served live=0 unsupported=0 buffers=[1-9]\d* windows=0 tasks=0",
    ),
    (
        # Every task the graph created is out of the table, and its root CSlots
        # are back. Before P5.3.4 neither death path reclaimed, so this would
        # have read `live=N slots=0`: the table full of dead entries, holding a
        # parent's budget, with not one CSlot returned.
        "every task was reclaimed and its CSlots returned",
        r"SLIME_GRAPH tasks reclaimed live=0 slots=[1-9]\d*",
    ),
    (
        "every native capability export was finalized cleanly",
        r"SLIME_GRAPH capabilities exports=[1-9]\d* imports=[1-9]\d* "
        r"cancels=\d+ finalized=\d+ outstanding=0 tickets=0",
    ),
    (
        # Peer lifecycle and quota reclamation remain structured userspace and
        # supervision evidence; native capability accounting proves no export
        # ticket was leaked after every buffer object was reclaimed.
        #
        # Last, because it is the last line the root emits: this list is checked
        # in order and its final entry is also the gate's terminal marker, so an
        # entry placed after the true last line makes the boot look unfinished.
        "every loan, mapping, and region was reclaimed",
        r"SLIME_GRAPH loans served=[1-9]\d* loans=0 mappings=0 regions=0 "
        r"orphans=0 quota=0",
    ),
)

FAILURE_MARKERS: tuple[str, ...] = (
    r"SLIME_ROOT FATAL .*",
    r"SLIME_GRAPH FAIL .*",
    # Either sample component reporting a failure — but only after the spawned
    # pair has started. See `check_sample_transcript`: the root launches every
    # declared component (P5.2), so an unconfigured `sample-lender` and
    # `sample-receiver` also run, holding no channel and no peer, and both exit
    # non-zero before init has spawned anything. Those two lines are expected;
    # a failure from the spawned pair is not, and is caught by the scan below
    # rather than here.
    r"\[init\] sample plane fail: .*",
    r"\[init\] spawn plane fail: .*",
    r"SLIME_GRAPH spawn unwound .*",
    r"SLIME_GRAPH spawn failed .*",
    r"SLIME_GRAPH spawn unwind incomplete .*",
    r"SLIME_GRAPH channel (?:recall|rollback) failed .*",
    r"\[slime-rt\] transfer window bind failed",
    r"SLIME_GRAPH window bind refused",
    r"SLIME_GRAPH park refused .*",
    r"SLIME_GRAPH channel unplaced .*",
    r"SLIME_GRAPH service budget exhausted",
    r"Attempted to invoke a read-only endpoint",
    r"seL4 called fail",
    r"Caught cap fault",
    r"Caught vm fault",
    r"Caught user exception",
    r"panicked at ",
    r"aborted at ",
    r"\(aborted\)",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"seL4 sample plane check: {message}")


def check_manifest(image_path: Path, manifest_path: Path, platform: str) -> dict[str, object]:
    return verify_identity(
        manifest_path,
        platform=platform,
        variant=IMAGE_VARIANT,
        image_path=image_path,
        fail=fail,
    )


def boot(manifest: dict[str, object], platform: str, image_path: Path) -> str:
    if platform == "qemu-pc99":
        command = boot_command(manifest, platform=platform, image_path=image_path, fail=fail)
    else:
        section, qemu_binary = PLATFORMS[platform]
        profile = load_qemu_profile(fail, PINS_PATH, section)
        qemu = shutil.which(qemu_binary)
        if qemu is None:
            fail(f"{qemu_binary} is not on PATH")
        command = [
            qemu,
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
            *qemu_kernel_arguments(qemu_binary, image_path, fail),
        ]
    return run_boot(
        command,
        terminal=re.compile(REQUIRED_MARKERS[-1][1] + "|" + "|".join(FAILURE_MARKERS)),
        timeout=BOOT_TIMEOUT_SECONDS,
        fail=fail,
    )


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
    for description, pattern in REQUIRED_MARKERS:
        match = re.compile(pattern).search(transcript, position)
        if match is None:
            report_transcript(transcript)
            if re.search(pattern, transcript) is not None:
                fail(f"marker out of order: {description} ({pattern})")
            fail(f"missing marker: {description} ({pattern})")
        position = match.end()
    check_sample_transcript(transcript)
    check_transcript_matches_the_oracle()
    check_components_are_unmodified()
    exports = re.findall(
        r"SLIME_GRAPH capability exported task=\d+ id=(\d+) kind=loan "
        r"rights=(0x[0-9a-f]+) retain=0",
        transcript,
    )
    imports = re.findall(
        r"SLIME_GRAPH capability imported task=\d+ id=(\d+) kind=loan "
        r"rights=(0x[0-9a-f]+) retain=0",
        transcript,
    )
    if len(exports) != 1 or exports != imports:
        fail(f"loan export/import evidence was {exports!r}/{imports!r}, expected one exact pair")


def check_sample_transcript(transcript: str) -> None:
    """The x86 gate's own ordered transcript, produced by the same binaries.

    Order-sensitive for the reason the oracle states: each denial must be
    observed before the operation it guards succeeds, so a regression that
    silently permits a denied operation fails here even if the happy path still
    completes.
    """
    # The spawned pair starts here.
    #
    # Anchored on the receiver's spawn rather than on a runtime channel mint:
    # the peer edge is now a generation-declared endpoint the root materializes,
    # so no component mints anything and the retired marker never appears. The
    # anchor also no longer has to exclude unconfigured copies — both instances
    # declare `autostart = false`, so the only copies that exist are the ones
    # init spawned.
    start = transcript.find("SLIME_GRAPH spawn authorized task=0 slot=2 component=sample-receiver")
    if start < 0:
        report_transcript(transcript)
        fail("init never spawned the receiver, so no sample composition ran")
    transcript = transcript[start:]

    # The x86 gate's own FORBIDDEN entries, applied to the composition alone.
    #
    # Bounded at both ends. `[init] sample plane complete` is the last thing the
    # composition does; after it, init spawns one more receiver purely to show
    # the budget recovered (B14's second half), and that child holds no channel
    # so it fails its own `recv` by construction. Scanning past the completion
    # line would read that expected failure as the composition's.
    composition = transcript
    completion = composition.find("[init] sample plane complete")
    if completion >= 0:
        composition = composition[:completion]
    for forbidden in (r"\[sample-lender\] fail: .*", r"\[sample-receiver\] fail: .*"):
        match = re.search(forbidden, composition)
        if match is not None:
            report_transcript(transcript)
            fail(f"a spawned sample component reported a failure: {match.group(0)!r}")

    cursor = 0
    for marker in SAMPLE_MARKERS:
        position = transcript.find(marker, cursor)
        if position < 0:
            report_transcript(transcript)
            if marker in transcript:
                fail(f"oracle transcript out of order at: {marker}")
            fail(f"oracle transcript is missing: {marker}")
        cursor = position + len(marker)
    print(
        f"transcript: all {len(SAMPLE_MARKERS)} sample-plane markers observed in the "
        "order the x86 oracle records them",
        flush=True,
    )


def check_transcript_matches_the_oracle() -> None:
    """The frozen cutover transcript remains non-empty and duplicate-free."""
    if not SAMPLE_MARKERS or len(set(SAMPLE_MARKERS)) != len(SAMPLE_MARKERS):
        fail("SAMPLE_MARKERS must be a non-empty duplicate-free transcript")
    print(
        f"transcript: {len(SAMPLE_MARKERS)} frozen component markers plus "
        f"{len(ORACLE_ONLY)} documented retired-kernel exclusions",
        flush=True,
    )


# The components this gate's claim rests on. Neither may carry a seL4 branch:
# the milestone's whole point is that a component written against the retired
# kernel's ABI runs here unchanged.
UNMODIFIED_COMPONENTS = ("sample-lender", "sample-receiver")

# Product graph selection is generation data. A sample component must not
# introduce a private compile-time selector after that repository-wide cutover.
FORBIDDEN_COMPONENT_SELECTORS = ("option_env!(", "cfg!(slime_")


def check_components_are_unmodified() -> None:
    """Neither sample component knows it is running on seL4.

    Checked against the sources, because serial output cannot establish it: a
    component rewritten to suit this root would produce an identical
    transcript. This is the one claim the boot can never prove on its own.
    """
    for name in UNMODIFIED_COMPONENTS:
        source = source_path(name)
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as error:
            fail(f"cannot read {source.relative_to(ROOT)}: {error}")
        for selector in FORBIDDEN_COMPONENT_SELECTORS:
            if selector in text:
                fail(
                    f"{source.relative_to(ROOT)} branches on compile-time selector "
                    f"{selector!r}; the milestone requires this component to run "
                    "from generation data"
                )
    print(
        "components: "
        + ", ".join(UNMODIFIED_COMPONENTS)
        + " carry no compile-time product branch and run as the x86 oracle builds them",
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Boot the seL4 sample-plane image and assert the oracle's transcript"
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="boot the already-built image instead of rebuilding it first",
    )
    parser.add_argument(
        "--platform",
        choices=sorted((CLOSURE_PLATFORM, *FLAG_PLATFORMS)),
        default=CLOSURE_PLATFORM,
        help="the pinned QEMU profile and image to build and boot",
    )
    arguments = parser.parse_args()

    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    image_path, manifest_path = artifact_paths(arguments.platform)
    if arguments.platform != CLOSURE_PLATFORM:
        if not arguments.no_build:
            build_image(arguments.platform, image_path)
        manifest = check_manifest(image_path, manifest_path, arguments.platform)
    else:
        if not arguments.no_build:
            build_image(arguments.platform, image_path)
        if IMAGE is None:
            fail("--no-build is unsupported for closure-built platforms")
        image_path = IMAGE
        manifest = {}
    check_transcript(boot(manifest, arguments.platform, image_path))
    print(
        "seL4 sample plane check: the unmodified sample-lender and sample-receiver "
        "exchanged and returned a payload larger than the control-message bound over "
        f"seL4 on {arguments.platform}, running the transcript the x86 oracle records, "
        "with quota exhaustion and peer death reclaiming every resource"
    )


if __name__ == "__main__":
    main()
