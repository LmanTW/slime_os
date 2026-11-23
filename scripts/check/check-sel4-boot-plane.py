#!/usr/bin/env python3

"""P5.4.9/C8.10 gate: the full C8 graph in one seL4 generation.

The x86 gate (``just data_fabric_boot_check``) proves that every C8 role can
coexist in one boot. This gate boots the ``sel4-boot`` image and proves the same
of ``slime-root``: one generation, all three planes at once, in disjoint slots
with no profile-dependent rewrite, every participant reaching a checked role or
a declared role-less idle, and the supervisor certifying the complete graph.

The healthy record is necessary evidence but not a stopping point (B55): it
fires the instant every declared instance exists as a live task, which is
causally *before* the twenty instances' own provisioning traffic — the record
is printed from the same central dispatch loop that also services every
task's IPC, and the last spawn returning is what satisfies it. Capture
continues until the transcript has gone quiet after the healthy record, which
is the declared end state (every task blocked idle, nothing left to say), and
any component exit anywhere in that window — before or after the healthy
record — poisons the transcript.
"""

from __future__ import annotations

import argparse
import queue as _queue
import re
import shutil
import subprocess
import sys
import threading
import tomllib
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from closure_image import ClosureImageError, build as build_closure_image  # noqa: E402

from harness import GENERATION_COMPOSITIONS, profile_text, profile_integer, sha256_file  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PINS_PATH = ROOT / "sel4" / "pins.toml"
# CP15: the closure identity names the build's inputs and is re-resolved from
# repository state before the build, so stale input is refused rather than
# silently producing a different image.
FIXTURE = GENERATION_COMPOSITIONS / "sel4-boot.zti"
CLOSURE = "sel4-boot"
IMAGE: Path | None = None
BOOT_TIMEOUT_SECONDS = 300
# How long the transcript may go silent after the healthy record before the
# graph is considered settled. Generous relative to how quickly twenty
# instances actually converge (well under a second observed), because a
# QEMU/CI host under load is not this host.
QUIET_SECONDS = 5.0

CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        # C8.10's declarative half: one generation carrying every C8 role, with
        # all five routes and the declared interposition admitted together.
        "one generation admitted every C8 role and route",
        (
            # Twenty instances: `init`, the fabric, its two route workers, and
            # the sixteen participants. Each is declared so the generation can
            # state the capabilities its owner hands it at spawn; only `init`
            # is root-autostart, which the staging line below asserts.
            r"SLIME_ROOT generation admitted number=22 executables=20 instances=20 grants=38 ",
            r"SLIME_ROOT fabric graph=admitted schemas=4 routes=5 participants=15 "
            r"interpositions=1",
            r"SLIME_GRAPH staged task=\d+ instance=init executable=init grants=\d+ bindings=\d+ ",
            r"SLIME_GRAPH staged instances=1 root_autostart=1 ",
            r"SLIME_GRAPH activated instances=1",
            r"\[init\] fabric boot control channels minted",
        ),
    ),
    (
        # The composition, in the order init forces it. Every task's own
        # supervision handle must exist before it can name that task in a
        # spawn grant, and no worker mints its own control endpoints (B55):
        # the generation places every one before any task runs, so the
        # component that grants a worker its participants' supervision
        # handles is whoever spawned those participants — which is init for
        # both workers, not the stream broker for either.
        "init launched the graph in dependency order",
        (
            r"\[init\] fabric boot stream participants spawned",
            r"SLIME_GRAPH spawned task=\d+ child=\d+ component=fabric-service ",
            r"\[init\] fabric boot stream broker spawned",
            r"SLIME_GRAPH spawned task=\d+ child=\d+ component=fabric-call-worker ",
            r"\[init\] fabric boot call plane spawned",
            r"SLIME_GRAPH spawned task=\d+ child=\d+ component=fabric-op-worker ",
            r"\[init\] fabric boot operation plane spawned",
            r"\[init\] fabric boot graph spawned with static endpoints",
        ),
    ),
    (
        # C8.10 required check 3: the probe is its own task, and holding a real
        # control endpoint buys it nothing. Its own request causally precedes
        # the fabric's denial, but both components' `debug_write`s cross the
        # same root-mediated console dispatcher, and the fabric's denial print
        # (already in flight from an earlier syscall) is what the dispatcher
        # services first — deterministically, not by source order within
        # either task. The probe's denial is also the last thing the stream
        # broker's provisioning sweep is waiting on — the declared proxy is
        # pre-marked answered, since it never contacts the broker at all under
        # boot — so the worker's own idle confirmation is this chain's causal
        # tail rather than a chain of its own.
        "the unauthorized probe is a distinct task and is refused",
        (
            r"\[fabric\] ungranted component denied: fabric-probe",
            r"\[fabric-probe\] exact route strings supplied",
            r"\[fabric-probe\] undeclared edge denied",
            r"\[fabric-probe\] done",
            r"\[fabric\] idle: parked on control endpoints",
        ),
    ),
)

# The call and operation planes hold no negotiated role at all (B55): each
# participant's control endpoint *is* its whole authority, a generation-declared
# native Endpoint the root installed at spawn, so there is nothing left to
# request. The gate requires each worker's ready line and each participant's
# idle line.
#
# It requires no order among them. The worker and its participants are separate
# tasks of one priority, and each prints its line when the scheduler runs it. A
# timer tick that ends a time slice moves a line, and where the tick lands
# depends on how fast the host runs QEMU. Fourteen boots of one image printed
# four orders: a ready line after its participants, a ready line after every
# other line here, and two call participants before the operation plane.
EXPECTED_UNORDERED: tuple[str, ...] = (
    r"\[fabric\] call endpoints ready",
    r"\[fabric-call-time\] boot idle without a role",
    r"\[fabric-call-server\] boot idle without a role",
    r"\[fabric-call-client-b\] boot idle without a role",
    r"\[fabric-call-client\] boot idle without a role",
    r"\[fabric\] operation endpoints ready",
    r"\[fabric-op-client-b-restart\] boot idle without a role",
    r"\[fabric-op-time\] boot idle without a role",
    r"\[fabric-op-server\] boot idle without a role",
    r"\[fabric-op-client-b\] boot idle without a role",
    r"\[fabric-op-client\] boot idle without a role",
)

# The supervisor record is required evidence, not certification of
# provisioning: `idle` here is `live` printed a second time, so the record
# means "every declared required instance exists as a live task" — nothing
# about its own userspace convergence (B55). That is exactly why `boot`
# reads past it rather than stopping there. The instance digest is
# deliberately shape-checked rather than pinned: it changes when the
# generation changes. The counts are shape-checked for the same reason:
# pinning `required=1` would assert the pre-migration graph shape rather
# than the property that every declared instance — the stream broker and
# both route workers among them — came up.
TERMINAL_MARKER = (
    r"SLIME_GRAPH healthy generation=\d+ instances=[0-9a-f]+ "
    r"required=(\d+) live=\1 idle=\1 failed=0"
)

FAILURE_MARKERS: tuple[str, ...] = (
    r"SLIME_ROOT FATAL",
    r"SLIME_ROOT FAIL",
    r"SLIME_GRAPH component exit .*status=-?[1-9]\d*",
    r"SLIME_GRAPH wedged waiter",
    r"\[init\] fabric boot fail: .*",
    r"SLIME_GRAPH spawn (?:failed|refused|unwound|unwind incomplete) .*",
    r"SLIME_GRAPH channel (?:recall|rollback) failed .*",
    r"SLIME_GRAPH capability transfer rolled back .*",
    r"SLIME_GRAPH debug write refused .*",
    r"SLIME_GRAPH channel unplaced .*",
    r"<<seL4\(CPU 0\) \[decodeInvocation",
    r"Caught cap fault",
    r"Caught vm fault",
    r"Caught user exception",
    r"panicked at ",
    r"aborted at ",
    r"\(aborted\)",
    r"unhandled",
)

SPAWN_PATTERN = re.compile(
    r"SLIME_GRAPH spawned task=(\d+) child=(\d+) component=([^ ]+) "
    r"grants=(\d+) endpoints=(\d+) notifications=(\d+) handle=(\d+)"
)
EXIT_PATTERN = re.compile(r"SLIME_GRAPH component exit task=(\d+) status=(-?\d+)")
STAGE_PATTERN = re.compile(
    r"SLIME_GRAPH staged task=(\d+) instance=([^ ]+) executable=([^ ]+) "
    r"grants=(\d+) bindings=(\d+) "
)
LAYOUT_HEADER = re.compile(r"\[layout\] path=init slots=(\d+) max=(\d+)")

# The nineteen components init spawns, in the exact order `drive_boot_plane`
# forces: seven stream participants, the stream broker, four call
# participants and their worker, five operation participants and their
# worker. Init spawns every one of them (B55): a worker cannot mint or
# receive its own control endpoints — those are generation-declared and root
# -installed before any task runs — and cannot be handed the supervision
# handles naming its participants unless it is also the party that spawned
# them, so `fabric-service` no longer spawns the two route workers itself.
EXPECTED_INIT_CHILDREN = (
    "fabric-publisher",
    "fabric-subscriber",
    "fabric-publisher-b",
    "fabric-subscriber-b",
    "fabric-observer",
    "fabric-proxy",
    "fabric-probe",
    "fabric-service",
    "fabric-call-client",
    "fabric-call-client-b",
    "fabric-call-server",
    "fabric-call-time",
    "fabric-call-worker",
    "fabric-op-client",
    "fabric-op-client-b",
    "fabric-op-server",
    "fabric-op-time",
    "fabric-op-client-b-restart",
    "fabric-op-worker",
)
# Roles the stream broker actually negotiates and narrows at runtime: the two
# publishers, the two subscribers, and the filtered-introspection client. The
# call and operation planes hold no negotiated role at all — a participant's
# control endpoint there is a direct generation-declared grant, not something
# a broker hands out, so there is nothing for those nine (plus the proxy) to
# request.
EXPECTED_ROLES = 5
EXPECTED_IDLE_WITHOUT_ROLE = (
    "fabric-proxy",
    "fabric-call-client",
    "fabric-call-client-b",
    "fabric-call-server",
    "fabric-call-time",
    "fabric-op-client",
    "fabric-op-client-b",
    "fabric-op-server",
    "fabric-op-time",
    "fabric-op-client-b-restart",
)
# Which of the five checked-role holders actually printed its own
# confirmation, and which server-side edge each of them was provisioned
# against — every entry required, but membership rather than sequence: the
# broker's per-edge print and a participant's own summary print race
# differently depending on whether that participant declares one route or
# two (whichever of client-recv/server-continue the scheduler runs first
# after the rendezvous), so encoding one fixed interleaving as a causal
# chain would assert a scheduling accident rather than a property.
EXPECTED_ROLE_HOLDERS = (
    "fabric-publisher",
    "fabric-subscriber",
    "fabric-publisher-b",
    "fabric-subscriber-b",
    "fabric-observer",
)
EXPECTED_PROVISIONED_EDGES = (
    "[fabric] provisioned fabric-publisher telemetry publish ring",
    "[fabric] provisioned fabric-subscriber telemetry subscribe ring",
    "[fabric] provisioned fabric-publisher-b telemetry publish ring",
    "[fabric] provisioned fabric-publisher-b diagnostics publish ring",
    "[fabric] provisioned fabric-subscriber-b telemetry subscribe ring",
    "[fabric] provisioned fabric-subscriber-b diagnostics subscribe ring",
    "[fabric] provisioned fabric-observer telemetry subscribe ring",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"seL4 boot plane check: {message}")


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


# The most recent boot transcript, whatever its outcome. Set by `boot`.
LAST_TRANSCRIPT = ""


def boot(profile: dict[str, object], *, image: Path | None = None) -> str:
    """Boot the plane image and return the transcript.

    `image` lets a gate that audits this plane's root — the capability-layout
    audit — boot a specific build, including a negative build case's
    deliberately mutated root, without that image ever occupying the path this
    gate's own build produces.
    """
    """Boot until the graph settles, or a failure appears.

    The healthy record is necessary evidence but not a stopping point: it
    fires the instant every declared instance *exists* as a live task, which
    the root confirms in the same central dispatch loop that services every
    task's own IPC. Twenty instances' worth of provisioning back-and-forth —
    role requests, matches, and their answering markers — is scheduled work
    that runs *after* the twentieth spawn returns, not before it, so the
    causal chains below are still incomplete when the healthy line appears
    (B55). Reading stops instead once the serial transcript has gone quiet for
    [`QUIET_SECONDS`] after the healthy record: the declared end state is
    every task blocked idle with no traffic, which is a graph that stops
    producing output, so quiet *is* the observable settled state. A component
    that exits nonzero after the healthy line — which used to be invisible to
    a gate that stopped reading at it — still poisons the transcript, because
    reading continues far enough to see it.
    """
    # Cleared up front so a caller that recovers `LAST_TRANSCRIPT` after a
    # failure cannot read the previous boot's output: every exit path from
    # here on either overwrites it or leaves it empty.
    global LAST_TRANSCRIPT
    LAST_TRANSCRIPT = ""
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
        str(image if image is not None else IMAGE),
    ]
    print(f"[boot] {' '.join(command)}", flush=True)
    failures = re.compile("|".join(FAILURE_MARKERS))
    terminal = re.compile(TERMINAL_MARKER)
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
    watchdog = threading.Timer(BOOT_TIMEOUT_SECONDS, process.kill)
    watchdog.start()
    # A background reader, because the settling wait below needs to give up
    # after a bounded quiet period — and a graph that has genuinely gone
    # silent leaves nothing for a plain blocking `for line in process.stdout`
    # to return, ever, short of the full 300s watchdog. The queue lets the
    # main thread poll with a timeout instead.
    queue: "_queue.Queue[str | None]" = _queue.Queue()

    def pump() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            queue.put(line.rstrip("\r\n"))
        queue.put(None)

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    outcome = "eof"
    failure: str | None = None
    saw_terminal = False
    try:
        while True:
            timeout = QUIET_SECONDS if saw_terminal else None
            try:
                line = queue.get(timeout=timeout)
            except _queue.Empty:
                # Quiet this long after the healthy record is the settled
                # state the boot declares: every task blocked idle, nothing
                # left to say.
                outcome = "terminal"
                break
            if line is None:
                # QEMU's own stdout closed. If the healthy record already
                # appeared this is still a legitimate settle — the process
                # exiting is at least as quiet as a timeout — otherwise it is
                # the pre-existing "process died early" failure.
                outcome = "terminal" if saw_terminal else "eof"
                break
            lines.append(line)
            matched_failure = failures.search(line)
            if matched_failure is not None:
                outcome = "failure"
                failure = matched_failure.group(0)
                break
            if not saw_terminal and terminal.search(line):
                saw_terminal = True
    finally:
        timed_out = not watchdog.is_alive()
        watchdog.cancel()
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        reader.join(timeout=5)
    transcript = "\n".join(lines)
    # Published so a gate that boots this image expecting a refusal can read
    # what the root actually said, rather than only that it failed.
    LAST_TRANSCRIPT = transcript
    if outcome == "failure":
        report_transcript(transcript)
        fail(f"boot stopped at failure marker: {failure!r}")
    if outcome != "terminal":
        report_transcript(transcript)
        if timed_out:
            fail(f"boot exceeded {BOOT_TIMEOUT_SECONDS}s without supervisor certification")
        fail("QEMU exited before the supervisor certified the graph healthy")
    return transcript


def report_transcript(transcript: str) -> None:
    tail = transcript.splitlines()[-60:]
    if tail:
        sys.stdout.write("--- serial transcript (tail) ---\n")
        sys.stdout.write("\n".join(tail) + "\n")
        sys.stdout.write("--- end transcript ---\n")
        sys.stdout.flush()


def check_layout(transcript: str) -> int:
    """Init's table is one collision-free layout, strictly under the ceiling."""
    headers = LAYOUT_HEADER.findall(transcript)
    if len(headers) != 1:
        fail(f"expected exactly one init layout report, saw {len(headers)}")
    used, ceiling = (int(value) for value in headers[0])
    if used >= ceiling:
        fail(f"init's layout uses {used} of {ceiling} slots; it must stay under the ceiling")
    slots = [int(slot) for slot in re.findall(r"\[layout\] (\d+) ", transcript)]
    if len(slots) != used:
        fail(f"the layout reports {used} slots but lists {len(slots)}")
    if len(set(slots)) != len(slots):
        fail("the layout claims a slot twice; the planes are not disjoint")
    return used


def check_root_instances(transcript: str) -> None:
    """Exactly the declared root-owned autostart instance is launched once."""
    stages = STAGE_PATTERN.findall(transcript)
    if len(stages) != 1:
        fail(f"expected exactly one staged root instance, saw {len(stages)}")
    _task, instance, executable, _grants, _bindings = stages[0]
    if instance != "init" or executable != "init":
        fail(
            f"root staged instance={instance!r} executable={executable!r}, expected init/init"
        )
    if len(re.findall(TERMINAL_MARKER, transcript)) != 1:
        fail("expected exactly one healthy supervisor terminal")


def check_composition(transcript: str) -> None:
    """Every declared role is a distinct live task, and none of them exited."""
    spawns = SPAWN_PATTERN.findall(transcript)
    parents = {match[0] for match in spawns}
    if parents != {"0"}:
        fail(f"expected init (task 0) as the sole spawning parent, saw {sorted(parents)}")
    children: dict[str, str] = {}
    child_tasks: set[str] = set()
    order: list[str] = []
    for _parent, child, component, *_ in spawns:
        if child in child_tasks:
            fail(f"child identity {child} was reused by multiple spawns")
        if component in children:
            fail(f"{component} was spawned twice; every executable identity is one task")
        child_tasks.add(child)
        children[component] = child
        order.append(component)
    if tuple(order) != EXPECTED_INIT_CHILDREN:
        fail(f"init spawned {tuple(order)!r}, expected {EXPECTED_INIT_CHILDREN!r}")
    exited = {
        component: task
        for component, task in children.items()
        for exit_task, _ in EXIT_PATTERN.findall(transcript)
        if exit_task == task
    }
    if exited:
        report_transcript(transcript)
        fail(f"composition tasks exited before the graph came to rest: {sorted(exited)}")
    roles = len(re.findall(r"\[fabric[^\]]*\] boot role provisioned", transcript))
    if roles != EXPECTED_ROLES:
        fail(f"{roles} participants took a checked role, expected {EXPECTED_ROLES}")
    for component in EXPECTED_ROLE_HOLDERS:
        if f"[{component}] boot role provisioned" not in transcript:
            fail(f"{component} did not report its checked role")
    for edge in EXPECTED_PROVISIONED_EDGES:
        if edge not in transcript:
            fail(f"missing provisioning evidence: {edge!r}")
    for component in EXPECTED_IDLE_WITHOUT_ROLE:
        if f"[{component}] boot idle without a role" not in transcript:
            fail(f"{component} did not report its declared role-less idle")


def check_transcript(transcript: str) -> None:
    for pattern in FAILURE_MARKERS:
        match = re.search(pattern, transcript)
        if match is not None:
            report_transcript(transcript)
            fail(f"failure marker in serial transcript: {match.group(0)!r}")
    for label, chain in CHAINS:
        position = 0
        for pattern in chain:
            match = re.compile(pattern).search(transcript, position)
            if match is None:
                report_transcript(transcript)
                if re.search(pattern, transcript) is not None:
                    fail(f"{label}: marker out of order: {pattern}")
                fail(f"{label}: missing marker: {pattern}")
            position = match.end()
    for pattern in EXPECTED_UNORDERED:
        if re.search(pattern, transcript) is None:
            report_transcript(transcript)
            fail(f"order-independent marker: missing marker: {pattern}")
    check_root_instances(transcript)
    used = check_layout(transcript)
    check_composition(transcript)
    print(
        f"transcript: {sum(len(chain) for _, chain in CHAINS)} markers observed across "
        f"{len(CHAINS)} causal chains and {len(EXPECTED_UNORDERED)} in no order; "
        f"init's layout used {used} slots; one root instance "
        f"and 19 composition tasks reached {EXPECTED_ROLES} checked roles plus "
        f"{len(EXPECTED_IDLE_WITHOUT_ROLE)} declared idles, and none exited",
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Boot the seL4 full-graph image and assert C8.10"
    )
    # No option skips the build. The closure build reuses an image whose inputs
    # did not change, and without it this gate has no image path to boot.
    parser.parse_args()

    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    if not FIXTURE.is_file():
        fail(f"missing generation fixture {FIXTURE.relative_to(ROOT)}")
    pins = load_pins()
    build_image()
    profile = pins["qemu_arm_virt"]
    assert isinstance(profile, dict)
    check_transcript(boot(profile))
    print(
        "seL4 boot plane check: one generation launched every C8 role at once through "
        "a collision-free layout, the stream broker and both bounded route workers "
        "spawned by init with generation-placed control endpoints, the unauthorized "
        "probe was refused as a distinct task, and the whole graph settled to idle "
        "without any participant exiting"
    )


if __name__ == "__main__":
    main()
