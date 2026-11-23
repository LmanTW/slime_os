#!/usr/bin/env python3

"""P5.3.2 gate: a loan crosses between components on seL4, against quotas the
generation declared.

Boots `build/slime-sel4-loan.elf` -- the image whose root task embeds the
loan-plane generation, `contracts/generation-manifest/v1/compositions/sel4-loan.zti` -- and
asserts ordered markers for each half of P5.3.2's exit condition:

1. a component loans a sealed subrange to a receiver named by capability, and
   the receiver maps it read-only and returns it exactly once;
2. each of the four quota classes fails at ceiling+1 against limits decoded
   from the generation, without disturbing an unrelated holder.

The receiver is `sample-receiver`, unmodified: the same binary the x86 oracle's
`just sample_plane_live_check` runs. That it needs no change is the load-bearing
claim -- a component written against the retired kernel's loan ABI runs on seL4
because the ABI is the same one, not because the scenario was rewritten to suit
whatever the root task happened to implement.

Modelled on `check-sel4-channel-plane.py`, which guards P5.3.1 against a
different image. The four seL4 images are separate artifacts on purpose: each
gate boots the one it asserts about, so none invalidates another's evidence by
being built last.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import os
import json
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

from harness import (  # noqa: E402
    GENERATION_COMPOSITIONS,
    profile_integer,
    profile_text,
    sha256_file,
)
from zutai_cli import STDLIB, binary  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PINS_PATH = ROOT / "sel4" / "pins.toml"
# CP15: this plane builds by closure identity rather than by a plane flag. The
# identity names the build's inputs and is re-resolved from repository state
# before the build, so a stale input is refused rather than silently producing
# a different image.
CLOSURE = "sel4-loan"
IMAGE: Path | None = None
GENERATOR = ROOT / "scripts" / "build" / "build-generation.py"
FIXTURE = GENERATION_COMPOSITIONS / "sel4-loan.zti"
AUTOMATIC_BINDING_SLOTS = {
    "init": {
        "dango-output": 0,
        "init-shared-buffer-factory": 2,
        "sample-receiver-side": 4,
    },
    "console": {"console-shared-buffer-factory": 1},
}

BOOT_TIMEOUT_SECONDS = 120

# The loaned payload, in bytes. Two pages -- far past the 64-byte control
# message bound, which is what makes the loan necessary rather than an
# optimization.
PAYLOAD_BYTES = 8192
MAX_MSG_BYTES = 64

REQUIRED_MARKERS: tuple[tuple[str, str], ...] = (
    (
        "the loan generation was admitted",
        # Five grants: three channel edges plus the two `bufferCreate` grants
        # P5.3.3 made load-bearing. Before that slice the factory slot was
        # discarded and the budget alone admitted an allocation (B13), so this
        # graph reached its loan with no factory grant declared at all.
        r"SLIME_ROOT generation admitted number=\d+ executables=3 instances=3 grants=6 ",
    ),
    (
        "all three payloads are native ELF and no legacy image was activated",
        r"SLIME_ROOT graph admitted executables=3 instances=3 slimecm=0 elf=3 unrecognized=0",
    ),
    (
        # The quota half's precondition: every holder's ceiling read from the
        # generation's `shared-buffer-budget` resource, which is what makes
        # every refusal below a refusal against a *declared* limit rather than
        # against a constant compiled into the root task.
        #
        # The three per-holder lines are asserted by `check_declared_quotas`
        # rather than here, because the root prints them in task-id order and
        # task ids are assigned by staging order -- so requiring a particular
        # order among them would pin something the milestone does not claim.
        # Two *launched* instances at this point -- console and init, both
        # root-owned autostart -- and three holders, because the budget covers
        # `sample-receiver` too, which init spawns later. `declared` counts
        # what the root has launched when it prints, not what the generation
        # declares; the two were the same number while every instance was
        # root-owned (B52).
        "every declared holder was budgeted",
        r"SLIME_GRAPH quotas declared=2 budgeted=2 holders=3",
    ),
    (
        # B13. The factory grant and the budget are independent gates: the
        # grant authorizes the operation, the budget bounds it. This is the
        # first, asserted before any ceiling is grazed so the refusal cannot be
        # a quota answer wearing another name -- `class=ungranted`, not
        # `class=quota`.
        #
        # Two arms in one marker pair, deliberately: an empty slot and a slot
        # holding real authority of another kind are refused identically, which
        # is what stops a component probing its own table by watching which
        # error comes back.
        "a slot holding no factory cannot allocate, whatever the budget says",
        r"SLIME_GRAPH buffer create refused task=\d+ class=ungranted",
    ),
    (
        "init observed the ungranted-factory refusal",
        r"\[init\] ungranted buffer factory refused",
    ),
    (
        # Quota class 1 of 4: pages. A five-page region against a four-page
        # ceiling, refused before a frame is allocated.
        "the page ceiling refused a region one page past it",
        r"SLIME_GRAPH buffer create refused task=\d+ pages=5 class=quota",
    ),
    ("init observed the page refusal", r"\[init\] page quota refused"),
    (
        # Quota class 2 of 4: buffers. Three single-page regions stay inside the
        # four-page budget, so it is the buffer count and nothing else that bites.
        "the buffer ceiling refused a third region",
        r"SLIME_GRAPH buffer create refused task=\d+ pages=1 class=quota",
    ),
    ("init observed the buffer refusal", r"\[init\] buffer quota refused"),
    (
        # Quota class 3 of 4: mappings. A mapping of a region already charged,
        # so no page or buffer limit is involved.
        "the mapping ceiling refused a third mapping",
        r"SLIME_GRAPH buffer map refused task=\d+ slot=\d+ class=quota",
    ),
    ("init observed the mapping refusal", r"\[init\] mapping quota refused"),
    (
        # Every probe charge handed back, so the loan below runs against
        # ceilings that are entirely unspent and its own refusals are
        # unambiguous.
        "the probes released every charge they took",
        r"\[init\] quota probes reclaimed",
    ),
    ("init wrote the payload", r"\[init\] payload written"),
    (
        # A loan requires an irreversibly sealed source. Checked before sealing,
        # because afterwards it is unobservable.
        "an unsealed region was not loanable",
        r"SLIME_GRAPH loan refused task=\d+ slot=\d+ class=unsealed",
    ),
    ("init observed the unsealed refusal", r"\[init\] unsealed loan denied"),
    (
        # "Named by capability" is the exit condition's own wording, so the ways
        # of naming a receiver badly are asserted, not just the way that works.
        # An empty slot and a slot holding real authority of the wrong kind are
        # both refused; the second is the sharper one, since it is the buffer's
        # own slot -- authority this component genuinely holds. Both now share
        # the root's exact `absent` class: neither resolves to a receiver.
        "an empty slot cannot name a receiver",
        r"SLIME_GRAPH loan refused task=\d+ slot=\d+ class=absent",
    ),
    (
        "a slot holding the wrong kind cannot name a receiver",
        r"SLIME_GRAPH loan refused task=\d+ slot=\d+ class=absent",
    ),
    ("init observed both refusals", r"\[init\] unnamed receiver denied"),
    (
        # The generation's delegation bit. `dango-output` is declared
        # `transferable = false`, and everything else about this loan would
        # succeed -- sealed source, live receiver at the other end of a channel
        # init holds -- so the bit is the only thing refusing it.
        "a loan cannot be minted over an edge the generation did not delegate",
        r"SLIME_GRAPH loan refused task=\d+ slot=\d+ class=undelegated",
    ),
    ("init observed the delegation refusal", r"\[init\] undelegated loan denied"),
    (
        # The loan itself: an exact sealed subrange, bound to the task at the
        # other end of the channel init named. `to=` is the claim that the
        # receiver was resolved through a capability rather than taken from the
        # caller's word.
        "the loan was minted against the receiver the caller named by capability",
        rf"SLIME_GRAPH loan created task=\d+ slot=\d+ id=\d+ to=\d+ offset=0 "
        rf"length={PAYLOAD_BYTES}",
    ),
    ("init observed the loan", r"\[init\] loan created"),
    (
        # Quota class 4 of 4: loans. The ceiling is one and it is spent, so a
        # second loan of the same sealed region is refused by the quota rather
        # than by anything about the range.
        "the loan ceiling refused a second loan",
        r"SLIME_GRAPH loan refused task=\d+ slot=\d+ class=quota",
    ),
    ("init observed the loan refusal", r"\[init\] loan quota refused"),
    (
        # Native capability export is bounded to one capability and preserves
        # the loan kind and attenuated rights in the export ticket.
        "the loan capability was exported for exactly one receiver import",
        r"SLIME_GRAPH capability exported task=\d+ id=\d+ kind=loan "
        r"rights=0x[0-9a-f]+ retain=0",
    ),
    (
        "the receiver imported the same native loan authority",
        r"SLIME_GRAPH capability imported task=\d+ id=\d+ kind=loan "
        r"rights=0x[0-9a-f]+ retain=0",
    ),
    (
        "the receiver received the descriptor and the loan",
        r"\[sample-receiver\] descriptor received",
    ),
    (
        # The receiver's own denial arms, all four from the unmodified binary:
        # a descriptor naming another loan, a map past the loaned range, a
        # writable map of a read-only loan, and a second return.
        "a malformed descriptor mapped nothing",
        r"\[sample-receiver\] malformed descriptor mapped nothing",
    ),
    (
        # An seL4 frame capability records exactly one mapping, and a loan is
        # two holders mapping the same frames — so the receiver's mapping must
        # go through a distinct capability, recorded against the exact mapping
        # it backs. Asserted at the moment it is minted, because the terminal
        # `aliases=0` cannot establish it: a boot that never aliased at all also
        # ends at zero, and its unmaps would tear down the lender's view while
        # the receiver's silently survived.
        "the receiver's mapping went through its own frame capability",
        r"SLIME_GRAPH frame aliased frame=\d+ vaddr=0x\w+ live=\d+",
    ),
    (
        "the receiver mapped exactly the loaned bytes",
        r"SLIME_GRAPH loan mapped task=\d+ slot=\d+ id=\d+",
    ),
    ("the receiver observed the mapping", r"\[sample-receiver\] loaned bytes mapped"),
    (
        "a loan grants no write access",
        r"\[sample-receiver\] loan stays read-only",
    ),
    (
        # The end-to-end claim: the receiver reconstructed a payload larger than
        # the control-message bound from bytes that never entered a queue.
        "the receiver verified the whole payload",
        r"\[sample-receiver\] payload verified",
    ),
    (
        "the loan was returned",
        r"SLIME_GRAPH loan returned task=\d+ slot=\d+ id=\d+",
    ),
    (
        # Single-return. The second return finds no capability, because the
        # first emptied the slot.
        "a returned loan cannot be returned again",
        r"\[sample-receiver\] loan returned once",
    ),
    ("init sent the descriptor", r"\[init\] loan transferred"),
    (
        # A move, not a copy: the sender can no longer name what it sent.
        "the sender can no longer name the transferred loan",
        r"\[init\] transferred loan released by sender",
    ),
    ("init observed the settlement", r"\[init\] receiver settled"),
    (
        # C7.5 retention, from the other side: the creator could not reclaim
        # while the loan was outstanding, and can now.
        "the creator reclaimed once the loan had settled",
        r"\[init\] released",
    ),
    (
        "an unrelated holder received on its channel",
        r"\[console\] unrelated holder intact",
    ),
    (
        # The unrelated-holder claim, and the only assertion that establishes
        # it. Init has by now exhausted all four of its own ceilings; console
        # then runs a full create/map/write/seal/unmap/release against its own
        # declared quota and succeeds. A ceiling that leaked across holders
        # would report `quota exhausted` here instead.
        "an unrelated holder's own quota was undisturbed by the exhaustion",
        r"\[console\] shared-buffer quota live",
    ),
    (
        # One export is deliberately left without an import. Root cancellation
        # and finalization must reclaim its ticket when the sender exits.
        "one export ticket was left for the root to reclaim",
        r"\[init\] export ticket left for reclamation",
    ),
    ("init completed the scenario", r"\[init\] loan plane complete"),
    (
        "the graph drained with every window and table reclaimed",
        r"SLIME_GRAPH served live=0 unsupported=0 buffers=\d+ windows=0 tasks=0",
    ),
    (
        "every native capability export was imported, cancelled, or finalized",
        r"SLIME_GRAPH capabilities exports=[1-9]\d* imports=[1-9]\d* "
        r"cancels=\d+ finalized=\d+ outstanding=0 tickets=0",
    ),
    (
        # Native clean accounting distinguishes buffer ownership from exported
        # capabilities: both must be empty after the graph drains.
        "every loan, mapping, region, and alias was reclaimed",
        r"SLIME_GRAPH loans served=\d+ loans=0 mappings=0 regions=0 "
        r"orphans=0 quota=0",
    ),
)

FAILURE_MARKERS: tuple[str, ...] = (
    r"SLIME_ROOT FATAL .*",
    r"SLIME_GRAPH FAIL .*",
    # The scenarios' own assertions. Every one means an operation returned
    # something other than what the plane promises, and the component says so
    # rather than exiting quietly.
    r"\[init\] loan plane fail: .*",
    r"\[sample-receiver\] fail: .*",
    # A holder whose reclamation could not complete leaves live state charged to
    # a dead task. The terminal marker's counts would show it, but this names
    # the cause at the point it happened.
    r"SLIME_GRAPH holder reclaim incomplete .*",
    # A component that could not bind its transfer window would issue no
    # windowed operation at all, and the graph would look quiet rather than
    # broken.
    r"\[slime-rt\] transfer window bind failed",
    r"SLIME_GRAPH window bind refused",
    r"SLIME_GRAPH park refused .*",
    # A channel the generation declared that the root could not place. This
    # graph declares none, so any occurrence means the fixture and the boot
    # layout have drifted apart.
    r"SLIME_GRAPH channel unplaced .*",
    r"SLIME_GRAPH service budget exhausted",
    # seL4's own complaints. `read-only endpoint` in particular means a
    # component cannot invoke the root at all, which is silent from the Slime
    # side: the component simply never speaks.
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
    raise SystemExit(f"seL4 loan plane check: {message}")


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


def generator_module(name: str):
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    if spec is None or spec.loader is None:
        fail("cannot import the generation builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_automatic_binding_slots() -> None:
    """Omitted named bindings must resolve to the frozen loan layout."""
    environment = dict(os.environ)
    environment["ZUTAI_STDLIB_ROOT"] = str(STDLIB)
    process = subprocess.run(
        [str(binary()), "json", str(FIXTURE)],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode:
        fail(f"cannot decode {FIXTURE.relative_to(ROOT)}: {process.stderr.strip()}")
    try:
        manifest = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        fail(f"cannot parse decoded {FIXTURE.relative_to(ROOT)}: {error}")
    instances = {instance["name"]: instance for instance in manifest["instances"]}
    for holder, expected_bindings in AUTOMATIC_BINDING_SLOTS.items():
        instance = instances.get(holder)
        if instance is None:
            fail(f"loan generation declares no {holder} instance")
        bindings = {binding["grant"]: binding for binding in instance["bindings"]}
        for grant in expected_bindings:
            binding = bindings.get(grant)
            if binding is None:
                fail(f"{holder} does not bind {grant}")
            if "slot" in binding:
                fail(f"{holder}/{grant} redundantly pins slot {binding['slot']}")

    resolved = generator_module("slime_build_generation_loan_slots").assign_declared_slots(
        copy.deepcopy(manifest)
    )
    resolved_instances = {instance["name"]: instance for instance in resolved["instances"]}
    for holder, expected_bindings in AUTOMATIC_BINDING_SLOTS.items():
        resolved_bindings = {
            binding["grant"]: binding["slot"] for binding in resolved_instances[holder]["bindings"]
        }
        for grant, expected in expected_bindings.items():
            if resolved_bindings.get(grant) != expected:
                fail(
                    f"{holder}/{grant} resolved to slot {resolved_bindings.get(grant)}, "
                    f"expected {expected}"
                )
    count = sum(len(bindings) for bindings in AUTOMATIC_BINDING_SLOTS.values())
    print(
        f"loan manifest: {count} named binding slots omitted and resolved unchanged",
        flush=True,
    )


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

def boot(profile: dict[str, object]) -> str:
    """Boot the image and return the serial transcript.

    The root task suspends itself once the graph has drained, so QEMU stays
    alive afterwards and waiting for an exit would always time out. Serial
    output is read line by line and the guest is killed as soon as the terminal
    or any failure marker appears.
    """
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
    ]
    print(f"[boot] {' '.join(command)}", flush=True)
    terminal = re.compile(REQUIRED_MARKERS[-1][1])
    failures = re.compile("|".join(FAILURE_MARKERS))
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
    # A wedged guest emits nothing, so the deadline cannot live in the read
    # loop; a watchdog kills QEMU, which closes the pipe and ends the loop.
    watchdog = threading.Timer(BOOT_TIMEOUT_SECONDS, process.kill)
    watchdog.start()
    try:
        assert process.stdout is not None
        for line in process.stdout:
            lines.append(line.rstrip("\n"))
            if terminal.search(line) or failures.search(line):
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
    transcript = "\n".join(lines)
    if timed_out and terminal.search(transcript) is None:
        report_transcript(transcript)
        fail(f"boot exceeded {BOOT_TIMEOUT_SECONDS}s without reaching the final marker")
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
    for description, pattern in REQUIRED_MARKERS:
        match = re.compile(pattern).search(transcript, position)
        if match is None:
            report_transcript(transcript)
            if re.search(pattern, transcript) is not None:
                fail(f"marker out of order: {description} ({pattern})")
            fail(f"missing marker: {description} ({pattern})")
        position = match.end()
    check_declared_quotas(transcript)
    check_quota_classes(transcript)
    check_payload_crosses_the_message_bound()
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
    if not exports or not imports or imports[0] != exports[0]:
        fail(f"settled loan export/import evidence was {exports!r}/{imports!r}")


# The export arm, `--export-share`. `EXPORT_SHARE` is how many exports one
# sender may hold that no receiver has imported.
EXPORT_SHARE = 4
EXPORT_SHARE_REFUSED = "[init] export share refused"
EXPORT_LINE = re.compile(
    r"SLIME_GRAPH capability exported task=(\d+) id=(\d+) kind=\S+ "
    r"rights=0x[0-9a-f]+ retain=[01]"
)
IMPORT_LINE = re.compile(
    r"SLIME_GRAPH capability imported task=(\d+) id=(\d+) kind=\S+ "
    r"rights=0x[0-9a-f]+ retain=[01]"
)
EXIT_LINE = re.compile(r"SLIME_GRAPH component exit task=(\d+) status=-?\d+")
RELEASE_LINE = re.compile(r"SLIME_GRAPH exports released task=(\d+) count=(\d+)")
DRAIN_LINE = re.compile(r"SLIME_GRAPH served live=0 .*")
EXPORT_CENSUS_LINE = re.compile(
    r"SLIME_GRAPH capabilities exports=(\d+) imports=(\d+) cancels=(\d+) "
    r"finalized=\d+ outstanding=(\d+) tickets=(\d+)"
)


def check_export_share(transcript: str) -> None:
    """Judge the export arm from the lines the root printed.

    Three facts must hold. The root refused the sender when it held exactly its
    share of unimported exports. Every release names a task that had exited, and
    precedes the drain of the graph. The census counts as imports only the
    imports the root printed, and the releases account for every other export.

    The arm does not require which task exits first. The sender and its receiver
    exit without an order between them, and the totals hold in either order.
    """

    def refuse(message: str) -> NoReturn:
        fail(f"export share: {message}")

    lines = [line.strip() for line in transcript.splitlines()]

    def found(pattern: re.Pattern[str]) -> list[tuple[int, re.Match[str]]]:
        return [
            (index, match)
            for index, line in enumerate(lines)
            if (match := pattern.fullmatch(line)) is not None
        ]

    exported = [(index, int(match[1]), int(match[2])) for index, match in found(EXPORT_LINE)]
    imported = [(index, int(match[2])) for index, match in found(IMPORT_LINE)]
    export_at = {identity: index for index, _task, identity in exported}
    if len(export_at) != len(exported):
        refuse("the root printed one export identity twice")
    if len({identity for _index, identity in imported}) != len(imported):
        refuse("the root printed two imports of one export")
    for index, identity in imported:
        if identity not in export_at:
            refuse(f"an import names export {identity}, which the root did not print")
        if export_at[identity] > index:
            refuse(f"the import of export {identity} precedes that export")

    refusals = [index for index, line in enumerate(lines) if line == EXPORT_SHARE_REFUSED]
    if len(refusals) != 1:
        refuse(f"expected one {EXPORT_SHARE_REFUSED!r} line, found {len(refusals)}")
    refused_at = refusals[0]
    before = [entry for entry in exported if entry[0] < refused_at]
    if not before:
        refuse("no export precedes the refusal")
    sender = before[-1][1]
    settled = {identity for index, identity in imported if index < refused_at}
    held = [
        identity
        for _index, task, identity in before
        if task == sender and identity not in settled
    ]
    if len(held) != EXPORT_SHARE:
        refuse(
            f"task {sender} held {len(held)} unimported exports when the root "
            f"refused it, and its share is {EXPORT_SHARE}"
        )

    drains = [index for index, _match in found(DRAIN_LINE)]
    if len(drains) != 1:
        refuse(f"expected one line that reports the drained graph, found {len(drains)}")
    exited: dict[int, int] = {}
    for index, match in found(EXIT_LINE):
        exited.setdefault(int(match[1]), index)
    released = [(index, int(match[1]), int(match[2])) for index, match in found(RELEASE_LINE)]
    if not released:
        refuse("no retirement released an export")
    for index, task, count in released:
        if task not in exited or exited[task] > index:
            refuse(f"the root released exports of task {task} before that task exited")
        if index > drains[0]:
            refuse(f"the root released exports of task {task} after the graph drained")
        if count == 0:
            refuse(f"the root reported a release of no export for task {task}")

    census = found(EXPORT_CENSUS_LINE)
    if len(census) != 1:
        refuse(f"expected one export census line, found {len(census)}")
    exports, imports, cancels, outstanding, tickets = (int(field) for field in census[0][1].groups())
    if exports != len(exported):
        refuse(f"the census counts {exports} exports, and the root printed {len(exported)}")
    if imports != len(imported):
        refuse(f"the census counts {imports} imports, and the root printed {len(imported)}")
    if cancels != 0:
        refuse(f"the census counts {cancels} cancels, and the scenario cancels no export")
    if outstanding != 0 or tickets != 0:
        refuse(f"the census leaves outstanding={outstanding} tickets={tickets}")
    total = sum(count for _index, _task, count in released)
    if total != exports - imports:
        refuse(
            f"retirements released {total} exports, and {exports - imports} "
            "exports left the table without an import"
        )


# The one ceiling this file needs by value rather than by comparison: the four
# quota probes are written against `init`'s limits, so a fixture edit that
# changed them would need matching probe edits. Checked against the fixture
# below rather than trusted.
INIT_QUOTA = {"pages": 4, "buffers": 2, "mappings": 2, "loans": 1}


def fixture_quotas() -> dict[str, tuple[int, int, int, int]]:
    """The ceilings `sel4-loan.zti` declares, read from the fixture itself.

    Parsed rather than hand-copied into this file. The claim under test is that
    the root's ceilings came from the *generation*; comparing its output to a
    constant transcribed here would only establish that two files in this
    repository agree with a third thing typed twice, and a fixture edit would
    silently invalidate the gate rather than fail it.

    The manifest is canonical Zutai, but the budget entries are a flat list of
    scalar fields, so a line-oriented read is sufficient and avoids depending on
    the Zutai binary from a gate that is not otherwise about the format.
    """
    try:
        text = FIXTURE.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {FIXTURE.relative_to(ROOT)}: {error}")
    # Field order is the fixture's, and Zutai renders record fields
    # alphabetically -- `bufferCount`, `bytePages`, `holder`, `loanCount`,
    # `mappingCount`. This pattern assumed `holder` came first and so matched
    # nothing; the gate never reached it, because it failed earlier.
    entries = [
        (
            match["holder"],
            match["bytePages"],
            match["bufferCount"],
            match["mappingCount"],
            match["loanCount"],
        )
        for match in re.finditer(
            r"\{\s*bufferCount\s*=\s*(?P<bufferCount>\d+)\s*;\s*"
            r"bytePages\s*=\s*(?P<bytePages>\d+)\s*;\s*"
            r"holder\s*=\s*\"(?P<holder>[^\"]+)\"\s*;\s*"
            r"loanCount\s*=\s*(?P<loanCount>\d+)\s*;\s*"
            r"mappingCount\s*=\s*(?P<mappingCount>\d+)\s*;",
            text,
        )
    ]
    if not entries:
        fail(f"{FIXTURE.relative_to(ROOT)} declares no shared-buffer budget entries")
    return {name: tuple(int(value) for value in limits) for name, *limits in entries}


def check_declared_quotas(transcript: str) -> None:
    """Every holder received exactly the ceiling the generation declared.

    Order-independent on purpose: the root reports these in task-id order, and
    task ids follow staging order, which the milestone claims nothing about.
    What it does claim is that each holder's ceiling came from the generation,
    so each is checked by name against the fixture as parsed.
    """
    declared = fixture_quotas()
    reported = {
        name: tuple(int(value) for value in limits)
        for name, *limits in re.findall(
            r"SLIME_GRAPH quota task=\d+ instance=(\S+) executable=\S+ pages=(\d+) buffers=(\d+) "
            r"mappings=(\d+) loans=(\d+)",
            transcript,
        )
    }
    if reported != declared:
        fail(
            f"the root declared {reported}, not the ceilings "
            f"{FIXTURE.relative_to(ROOT)} states ({declared})"
        )
    # The probes are written against init's exact numbers, so a fixture edit
    # that moved them would make every ceiling+1 probe test the wrong thing
    # while still refusing. Fail here rather than pass on a coincidence.
    if declared.get("init") != tuple(
        INIT_QUOTA[key] for key in ("pages", "buffers", "mappings", "loans")
    ):
        fail(
            f"{FIXTURE.relative_to(ROOT)} declares init {declared.get('init')}, but the "
            f"quota probes in init.rs are written against {INIT_QUOTA}"
        )
    print(
        f"quota: every holder received exactly the ceiling "
        f"{FIXTURE.relative_to(ROOT)} declares for it",
        flush=True,
    )


def check_quota_classes(transcript: str) -> None:
    """Each of the four ceilings refused, and each named its own class.

    The ordered markers assert that four refusals happened in the right places.
    This asserts something the ordering cannot: that every refusal came from a
    *quota* rather than from some other check that happens to refuse the same
    request. A region refused for a malformed range would satisfy the ordered
    marker for the page ceiling equally well and would prove nothing about the
    generation's declared limits.
    """
    # `loan refused` carries no operation word, while `buffer create refused`
    # and `loan mapped refused` do, so the word is optional. A pattern that
    # required it would silently miss both loan-mint refusals -- the unsealed
    # one and the loan ceiling -- and report three classes where there are four.
    refusals = re.findall(
        r"SLIME_GRAPH (?:buffer|loan)(?: \w+)? refused task=\d+ [^\n]*class=(\w+)",
        transcript,
    )
    quota_refusals = [name for name in refusals if name == "quota"]
    if len(quota_refusals) != len(INIT_QUOTA):
        fail(
            f"the transcript records {len(quota_refusals)} quota refusals, not the "
            f"{len(INIT_QUOTA)} classes the milestone requires "
            f"({', '.join(sorted(INIT_QUOTA))}); refusal classes seen: "
            f"{', '.join(refusals) or 'none'}"
        )
    print(
        f"quota: all {len(INIT_QUOTA)} declared ceilings refused at ceiling+1 "
        f"({', '.join(sorted(INIT_QUOTA))})",
        flush=True,
    )


def check_payload_crosses_the_message_bound() -> None:
    """The loaned payload must exceed what a control message can carry.

    Asserted against the source rather than inferred from the transcript,
    because a payload that shrank below the message bound would still be loaned,
    still be mapped, and still verify -- the gate would pass while the property
    that makes a loan necessary at all went unexercised.
    """
    if PAYLOAD_BYTES <= MAX_MSG_BYTES:
        fail(
            f"the loaned payload is {PAYLOAD_BYTES} bytes, which fits in the "
            f"{MAX_MSG_BYTES}-byte control message and needs no loan"
        )
    print(
        f"payload: {PAYLOAD_BYTES} bytes exceeds the {MAX_MSG_BYTES}-byte control "
        "message bound, so it can only cross as a loan",
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Boot the seL4 loan-plane image and assert ordered markers"
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="boot the already-built image instead of rebuilding it first",
    )
    parser.add_argument(
        "--export-share",
        action="store_true",
        help="also judge the export arm: one sender's share, and what a retirement releases",
    )
    arguments = parser.parse_args()

    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    pins = load_pins()
    check_automatic_binding_slots()
    if not arguments.no_build:
        build_image()
    profile = pins["qemu_arm_virt"]
    assert isinstance(profile, dict)
    transcript = boot(profile)
    check_transcript(transcript)
    if arguments.export_share:
        try:
            check_export_share(transcript)
        except SystemExit:
            report_transcript(transcript)
            raise
        print(
            f"seL4 export share check: the root refused a sender that held {EXPORT_SHARE} "
            "unimported exports, released them when a task they named exited, and "
            "counted as imports only the imports it printed"
        )
    print(
        "seL4 loan plane check: a sealed subrange was loaned to a receiver named by "
        "capability, mapped read-only, returned once, and reclaimed; all four declared "
        "quota classes refused at ceiling+1 without disturbing an unrelated holder"
    )


if __name__ == "__main__":
    main()
