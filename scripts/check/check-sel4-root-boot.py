#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from sel4_boot import (  # noqa: E402
    PLATFORMS,
    artifact_paths as platform_artifact_paths,
    boot_command,
    report_transcript,
    run as run_boot,
    verify_identity,
)

ROOT = Path(__file__).resolve().parents[2]
PINS_PATH = ROOT / "sel4" / "pins.toml"
BUILD_SCRIPT = ROOT / "scripts" / "build" / "build-sel4.py"

# The userspace timer each platform's root drives: the ARM generic timer's
# secure physical PPI, RISC-V's goldfish RTC alarm, and the IA-PC HPET's first
# comparator, on the IOAPIC pin `platform_timer::TIMER_IRQ` names.
TIMER_IRQS = {"qemu-arm-virt": 30, "qemu-riscv-virt": 11, "qemu-pc99": 20}

# x86-64 seL4 exposes no execute-never frame attribute — `seL4_X86_VMAttributes`
# is a cache-policy selector — so P6.1 recorded W^X on child data pages as
# *unenforced* on this profile rather than claiming it. The fixture drops the
# execute probe entirely there rather than letting it pass vacuously, and the
# root prints `wx_execute=unenforced` so a transcript cannot read as an
# enforced mapping.
#
# `WX_PROBES` pins the verdict line per platform, and `WX_ENFORCED_MARKERS`
# names the markers that exist only where the attribute does. Both are pinned
# per platform rather than relaxed everywhere, so a future profile that
# silently stopped enforcing W^X on ARM or RISC-V would fail this gate.
WX_PROBES = {
    "qemu-arm-virt": r"ro_write=refused wx_execute=refused probes=2",
    "qemu-riscv-virt": r"ro_write=refused wx_execute=refused probes=2",
    "qemu-pc99": r"ro_write=refused wx_execute=unenforced probes=1",
}
WX_ENFORCED_MARKERS = frozenset({"execute-never mapping refused execution from a data page"})
WX_ENFORCED_PLATFORMS = frozenset({"qemu-arm-virt", "qemu-riscv-virt"})


def artifact_paths(platform: str) -> tuple[Path, Path]:
    return platform_artifact_paths("slime-sel4", platform)


# The boot is bounded: a wedged guest must fail loudly instead of hanging the
# gate. seL4 plus the root task reaches its final marker in a few seconds.
BOOT_TIMEOUT_SECONDS = 120

# Ordered evidence for the standalone seL4 vertical slice, matched in this
# order against the serial transcript. Together these establish the whole
# chain: the root task admitted the generation and its authority manifest,
# activated no legacy component image, took ownership of untyped memory,
# acquired the platform's userspace timer IRQ and observed one delivered and
# acknowledged interrupt with the counter advancing across the wait, staged
# both child tasks from the native ELF fixture, activated each one, served
# its badged request, then observed a clean exit from one and a real VM
# fault from the other, reclaimed both, and reached its ready state with
# nothing live.
#
# Numeric fields (badges, slot ranges, counts, fault status words) vary per
# build and are matched loosely. What is pinned is the ordering, the task and
# role identities, the typed service label, the exit status, the fault kind,
# and the terminal `live=0`.
REQUIRED_MARKERS: tuple[tuple[str, str], ...] = (
    (
        "allocator admitted nonzero kernel resources",
        r"SLIME_ROOT allocator slots=[1-9]\d* untypeds=[1-9]\d* bytes=[1-9]\d*",
    ),
    (
        "kernel admitted an ordinary physical range",
        r"SLIME_ROOT ordinary range=\d+ paddr=0x[0-9a-f]+ bytes=[1-9]\d*",
    ),
    (
        "kernel ordinary memory inventory reaches its physical end",
        r"SLIME_ROOT ordinary ranges=[1-9]\d* bytes=[1-9]\d* end=0x[0-9a-f]+",
    ),
    (
        "an ordinary frame from the highest admitted range was mapped and verified",
        r"SLIME_ROOT ordinary probe paddr=0x[0-9a-f]+ bytes=\d+ "
        r"beyond_legacy=[01] verified=1",
    ),
    (
        "timer source acquired",
        r"SLIME_TIMER acquired irq=(\d+) freq_hz=\d+",
    ),
    (
        "timer interrupt delivered",
        r"SLIME_TIMER delivered badge=0x1 polls=\d+",
    ),
    (
        "timer expiry serviced and acknowledged",
        r"SLIME_TIMER serviced events=1 programming=\S",
    ),
    (
        # Corroborating only: CNTPCT_EL0 free-runs, so a non-zero delta proves
        # the counter is readable and monotonic across the wait, NOT that the
        # interrupt fired. `SLIME_TIMER delivered` above is the load-bearing
        # IRQ evidence; this one would still hold if delivery had degraded.
        "timer counter readable and advancing",
        r"SLIME_TIMER advanced start=\d+ end=\d+ delta=[1-9]\d*",
    ),
    ("timer phase complete", r"SLIME_TIMER OK"),
    (
        "two typed frame allocations were independent and exactly accounted",
        r"SLIME_FOUNDATION frames independent objects_delta=2 slots_delta=2 "
        r"bytes_delta=8192 caps_deleted=2",
    ),
    # Product images no longer pre-probe or claim device transports. Admission
    # decides whether a declared userspace IO driver receives raw authority;
    # this no-disk fixture has no such budget, so the device phase is silent.
    ("generation admitted", r"SLIME_ROOT generation admitted number=\d+"),
    # The default fixture uses the product composition's six-entry catalogue
    # but keeps graph launch disabled so the standalone native child exercise
    # below remains independent.
    (
        "the fixture declares no fabric graph",
        r"SLIME_ROOT fabric graph=absent schemas=0 routes=0 "
        r"participants=0 interpositions=0",
    ),
    ("authority manifest reported", r"SLIME_ROOT authority manifest=\["),
    (
        "the product executable catalogue is admitted",
        r"SLIME_ROOT graph admitted executables=6 instances=6 "
        r"slimecm=0 elf=6 unrecognized=0",
    ),
    (
        "clean-exit task staged",
        r"SLIME_ROOT native fixture staged task=0 role=clean-exit \S+ badge=\S+",
    ),
    (
        "deliberate-fault task staged",
        r"SLIME_ROOT native fixture staged task=1 role=deliberate-fault \S+ badge=\S+",
    ),
    ("allocation complete", r"SLIME_ROOT allocations complete tasks=2 "),
    # The shared-buffer phase maps real frames into the clean-exit fixture's
    # VSpace before any task is activated, so its mapping markers precede
    # activation; the child's observations then interleave with that fixture's
    # request record, and the root's adjudication follows both fixtures.
    (
        "shared read-write region mapped at the exact requested range",
        r"SLIME_BUF mapped buffer=\d+ vaddr=0x40000000\.\.0x40001000 pages=1 "
        r"rights=read-write holder=0 frames=[1-9]\d* tables=\d+",
    ),
    (
        "shared read-only region mapped at the exact requested range",
        r"SLIME_BUF mapped buffer=\d+ vaddr=0x40010000\.\.0x40011000 pages=1 "
        r"rights=read-only holder=0 frames=[1-9]\d* tables=\d+",
    ),
    (
        "shared-buffer accounting charged before the child runs",
        r"SLIME_BUF accounting live=2 pages=2 mappings=2 holder_pages=2 orphans=0",
    ),
    ("clean-exit task activated", r"SLIME_ROOT task activated task=0 role=clean-exit"),
    ("clean-exit child issued a request", r"SLIME_CHILD request op=5 tag=0x534c494d45524551"),
    (
        "root served the clean-exit request",
        r"SLIME_ROOT request badge=\S+ task=0 service_label=5 directive=0",
    ),
    (
        "root replied to the clean-exit child",
        r"SLIME_ROOT child request served task=0 role=clean-exit service_label=5 result=0",
    ),
    # The exact bytes, pinned literally: this is the assertion that a real
    # frame — not a separately zeroed page — is shared with the child.
    (
        "child read back the exact bytes the root wrote",
        r"SLIME_CHILD shared read vaddr=0x40000040 "
        r"observed=0x534255465f525721 expected=0x534255465f525721",
    ),
    (
        "read-only mapping refused the child write by mechanism",
        r"SLIME_BUF probe refused task=0 kind=ro-write access=Write address=0x40010040",
    ),
    (
        "read-only region still holds the root's bytes after the refused write",
        r"SLIME_CHILD ro write result observed=0x534255465f525721 "
        r"intrusion=0xdeadbeefdeadbeef",
    ),
    (
        "execute-never mapping refused execution from a data page",
        r"SLIME_BUF probe refused task=0 kind=wx-execute access=Execute address=0x40000000",
    ),
    (
        "child reported the shared-buffer phase",
        r"SLIME_BUF child reported task=0 observed=0x534255465f525721 flags=0x3",
    ),
    # C10.1's private-memory phase. It runs after the shared-buffer report and
    # before the clean exit, so the fixture is still live and attributable for
    # every growth. Each pair below is deliberate: the root's own record of what
    # it mapped, then the child's observation from inside its own address space.
    # Neither alone is sufficient — the root cannot read the child's memory, and
    # the child cannot see the page accounting.
    #
    # The base is matched loosely (`0x[0-9a-f]+`) rather than pinned: it is
    # derived from the fixture image's own footprint, so pinning it would make
    # every recompilation of the child a gate edit. That the base is the *same*
    # value in every record — the property that actually matters — is checked by
    # `check_private_memory_base` below, because a backreference cannot span two
    # separately compiled patterns.
    (
        "a size query answers zero pages and the window base, allocating nothing",
        r"SLIME_MEM grown task=0 delta=0 previous=0 pages=0 base=0x[0-9a-f]+ "
        r"quota=4 total=0",
    ),
    (
        "the child read a base from the size query",
        r"SLIME_CHILD mem query pages=0 base=0x[0-9a-f]+",
    ),
    (
        "the first growth backs two pages and answers the previous count",
        r"SLIME_MEM grown task=0 delta=2 previous=0 pages=2 base=0x[0-9a-f]+ "
        r"quota=4 total=2",
    ),
    (
        "the child observed the first growth",
        r"SLIME_CHILD mem grew previous=0 delta=2 base=0x[0-9a-f]+",
    ),
    # The zero read, over an address the child actually dereferenced rather than
    # merely a flag saying it succeeded. `zeroed=1` over both freshly backed
    # pages is the "every new page reads as zero" requirement; the base makes it
    # an assertion about where those reads landed, which
    # `check_private_memory_base` folds into the single-base set.
    (
        "both new pages read as zero at the base the root reported",
        r"SLIME_CHILD mem read base=0x[0-9a-f]+ pages=2 bytes=8192 zeroed=1",
    ),
    (
        "the second growth reaches the declared ceiling",
        r"SLIME_MEM grown task=0 delta=2 previous=2 pages=4 base=0x[0-9a-f]+ "
        r"quota=4 total=4",
    ),
    # The load-bearing base-stability assertion: the pattern the child wrote
    # into the first page before the second growth is still there afterwards.
    # Native component images hold real machine pointers, so a growth that
    # relocated the base would invalidate every one of them; this is what proves
    # it does not.
    (
        "a pattern written before the growth survived it",
        r"SLIME_CHILD mem grew previous=2 delta=2 base=0x[0-9a-f]+ "
        r"survived=0x4d454d5f42415345 expected=0x4d454d5f42415345",
    ),
    (
        "the surviving pattern was read back from the same base",
        r"SLIME_CHILD mem pattern base=0x[0-9a-f]+ offset=0",
    ),
    # The refusal names its own cause. `quota` rather than `reservation`,
    # `root-ceiling`, `frames`, or `delta-overflow`: the region is at its
    # declared ceiling and nowhere near the structural one, so a mechanism that
    # reported the wrong bound would be telling an allocator to wait for
    # capacity that was never coming.
    (
        "growth past the declared quota is refused, naming the quota",
        r"SLIME_MEM refused task=0 delta=1 cause=quota "
        r"detail=QuotaExceeded \{ pages: 4, delta: 1, quota: 4 \}",
    ),
    (
        "the caller survived the refusal and observed it as a structured error",
        r"SLIME_CHILD mem quota probe delta=1 result=-5",
    ),
    # All-or-nothing: the refused growth left the page count and the contents
    # exactly as they were. A partial growth would show up as five pages or a
    # lost pattern.
    (
        "the refusal changed nothing: the same page count",
        r"SLIME_MEM grown task=0 delta=0 previous=4 pages=4 base=0x[0-9a-f]+ "
        r"quota=4 total=4",
    ),
    (
        "the region is intact after the refusal",
        r"SLIME_CHILD mem intact pages=4 pattern=0x4d454d5f42415345 "
        r"expected=0x4d454d5f42415345",
    ),
    # 0x7f is every flag the phase must set, pinned exactly rather than as a
    # mask test: the query, the two growths, the zero read, the surviving base,
    # the refusal, and the refusal having no effect. A phase reporting fewer
    # observations than it was supposed to make would otherwise pass.
    (
        "the child reported every private-memory observation",
        r"SLIME_MEM child reported task=0 flags=0x7f",
    ),
    ("child exited cleanly", r"SLIME_CHILD clean exit status=0"),
    (
        "root observed the clean exit",
        r"SLIME_ROOT child exit observed task=0 role=clean-exit status=0",
    ),
    (
        "deliberate-fault task activated",
        r"SLIME_ROOT task activated task=1 role=deliberate-fault",
    ),
    (
        "root served the fault-directive request",
        r"SLIME_ROOT request badge=\S+ task=1 service_label=5 directive=1",
    ),
    ("child requested a fault", r"SLIME_CHILD fault requested addr=0x0"),
    (
        "root observed the child fault",
        r"SLIME_ROOT child fault observed task=1 role=deliberate-fault "
        r"kind=VirtualMemory \{ access: Write",
    ),
    # Adjudication runs after both fixtures have finished, because the root
    # decides the phase from its own fault records rather than from the child's
    # self-report. Teardown then proves the accounting really returns to zero.
    (
        "root confirmed the exact bytes crossed the shared frame both ways",
        r"SLIME_BUF readback vaddr=0x40000040 root_wrote=0x534255465f525721 "
        r"child_read=0x534255465f525721 child_wrote=0x4348494c445f4f4b match=1",
    ),
    # `{wx_probes}` is substituted per platform from `WX_PROBES`: the number of
    # protection probes and the W^X verdict differ because x86-64 seL4 has no
    # execute-never frame attribute. Everything else about the marker — the
    # read-only refusal and the single supervised fault — holds everywhere.
    (
        "the mapping protections were enforced and supervised",
        r"SLIME_BUF rights enforced {wx_probes} supervised=1",
    ),
    # The root's own private-memory verdict, adjudicated in the same pass as the
    # shared-buffer one: after both fixtures have finished, from the root's page
    # accounting rather than the child's self-report. `grants=2` is the
    # assertion a page total cannot make — the two size queries and the refusal
    # each charged nothing, so four pages were handed out by exactly two
    # operations, and a mechanism charging a query would reach the same total by
    # a wrong route.
    (
        "the root adjudicated the private-memory phase against its own accounting",
        r"SLIME_MEM enforced quota=4 pages=4 grants=2 grown=4 reclaimed=0 flags=0x7f",
    ),
    (
        "teardown reclaimed every frame and mapping with quotas back at zero",
        r"SLIME_BUF teardown unmapped=[1-9]\d* revoked=[1-9]\d* released=[1-9]\d* "
        r"live=0 pages=0 mappings=0 holder_pages=0 orphans=0",
    ),
    # B9 on seL4 (P5.4.10): `kernel/tests/task_reclamation.rs` measures frame
    # conservation across spawn/release cycles — a task that goes away returns
    # every frame it consumed. The seL4 shape of the same property is CSlot
    # conservation, and the counts were wildcards here, so a task reclaiming
    # half its slots passed unnoticed.
    #
    # Each task's range is pinned exactly: contiguous, equal-width, and
    # adjoining its neighbour, which is the conservation B9 asserts. Root
    # CSlots are deliberately *not* returned to the allocator
    # (`task.rs::CleanupRecord::revoke`), so the property here is "every slot a
    # task took is accounted for", not "the free count returns to its start" —
    # the drift B9 measures cannot exist on a monotonic allocator.
    # The absolute base is *not* the property: it is wherever the allocator's
    # cursor stands once the root's static tables are placed and its boot-time
    # allocations are made, so it moves whenever either changes. P5.4.9's larger
    # tables moved it 832 → 839, P5.4.2a's device probe — which retypes ten
    # granules to reach four scattered MMIO pages — moved it 839 → 849, and
    # P5.4.2b's IRQ binding took four more for 853, and P5.4.3's namespace, device, and
    # Reclaim records now report an explicit slot count and arena generation;
    # reusable root CSlots are intentionally noncontiguous across lifetimes.
    # Interleaved with the settle markers rather than grouped after them: each
    # task is reclaimed as it settles, and this list is order-sensitive, so
    # grouping would assert a sequence the root does not produce.
    (
        "clean-exit task settled",
        r"SLIME_ROOT task settled task=0 role=clean-exit termination=Exit\(0\)",
    ),
    (
        "the clean-exit task's arena-owned slots are accounted for",
        r"SLIME_ROOT task reclaimed task=0 source=generation slots=(\d+) arena=\d+",
    ),
    (
        "deliberate-fault task settled",
        r"SLIME_ROOT task settled task=1 role=deliberate-fault termination=Fault\(",
    ),
    (
        "the faulted task's arena-owned slots are accounted for",
        r"SLIME_ROOT task reclaimed task=1 source=generation slots=(\d+) arena=\d+",
    ),
    # C10.1's reclamation half: every private page returned when its task died.
    # `grown=4 reclaimed=4 pages=0` pinned exactly, because the property is
    # conservation rather than a low number — a mechanism that returned three of
    # four pages would still print a small `pages=` if the comparison were an
    # inequality. The frames themselves go with the arena revoke above; this is
    # the page charge, which is the half a revoke cannot see and therefore the
    # half a leak would hide in.
    (
        "every private-memory page was returned on task death",
        r"SLIME_MEM teardown grown=4 reclaimed=4 pages=0",
    ),
    ("both tasks reclaimed", r"SLIME_ROOT cleanup tasks=2 slots=(\d+) live=0"),
    (
        "root reached ready",
        r"SLIME_ROOT READY tasks=2 grants=\d+ declared_grants=\d+ reclaimed_slots=(\d+)",
    ),
)

# Anything here means the slice failed even if a later marker still appeared.
# `SLIME_ROOT FATAL` is the root task's own abort path: it suspends rather than
# exiting, so without matching it here a rejected child image would burn the
# whole boot timeout instead of failing immediately with the reason.
FAILURE_MARKERS: tuple[str, ...] = (
    r"SLIME_ROOT FATAL .*",
    r"SLIME_ROOT \w+ rejected",
    r"SLIME_ROOT closure rejected",
    # A service loop that never reaches its terminal message: a livelock, not
    # a slow child.
    r"SLIME_ROOT service budget exhausted",
    # The child's own panic handler, and the one outcome that would mean
    # isolation genuinely broke: the deliberate store to an unmapped page
    # returned instead of faulting.
    r"SLIME_CHILD panic ",
    r"SLIME_CHILD fault escaped",
    r"seL4 called fail",
    r"Caught cap fault",
    r"Caught vm fault",
    r"Caught user exception",
    # A Rust panic or abort in the root task. `sel4-panicking` prints
    # `PanicInfo` verbatim (`panicked at <loc>:\n<msg>`) and `AbortInfo` as
    # `aborted at <loc>`. The root task suspends rather than exiting, so
    # without these the gate would burn the full timeout on a panic instead of
    # reporting it.
    r"panicked at ",
    r"aborted at ",
    r"\(aborted\)",
    # The bounded timer-proof wait loop (`platform_timer.rs` wired in
    # `main.rs`) hits this instead of hanging when the scheduled IRQ never
    # arrives — e.g. a broken IRQ/notification bind.
    r"SLIME_TIMER FAIL timeout",
    # The shared-buffer phase fails closed: a protection that stopped being
    # enforced, a byte pattern that did not survive the shared frame, an
    # unattributable fault from the probing fixture, or a teardown that left a
    # frame or charge behind all abort here rather than silently omitting a
    # marker. `SLIME_ROOT FATAL` above already catches these, but naming the
    # family explicitly keeps the failure legible in the transcript.
    r"SLIME_BUF FAIL .*",
    r"SLIME_FOUNDATION FAIL .*",
    # The private-memory phase fails closed on the same terms: a growth that
    # was not bounded by the declared quota, a page count the child and the root
    # disagree about, a report missing an observation the phase must make, or a
    # teardown that left a page charged (C10.1).
    r"SLIME_MEM FAIL .*",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"seL4 root boot check: {message}")


def build_image(platform: str) -> None:
    command = [sys.executable, str(BUILD_SCRIPT), "--platform", platform]
    print(f"[build] {' '.join(command)}", flush=True)
    try:
        process = subprocess.run(command, cwd=ROOT, check=False)
    except OSError as error:
        fail(f"cannot run the seL4 image build: {error}")
    if process.returncode != 0:
        fail(f"seL4 image build failed with exit status {process.returncode}")


def required_markers(platform: str) -> tuple[tuple[str, str], ...]:
    """The marker chain this platform's transcript must satisfy.

    One ordered sequence for every platform, with two platform-specific
    adjustments and no others: the W^X verdict line is substituted from
    `WX_PROBES`, and the markers naming an execute-never refusal are dropped
    where the architecture has no such attribute. A platform may differ in what
    a marker says or in whether a mechanism exists at all; it may never differ
    in the order of the mechanisms it does have.
    """
    probes = WX_PROBES[platform]
    enforced = platform in WX_ENFORCED_PLATFORMS
    return tuple(
        (description, pattern.format(wx_probes=probes) if "{wx_probes}" in pattern else pattern)
        for description, pattern in REQUIRED_MARKERS
        if enforced or description not in WX_ENFORCED_MARKERS
    )


def check_transcript(transcript: str, platform: str) -> None:
    for pattern in FAILURE_MARKERS:
        match = re.search(pattern, transcript)
        if match is not None:
            report_transcript(transcript)
            fail(f"failure marker in serial transcript: {match.group(0)!r}")
    position = 0
    for description, pattern in required_markers(platform):
        match = re.compile(pattern).search(transcript, position)
        if match is None:
            report_transcript(transcript)
            if re.search(pattern, transcript) is not None:
                fail(f"marker out of order: {description} ({pattern})")
            fail(f"missing marker: {description} ({pattern})")
        position = match.end()
    timer_match = re.search(r"SLIME_TIMER acquired irq=(\d+) freq_hz=\d+", transcript)
    if timer_match is None or int(timer_match.group(1)) != TIMER_IRQS[platform]:
        fail(
            f"timer IRQ is {timer_match.group(1) if timer_match else 'missing'}, "
            f"expected {TIMER_IRQS[platform]} for {platform}"
        )

    clean = re.search(
        r"SLIME_ROOT task reclaimed task=0 source=generation slots=(\d+) arena=\d+",
        transcript,
    )
    faulted = re.search(
        r"SLIME_ROOT task reclaimed task=1 source=generation slots=(\d+) arena=\d+",
        transcript,
    )
    cleanup = re.search(r"SLIME_ROOT cleanup tasks=2 slots=(\d+) live=0", transcript)
    ready = re.search(r"SLIME_ROOT READY .* reclaimed_slots=(\d+)", transcript)
    if clean is None or faulted is None or cleanup is None or ready is None:
        fail("task reclaim accounting disappeared after marker matching")
    total = int(clean.group(1)) + int(faulted.group(1))
    if total != int(cleanup.group(1)) or total != int(ready.group(1)):
        fail(
            f"task reclaim totals disagree: tasks={total} cleanup={cleanup.group(1)} ready={ready.group(1)}"
        )
    check_private_memory_base(transcript)
    check_ordinary_memory(transcript, platform)


# The physical address the platform's superseded kernel window ended at, and
# therefore the address a capacity probe must pass to prove the raise reached
# the kernel. AArch64 QEMU `virt` places DRAM at 0x4000_0000, so the retired
# 1024 MiB platform ended here. RISC-V `virt` never had a superseded window on
# this lane, and its DRAM base *is* 0x8000_0000 — reusing the ARM bound there
# would sit below every RV64 ordinary address and assert nothing, so RV64
# declares none and the root reports `beyond_legacy=0`. pc99 likewise never had
# one: its ordinary memory comes from the x86 E820/Multiboot map, so it also
# declares none, matching the arm of `TARGET_PROFILE` in `slime-root`.
LEGACY_PLATFORM_RAM_END = {
    "qemu-arm-virt": 0x8000_0000,
    "qemu-riscv-virt": None,
    "qemu-pc99": None,
}


def check_ordinary_memory(transcript: str, platform: str) -> None:
    """The ordinary-memory inventory is the kernel's window, not the launcher's.

    A larger `-m` alone moves no marker here: every range comes from BootInfo,
    which the kernel derives from its own pinned physical description. The
    summary must agree with the enumerated ranges, and the exact page-sized,
    page-aligned probe must be fully contained in the highest range capable of
    holding such a page — which is what a launcher argument cannot manufacture.

    A range is capable only in the bytes the root has not already spent. Before
    it probes, the root may fund its own metadata from the tail of a range and
    report that as `SLIME_BACKING infrastructure_tail`. Such a tail runs to the
    end of exactly one enumerated range, and no frame can come from it.
    """
    ranges = [
        (int(paddr, 16), int(size))
        for paddr, size in re.findall(
            r"SLIME_ROOT ordinary range=\d+ paddr=(0x[0-9a-f]+) bytes=(\d+)", transcript
        )
    ]
    summary = re.search(
        r"SLIME_ROOT ordinary ranges=(\d+) bytes=(\d+) end=(0x[0-9a-f]+)", transcript
    )
    probe = re.search(
        r"SLIME_ROOT ordinary probe paddr=(0x[0-9a-f]+) bytes=(\d+) "
        r"beyond_legacy=([01]) verified=1",
        transcript,
    )
    if not ranges or summary is None or probe is None:
        fail("the ordinary-memory inventory disappeared after marker matching")
    if int(summary.group(1)) != len(ranges):
        fail(
            f"ordinary inventory reports {summary.group(1)} range(s) but enumerated {len(ranges)}"
        )
    if int(summary.group(2)) != sum(size for _, size in ranges):
        fail("ordinary inventory byte total disagrees with the enumerated ranges")
    expected_end = max(paddr + size for paddr, size in ranges)
    if int(summary.group(3), 16) != expected_end:
        fail(
            f"ordinary inventory end is {summary.group(3)}, "
            f"expected {expected_end:#x} from the enumerated ranges"
        )
    # A tail the root reports before the probe shortens the free part of its
    # range. Each tail must end where one enumerated range ends and start after
    # that range starts; a tail reported after the probe excuses nothing.
    free_end = {paddr: paddr + size for paddr, size in ranges}
    range_by_end = {paddr + size: paddr for paddr, size in ranges}
    for tail_paddr, tail_bytes in re.findall(
        r"SLIME_BACKING infrastructure_tail parent=\d+ paddr=(\d+) bytes=(\d+)",
        transcript[: probe.start()],
    ):
        tail_start = int(tail_paddr)
        tail_end = tail_start + int(tail_bytes)
        owner = range_by_end.get(tail_end)
        if owner is None or not owner < tail_start < tail_end:
            fail(
                f"the infrastructure tail {tail_start:#x}..{tail_end:#x} is not the "
                f"tail of one enumerated ordinary range"
            )
        if free_end[owner] != tail_end:
            fail(f"the ordinary range at {owner:#x} reports two infrastructure tails")
        free_end[owner] = tail_start
    # The root allocates one seL4 base-page granule from the highest range that
    # can place that complete, aligned object. The inventory's own tail may be
    # a run of sub-page descriptors the kernel publishes for leftover bytes;
    # those are ordinary memory, but cannot be retyped into this frame.
    granule_bytes = 4096
    probe_paddr = int(probe.group(1), 16)
    probe_bytes = int(probe.group(2))
    if probe_bytes != granule_bytes:
        fail(
            f"the ordinary probe reports {probe_bytes} bytes, expected exactly "
            f"one {granule_bytes}-byte frame"
        )
    if probe_paddr % granule_bytes != 0:
        fail(f"the ordinary probe address {probe.group(1)} is not granule-aligned")

    def can_hold_granule(paddr: int) -> bool:
        aligned = (paddr + granule_bytes - 1) & -granule_bytes
        return aligned + granule_bytes <= free_end[paddr]

    capable = [paddr for paddr, _ in ranges if can_hold_granule(paddr)]
    if not capable:
        fail(f"no admitted ordinary range can hold a {granule_bytes}-byte frame")
    highest = max(capable)
    highest_end = free_end[highest]
    if probe_paddr < highest or probe_paddr + probe_bytes > highest_end:
        fail(
            f"the probe frame {probe.group(1)}..{probe_paddr + probe_bytes:#x} is not "
            f"fully contained in the highest granule-capable range "
            f"{highest:#x}..{highest_end:#x}"
        )
    legacy_end = LEGACY_PLATFORM_RAM_END[platform]
    expected_beyond = "0" if legacy_end is None else "1"
    if probe.group(3) != expected_beyond:
        fail(
            f"{platform} reported beyond_legacy={probe.group(3)}, expected {expected_beyond}"
        )
    if legacy_end is not None and probe_paddr < legacy_end:
        fail(
            f"the probe took {probe.group(1)}, which the superseded "
            f"{legacy_end:#x} platform already contained"
        )
    for line in transcript.splitlines():
        if line.startswith("SLIME_ROOT ordinary "):
            print(line)


def check_private_memory_base(transcript: str) -> None:
    """Every private-memory record names the same window base (C10.1).

    The base itself is not pinned — it derives from the fixture image's own
    footprint, so pinning it would make every child recompilation a gate edit.
    What must hold is that it never moves: native component images link at fixed
    virtual addresses and hold real machine pointers, so a growth that relocated
    the base would invalidate every one of them.

    Checked here rather than by a backreference in `REQUIRED_MARKERS`, because
    each of those patterns is compiled separately and a group in one cannot be
    referenced from another.

    Three sets are collected, and the third is what makes this more than a
    consistency check on printed numbers: the root's record of what it mapped,
    the base the child was *answered*, and the base the child actually
    *dereferenced* for its zero read and its pattern readback. Without the
    third, a root that answered one address while mapping another would produce
    a transcript indistinguishable from a correct one.
    """
    root_bases = re.findall(r"SLIME_MEM grown task=0 .*? base=(0x[0-9a-f]+)", transcript)
    child_bases = re.findall(r"SLIME_CHILD mem (?:query|grew) .*? base=(0x[0-9a-f]+)", transcript)
    dereferenced = re.findall(r"SLIME_CHILD mem (?:read|pattern) base=(0x[0-9a-f]+)", transcript)
    # Four `grown` records from the phase's five operations: two size queries
    # and two growths each answer a base, while the refused one reports
    # `SLIME_MEM refused` and no base at all. Counted rather than merely
    # collected, so a phase that silently stopped issuing an operation cannot
    # pass this by leaving a consistent smaller set.
    if len(root_bases) != 4:
        fail(f"expected 4 private-memory growth records, found {len(root_bases)}")
    if len(child_bases) != 3:
        fail(f"expected 3 child private-memory base records, found {len(child_bases)}")
    if len(dereferenced) != 2:
        fail(
            "expected 2 child records naming a dereferenced private-memory address, "
            f"found {len(dereferenced)}"
        )
    observed = set(root_bases) | set(child_bases) | set(dereferenced)
    if len(observed) != 1:
        fail(f"the private-memory window base moved across records: {sorted(observed)}")
    base = int(observed.pop(), 16)
    if base == 0:
        fail("the private-memory window base is zero, which is never a mapped child address")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Boot the pinned standalone Slime seL4 image and assert ordered markers"
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="boot the already-built image instead of rebuilding it first",
    )
    parser.add_argument(
        "--platform",
        choices=sorted(PLATFORMS),
        default="qemu-arm-virt",
        help="the pinned QEMU profile and image to build and boot",
    )
    arguments = parser.parse_args()

    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    image_path, manifest_path = artifact_paths(arguments.platform)
    if not arguments.no_build:
        build_image(arguments.platform)
    manifest = verify_identity(
        manifest_path,
        platform=arguments.platform,
        variant=None,
        image_path=image_path,
        fail=fail,
    )
    transcript = run_boot(
        boot_command(
            manifest,
            platform=arguments.platform,
            image_path=image_path,
            fail=fail,
        ),
        terminal=re.compile(
            required_markers(arguments.platform)[-1][1] + "|" + "|".join(FAILURE_MARKERS)
        ),
        timeout=BOOT_TIMEOUT_SECONDS,
        fail=fail,
    )
    check_transcript(transcript, arguments.platform)
    print(
        "seL4 root boot check: ordered generation, timer, task, IPC, fault, and "
        f"ready markers observed on the pinned {arguments.platform} profile"
    )


if __name__ == "__main__":
    main()
