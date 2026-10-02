#!/usr/bin/env python3
"""Prove seL4 gates fail closed when evidence or shared execution breaks.

Marker controls synthesize each gate's declared evidence, then delete, reorder,
or poison it. Runtime controls call ``sel4_plane`` directly with temporary images,
identity manifests, pins, and QEMU executables. Product gates retain ownership of
their concrete boot claims; this checker proves the mechanisms enforcing those
claims reject invalid inputs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import sys as _sys
import tempfile
from collections.abc import Callable
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

from harness import ROOT, load_script  # noqa: E402
from sel4_gate_markers import chains_from_gate, match_marker_contract  # noqa: E402
from sel4_plane import run_plane, verify_image_identity  # noqa: E402

# Counts are pinned rather than derived so deleting a required marker cannot
# silently weaken a gate. Boot-layout fixture equality is controlled separately.
GATES: tuple[tuple[str, str, int], ...] = (
    ("sel4_channel_plane", "check/check-sel4-channel-plane.py", 18),
    ("sel4_io_network_plane", "check/check-sel4-io-network-plane.py", 218),
    ("sel4_component_graph", "check/check-sel4-component-graph.py", 109),
    ("sel4_crossing_plane", "check/check-sel4-crossing-plane.py", 10),
    ("sel4_loan_plane", "check/check-sel4-loan-plane.py", 46),
    ("sel4_io_queue_plane", "check/check-sel4-io-queue-plane.py", 15),
    ("sel4_io_link_plane", "check/check-sel4-io-link-plane.py", 28),
    ("sel4_io_driver_authority_plane", "check/check-sel4-io-driver-authority-plane.py", 16),
    ("sel4_device_plane", "check/check-sel4-device-plane.py", 2),
    ("sel4_root_boot", "check/check-sel4-root-boot.py", 59),
    ("sel4_sample_plane", "check/check-sel4-sample-plane.py", 25),
    ("sel4_spawn_plane", "check/check-sel4-spawn-plane.py", 27),
    ("sel4_supervision_plane", "check/check-sel4-supervision-plane.py", 12),
    # 54 existing markers plus 6 cspace, 12 metadata and 14 bootstrap markers,
    # 12 elastic, 12 fragmentation, 13 rollback and 7 conservation markers, one
    # order-independent marker, and MEM-ADAPTIVE's 31: 4 reserve-first policy and
    # binding markers, 5 denial/duplicate-incarnation markers, 6 schedule
    # markers, 6 restart markers, 4 omitted-subject markers and 6 survival and
    # completion markers. The over-guaranteed negative composition's chain is
    # deliberately *not* counted here: its terminal is a `SLIME_MEM FAIL` line
    # that every other arm vetoes, so a synthetic transcript carrying both would
    # contradict itself. It is controlled by `check_private_adaptive_controls`.
    ("sel4_private_memory_plane", "check/check-sel4-private-memory-plane.py", 161),
    ("sel4_clock_authority_plane", "check/check-sel4-clock-authority-plane.py", 19),
    # The device-present boot only; the device-less boot's chains contradict its
    # hardware draws and are controlled by the gate's own mutations.
    ("sel4_entropy_plane", "check/check-sel4-entropy-plane.py", 17),
    ("sel4_wait_set_plane", "check/check-sel4-wait-set-plane.py", 15),
    ("sel4_scheduling_class_plane", "check/check-sel4-scheduling-class-plane.py", 25),
    ("sel4_lifecycle_restart_plane", "check/check-sel4-lifecycle-restart-plane.py", 66),
    ("sel4_replay_plane", "check/check-sel4-replay-plane.py", 29),
    ("sel4_robot_runtime_plane", "check/check-sel4-robot-runtime-plane.py", 45),
    ("sel4_stream_plane", "check/check-sel4-stream-plane.py", 57),
    ("sel4_qos_plane", "check/check-sel4-qos-plane.py", 14),
    # Only the demo slice arm exposes CHAINS; wrong-target and rollback use
    # separate validators owned by that checker.
    ("sel4_demo_plane", "check/check-sel4-demo-plane.py", 29),
    ("sel4_trace_plane", "check/check-sel4-trace-plane.py", 6),
    ("sel4_call_plane", "check/check-sel4-call-plane.py", 47),
    ("sel4_operation_plane", "check/check-sel4-operation-plane.py", 53),
    ("sel4_visibility_plane", "check/check-sel4-visibility-plane.py", 26),
    ("sel4_matrix_plane", "check/check-sel4-matrix-plane.py", 26),
    ("sel4_traffic_plane", "check/check-sel4-traffic-plane.py", 10),
    ("sel4_saturation_plane", "check/check-sel4-saturation-plane.py", 10),
    ("sel4_fault_plane", "check/check-sel4-fault-plane.py", 10),
    ("sel4_boot_plane", "check/check-sel4-boot-plane.py", 30),
    ("sel4_io_block_plane", "check/check-sel4-io-block-plane.py", 10),
    ("sel4_storage_plane", "check/check-sel4-storage-plane.py", 12),
    ("sel4_store_plane", "check/check-sel4-store-plane.py", 17),
    ("sel4_rollback_plane", "check/check-sel4-rollback-plane.py", 19),
    ("sel4_recovery_plane", "check/check-sel4-recovery-plane.py", 12),
    ("sel4_generation_plane", "check/check-sel4-generation-plane.py", 21),
    ("sel4_directory_plane", "check/check-sel4-directory-plane.py", 16),
    ("sel4_filesystem_plane", "check/check-sel4-filesystem-plane.py", 14),
    ("sel4_input_plane", "check/check-sel4-input-plane.py", 7),
    ("sel4_powerbox_plane", "check/check-sel4-powerbox-plane.py", 11),
    ("sel4_transfer_plane", "check/check-sel4-transfer-plane.py", 12),
    ("rpi5_boot", "check/check-rpi5-boot.py", 11),
)


def fail(message: str) -> None:
    raise SystemExit(f"seL4 gate control check: {message}")


def literal_for(pattern: str) -> str:
    """One concrete line that satisfies `pattern`.

    The marker tables are regexes over serial output, so a synthetic transcript
    has to instantiate them. Only the constructs the tables actually use are
    handled, and anything else is a hard error rather than a silent skip — a
    control that quietly stopped covering a marker would be worse than no control.
    """
    text = pattern
    # Anchors and whitespace-tolerance constructs carry no content.
    text = text.replace(r"\s+", " ").replace(r"\s*", "")
    text = text.replace("^", "").replace("$", "")
    # Multi-line marker contracts spell transcript newlines as regex `\n`.
    # Materialize them before escaped-literal parking so the synthetic evidence
    # is the same byte sequence the gate searches.
    text = text.replace(r"\n", "\n")
    text = text.replace("-?", "-")
    # Character classes and repetitions, narrowest first.
    #
    # Bounded repetition over the two digit classes the marker tables use, plus a
    # single literal character. It comes before the open-ended forms because
    # `[0-9a-f]+` would otherwise consume the class before its count was seen,
    # leaving a stray `{16}` no instantiation satisfies. Escaped shorthands such
    # as `\d{4}` are deliberately not handled: no marker table uses one, and the
    # round-trip check below fails loudly rather than silently if one appears.
    def repeat(match: re.Match[str]) -> str:
        return match.group(1) * int(match.group(2))

    text = re.sub(r"\[0-9a-f\]\{(\d+)\}", lambda m: "a" * int(m.group(1)), text)
    text = re.sub(r"\[0-9\]\{(\d+)\}", lambda m: "7" * int(m.group(1)), text)
    text = re.sub(r"(\w)\{(\d+)\}", repeat, text)
    # Lowercase-with-hyphen words: worker and family names in the trace tables.
    text = re.sub(r"\[a-z-\]\+", "stream", text)
    text = re.sub(r"\[0-9a-fx\]\+", "0x10", text)
    text = re.sub(r"\[0-9a-f\]\+", "abc123", text)
    text = re.sub(r"\[\^ \]\+", "value", text)
    # An enumerated digit class such as `[01]`: a marker whose field is a small
    # closed set rather than an open-ended number. Matched before the ranged
    # classes below because those all contain a hyphen and cannot collide, and
    # the first member is as valid an instantiation as any other.
    text = re.sub(r"\[(\d+)\]", lambda m: m.group(1)[0], text)
    # `[1-9]\d*` and friends: a non-zero digit followed by optional digits.
    text = re.sub(r"\[1-9\]\\d\*", "7", text)
    text = re.sub(r"\[1-9\]", "7", text)
    text = re.sub(r"\[0-9\]\+", "7", text)
    text = re.sub(r"\\d\*", "7", text)
    text = re.sub(r"\\d\+", "7", text)
    text = re.sub(r"\\d", "7", text)
    # Backreferences hold two fields equal, which is the assertion rather than
    # decoration -- `required=(\d+) live=\1` says a healthy graph has every
    # required instance live. Replaying the group's own instantiated text keeps
    # that true in the synthetic line; dropping it would emit a literal `\1`
    # and fail the round-trip check below.
    groups = re.findall(r"\((?!\?)([^()]*)\)", text)
    for index, group in enumerate(groups, start=1):
        text = text.replace(f"\\{index}", group)
    text = re.sub(r"\\w\+", "word", text)
    text = re.sub(r"\.\+", "text", text)
    text = re.sub(r"\.\*", "", text)
    # Zero-width lookarounds constrain neighbours, not content.
    text = re.sub(r"\(\?[!=][^()]*\)", "", text)
    # Alternations inside a group: take the first branch, non-capturing first so
    # its `?:` does not survive into the capturing rule below.
    text = re.sub(r"\(\?:([^()|]*)\|[^()]*\)", r"\1", text)
    text = re.sub(r"\(([^()|]*)\|[^()]*\)", r"\1", text)
    # A digit range left by that first branch, e.g. `3[3-9]`.
    text = re.sub(r"\[(\d)-\d\]", r"\1", text)
    # Escaped literals are parked as sentinels first, so `\(aborted\)` keeps its
    # parentheses instead of losing them to the group-unwrapping below.
    parked: list[str] = []

    def park(match: re.Match[str]) -> str:
        parked.append(match.group(1))
        return f"\x01{len(parked) - 1}\x02"

    text = re.sub(r"\\([-\[\]().*+?{}|^$/\\])", park, text)
    # Remaining group wrappers, now unambiguous.
    text = text.replace("(?:", "(")
    text = re.sub(r"\((.*?)\)", r"\1", text)
    for index, literal in enumerate(parked):
        text = text.replace(f"\x01{index}\x02", literal)
    if re.search(pattern, text) is None:
        fail(f"cannot instantiate marker pattern: {pattern!r} -> {text!r}")
    return text


def required_of(gate) -> tuple[tuple[str, str], ...]:
    """Flatten declarations for synthesis and count pins, not matching."""
    return tuple(
        (f"{label}: {pattern}", pattern)
        for label, chain in chains_from_gate(gate)
        for pattern in chain
    )


def transcript_for(gate) -> str:
    lines = [literal_for(pattern) for _, pattern in required_of(gate)]
    return "\n".join(lines) + "\n"


def boot_plane_transcript(gate, marker_transcript: str) -> str:
    """Add the structural composition evidence required by the boot-plane gate.

    Init is the sole spawning parent. The three chain positions divide its child
    sequence, so each required spawn marker must be expanded with the preceding
    siblings instead of emitting the full sequence at the first position.
    """
    lines = marker_transcript.splitlines()
    children = list(gate.EXPECTED_INIT_CHILDREN)
    service_at = children.index("fabric-service")
    call_worker_at = children.index("fabric-call-worker")
    slices = {
        "component=fabric-service ": children[: service_at + 1],
        "component=fabric-call-worker ": children[service_at + 1 : call_worker_at + 1],
        "component=fabric-op-worker ": children[call_worker_at + 1 :],
    }

    def spawn_line(index: int, component: str) -> str:
        return (
            f"SLIME_GRAPH spawned task=0 child={201 + index} component={component} "
            "grants=1 endpoints=1 notifications=0 handle=1"
        )

    expanded: list[str] = []
    cursor = 0
    for line in lines:
        needle = next((key for key in slices if key in line), None)
        if needle is None:
            expanded.append(line)
            continue
        for component in slices[needle]:
            expanded.append(spawn_line(cursor, component))
            cursor += 1
    # Only components the gate's *own, unmutated* CHAINS declaration does not
    # already require an idle-without-role line for: chain 4/5 name nine of
    # the ten in causal order (readiness before each participant's own
    # marker). Derived from `gate.CHAINS` rather than from `lines` — `lines`
    # is this call's possibly-*mutated* transcript, and computing the filter
    # from it would silently re-add whichever marker the deletion mutation
    # below just removed, defeating the very test that removal drives. Only
    # `fabric-proxy` is absent from every chain.
    chain_literals = {
        literal_for(pattern) for _, chain in chains_from_gate(gate) for pattern in chain
    }
    extra_idle = [
        component
        for component in gate.EXPECTED_IDLE_WITHOUT_ROLE
        if f"[{component}] boot idle without a role" not in chain_literals
    ]
    expanded.extend(
        [
            "[layout] path=init slots=1 max=64",
            "[layout] 1 endpoint control",
            *(f"[{component}] boot role provisioned" for component in gate.EXPECTED_ROLE_HOLDERS),
            *gate.EXPECTED_PROVISIONED_EDGES,
            *(f"[{component}] boot idle without a role" for component in extra_idle),
            # `check_transcript` requires exactly one healthy-supervisor
            # terminal, but `TERMINAL_MARKER` is not in `REQUIRED_MARKERS`, so
            # the marker synthesis never produces one. Instantiated from the
            # gate's own pattern rather than written out here, so a change to
            # it cannot leave this stale.
            literal_for(gate.TERMINAL_MARKER),
        ]
    )
    return "\n".join(expanded) + "\n"


def marker_check(gate, transcript: str) -> None:
    """Invoke the exact matcher used by chain-aware product gates."""
    match_marker_contract(
        transcript,
        chains_from_gate(gate),
        gate.FAILURE_MARKERS,
        lambda message: (_ for _ in ()).throw(SystemExit(message)),
    )


def rejects(gate, transcript: str) -> bool:
    """True when the product gate refuses this transcript."""
    try:
        if gate.__name__ == "sel4_boot_plane":
            gate.check_transcript(transcript)
        else:
            marker_check(gate, transcript)
    except SystemExit:
        return True
    return False


def check_gate(name: str, relative_path: str, expected_required: int) -> int:
    gate = load_script(name, relative_path)
    required = required_of(gate)
    failures = getattr(gate, "FAILURE_MARKERS", ())
    if len(required) != expected_required:
        fail(
            f"{name}: declares {len(required)} required markers, expected "
            f"{expected_required}. A gate that lost a marker lost coverage; "
            "update the pin here only alongside the gate change that justifies it"
        )
    chains = chains_from_gate(gate)
    if not any(len(patterns) >= 2 for _, patterns in chains):
        fail(f"{name}: no causal chain has two markers, nothing to transpose")
    if not failures:
        fail(f"{name}: no failure markers declared")

    marker_baseline = transcript_for(gate)

    def complete(text: str) -> str:
        return boot_plane_transcript(gate, text) if name == "sel4_boot_plane" else text

    baseline = complete(marker_baseline)
    if rejects(gate, baseline):
        fail(
            f"{name}: rejected a transcript built from its own REQUIRED_MARKERS; "
            "the control cannot distinguish a real absence from its own synthesis"
        )

    lines = marker_baseline.splitlines()

    # Delete every occurrence of the selected concrete marker. A regex shared by
    # two chains may legitimately use either occurrence, so deleting only one
    # physical line is not evidence removal; deleting them all is.
    evaluated = 0
    for index, removed in enumerate(lines):
        without = "\n".join(line for line in lines if line != removed) + "\n"
        if not rejects(gate, complete(without)):
            description = required[index][0]
            fail(f"{name}: accepted a transcript missing all evidence for {description!r}")
        evaluated += 1

    offset = 0
    for _label, patterns in chains:
        if len(patterns) >= 2:
            first = lines[offset]
            second = lines[offset + 1]
            insertion = next(
                index for index, line in enumerate(lines) if line == first or line == second
            )
            remaining = [line for line in lines if line != first and line != second]
            transposed_lines = remaining[:insertion] + [second, first] + remaining[insertion:]
            transposed = "\n".join(transposed_lines) + "\n"
            if not rejects(gate, complete(transposed)):
                fail(f"{name}: accepted the first two markers of a causal chain out of order")
            evaluated += 1
        offset += len(patterns)

    # A failure marker must veto an otherwise-complete transcript.
    for pattern in failures:
        poisoned = baseline + literal_for(pattern) + "\n"
        if not rejects(gate, poisoned):
            fail(f"{name}: accepted a transcript containing failure marker {pattern!r}")

    if name == "sel4_boot_plane":
        baseline_lines = baseline.splitlines()
        idle = literal_for(r"\[fabric\] idle: parked on control endpoints")
        terminal = literal_for(gate.TERMINAL_MARKER)
        if idle not in baseline_lines or terminal not in baseline_lines:
            fail(f"{name}: synthetic transcript lacks its idle or healthy supervisor marker")
        terminal_index = baseline_lines.index(terminal)
        early_idle_then_exit = "\n".join(
            [
                *baseline_lines[:terminal_index],
                idle,
                "SLIME_GRAPH component exit task=17 status=-9",
                *baseline_lines[terminal_index:],
            ]
        ) + "\n"
        if not rejects(gate, early_idle_then_exit):
            fail(
                f"{name}: accepted early fabric idle followed by nonzero component exit "
                "before the healthy supervisor terminal"
            )
        nonzero_exit = next(
            pattern for pattern in failures if pattern.startswith("SLIME_GRAPH component exit")
        )
        if re.search(nonzero_exit, "SLIME_GRAPH component exit task=17 status=0"):
            fail(f"{name}: generic nonzero-exit failure marker also matches status zero")
        for status in ("7", "-9"):
            if re.search(
                nonzero_exit, f"SLIME_GRAPH component exit task=17 status={status}"
            ) is None:
                fail(f"{name}: generic nonzero-exit failure marker misses status {status}")
        evaluated += 1

    return evaluated + len(failures)


def check_http_evidence_controls() -> int:
    """Body equality, byte accounting and cleanup cannot be replaced by markers."""
    gate = load_script("sel4_http_evidence_controls", "check/check-sel4-io-network-plane.py")
    case = gate.http_peer.cases()[0]
    body = "".join(
        "[http-get] body hex=" + case.body[offset:offset + 64].hex() + "\n"
        for offset in range(0, len(case.body), 64)
    )
    cleanup = "[http-get] cleanup close=1 detach=1\n"
    completion = f"[http-get] complete success=1 status=200 bytes={len(case.body)} error=none\n"
    baseline = body + cleanup + completion
    if gate.check_http_body(baseline, case) != (200, len(case.body)):
        fail("HTTP validator rejected its independent body baseline")
    mutations = (
        ("wrong body", baseline.replace("hex=0b", "hex=0c", 1)),
        ("wrong byte count", baseline.replace("bytes=12289", "bytes=12288")),
        ("missing cleanup", baseline.replace(cleanup, "")),
        ("failed cleanup", baseline.replace("detach=1", "detach=0")),
        ("missing completion", baseline.replace(completion, "")),
        ("duplicate completion", baseline + completion),
        ("body after completion", baseline + body),
        ("completion before cleanup", body + completion + cleanup),
        ("odd hex body", baseline.replace("hex=0b", "hex=b", 1)),
        ("oversized body record", "[http-get] body hex=" + "aa" * 65 + "\n" + cleanup + completion),
        ("false success", baseline.replace("success=1", "success=0")),
        ("wrong status", baseline.replace("status=200", "status=404")),
    )
    for description, transcript in mutations:
        try:
            gate.check_http_body(transcript, case)
        except SystemExit:
            continue
        fail(f"HTTP evidence accepted {description}")
    failure_case = next(case for case in gate.http_peer.cases() if case.name == "url-scheme")
    aborted = "[http-get] cleanup close=0 detach=1 abort=1\n[http-get] complete success=0 status=0 bytes=0 error=url\n"
    gate.check_http_body(aborted, failure_case)
    for bad in (aborted.replace("detach=1", "detach=0"), aborted.replace(" abort=1", ""), aborted.replace("error=url", "error=none")):
        try:
            gate.check_http_body(bad, failure_case)
        except SystemExit:
            continue
        fail("HTTP abort evidence accepted absent/failed abort acknowledgment")
    count = len(mutations) + 3
    print(f"seL4 gate control check: HTTP body/status/cleanup rejected {count} mutations")
    return count


def check_http_capture_controls() -> int:
    """Synthetic packets test the observer; only QEMU qualifies actual HTTP."""
    gate = load_script("sel4_http_capture_controls", "check/check-sel4-io-network-plane.py")
    peer, capture = gate.link_peer, gate.http_capture
    guest, server = bytes([10, 0, 2, 15]), bytes([10, 0, 2, 2])
    query = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x07example\x04test\0\0\x01\0\x01"

    def frame(source: bytes, destination: bytes, protocol: int, payload: bytes) -> bytes:
        return peer.ethernet(b"\x52\x54\0\0\0\x02", b"\x52\x54\0\0\0\x01", 0x0800,
                             peer.ipv4(source, destination, protocol, payload))

    def udp(source: bytes, destination: bytes, source_port: int, destination_port: int, packet: bytes) -> bytes:
        return frame(source, destination, 17, struct.pack("!HHHH", source_port, destination_port, 8 + len(packet), 0) + packet)

    outgoing = udp(guest, server, 53000, 1053, query)
    syn = frame(guest, server, 6, peer.tcp(guest, server, 54000, 18080, 123, 0, peer.TCP_SYN))

    def encoded(frames: list[bytes], endian: str = "<") -> bytes:
        return struct.pack(endian + "IHHiiII", 0xA1B2C3D4, 2, 4, 0, 0, 65536, 1) + b"".join(
            struct.pack(endian + "IIII", index + 1, 0, len(packet), len(packet)) + packet
            for index, packet in enumerate(frames)
        )

    def verify(data: bytes, *, connect: bool = True):
        return capture.verify_capture(data, hostname="example.test", resolver=("10.0.2.2", 1053),
                                      port=18080, expected_destination="10.0.2.2", expect_connect=connect)

    for mode in ("a", "cname"):
        answer = gate.http_peer.dns_response(query, query[12:], mode)
        incoming = udp(server, guest, 1053, 53000, answer)
        for endian in ("<", ">"):
            verify(encoded([outgoing, incoming, syn], endian))
    normal = gate.http_peer.dns_response(query, query[12:], "a")
    incoming = udp(server, guest, 1053, 53000, normal)
    mutations = [
        b"", encoded([]), encoded([outgoing, incoming, syn])[:-1],
        encoded([outgoing, incoming, syn]) + b"x", encoded([outgoing, syn]),
        encoded([incoming, outgoing, syn]),
        encoded([outgoing, udp(server, guest, 1054, 53000, normal), syn]),
        encoded([outgoing, udp(server, guest, 1053, 53001, normal), syn]),
    ]
    for mode in ("nxdomain", "truncated", "loop", "mismatched-id", "forbidden", "wrong-question", "excessive-records", "excessive-aliases", "zero-ttl"):
        answer = udp(server, guest, 1053, 53000, gate.http_peer.dns_response(query, query[12:], mode))
        verify(encoded([outgoing, answer]), connect=False)
        mutations.append(encoded([outgoing, answer, syn]))
    capture.verify_capture(encoded([]), hostname=None, resolver=("10.0.2.2", 1053), port=18080,
                           expect_connect=False, expect_no_application_traffic=True)
    for data in mutations:
        try:
            verify(data)
        except ValueError:
            continue
        fail("HTTP packet observer accepted corrupted or unbound DNS/TCP evidence")
    for data in (encoded([outgoing]), encoded([syn]), encoded([])[:-1]):
        try:
            capture.verify_capture(data, hostname=None, resolver=("10.0.2.2", 1053), port=18080,
                                   expect_connect=False, expect_no_application_traffic=True)
        except ValueError:
            continue
        fail("HTTP no-application-traffic control accepted packets or a malformed capture")
    count = len(mutations) + 3
    print(f"seL4 gate control check: independent HTTP/DNS packet observer rejected {count} mutations")
    return count


def check_root_memory_runtime_control() -> int:
    """A larger launcher alone cannot manufacture kernel-visible high RAM.

    Driven against `check_ordinary_memory`, which is where the claim lives: the
    marker table can only say the fields are well-formed, while the validator
    is what ties the summary to the enumerated ranges, the probe to the highest
    granule-capable range, and `beyond_legacy` to the platform's own superseded
    window. Each mutation below is a way a `-m`-only change or a regressed
    validator would read as success.
    """
    gate = load_script("sel4_root_boot_memory_control", "check/check-sel4-root-boot.py")
    # An ARM inventory in the shape the kernel publishes: ascending ranges with
    # real page-sized/aligned frame-capable extents plus a final sub-page tail.
    # The addresses are the observed qemu-arm-virt ones.
    ranges = (
        (0x6000_0000, 16 * 4096),
        (0x8000_0000, 131072 * 4096),
        (0xBF94_8000, 2 * 4096),
        (0xBF94_BF00, 256),
    )

    def inventory(
        entries: tuple[tuple[int, int], ...],
        probe_paddr: int = 0xBF94_8000,
        probe_bytes: int = 4096,
        beyond_legacy: int = 1,
    ) -> str:
        records = [
            f"SLIME_ROOT ordinary range={index} paddr={paddr:#x} bytes={size}"
            for index, (paddr, size) in enumerate(entries)
        ]
        records.append(
            f"SLIME_ROOT ordinary ranges={len(entries)} "
            f"bytes={sum(size for _, size in entries)} "
            f"end={max(paddr + size for paddr, size in entries):#x}"
        )
        records.append(
            f"SLIME_ROOT ordinary probe paddr={probe_paddr:#x} bytes={probe_bytes} "
            f"beyond_legacy={beyond_legacy} verified=1"
        )
        return "\n".join(records) + "\n"

    baseline = inventory(ranges)

    def rejects_inventory(transcript: str, platform: str = "qemu-arm-virt") -> bool:
        try:
            gate.check_ordinary_memory(transcript, platform)
        except SystemExit:
            return True
        return False

    if rejects_inventory(baseline):
        fail("sel4_root_boot: rejected its synthesized ordinary-memory baseline")
    mutations = (
        (
            "a probe that never left the range the superseded platform contained",
            inventory(ranges, probe_paddr=0x6000_0000),
        ),
        (
            "a probe reporting it stayed inside the legacy window",
            inventory(ranges, beyond_legacy=0),
        ),
        (
            "a zero-byte probe placed in the inventory's sub-page tail",
            inventory(ranges, probe_paddr=0xBF94_BF00, probe_bytes=0),
        ),
        (
            "a page-sized probe with a misaligned physical address",
            inventory(ranges, probe_paddr=0xBF94_8001),
        ),
        (
            "an aligned page-sized probe extending past its selected range",
            inventory(
                (*ranges[:2], (0xBF94_8000, 6144), ranges[3]),
                probe_paddr=0xBF94_9000,
            ),
        ),
        (
            "a summary claiming an end no enumerated range reaches",
            baseline.replace("end=0xbf94c000", "end=0x100000000"),
        ),
        (
            "a summary byte total that does not sum its ranges",
            baseline.replace(
                f"bytes={sum(size for _, size in ranges)} end=", "bytes=2147483648 end="
            ),
        ),
        (
            "a summary counting ranges the transcript never enumerated",
            baseline.replace(f"ranges={len(ranges)} ", "ranges=34 "),
        ),
        (
            "the whole inventory deleted while the probe line remains",
            "\n".join(
                line for line in baseline.splitlines() if "ordinary range=" not in line
            )
            + "\n",
        ),
    )
    for description, mutated in mutations:
        if not rejects_inventory(mutated):
            fail(f"sel4_root_boot: accepted {description}")
    # The same evidence read as RISC-V, whose DRAM base *is* the ARM legacy end:
    # a platform with no superseded window must not be credited with crossing
    # one, or `beyond_legacy` would be true by arithmetic rather than by RAM.
    if not rejects_inventory(baseline, "qemu-riscv-virt"):
        fail(
            "sel4_root_boot: credited qemu-riscv-virt with passing a superseded "
            "window it never had"
        )
    print(
        "seL4 gate control check: root memory evidence rejected "
        f"{len(mutations) + 1} launcher-only and inventory mutations"
    )
    return len(mutations) + 1


def check_layout_gate() -> int:
    """The boot-layout gate's structural validator, driven with broken fixtures.

    That gate's claim is fixture *equality*, so it has no marker table to mutate.
    But it also runs `check_shape` over every captured layout before comparing,
    and that validator has properties worth guarding: a header, a terminator,
    well-formed rows, a declared count matching the rows carried, and ascending
    slot numbers. Each is driven here from a real blessed fixture, so a
    `check_shape` that stopped enforcing one would be caught without a boot.
    """
    gate = load_script("sel4_boot_layout", "check/check-sel4-boot-layout.py")
    fixture = (
        ROOT / "contracts" / "boot-layout" / "v1" / "fixtures" / "sel4-channel.layout"
    )
    if not fixture.is_file():
        fail(f"missing blessed fixture: {fixture}")
    baseline = fixture.read_text(encoding="utf-8")

    def rejects_shape(text: str) -> bool:
        try:
            gate.check_shape("control", text)
        except SystemExit:
            return True
        return False

    if rejects_shape(baseline):
        fail("boot-layout gate rejected its own blessed fixture")

    lines = baseline.splitlines()
    mutations: tuple[tuple[str, str], ...] = (
        ("header removed", "\n".join(lines[1:]) + "\n"),
        ("terminator removed", "\n".join(lines[:-1]) + "\n"),
        (
            # Derive the mutation from the fixture so a layout-size change cannot
            # turn the control into a no-op.
            "declared count disagrees with the rows carried",
            re.sub(
                r"slots=(\d+)",
                lambda match: f"slots={int(match.group(1)) + 1}",
                baseline,
                count=1,
            ),
        ),
        (
            # Removing the first row's slot number is malformed for every layout
            # shape and does not depend on a particular blessed slot.
            "row is malformed",
            re.sub(r"\[layout\] \d+ ", "[layout] ", baseline, count=1),
        ),
        (
            "slot numbers descend",
            "\n".join([lines[0], lines[2], lines[1], *lines[3:]]) + "\n",
        ),
    )
    for description, text in mutations:
        if not rejects_shape(text):
            fail(f"boot-layout gate accepted a layout whose {description}")
    return len(mutations)

class ControlRejection(Exception):
    pass


def reject_control(message: str) -> None:
    raise ControlRejection(message)


def require_rejection(
    description: str, expected_message: str, action: Callable[[], object]
) -> None:
    try:
        action()
    except ControlRejection as error:
        if expected_message not in str(error):
            fail(f"{description} was rejected for the wrong reason: {error}")
    else:
        fail(f"{description} was accepted")


def check_image_identity_controls(root: _Path) -> int:
    image = root / "plane.img"
    manifest = root / "plane.identity.json"
    image.write_bytes(b"temporary seL4 plane image\n")
    digest = hashlib.sha256(image.read_bytes()).hexdigest()

    def write_identity(identity: object) -> None:
        manifest.write_text(json.dumps(identity), encoding="utf-8")

    valid_identity = {"variant": "control", "image": {"sha256": digest}}
    write_identity(valid_identity)
    verify_image_identity(
        image=image, manifest=manifest, variant="control", fail=reject_control
    )

    missing_image = root / "missing.img"
    controls: tuple[tuple[str, str, Callable[[], object]], ...] = (
        (
            "missing image identity control",
            "image missing",
            lambda: verify_image_identity(
                image=missing_image,
                manifest=manifest,
                variant="control",
                fail=reject_control,
            ),
        ),
        (
            "missing manifest identity control",
            "identity manifest missing",
            lambda: verify_image_identity(
                image=image,
                manifest=root / "missing.identity.json",
                variant="control",
                fail=reject_control,
            ),
        ),
    )
    for description, expected, action in controls:
        require_rejection(description, expected, action)

    malformed = root / "malformed.identity.json"
    malformed.write_text("{not json", encoding="utf-8")
    require_rejection(
        "malformed JSON identity control",
        "cannot parse identity manifest",
        lambda: verify_image_identity(
            image=image, manifest=malformed, variant="control", fail=reject_control
        ),
    )

    invalid_identities: tuple[tuple[str, object, str], ...] = (
        ("non-object identity control", [], "must contain an object"),
        (
            "wrong variant identity control",
            {"variant": "wrong", "image": {"sha256": digest}},
            "wrong image variant",
        ),
        (
            "missing image record identity control",
            {"variant": "control"},
            "has no image record",
        ),
        (
            "wrong digest identity control",
            {"variant": "control", "image": {"sha256": "0" * 64}},
            "digest does not match",
        ),
    )
    for description, identity, expected in invalid_identities:
        write_identity(identity)
        require_rejection(
            description,
            expected,
            lambda: verify_image_identity(
                image=image, manifest=manifest, variant="control", fail=reject_control
            ),
        )

    print("seL4 gate control check: image identity accepted 1 valid pair and rejected 7 invalid pairs")
    return 8


def write_qemu_stub(path: _Path) -> None:
    path.write_text(
        f"""#!{_sys.executable}
import os
import signal
import sys
import time
from pathlib import Path

pid_path = Path(os.environ["SLIME_QEMU_CONTROL_PID"])
stop_path = Path(os.environ["SLIME_QEMU_CONTROL_STOP"])
pid_path.write_text(str(os.getpid()), encoding="utf-8")

def stop(_signal, _frame):
    stop_path.write_text("stopped", encoding="utf-8")
    raise SystemExit(0)

signal.signal(signal.SIGTERM, stop)
mode = os.environ["SLIME_QEMU_CONTROL_MODE"]
if mode == "terminal":
    print("SLIME CONTROL TERMINAL", flush=True)
elif mode == "input":
    print("SLIME CONTROL READY", flush=True)
    if sys.stdin.readline() != "private launch control\\n":
        raise SystemExit(9)
    print("SLIME CONTROL TERMINAL", flush=True)
elif mode == "failure":
    print("SLIME CONTROL EARLY FAILURE", flush=True)
    raise SystemExit(7)
elif mode == "early-success":
    print("SLIME CONTROL EARLY EXIT", flush=True)
    raise SystemExit(0)
while True:
    time.sleep(1)
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def with_environment(updates: dict[str, str], action: Callable[[], object]) -> object:
    previous = {key: os.environ.get(key) for key in updates}
    os.environ.update(updates)
    try:
        return action()
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def require_stopped(pid_path: _Path, stop_path: _Path, description: str) -> None:
    if not stop_path.is_file():
        fail(f"{description} left the fake QEMU process without termination evidence")
    pid = int(pid_path.read_text(encoding="utf-8"))
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    fail(f"{description} left fake QEMU process {pid} alive")


def check_plane_runtime_controls(root: _Path) -> int:
    executable_dir = root / "bin"
    executable_dir.mkdir()
    qemu = executable_dir / "qemu-system-aarch64"
    write_qemu_stub(qemu)
    image = root / "runtime.img"
    image.write_bytes(b"runtime control image\n")
    pins = root / "pins.toml"
    pins.write_text(
        """[qemu_arm_virt]
machine = "virt"
cpu = "cortex-a53"
cpus = 1
memory_mib = 64
""",
        encoding="utf-8",
    )
    terminal = re.compile(r"SLIME CONTROL TERMINAL")

    def run(mode: str, timeout: int, *, launch_input: bool = False, stepped: str | None = None) -> str:
        pid_path = root / f"{mode}.pid"
        stop_path = root / f"{mode}.stopped"
        try:
            result = with_environment(
                {
                    "PATH": str(executable_dir),
                    "SLIME_QEMU_CONTROL_MODE": mode,
                    "SLIME_QEMU_CONTROL_PID": str(pid_path),
                    "SLIME_QEMU_CONTROL_STOP": str(stop_path),
                },
                lambda: run_plane(
                    image=image,
                    timeout=timeout,
                    terminal_condition=terminal,
                    fail=reject_control,
                    pins_path=pins,
                    cwd=root,
                    input_trigger=re.compile("SLIME CONTROL READY") if launch_input else None,
                    input_text="private launch control\n" if launch_input else None,
                    input_character_delay=0,
                    input_steps=(((re.compile(stepped),), "private launch control\n"),) if stepped is not None else (),
                ),
            )
            return str(result)
        finally:
            if mode in {"terminal", "timeout", "input"} and pid_path.is_file():
                require_stopped(pid_path, stop_path, f"{mode} runtime control")

    transcript = run("terminal", 2)
    if "SLIME CONTROL TERMINAL" not in transcript:
        fail("terminal runtime control returned no terminal evidence")
    transcript = run("input", 2, launch_input=True)
    if transcript != "SLIME CONTROL READY\nSLIME CONTROL TERMINAL":
        fail("launch input was not readiness-gated or leaked into the transcript")
    require_rejection(
        "missing launch readiness control",
        "without accepting launch input",
        lambda: run("terminal", 2, launch_input=True),
    )
    transcript = run("input", 2, stepped="SLIME CONTROL READY")
    if transcript != "SLIME CONTROL READY\nSLIME CONTROL TERMINAL":
        fail("stepped input was not readiness-gated or leaked into the transcript")
    require_rejection(
        "missing stepped readiness control",
        "without accepting launch input",
        lambda: run("terminal", 2, stepped="SLIME CONTROL NEVER"),
    )

    require_rejection(
        "timeout runtime control",
        "timed out after 1s",
        lambda: run("timeout", 1),
    )
    require_rejection(
        "early process failure runtime control",
        "exited with status 7",
        lambda: run("failure", 2),
    )
    require_rejection(
        "early successful process exit runtime control",
        "exited with status 0",
        lambda: run("early-success", 2),
    )
    empty_path = root / "empty-path"
    empty_path.mkdir()
    require_rejection(
        "missing QEMU runtime control",
        "not on PATH",
        lambda: with_environment(
            {"PATH": str(empty_path)},
            lambda: run_plane(
                image=image,
                timeout=1,
                terminal_condition=terminal,
                fail=reject_control,
                pins_path=pins,
                cwd=root,
            ),
        ),
    )

    print(
        "seL4 gate control check: runtime returned terminal evidence and rejected "
        "timeout, early process failure/success, missing QEMU and missing launch readiness; "
        "readiness-gated input was not logged"
    )
    return 7


def capacity_workload_transcript() -> str:
    """One synthetic run of the 1 GiB workload, in the plane's exact grammar."""
    bases = {0: 0x10000000, 1: 0x20000000, 2: 0x30000000, 3: 0x40000000}
    guard = bases[3] + 65536 * 4096
    census = "slots=96 bytes=268435456 live_objects=12 mapped_pages=196608 extent_reuses=4"
    lines: list[str] = []

    def spawn(task: int, holder: int, incarnation: int) -> None:
        name = "abcd"[holder]
        lines.extend([
            f"SLIME_MEM quota task={task} instance=private-memory-1g-holder-{name} "
            f"declared=65536 installed=65536 base=0x{bases[holder]:x}",
            f"SLIME_GRAPH spawned task=1 child={task} component=private-memory-1g-holder-{name} slots=8",
            f"SLIME_MEM grown task={task} delta=65536 previous=0 pages=65536 "
            f"base=0x{bases[holder]:x} quota=65536 total={min(holder + 1, 4) * 65536} "
            "large_frames=128 base_frames=0 leaf_tables=0",
            f"[private-memory-1g] zeroed holder={holder} incarnation={incarnation} pages=65536",
        ])

    def verify(task: int, holder: int, incarnation: int, round_index: int) -> None:
        lines.append(
            f"SLIME_MEM refused task={task} delta=1 cause=reservation "
            "detail=ReservationExceeded { pages: 65536, delta: 1, reservation: 65536 }"
        )
        lines.append(
            f"SLIME_MEM grown task={task} delta=0 previous=65536 pages=65536 "
            f"base=0x{bases[holder]:x} quota=65536 total=262144 large_frames=128 "
            "base_frames=0 leaf_tables=0"
        )
        if holder == 0:
            lines.extend([
                f"SLIME_GRAPH buffer created task={task} slot=9 id=3 pages=1 writable=1",
                f"SLIME_GRAPH buffer create refused task={task} pages=1 class=quota",
                f"SLIME_MEM mapping refused task={task} base=0x{bases[0]:x} "
                f"end=0x{bases[0] + 4096:x} window=0x{bases[0]:x}..0x{guard:x}",
            ])
        lines.append(
            f"[private-memory-1g] verified holder={holder} incarnation={incarnation} "
            f"round={round_index} pages=65536 refused=1 shared={int(holder == 0)}"
        )

    current = [2, 3, 4, 5]
    rounds = [0, 0, 0, 0]
    for holder in range(4):
        spawn(current[holder], holder, 0)
    lines.append("[private-memory-1g] resident holders=4 pages=262144")
    for cycle in range(20):
        for holder in range(4):
            verify(current[holder], holder, cycle if holder == 3 else 0, rounds[holder])
            rounds[holder] += 1
        lines.extend([
            f"SLIME_GRAPH component fault task={current[3]} kind=VirtualMemory "
            f"{{ access: Write, status: 15 }} address=Some({guard})",
            f"SLIME_MEM census retired={current[3]} {census}",
            f"SLIME_LIFECYCLE restart admitted task=1 subject={current[3]} attempt={cycle} "
            f"remaining={19 - cycle} ready_at=1000",
        ])
        current[3] = 6 + cycle
        rounds[3] = 0
        spawn(current[3], 3, cycle + 1)
        for holder in range(4):
            verify(current[holder], holder, cycle + 1 if holder == 3 else 0, rounds[holder])
            rounds[holder] += 1
        lines.append(f"[private-memory-1g] retained cycle={cycle + 1} holders=4 pages=262144")
    for task in current:
        lines.extend([
            f"SLIME_GRAPH component exit task={task} status=0",
            f"SLIME_MEM census retired={task} {census}",
        ])
    lines.extend([
        "[private-memory-1g] complete faults=20 replacements=20 exits=4",
        "SLIME_GRAPH loans served=40 loans=0 mappings=0 regions=0 orphans=0 quota=0",
        "SLIME_GRAPH HEALTHY generation=56 required=2 live=0 completed=2 failed=0",
    ])
    return "\n".join(lines)


def check_private_capacity_controls(gate) -> int:
    """The 1 GiB claim must fail closed: a peer that was not resident during a
    reclamation, a replacement that reused a dead incarnation's identity, a
    fault charged to a surviving holder, and a skipped restart admission are
    each rejected rather than absorbed as an equivalent run."""
    transcript = capacity_workload_transcript()
    gate.check_capacity_workload(transcript)
    mutations = (
        ("capacity peers not resident during reclamation", transcript.replace("mapped_pages=196608", "mapped_pages=131072", 1)),
        ("capacity census missing for a dead incarnation", transcript.replace("SLIME_MEM census retired=5 slots=96 bytes=268435456 live_objects=12 mapped_pages=196608 extent_reuses=4\n", "", 1)),
        ("capacity replacement reuses a dead task identity", transcript.replace("child=6 component=private-memory-1g-holder-d", "child=5 component=private-memory-1g-holder-d", 1)),
        ("capacity aggregate below the declared total", transcript.replace("quota=65536 total=262144", "quota=65536 total=196608", 1)),
        ("capacity fault charged to a surviving peer", transcript.replace("SLIME_GRAPH component fault task=5 ", "SLIME_GRAPH component fault task=2 ", 1)),
        ("capacity fault away from the guard page", transcript.replace(f"address=Some({0x40000000 + 65536 * 4096})", "address=Some(1074790400)", 1)),
        ("capacity restart admission skipped", transcript.replace("SLIME_LIFECYCLE restart admitted task=1 subject=5 attempt=0 remaining=19 ready_at=1000\n", "", 1)),
        ("capacity restart ordinal repeated", transcript.replace("subject=6 attempt=1 remaining=18", "subject=6 attempt=0 remaining=19", 1)),
        ("capacity replacement served stale pages", transcript.replace("[private-memory-1g] zeroed holder=3 incarnation=1 pages=65536\n", "", 1)),
        ("capacity peer verification dropped after a replacement", transcript.replace("[private-memory-1g] verified holder=1 incarnation=0 round=1 pages=65536 refused=1 shared=0\n", "", 1)),
        ("capacity holder admitted beyond its quota", transcript.replace("SLIME_MEM refused task=2 delta=1 cause=reservation detail=ReservationExceeded { pages: 65536, delta: 1, reservation: 65536 }\n", "", 1)),
        ("capacity completion claimed twice", transcript + "\n[private-memory-1g] complete faults=20 replacements=20 exits=4"),
        ("capacity holder left running at teardown", transcript.replace("SLIME_GRAPH component exit task=2 status=0\n", "", 1)),
    )
    for description, mutated in mutations:
        require_rejection(description, "capacity workload:",
            lambda mutated=mutated: gate.check_capacity_workload(mutated))
    return len(mutations)


def check_private_isolation_controls(gate) -> int:
    """MEM-1G's denial evidence must be unforgeable: a survived foreign access,
    a fault charged to the wrong task, an attacker without its own window, and
    a denial claimed before the fault that proves it each differ from isolation
    only in the transcript, never in the plane's outcome."""
    address = 0x10000000
    probe = address + 65536 * 4096 // 2
    lines = [
        f"[private-memory-isolation] victim base={address} pages=65536",
        f"SLIME_MEM quota task=1 instance=private-memory-1g-holder-a declared=65536 installed=65536 base=0x{address:x}",
        f"SLIME_MEM quota task=2 instance=private-memory-1g-holder-b declared=1 installed=1 base=0x{address:x}",
        f"SLIME_MEM quota task=3 instance=private-memory-1g-holder-c declared=1 installed=1 base=0x{address:x}",
        f"SLIME_MEM grown task=1 delta=65536 previous=0 pages=65536 base=0x{address:x} quota=65536 total=65536 large_frames=128 base_frames=0 leaf_tables=0",
        f"SLIME_MEM grown task=2 delta=1 previous=0 pages=1 base=0x{address:x} quota=1 total=65537 large_frames=0 base_frames=1 leaf_tables=1",
        f"SLIME_MEM grown task=3 delta=1 previous=0 pages=1 base=0x{address:x} quota=1 total=65538 large_frames=0 base_frames=1 leaf_tables=1",
        "SLIME_GRAPH buffer created task=1 slot=20 id=1 pages=1 writable=1",
    ]
    for source, receiver, lender, recipient, loan, exported in ((1, 2, 2, 3, 10, 30), (2, 1, 3, 2, 11, 31)):
        lines.extend([
            f"SLIME_GRAPH buffer created task={lender} slot=20 id={source + 1} pages=1 writable=1",
            f"SLIME_GRAPH loan created task={lender} slot=21 id={loan} to={recipient} offset=0 length=4096",
            f"SLIME_GRAPH capability exported task={lender} id={exported} kind=loan rights=0x200 retain=0",
            f"SLIME_GRAPH capability imported task={recipient} id={exported} kind=loan rights=0x200 retain=0",
            *[
                f"SLIME_MEM mapping refused task={recipient} base=0x{target:x} end=0x{target + 4096:x} window=0x{address:x}..0x{address + 65536 * 4096:x}"
                for target in (address, probe)
            ],
            f"SLIME_GRAPH loan mapped task={recipient} slot=22 id={loan}",
            f"SLIME_GRAPH loan returned task={recipient} slot=22 id={loan}",
            f"[private-memory-isolation] loan receiver source={source} holder={receiver} positive=1 window_denied=2 unmapped=1 returned=1 return_denied=1 pages=0 buffers=0 mappings=0 loans=0",
            f"[private-memory-isolation] loan lender holder={source} receiver={receiver} transferred=1 released=1 pages=0 buffers=0 mappings=0 loans=0",
        ])
    for holder, task, operation, access in ((1, 2, 6, "Read"), (2, 3, 7, "Write")):
        lines.extend([
            f"SLIME_GRAPH buffer created task={task} slot=20 id={holder + 3} pages=1 writable=1",
            *[
                f"SLIME_MEM mapping refused task={task} base=0x{target:x} end=0x{target + 4096:x} window=0x{address:x}..0x{address + 65536 * 4096:x}"
                for target in (address, probe)
            ],
            f"SLIME_GRAPH buffer map refused task={task} slot=20 class=write",
            f"[private-memory-isolation] attacker holder={holder} operation={operation} address={probe} own_base={address} own_pages=1 own_buffer=1 buffer_window_denied=2 unowned_denied=3 seal_denied=1 pages=0 buffers=0 mappings=0 loans=0",
            f"SLIME_GRAPH component fault task={task} kind=VirtualMemory {{ access: {access}, status: 15 }} address=Some({probe})",
            f"[private-memory-1g] verified holder=0 incarnation=0 round={holder - 1} pages=65536 refused=1 shared=1",
            f"[private-memory-isolation] denied holder={holder} operation={operation} address={probe} victim_preserved=1",
        ])
    lines.extend([
        f"[private-memory-isolation] execute address={address} pages=65536",
        f"SLIME_GRAPH component fault task=1 kind=VirtualMemory {{ access: Execute, status: 15 }} address=Some({address})",
        "[private-memory-isolation] complete read=1 write=1 execute=1 buffer_window_denied=4 loan_window_denied=4 unowned_denied=6 seal_denied=2 loan_transfer=2",
        "SLIME_GRAPH native task_caps=0 exports=0 tickets=0",
        "SLIME_GRAPH capabilities exports=2 imports=2 cancels=0 finalized=2 outstanding=0 tickets=0",
        "SLIME_GRAPH loans served=2 loans=0 mappings=0 regions=0 orphans=0 quota=0",
        "SLIME_GRAPH HEALTHY generation=57 required=2 live=0 completed=2 failed=0",
    ])
    transcript = "\n".join(lines)
    gate.check_private_isolation(transcript)
    mutations = (
        ("isolation read survived", transcript.replace("SLIME_GRAPH component fault task=2 kind=VirtualMemory { access: Read, status: 15 } " f"address=Some({probe})\n", "")),
        ("isolation fault charged to victim", transcript.replace("fault task=2 ", "fault task=1 ", 1)),
        ("isolation write reported as read", transcript.replace("access: Write", "access: Read", 1)),
        ("isolation fault outside the victim's extent", transcript.replace(f"access: Read, status: 15 }} address=Some({probe})", f"access: Read, status: 15 }} address=Some({address + 65536 * 4096})", 1)),
        ("isolation probe inside the attacker's own window", transcript.replace(f"address={probe} own_base", f"address={address} own_base", 1)),
        ("isolation stale fault status", transcript.replace("status: 15", "status: 0", 1)),
        ("isolation attacker quota differs from its declaration", transcript.replace("instance=private-memory-1g-holder-b declared=1 installed=1", "instance=private-memory-1g-holder-b declared=1 installed=4")),
        ("isolation attacker has no window of its own", transcript.replace(f"SLIME_MEM grown task=2 delta=1 previous=0 pages=1 base=0x{address:x} quota=1 total=65537 large_frames=0 base_frames=1 leaf_tables=1\n", "", 1)),
        ("isolation attacker page outlived its incarnation", transcript.replace("quota=1 total=65537", "quota=1 total=65538", 1)),
        ("isolation attacker window origin differs", transcript.replace(f"instance=private-memory-1g-holder-b declared=1 installed=1 base=0x{address:x}", "instance=private-memory-1g-holder-b declared=1 installed=1 base=0x99000000")),
        ("isolation victim pattern lost after the denial", transcript.replace("[private-memory-1g] verified holder=0 incarnation=0 round=1 pages=65536 refused=1 shared=1", "[private-memory-1g] FAIL pattern mismatch")),
        ("isolation victim unverified", transcript.replace("[private-memory-1g] verified holder=0 incarnation=0 round=0 pages=65536 refused=1 shared=1\n", "")),
        ("isolation denial claimed before the fault that proves it", transcript.replace(
            f"SLIME_GRAPH component fault task=2 kind=VirtualMemory {{ access: Read, status: 15 }} address=Some({probe})\n"
            f"[private-memory-1g] verified holder=0 incarnation=0 round=0 pages=65536 refused=1 shared=1\n"
            f"[private-memory-isolation] denied holder=1 operation=6 address={probe} victim_preserved=1\n",
            f"[private-memory-isolation] denied holder=1 operation=6 address={probe} victim_preserved=1\n"
            f"SLIME_GRAPH component fault task=2 kind=VirtualMemory {{ access: Read, status: 15 }} address=Some({probe})\n"
            f"[private-memory-1g] verified holder=0 incarnation=0 round=0 pages=65536 refused=1 shared=1\n")),
        ("isolation NX never attempted", transcript.replace(f"[private-memory-isolation] execute address={address} pages=65536\n", "")),
        ("isolation execute fault away from the victim's own base", transcript.replace(f"access: Execute, status: 15 }} address=Some({address})", f"access: Execute, status: 15 }} address=Some({probe})")),
        ("isolation victim not one large-frame set", transcript.replace("large_frames=128 base_frames=0", "large_frames=0 base_frames=65536")),
        ("isolation explicit component failure", transcript.replace("[private-memory-isolation] complete", "[private-memory-1g] FAIL pattern mismatch\n[private-memory-isolation] complete")),
        ("isolation leaked authority at exit", transcript.replace("loans=0 mappings=0 regions=0 orphans=0 quota=0", "loans=0 mappings=1 regions=1 orphans=0 quota=0")),
    )
    mutations = list(mutations)
    for source, receiver, lender, recipient, loan, exported in ((1, 2, 2, 3, 10, 30), (2, 1, 3, 2, 11, 31)):
        receiver_marker = next(line for line in lines if line.startswith(f"[private-memory-isolation] loan receiver source={source} "))
        lender_marker = next(line for line in lines if line.startswith(f"[private-memory-isolation] loan lender holder={source} "))
        created = f"SLIME_GRAPH loan created task={lender} slot=21 id={loan} to={recipient} offset=0 length=4096"
        imported = f"SLIME_GRAPH capability imported task={recipient} id={exported} kind=loan rights=0x200 retain=0"
        mapped = f"SLIME_GRAPH loan mapped task={recipient} slot=22 id={loan}"
        returned = f"SLIME_GRAPH loan returned task={recipient} slot=22 id={loan}"
        direction = f"isolation loan {source}->{receiver}: "
        for label, old, new in (
            ("source buffer absent", f"SLIME_GRAPH buffer created task={lender} slot=20 id={source + 1} pages=1 writable=1\n", ""),
            ("creation absent", created + "\n", ""),
            ("receiver binding wrong", created, created.replace(f"to={recipient}", "to=1")),
            ("import absent", imported + "\n", ""),
            ("transfer identity mismatch", imported, imported.replace(f"id={exported}", "id=999")),
            ("imported by wrong task", imported, imported.replace(f"task={recipient}", "task=1")),
            ("positive map absent", mapped + "\n", ""),
            ("positive map wrong loan", mapped, mapped.replace(f"id={loan}", "id=999")),
            ("return absent", returned + "\n", ""),
            ("return wrong slot", returned, returned.replace("slot=22", "slot=23")),
            ("return precedes map", mapped + "\n" + returned, returned + "\n" + mapped),
            ("positive read failed", receiver_marker, receiver_marker.replace("positive=1", "positive=0")),
            ("explicit unmap absent", receiver_marker, receiver_marker.replace("unmapped=1", "unmapped=0")),
            ("single return not enforced", receiver_marker, receiver_marker.replace("return_denied=1", "return_denied=0")),
            ("receiver retains mapping", receiver_marker, receiver_marker.replace("mappings=0", "mappings=1")),
            ("receiver report duplicated", receiver_marker, receiver_marker + "\n" + receiver_marker),
            ("lender source not released", lender_marker, lender_marker.replace("released=1", "released=0")),
            ("lender retains buffer", lender_marker, lender_marker.replace("buffers=0", "buffers=1")),
            ("lender release precedes return", receiver_marker + "\n" + lender_marker, lender_marker + "\n" + receiver_marker),
        ):
            mutations.append((direction + label, transcript.replace(old, new, 1)))
        for target in (address, probe):
            refusal = f"SLIME_MEM mapping refused task={recipient} base=0x{target:x} end=0x{target + 4096:x} window=0x{address:x}..0x{address + 65536 * 4096:x}"
            mutations.append((direction + f"window refusal {target:x} absent", transcript.replace(refusal + "\n", "", 1)))
            mutations.append((direction + f"window refusal {target:x} wrong task", transcript.replace(refusal, refusal.replace(f"task={recipient}", "task=1"), 1)))
    for holder, task in ((1, 2), (2, 3)):
        marker = next(line for line in lines if line.startswith(f"[private-memory-isolation] attacker holder={holder} "))
        for field in ("own_buffer=1", "buffer_window_denied=2", "unowned_denied=3", "seal_denied=1"):
            mutations.append((f"isolation attacker {holder} missing {field}", transcript.replace(marker, marker.replace(field, field.split("=")[0] + "=0"), 1)))
        sealed = f"SLIME_GRAPH buffer map refused task={task} slot=20 class=write"
        mutations.append((f"isolation attacker {holder} seal denial missing", transcript.replace(sealed + "\n", "", 1)))
        mutations.append((f"isolation attacker {holder} seal refusal wrong capability", transcript.replace(sealed, sealed.replace("slot=20", "slot=21"), 1)))
    late_growth = f"SLIME_MEM grown task=3 delta=1 previous=0 pages=1 base=0x{address:x} quota=1 total=65538 large_frames=0 base_frames=1 leaf_tables=1"
    mutations.extend([
        ("isolation receiver private page backed only after exchange", transcript.replace(late_growth + "\n", "", 1) + "\n" + late_growth),
        ("isolation export survives teardown", transcript.replace("outstanding=0 tickets=0", "outstanding=1 tickets=1")),
        ("isolation native capability survives teardown", transcript.replace("task_caps=0 exports=0", "task_caps=1 exports=0")),
        ("isolation transfer not finalized", transcript.replace("finalized=2", "finalized=1")),
        ("isolation extra loan mapping", transcript + "\nSLIME_GRAPH loan mapped task=3 slot=22 id=10"),
        ("isolation duplicate loan identity", transcript.replace("id=11", "id=10")),
        ("isolation duplicate transfer identity", transcript.replace("id=31", "id=30")),
    ])
    for description, mutated in mutations:
        if mutated == transcript:
            fail(f"{description}: mutation did not change the transcript")
        require_rejection(description, "private isolation:",
            lambda mutated=mutated: gate.check_private_isolation(mutated))
    return len(mutations)


def check_private_stress_controls(gate) -> int:
    address = 0x10000000
    lines = []
    for index, name in enumerate("abc"):
        task = index + 2
        lines += [
            f"SLIME_GRAPH spawned task=1 child={task} component=private-memory-1g-holder-{name} slots=8",
            f"SLIME_MEM grown task={task} delta=65536 previous=0 pages=65536 base=0x{address:x} quota=65536 total={(index + 1) * 65536} large_frames=128 base_frames=0 leaf_tables=0",
        ]
    for attempt, case in enumerate(("construction", "slots", "descriptors")):
        lines += [
            f"SLIME_MEM stress census attempt={attempt} phase=before slots=1000 descriptors=1000 extents=100 objects=100 bytes=1000 reusable_anchors=0 reusable_bytes=0 ordinary_bytes=10000 preserved_bytes=0 preserved_anchors=0 descriptor_capacity=1000 extent_capacity=100 infrastructure_owned=0",
            f"SLIME_MEM stress construction case={case} attempt={attempt} actual=1000 effective=1 required=2 reserved={0 if case == 'construction' else 999}",
            f"SLIME_MEM stress census attempt={attempt} phase=after slots=1000 descriptors=1000 extents=100 objects=100 bytes=1000 reusable_anchors=0 reusable_bytes=0 ordinary_bytes=10000 preserved_bytes=0 preserved_anchors=0 descriptor_capacity=1000 extent_capacity=100 infrastructure_owned=0",
            *[f"[private-memory-1g] verified holder={holder} incarnation=0 round=0 pages=65536 refused=1 shared={int(holder == 0)}" for holder in range(3)],
            f"[private-memory-stress] spawn_refused attempt={attempt + 1} peers_preserved=3",
        ]
    for incarnation, task in enumerate((8, 9)):
        lines += [
            f"SLIME_MEM quota task={task} instance=private-memory-1g-holder-d declared=65536 installed=65536 base=0x{address:x}",
            f"SLIME_GRAPH spawned task=1 child={task} component=private-memory-1g-holder-d slots=8",
        ]
        schedule = [(12, 1), (12, 511)]
        if incarnation == 0:
            schedule += [(13, 1024)]
        schedule += [(12, 1024), (12, 63998)]
        if incarnation == 0:
            schedule += [(13, 2)]
        schedule += [(12, 2), (14, 0)]
        pages = 0
        for stage, (operation, delta) in enumerate(schedule):
            previous = pages
            if operation == 13:
                case, backed = ("map", 512) if previous == 512 else ("allocation", 1)
                lines += [
                    f"SLIME_MEM stress growth case={case} previous={previous} delta={delta} backed={backed}",
                    f"SLIME_MEM refused task={task} delta={delta} cause=frames detail=Frames {{ allocated: {backed}, error: NotEnoughMemory }}",
                ]
            elif operation == 12:
                pages += delta
                large = max(0, pages // 512 - 1)
                base = pages - large * 512
                lines += [f"SLIME_MEM grown task={task} delta={delta} previous={previous} pages={pages} base=0x{address:x} quota=65536 total={196608 + pages} large_frames={large} base_frames={base} leaf_tables=2"]
            lines += [f"[private-memory-stress] stage incarnation={incarnation} operation={operation} delta={delta} previous={previous} pages={pages} zeroed={int(operation == 12)} preserved=1"]
            if operation != 14:
                lines += [f"[private-memory-1g] verified holder={holder} incarnation=0 round={stage} pages=65536 refused=1 shared={int(holder == 0)}" for holder in range(3)]
                lines += [f"[private-memory-stress] retained incarnation={incarnation} stage={stage} peers=3 pages=196608"]
        if incarnation == 0:
            lines += [f"SLIME_GRAPH component exit task={task} status=0"]
        else:
            lines += [f"SLIME_GRAPH component fault task={task} kind=VirtualMemory {{ access: Write, status: 15 }} address=Some({address + 65536 * 4096})"]
        lines += [f"SLIME_MEM census retired={task} mapped_pages=196608 free_slots=1000"]
        lines += [f"SLIME_ROOT reclaim census task={task} slots=1000 bytes=1000 live_objects=100 extent_reuses={incarnation + 1}"]
        lines += [f"[private-memory-1g] verified holder={holder} incarnation=0 round=0 pages=65536 refused=1 shared={int(holder == 0)}" for holder in range(3)]
    lines += [f"SLIME_GRAPH component exit task={task} status=0" for task in (2, 3, 4)]
    lines += [
        "[private-memory-stress] complete spawn_refused=3 growth_refused=2 retries=2 replacements=1 faults=1 exits=4",
        "SLIME_GRAPH native task_caps=0 exports=0 tickets=0",
        "SLIME_GRAPH loans served=0 loans=0 mappings=0 regions=0 orphans=0 quota=0",
        "SLIME_GRAPH HEALTHY generation=58 required=2 live=0 completed=2 failed=0",
    ]
    lines += ["SLIME_MEM stress fragmented guards=4 bytes=16777216 released=1"]
    lines += [f"SLIME_MEM stress backing attempt={attempt} data_extents=128 discontinuities=3 reused={0 if attempt == 0 else 256}" for attempt in (0, 1, 3, 4)]
    transcript = "\n".join(lines)
    gate.check_stress_workload(transcript)
    mutations = []
    for index, line in enumerate(lines):
        if line.startswith(("SLIME_MEM stress ", "[private-memory-stress]", "[private-memory-1g] verified", "SLIME_MEM grown", "SLIME_GRAPH component")):
            mutations.append((f"stress missing evidence {index}", "\n".join(lines[:index] + lines[index + 1:])))
    for description, old, new in (
        ("slot limit not binding", "case=slots attempt=1 actual=1000 effective=1 required=2", "case=slots attempt=1 actual=1000 effective=2 required=2"),
        ("unwind leaks slots", "phase=after slots=1000", "phase=after slots=999"),
        ("unwind leaks descriptors", "phase=after slots=1000 descriptors=1000", "phase=after slots=1000 descriptors=999"),
        ("wrong failed subject", "refused task=8 delta=1024", "refused task=2 delta=1024"),
        ("mapping failure before partial work", "case=map previous=512 delta=1024 backed=512", "case=map previous=512 delta=1024 backed=0"),
        ("wrong retry population", "quota=65536 total=198144", "quota=65536 total=198143"),
        ("peer reclaimed with subject", "retired=8 mapped_pages=196608", "retired=8 mapped_pages=131072"),
        ("foreign fault", "fault task=9", "fault task=2"),
        ("backing never reused", "extent_reuses=2", "extent_reuses=1"),
        ("reclamation drift", "retired=9 mapped_pages=196608 free_slots=1000", "retired=9 mapped_pages=196608 free_slots=999"),
        ("pressure not reserved", "required=2 reserved=999", "required=2 reserved=0"),
        ("backing contiguous", "discontinuities=3", "discontinuities=0"),
        ("fragmented backing not reused", "reused=256", "reused=0"),
        ("only base pages", "large_frames=127 base_frames=512", "large_frames=0 base_frames=65536"),
        ("leaked export", "task_caps=0 exports=0", "task_caps=0 exports=1"),
    ):
        mutations.append((description, transcript.replace(old, new, 1)))
    for description, mutated in mutations:
        if mutated == transcript:
            fail(f"{description}: stress mutation did not change evidence")
        require_rejection(description, "private stress:", lambda mutated=mutated: gate.check_stress_workload(mutated))
    peer_checks = [f"[private-memory-1g] verified holder={holder} incarnation=0 round=0 pages=65536 refused=1 shared={int(holder == 0)}" for holder in range(3)]
    heap_lines = []
    for index, name in enumerate("abc"):
        heap_lines += [
            f"SLIME_GRAPH spawned task=1 child={index + 2} component=private-memory-1g-holder-{name} slots=8",
            f"SLIME_MEM grown task={index + 2} delta=65536 previous=0 pages=65536 base=0x10000000 quota=65536 total={(index + 1) * 65536} large_frames=128 base_frames=0 leaf_tables=0",
        ]
    heap_lines += [
        "SLIME_MEM quota task=5 instance=private-heap-probe declared=65536 installed=65536 base=0x10000000",
        "SLIME_GRAPH spawned task=1 child=5 component=private-heap-probe slots=8",
        *peer_checks,
        "SLIME_MEM grown task=5 delta=61457 previous=0 pages=61457 base=0x10000000 quota=65536 total=258065 large_frames=119 base_frames=529 leaf_tables=2",
        "[private-heap-probe:stress] capacity payload=251723776 overhead=4096 backed=251727872 pages=61457 touched=1 vecs=120 boxes=120 small=256",
        "[private-heap-probe:stress] holes reused=1 growths=1 pages=61457",
        "[private-heap-probe:stress] exhaustion requested=16777216 refused=1 intact=1 pages=61457",
        *peer_checks,
        "[private-heap-probe:stress] verified payload=251723776 intact=1",
        *peer_checks,
        "[private-heap-probe:stress] released live=0 reused=1 growths=1 pages=61457",
        "SLIME_GRAPH component exit task=5 status=0",
        *peer_checks,
        *[f"SLIME_GRAPH component exit task={task} status=0" for task in (2, 3, 4)],
        "[private-memory-stress] heap_complete peers=3 exits=4",
        "SLIME_GRAPH native task_caps=0 exports=0 tickets=0",
        "SLIME_GRAPH loans served=0 loans=0 mappings=0 regions=0 orphans=0 quota=0",
        "SLIME_GRAPH HEALTHY generation=59 required=2 live=0 completed=2 failed=0",
    ]
    heap = "\n".join(heap_lines)
    gate.check_heap_stress_workload(heap)
    for index in range(len(heap_lines)):
        mutated = "\n".join(heap_lines[:index] + heap_lines[index + 1:])
        require_rejection(f"heap stress missing evidence {index}", "heap stress:", lambda mutated=mutated: gate.check_heap_stress_workload(mutated))
    heap_mutations = (
        ("heap wrong quota", heap.replace("installed=65536", "installed=65535", 1)),
        ("heap wrong root charge", heap.replace("total=258065", "total=258064", 1)),
        ("heap reuse grew backing", heap.replace("released live=0 reused=1 growths=1", "released live=0 reused=1 growths=2", 1)),
        ("heap wrong task", heap.replace("grown task=5", "grown task=6", 1)),
        ("heap explicit failure", heap + "\n[private-heap-probe:stress] FAIL injected"),
    )
    for description, mutated in heap_mutations:
        require_rejection(description, "heap stress:", lambda mutated=mutated: gate.check_heap_stress_workload(mutated))
    return len(mutations) + len(heap_lines) + len(heap_mutations)


def check_adaptive_control_mutations(validator, prefix: str, lines: list[str], mutations: list[tuple[str, str]]) -> int:
    transcript = "\n".join(lines)
    validator(transcript)
    for index in range(len(lines)):
        mutations.append((f"missing line {index}", "\n".join(lines[:index] + lines[index + 1:])))
    mutations.append(("explicit failure", transcript + "\nSLIME_ROOT FATAL injected"))
    for description, mutated in mutations:
        if mutated == transcript:
            fail(f"{prefix}{description}: mutation did not change evidence")
        require_rejection(description, prefix, lambda mutated=mutated: validator(mutated))
    return len(mutations)


def check_private_cspace_controls(gate) -> int:
    base = 1 << 60
    lines = [
        f"SLIME_ROOT cspace expanded base={base} infrastructure_caps=2",
        "SLIME_ROOT cspace pressure initial_limit=524288 retired=64 free=0",
        f"SLIME_ROOT cspace leaf base={base} slots=1024 beyond_initial=1",
        f"SLIME_ROOT cspace exercised created=1 invoked=1 copied=1 retyped=1 deleted=1 revoked=1 min_address={base + 1} initial_limit=524288",
        "SLIME_ROOT cspace live root=1 second=1 leaves=1",
        f"SLIME_ALLOC global region=0 parent=10 slot={base + 2} prior=0 start=0 end=4096 bytes=4096 gap=0",
        "SLIME_GRAPH HEALTHY generation=1 required=1 live=0 completed=1 failed=0",
    ]
    transcript = "\n".join(lines)
    later_leaf = lines[2].replace(str(base), str(base + 1024))
    after_live = transcript.replace(lines[5], later_leaf + "\n" + lines[5])
    gate.check_cspace_execution(after_live)
    before_live = transcript.replace(lines[4], later_leaf + "\n" + lines[4]).replace("leaves=1", "leaves=2")
    gate.check_cspace_execution(before_live)
    mutations = []
    for old, new in (
        ("initial_limit=524288", "initial_limit=262144"),
        ("retired=64", "retired=0"), ("free=0", "free=1024"),
        ("slots=1024", "slots=512"), ("beyond_initial=1", "beyond_initial=0"),
        (f"leaf base={base}", f"leaf base={base - 1}"),
        (f"min_address={base + 1}", "min_address=524288"),
        ("second=1", "second=0"), ("root=1", "root=0"), ("leaves=1", "leaves=2"),
        (f"slot={base + 2}", "slot=524288"),
        *((f"{field}=1", f"{field}=0") for field in ("created", "invoked", "copied", "retyped", "deleted", "revoked")),
    ):
        mutations.append((old, transcript.replace(old, new, 1)))
    mutations += [
        ("inconsistent exercised limit", transcript.replace(lines[3], lines[3].replace("initial_limit=524288", "initial_limit=262144"))),
        ("duplicate leaf", transcript.replace(lines[2], lines[2] + "\n" + lines[2]).replace("leaves=1", "leaves=2")),
        ("pressure after leaf", "\n".join(lines[:1] + [lines[2], lines[1]] + lines[3:])),
        ("live counts future leaf", after_live.replace("leaves=1", "leaves=2")),
        ("live omits preceding leaf", before_live.replace("leaves=2", "leaves=1")),
        ("no leaf before exercise", "\n".join(lines[:2] + [lines[3], lines[2]] + lines[4:])),
        ("late duplicate leaf", after_live.replace(later_leaf, lines[2])),
        ("late leaf aliases initial namespace", after_live.replace(later_leaf, later_leaf.replace(f"base={base + 1024}", "base=524288"))),
        ("late leaf wrong width", after_live.replace(later_leaf, later_leaf.replace("slots=1024", "slots=512"))),
        ("late leaf not expanded", after_live.replace(later_leaf, later_leaf.replace("beyond_initial=1", "beyond_initial=0"))),
    ]
    for family in ("SLIME_MEM grown", "SLIME_BACKING preserve"):
        mutations.append((family + " aliases branch zero", transcript + f"\n{family} slot=524288"))
    return check_adaptive_control_mutations(gate.check_cspace_execution, "cspace execution:", lines, mutations)


def check_private_metadata_controls(gate) -> int:
    def census(phase: str, **changes: int) -> str:
        fields = dict(zip(gate.METADATA_FIELDS, (2, 8192, 2, 10, 2, 10, 2, 10, 16, 100, 1, 0, 0), strict=True))
        fields.update(changes)
        return f"SLIME_ROOT metadata census phase={phase} " + " ".join(f"{key}={value}" for key, value in fields.items())

    lines = [
        census("baseline"),
        "SLIME_ROOT metadata round=0 grew=2 reused=0",
        "SLIME_ROOT metadata round=1 grew=0 reused=2",
        "SLIME_ROOT metadata round=2 grew=0 reused=2",
        "SLIME_ROOT metadata injected kind=construction retained=1 reassigned=0",
        "SLIME_ROOT metadata injected kind=revoke retained=1 reassigned=0",
        census("grown", pages=4, bytes=16384, allocations_free=20, quarantined=2, pending=1),
        "SLIME_ROOT metadata retry kind=construction released=1 reassigned=0",
        "SLIME_ROOT metadata retry kind=revoke released=1 reassigned=0",
        census("released", pages=5, bytes=16384, allocations_free=30, nodes=2),
        census("final", pages=5, bytes=20480, nodes=2),
        "SLIME_GRAPH HEALTHY generation=1 required=1 live=0 completed=1 failed=0",
    ]
    transcript = "\n".join(lines)
    gate.check_metadata_lifecycle(transcript.replace(lines[9], lines[9].replace("bytes=16384", "bytes=20480")))
    mutations = []
    for index, field, value in (
        (6, "pages", 2), (9, "pages", 4), (9, "pages", 6), (9, "bytes", 12288),
        *((9, field, 3) for field in ("allocations_live", "extents_live", "preserved_live", "slots_free")),
        (6, "nodes", 2), (9, "nodes", 1), (9, "nodes", 3),
        (6, "allocations_free", 10), (6, "allocations_free", 30),
        (9, "allocations_free", 20), (9, "allocations_free", 10),
        (10, "pages", 3), (10, "bytes", 12288), (10, "nodes", 0),
        (0, "bytes", 32768),
        *((index, "pending", value) for index, value in ((0, 1), (6, 0), (9, 1), (10, 1))),
        *((index, "quarantined", value) for index, value in ((0, 1), (6, 0), (9, 1), (10, 1))),
    ):
        changed = re.sub(rf"\b{field}=\d+", f"{field}={value}", lines[index])
        mutations.append((f"census {index} {field}", transcript.replace(lines[index], changed)))
    for index in (4, 5, 7, 8):
        mutations.append((f"premature reassignment {index}", transcript.replace(lines[index], lines[index].replace("reassigned=0", "reassigned=1"))))
        field = "retained" if index < 7 else "released"
        mutations.append((f"missing {field} {index}", transcript.replace(lines[index], lines[index].replace(f"{field}=1", f"{field}=0"))))
    mutations += [
        ("growth missing", transcript.replace("grew=2", "grew=0")),
        ("later reuse missing", transcript.replace("reused=2", "reused=0")),
        ("reuse before growth only", transcript.replace("round=0 grew=2 reused=0", "round=0 grew=0 reused=2").replace("round=1 grew=0 reused=2", "round=1 grew=0 reused=0").replace("round=2 grew=0 reused=2", "round=2 grew=2 reused=0")),
        ("duplicate census", transcript + "\n" + lines[9]),
        ("duplicate round", transcript.replace(lines[3], lines[3] + "\n" + lines[3])),
        ("duplicate injection", transcript.replace(lines[4], lines[4] + "\n" + lines[4])),
        ("duplicate retry", transcript.replace(lines[7], lines[7] + "\n" + lines[7])),
        ("phases reordered", transcript.replace(lines[9], "PHASE").replace(lines[10], lines[9]).replace("PHASE", lines[10])),
        ("retry before pending census", "\n".join(lines[:6] + [lines[7], lines[6]] + lines[8:])),
        ("round outside baseline", "\n".join([lines[1], lines[0]] + lines[2:])),
    ]
    return check_adaptive_control_mutations(gate.check_metadata_lifecycle, "metadata lifecycle:", lines, mutations)


def check_private_bootstrap_controls(gate) -> int:
    lines = [
        "SLIME_ROOT metadata bootstrap objects=4096 alignment=4096 remaining=8192",
        "SLIME_ROOT bootstrap reserve objects=4096 alignment=4096 remaining=8192 slots=64 transaction=12 recursion=0 fit=1",
        "SLIME_ROOT bootstrap exhausted cause=ram published=0 refused=1 ram_free=0 slots_free=64 metadata_free=10",
        "SLIME_ROOT bootstrap exhausted cause=cnode-slots published=0 refused=1 ram_free=8192 slots_free=0 metadata_free=10",
        "SLIME_ROOT bootstrap exhausted cause=metadata published=0 refused=1 ram_free=8192 slots_free=64 metadata_free=0",
        "SLIME_ROOT bootstrap boundaries complete cases=3 published=1",
        "SLIME_GRAPH staged task=0 instance=init",
        "SLIME_GRAPH HEALTHY generation=1 required=1 live=0 completed=1 failed=0",
    ]
    transcript = "\n".join(lines)
    mutations = []
    for old, new in (("slots=64", "slots=63"), ("transaction=12", "transaction=64"), ("recursion=0", "recursion=1"), ("fit=1", "fit=0"), ("remaining=8192", "remaining=8191"), ("cases=3", "cases=2"), ("complete cases=3 published=1", "complete cases=3 published=0")):
        mutations.append((old, transcript.replace(old, new, 1)))
    for index in (2, 3, 4):
        for old, new in (("published=0", "published=1"), ("refused=1", "refused=0")):
            mutations.append((f"refusal {index} {old}", transcript.replace(lines[index], lines[index].replace(old, new))))
        for field in ("ram_free", "slots_free", "metadata_free"):
            value = int(re.search(rf"{field}=(\d+)", lines[index]).group(1))
            changed = re.sub(rf"{field}=\d+", f"{field}={int(value == 0)}", lines[index])
            mutations.append((f"non-independent exhaustion {index} {field}", transcript.replace(lines[index], changed)))
    mutations += [
        ("duplicate cause", transcript.replace(lines[2], lines[2] + "\n" + lines[2])),
        ("cause omitted", transcript.replace("cause=metadata", "cause=ram")),
        ("refusal after completion", "\n".join(lines[:4] + [lines[5], lines[4]] + lines[6:])),
        ("first publication before refusal", lines[6] + "\n" + transcript),
        ("refusal before reservation", "\n".join([lines[0], lines[2], lines[1]] + lines[3:])),
        ("duplicate reserve", transcript.replace(lines[1], lines[1] + "\n" + lines[1])),
    ]
    return check_adaptive_control_mutations(gate.check_bootstrap_boundaries, "bootstrap boundaries:", lines, mutations)


def check_private_elastic_controls(gate) -> int:
    census = (
        "ordinary=1587035824 retained=10512 reusable=0 live_bytes=512 extents_active=0 "
        "extents_anchored=0 slots_free=523220 descriptors_free=400000 "
        "extent_records_free=2048 metadata=851888"
    )
    lines = [
        f"SLIME_MEM elastic census phase=admitted {census}",
        "SLIME_MEM elastic admitted pool_bytes=33554432 guarantee_pages=64 holders=3",
        "SLIME_MEM elastic idle subject=qualification-idle maximum=65536 reserved_bytes=0 "
        "pool_before=33554432 pool_after=33554432",
        "SLIME_MEM elastic grow subject=qualification-bulk committed=512 bytes=2097152 "
        "pool_after=31457280",
        "SLIME_MEM elastic refused subject=qualification-bulk pages=512 cause=policy "
        "committed=512 peer_committed=0",
        "SLIME_MEM elastic guarantee subject=qualification-guaranteed-holder committed=64 "
        "promised=64 served=1",
        "SLIME_MEM elastic idle_request subject=qualification-idle served=1 committed=1",
        "SLIME_MEM elastic intact bulk=1 guaranteed=1 idle=1 pages=577",
        f"SLIME_MEM elastic census phase=served {census}",
        f"SLIME_MEM elastic census phase=retired {census}",
        "SLIME_MEM elastic complete case=idle-and-guarantee holders=3 granted=577 reclaimed=577",
        "SLIME_GRAPH HEALTHY generation=1 required=1 live=0 completed=1 failed=0",
    ]
    transcript = "\n".join(lines)
    mutations = [
        ("idle maximum reserved bytes", transcript.replace("reserved_bytes=0", "reserved_bytes=4096")),
        ("idle maximum shrank the pool", transcript.replace("pool_before=33554432 pool_after=33554432", "pool_before=33554432 pool_after=31457280")),
        ("idle holder had no authorization", transcript.replace("maximum=65536", "maximum=0")),
        ("peer consumed nothing", transcript.replace("grow subject=qualification-bulk committed=512 bytes=2097152", "grow subject=qualification-bulk committed=0 bytes=0")),
        ("grown bytes do not match pages", transcript.replace("bytes=2097152", "bytes=2097151")),
        ("refusal changed committed pages", transcript.replace("cause=policy committed=512", "cause=policy committed=256")),
        ("idle neighbour silently held pages", transcript.replace("peer_committed=0", "peer_committed=4")),
        ("guarantee unserved", transcript.replace("promised=64 served=1", "promised=64 served=0")),
        ("guarantee partially served", transcript.replace("guarantee subject=qualification-guaranteed-holder committed=64", "guarantee subject=qualification-guaranteed-holder committed=32")),
        ("guarantee served before exhaustion", "\n".join(lines[:4] + [lines[5], lines[4]] + lines[6:])),
        ("a refusal damaged the peer", transcript.replace("intact bulk=1", "intact bulk=0")),
        ("a refusal damaged the guarantee", transcript.replace("guaranteed=1 idle=1", "guaranteed=0 idle=1")),
    ]
    return check_adaptive_control_mutations(
        gate.check_idle_and_guarantee, "elastic guarantee:", lines, mutations
    )


def check_private_fragmentation_controls(gate) -> int:
    lines = [
        "SLIME_MEM elastic inventory pool_bytes=33554432 largest_aligned=2097152 retained=10512 reusable=0",
        "SLIME_MEM elastic request kind=single pages=1 committed=1 charged=8192 large=0 base=1 tables=1",
        "SLIME_MEM elastic request kind=mixed pages=515 committed=515 charged=2113536 large=1 base=3 tables=1",
        "SLIME_MEM elastic fragmented ordinary_aligned=0 served=1 committed=2 retained=2144496 reusable=0",
        "SLIME_MEM elastic fragmented_span served=0 cause=acquisition committed=515",
        "SLIME_MEM elastic request kind=bulk pages=7168 committed=7168 charged=29360128 large=14 base=0 tables=0",
        "SLIME_MEM elastic cost small_bytes_per_page=8192 bulk_bytes_per_page=4096",
        "SLIME_MEM elastic refusal kind=bulk resource=policy pool_bytes=2068480 ordinary=1544896256 retained=8370368 reusable=2097152",
        "SLIME_MEM elastic next kind=fitting served=1 committed=3 pool_bytes=2064384",
        "SLIME_MEM elastic reuse returned_pages=7168 reused_extents=1 served=1 committed=515",
        "SLIME_MEM elastic complete case=mixed-fragmentation granted=8198 reclaimed=8198",
        "SLIME_GRAPH HEALTHY generation=1 required=1 live=0 completed=1 failed=0",
    ]
    transcript = "\n".join(lines)
    mutations = [
        ("a single page charged a span", transcript.replace("charged=8192", "charged=2097152")),
        ("the mixed request took no large frame", transcript.replace("charged=2113536 large=1", "charged=2113536 large=0")),
        ("the mixed request took no base page", transcript.replace("large=1 base=3", "large=1 base=0")),
        ("bulk capacity reported as the small-page cost", transcript.replace("bulk_bytes_per_page=4096", "bulk_bytes_per_page=8192")),
        ("fragmented service still had an aligned block", transcript.replace("ordinary_aligned=0", "ordinary_aligned=2097152")),
        ("page-granular growth was refused", transcript.replace("ordinary_aligned=0 served=1", "ordinary_aligned=0 served=0")),
        ("the span refusal was an authorization answer", transcript.replace("cause=acquisition", "cause=policy")),
        ("the unbackable span was served", transcript.replace("fragmented_span served=0", "fragmented_span served=1")),
        ("no fitting request followed the refusal", transcript.replace("next kind=fitting served=1", "next kind=fitting served=0")),
        ("returned extents were not reused", transcript.replace("reused_extents=1", "reused_extents=0")),
        ("nothing was returned to reuse", transcript.replace("returned_pages=7168", "returned_pages=0")),
    ]
    return check_adaptive_control_mutations(
        gate.check_mixed_fragmentation, "elastic fragmentation:", lines, mutations
    )


def check_private_rollback_controls(gate) -> int:
    def stage(name: str, *, committed: int = 8, retained: int = 0, sentinels: int = 1, quarantined: int = 0) -> str:
        pool = 33480704
        return (
            f"SLIME_MEM elastic injected stage={name} cause=acquisition committed={committed} "
            f"pool_before={pool} pool_after={pool - retained * 4096} ordinary_before=1584725712 "
            f"ordinary_after=1584725712 retained_tables={retained} sentinels={sentinels} "
            f"quarantined={quarantined}"
        )

    lines = [
        "SLIME_MEM elastic baseline committed=8 charged=16384 pool_bytes=33480704 peer=8",
        stage("extent"),
        stage("descriptors"),
        stage("retype"),
        stage("table-map"),
        stage("frame-map", retained=1),
        stage("near-limit-descriptors"),
        "SLIME_MEM elastic retry stage=all committed=12 charged=16384 clean=16384 doubled=0",
        "SLIME_MEM elastic quarantine stage=cleanup cause=cleanup owned=1 refused=1 released=1 "
        "remaining=0 pool_held=33443840 pool_after=33443840",
        *(f"SLIME_MEM elastic acquisition_quarantine stage={stage} committed=4 peer=8 "
          "sentinels=1 retained=4096 charged=4096 retry_refund=0 pre_acquire_refused=1 "
          "refund=24576 pool_held=33000000 pool_after=33024576 root_before=8192 "
          "root_after=8192 retired_once=1"
          for stage in ("extent-revoke", "descriptors-revoke")),
        "SLIME_MEM elastic complete case=failure-rollback stages=7 granted=20 reclaimed=20",
        "SLIME_GRAPH HEALTHY generation=1 required=1 live=0 completed=1 failed=0",
    ]
    transcript = "\n".join(lines)
    mutations = [
        ("a failed stage changed committed pages", transcript.replace(lines[1], stage("extent", committed=12))),
        ("a failed stage damaged a sentinel", transcript.replace(lines[2], stage("descriptors", sentinels=0))),
        ("a failed stage kept resources owned", transcript.replace(lines[3], stage("retype", quarantined=1))),
        ("a failed stage kept pool bytes", transcript.replace(lines[4], stage("table-map").replace("pool_after=33480704", "pool_after=33476608"))),
        ("a retained table was not charged", transcript.replace(lines[5], stage("frame-map", retained=1).replace("pool_after=33476608", "pool_after=33480704"))),
        ("no stage reached a span-bound table", transcript.replace(lines[5], stage("frame-map"))),
        ("stages ran out of order", "\n".join(lines[:1] + [lines[2], lines[1]] + lines[3:])),
        ("the retry charged twice", transcript.replace("charged=16384 clean=16384 doubled=0", "charged=32768 clean=16384 doubled=0")),
        ("the retry admitted doubling", transcript.replace("doubled=0", "doubled=1")),
        ("a failed cleanup owned nothing", transcript.replace("owned=1 refused=1", "owned=0 refused=1")),
        ("a quarantined holder was served", transcript.replace("refused=1 released=1", "refused=0 released=1")),
        ("the quarantine was not retryable", transcript.replace("released=1 remaining=0", "released=0 remaining=0")),
        ("the retry left resources owned", transcript.replace("remaining=0", "remaining=1")),
        ("the cleanup case preceded its stages", "\n".join([lines[0], lines[8]] + lines[1:8] + lines[9:])),
        ("acquisition quarantine missing", transcript.replace(lines[9], "")),
        ("acquisition quarantine duplicated", transcript.replace(lines[9], lines[9] + "\n" + lines[9])),
        ("acquisition quarantine order", "\n".join(lines[:9] + [lines[10], lines[9]] + lines[11:])),
        ("acquisition quarantine uncharged", transcript.replace("charged=4096", "charged=0")),
        ("acquisition quarantine empty", transcript.replace("retained=4096 charged=4096", "retained=0 charged=0")),
        ("acquisition retry refunded", transcript.replace("retry_refund=0", "retry_refund=1")),
        ("acquisition after quarantine retry", transcript.replace("pre_acquire_refused=1", "pre_acquire_refused=0")),
        ("acquisition committed pages changed", transcript.replace("committed=4 peer=8", "committed=5 peer=8")),
        ("acquisition peer damaged", transcript.replace("peer=8 sentinels=1", "peer=8 sentinels=0")),
        ("acquisition retirement refund wrong", transcript.replace("pool_after=33024576", "pool_after=33024577")),
        ("acquisition retirement refunded root", transcript.replace("root_after=8192", "root_after=0")),
        ("acquisition retirement doubled", transcript.replace("retired_once=1", "retired_once=0")),
    ]
    return check_adaptive_control_mutations(
        gate.check_failure_rollback, "elastic rollback:", lines, mutations
    )


def check_private_conservation_controls(gate) -> int:
    lines = [
        "SLIME_MEM elastic holder subject=qualification-first committed=512 pattern=1 pool_bytes=29360128",
        "SLIME_MEM elastic retire subject=qualification-first revoked=1 returned_pages=512 "
        "pool_before=29360128 pool_after=31457280 reusable=2097152",
        "SLIME_MEM elastic reuse subject=qualification-second committed=512 reused_extents=1 "
        "zeroed=1 peer_pattern=1",
        "SLIME_MEM elastic revoke_failure subject=qualification-stuck first_attempt=0 retained=1 "
        "retry=1 pool_before=29323264 pool_held=29323264 pool_after=29360128",
        "SLIME_MEM elastic baseline phase=final owned_before=1587046336 owned_after=1587046336 "
        "slots_before=523220 slots_after=523167 pool_before=33554432 pool_after=33554432 "
        "granted=1544 reclaimed=1544",
        "SLIME_MEM elastic complete case=cross-holder-conservation holders=4 granted=1544 reclaimed=1544",
        "SLIME_GRAPH HEALTHY generation=1 required=1 live=0 completed=1 failed=0",
    ]
    transcript = "\n".join(lines)
    mutations = [
        ("a completed revoke returned nothing", transcript.replace("returned_pages=512", "returned_pages=0")),
        ("a completed revoke freed no capacity", transcript.replace("pool_before=29360128 pool_after=31457280", "pool_before=29360128 pool_after=29360128")),
        ("recovered pages carried the previous holder's bytes", transcript.replace("zeroed=1", "zeroed=0")),
        ("a peer's pattern was lost", transcript.replace("peer_pattern=1", "peer_pattern=0")),
        ("recovered extents were not reused", transcript.replace("reused_extents=1", "reused_extents=0")),
        ("the failed revoke reported success", transcript.replace("first_attempt=0", "first_attempt=1")),
        ("the failed revoke released ownership", transcript.replace("retained=1", "retained=0")),
        ("the failed revoke advertised capacity", transcript.replace("pool_held=29323264", "pool_held=31457280")),
        ("the retry lost capacity", transcript.replace("pool_held=29323264 pool_after=29360128", "pool_held=29323264 pool_after=29000000")),
        ("owned capacity drifted downward", transcript.replace("owned_after=1587046336", "owned_after=1587042240")),
        ("granted pages were never reclaimed", transcript.replace(lines[4], lines[4].replace("reclaimed=1544", "reclaimed=1540"))),
        ("no root CSlots survived", transcript.replace("slots_after=523167", "slots_after=0")),
    ]
    return check_adaptive_control_mutations(
        gate.check_cross_holder_conservation, "elastic conservation:", lines, mutations
    )


# MEM-ADAPTIVE's synthetic schedule. The deltas are the ones the coordinator's
# own table produces; restating them here is what lets a control transcript
# exist at all, and every assertion the gate makes about them is derived from
# the *composition's* declared maxima rather than from these numbers.
ADAPTIVE_UNIT = 257
ADAPTIVE_ROUNDS = 3


def adaptive_control_schedule(policy: dict) -> list[tuple[str, int]]:
    """`(instance, delta)` for each of the eighteen scheduled requests."""
    guaranteed = "private-adaptive-guaranteed"
    pool_a, pool_b = "private-adaptive-pool-a", "private-adaptive-pool-b"
    guarantee = policy["entitlements"]["adaptive-guaranteed"]["guaranteePages"]
    pool_maximum = policy["subjects"][pool_a]["maximumPages"]
    guaranteed_maximum = policy["subjects"][guaranteed]["maximumPages"]
    held = (ADAPTIVE_ROUNDS + 1) * ADAPTIVE_UNIT
    schedule = [(pool_b, ADAPTIVE_UNIT), (pool_a, ADAPTIVE_UNIT), (guaranteed, guarantee)]
    for _ in range(ADAPTIVE_ROUNDS):
        schedule += [
            (pool_a, ADAPTIVE_UNIT),
            (pool_b, ADAPTIVE_UNIT),
            (guaranteed, ADAPTIVE_UNIT),
        ]
    schedule += [
        (pool_a, pool_maximum - held),
        (pool_b, pool_maximum - held + 1),
        (guaranteed, guaranteed_maximum - guarantee - ADAPTIVE_ROUNDS * ADAPTIVE_UNIT + 1),
        (pool_a, ADAPTIVE_UNIT),
        (pool_b, ADAPTIVE_UNIT),
        (guaranteed, ADAPTIVE_UNIT),
    ]
    return schedule


def adaptive_control_transcript(gate, policy: dict) -> list[str]:
    """A complete, self-consistent adaptive transcript, line by line.

    Every line has to be load-bearing: `check_adaptive_control_mutations`
    deletes each one in turn and requires a refusal, so a decorative line here
    would be reported as a hole in the gate rather than in this fixture.
    """
    identity = gate.entitlement_identity
    base = "0x10000000"
    pool = 1_610_612_736
    subjects = policy["subjects"]
    entitlements = policy["entitlements"]
    guarantee_pages = sum(entry["guaranteePages"] for entry in entitlements.values())
    # What marker A reports is the guarantee reservation the root materialized,
    # not the declared operational reserve: one payload granule and one leaf
    # table per promised page, a descriptor and a CSlot for each, taken from
    # coarse aligned spans that each cost one extent and one anchor CSlot.
    spans = sum(
        -(-entry["guaranteePages"] // 512)
        for entry in entitlements.values()
        if entry["guaranteePages"]
    )
    reserve = {
        "bytes": guarantee_pages * 8192,
        "slots": guarantee_pages * 2 + spans * 2,
        "descriptors": guarantee_pages * 2,
        "extents": spans * 2,
        "tables": guarantee_pages,
    }

    io_window_end = hex(
        int(base, 16) + subjects["private-adaptive-io-holder"]["maximumPages"] * 4096
    )

    def incarnation(instance: str, live: int) -> str:
        subject = subjects[instance]
        return (
            f"SLIME_MEM adaptive incarnation instance={instance} "
            f"entitlement={identity(subject['entitlement'])} live={live} "
            "admitted=1 cause=ok"
        )

    def binding(task: int, instance: str, incarnation: int = 0) -> str:
        subject = subjects.get(instance)
        if subject is None:
            return (
                f"SLIME_MEM entitlement task={task} instance={instance} entitlement=none "
                "incarnation=0 guarantee=0 maximum=0 mode=none installed=0 base=0x0"
            )
        entitlement = entitlements[subject["entitlement"]]
        return (
            f"SLIME_MEM entitlement task={task} instance={instance} "
            f"entitlement={identity(subject['entitlement'])} incarnation={incarnation} "
            f"guarantee={entitlement['guaranteePages']} maximum={subject['maximumPages']} "
            f"mode={subject['maximumMode']} installed={subject['maximumPages']} base={base}"
        )

    lines = [
        f"SLIME_MEM policy entitlements={len(entitlements)} subjects={len(subjects)} "
        f"guarantee_pages={guarantee_pages} reserved_bytes={reserve['bytes']} "
        f"reserved_slots={reserve['slots']} reserved_descriptors={reserve['descriptors']} "
        f"reserved_extents={reserve['extents']} reserved_tables={reserve['tables']} "
        f"pool_bytes={pool}",
        binding(1, "init"),
        binding(2, "private-adaptive-coordinator"),
        binding(10, "private-adaptive-io-supervisor"),
        incarnation("private-adaptive-pool-b", 1),
        binding(3, "private-adaptive-pool-b"),
        "[private-adaptive] coordinator subject=private-adaptive-coordinator "
        "entitlement=none base=0x0 pages=0 refused=1",
        incarnation("private-adaptive-guaranteed", 2),
        binding(4, "private-adaptive-guaranteed"),
        incarnation("private-adaptive-pool-a", 3),
        binding(5, "private-adaptive-pool-a"),
        # The IO holder's block, in the order a boot produces it: bound during
        # construction, then its own positive controls, then the four refused
        # destinations the root names against its window.
        incarnation("private-adaptive-io-holder", 4),
        binding(9, "private-adaptive-io-holder"),
        "[private-adaptive:io-supervisor] holder spawned",
        "[private-adaptive:io] outside_window mmio=1 queue=1",
        f"SLIME_MEM mapping refused task=9 base={base} end=0x10001000 "
        f"window={base}..{io_window_end}",
        f"SLIME_MEM mapping refused task=9 base=0x14000000 end=0x14001000 "
        f"window={base}..{io_window_end}",
        f"SLIME_MEM mapping refused task=9 base={base} end=0x10002000 "
        f"window={base}..{io_window_end}",
        f"SLIME_MEM mapping refused task=9 base=0x14000000 end=0x14002000 "
        f"window={base}..{io_window_end}",
        "[private-adaptive:io] mmio_backed_refused=1",
        "[private-adaptive:io] mmio_unbacked_refused=1",
        "[private-adaptive:io] queue_backed_refused=1",
        "[private-adaptive:io] queue_unbacked_refused=1",
        "[private-adaptive:io] pages=1",
        "[private-adaptive:io] device mappings excluded from the private window",
        # The root refuses a duplicate before a task exists, so the control
        # transcript carries the spawn refusal rather than a ledger bind that
        # never happens.
        "SLIME_GRAPH spawn refused task=2 child=private-adaptive-guaranteed "
        "class=instance-live",
        f"[private-adaptive] duplicate subject=private-adaptive-guaranteed refused=1 live_base={base}",
    ]
    tasks = {
        "private-adaptive-guaranteed": 4,
        "private-adaptive-pool-a": 5,
        "private-adaptive-pool-b": 3,
    }
    labels = {
        "private-adaptive-guaranteed": "guaranteed",
        "private-adaptive-pool-a": "pool-a",
        "private-adaptive-pool-b": "pool-b",
    }
    held = dict.fromkeys(tasks, 0)
    committed = dict.fromkeys(entitlements, 0)
    served_total = 0
    for number, (instance, delta) in enumerate(adaptive_control_schedule(policy)):
        subject = subjects[instance]
        entitlement = subject["entitlement"]
        promise = entitlements[entitlement]["guaranteePages"]
        pages = held[instance]
        # Only the three boundary steps are refused, distinguished by which
        # declaration they cross: past a subject maximum, or inside it but past
        # any inventory. Every other request fits and is served.
        cause = None
        if number in (gate.ADAPTIVE_POOL_REFUSAL, *gate.ADAPTIVE_DECLARED_REFUSALS):
            cause = "maximum" if pages + delta > subject["maximumPages"] else "resource"
        if cause is None:
            from_guarantee = max(0, min(delta, promise - committed[entitlement]))
            held[instance] = pages + delta
            committed[entitlement] += delta
            served_total += 1
            lines.append(
                f"SLIME_MEM adaptive grant task={tasks[instance]} instance={instance} "
                f"entitlement={identity(entitlement)} delta={delta} previous={pages} "
                f"pages={held[instance]} guaranteed={from_guarantee} "
                f"elastic={delta - from_guarantee} "
                f"entitlement_committed={committed[entitlement]} pool_bytes={pool} base={base}"
            )
        else:
            lines.append(
                f"SLIME_MEM adaptive refused task={tasks[instance]} instance={instance} "
                f"entitlement={identity(entitlement)} delta={delta} pages={pages} "
                f"cause={cause} entitlement_committed={committed[entitlement]} "
                f"pool_bytes={pool}"
            )
        lines.append(
            f"[private-adaptive] step={number} subject={instance} delta={delta} "
            f"served={int(cause is None)} pages={held[instance]} base={base}"
        )
        lines.append(
            f"[private-adaptive:{labels[instance]}] request incarnation=0 delta={delta} "
            f"served={int(cause is None)} pages={held[instance]} base={base} "
            f"zeroed={int(cause is None)} stable=1"
        )
    steps = len(adaptive_control_schedule(policy))
    lines.append(
        f"[private-adaptive] schedule steps={steps} served={served_total} "
        f"refused={steps - served_total} digest=0x{'1234567890abcdef'}"
    )

    restart = "private-adaptive-restart"
    promise = entitlements[subjects[restart]["entitlement"]]["guaranteePages"]
    restart_identity = identity(subjects[restart]["entitlement"])
    lines += [
        incarnation(restart, 5),
        binding(6, restart),
        f"SLIME_MEM adaptive grant task=6 instance={restart} entitlement={restart_identity} "
        f"delta={promise} previous=0 pages={promise} guaranteed={promise} elastic=0 "
        f"entitlement_committed={promise} pool_bytes={pool} base={base}",
        f"[private-adaptive] restart subject={restart} incarnation=0 base={base} "
        f"pages={promise} end=fault",
        f"[private-adaptive:restart] end incarnation=0 pages={promise} refused=0 kind=fault",
        f"SLIME_MEM adaptive retired task=6 instance={restart} entitlement={restart_identity} "
        f"returned_pages={promise} entitlement_committed=0 quarantined=0",
        incarnation(restart, 5),
        binding(7, restart, incarnation=1),
        f"SLIME_MEM adaptive grant task=7 instance={restart} entitlement={restart_identity} "
        f"delta={promise} previous=0 pages={promise} guaranteed={promise} elastic=0 "
        f"entitlement_committed={promise} pool_bytes={pool} base={base}",
        f"[private-adaptive] restart subject={restart} incarnation=1 base={base} "
        f"pages={promise} same_base=1 end=exit",
        f"[private-adaptive:restart] end incarnation=1 pages={promise} refused=0 kind=exit",
        binding(8, "private-adaptive-denied"),
        "SLIME_MEM adaptive refused task=8 instance=private-adaptive-denied entitlement=none "
        f"delta=1 pages=0 cause=entitlement entitlement_committed=0 pool_bytes={pool}",
        "[private-adaptive] denied subject=private-adaptive-denied pages=0 base=0x0 "
        "refused=1 end=exit",
        "[private-adaptive:denied] end incarnation=0 pages=0 refused=1 kind=exit",
        f"[private-adaptive] stable subjects=3 "
        f"guaranteed_pages={held['private-adaptive-guaranteed']} "
        f"pool_a_pages={held['private-adaptive-pool-a']} "
        f"pool_b_pages={held['private-adaptive-pool-b']}",
        f"[private-adaptive:guaranteed] end incarnation=0 "
        f"pages={held['private-adaptive-guaranteed']} refused=1 kind=exit",
        f"[private-adaptive:pool-a] end incarnation=0 pages={held['private-adaptive-pool-a']} "
        "refused=1 kind=exit",
        f"[private-adaptive:pool-b] end incarnation=0 pages={held['private-adaptive-pool-b']} "
        "refused=1 kind=exit",
        f"[private-adaptive] complete steps={steps} served={served_total} "
        f"refused={steps - served_total} restarts=1 duplicates=1 denied=1 exits=5 "
        f"digest=0x{'1234567890abcdef'}",
        "SLIME_GRAPH HEALTHY generation=1 required=1 live=0 completed=1 failed=0",
    ]
    return lines


MATRIX_CONTROL_POOL = 487864208


def matrix_walk_lines(task: int, instance: str, unit: int, served: int, limit: str) -> list[str]:
    """One holder's exhaustion walk as the root reports it: `served` grants at
    `unit`, then a halving refusal chain ending at one page with `limit`."""
    lines = []
    pages = 0
    for _ in range(served):
        lines.append(
            f"SLIME_MEM adaptive grant task={task} instance={instance} entitlement=0000000000000000 "
            f"delta={unit} previous={pages} pages={pages + unit} guaranteed=0 elastic={unit} "
            f"entitlement_committed={pages + unit} pool_bytes=0 base=0x400000"
        )
        pages += unit
    delta = unit
    while True:
        lines.append(
            f"SLIME_MEM adaptive refused task={task} instance={instance} entitlement=0000000000000000 "
            f"delta={delta} pages={pages} cause=pool entitlement_committed={pages} pool_bytes=0"
        )
        final = delta == 1
        lines.append(
            f"SLIME_MEM adaptive limit task={task} instance={instance} delta={delta} "
            + (limit if final else "resource=ledger-pool required=0 available=0 ledger_pool=0 "
               "inventory_bytes=16777216 inventory_slots=517340 largest_block=0")
        )
        inventory = re.search(r"inventory_bytes=(\d+)", lines[-1]).group(1)
        ledger = int(re.search(r"ledger_pool=(\d+)", lines[-1]).group(1))
        # Synthetic accounting witnesses the equations, not physical frame charges.
        lines.append(
            "SLIME_MEM funding reserve=16777216 root_owned=0 system_owned=0 "
            f"common_held={MATRIX_CONTROL_POOL - ledger} inventory_bytes={inventory}"
        )
        if final:
            return lines
        delta //= 2


def matrix_control_transcript(gate) -> list[str]:
    """A complete, self-consistent single-row matrix transcript, line by line."""
    bulk, small = gate.MATRIX_BULK_UNIT, gate.MATRIX_SMALL_UNIT
    exhausted = (
        "resource=ledger-pool required=0 available=0 ledger_pool=0 inventory_bytes=16777216 "
        "inventory_slots=517340 largest_block=0"
    )
    census = (
        "SLIME_MEM census retired={} free_slots=517340 untyped=5521312 reusable=0 anchors=3 "
        "mapped_pages=0 allocations_free=10 shared_reusable=0 shared_anchors=0 "
        "active_extent_bytes=0 preserved_bytes=0 preserved_anchors=0 infrastructure_owned=65536"
    )
    lines = [
        "SLIME_ROOT ordinary range=0 paddr=0x60000000 bytes=536870912",
        "SLIME_ROOT ordinary ranges=1 bytes=536870912 end=0x80000000",
        "SLIME_MEM policy entitlements=2 subjects=3 guarantee_pages=1024 reserved_bytes=8388608 "
        "reserved_slots=2052 reserved_descriptors=2048 reserved_extents=4 reserved_tables=1024 "
        f"pool_bytes={MATRIX_CONTROL_POOL}",
        "SLIME_MEM entitlement task=2 instance=private-matrix-guaranteed entitlement=0000000000000000 incarnation=0 guarantee=1024 maximum=2048 mode=fixed installed=2048 base=0x400000",
        "[private-matrix:bulk] verified incarnation=0 base=0x400000 pages=0 pattern=1 refused=0",
        *matrix_walk_lines(3, "private-matrix-bulk", bulk, 3, exhausted),
        "[private-matrix] guarantee pressure redeemed=1 beyond_promise_served=0 pages=1024",
        "[private-matrix] idle maximum subject=private-matrix-small pages=0 refused=1",
        "[private-matrix:small] end incarnation=0 pages=0 refused=1 kind=exit",
        "[private-matrix] reserve spawn subject=private-matrix-small incarnation=1 pages=0 refused=1",
        f"[private-matrix] exhausted schedule=bulk subject=private-matrix-bulk incarnation=0 "
        f"pages={3 * bulk} served=3 refused=16 final_delta=1",
        f"[private-matrix] resident schedule=bulk pages={3 * bulk + 1024} "
        f"bytes={(3 * bulk + 1024) * 4096} guaranteed=1024 bulk={3 * bulk} small=0",
        f"[private-matrix:bulk] end incarnation=0 pages={3 * bulk} refused=16 kind=exit",
        *matrix_walk_lines(5, "private-matrix-small", small, 4, exhausted),
        f"[private-matrix] exhausted schedule=small subject=private-matrix-small incarnation=1 "
        f"pages={4 * small} served=4 refused=9 final_delta=1",
        f"[private-matrix] resident schedule=small pages={4 * small + 1024} "
        f"bytes={(4 * small + 1024) * 4096} guaranteed=1024 bulk=0 small={4 * small}",
        f"[private-matrix:small] end incarnation=1 pages={4 * small} refused=9 kind=exit",
        *matrix_walk_lines(6, "private-matrix-bulk", bulk, 2, exhausted),
        *matrix_walk_lines(7, "private-matrix-small", small, 1, exhausted),
        f"[private-matrix] exhausted schedule=mixed subject=private-matrix-bulk incarnation=1 "
        f"pages={2 * bulk} served=2 refused=16 final_delta=1",
        f"[private-matrix] exhausted schedule=mixed subject=private-matrix-small incarnation=2 "
        f"pages={small} served=1 refused=9 final_delta=1",
        f"[private-matrix] resident schedule=mixed pages={2 * bulk + small + 1024} "
        f"bytes={(2 * bulk + small + 1024) * 4096} guaranteed=1024 bulk={2 * bulk} small={small}",
        "[private-matrix] mixed probe begin",
        "SLIME_MEM entitlement task=8 instance=private-matrix-probe entitlement=none incarnation=0 guarantee=0 maximum=0 mode=none installed=0 base=0x0",
        "SLIME_GRAPH spawned task=1 child=8 component=private-matrix-probe grants=0 endpoints=0 notifications=0 handle=1 supervision_grants=0 buffer_factory_grants=0",
        "SLIME_MEM adaptive refused task=8 instance=private-matrix-probe entitlement=none delta=1 pages=0 cause=entitlement entitlement_committed=0 pool_bytes=0",
        "[private-matrix:probe] ran pages=0 base=0x0 refused=1",
        "SLIME_GRAPH component exit task=8 status=0",
        "SLIME_ROOT reclaim census task=8 slots=0 bytes=0 live_objects=0 extent_reuses=0",
        "[private-matrix:guaranteed] verified incarnation=0 base=0x400000 pages=1024 pattern=1 refused=1",
        f"[private-matrix:bulk] verified incarnation=1 base=0x400000 pages={2 * bulk} pattern=1 refused=16",
        f"[private-matrix:small] verified incarnation=2 base=0x400000 pages={small} pattern=1 refused=9",
        f"[private-matrix] mixed probe complete resident={2 * bulk + small + 1024} preserved=1",
        f"[private-matrix:bulk] end incarnation=1 pages={2 * bulk} refused=16 kind=exit",
        f"[private-matrix:small] end incarnation=2 pages={small} refused=9 kind=exit",
        census.format(8),
        "SLIME_ALLOC preserved parent=1 slot=2 paddr=4096 bytes=4096",
        f"[private-matrix] cycles begin count={gate.MATRIX_CYCLES} pages={gate.MATRIX_CYCLE_PAGES}",
    ]
    for cycle in range(gate.MATRIX_CYCLES):
        victim, reuser = ("bulk", "small") if cycle % 2 == 0 else ("small", "bulk")
        lines += [
            census.format(9 + 2 * cycle),
            f"[private-matrix] cycle={cycle} victim=private-matrix-{victim} incarnation={2 + cycle} "
            f"end={'fault' if cycle % 4 < 2 else 'exit'} reuser=private-matrix-{reuser} "
            f"incarnation={3 + cycle} pages={gate.MATRIX_CYCLE_PAGES} zeroed=1 peer_pages=1024",
        ]
    lines += [
        "[private-matrix:guaranteed] end incarnation=0 pages=1024 refused=1 kind=exit",
        f"[private-matrix] complete schedules=3 cycles={gate.MATRIX_CYCLES}",
        census.format(9 + 2 * gate.MATRIX_CYCLES),
        "SLIME_GRAPH HEALTHY generation=1 required=1 live=0 completed=1 failed=0",
    ]
    return lines


def check_private_matrix_controls(gate) -> int:
    """MEM-ADAPTIVE's inventory matrix: exhaustion, reuse and cross-row claims.

    A still-fitting refusal, an exhaustion that was really a declaration, a
    refusal with no named cost, a walk that skipped its halving, a holder whose
    report disagrees with the root, census drift across a reuse cycle, reuse by
    the dying holder itself, and every cross-row identity and growth claim must
    each be refused.
    """
    reserve = gate.matrix_policy(gate.MATRIX_FIXTURES["qemu-arm-virt"])["reserve"]["bytes"]
    lines = matrix_control_transcript(gate)
    transcript = "\n".join(lines)
    measured = gate.check_matrix_transcript(transcript, reserve, "control: ")
    for schedule in measured["schedules"].values():
        for instance, walk in schedule["walks"].items():
            if any(walk.get(key) != value for key, value in {
                "reserve": reserve, "root_owned": 0, "system_owned": 0,
                "common_held": MATRIX_CONTROL_POOL,
            }.items()):
                fail("matrix control: final funding fields were not exposed")
            boundary = {**walk, "ledger_pool": 8192, "inventory_bytes": reserve + 8192,
                        "common_held": MATRIX_CONTROL_POOL - 8192}
            gate.check_matrix_limit({**boundary, "resource": "ordinary-layout"}, instance, reserve, "control: ")
            require_rejection("ledger refused a page at its exact funding boundary", "control: ",
                              lambda boundary=boundary, instance=instance: gate.check_matrix_limit(
                                  boundary, instance, reserve, "control: "))
            for resource in gate.MATRIX_EXHAUSTION_RESOURCES:
                gate.check_matrix_limit({**walk, "resource": resource, "required": 1,
                                         "available": 0}, instance, reserve, "control: ")
            require_rejection("final funding reserve differs from declaration", "control: ",
                              lambda walk=walk, instance=instance: gate.check_matrix_limit(
                                  {**walk, "reserve": reserve + 1}, instance, reserve, "control: "))
    final = "delta=1 resource=ledger-pool required=0 available=0 ledger_pool=0 inventory_bytes=16777216"
    bulk = gate.MATRIX_BULK_UNIT
    mutations = [
        ("probe received hidden grants", transcript.replace(
            "component=private-matrix-probe grants=0", "component=private-matrix-probe grants=1", 1)),
        ("probe received buffer authority", transcript.replace(
            "supervision_grants=0 buffer_factory_grants=0", "supervision_grants=0 buffer_factory_grants=1", 1)),
        ("admitted pool does not conserve final funding", transcript.replace(
            f"pool_bytes={MATRIX_CONTROL_POOL}", f"pool_bytes={MATRIX_CONTROL_POOL + 1}", 1)),
        ("still-fitting refusal", transcript.replace(
            final, final.replace("inventory_bytes=16777216", f"inventory_bytes={reserve + (1 << 20)}"), 1)),
        ("invented fit under a counted resource", transcript.replace(
            final, "delta=1 resource=ordinary-bytes required=4096 available=8192 ledger_pool=0 "
            "inventory_bytes=16777216", 1)),
        ("ledger refused a page it could fund", transcript.replace(
            final, final.replace("ledger_pool=0", "ledger_pool=8192"), 1)),
        ("exhaustion was a declaration", transcript.replace(
            final, final.replace("resource=ledger-pool", "resource=maximum"), 1)),
        ("refusal with no named cost", "\n".join(
            line for index, line in enumerate(lines)
            if not (line.startswith("SLIME_MEM adaptive limit") and "delta=16384 " in line
                    and "instance=private-matrix-bulk" in line and index < 40))),
        ("walk skipped its halving", transcript.replace(
            " delta=16384 pages=", " delta=8192 pages=", 1)),
        ("grant disagrees with the extent", transcript.replace(
            f"delta={bulk} previous={bulk} pages={2 * bulk}", f"delta={bulk} previous={bulk} pages={2 * bulk + 1}", 1)),
        ("holder report disagrees with the root", transcript.replace(
            f"pages={3 * bulk} served=3 refused=16", f"pages={3 * bulk + 1} served=3 refused=16", 1)),
        ("resident total is not the holders' sum", transcript.replace(
            f"resident schedule=bulk pages={3 * bulk + 1024}", f"resident schedule=bulk pages={3 * bulk + 1025}", 1)),
        ("missing per-cycle census", "\n".join(
            line for line in lines if not line.startswith("SLIME_MEM census retired=19 "))),
        ("census drifted across a cycle", transcript.replace(
            "SLIME_MEM census retired=19 free_slots=517340", "SLIME_MEM census retired=19 free_slots=517339", 1)),
        ("the dying holder reused its own capacity", transcript.replace(
            "victim=private-matrix-bulk incarnation=2 end=fault reuser=private-matrix-small",
            "victim=private-matrix-bulk incarnation=2 end=fault reuser=private-matrix-bulk", 1)),
        ("a cycle ended by the wrong path", transcript.replace(
            "incarnation=2 end=fault", "incarnation=2 end=exit", 1)),
        ("a cycle is missing", "\n".join(line for line in lines if not line.startswith("[private-matrix] cycle=7 "))),
        ("a reuser was not zeroed", transcript.replace("pages=4095 zeroed=1", "pages=4095 zeroed=0", 1)),
        ("explicit holder failure", transcript + "\n[private-matrix:small] FAIL a newly served word was not zero"),
        ("explicit coordinator failure", transcript + "\n[private-matrix] FAIL injected"),
        ("adopted backing counted twice", transcript.replace(
            f"retired={9 + 2 * gate.MATRIX_CYCLES} free_slots=517340 untyped=5521312",
            f"retired={9 + 2 * gate.MATRIX_CYCLES} free_slots=517340 untyped=5455776", 1).replace(
            "active_extent_bytes=0 preserved_bytes=0 preserved_anchors=0 infrastructure_owned=65536\n"
            "SLIME_GRAPH",
            "active_extent_bytes=65536 preserved_bytes=0 preserved_anchors=0 infrastructure_owned=131072\n"
            "SLIME_GRAPH", 1)),
    ]
    for index, line in enumerate(lines):
        if not line.startswith("SLIME_MEM adaptive limit"):
            continue
        funding = lines[index + 1]
        mutations.append((f"limit {index} missing funding", "\n".join(
            lines[:index + 1] + lines[index + 2:]
        )))
        mutations.append((f"limit {index} wrong declared reserve", "\n".join(
            lines[:index + 1] + [funding.replace(f"reserve={reserve}", f"reserve={reserve + 1}")]
            + lines[index + 2:]
        )))
        if " delta=1 " not in line:
            continue
        for resource in ("unknown", "arithmetic", "payload-funding", "cleanup", "transaction-extents"):
            mutations.append((f"final refusal {index} invalid resource {resource}", "\n".join(
                lines[:index] + [line.replace("resource=ledger-pool", f"resource={resource}")]
                + lines[index + 1:]
            )))
        for resource in ("root-funding", "operational-reserve"):
            mutations.append((f"final refusal {index} {resource} required equals available", "\n".join(
                lines[:index] + [line.replace("resource=ledger-pool required=0 available=0",
                                             f"resource={resource} required=4096 available=4096")]
                + lines[index + 1:]
            )))
        for field in ("root_owned", "system_owned", "common_held"):
            value = int(re.search(rf"{field}=(\d+)", funding).group(1))
            mutations.append((f"final funding {index} hidden {field} charge", "\n".join(
                lines[:index + 1] + [funding.replace(f"{field}={value}", f"{field}={value + 1}")]
                + lines[index + 2:]
            )))
        for residual in (reserve + 1, reserve + 8192):
            mutations.append((f"final funding {index} ledger and residual disagree", "\n".join(
                lines[:index] + [re.sub(r"inventory_bytes=\d+", f"inventory_bytes={residual}", record)
                                 for record in (line, funding)] + lines[index + 2:]
            )))
        mutations.append((f"final funding {index} ledger changes without conserved pool", "\n".join(
            lines[:index] + [line.replace("ledger_pool=0", "ledger_pool=1").replace(
                f"inventory_bytes={reserve}", f"inventory_bytes={reserve + 1}"),
                funding.replace(f"inventory_bytes={reserve}", f"inventory_bytes={reserve + 1}")]
            + lines[index + 2:]
        )))
        for field in ("reserve", "root_owned", "system_owned", "common_held", "inventory_bytes"):
            mutations.append((f"final funding {index} missing {field}", "\n".join(
                lines[:index + 1] + [re.sub(rf" {field}=\d+", "", funding)] + lines[index + 2:]
            )))
        mutations.append((f"final funding {index} mismatched inventory", "\n".join(
            lines[:index + 1] + [re.sub(r"inventory_bytes=\d+", f"inventory_bytes={reserve + 1}", funding)]
            + lines[index + 2:]
        )))
        mutations.append((f"final funding {index} not immediate", "\n".join(
            lines[:index + 1] + ["SLIME_ROOT unrelated record", funding] + lines[index + 2:]
        )))
        for residual in (reserve - 1, reserve + 8193):
            mutations.append((f"final refusal {index} residual {residual} outside reserve bound", "\n".join(
                lines[:index] + [re.sub(r"inventory_bytes=\d+", f"inventory_bytes={residual}", record)
                                 for record in (line, funding)] + lines[index + 2:]
            )))
    probe_begin = lines.index("[private-matrix] mixed probe begin")
    probe_end = next(index for index, line in enumerate(lines) if line.startswith("[private-matrix] mixed probe complete"))
    for index in range(probe_begin, probe_end + 1):
        mutations.append((f"probe evidence {index} missing", "\n".join(lines[:index] + lines[index + 1:])))
    # Keep every record, but move construction before the last holder's final
    # refusal or after either holder's release; presence alone cannot qualify it.
    block = lines[probe_begin:probe_end + 1]
    without = lines[:probe_begin] + lines[probe_end + 1:]
    early = next(index for index, line in enumerate(without) if "limit task=7 " in line and " delta=1 " in line)
    mutations.append(("probe before both holders exhausted", "\n".join(without[:early] + block + without[early:])))
    for role in ("bulk", "small"):
        release = next(index for index, line in enumerate(without) if line.startswith(f"[private-matrix:{role}] end incarnation={1 if role == 'bulk' else 2} "))
        mutations.append((f"probe after {role} release", "\n".join(without[:release + 1] + block + without[release + 1:])))
    for task in (2, 6, 7):
        mutations.append((f"root retires holder {task} before probe", transcript.replace(
            "[private-matrix] mixed probe begin", f"SLIME_GRAPH component exit task={task} status=0\n[private-matrix] mixed probe begin", 1)))
    for index in range(probe_begin + 1, probe_end):
        reordered = lines.copy()
        reordered[index], reordered[index + 1] = reordered[index + 1], reordered[index]
        # The three peer verification records have no ordering requirement.
        if " verified " in lines[index] and " verified " in lines[index + 1]:
            continue
        mutations.append((f"probe records {index} transposed", "\n".join(reordered)))
    for description, mutated in mutations:
        if mutated == transcript:
            fail(f"matrix control {description}: mutation did not change evidence")
        require_rejection(description, "control: ",
                          lambda mutated=mutated: gate.check_matrix_transcript(mutated, reserve, "control: "))

    kernel = [{"start": "0x60000000", "end": "0x80000000", "bytes": 1 << 29}]
    gate.check_matrix_inventory(transcript, kernel, "control: ")
    require_rejection("device memory counted as ordinary", "control: ", lambda: gate.check_matrix_inventory(
        transcript.replace("paddr=0x60000000 bytes=536870912", "paddr=0x08000000 bytes=536870912", 1),
        kernel, "control: "))

    rows = (1024, 2048, 4096)

    def row(scale: int) -> dict:
        grown = {name: {"resident": value["resident"] * scale, "walks": value["walks"]}
                 for name, value in measured["schedules"].items()}
        return {"ordinary": measured["ordinary"] * scale, "pool": measured["pool"] * scale,
                "schedules": grown, "cycles": measured["cycles"]}

    def identity(scale: int) -> dict:
        record = {key: {"sha256": f"{key}-{scale}"} for key in ("kernel", "dtb", "loader", "image")}
        return {**record, "root": {"sha256": "root"}, "abi": "abi"}

    measurements = {size: row(size // 1024 * 4) for size in rows}
    identities = {size: identity(size) for size in rows}
    gate.check_matrix_rows(identities, measurements, rows, 2048)
    row_mutations = [
        ("rows share a kernel", {**identities, 4096: {**identities[4096], "kernel": identities[2048]["kernel"]}},
         measurements, rows, 2048),
        ("rows booted different roots", {**identities, 1024: {**identities[1024], "root": {"sha256": "other"}}},
         measurements, rows, 2048),
        ("rows disagree on the ABI", {**identities, 1024: {**identities[1024], "abi": "other"}},
         measurements, rows, 2048),
        ("residency did not grow", identities, {**measurements, 4096: measurements[2048]}, rows, 2048),
        ("the largest row stayed under 1 GiB", identities, {size: row(1) for size in rows} | {
            1024: row(1), 2048: {**row(1), "ordinary": row(1)["ordinary"] + 1, "pool": row(1)["pool"] + 1,
                                 "schedules": {n: {"resident": v["resident"] + 1, "walks": v["walks"]}
                                               for n, v in row(1)["schedules"].items()}},
            4096: {**row(1), "ordinary": row(1)["ordinary"] + 2, "pool": row(1)["pool"] + 2,
                   "schedules": {n: {"resident": v["resident"] + 2, "walks": v["walks"]}
                                 for n, v in row(1)["schedules"].items()}}}, rows, 2048),
        ("the pinned row is not bracketed", identities, measurements, rows, 4096),
    ]
    for description, ids, measured_rows, row_sizes, product in row_mutations:
        require_rejection(description, "matrix: ", lambda ids=ids, measured_rows=measured_rows,
                          row_sizes=row_sizes, product=product: gate.check_matrix_rows(
                              ids, measured_rows, row_sizes, product))
    gate.check_matrix_launcher_only(measurements[2048], measurements[2048])
    require_rejection("a launcher-only boot changed the inventory", "matrix launcher-only: ",
                      lambda: gate.check_matrix_launcher_only(measurements[4096], measurements[2048]))
    return len(mutations) + 4 + 1 + len(row_mutations) + 1


def check_private_adaptive_controls(gate) -> int:
    """MEM-ADAPTIVE's arm: every adjudication, binding and outcome is checked.

    Built from the composition's *own* declared policy rather than from numbers
    invented here, so a control that drifted from the plane it guards fails
    while building instead of passing against a fiction.
    """
    policy = gate.declared_policy(gate.ADAPTIVE_FIXTURES["qemu-arm-virt"])
    lines = adaptive_control_transcript(gate, policy)
    transcript = "\n".join(lines)
    pool_maximum = policy["subjects"]["private-adaptive-pool-a"]["maximumPages"]
    permitted = sum(entry["maximumPages"] for entry in policy["subjects"].values())
    mutations = [
        (
            "admission reserved the sum of elastic maxima",
            transcript.replace("guarantee_pages=6144", f"guarantee_pages={permitted}", 1),
        ),
        (
            "the materialized reserve is below the declaration",
            transcript.replace("reserved_slots=512", "reserved_slots=0", 1),
        ),
        (
            "a task was constructed before the guarantees were reserved",
            "\n".join([lines[1], lines[0]] + lines[2:]),
        ),
        (
            "a subject's installed maximum differs from its declaration",
            transcript.replace(
                f"maximum={pool_maximum} mode=fixed installed={pool_maximum}",
                f"maximum={pool_maximum} mode=fixed installed={pool_maximum - 1}",
                1,
            ),
        ),
        (
            "a declaration-derived refusal was reported as exhaustion",
            transcript.replace(
                f"delta={pool_maximum - (ADAPTIVE_ROUNDS + 1) * ADAPTIVE_UNIT + 1} pages=",
                f"delta={pool_maximum - (ADAPTIVE_ROUNDS + 1) * ADAPTIVE_UNIT + 1} pages=",
                1,
            ).replace("cause=maximum", "cause=resource", 1),
        ),
        (
            "an inventory refusal was reported as a declaration",
            transcript.replace("cause=resource", "cause=maximum", 1),
        ),
        (
            "the root and the holder disagree on an outcome",
            transcript.replace("[private-adaptive] step=0 subject=private-adaptive-pool-b "
                               f"delta={ADAPTIVE_UNIT} served=1",
                               "[private-adaptive] step=0 subject=private-adaptive-pool-b "
                               f"delta={ADAPTIVE_UNIT} served=0", 1),
        ),
        (
            "a served request's sources do not sum to its delta",
            transcript.replace("guaranteed=0 elastic=257", "guaranteed=0 elastic=256", 1),
        ),
        (
            "a refused request charged its entitlement",
            transcript.replace(
                "cause=resource entitlement_committed=2056",
                "cause=resource entitlement_committed=4112",
                1,
            ),
        ),
        (
            "a holder reported zeroing after a refusal",
            transcript.replace("served=0 pages=1028 base=0x10000000 zeroed=0",
                               "served=0 pages=1028 base=0x10000000 zeroed=1", 1),
        ),
        (
            "a holder lost an earlier stamp",
            transcript.replace("zeroed=1 stable=1", "zeroed=1 stable=0", 1),
        ),
        (
            "a replacement bound a different entitlement",
            transcript.replace(
                f"instance=private-adaptive-restart "
                f"entitlement={gate.entitlement_identity('adaptive-restart')} incarnation=1",
                "instance=private-adaptive-restart "
                f"entitlement={gate.entitlement_identity('adaptive-pool')} incarnation=1",
                1,
            ),
        ),
        (
            "a dead incarnation's charge outlived it",
            transcript.replace("returned_pages=2048 entitlement_committed=0",
                               "returned_pages=2048 entitlement_committed=2048", 1),
        ),
        (
            "reclamation quarantined the returned backing",
            transcript.replace("quarantined=0", "quarantined=1", 1),
        ),
        (
            "a replacement multiplied its entitlement",
            transcript.replace(
                "guaranteed=2048 elastic=0 entitlement_committed=2048",
                "guaranteed=2048 elastic=0 entitlement_committed=4096",
            ).replace("entitlement_committed=2048 pool_bytes", "entitlement_committed=4096 pool_bytes"),
        ),
    ]
    mutations = [entry for entry in mutations if entry[1] != transcript]
    count = check_adaptive_control_mutations(
        lambda text: gate.check_adaptive_plane(text, policy),
        "adaptive plane:",
        lines,
        mutations,
    )

    # Determinism is a two-boot claim, so its control is a second transcript
    # rather than a mutated single one.
    steps = gate.check_adaptive_plane(transcript, policy)
    gate.check_adaptive_determinism(transcript, transcript, steps)
    for description, replay in (
        (
            "two boots answered one step differently",
            transcript.replace("step=17 subject=private-adaptive-guaranteed "
                               f"delta={ADAPTIVE_UNIT} served=1",
                               "step=17 subject=private-adaptive-guaranteed "
                               f"delta={ADAPTIVE_UNIT} served=0", 1),
        ),
        (
            "two boots reported different schedule digests",
            transcript.replace("digest=0x1234567890abcdef", "digest=0xfedcba0987654321"),
        ),
        (
            "a window base moved between boots",
            transcript.replace("step=0 subject=private-adaptive-pool-b delta=257 served=1 "
                               "pages=257 base=0x10000000",
                               "step=0 subject=private-adaptive-pool-b delta=257 served=1 "
                               "pages=257 base=0x20000000", 1),
        ),
    ):
        require_rejection(
            description,
            "adaptive plane:",
            lambda replay=replay: gate.check_adaptive_determinism(transcript, replay, steps),
        )
        count += 1

    # The over-guaranteed negative composition, whose whole claim is that
    # nothing was published. Its terminal is a failure marker, so it cannot
    # share a synthetic transcript with the arm above.
    refusal = (
        "SLIME_MEM FAIL adaptive guarantee exceeds inventory required=1048576 "
        "available=520192 published=0"
    )
    gate.check_adaptive_refusal(refusal)
    for description, mutated in (
        ("the refusal was never reported", "SLIME_ROOT boot\n"),
        (
            "a refused admission still staged a task",
            refusal + "\nSLIME_GRAPH staged task=1 instance=init",
        ),
        (
            "a refused admission still reserved a policy",
            "SLIME_MEM policy entitlements=3 subjects=4 guarantee_pages=1 reserved_bytes=1 "
            "reserved_slots=1 reserved_descriptors=1 reserved_extents=1 reserved_tables=1 "
            "pool_bytes=1\n" + refusal,
        ),
        (
            "a refused admission still reached a healthy graph",
            refusal + "\nSLIME_GRAPH HEALTHY generation=1 required=1 live=1 completed=0 failed=0",
        ),
        (
            "admission refused a guarantee its inventory could fund",
            refusal.replace("available=520192", "available=2097152"),
        ),
    ):
        require_rejection(
            description,
            "adaptive refusal:",
            lambda mutated=mutated: gate.check_adaptive_refusal(mutated),
        )
        count += 1
    return (
        count
        + check_adaptive_quarantine_controls(gate)
        + check_adaptive_construction_controls(gate)
    )


def check_adaptive_construction_controls(gate) -> int:
    """A failed construction may neither leak its incarnation nor double it."""
    holder = "private-adaptive-io-holder"
    identity = "27f32bfd1f46f2fc"

    def bound(task: int, incarnation: int) -> str:
        return (
            f"SLIME_MEM entitlement task={task} instance={holder} entitlement={identity} "
            f"incarnation={incarnation} guarantee=0 maximum=32768 mode=fixed "
            "installed=32768 base=0x400000"
        )

    injected = f"SLIME_MEM adaptive injected kind=construction task=4 instance={holder}"
    quarantined = (
        f"SLIME_MEM adaptive retired task=4 instance={holder} entitlement={identity} "
        "returned_pages=0 entitlement_committed=0 quarantined=1"
    )
    unwound = (
        f"SLIME_MEM adaptive retired task=4 instance={holder} entitlement={identity} "
        "returned_pages=0 entitlement_committed=0 quarantined=0"
    )
    retrying = "[private-adaptive:io-supervisor] spawn refused, retrying"
    lines = [bound(4, 0), injected, quarantined, retrying, unwound, bound(5, 1)]
    baseline = "\n".join(lines)
    gate.check_adaptive_construction_failure(baseline)
    count = 0
    for description, mutated in (
        ("no failure was injected", baseline.replace(injected + "\n", "")),
        ("the failed incarnation was never released", baseline.replace(unwound + "\n", "")),
        (
            "the failed incarnation was released while quarantined",
            baseline.replace("returned_pages=0 entitlement_committed=0 quarantined=0", "returned_pages=0 entitlement_committed=0 quarantined=1"),
        ),
        ("the unwind's failed revoke was never quarantined", baseline.replace(quarantined + "\n", "")),
        (
            "the incarnation was released before its quarantine",
            "\n".join([bound(4, 0), injected, unwound, quarantined, retrying, bound(5, 1)]),
        ),
        ("the retry was never bound", baseline.replace("\n" + bound(5, 1), "")),
        ("the retry reused the failed task", baseline.replace(bound(5, 1), bound(4, 1))),
        ("the retry did not advance the incarnation", baseline.replace(bound(5, 1), bound(5, 0))),
        (
            "the retry bound before the failure was released",
            "\n".join([bound(4, 0), injected, quarantined, retrying, bound(5, 1), unwound]),
        ),
        ("the spawner never saw the refusal", baseline.replace(retrying + "\n", "")),
    ):
        require_rejection(
            description,
            "adaptive lifecycle:",
            lambda mutated=mutated: gate.check_adaptive_construction_failure(mutated),
        )
        count += 1
    return count


def check_adaptive_quarantine_controls(gate) -> int:
    """The injected revoke failure's own controls.

    Its claim is narrow and entirely about what a failed cleanup may not do,
    so every mutation below is a way of refunding capacity the machine never
    recovered, or of never proving that it was recovered later.
    """
    injected = "SLIME_MEM adaptive injected kind=revoke task=4 instance=private-adaptive-io-holder"
    quarantined = (
        "SLIME_MEM adaptive retired task=4 instance=private-adaptive-io-holder "
        "entitlement=27f32bfd1f46f2fc returned_pages=0 entitlement_committed=1 quarantined=1"
    )
    settled = (
        "SLIME_MEM adaptive retired task=4 instance=private-adaptive-io-holder "
        "entitlement=27f32bfd1f46f2fc returned_pages=1 entitlement_committed=0 quarantined=0"
    )
    complete = (
        "[private-adaptive] complete steps=18 served=15 refused=3 restarts=1 "
        "duplicates=1 denied=1 exits=5 digest=0x1234567890abcdef"
    )
    baseline = "\n".join([injected, quarantined, settled, complete])
    gate.check_adaptive_quarantine(baseline)
    count = 0
    for description, mutated in (
        ("no failure was injected", baseline.replace(injected + "\n", "")),
        (
            "a failed revoke refunded pages",
            baseline.replace("returned_pages=0 entitlement_committed=1 quarantined=1", "returned_pages=1 entitlement_committed=0 quarantined=1"),
        ),
        ("the quarantine was never retried", baseline.replace("\n" + settled, "")),
        (
            "the retry returned nothing",
            baseline.replace("returned_pages=1 entitlement_committed=0 quarantined=0", "returned_pages=0 entitlement_committed=0 quarantined=0"),
        ),
        (
            "a second quarantine was reported as settled",
            baseline.replace(complete, quarantined.replace("task=4", "task=4") + "\n" + complete),
        ),
        ("the plane never completed", baseline.replace("\n" + complete, "")),
    ):
        require_rejection(
            description,
            "adaptive lifecycle:",
            lambda mutated=mutated: gate.check_adaptive_quarantine(mutated),
        )
        count += 1
    return count


def check_private_memory_capacity_controls() -> int:
    gate = load_script(
        "sel4_private_memory_semantic_controls", "check/check-sel4-private-memory-plane.py"
    )
    gate.fail = reject_control
    profile = {"memory_mib": 2048}
    section = "control"
    target = "aarch64-sel4-qemu-virt"
    qualification = (
        "SLIME_MEM qualification scope=contract-aggregate-headroom holders=4 "
        "pages=65536 private_allocations=263168 private_extents=1028 private_cslots=264196 "
        "private_reserved=1075838976 payload=1073741824 tables=2097152 alignment=0 "
        "static_allocations=8 static_reserved=16384 required_allocations=263200 "
        "required_extents=1028 required_cslots=264228 required_reserved=1075904512 "
        "allocation_capacity=400000 allocations_available=380000 extent_capacity=2048 "
        "extents_available=1500 cslots_available=500000 ordinary_available=2013265920 "
        "ordinary_layout=1 root_image=8388608 root_metadata=1048576 root_stack=1048576 "
        "root_heap=524288 fit=1 limit=none"
    )
    gate.check_segmented_capacity_report(qualification, profile, section, target, 0)
    # The headroom the report claims must follow the quotas the generation
    # already declares, not the whole aggregate a fresh image would admit.
    require_rejection(
        "capacity headroom ignores already-declared quotas",
        "capacity qualification:",
        lambda: gate.check_segmented_capacity_report(qualification, profile, section, target, 65536),
    )
    capacity_mutations = (
        ("capacity false refusal", qualification.replace("fit=1 limit=none", "fit=0 limit=none")),
        (
            "capacity missing static descriptors",
            qualification.replace("required_allocations=263200", "required_allocations=263168"),
        ),
        (
            "capacity missing static RAM",
            qualification.replace("required_reserved=1075904512", "required_reserved=1075838976"),
        ),
        (
            "capacity ignores impossible ordinary layout",
            qualification.replace("ordinary_layout=1", "ordinary_layout=0"),
        ),
        ("capacity forged limit", qualification.replace("limit=none", "limit=ordinary-bytes")),
        ("capacity missing limit", qualification.replace(" limit=none", "")),
        (
            "capacity unnamed refusal",
            qualification.replace("allocations_available=380000", "allocations_available=263199")
            .replace("fit=1 limit=none", "fit=0 limit=none"),
        ),
        (
            "capacity misnamed refusal",
            qualification.replace("allocations_available=380000", "allocations_available=263199")
            .replace("fit=1 limit=none", "fit=0 limit=extent-descriptors"),
        ),
        ("capacity allocation exhaustion", qualification.replace("allocations_available=380000", "allocations_available=263199")),
        ("capacity extent exhaustion", qualification.replace("extents_available=1500", "extents_available=1027")),
        ("capacity slot exhaustion", qualification.replace("cslots_available=500000", "cslots_available=264227")),
        ("capacity ordinary exhaustion", qualification.replace("ordinary_available=2013265920", "ordinary_available=1075904511")),
        ("capacity small tables", qualification.replace("allocation_capacity=400000 allocations_available=380000", "allocation_capacity=4096 allocations_available=3000")),
        ("capacity envelope below the declared row", qualification.replace("holders=4 pages=65536", "holders=2 pages=65536")),
        ("capacity duplicate report", qualification + "\n" + qualification),
        (
            "capacity missing static field",
            qualification.replace(" static_allocations=8", ""),
        ),
    )
    for description, transcript in capacity_mutations:
        require_rejection(
            description,
            "capacity qualification:",
            lambda transcript=transcript: gate.check_segmented_capacity_report(
                transcript, profile, section, target, 0
            ),
        )
    conversion_lines = [
        "SLIME_MEM refused task=5 delta=16384 cause=frames detail=Frames { allocated: 0, error: Retype }",
        "SLIME_MEM grown task=5 delta=1 previous=0 pages=1 base=0x400000 quota=16384 total=1 large_frames=0 base_frames=1 leaf_tables=1",
        "SLIME_MEM grown task=5 delta=16383 previous=1 pages=16384 base=0x400000 quota=16384 total=16384 large_frames=31 base_frames=512 leaf_tables=1",
        "[private-memory-probe] granted pages=16384 base=0x400000 zeroed=1 survived=1 refused=1 worker_rpc_once=1 worker_grow_refused=1 retries=1",
    ]
    conversion = "\n".join(conversion_lines)
    gate.check_large_map_retry(conversion)
    conversion_mutations = (
        ("conversion missing first page", "\n".join(conversion_lines[:1] + conversion_lines[2:])),
        ("conversion reported no base pages", conversion.replace("base_frames=512", "base_frames=0")),
        ("conversion demoted every span", conversion.replace("large_frames=31 ", "large_frames=0 ")),
        ("conversion changed task", conversion.replace("task=5 delta=16383", "task=6 delta=16383")),
        ("conversion changed base", conversion.replace("previous=1 pages=16384 base=0x400000", "previous=1 pages=16384 base=0x600000")),
        ("conversion wrong order", "\n".join([conversion_lines[0], conversion_lines[2], conversion_lines[1], conversion_lines[3]])),
    )
    for description, transcript in conversion_mutations:
        require_rejection(
            description,
            "large-map",
            lambda transcript=transcript: gate.check_large_map_retry(transcript),
        )


    rollback_lines = [
        "SLIME_MEM refused task=0 delta=2 cause=frames detail=Frames { allocated: 1, error: Retype }",
        "SLIME_CHILD mem rollback preserved pages=1 base=0x40000000 survived=0x4d454d5f42415345",
        "SLIME_MEM refused task=1 delta=2 cause=frames detail=Frames { allocated: 1, error: Retype }",
        "SLIME_CHILD mem zero rollback result=-5 pages=0 base=0x50000000",
        "SLIME_MEM grown task=1 delta=512 previous=0 pages=512 base=0x50000000 quota=512 total=513 large_frames=0 base_frames=512 leaf_tables=1",
        "SLIME_CHILD mem whole retry pages=512 base=0x50000000 zeroed=1 preserved=1 survived=0x4d454d5f42415345",
        "SLIME_CHILD fault requested addr=0x0",
        "SLIME_ROOT child fault observed task=1 role=deliberate-fault kind=VirtualMemory { access: Write, level: 0 } instruction=Some(0) address=Some(0)",
        "SLIME_MEM enforced clean_quota=4 retry_quota=512 pages=513 grants=2 grown=513 reclaimed=0 flags=0x7f",
        "SLIME_MEM teardown grown=513 reclaimed=513 pages=0",
        "SLIME_ROOT READY tasks=2 grants=2 declared_grants=2 reclaimed_slots=600",
    ]
    rollback = "\n".join(rollback_lines)
    gate.check_incremental_rollback(rollback)
    reordered = rollback_lines.copy()
    reordered[3], reordered[4] = reordered[4], reordered[3]
    rollback_mutations = (
        ("rollback missing zero marker", "\n".join(line for index, line in enumerate(rollback_lines) if index != 3)),
        ("rollback reordered zero and bulk", "\n".join(reordered)),
        ("rollback used large frame", rollback.replace("large_frames=0", "large_frames=1")),
        ("rollback explicit failure", rollback + "\nSLIME_CHILD mem zero retry failed"),
        ("rollback missing ready", "\n".join(rollback_lines[:-1])),
    )
    for description, transcript in rollback_mutations:
        require_rejection(
            description,
            "private rollback:",
            lambda transcript=transcript: gate.check_incremental_rollback(transcript),
        )
    quota_lines = [
        "SLIME_MEM quota task=3 instance=private-heap-granted declared=15872 "
        "installed=15872 base=0x4000000",
        "[private-heap-probe:granted] capacity payload=62914560 overhead=16 "
        "backed=63008768 pages=15383 touched=1",
        "SLIME_MEM refused task=3 delta=50153 cause=quota "
        "detail=QuotaExceeded { pages: 15383, delta: 50153, quota: 15872 }",
    ]
    quota_refusal = "\n".join(quota_lines)
    declared = {"private-heap-granted": 15872}
    gate.check_heap_refusal_is_the_declared_quota(
        quota_refusal, declared, "qemu-arm-virt"
    )
    quota_mutations = (
        (
            "heap quota refusal names reservation instead",
            quota_refusal.replace(
                "cause=quota detail=QuotaExceeded",
                "cause=reservation detail=ReservationExceeded",
            ),
        ),
        (
            "heap quota refusal names a different quota",
            quota_refusal.replace("quota: 15872", "quota: 16384"),
        ),
        (
            "heap quota refusal request stops short of the reservation",
            quota_refusal.replace("delta=50153", "delta=50152"),
        ),
        (
            "heap quota installation differs from the declaration",
            quota_refusal.replace("installed=15872", "installed=16384"),
        ),
        (
            "heap quota refusal is attributed to a different task",
            quota_refusal.replace("refused task=3", "refused task=4"),
        ),
    )
    for description, transcript in quota_mutations:
        require_rejection(
            description,
            "private-heap-granted:",
            lambda transcript=transcript: gate.check_heap_refusal_is_the_declared_quota(
                transcript, declared, "qemu-arm-virt"
            ),
        )
    cold = (
        "SLIME_MEM census retired=0 untyped=10000 reusable=0 shared_reusable=0 "
        "preserved_bytes=0 active_extent_bytes=100 mapped_pages=0 free_slots=100 "
        "anchors=0 shared_anchors=0 preserved_anchors=0 allocations_free=100 infrastructure_owned=0\n"
        "SLIME_ALLOC preserved parent=1 slot=2 paddr=4096 bytes=16\n"
        "SLIME_MEM census retired=1 untyped=9000 reusable=1000 shared_reusable=16 "
        "preserved_bytes=84 active_extent_bytes=0 mapped_pages=0 free_slots=96 "
        "anchors=2 shared_anchors=1 preserved_anchors=1 allocations_free=102 infrastructure_owned=0"
    )
    gate.check_capacity_conservation(cold)
    conservation_mutations = (
        ("cold backing lost", cold.replace("untyped=9000", "untyped=8999")),
        ("infrastructure charge forged", cold.replace("allocations_free=102 infrastructure_owned=0", "allocations_free=102 infrastructure_owned=1")),
        ("infrastructure charge missing", cold.replace(" infrastructure_owned=0", "")),
        ("cold backing double counted", cold.replace("preserved_bytes=84", "preserved_bytes=85")),
        ("cold slots lost", cold.replace("free_slots=96", "free_slots=95")),
        ("cold mapping remains", cold.replace("active_extent_bytes=0 mapped_pages=0", "active_extent_bytes=0 mapped_pages=1")),
        ("cold descriptor lost", cold.replace("allocations_free=102", "allocations_free=99")),
        ("cold missing initial backing", cold.replace("active_extent_bytes=100", "active_extent_bytes=0")),
        ("cold no real reuse", "\n".join(line for line in cold.splitlines() if not line.startswith("SLIME_ALLOC"))),
    )
    for description, transcript in conservation_mutations:
        require_rejection(description, "capacity conservation:",
            lambda transcript=transcript: gate.check_capacity_conservation(transcript))
    ledger = "\n".join([
        "SLIME_BACKING inventory parent=1 paddr=4096 bytes=4096",
        "SLIME_BACKING preserve parent=1 child=2 paddr=4096 bytes=16",
        "SLIME_ROOT ordinary range=0 paddr=0x1000 bytes=4096",
        "SLIME_MEM census untyped=4080 preserved_bytes=16 preserved_anchors=1 active_extent_bytes=0 reusable=0 anchors=0 shared_reusable=0 shared_retained=0 shared_anchors=0",
        "SLIME_BACKING snapshot phase=initial begin",
        "SLIME_BACKING ordinary parent=1 paddr=4096 bytes=4096 used=16",
        "SLIME_BACKING retained parent=2 paddr=4096 bytes=16 used=0",
        "SLIME_BACKING snapshot phase=initial end",
        "SLIME_BACKING preserve parent=1 child=3 paddr=4112 bytes=16",
        "SLIME_BACKING consume source=ordinary parent=1 slot=4 paddr=4128 bytes=32 count=1",
        "SLIME_BACKING consume source=preserved parent=3 slot=5 paddr=4112 bytes=16 count=1",
        "SLIME_MEM census untyped=4032 preserved_bytes=16 preserved_anchors=2 active_extent_bytes=0 reusable=32 anchors=1 shared_reusable=16 shared_retained=16 shared_anchors=1",
        "SLIME_BACKING snapshot phase=final begin",
        "SLIME_BACKING ordinary parent=1 paddr=4096 bytes=4096 used=64",
        "SLIME_BACKING retained parent=2 paddr=4096 bytes=16 used=0",
        "SLIME_BACKING retained parent=3 paddr=4112 bytes=16 used=16",
        "SLIME_BACKING task_extent parent=4 bytes=32 active=0",
        "SLIME_BACKING shared_node cap=5 parent=0 paddr=4112 bytes=16 state=Free",
        "SLIME_BACKING snapshot phase=final end",
    ])
    gate.check_backing_ledger(ledger)
    ledger_mutations = (
        ("ledger omitted prefix", ledger.replace("SLIME_BACKING preserve parent=1 child=3 paddr=4112 bytes=16\n", "")),
        ("ledger overlapping ownership", ledger.replace("child=3 paddr=4112", "child=3 paddr=4096")),
        ("ledger duplicate parent", ledger.replace("child=3 paddr=4112", "child=2 paddr=4112")),
        ("ledger false reusable consumed leaf", ledger.replace("parent=3 paddr=4112 bytes=16 used=16", "parent=3 paddr=4112 bytes=16 used=0")),
        ("ledger duplicate extent", ledger.replace("SLIME_BACKING task_extent parent=4 bytes=32 active=0", "SLIME_BACKING task_extent parent=4 bytes=32 active=0\nSLIME_BACKING task_extent parent=4 bytes=32 active=0")),
        ("ledger incomplete snapshot", ledger.replace("SLIME_BACKING snapshot phase=final end", "")),
        ("ledger wrong inventory", ledger.replace("ordinary range=0 paddr=0x1000", "ordinary range=0 paddr=0x2000")),
        ("ledger invalid shared ancestry", ledger.replace("shared_node cap=5 parent=0", "shared_node cap=5 parent=99")),
    )
    for description, transcript in ledger_mutations:
        require_rejection(description, "backing ledger:",
            lambda transcript=transcript: gate.check_backing_ledger(transcript))
    fault_lines = []
    for cycle in range(gate.CYCLE_COUNT):
        task = cycle + 1
        base = 0x10000000
        fault_lines.extend([
            f"SLIME_MEM quota task={task} instance=private-cycle-probe declared=16384 installed=16384 base=0x{base:x}",
            f"SLIME_MEM grown task={task} delta=16384 previous=0 pages=16384 base=0x{base:x} quota=16384 total=16384 large_frames=32 base_frames=0 leaf_tables=0",
            f"[private-cycle-probe] cycle={cycle} pages=16384 base=0x{base:x} stamp=0x{cycle + 1:x} zeroed=1 verified=1 end={'fault' if cycle % 2 else 'exit'}",
        ])
        if cycle % 2:
            access = "Write" if cycle % 4 == 1 else "Execute"
            address = base + (16384 * 4096 if access == "Write" else 0)
            fault_lines.append(f"SLIME_GRAPH component fault task={task} kind=VirtualMemory {{ access: {access}, status: 15 }} address=Some({address})")
    fault_trace = "\n".join(fault_lines)
    gate.check_cycle_fault_attribution(fault_trace, 16384)
    fault_mutations = (
        ("fault wrong task", fault_trace.replace("fault task=2 ", "fault task=99 ")),
        ("fault wrong access", fault_trace.replace("access: Write", "access: Read", 1)),
        ("fault stale status", fault_trace.replace("status: 15", "status: 0", 1)),
        ("fault stale address", fault_trace.replace("address=Some(335544320)", "address=Some(9)", 1)),
        ("fault NX at guard", fault_trace.replace("access: Execute, status: 15 } address=Some(268435456)", "access: Execute, status: 15 } address=Some(335544320)", 1)),
        ("fault missing record", "\n".join(line for line in fault_lines if not line.startswith("SLIME_GRAPH component fault task=2 "))),
        ("fault duplicate record", fault_trace + "\n" + fault_lines[6]),
        ("fault missing backed region", fault_trace.replace("grown task=4 delta=16384", "grown task=99 delta=16384", 1)),
    )
    for description, transcript in fault_mutations:
        require_rejection(description, "cycle fault attribution:",
            lambda transcript=transcript: gate.check_cycle_fault_attribution(transcript, 16384))
    isolation_mutations = check_private_isolation_controls(gate)
    stress_mutations = check_private_stress_controls(gate)
    workload_mutations = check_private_capacity_controls(gate)
    return (
        workload_mutations
        + isolation_mutations
        + stress_mutations
        + check_private_cspace_controls(gate)
        + check_private_metadata_controls(gate)
        + check_private_bootstrap_controls(gate)
        + check_private_elastic_controls(gate)
        + check_private_fragmentation_controls(gate)
        + check_private_rollback_controls(gate)
        + check_private_conservation_controls(gate)
        + check_private_adaptive_controls(gate)
        + check_private_matrix_controls(gate)
        + len(fault_mutations)
        + len(ledger_mutations)
        + len(conservation_mutations)
        + len(capacity_mutations)
        + len(rollback_mutations)
        + len(conversion_mutations)
        + len(quota_mutations)
    )



def main() -> None:
    if Path_cwd() != ROOT:
        fail(f"run from repository root: {ROOT}")
    total = 0
    for name, relative_path, expected_required in GATES:
        total += check_gate(name, relative_path, expected_required)
    total += check_root_memory_runtime_control()
    total += check_http_evidence_controls()
    total += check_http_capture_controls()
    total += check_layout_gate()
    total += check_private_memory_capacity_controls()
    with tempfile.TemporaryDirectory(prefix="slime-sel4-gate-controls-") as temporary:
        control_root = _Path(temporary)
        identity_controls = check_image_identity_controls(control_root)
        runtime_controls = check_plane_runtime_controls(control_root)
    print(
        f"seL4 gate control check: {len(GATES) + 1} gates plus 9 adaptive arms reject "
        f"{total} mutated transcripts and layouts; "
        f"{identity_controls} identity cases and {runtime_controls} runtime cases passed"
    )


def Path_cwd() -> _Path:
    return _Path.cwd().resolve()


if __name__ == "__main__":
    main()
