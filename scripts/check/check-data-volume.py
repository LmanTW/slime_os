#!/usr/bin/env python3

"""Judge a hash-pinned data volume: the host builder that writes it and the guest probe that reads it.

The expectation lives in `scripts/lib/data_volume_exam.py`, and the format in
`contracts/data-volume/v1/schema.zt`. This script runs the product as commands and imports none of it:

    python3 scripts/build/build-data-volume.py --kind frame-store --payload FILE --output DISK
        write the one disk image of the frame store FILE to DISK, or refuse with a final stderr line
        `build-data-volume: refused CLASS`, CLASS one of kind, output, payload, writing nothing
    python3 scripts/build/build-system-image.py contracts/system-image-closure/v3/closures/sel4-data-volume.zti OUT
        build the `sel4-data-volume` image into OUT/image.elf

The image runs `data-volume-probe` with a read-only block ring on the disk QEMU attaches read-only. For an
accepted volume the probe prints, in this order, each line prefixed `[data-volume-probe] `:

    volume kind=frame-store bytes=N sha256=H        after the payload's SHA-256 matched its header
    frames count=F period=P first=T0 last=TN digest=D
                                                    after the frame store validated; D is the SHA-256 of
                                                    the payloads concatenated in index order
    write refused                                   one write to the ring was refused for its rights, after
                                                    the driver printed `[virtio-blk-driver] refused write
                                                    ring=0 rights=read`; the driver's authority line reads
                                                    `[virtio-blk-driver] authority rings=1 rights=read
                                                    source=generation`
    heap used=U                                     U at most 65536 bytes
    complete

For a refused volume it prints `refused CLASS`, CLASS the first failing check in the contract's order, and
nothing after it; a frame-store refusal follows the volume line.

Steps:

1. The judges' controls hold, and the schema states the pinned constants.
2. The builder writes exactly the exam's disk for the honest payload and for the committed frame-store
   fixture, and refuses an unknown kind, a payload that is not a frame store, and an existing output,
   leaving the output untouched.
3. `sel4-data-volume` builds, and boots on aarch64 QEMU once with the builder's honest disk and once with
   each of fifty disks, one per check of the exam's decoder, each built so that only that check refuses
   it. A boot is read for five seconds past its terminal line, so a line printed after a refusal is judged.
   The probe's lines must be exactly the expected ones.

`--controls-only` runs step 1; `--skip-boots` stops after step 2.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import hashlib
import os
import re
import subprocess
import tempfile
import threading
import time
import tomllib
from pathlib import Path

import data_volume_exam as exam
import frame_store_exam as frames
from harness import ROOT

IMAGE_BUILDER = "scripts/build/build-system-image.py"
SOURCE = f"contracts/system-image-closure/v3/closures/{exam.CLOSURE}.zti"
BOOT_TIMEOUT_SECONDS = 240
# How long a boot is read past its terminal or failure line, so a line printed after a refusal is judged.
POST_TERMINAL_SECONDS = 5
FAILURES = re.compile(r"panic|PANIC|\] fail: |SLIME_GRAPH exhausted|SLIME_ROOT .*refused launch")
TERMINAL = re.compile(rf"\[{exam.PROBE}\] (complete|refused [a-z-]+)\s*$")


class Findings(list):
    def add(self, step: str, messages: list[str]) -> None:
        self.extend(f"{step}: {message}" for message in messages)


def run(*arguments: str, timeout: int = 3600) -> subprocess.CompletedProcess[str]:
    return subprocess.run([_sys.executable, *arguments], cwd=ROOT, capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def tail(result: subprocess.CompletedProcess[str]) -> str:
    lines = (result.stderr or result.stdout).strip().splitlines()
    return lines[-1][:300] if lines else ""


def step_builder(directory: Path, data: exam.Corpus, findings: Findings) -> Path | None:
    if not (ROOT / exam.BUILDER).is_file():
        findings.add("builder", [f"{exam.BUILDER} does not exist"])
        return None
    honest = None
    for label, payload in (("honest", data.store), ("fixture", frames.FIXTURE.read_bytes())):
        source = directory / f"{label}.store"
        source.write_bytes(payload)
        disk = directory / f"{label}.img"
        result = run(exam.BUILDER, "--kind", "frame-store", "--payload", str(source), "--output", str(disk))
        if result.returncode != 0 or not disk.is_file():
            findings.add("builder", [f"{label}: exited {result.returncode}: {tail(result)}"])
            continue
        if disk.read_bytes() != exam.encode(payload):
            findings.add("builder", [f"{label}: the disk is not the contract's one image of the payload"])
            continue
        if label == "honest":
            honest = disk
    not_a_store = directory / "not-a-store.bin"
    not_a_store.write_bytes(b"\xff" + data.store[1:])
    existing = directory / "existing.img"
    existing.write_bytes(b"keep")
    for label, arguments, wanted, output in (
        ("unknown kind", ("--kind", "bitmap", "--payload", str(directory / "honest.store")), "kind", directory / "kind.img"),
        ("not a frame store", ("--kind", "frame-store", "--payload", str(not_a_store)), "payload", directory / "bad.img"),
        ("existing output", ("--kind", "frame-store", "--payload", str(directory / "honest.store")), "output", existing),
    ):
        result = run(exam.BUILDER, *arguments, "--output", str(output))
        got = exam.builder_refusal(result.stderr)
        if result.returncode == 0 or got != wanted:
            findings.add("builder", [f"{label}: exit {result.returncode}, refusal {got!r}; expected refused {wanted}"])
        if output == existing:
            if existing.read_bytes() != b"keep":
                findings.add("builder", [f"{label}: the existing output was changed"])
        elif output.exists():
            findings.add("builder", [f"{label}: a refused run left {output.name}"])
    print("data volume: builder judged on 2 payloads and 3 refusals")
    return honest


def collect(command: list[str], timeout: float = BOOT_TIMEOUT_SECONDS) -> str:
    """Everything `command` prints until `POST_TERMINAL_SECONDS` after its first terminal or failure line, until
    it exits, or until `timeout`. Reading on past the terminal line is what lets a judge see a line printed
    after a refusal."""
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, bufsize=1)
    lines: list[str] = []
    finished = threading.Event()

    def read() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            lines.append(line.rstrip("\r\n"))
        finished.set()

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    stop_at = None
    seen = 0
    try:
        while time.monotonic() < deadline and not finished.is_set():
            current = len(lines)
            if stop_at is None and any(FAILURES.search(line) or TERMINAL.search(line) for line in lines[seen:current]):
                stop_at = time.monotonic() + POST_TERMINAL_SECONDS
            seen = current
            if stop_at is not None and time.monotonic() >= stop_at:
                break
            time.sleep(0.05)
    finally:
        process.kill()
        process.wait()
        reader.join(timeout=5)
    return "\n".join(lines)


def boot(image: Path, disk: Path) -> str:
    profile = tomllib.loads((ROOT / "sel4" / "pins.toml").read_text(encoding="utf-8"))["qemu_arm_virt"]
    return collect([
        "qemu-system-aarch64", "-machine", profile["machine"], "-cpu", profile["cpu"], "-smp", str(profile["cpus"]),
        "-m", f"size={profile['memory_mib']}M", "-nographic", "-serial", "mon:stdio", "-kernel", str(image),
        "-drive", f"if=none,id=slimedata,format=raw,readonly=on,file={disk}",
        "-device", "virtio-blk-device,drive=slimedata",
    ])


def collector_controls(store: bytes) -> list[tuple[str, bool]]:
    """The transcript collector, run on stand-in processes: a line printed after a refusal must reach the judge."""
    def emit(*steps: tuple[float, str]) -> list[str]:
        script = "import sys, time\n" + "".join(
            f"time.sleep({delay})\nprint({line!r}, flush=True)\n" for delay, line in steps) + "time.sleep(30)\n"
        return [_sys.executable, "-c", script]

    tag = f"[{exam.PROBE}] "
    refused = collect(emit((0, f"{tag}refused hash")), timeout=20)
    after = collect(emit((0, f"{tag}refused hash"), (1.0, f"{tag}complete")), timeout=20)
    failing = collect(emit((0, f"{tag}refused hash"), (1.0, f"[{exam.PROBE}] fail: late")), timeout=20)
    return [
        ("collector-refusal", not exam.refusal_findings(exam.probe_lines(refused), "hash", store)
         and FAILURES.search(refused) is None),
        ("collector-line-after-refusal", bool(exam.refusal_findings(exam.probe_lines(after), "hash", store))),
        ("collector-failure-after-refusal", FAILURES.search(failing) is not None),
    ]


def step_boots(directory: Path, honest: Path, data: exam.Corpus, findings: Findings) -> None:
    if not (ROOT / SOURCE).is_file():
        findings.add("image", [f"{SOURCE} does not exist"])
        return
    output = directory / "image"
    result = run(IMAGE_BUILDER, SOURCE, str(output))
    image = output / "image.elf"
    if result.returncode != 0 or not image.is_file():
        findings.add("image", [f"{exam.CLOSURE} did not build: {tail(result)}"])
        return
    transcript = boot(image, honest)
    failure = FAILURES.search(transcript)
    if failure is not None:
        findings.add("honest boot", [f"the boot failed: {failure.group(0)!r}"])
    findings.add("honest boot", exam.honest_findings(exam.probe_lines(transcript), data.store))
    findings.add("honest boot", exam.driver_findings(transcript))
    for name, disk_bytes in data.broken.items():
        kind = exam.check_class(name)
        disk = directory / f"broken-{name}.img"
        disk.write_bytes(disk_bytes)
        transcript = boot(image, disk)
        failure = FAILURES.search(transcript)
        if failure is not None:
            findings.add(f"{name} boot", [f"the boot failed: {failure.group(0)!r}"])
        findings.add(f"{name} boot", exam.refusal_findings(exam.probe_lines(transcript), kind, data.store))
    print(f"data volume: 1 honest and {len(data.broken)} refused boot(s) judged")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--controls-only", action="store_true", help="run the judges' controls only")
    parser.add_argument("--skip-boots", action="store_true", help="stop after judging the builder")
    arguments = parser.parse_args()
    results = exam.controls() + collector_controls(exam.payload())
    failed = [label for label, held in results if not held]
    schema = exam.schema_findings((ROOT / exam.SCHEMA).read_text(encoding="utf-8"))
    if failed or schema:
        print(f"data volume: FAIL: controls {failed}, schema {schema}")
        return 1
    print(f"data volume: {len(results)} controls held")
    if arguments.controls_only:
        return 0
    data = exam.corpus()
    findings = Findings()
    with tempfile.TemporaryDirectory(prefix="slime-data-volume-") as name:
        directory = Path(name)
        honest = step_builder(directory, data, findings)
        if honest is not None and not arguments.skip_boots:
            print(f"data volume: honest disk sha256={hashlib.sha256(honest.read_bytes()).hexdigest()}")
            step_boots(directory, honest, data, findings)
    for finding in findings:
        print(f"data volume: FAIL: {finding}")
    if findings:
        return 1
    if arguments.skip_boots:
        print("data volume: PASS (builder only): the builder writes and refuses as specified; no image was booted")
    else:
        print("data volume: PASS: the builder writes and refuses as specified, and the probe reads the honest "
              "volume and refuses each broken one with its class")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
