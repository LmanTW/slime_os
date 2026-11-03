#!/usr/bin/env python3

"""Judge the LiDAR publisher: `sel4-lidar-external` against a stock Zenoh peer on the host.

The expectation lives in `scripts/lib/lidar_publish_exam.py`. This script runs the product as commands and
imports none of it:

    python3 scripts/build/build-data-volume.py --kind frame-store --payload FILE --output DISK
        write the one data-volume disk of the frame store FILE
    the `sel4-lidar-external` image, built from its closure source by `closure_image`

Steps:

1. The exam's judges hold their controls.
2. The composition's system spec declares an arrival ceiling above the root's default, and its derived
   manifest grants the publisher one outbound TCP connection and one read-only block ring on the block
   driver's device.
3. The frame store is encoded by the exam from the bag `SLIME_LIDAR_BAG` names, pinned by size and SHA-256,
   and the builder's disk must be the data-volume contract's one image of it.
4. A stock `eclipse-zenoh==1.0.0` peer, built from the wheel pinned for this host, listens on the host
   loopback. The image boots on aarch64 QEMU with the NIC attached and then the disk, read-only, and the NIC
   is captured.
5. The transcript, the capture and the peer's `contracts/zenoh-digest-receipt/v1` record are judged
   against the store.

A boot that prints a failure line is refused at once; the peer is not waited for. `--controls-only` runs step
1. The bag and a registry are needed, so the recipe is explicit and in no aggregate.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import os
import subprocess
import tempfile
from pathlib import Path
from typing import NoReturn

import data_volume_exam
import devloop_observations
import lidar_publish_exam as exam
import zenoh_capture
import zenoh_exchange
import zenoh_listener_peer
from closure_image import ClosureImageError, build as build_closure_image
from harness import ROOT, sha256_file
from sel4_plane import run_plane

PINS = ROOT / "sel4" / "pins.toml"


def fail(message: str) -> NoReturn:
    raise SystemExit(f"lidar publish check: {message}")


def build_image(closure: str) -> Path:
    try:
        built = build_closure_image(closure)
    except ClosureImageError as error:
        fail(str(error))
    image = built.image
    actual = sha256_file(image, fail)
    if actual != built.digest():
        fail(f"{image} SHA-256 is {actual}, but the build result records {built.digest()}; the image changed after it was built")
    return image


def controls() -> int:
    try:
        accepted, refused = exam.controls()
    except exam.ExamError as error:
        fail(str(error))
    print(f"[lidar-publish] controls accepted={accepted} refused={refused}")
    return refused


def write_disk(directory: Path, store: bytes) -> Path:
    source, disk = directory / "lidar.store", directory / "lidar.img"
    source.write_bytes(store)
    built = subprocess.run(
        [_sys.executable, str(ROOT / data_volume_exam.BUILDER), "--kind", "frame-store", "--payload", str(source), "--output", str(disk)],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    if built.returncode != 0 or not disk.is_file():
        fail(f"{data_volume_exam.BUILDER} exited {built.returncode}: {built.stderr.strip()[-300:]}")
    if disk.read_bytes() != data_volume_exam.encode(store):
        fail("the builder's disk is not the data-volume contract's one image of the store")
    return disk


def run(transcript_path: Path | None) -> None:
    refused = controls()
    for path in (exam.SYSTEM, exam.COMPOSITION):
        if not path.is_file():
            fail(f"{path.relative_to(ROOT)} does not exist; the {exam.CLOSURE} composition has not landed")
    try:
        ceiling = exam.read_ceiling(exam.SYSTEM.read_text(encoding="utf-8"))
        rows = exam.composition_from_text(exam.COMPOSITION.read_text(encoding="utf-8"))
        facts = exam.check_rows(*rows)
        store = exam.store_from_bag(os.environ.get("SLIME_LIDAR_BAG"))
        want = exam.expected(store)
    except (exam.ExamError, zenoh_exchange.ExchangeError) as error:
        fail(str(error))
    generation = rows[0]
    image = build_image(exam.CLOSURE)
    netdev = f"user,id=slimenet,net=10.0.2.0/24,host={zenoh_capture.PEER},dhcpstart={zenoh_capture.GUEST},ipv6=off"
    try:
        with tempfile.TemporaryDirectory(prefix="slime-lidar-publish-") as name:
            directory = Path(name)
            disk = write_disk(directory, store)
            receipt = directory / "receipt.zti"
            capture = directory / "network.pcap"
            with zenoh_listener_peer.Listener(
                receipt, zenoh_capture.PORT, key=exam.KEY, samples=len(want.frames),
                form="digest", deadline=exam.LISTENER_SECONDS,
            ) as listener:
                transcript = run_plane(
                    image=image, timeout=exam.QEMU_SECONDS, terminal_condition=exam.TERMINAL,
                    fail=fail, pins_path=PINS,
                    additional_arguments=(
                        "-netdev", netdev,
                        "-device", f"virtio-net-device,netdev=slimenet,mac={exam.INTERFACE['mac']}",
                        "-object", f"filter-dump,id=netcapture,netdev=slimenet,file={capture}",
                        "-drive", f"if=none,id=slimedata,format=raw,readonly=on,file={disk}",
                        "-device", "virtio-blk-device,drive=slimedata",
                    ),
                )
                if transcript_path is not None:
                    transcript_path.write_text(transcript, encoding="utf-8")
                # The guest has already failed; the peer would only wait out its deadline for samples that
                # cannot come. Leaving the context stops it.
                failure = exam.FAILURES.search(transcript)
                if failure is not None:
                    print(transcript)
                    fail(f"lidar-publish evidence refused: a failure line: {failure.group(0)!r}")
                if not capture.is_file():
                    fail("QEMU did not produce the lidar-publish packet observation")
                packets = capture.read_bytes()
                listener_output = listener.finish(exam.LISTENER_SECONDS)
                if transcript_path is not None:
                    transcript_path.write_text(transcript + "\n" + listener_output, encoding="utf-8")
                    transcript_path.with_suffix(".pcap").write_bytes(packets)
                try:
                    observed = exam.judge_transcript(transcript, want, ceiling, generation)
                    wire = exam.judge_capture(packets, want)
                    samples = exam.judge_receipt(*exam.read_receipt(receipt), want)
                except exam.ExamError as error:
                    print(transcript)
                    fail(f"lidar-publish evidence refused: {error}")
    except (OSError, RuntimeError, ValueError) as error:
        fail(f"lidar-publish evidence refused: {error}")
    span_s = wire["span_ns"] / 1e9
    rate = want.total / span_s / 1e6 if span_s else 0.0
    print(f"[lidar-publish-wire] puts={wire['puts']} batches={wire['batches']} largest-batch={wire['largest_batch']} guest-stream={wire['guest_stream']} min-gap-ms={wire['min_gap_ns'] / 1e6:.3f} span-s={span_s:.3f} mb-per-s={rate:.3f}")
    print(f"[lidar-publish] samples-in-receipt={samples} bytes={want.total} late={observed['late']} elapsed-ms={observed['elapsed_ms']} ceiling={observed['ceiling']} authority-facts={facts}")
    devloop_observations.record(casesObserved=samples, bytesObserved=want.total, negativeControlsRefused=refused)
    print("lidar publish check: the guest read every frame from the read-only disk and sent it over one TCP connection to a stock eclipse-zenoh 1.0.0 peer, which received each frame byte for byte, in order and never early")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--controls-only", action="store_true", help="run the judges against their controls, without QEMU or a peer")
    parser.add_argument("--transcript", type=Path, help="write the serial transcript and peer output here, and the capture beside it")
    arguments = parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    if arguments.controls_only:
        controls()
        return
    run(arguments.transcript)


if __name__ == "__main__":
    main()
