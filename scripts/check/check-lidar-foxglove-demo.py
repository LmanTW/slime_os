#!/usr/bin/env python3

"""Judge the LiDAR demo: `sel4-lidar-external` through `tools/foxglove-bridge/bridge.py` to a Foxglove client.

Work item 01a1a8cb-a7a0-7dc1-bb24-951d0db30d1e. Every judgement here is one `lidar_publish_check` or
`lidar_foxglove_bridge_check` already holds to its controls; this script joins the two runs into one:

1. Both exams' judges hold their controls, in a child process (see `controls_in_child`).
2. The composition's system spec declares its arrival ceiling and its derived manifest grants the publisher
   one outbound TCP connection and one read-only block ring, as `lidar_publish_exam` judges them.
3. The frame store is encoded by the exam from the bag `SLIME_LIDAR_BAG` names, and the builder's disk must
   be the data-volume contract's one image of it.
4. The bridge starts on the store with its Zenoh listener on tcp/127.0.0.1:17447, the host peer the
   composition grants. An independent client (`foxglove_ws`) connects, reads server info and the one
   advertisement, and subscribes; it then reads on its own thread for the rest of the run.
5. The image boots on aarch64 QEMU with the NIC attached and then the disk, read-only, and the NIC captured.
6. The guest's transcript and the capture are judged by `lidar_publish_exam`, the client's session and the
   bridge's own lines by `foxglove_bridge_exam`, all against the store.

A boot that prints a failure line is refused at once. The bag and a registry are needed, so the recipe is
explicit and in no aggregate. `--controls-only` runs step 1.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import os
import re
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import NoReturn

import devloop_observations
import foxglove_bridge_exam as bridge_exam
import foxglove_ws as ws
import lidar_publish_exam as publish_exam
import zenoh_capture
import zenoh_exchange
from harness import ROOT, load_script
from sel4_plane import run_plane

PUBLISH = load_script("lidar_publish_check", "check/check-lidar-publish.py")
BRIDGE = load_script("foxglove_bridge_check", "check/check-foxglove-bridge.py")
# The host peer the composition grants the publisher: QEMU's 10.0.2.2:17447 is the host's loopback.
ZENOH_PORT = zenoh_capture.PORT
# How long the client reads before it subscribes, and how long it reads on once the guest's boot has ended:
# collection stops only after this long with no message, whatever the count, so a late extra message is seen.
BEFORE_SECONDS = 5
SETTLE_SECONDS = 5


def fail(message: str) -> NoReturn:
    raise SystemExit(f"lidar foxglove demo check: {message}")


def controls() -> int:
    try:
        _accepted, publish_refused = publish_exam.controls()
        _accepted, bridge_refused = bridge_exam.controls()
    except (publish_exam.ExamError, bridge_exam.ExamError) as error:
        fail(str(error))
    collector_refused = collector_controls()
    print(f"[lidar-foxglove-demo] controls refused publish={publish_refused} bridge={bridge_refused} collector={collector_refused}")
    return publish_refused + bridge_refused + collector_refused


def collector_controls() -> int:
    """This script's own collection, against stand-in servers: an honest session is accepted, and one with a
    duplicate of the last frame after the expected count, or a frame missing, is refused."""
    want = bridge_exam.control_store()
    before, after = bridge_exam.honest_session(want)
    # The frames follow the advertisement after the client's pre-subscription read has ended, as the guest's do.
    pause = BEFORE_SECONDS_CONTROL * 2
    frames = (pause, bridge_exam.stream([], after))
    duplicate = (SETTLE_SECONDS_CONTROL / 2, bridge_exam.stream([], after[-1:]))
    cases = (
        ("honest", (frames,), True),
        ("a duplicate of the last frame after the count", (frames, duplicate), False),
        ("the last frame missing", ((pause, bridge_exam.stream([], after[:-1])),), False),
    )
    refused = 0
    for label, later, honest in cases:
        port, thread = bridge_exam.stand_in(bridge_exam.stream(before, []), later=later)
        client = ws.Client("127.0.0.1", port, timeout=5)
        try:
            got_before = read_before(client, BEFORE_SECONDS_CONTROL)
            got_after = Reader(client, SETTLE_SECONDS_CONTROL).finish()
            bridge_exam.judge_session(got_before, got_after, want)
            took = True
        except (bridge_exam.ExamError, ws.ProtocolError):
            took = False
        finally:
            client.close()
            thread.join(5)
        if took != honest:
            fail(f"control: the client's collection {'refused' if honest else 'accepted'} {label}")
        refused += not took
    return refused


# The collector controls' timings: shorter than the run's, and in the same proportions.
BEFORE_SECONDS_CONTROL = 0.5
SETTLE_SECONDS_CONTROL = 1.5


def read_before(client: ws.Client, seconds: float) -> list[ws.Message]:
    """Every message before the client subscribes: until `seconds` pass with none."""
    before: list[ws.Message] = []
    deadline = time.monotonic() + seconds
    while (message := client.receive(deadline)) is not None:
        before.append(message)
        deadline = time.monotonic() + seconds
    return before


CONTROLS_LINE = re.compile(r"\[lidar-foxglove-demo\] controls refused publish=(\d+) bridge=(\d+) collector=(\d+)")


def controls_in_child() -> int:
    """Run `controls()` in a child process and return its refusal count.

    The controls build captures of tens of megabytes and leave a large heap behind. The process that boots
    the guest reads QEMU's serial output; a collector pause there stalls QEMU's serial writes and so the
    guest, past its Zenoh lease. Keeping the controls in another process keeps that heap out of it."""
    done = subprocess.run([_sys.executable, str(_Path(__file__).resolve()), "--controls-only"], cwd=ROOT,
                          capture_output=True, text=True, check=False)
    match = CONTROLS_LINE.search(done.stdout)
    if done.returncode != 0 or match is None:
        fail(f"the controls did not hold: {(done.stdout + done.stderr).strip()[-400:]}")
    print(match.group(0))
    return int(match.group(1)) + int(match.group(2)) + int(match.group(3))


class Reader:
    """Reads the client's messages on a thread, so the server never holds a backlog for it."""

    def __init__(self, client: ws.Client, settle: float = SETTLE_SECONDS) -> None:
        self.client = client
        self.settle = settle
        self.messages: list[ws.Message] = []
        self.error: Exception | None = None
        self.stop = threading.Event()
        self.last = time.monotonic()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            while not self.stop.is_set():
                message = self.client.receive(time.monotonic() + 0.5)
                if message is not None:
                    self.messages.append(message)
                    self.last = time.monotonic()
                elif self.client.frames.closed:
                    return
        except (ws.ProtocolError, OSError) as error:
            self.error = error

    def finish(self) -> list[ws.Message]:
        """Every message read until none has arrived for the settle time. The count is never a reason to
        stop: a message after the expected last one is collected, and the judge refuses it."""
        while time.monotonic() - self.last < self.settle and self.error is None and not self.client.frames.closed:
            time.sleep(0.1)
        self.stop.set()
        self.thread.join(5)
        if self.error is not None:
            raise ws.ProtocolError(str(self.error))
        return list(self.messages)


def run(transcript_path: Path | None) -> None:
    refused = controls_in_child()
    for path in (publish_exam.SYSTEM, publish_exam.COMPOSITION, bridge_exam.BRIDGE, bridge_exam.PINS):
        if not path.is_file():
            fail(f"{path.relative_to(ROOT)} does not exist")
    try:
        ceiling = publish_exam.read_ceiling(publish_exam.SYSTEM.read_text(encoding="utf-8"))
        rows = publish_exam.composition_from_text(publish_exam.COMPOSITION.read_text(encoding="utf-8"))
        facts = publish_exam.check_rows(*rows)
        bridge_exam.judge_pins(bridge_exam.PINS.read_text(encoding="utf-8"))
        store = publish_exam.store_from_bag(os.environ.get("SLIME_LIDAR_BAG"))
        published = publish_exam.expected(store)
        viewed = bridge_exam.store_of(store)
    except (publish_exam.ExamError, bridge_exam.ExamError, zenoh_exchange.ExchangeError) as error:
        fail(str(error))
    generation = rows[0]
    image = PUBLISH.build_image(publish_exam.CLOSURE)
    netdev = f"user,id=slimenet,net=10.0.2.0/24,host={zenoh_capture.PEER},dhcpstart={zenoh_capture.GUEST},ipv6=off"
    with tempfile.TemporaryDirectory(prefix="slime-lidar-foxglove-demo-") as name:
        directory = Path(name)
        disk = PUBLISH.write_disk(directory, store)
        websocket_port = BRIDGE.free_port()
        bridge = BRIDGE.Bridge(directory / "lidar.store", ZENOH_PORT, websocket_port)
        client: ws.Client | None = None
        reader: Reader | None = None
        # Whatever ends the run, the client is closed and the bridge stopped before the step returns or fails.
        try:
            if not bridge.ready.wait(bridge_exam.READY_SECONDS):
                fail(f"the bridge printed no ready line within {bridge_exam.READY_SECONDS} s: {''.join(bridge.stderr)[-400:]}")
            try:
                client = ws.Client("127.0.0.1", websocket_port, timeout=10)
                before = read_before(client, BEFORE_SECONDS)
                advertised = [m.json() for m in before if m.text is not None and m.json().get("op") == "advertise"]
                if len(advertised) != 1 or len(advertised[0].get("channels", [])) != 1:
                    bridge_exam.judge_session(before, [], viewed)
                channel = advertised[0]["channels"][0]["id"]
                client.send_json({"op": "subscribe", "subscriptions": [{"id": bridge_exam.SUBSCRIPTION, "channelId": channel}]})
                reader = Reader(client)
                capture = directory / "network.pcap"
                transcript = run_plane(
                    image=image, timeout=publish_exam.QEMU_SECONDS, terminal_condition=publish_exam.TERMINAL,
                    fail=fail, pins_path=PUBLISH.PINS,
                    additional_arguments=(
                        "-netdev", netdev,
                        "-device", f"virtio-net-device,netdev=slimenet,mac={publish_exam.INTERFACE['mac']}",
                        "-object", f"filter-dump,id=netcapture,netdev=slimenet,file={capture}",
                        "-drive", f"if=none,id=slimedata,format=raw,readonly=on,file={disk}",
                        "-device", "virtio-blk-device,drive=slimedata",
                    ),
                )
                if transcript_path is not None:
                    transcript_path.write_text(transcript, encoding="utf-8")
                failure = publish_exam.FAILURES.search(transcript)
                if failure is not None:
                    print(transcript)
                    fail(f"the guest printed a failure line: {failure.group(0)!r}")
                if not capture.is_file():
                    fail("QEMU did not produce the demo's packet observation")
                after = reader.finish()
                observed = publish_exam.judge_transcript(transcript, published, ceiling, generation)
                wire = publish_exam.judge_capture(capture.read_bytes(), published)
                bridge_exam.judge_session(before, after, viewed)
            except (publish_exam.ExamError, bridge_exam.ExamError, ws.ProtocolError, OSError) as error:
                fail(f"demo evidence refused: {error}; bridge said {''.join(bridge.stdout)[-300:]!r}")
        finally:
            if reader is not None:
                reader.stop.set()
            if client is not None:
                client.close()
            returncode, timely = bridge.stop()
        if not timely:
            fail(f"the bridge did not stop within {BRIDGE.STOP_SECONDS} s of SIGTERM")
        try:
            bridge_exam.judge_lines("".join(bridge.stdout), returncode, ZENOH_PORT, websocket_port, len(viewed.frames))
        except bridge_exam.ExamError as error:
            fail(f"bridge lines: {error}")
    print(f"[lidar-foxglove-demo] guest puts={wire['puts']} late={observed['late']} min-gap-ms={wire['min_gap_ns'] / 1e6:.3f} span-s={wire['span_ns'] / 1e9:.3f} authority-facts={facts}")
    print(f"[lidar-foxglove-demo] client messages={len(after)} bytes={sum(len(p) for _, p in viewed.frames)} channel={channel}")
    devloop_observations.record(casesObserved=len(after), bytesObserved=sum(len(p) for _, p in viewed.frames), negativeControlsRefused=refused)
    print("lidar foxglove demo check: every frame the guest read from its read-only disk reached an independent Foxglove client through the bridge, byte for byte, in order and with its log time, and the boot ended HEALTHY")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--controls-only", action="store_true", help="run both exams' controls only")
    parser.add_argument("--transcript", type=Path, help="write the guest's serial transcript here")
    arguments = parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    if arguments.controls_only:
        controls()
        return
    run(arguments.transcript)


if __name__ == "__main__":
    main()
