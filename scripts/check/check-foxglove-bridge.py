#!/usr/bin/env python3

"""Judge the Foxglove bridge: `tools/foxglove-bridge/bridge.py` between a Zenoh replayer and a client.

The expectation lives in `scripts/lib/foxglove_bridge_exam.py`, and the client in `scripts/lib/foxglove_ws.py`.
This script runs the bridge as a command and imports none of it:

    python3 tools/foxglove-bridge/bridge.py --store FILE --zenoh-port P --websocket-port Q [--pins FILE]
        listen for Zenoh on tcp/127.0.0.1:P and serve Foxglove on ws://127.0.0.1:Q until SIGTERM

Steps:

1. The exam's judges hold their controls, and the bridge's committed pin file names exactly the exam's wheels.
2. The bridge, started with a pin file whose eclipse-zenoh hash for this host is changed, refuses as a
   dependency and calls listen() on no socket. Both runs of the bridge load `scripts/lib/listen_log.c`,
   built with the host's cc, which records every listen() its process tree calls without changing it, as
   `contracts/listen-record/v1` records the exam reads through that contract's decoder; the ports stay free.
   Three stand-ins hold the step to its claim: one that refuses, one that listens for 50 ms before it
   refuses, and one that tries to listen, ignores the outcome and refuses. A fourth listens on both ports,
   and its records must decode and show both listeners, so the shim's writer and the contract agree.
3. The frame store is encoded by the exam from the bag `SLIME_LIDAR_BAG` names, pinned by size and SHA-256.
   The bridge starts on it. A client connects and subscribes the channel the bridge advertises.
4. A stock eclipse-zenoh 1.0.0 peer, from the external Zenoh checks' pinned wheel, puts one sample on
   another key under domain 0 and every frame on the store's key. The bridge subscribes the store's key
   alone, so the other sample reaches neither the client nor a line of the bridge's.
5. The session the client saw and the bridge's own lines are judged against the store, and the shim must
   have recorded the bridge listening on both ports, so the refusal's empty record is an observation.

Runs entirely on the host and needs no QEMU. The bag and a registry are needed, so the recipe is explicit and
in no aggregate. `--controls-only` runs step 1's controls.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import os
import platform
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import NoReturn

import devloop_observations
import foxglove_bridge_exam as exam
import foxglove_ws as ws
import lidar_publish_exam
import zenoh_listener_peer
from harness import ROOT

REPLAYER = ROOT / "scripts" / "lib" / "zenoh_replayer.py"
SHIM_SOURCE = ROOT / "scripts" / "lib" / "listen_log.c"
REFUSAL_SECONDS = 600
STOP_SECONDS = 30


def fail(message: str) -> NoReturn:
    raise SystemExit(f"foxglove bridge check: {message}")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Shim:
    """`listen_log.c` built for this host, and the environment that loads it into a process tree."""

    def __init__(self, directory: Path) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            fail("no cc on PATH to build scripts/lib/listen_log.c")
        if _sys.platform == "darwin":
            self.library, flags, self.variable = directory / "listen_log.dylib", ["-dynamiclib"], "DYLD_INSERT_LIBRARIES"
        elif _sys.platform == "linux":
            self.library, flags, self.variable = directory / "listen_log.so", ["-shared", "-fPIC", "-ldl"], "LD_PRELOAD"
        else:
            fail(f"no listen shim is defined for {_sys.platform}")
        built = subprocess.run([compiler, *flags, "-o", str(self.library), str(SHIM_SOURCE)], capture_output=True, text=True, check=False)
        if built.returncode != 0 or not self.library.is_file():
            fail(f"cc could not build scripts/lib/listen_log.c: {built.stderr.strip()[-300:]}")
        self.directory = directory
        self.runs = 0

    def environment(self) -> tuple[dict[str, str], Path]:
        """The variables that load the shim, and the fresh, empty directory it writes its records to."""
        self.runs += 1
        records = self.directory / f"listen-records-{self.runs}"
        shutil.rmtree(records, ignore_errors=True)
        records.mkdir()
        return {self.variable: str(self.library), "SLIME_LISTEN_RECORDS": str(records)}, records


def records(directory: Path) -> list[tuple[int, int, bool]]:
    return exam.read_records(directory)


class Bridge:
    """The bridge as a child process, its stdout read on a thread so a chatty child never blocks."""

    def __init__(self, store: Path, zenoh_port: int, websocket_port: int, pins: Path | None = None, program: Path | None = None,
                 shim: dict[str, str] | None = None) -> None:
        command = [_sys.executable, str(program or exam.BRIDGE), "--store", str(store), "--zenoh-port", str(zenoh_port), "--websocket-port", str(websocket_port)]
        if pins is not None:
            command += ["--pins", str(pins)]
        self.process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **(shim or {})})
        self.stdout: list[str] = []
        self.stderr: list[str] = []
        self.ready = threading.Event()
        self.threads = [threading.Thread(target=self._read, args=(stream, sink), daemon=True)
                        for stream, sink in ((self.process.stdout, self.stdout), (self.process.stderr, self.stderr))]
        for thread in self.threads:
            thread.start()

    def _read(self, stream, sink: list[str]) -> None:
        for line in stream:
            sink.append(line)
            if exam.READY.fullmatch(line.strip()):
                self.ready.set()

    def stop(self) -> tuple[int, bool]:
        """Stop the bridge whatever state the run is in, and return its exit status and whether it stopped
        within `STOP_SECONDS` of SIGTERM. It never raises, so a failing step can call it on its way out."""
        timely = True
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
        try:
            self.process.wait(timeout=STOP_SECONDS)
        except subprocess.TimeoutExpired:
            timely = False
            self.process.kill()
            self.process.wait()
        for thread in self.threads:
            thread.join(5)
        return self.process.returncode, timely


def controls() -> int:
    try:
        accepted, refused = exam.controls()
    except exam.ExamError as error:
        fail(str(error))
    with tempfile.TemporaryDirectory(prefix="slime-foxglove-refusal-") as name:
        shim = Shim(Path(name))
        refused += refusal_controls(Path(name), shim)
        writer_control(Path(name), shim)
    print(f"[foxglove-bridge] controls accepted={accepted + 2} refused={refused}")
    return refused


def refusal(shim: Shim, store: Path, pins: Path, program: Path | None = None) -> None:
    """Start `program` (the bridge) with `pins` under the shim, on free ports, and judge its refusal."""
    zenoh_port, websocket_port = free_port(), free_port()
    variables, log = shim.environment()
    bridge = Bridge(store, zenoh_port, websocket_port, pins, program, variables)
    try:
        bridge.process.wait(timeout=REFUSAL_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    returncode = bridge.process.poll()
    if returncode is None:
        bridge.stop()
    for thread in bridge.threads:
        thread.join(5)
    exam.judge_refusal(returncode, "".join(bridge.stderr), records(log))


STAND_IN_SERVES = """import socket, sys, time
ports = [int(sys.argv[sys.argv.index(flag) + 1]) for flag in ("--zenoh-port", "--websocket-port")]
sockets = []
for port in ports:
    s = socket.socket()
    s.bind(("127.0.0.1", port))
    s.listen()
    sockets.append(s)
"""


def writer_control(directory: Path, shim: Shim) -> None:
    """A process that listens on both ports under the shim: its records decode and show both listeners."""
    program = directory / "stand-in-serves.py"
    program.write_text(STAND_IN_SERVES, encoding="utf-8")
    zenoh_port, websocket_port = free_port(), free_port()
    variables, log = shim.environment()
    done = subprocess.run([_sys.executable, str(program), "--zenoh-port", str(zenoh_port), "--websocket-port", str(websocket_port)],
                          env={**os.environ, **variables}, capture_output=True, text=True, timeout=60, check=False)
    if done.returncode != 0:
        fail(f"control: the listening stand-in exited {done.returncode}: {done.stderr[-300:]}")
    try:
        exam.judge_listeners(records(log), zenoh_port, websocket_port)
    except exam.ExamError as error:
        fail(f"control: the shim's records of a listening process do not hold: {error}")


STAND_IN_REFUSES = """import sys
print("foxglove-bridge: refused dependency", file=sys.stderr, flush=True)
sys.exit(1)
"""
STAND_IN_LISTENS = """import socket, sys, time
ports = [int(sys.argv[sys.argv.index(flag) + 1]) for flag in ("--zenoh-port", "--websocket-port")]
sockets = []
for port in ports:
    s = socket.socket()
    s.bind(("127.0.0.1", port))
    s.listen()
    sockets.append(s)
time.sleep(0.05)
print("foxglove-bridge: refused dependency", file=sys.stderr, flush=True)
sys.exit(1)
"""
STAND_IN_TRIES = """import socket, sys
ports = [int(sys.argv[sys.argv.index(flag) + 1]) for flag in ("--zenoh-port", "--websocket-port")]
for port in ports:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        s.listen()
    except OSError:
        pass
print("foxglove-bridge: refused dependency", file=sys.stderr, flush=True)
sys.exit(1)
"""


def refusal_controls(directory: Path, shim: Shim) -> int:
    """The refusal step on stand-ins: a refusal is accepted, and a refusal after listening, or after trying
    to listen whatever the outcome, is not."""
    store, pins = directory / "control.store", directory / "control-pins.txt"
    store.write_bytes(b"")
    pins.write_text(exam.pin_text(), encoding="utf-8")
    cases = (("refuses", STAND_IN_REFUSES, True), ("listens-then-refuses", STAND_IN_LISTENS, False),
             ("tries-to-listen-then-refuses", STAND_IN_TRIES, False))
    for name, source, honest in cases:
        program = directory / f"stand-in-{name}.py"
        program.write_text(source, encoding="utf-8")
        try:
            refusal(shim, store, pins, program)
            took = True
        except exam.ExamError:
            took = False
        if took != honest:
            fail(f"control: the refusal step {'refused' if honest else 'accepted'} the stand-in that {name}")
    return len(cases) - 1


def step_refusal(directory: Path, store: Path, shim: Shim) -> None:
    marker = exam.host_marker(_sys.platform, platform.machine())
    pins = directory / "altered-pins.txt"
    pins.write_text(exam.altered_pins(exam.PINS.read_text(encoding="utf-8"), marker), encoding="utf-8")
    try:
        refusal(shim, store, pins)
    except exam.ExamError as error:
        fail(f"refusal: {error}")
    print("[foxglove-bridge] a changed pin is refused as a dependency, and the bridge called listen() on no socket")


def step_run(store_path: Path, want: exam.Store, shim: Shim) -> int:
    zenoh_port, websocket_port = free_port(), free_port()
    variables, log = shim.environment()
    bridge = Bridge(store_path, zenoh_port, websocket_port, shim=variables)
    client: ws.Client | None = None
    # Whatever ends the session, the client is closed and the bridge stopped before the step returns or fails,
    # so a failed run leaves no bridge or listener behind.
    try:
        if not bridge.ready.wait(exam.READY_SECONDS):
            fail(f"the bridge printed no ready line within {exam.READY_SECONDS} s: {''.join(bridge.stderr)[-400:]}")
        try:
            client = ws.Client("127.0.0.1", websocket_port, timeout=10)
            before: list[ws.Message] = []
            deadline = time.monotonic() + 5
            while (message := client.receive(deadline)) is not None:
                before.append(message)
            advertised = [m.json() for m in before if m.text is not None and m.json().get("op") == "advertise"]
            if len(advertised) != 1 or len(advertised[0].get("channels", [])) != 1:
                exam.judge_session(before, [], want)
            channel = advertised[0]["channels"][0]["id"]
            client.send_json({"op": "subscribe", "subscriptions": [{"id": exam.SUBSCRIPTION, "channelId": channel}]})
            interpreter = zenoh_listener_peer.ensure_venv()
            replay = subprocess.run(
                [str(interpreter), "-E", str(REPLAYER), str(zenoh_port), str(store_path), lidar_publish_exam.KEY,
                 exam.OTHER_KEY, str(exam.REPLAY_PERIOD_MS)],
                capture_output=True, text=True, timeout=len(want.frames) * exam.REPLAY_PERIOD_MS / 1000 + 300,
                env={k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "PIP_"))},
            )
            if replay.returncode != 0:
                raise exam.ExamError(f"the replayer exited {replay.returncode}: {(replay.stdout + replay.stderr)[-400:]}")
            after: list[ws.Message] = []
            deadline = time.monotonic() + exam.SETTLE_SECONDS
            while (message := client.receive(deadline)) is not None:
                after.append(message)
                deadline = time.monotonic() + exam.SETTLE_SECONDS
            exam.judge_session(before, after, want)
        except (exam.ExamError, ws.ProtocolError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            fail(f"session: {error}; bridge said {''.join(bridge.stdout)[-300:]!r}")
    finally:
        if client is not None:
            client.close()
        returncode, timely = bridge.stop()
    if not timely:
        fail(f"the bridge did not stop within {STOP_SECONDS} s of SIGTERM")
    try:
        exam.judge_lines("".join(bridge.stdout), returncode, zenoh_port, websocket_port, len(want.frames))
        exam.judge_listeners(records(log), zenoh_port, websocket_port)
    except exam.ExamError as error:
        fail(f"bridge lines: {error}")
    print(f"[foxglove-bridge] messages={len(after)} bytes={sum(len(p) for _, p in want.frames)} channel={channel} other-key-messages=0")
    return len(after)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--controls-only", action="store_true", help="run the judges against their controls only")
    arguments = parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    refused = controls()
    if arguments.controls_only:
        return
    for path in (exam.BRIDGE, exam.PINS):
        if not path.is_file():
            fail(f"{path.relative_to(ROOT)} does not exist; the bridge has not landed")
    try:
        exam.judge_pins(exam.PINS.read_text(encoding="utf-8"))
        data = lidar_publish_exam.store_from_bag(os.environ.get("SLIME_LIDAR_BAG"))
        want = exam.store_of(data)
    except (exam.ExamError, lidar_publish_exam.ExamError) as error:
        fail(str(error))
    with tempfile.TemporaryDirectory(prefix="slime-foxglove-bridge-") as name:
        directory = Path(name)
        store = directory / "lidar.store"
        store.write_bytes(data)
        shim = Shim(directory)
        step_refusal(directory, store, shim)
        messages = step_run(store, want, shim)
    devloop_observations.record(casesObserved=messages, bytesObserved=sum(len(p) for _, p in want.frames), negativeControlsRefused=refused)
    print("foxglove bridge check: a stock Zenoh replayer's every frame reached an independent Foxglove client through the bridge, byte for byte and in order, the replayer's sample on another key reached neither the client nor the bridge's output, and the bridge refused a changed pin")


if __name__ == "__main__":
    main()
