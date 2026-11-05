#!/usr/bin/env python3
"""Run the LiDAR demo for a person: the recorded point cloud from a SlimeOS guest into Foxglove.

    SLIME_LIDAR_BAG=<bag> python3 tools/foxglove-bridge/demo.py [--websocket-port Q] [--no-wait]

A manual tool, in no aggregate and judged by no gate; `just lidar_foxglove_demo_check` judges the same chain.
It runs, in order:

1. `tools/frame-store/convert-mcap.py` on the bag SLIME_LIDAR_BAG names, which it refuses unless the bag's
   SHA-256 is `BAG_SHA256`, for the `/velodyne_points` channel;
2. `scripts/build/build-data-volume.py` on that store, for the disk the guest reads;
3. the `sel4-lidar-external` image, from its closure;
4. `bridge.py` on the store, listening for Zenoh on tcp/127.0.0.1:17447, the host peer the composition
   grants, and serving Foxglove on ws://127.0.0.1:Q, 8765 by default.

It then prints the WebSocket URL and, unless `--no-wait` is given, waits for Enter, so Foxglove can connect
before any frame is sent: the bridge forwards live samples only. The guest boots on aarch64 QEMU with the disk
attached read-only, and the publisher's lines are shown as it prints them. When the guest's graph ends, the
bridge keeps serving until Ctrl-C, so the received cloud can still be viewed.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import closure_image  # noqa: E402  (the closure build the gates use)
import sel4_plane  # noqa: E402  (the pinned qemu-arm-virt command the gates use)

BAG_ENV = "SLIME_LIDAR_BAG"
# The recorded bag the frame store is converted from, as tools/frame-store's exam pins it.
BAG_SHA256 = "9ddece1e03367bd7c5cf1b6f9b977be35b97f00a36dfb4d55990429f0e1558ad"
CHANNEL = "/velodyne_points"
CLOSURE = "sel4-lidar-external"
ZENOH_PORT = 17447
DEFAULT_WEBSOCKET_PORT = 8765
# The composition's interface: QEMU user networking with the guest at 10.0.2.15 and the host at 10.0.2.2.
NETDEV = "user,id=slimenet,net=10.0.2.0/24,host=10.0.2.2,dhcpstart=10.0.2.15,ipv6=off"
MAC = "52:54:00:53:4c:01"
SHOWN = re.compile(r"^(\[lidar-publisher\] |SLIME_GRAPH (HEALTHY|FAIL|exhausted))")
DONE = re.compile(r"SLIME_GRAPH (HEALTHY|FAIL|exhausted)|\] fail: |panic|PANIC")
PREFIX = "lidar-demo: "


def fail(message: str) -> None:
    raise SystemExit(f"{PREFIX}{message}")


def run(*command: str) -> None:
    done = subprocess.run([sys.executable, "-B", *command], cwd=ROOT, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        fail(f"{command[0]} exited {done.returncode}: {(done.stderr or done.stdout).strip()[-400:]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--websocket-port", type=int, default=DEFAULT_WEBSOCKET_PORT, help="the Foxglove server's port on 127.0.0.1")
    parser.add_argument("--no-wait", action="store_true", help="boot the guest without waiting for Enter")
    arguments = parser.parse_args()
    bag = os.environ.get(BAG_ENV)
    if not bag:
        fail(f"{BAG_ENV} must name the LiDAR bag (SHA-256 {BAG_SHA256})")
    with tempfile.TemporaryDirectory(prefix="slime-lidar-demo-") as name:
        directory = Path(name)
        store, disk = directory / "lidar.store", directory / "lidar.img"
        print(f"{PREFIX}converting {CHANNEL} from {bag}", flush=True)
        os.environ[BAG_ENV] = bag
        run("tools/frame-store/convert-mcap.py", "--sha256", BAG_SHA256, "--channel", CHANNEL, "--output", str(store))
        run("scripts/build/build-data-volume.py", "--kind", "frame-store", "--payload", str(store), "--output", str(disk))
        print(f"{PREFIX}building {CLOSURE}", flush=True)
        try:
            image = closure_image.build(CLOSURE).image
        except closure_image.ClosureImageError as error:
            fail(str(error))
        bridge = subprocess.Popen(
            [sys.executable, "-B", str(HERE / "bridge.py"), "--store", str(store), "--zenoh-port", str(ZENOH_PORT),
             "--websocket-port", str(arguments.websocket_port)],
            cwd=ROOT, stdout=subprocess.PIPE, text=True,
        )
        qemu: subprocess.Popen[str] | None = None
        try:
            assert bridge.stdout is not None
            for line in bridge.stdout:
                print(line, end="", flush=True)
                if line.startswith("foxglove-bridge: ready"):
                    break
            else:
                fail(f"the bridge exited {bridge.wait()} before it was ready")
            url = f"ws://127.0.0.1:{arguments.websocket_port}"
            print(f"{PREFIX}in Foxglove, open a Foxglove WebSocket connection to {url} and add a 3D panel for {CHANNEL}", flush=True)
            if not arguments.no_wait:
                input(f"{PREFIX}press Enter to boot the guest ")
            command = sel4_plane.qemu_base_command(image=image, fail=fail) + [
                "-netdev", NETDEV,
                "-device", f"virtio-net-device,netdev=slimenet,mac={MAC}",
                "-drive", f"if=none,id=slimedata,format=raw,readonly=on,file={disk}",
                "-device", "virtio-blk-device,drive=slimedata",
            ]
            qemu = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="replace")
            assert qemu.stdout is not None
            for line in qemu.stdout:
                if SHOWN.search(line):
                    print(line, end="", flush=True)
                if DONE.search(line):
                    break
            qemu.kill()
            qemu.wait()
            print(f"{PREFIX}the guest has finished; the bridge keeps serving {url}. Press Ctrl-C to stop it.", flush=True)
            try:
                signal.pause()
            except KeyboardInterrupt:
                pass
        except KeyboardInterrupt:
            pass
        finally:
            if qemu is not None and qemu.poll() is None:
                qemu.kill()
                qemu.wait()
            if bridge.poll() is None:
                bridge.send_signal(signal.SIGTERM)
            try:
                output, _ = bridge.communicate(timeout=30)
                print(output, end="", flush=True)
            except subprocess.TimeoutExpired:
                bridge.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
