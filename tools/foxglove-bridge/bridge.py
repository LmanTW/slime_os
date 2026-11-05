#!/usr/bin/env python3
"""Forward one frame store's ROS 2 topic from Zenoh to Foxglove over the SDK's WebSocket protocol.

    python3 tools/foxglove-bridge/bridge.py --store STORE --zenoh-port P --websocket-port Q [--pins FILE]

A manual demo tool, in no aggregate. It reads the `contracts/frame-store/v1` file STORE only for its
topic, type name, type hash and schema text, and never forwards the store's own frames.

On every start it rebuilds its environment under `build/foxglove-bridge/venv` from the wheels FILE pins,
by default `pins.txt` beside this file, with `pip --require-hashes --no-deps --only-binary=:all:`. A host
with no pin, a pin pip refuses and a store that is not valid are each refused before anything listens,
with a final stderr line `foxglove-bridge: refused CLASS`, CLASS one of host, dependency and store.

It then runs, in that environment:

* an eclipse-zenoh peer listening on tcp/127.0.0.1:P, subscribed to the store's ROS 2 data key alone;
* a foxglove-sdk WebSocket server on 127.0.0.1:Q, with one channel: the store's topic, message encoding
  `cdr`, schema name the store's type, schema encoding `ros2msg` and the store's schema text.

A sample on the store's ROS 2 data key is logged on the channel with its payload unchanged. Its log time
is the timestamp of its 33-byte rmw_zenoh attachment, or the host receive time if it carries none. The
subscription names the key in full: the guest's Zenoh Profile 0 session refuses a wildcard key declaration,
so a bridge subscribed to a pattern ends the publisher's session. A sample on any other key is never
delivered to the bridge. It prints each of these lines on stdout:

    foxglove-bridge: ready zenoh=tcp/127.0.0.1:P websocket=ws://127.0.0.1:Q
    foxglove-bridge: stopped forwarded=F

The ready line follows once both servers listen; the stopped line follows SIGINT or SIGTERM, and the
bridge then exits 0.
"""

from __future__ import annotations

import argparse
import os
import platform
import signal
import struct
import subprocess
import sys
from pathlib import Path

# The bridge imports modules from the checkout, and a bytecode cache written there would change the tree
# a gate is grading while it runs. Neither process writes one.
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "frame-store"))
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import frame_store  # noqa: E402  (the converter's validator, written from contracts/frame-store/v1)
import frame_store_contract as contract  # noqa: E402  (generated from contracts/frame-store/v1)

ENVIRONMENT = ROOT / "build" / "foxglove-bridge" / "venv"
DEFAULT_PINS = HERE / "pins.txt"
# The hosts the committed pins name wheels for. pip skips a pin whose marker does not match, so a host
# outside this set would install nothing and is refused rather than started without its dependencies.
HOSTS = {("linux", "x86_64"), ("darwin", "arm64")}
# The rmw_zenoh attachment: sequence (i64), source timestamp (i64), GID length (u8, 16), GID.
ATTACHMENT = struct.Struct("<qqB16s")
GID_BYTES = 16
PREFIX = "foxglove-bridge: "


def refuse(kind: str, detail: str = "") -> None:
    if detail:
        print(f"{PREFIX}{detail}", file=sys.stderr, flush=True)
    print(f"{PREFIX}refused {kind}", file=sys.stderr, flush=True)
    raise SystemExit(1)


class Store:
    """The facts of a frame store the bridge advertises and subscribes by."""

    def __init__(self, data: bytes) -> None:
        frame_store.validate(data)
        (_magic, _version, _hash_version, _r0, _count, topic_len, type_len, schema_len, _r1, _period,
         type_hash) = contract.FRAME_STORE_HEADER.unpack_from(data)
        topic_end = contract.HEADER_BYTES + topic_len
        type_end = topic_end + type_len
        self.topic = data[contract.HEADER_BYTES:topic_end].decode("utf-8")
        self.type_name = data[topic_end:type_end].decode("utf-8")
        self.schema = data[type_end:type_end + schema_len]
        self.key = data_key(self.topic, self.type_name, type_hash)


def data_key(topic: str, type_name: str, type_hash: bytes) -> str:
    """The rmw_zenoh data key of `topic` in ROS 2 domain 0: domain, topic, DDS type name and type hash."""
    package, separator, name = type_name.partition("/msg/")
    if not separator or not package or not name or "/" in name:
        refuse("store", f"the type {type_name!r} is not a ROS 2 message type")
    return f"0/{topic.strip('/')}/{package}::msg::dds_::{name}_/RIHS01_{type_hash.hex()}"


def log_time_of(attachment: bytes | None, received: int) -> int:
    """The source timestamp of a 33-byte rmw_zenoh attachment, or `received` without a usable one."""
    if attachment is None or len(attachment) != ATTACHMENT.size:
        return received
    _sequence, timestamp, gid_length, _gid = ATTACHMENT.unpack(attachment)
    if gid_length != GID_BYTES or timestamp < 0:
        return received
    return timestamp


def build_environment(pins: Path) -> Path:
    """The interpreter of a fresh environment holding exactly the pinned wheels, or a refusal."""
    if (sys.platform, platform.machine()) not in HOSTS:
        refuse("host", f"no wheel is pinned for {sys.platform} {platform.machine()}")
    if not pins.is_file():
        refuse("dependency", f"{pins} does not exist")
    python = ENVIRONMENT / "bin" / "python"
    clean = {key: value for key, value in os.environ.items() if not key.startswith(("PYTHON", "PIP_"))}
    steps = (
        [sys.executable, "-I", "-m", "venv", "--clear", str(ENVIRONMENT)],
        [str(python), "-I", "-m", "pip", "--isolated", "install", "--quiet", "--require-hashes", "--no-deps",
         "--only-binary=:all:", "-r", str(pins)],
    )
    for command in steps:
        done = subprocess.run(command, env=clean, capture_output=True, text=True, check=False)
        if done.returncode != 0:
            refuse("dependency", (done.stderr.strip().splitlines() or [f"{command[2]} exited {done.returncode}"])[-1])
    return python


def serve(store: Store, zenoh_port: int, websocket_port: int) -> int:
    """Run both servers in the pinned environment until SIGINT or SIGTERM."""
    import json
    import threading
    import time

    import foxglove
    import zenoh

    for module in (foxglove, zenoh):
        location = Path(module.__file__).resolve()
        if Path(sys.prefix).resolve() not in location.parents:
            refuse("dependency", f"{module.__name__} imported from {location}, not from {sys.prefix}")
    server = foxglove.start_server(host="127.0.0.1", port=websocket_port)
    channel = foxglove.Channel(
        store.topic, message_encoding="cdr",
        schema=foxglove.Schema(name=store.type_name, encoding="ros2msg", data=store.schema),
    )
    config = zenoh.Config()
    config.insert_json5("mode", json.dumps("peer"))
    config.insert_json5("listen/endpoints", json.dumps([f"tcp/127.0.0.1:{zenoh_port}"]))
    config.insert_json5("scouting/multicast/enabled", "false")
    config.insert_json5("scouting/gossip/enabled", "false")
    session = zenoh.open(config)
    forwarded = 0
    # Zenoh delivers on its own threads; one lock keeps the count and the channel's order in step.
    lock = threading.Lock()

    def on_sample(sample: zenoh.Sample) -> None:
        nonlocal forwarded
        received = time.time_ns()
        attachment = None if sample.attachment is None else bytes(sample.attachment)
        with lock:
            channel.log(bytes(sample.payload), log_time=log_time_of(attachment, received))
            forwarded += 1

    subscriber = session.declare_subscriber(store.key, on_sample)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    print(f"{PREFIX}ready zenoh=tcp/127.0.0.1:{zenoh_port} websocket=ws://127.0.0.1:{websocket_port}", flush=True)
    stop.wait()
    subscriber.undeclare()
    session.close()
    server.stop()
    with lock:
        print(f"{PREFIX}stopped forwarded={forwarded}", flush=True)
    return 0


def port(text: str) -> int:
    value = int(text)
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError(f"{value} is not a TCP port")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--store", type=Path, required=True, help="the frame store whose topic is forwarded")
    parser.add_argument("--zenoh-port", type=port, required=True, help="the Zenoh listener's port on 127.0.0.1")
    parser.add_argument("--websocket-port", type=port, required=True, help="the Foxglove server's port on 127.0.0.1")
    parser.add_argument("--pins", type=Path, default=DEFAULT_PINS, help="the hash-pinned wheels to install")
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.zenoh_port == arguments.websocket_port:
        parser.error("the Zenoh and WebSocket ports are the same")
    try:
        store = Store(arguments.store.read_bytes())
    except (OSError, frame_store.InvalidStore) as error:
        refuse("store", f"{arguments.store}: {error}")
    if arguments.serve:
        return serve(store, arguments.zenoh_port, arguments.websocket_port)
    python = build_environment(arguments.pins)
    # The servers run in the pinned environment, as a child that inherits this process's output, so the
    # signal that stops the bridge is passed on to it and its exit status is the bridge's.
    child = subprocess.Popen(
        [str(python), "-E", "-B", str(Path(__file__).resolve()), "--serve", "--store", str(arguments.store),
         "--zenoh-port", str(arguments.zenoh_port), "--websocket-port", str(arguments.websocket_port)],
        env={key: value for key, value in os.environ.items() if not key.startswith(("PYTHON", "PIP_"))},
    )
    signal.signal(signal.SIGTERM, lambda *_: child.send_signal(signal.SIGTERM))
    signal.signal(signal.SIGINT, lambda *_: child.send_signal(signal.SIGTERM))
    return child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
