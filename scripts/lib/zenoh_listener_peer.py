"""A stock eclipse-zenoh 1.0.0 listener on the host, and the record it writes about what it received.

Two halves in one file. The importing half (`ensure_venv`, `Listener`) runs under the system
Python: it builds a virtual environment under `build/zenoh-external/` from the wheel pinned below
for the host's platform with `pip --require-hashes --no-deps`, then starts the second half in that
environment. The script half (`python zenoh_listener_peer.py <port> <receipt> <key> <samples>
<form> <deadline>`) is the stock peer: mode peer, multicast scouting and gossip off, one TCP
listener on the host loopback, one subscriber on the key. When the guest's session ends it writes
one record: `contracts/zenoh-external-receipt/v1` for the `whole` form, each payload as
hexadecimal, or `contracts/zenoh-digest-receipt/v1` for the `digest` form, each payload as its
length and SHA-256. It never reads the wire the packet capture holds.

QEMU user networking forwards the guest's `10.0.2.2` to the host's loopback, so the listener
binds `127.0.0.1` and nothing wider. The wheel is a registry download and this is an explicit
local experiment, never part of CI.
"""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import sys
import threading
import time
from pathlib import Path

from harness import ROOT

# One wheel per host platform the exams run on, each pinned by its registry SHA-256. A host with
# no pin here is refused rather than given whichever wheel the registry offers it.
WHEELS = {
    ("linux", "x86_64"): (
        "eclipse_zenoh-1.0.0-cp38-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "1763912951ecd2a3706f668faf0541245387096b37a4fefb73af7848dadd46ff",
    ),
    ("darwin", "arm64"): (
        "eclipse_zenoh-1.0.0-cp38-abi3-macosx_10_12_x86_64.macosx_11_0_arm64.macosx_10_12_universal2.whl",
        "08b0871119786a1432864af8aa0cf42019a4b7bc8cfe725588cbc15f7d007f90",
    ),
}
VERSION = "1.0.0"
FORMS = ("whole", "digest")
PORT = 17447
SCRATCH = ROOT / "build" / "zenoh-external"
VENV = SCRATCH / "venv"
REQUIREMENTS = SCRATCH / "requirements.txt"
KEY = "0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_a82fd5ffcb96d0a197a5ad3680d1c4e6ba43a962928ecd592fb565eb8129595b"
SAMPLES = 4
READY = "[zenoh-listener] ready"
# The guest's session is judged by the capture; the listener only has to stay up until the
# guest's four samples have arrived and the link has closed, or this bound passes.
DEADLINE_SECONDS = 150
READY_SECONDS = 30
SETTLE_SECONDS = 3


class ListenerError(RuntimeError):
    """The pinned peer could not be built or did not run."""


def _clean_environment() -> dict[str, str]:
    """The caller's environment without anything that steers Python's imports or its installer."""
    return {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "PIP_"))}


def venv_python() -> Path:
    return VENV / "bin" / "python"


def wheel_pin() -> tuple[str, str]:
    """The pinned wheel's file name and SHA-256 for this host, or a refusal."""
    host = (sys.platform, platform.machine())
    if host not in WHEELS:
        raise ListenerError(f"no eclipse-zenoh {VERSION} wheel is pinned for {host[0]} {host[1]}")
    return WHEELS[host]


def ensure_venv() -> Path:
    """The pinned peer's interpreter, built fresh from the hash-pinned wheel on every call.

    An existing environment is never reused: its metadata says nothing about the files installed,
    and only the hash-constrained install proves they are the pinned wheel's.
    """
    interpreter = venv_python()
    SCRATCH.mkdir(parents=True, exist_ok=True)
    _wheel, digest = wheel_pin()
    REQUIREMENTS.write_text(f"eclipse-zenoh=={VERSION} --hash=sha256:{digest}\n", encoding="utf-8")
    steps = (
        [sys.executable, "-I", "-m", "venv", "--clear", str(VENV)],
        # --isolated ignores environment variables and every pip configuration file, user and global,
        # which -I does not: a `no-index` or a `target` in the caller's pip.conf would change the install.
        [str(interpreter), "-I", "-m", "pip", "--isolated", "install", "--quiet", "--require-hashes", "--no-deps", "--only-binary=:all:", "-r", str(REQUIREMENTS)],
    )
    for command in steps:
        done = subprocess.run(command, capture_output=True, text=True, check=False, env=_clean_environment())
        if done.returncode != 0:
            raise ListenerError(f"{' '.join(command[:4])} failed: {done.stderr.strip()[-400:]}")
    return interpreter


class Listener:
    """The stock peer as a child process; the context returns once it is subscribed."""

    def __init__(
        self, receipt: Path, port: int = PORT, key: str = KEY, samples: int = SAMPLES,
        form: str = "whole", deadline: int = DEADLINE_SECONDS,
    ) -> None:
        if form not in FORMS:
            raise ListenerError(f"a record form {form!r}, the listener writes {FORMS}")
        self.receipt, self.port, self.key, self.samples, self.form, self.deadline = receipt, port, key, samples, form, deadline
        self.process: subprocess.Popen[str] | None = None

    def __enter__(self) -> Listener:
        interpreter = ensure_venv()
        self.receipt.unlink(missing_ok=True)
        arguments = (self.port, self.receipt, self.key, self.samples, self.form, self.deadline)
        self.process = subprocess.Popen(
            [str(interpreter), "-E", str(Path(__file__).resolve()), *map(str, arguments)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=_clean_environment(),
        )
        assert self.process.stdout is not None
        # readline() blocks until a newline, so a child that stays alive and silent would hold the
        # deadline hostage. A reader thread reports the first line and the wait on it is bounded.
        ready = threading.Event()
        stream = self.process.stdout
        self.output: list[str] = []

        def watch() -> None:
            # The reader runs until the child closes its output: stopping at READY would leave a
            # pipe nobody drains, and a chatty child would block on it before it wrote its record.
            for line in stream:
                self.output.append(line)
                if line.strip() == READY:
                    ready.set()

        self.reader = threading.Thread(target=watch, daemon=True)
        self.reader.start()
        if ready.wait(READY_SECONDS):
            return self
        self.__exit__(None, None, None)
        raise ListenerError(f"the stock listener did not report ready within {READY_SECONDS} s")

    def finish(self, timeout: float) -> str:
        """Wait for the peer to write its record; returns what it printed."""
        assert self.process is not None and self.process.stdout is not None
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise ListenerError("the stock listener did not finish") from error
        self.reader.join(10)
        output = "".join(self.output)
        if self.process.returncode != 0:
            raise ListenerError(f"the stock listener exited {self.process.returncode}: {output[-300:]}")
        return output

    def __exit__(self, *_exc: object) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


def receipt_text(listen: str, remote_peers: int, samples: list[tuple[str, bytes, bytes]]) -> str:
    rows = "".join(f'    {{ key = "{key}"; payloadHex = "{payload.hex()}"; attachmentHex = "{attachment.hex()}"; }};\n' for key, payload, attachment in samples)
    return f'{{\n  formatVersion = 1;\n  peerVersion = "{VERSION}";\n  listen = "{listen}";\n  maxRemotePeers = {remote_peers};\n  samples = [\n{rows}  ];\n}}\n'


def digested(key: str, payload: bytes, attachment: bytes) -> tuple[str, int, str, bytes]:
    """One delivery reduced to what the digest record keeps, so the peer never holds a payload."""
    return key, len(payload), hashlib.sha256(payload).hexdigest(), attachment


def digest_receipt_text(listen: str, remote_peers: int, samples: list[tuple[str, int, str, bytes]]) -> str:
    """A `contracts/zenoh-digest-receipt/v1` record from rows `digested` made."""
    rows = "".join(
        f'    {{ key = "{key}"; payloadBytes = {size}; payloadSha256 = "{sha256}"; attachmentHex = "{attachment.hex()}"; }};\n'
        for key, size, sha256, attachment in samples
    )
    return f'{{\n  formatVersion = 1;\n  peerVersion = "{VERSION}";\n  listen = "{listen}";\n  maxRemotePeers = {remote_peers};\n  samples = [\n{rows}  ];\n}}\n'


def serve(port: int, receipt: Path, key: str = KEY, expected: int = SAMPLES, form: str = "whole", seconds: int = DEADLINE_SECONDS) -> int:
    import json

    import zenoh

    listen = f"tcp/127.0.0.1:{port}"
    config = zenoh.Config()
    config.insert_json5("mode", json.dumps("peer"))
    config.insert_json5("listen/endpoints", json.dumps([listen]))
    config.insert_json5("scouting/multicast/enabled", "false")
    config.insert_json5("scouting/gossip/enabled", "false")
    # The pinned wheel is the only zenoh this process may use: an import from anywhere else would
    # let the run pass without the hash-pinned peer.
    location = Path(zenoh.__file__).resolve()
    if Path(sys.prefix).resolve() not in location.parents:
        print(f"[zenoh-listener] fail: zenoh imported from {location}, not from {sys.prefix}", flush=True)
        return 1
    session = zenoh.open(config)
    received: list[tuple] = []
    # A sample is delivered by a remote peer, so the peers the session holds when one arrives are
    # the peers that sent it. A peer that connects, publishes and leaves between two polls is
    # still counted, because the delivery itself records it.
    most = 0
    seen = False
    # The delivery callback runs on Zenoh's thread while the loop below polls on this one, and each
    # updates `most` from a value it read earlier, so an unlocked store from one could undo the
    # other's. One lock covers every read-modify-write of the count.
    lock = threading.Lock()
    last_delivery = time.monotonic()

    def note(peers: int) -> None:
        nonlocal most, seen
        with lock:
            most, seen = max(most, peers), seen or peers > 0

    def on_sample(sample: zenoh.Sample) -> None:
        attachment = sample.attachment
        nonlocal last_delivery
        row = (str(sample.key_expr), bytes(sample.payload), b"" if attachment is None else bytes(attachment))
        if form == "digest":
            row = digested(*row)
        with lock:
            received.append(row)
            last_delivery = time.monotonic()
        # A delivery is evidence of a remote peer even when no snapshot shows one.
        note(max(len(session.info.peers_zid()), 1))

    subscriber = session.declare_subscriber(key, on_sample)
    print(READY, flush=True)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        note(len(session.info.peers_zid()))
        with lock:
            delivered, quiet = len(received), time.monotonic() - last_delivery
        # The connector keeps its link open until the peer closes it, so waiting for the peer to
        # disconnect first would wait out the whole deadline. Once every expected sample has arrived
        # and none has followed for the settle time, the session is closed from this side.
        if delivered >= expected and quiet >= SETTLE_SECONDS:
            break
        time.sleep(0.2)
    with lock:
        # A record with samples and no peer cannot be honest: floor the count at one.
        count = max(most, 1 if received else 0)
        samples = list(received)
    writer = digest_receipt_text if form == "digest" else receipt_text
    receipt.write_text(writer(listen, count, samples), encoding="utf-8")
    print(f"[zenoh-listener] received={len(samples)} remote-peers={count}", flush=True)
    # The handle is held to here so the subscriber stays declared for the whole collection.
    subscriber.undeclare()
    session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve(int(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5], int(sys.argv[6])))
