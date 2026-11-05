"""The Foxglove bridge exam: what `tools/foxglove-bridge/bridge.py` must show an independent client.

Work items 01a1a43b-cb66-7d19-8b91-12240b7e1e74, and 01a1a8cb-a7a0-7dc1-bb24-951d0db30d1e, which has the
bridge subscribe the store's exact data key so the guest's Profile 0 session accepts it. Nothing here imports the bridge, the Foxglove SDK or a
WebSocket library; the client is `foxglove_ws`. The exam owns five judgements:

* the pins: the bridge's committed pin file names exactly the wheels below, one line per host;
* the session: the handshake, server info, one channel advertisement equal to the store's, and after the
  client subscribes, exactly one Message Data per frame, in order, with the frame's payload and log time;
* the bridge's lines: one ready line naming both endpoints and one stop line with the forwarded count, and
  nothing between them, so the replayer's other-key sample reached the bridge as no line and no client
  as no message;
* the refusal: started with one wheel's hash changed, the bridge exits nonzero with its refusal line and
  calls listen() on no socket, as the checker's `listen_log` shim records over its whole process tree in
  `contracts/listen-record/v1` records, read only through that contract's decoder;
* the listeners: on an honest run the shim records the bridge listening on both of its ports, so the
  refusal's empty record is the shim's observation and not its absence;
* the client itself, against a local stand-in server that sends an honest stream in every frame form a
  server may use, and a corrupted one.

Each judgement is trusted only after it accepts the honest synthetic evidence in `controls()` and refuses
every corruption of it. The bridge's lines are exactly, each on stdout:

    foxglove-bridge: ready zenoh=tcp/127.0.0.1:P websocket=ws://127.0.0.1:Q
    foxglove-bridge: stopped forwarded=F

and a refused start's last stderr line is `foxglove-bridge: refused dependency`.
"""

from __future__ import annotations

import copy
import json
import re
import socket
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import shutil

import foxglove_ws as ws
import zutai_cli
from harness import ROOT

ITEM = "01a1a43b-cb66-7d19-8b91-12240b7e1e74"
BRIDGE = ROOT / "tools" / "foxglove-bridge" / "bridge.py"
PINS = ROOT / "tools" / "foxglove-bridge" / "pins.txt"
RECORD_SCHEMA = ROOT / "contracts" / "listen-record" / "v1" / "schema.zt"
SCRATCH = ROOT / "build" / "foxglove-bridge-exam"
RECORD_FILE = re.compile(r"listen-\d+-\d+\.zti")
DOMAIN_KEYS = "0/**"
OTHER_KEY = "0/slime_exam/other/std_msgs::msg::dds_::String_/RIHS01_" + "0" * 64
LINUX = 'sys_platform == "linux" and platform_machine == "x86_64"'
DARWIN = 'sys_platform == "darwin" and platform_machine == "arm64"'
# The wheels the bridge may install, by host: (name, version, environment marker, SHA-256).
WHEELS = (
    ("eclipse-zenoh", "1.0.0", LINUX, "1763912951ecd2a3706f668faf0541245387096b37a4fefb73af7848dadd46ff"),
    ("eclipse-zenoh", "1.0.0", DARWIN, "08b0871119786a1432864af8aa0cf42019a4b7bc8cfe725588cbc15f7d007f90"),
    ("foxglove-sdk", "0.30.3", LINUX, "063c5331549d6f8987f0d1cb060b494383c11247bb853b44519aa83bd84ef1fd"),
    ("foxglove-sdk", "0.30.3", DARWIN, "f4934a2f0012cfd2bbcf20c52d72549c514df135f002a89f1291e1582e08e643"),
)
PIN_LINE = re.compile(r"^([a-z0-9-]+)==([0-9.]+) ; (.+?) --hash=sha256:([0-9a-f]{64})$")
READY = re.compile(r"foxglove-bridge: ready zenoh=tcp/127\.0\.0\.1:(\d+) websocket=ws://127\.0\.0\.1:(\d+)")
STOPPED = re.compile(r"foxglove-bridge: stopped forwarded=(\d+)")
REFUSED = "foxglove-bridge: refused dependency"
LINE_PREFIX = "foxglove-bridge: "
SUBSCRIPTION = 1
# One replayed frame every this many milliseconds: far below the 500 ms the guest uses, and enough for a
# loopback client to read each message before the next.
REPLAY_PERIOD_MS = 50
READY_SECONDS = 300
SETTLE_SECONDS = 2


class ExamError(Exception):
    """The evidence does not meet the exam."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise ExamError(reason)


@dataclass(frozen=True)
class Store:
    """What the client must see: the store's channel facts and its frames as (log time, payload)."""

    topic: str
    type_name: str
    schema: str
    frames: tuple[tuple[int, bytes], ...]


# ------------------------------------------------------------------------------------------- pins


def pin_text() -> str:
    """The pin file the exam expects, one line per wheel."""
    return "".join(f"{name}=={version} ; {marker} --hash=sha256:{digest}\n" for name, version, marker, digest in WHEELS)


def judge_pins(text: str) -> None:
    """The bridge's pin file names exactly the exam's wheels. Comments and blank lines are ignored."""
    found = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = PIN_LINE.fullmatch(stripped)
        _need(match is not None, f"a pin line the exam does not read: {stripped[:120]!r}")
        found.append(match.groups())
    _need(sorted(found) == sorted(WHEELS), f"the pin file names {sorted(found)}, the exam pins {sorted(WHEELS)}")


def altered_pins(text: str, marker: str) -> str:
    """The pin file with the eclipse-zenoh hash for `marker`'s host changed in its first digit."""
    lines, changed = [], 0
    for line in text.splitlines(keepends=True):
        match = PIN_LINE.fullmatch(line.strip())
        if match and match.group(1) == "eclipse-zenoh" and match.group(3) == marker:
            digest = match.group(4)
            line = line.replace(digest, ("1" if digest[0] == "0" else "0") + digest[1:])
            changed += 1
        lines.append(line)
    _need(changed == 1, f"{changed} eclipse-zenoh pins for this host, the exam changes one")
    return "".join(lines)


def host_marker(platform: str, machine: str) -> str:
    markers = {("linux", "x86_64"): LINUX, ("darwin", "arm64"): DARWIN}
    _need((platform, machine) in markers, f"no wheel is pinned for {platform} {machine}")
    return markers[(platform, machine)]


# ----------------------------------------------------------------------------------------- session


def judge_session(before: list[ws.Message], after: list[ws.Message], want: Store) -> int:
    """The messages before the client subscribed, and after. Returns the channel id."""
    _need(bool(before), "the server sent nothing before the client subscribed")
    info = before[0].json()
    _need(info["op"] == "serverInfo", f"the first message is {info['op']!r}, not serverInfo")
    adverts = []
    for message in before[1:]:
        value = message.json()
        _need(value["op"] == "advertise", f"a {value['op']!r} message before the subscription, only one advertise follows server info")
        adverts.append(value)
    _need(len(adverts) == 1, f"{len(adverts)} advertise messages, the bridge advertises once")
    channels = adverts[0].get("channels")
    _need(isinstance(channels, list) and len(channels) == 1, "the advertisement does not carry exactly one channel")
    channel = channels[0]
    _need(isinstance(channel, dict), "a channel that is not an object")
    expected = {"topic": want.topic, "encoding": "cdr", "schemaName": want.type_name, "schemaEncoding": "ros2msg", "schema": want.schema}
    for field, value in expected.items():
        _need(channel.get(field) == value, f"the channel's {field} is {str(channel.get(field))[:80]!r}, the store's is {value[:80]!r}")
    identity = channel.get("id")
    _need(isinstance(identity, int) and not isinstance(identity, bool) and identity >= 0, "the channel has no integer id")
    _need(len(after) == len(want.frames), f"{len(after)} messages after the subscription, the store has {len(want.frames)} frames")
    for index, (message, (log_time, payload)) in enumerate(zip(after, want.frames, strict=True)):
        try:
            subscription, got_time, got = ws.message_data(message)
        except ws.ProtocolError as error:
            raise ExamError(f"message {index}: {error}") from error
        _need(subscription == SUBSCRIPTION, f"message {index} is on subscription {subscription}, the client subscribed {SUBSCRIPTION}")
        _need(got == payload, f"message {index}'s payload is not frame {index}'s")
        _need(got_time == log_time, f"message {index}'s log time is {got_time}, frame {index}'s is {log_time}")
    return identity


def honest_session(want: Store, channel: int = 3) -> tuple[list[ws.Message], list[ws.Message]]:
    info = ws.Message(text=json.dumps({"op": "serverInfo", "name": "", "capabilities": [], "metadata": {}, "sessionId": "1"}))
    advert = ws.Message(text=json.dumps({"op": "advertise", "channels": [{
        "id": channel, "topic": want.topic, "encoding": "cdr", "schemaName": want.type_name,
        "schemaEncoding": "ros2msg", "schema": want.schema,
    }]}))
    after = [ws.Message(data=ws.MESSAGE_DATA_HEADER.pack(ws.MESSAGE_DATA, SUBSCRIPTION, log_time) + payload) for log_time, payload in want.frames]
    return [info, advert], after


def _data(subscription: int, log_time: int, payload: bytes, opcode: int = ws.MESSAGE_DATA) -> ws.Message:
    return ws.Message(data=ws.MESSAGE_DATA_HEADER.pack(opcode, subscription, log_time) + payload)


def session_mutations(want: Store) -> list[tuple[str, Callable[[list, list], tuple[list, list]]]]:
    def channel(**change: object) -> Callable[[list, list], tuple[list, list]]:
        def apply(before: list, after: list) -> tuple[list, list]:
            value = json.loads(before[1].text)
            value["channels"][0].update(change)
            return [before[0], ws.Message(text=json.dumps(value)), *before[2:]], after
        return apply

    def drop_field(name: str) -> Callable[[list, list], tuple[list, list]]:
        def apply(before: list, after: list) -> tuple[list, list]:
            value = json.loads(before[1].text)
            del value["channels"][0][name]
            return [before[0], ws.Message(text=json.dumps(value)), *before[2:]], after
        return apply

    def at(index: int, message: Callable[[int, bytes], ws.Message]) -> Callable[[list, list], tuple[list, list]]:
        def apply(before: list, after: list) -> tuple[list, list]:
            log_time, payload = want.frames[index]
            return before, [*after[:index], message(log_time, payload), *after[index + 1 :]]
        return apply

    flipped = bytearray(want.frames[1][1])
    flipped[len(flipped) // 2] ^= 1
    schema = want.schema
    return [
        ("no server info", lambda b, a: (b[1:], a)),
        ("advertise before server info", lambda b, a: ([b[1], b[0]], a)),
        ("no advertisement", lambda b, a: (b[:1], a)),
        ("two advertisements", lambda b, a: ([*b, b[1]], a)),
        ("a status message", lambda b, a: ([*b, ws.Message(text='{"op":"status","level":0,"message":"x"}')], a)),
        ("a binary message before the subscription", lambda b, a: ([*b, a[0]], a)),
        ("a text message that is not JSON", lambda b, a: ([*b, ws.Message(text="advertise")], a)),
        ("two channels", lambda b, a: ([b[0], ws.Message(text=b[1].text.replace('"channels": [', '"channels": [{"id": 9}, ', 1))], a)),
        ("another topic", channel(topic=want.topic + "x")),
        ("json encoding", channel(encoding="json")),
        ("another schema name", channel(schemaName="sensor_msgs/msg/Image")),
        ("ros2idl schema encoding", channel(schemaEncoding="ros2idl")),
        ("a schema one byte short", channel(schema=schema[:-1])),
        ("a schema with a byte changed", channel(schema=("X" if schema[0] != "X" else "Y") + schema[1:])),
        ("no schema encoding", drop_field("schemaEncoding")),
        ("no channel id", drop_field("id")),
        ("a string channel id", channel(id="3")),
        ("the last frame missing", lambda b, a: (b, a[:-1])),
        ("the last frame twice", lambda b, a: (b, [*a, a[-1]])),
        ("the first two frames swapped", lambda b, a: (b, [a[1], a[0], *a[2:]])),
        ("one payload bit flipped", at(1, lambda t, p: _data(SUBSCRIPTION, t, bytes(flipped)))),
        ("a payload one byte short", at(1, lambda t, p: _data(SUBSCRIPTION, t, p[:-1]))),
        ("a log time one off", at(0, lambda t, p: _data(SUBSCRIPTION, t + 1, p))),
        ("another subscription id", at(0, lambda t, p: _data(SUBSCRIPTION + 1, t, p))),
        ("a Time message for a frame", at(0, lambda t, p: _data(SUBSCRIPTION, t, p, opcode=2))),
        ("a JSON message for a frame", at(0, lambda t, p: ws.Message(text='{"op":"status"}'))),
        ("a binary message shorter than its header", at(0, lambda t, p: ws.Message(data=b"\x01\x01\x00\x00"))),
    ]


# ------------------------------------------------------------------------------------------- lines


def judge_lines(stdout: str, returncode: int, zenoh_port: int, websocket_port: int, forwarded: int) -> None:
    """The bridge's own lines: exactly ready, then stopped with the forwarded count, and exit 0.

    The replayer also puts one sample on another key. A bridge subscribed to the store's key alone never
    receives it, so any line between ready and stopped, a drop line included, refuses the run."""
    lines = [line.strip() for line in stdout.splitlines() if line.strip().startswith(LINE_PREFIX)]
    _need(len(lines) == 2, f"the bridge printed {len(lines)} lines, it prints exactly ready and stopped")
    ready = READY.fullmatch(lines[0])
    _need(ready is not None, f"the bridge's first line is not its ready line: {lines[0][:120]!r}")
    _need((int(ready.group(1)), int(ready.group(2))) == (zenoh_port, websocket_port), f"the ready line names ports {ready.groups()}, the exam gave {zenoh_port} and {websocket_port}")
    stopped = STOPPED.fullmatch(lines[1])
    _need(stopped is not None, f"the bridge's last line is not its stop line: {lines[1][:120]!r}")
    _need(int(stopped.group(1)) == forwarded, f"the stop line counts {stopped.group(1)} forwarded, the run forwarded {forwarded}")
    _need(returncode == 0, f"the bridge exited {returncode} after SIGTERM, not 0")


def honest_stdout(zenoh_port: int, websocket_port: int, forwarded: int) -> str:
    return (
        f"{LINE_PREFIX}ready zenoh=tcp/127.0.0.1:{zenoh_port} websocket=ws://127.0.0.1:{websocket_port}\n"
        "zenoh: an unrelated library line\n"
        f"{LINE_PREFIX}stopped forwarded={forwarded}\n"
    )


def line_mutations(z: int, w: int, n: int) -> list[tuple[str, Callable[[str], str]]]:
    ready = f"{LINE_PREFIX}ready zenoh=tcp/127.0.0.1:{z} websocket=ws://127.0.0.1:{w}"
    stop = f"{LINE_PREFIX}stopped forwarded={n}"
    drop = f"{LINE_PREFIX}dropped key={OTHER_KEY} total=1"
    return [
        ("no ready line", lambda s: s.replace(ready + "\n", "")),
        ("another zenoh port", lambda s: s.replace(f":{z} ", f":{z + 1} ")),
        ("another websocket port", lambda s: s.replace(f"127.0.0.1:{w}\n", f"127.0.0.1:{w + 1}\n")),
        ("a wildcard zenoh address", lambda s: s.replace("tcp/127.0.0.1", "tcp/0.0.0.0")),
        ("a drop line for the other key", lambda s: s.replace(stop, drop + "\n" + stop)),
        ("a stop line that counts a drop", lambda s: s.replace(stop, stop + " dropped=1")),
        ("no stop line", lambda s: s.replace(stop + "\n", "")),
        ("one frame fewer forwarded", lambda s: s.replace(f"forwarded={n}", f"forwarded={n - 1}")),
        ("the stop line before the ready line", lambda s: s.replace(ready + "\n", "").replace(stop, stop + "\n" + ready)),
        ("an extra bridge line", lambda s: s.replace(stop, f"{LINE_PREFIX}forwarded one\n" + stop)),
    ]


# ----------------------------------------------------------------------------------------- refusal


def read_record(path: Path) -> tuple[int, int, bool]:
    """Decode one listen record through contracts/listen-record/v1, then read its values."""
    scratch = SCRATCH / "decoder"
    scratch.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(RECORD_SCHEMA, scratch / "schema.zt")
    (scratch / "decode.zt").write_text(
        's ::= import "schema.zt"; env ::= import stdlib.env; load ::= import stdlib.load; '
        "main :: { env : Env; load : Load; } -> Validation DecodeIssue s.Record ! { * env.GetEffects; * load.ZtiEffects; } "
        '= caps => [ path := env.get caps.env "SLIME_RECORD_PATH" ?? ""; s.decodeRecord (load.zti caps.load path) ]; main\n',
        encoding="utf-8",
    )
    try:
        decoded = zutai_cli.evaluate("run", scratch / "decode.zt", input_path=path, env_var="SLIME_RECORD_PATH")
    except zutai_cli.ZutaiError as error:
        raise ExamError(f"a listen record does not decode: {error}") from error
    _need(decoded.startswith("#valid"), f"a listen record is refused by its contract: {decoded[:160]}")
    pid = re.search(r"\bpid = (\d+)", decoded)
    port = re.search(r"\bport = (-?\d+)", decoded)
    succeeded = re.search(r"\bsucceeded = (true|false)", decoded)
    _need(pid is not None and port is not None and succeeded is not None, "the decoded listen record has no pid, port or succeeded")
    return int(pid.group(1)), int(port.group(1)), succeeded.group(1) == "true"


def read_records(directory: Path) -> list[tuple[int, int, bool]]:
    """Every record the shim wrote in `directory`. A file the shim does not name is refused."""
    records = []
    for path in sorted(directory.iterdir()) if directory.is_dir() else []:
        _need(path.is_file() and RECORD_FILE.fullmatch(path.name) is not None, f"a file the listen shim does not write: {path.name!r}")
        records.append(read_record(path))
    return records


def judge_listeners(records: list[tuple[int, int, bool]], zenoh_port: int, websocket_port: int) -> None:
    """An honest run: the shim saw the bridge listen on both of its ports, so it reaches the bridge's servers."""
    listened = {port for _pid, port, ok in records if ok}
    for name, port in (("zenoh", zenoh_port), ("websocket", websocket_port)):
        _need(port in listened, f"the shim recorded no listener on the {name} port {port}, so it does not observe the bridge")


def judge_refusal(returncode: int | None, stderr: str, records: list[tuple[int, int, bool]]) -> None:
    """A refused start. `records` are the listen() calls the shim saw over the bridge's whole process tree;
    a refusal opens no server, so any call, failed or not, on any port, refuses the start."""
    _need(not records, f"the refused bridge called listen() {len(records)} time(s), on port(s) {sorted({port for _pid, port, _ok in records})}")
    _need(returncode is not None, "the bridge with a changed pin did not exit")
    _need(returncode != 0, "the bridge with a changed pin exited 0")
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    _need(bool(lines) and lines[-1] == REFUSED, f"the refused bridge's last stderr line is {lines[-1][:120] if lines else ''!r}, not {REFUSED!r}")


REFUSAL_CASES = (
    ("an honest refusal", (1, "pip: hash mismatch\n" + REFUSED + "\n", []), True),
    ("an honest refusal with exit 2", (2, REFUSED + "\n\n", []), True),
    ("exit 0", (0, REFUSED + "\n", []), False),
    ("no exit", (None, REFUSED + "\n", []), False),
    ("no refusal line", (1, "pip: hash mismatch\n", []), False),
    ("the refusal line not last", (1, REFUSED + "\nTraceback\n", []), False),
    ("a listener on the zenoh port", (1, REFUSED + "\n", [(10, 17448, True)]), False),
    ("a failed listen on the websocket port", (1, REFUSED + "\n", [(10, 18765, False)]), False),
    ("a listener on another port", (1, REFUSED + "\n", [(11, 40000, True)]), False),
)

def record_text(pid: int, port: int, succeeded: bool, version: int = 1, extra: str = "", succeeded_text: str | None = None) -> str:
    """A listen record as the shim writes it."""
    value = succeeded_text if succeeded_text is not None else ("true" if succeeded else "false")
    return f"{{\n  formatVersion = {version};\n  pid = {pid};\n  port = {port};\n  succeeded = {value};\n{extra}}}\n"


Z, W = 17448, 18765
# (label, the files the shim's directory holds, accepted as an honest run's listeners).
LISTENER_CASES = (
    ("both ports, from two processes", {"listen-3-1.zti": record_text(3, Z, True), "listen-4-1.zti": record_text(4, W, True)}, True),
    ("both ports and a socket with no address", {"listen-3-1.zti": record_text(3, Z, True), "listen-3-2.zti": record_text(3, -1, True), "listen-3-3.zti": record_text(3, W, True)}, True),
    ("no records", {}, False),
    ("only the zenoh port", {"listen-3-1.zti": record_text(3, Z, True)}, False),
    ("only the websocket port", {"listen-3-1.zti": record_text(3, W, True)}, False),
    ("the zenoh listen failed", {"listen-3-1.zti": record_text(3, Z, False), "listen-3-2.zti": record_text(3, W, True)}, False),
    ("a file the shim does not name", {"listen-3-1.zti": record_text(3, Z, True), "listen-3-2.zti": record_text(3, W, True), "notes.txt": "x"}, False),
    ("format version 2", {"listen-3-1.zti": record_text(3, Z, True, version=2), "listen-3-2.zti": record_text(3, W, True)}, False),
    ("a port above 65535", {"listen-3-1.zti": record_text(3, 70000, True), "listen-3-2.zti": record_text(3, W, True)}, False),
    ("a port below -1", {"listen-3-1.zti": record_text(3, -2, True), "listen-3-2.zti": record_text(3, Z, True), "listen-3-3.zti": record_text(3, W, True)}, False),
    ("pid 0", {"listen-0-1.zti": record_text(0, Z, True), "listen-3-2.zti": record_text(3, W, True)}, False),
    ("succeeded as an integer", {"listen-3-1.zti": record_text(3, Z, True, succeeded_text="1"), "listen-3-2.zti": record_text(3, W, True)}, False),
    ("a field the contract does not name", {"listen-3-1.zti": record_text(3, Z, True, extra="  note = \"x\";\n"), "listen-3-2.zti": record_text(3, W, True)}, False),
    ("a record that is not one", {"listen-3-1.zti": "listen pid=3 port=17448 ok=1\n", "listen-3-2.zti": record_text(3, W, True)}, False),
)


def write_records(directory: Path, files: dict[str, str]) -> Path:
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    for name, text in files.items():
        (directory / name).write_text(text, encoding="utf-8")
    return directory


# ------------------------------------------------------------------------------------------ client


def _server_frame(opcode: int, payload: bytes, fin: bool = True, mask: bool = False, rsv: int = 0, length_form: str = "") -> bytes:
    """One server frame. `length_form` forces the 16- or 64-bit length form instead of the shortest."""
    length = len(payload)
    first = (0x80 if fin else 0) | rsv | opcode
    masked = 0x80 if mask else 0
    form = length_form or ("7" if length < 126 else "16" if length < 1 << 16 else "64")
    if form == "7":
        header = bytes([first, masked | length])
    elif form == "16":
        header = bytes([first, masked | 126]) + struct.pack("!H", length)
    else:
        header = bytes([first, masked | 127]) + struct.pack("!Q", length)
    return header + (b"\x00\x00\x00\x00" if mask else b"") + payload


def stream(before: list[ws.Message], after: list[ws.Message], form: str = "plain") -> bytes:
    """An honest server's bytes for the messages, in one of the frame forms a server may use."""
    out = bytearray()
    for index, message in enumerate([*before, *after]):
        opcode = ws.OP_TEXT if message.text is not None else ws.OP_BINARY
        payload = message.text.encode() if message.text is not None else message.data
        if form == "fragmented" and len(payload) > 3:
            out += _server_frame(opcode, payload[:2], fin=False)
            out += _server_frame(ws.OP_PING, b"p")
            out += _server_frame(ws.OP_CONTINUATION, payload[2:-1], fin=False)
            out += _server_frame(ws.OP_CONTINUATION, payload[-1:])
        else:
            out += _server_frame(opcode, payload)
        if form == "pings" and index % 2:
            out += _server_frame(ws.OP_PING, b"")
    return bytes(out)


def stream_mutations(before: list[ws.Message], after: list[ws.Message]) -> list[tuple[str, bytes]]:
    text = before[0].text.encode()
    honest = stream(before, after)
    return [
        ("a masked server frame", _server_frame(ws.OP_TEXT, text, mask=True) + honest),
        ("a reserved bit", _server_frame(ws.OP_TEXT, text, rsv=0x40) + honest),
        ("a 16-bit length that fits seven bits", _server_frame(ws.OP_TEXT, text[:100], length_form="16") + honest),
        ("a 64-bit length that fits sixteen bits", _server_frame(ws.OP_BINARY, bytes(300), length_form="64") + honest),
        ("a reserved data opcode", _server_frame(0x3, text) + honest),
        ("a reserved control opcode", _server_frame(0xB, b"") + honest),
        ("a fragmented ping", _server_frame(ws.OP_PING, b"p", fin=False) + honest),
        ("a ping of 126 bytes", _server_frame(ws.OP_PING, bytes(126)) + honest),
        ("a continuation outside a message", _server_frame(ws.OP_CONTINUATION, text) + honest),
        ("a new message inside a fragmented one", _server_frame(ws.OP_TEXT, text[:2], fin=False) + honest),
        ("a text message that is not UTF-8", _server_frame(ws.OP_TEXT, b"\xff\xfe") + honest),
    ]


HANDSHAKE_MUTATIONS = (
    ("status 200", lambda r: r.replace("101 Switching Protocols", "200 OK")),
    ("no upgrade header", lambda r: r.replace("Upgrade: websocket\r\n", "")),
    ("an upgrade to h2c", lambda r: r.replace("Upgrade: websocket", "Upgrade: h2c")),
    ("no Connection upgrade", lambda r: r.replace("Connection: Upgrade", "Connection: keep-alive")),
    ("a wrong accept value", lambda r: re.sub(r"Sec-WebSocket-Accept: \S+", "Sec-WebSocket-Accept: AAAA", r)),
    ("the v1 subprotocol", lambda r: r.replace(ws.SUBPROTOCOL, "foxglove.websocket.v1")),
    ("no subprotocol", lambda r: r.replace(f"Sec-WebSocket-Protocol: {ws.SUBPROTOCOL}\r\n", "")),
    ("two subprotocol headers", lambda r: r.replace(f"Sec-WebSocket-Protocol: {ws.SUBPROTOCOL}\r\n", f"Sec-WebSocket-Protocol: {ws.SUBPROTOCOL}\r\nSec-WebSocket-Protocol: {ws.SUBPROTOCOL}\r\n")),
)


def _response(key: str) -> str:
    return (
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {ws.accept_value(key)}\r\nSec-WebSocket-Protocol: {ws.SUBPROTOCOL}\r\n\r\n"
    )


def stand_in(body: bytes, handshake: Callable[[str], str] = lambda r: r,
             later: tuple[tuple[float, bytes], ...] = ()) -> tuple[int, threading.Thread]:
    """A one-connection server on the loopback that answers the handshake and then sends `body`, then each
    of `later`'s bytes after its delay in seconds."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            data = b""
            while b"\r\n\r\n" not in data:
                data += connection.recv(4096)
            key = re.search(rb"Sec-WebSocket-Key: (\S+)\r\n", data).group(1).decode()
            connection.sendall(handshake(_response(key)).encode() + body)
            for delay, data in later:
                time.sleep(delay)
                connection.sendall(data)
            time.sleep(0.3)
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread


def collect(port: int, count: int) -> list[ws.Message]:
    """Every message a server sends on `port`, until `count` or it falls silent."""
    client = ws.Client("127.0.0.1", port, timeout=5)
    out = []
    deadline = time.monotonic() + 3
    while len(out) < count and (message := client.receive(deadline)) is not None:
        out.append(message)
    client.close()
    return out


# ---------------------------------------------------------------------------------------- controls


def control_store() -> Store:
    payloads = (bytes(range(256)) * 4, bytes((i * 7) % 251 for i in range(70_000)), b"\x01")
    return Store(
        "/velodyne_points", "sensor_msgs/msg/PointCloud2", "uint8 x\nfloat32[] y\n",
        tuple((1_700_000_000_000_000_000 + i * 100_000_000, p) for i, p in enumerate(payloads)),
    )


# The counts the controls produce, pinned so a judge that quietly loses a case is seen.
PINNED_ACCEPTED = 12
PINNED_REFUSED = 81


def controls() -> tuple[int, int]:
    want = control_store()
    accepted = refused = 0

    def accept(label: str, check: Callable[[], object]) -> None:
        nonlocal accepted
        try:
            check()
        except (ExamError, ws.ProtocolError) as error:
            raise ExamError(f"control: refused {label}: {error}") from error
        accepted += 1

    def refuse(label: str, check: Callable[[], object]) -> None:
        nonlocal refused
        try:
            check()
        except (ExamError, ws.ProtocolError):
            refused += 1
            return
        raise ExamError(f"control: accepted {label}")

    accept("the exam's pin file", lambda: judge_pins(pin_text()))
    accept("the pin file with a comment", lambda: judge_pins("# pins\n\n" + pin_text()))
    refuse("a pin file missing a wheel", lambda: judge_pins("".join(pin_text().splitlines(keepends=True)[1:])))
    refuse("a pin file with an extra wheel", lambda: judge_pins(pin_text() + pin_text().splitlines(keepends=True)[0].replace("1.0.0", "1.0.1")))
    refuse("a pin with another hash", lambda: judge_pins(altered_pins(pin_text(), DARWIN)))
    refuse("a pin without a marker", lambda: judge_pins(pin_text().replace(" ; " + LINUX, "", 1)))
    refuse("a pin to another version", lambda: judge_pins(pin_text().replace("0.30.3", "0.30.4")))
    accept("the altered pin file has one changed hash", lambda: _need(
        sum(a != b for a, b in zip(pin_text(), altered_pins(pin_text(), LINUX), strict=True)) == 1, "not one character changed"))

    before, after = honest_session(want)
    accept("an honest session", lambda: judge_session(before, after, want))
    for label, change in session_mutations(want):
        b, a = change(copy.copy(before), copy.copy(after))
        refuse(label, lambda b=b, a=a: judge_session(b, a, want))

    z, w, n = 17448, 18765, len(want.frames)
    accept("honest bridge lines", lambda: judge_lines(honest_stdout(z, w, n), 0, z, w, n))
    refuse("an exit of 1 after SIGTERM", lambda: judge_lines(honest_stdout(z, w, n), 1, z, w, n))
    for label, change in line_mutations(z, w, n):
        refuse(label, lambda change=change: judge_lines(change(honest_stdout(z, w, n)), 0, z, w, n))

    for label, args, honest in REFUSAL_CASES:
        (accept if honest else refuse)(label, lambda args=args: judge_refusal(*args))
    for index, (label, files, honest) in enumerate(LISTENER_CASES):
        directory = write_records(SCRATCH / "listener-controls" / str(index), files)
        (accept if honest else refuse)(label, lambda directory=directory: judge_listeners(read_records(directory), Z, W))

    # The client against a stand-in server: every honest frame form yields the same messages, and each
    # corruption of the frames or the handshake is refused.
    expected = [*before, *after]
    for form in ("plain", "fragmented", "pings"):
        port, thread = stand_in(stream(before, after, form))
        got = collect(port, len(expected))
        thread.join(5)
        accept(f"the client on a {form} stream", lambda got=got: _need(got == expected, "the client read other messages than the server sent"))
    for label, body in stream_mutations(before, after):
        port, thread = stand_in(body)
        refuse(label, lambda port=port: collect(port, len(expected)))
        thread.join(5)
    for label, change in HANDSHAKE_MUTATIONS:
        port, thread = stand_in(stream(before, after), change)
        refuse(label, lambda port=port: collect(port, len(expected)))
        thread.join(5)

    _need(accepted == PINNED_ACCEPTED, f"the judges accept {accepted} honest variants, the exam pins {PINNED_ACCEPTED}")
    _need(refused == PINNED_REFUSED, f"the judges refuse {refused} corruptions, the exam pins {PINNED_REFUSED}")
    return accepted, refused


def store_of(data: bytes) -> Store:
    """The channel facts and frames of an encoded frame store, read by the frame-store exam's decoder."""
    import frame_store_exam as frames

    try:
        reading = frames.decode(data)
    except frames.Refused as refusal:
        raise ExamError(f"the exam's store is refused: {refusal}") from refusal
    return Store(
        reading.topic.decode(), reading.type_name.decode(), reading.schema.decode(),
        tuple((f.log_time, data[f.offset : f.offset + f.length]) for f in reading.frames),
    )

