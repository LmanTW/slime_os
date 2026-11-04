"""A stock eclipse-zenoh 1.0.0 peer that replays a frame store to a listening peer.

Run by `scripts/check/check-foxglove-bridge.py` with the interpreter of the hash-pinned environment that
`zenoh_listener_peer.ensure_venv` builds:

    python zenoh_replayer.py PORT STORE KEY OTHER_KEY PERIOD_MS

It connects to tcp/127.0.0.1:PORT with multicast scouting off and waits for the peer. It then puts one
sample on OTHER_KEY, and every frame of the `contracts/frame-store/v1` file STORE on KEY in index order,
PERIOD_MS apart. Frame i carries the rmw_zenoh attachment of sequence i + 1, its log time and the demo GID.
The store is read with the frame-store exam's own decoder, never the bridge's. It prints one line at the end:

    [zenoh-replayer] sent frames=N other=1
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import frame_store_exam as frames  # noqa: E402
import zenoh_wire  # noqa: E402

GID = bytes(range(0xE0, 0xF0))
PEER_SECONDS = 30
# The time a peer takes, once connected, to receive the other side's subscriber declaration.
DECLARE_SECONDS = 2
DRAIN_SECONDS = 2


def main() -> int:
    import zenoh

    port, store_path, key, other_key, period_ms = int(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5])
    location = Path(zenoh.__file__).resolve()
    if Path(sys.prefix).resolve() not in location.parents:
        print(f"[zenoh-replayer] fail: zenoh imported from {location}, not from {sys.prefix}", flush=True)
        return 1
    data = store_path.read_bytes()
    reading = frames.decode(data)
    config = zenoh.Config()
    config.insert_json5("mode", json.dumps("peer"))
    config.insert_json5("connect/endpoints", json.dumps([f"tcp/127.0.0.1:{port}"]))
    config.insert_json5("scouting/multicast/enabled", "false")
    config.insert_json5("scouting/gossip/enabled", "false")
    session = zenoh.open(config)
    deadline = time.monotonic() + PEER_SECONDS
    while not session.info.peers_zid():
        if time.monotonic() > deadline:
            print("[zenoh-replayer] fail: no peer", flush=True)
            return 1
        time.sleep(0.1)
    time.sleep(DECLARE_SECONDS)
    session.put(other_key, b"not a frame", attachment=zenoh_wire.attachment(1, 0, GID))
    time.sleep(period_ms / 1000)
    for index, frame in enumerate(reading.frames):
        payload = data[frame.offset : frame.offset + frame.length]
        session.put(key, payload, attachment=zenoh_wire.attachment(index + 1, frame.log_time, GID))
        time.sleep(period_ms / 1000)
    time.sleep(DRAIN_SECONDS)
    session.close()
    print(f"[zenoh-replayer] sent frames={len(reading.frames)} other=1", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
