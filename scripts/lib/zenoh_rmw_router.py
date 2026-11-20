"""Bytes `rmw_zenohd` wrote to a Slime-side client during a handshake, captured twice.

Provenance, one x86_64 Linux host, two runs:

* router: `rmw_zenohd` of `rmw_zenoh_cpp` 0.6.10-r1 (ROS 2 Kilted), built by nix-ros-overlay with the pins of
  `zenoh_rmw_peer`, on its default configuration, listening on `tcp/127.0.0.1:7447`. `AMENT_PREFIX_PATH` named the
  ROS environment, which the router needs to start.
* client: a host script on `zenoh_wire` that opened one TCP connection, wrote an INIT_SYN with the client form of
  the packed byte (`whatami` 2) and a ZID of the bytes 1 to 16, announced a 512-byte batch, read the INIT_ACK,
  wrote an OPEN_SYN of a 10 s lease and initial sequence number 7 that echoes the cookie, and read the OPEN_ACK.
  The batch bodies are without the 2-byte stream length. The router wrote nothing else in the 2 s after the OPEN_ACK.

The router answers the client form with an INIT_ACK of `whatami` 0, a 16-byte ZID of its own, the resolution `0x0a`,
a batch of 512 and a cookie of 49 bytes, and no extension. Its OPEN_ACK carries a lease of 60 s and a 4-byte
initial sequence number. The ZID, the cookie and the sequence number differ between runs. The OPEN_SYN is what this
side wrote, so it is not a fixture of the router.

What this does not cover: a router that forwards a sample, a router's liveliness tokens, a router with a
configuration other than its default, and a client that announces a batch other than 512.
"""

CLIENT_ZID = bytes(range(1, 17))
CLIENT_BATCH = 512
CLIENT_LEASE_MS = 10_000
CLIENT_INITIAL_SN = 7
ROUTER_LEASE_MS = 60_000

# (name, INIT_SYN the client wrote, INIT_ACK of the router, OPEN_ACK of the router)
RUNS = (
    (
        "router-1",
        "4109f20102030405060708090a0b0c0d0e0f100a0002",
        "6109f0f5154ece1bde0ff777f15eb6517bc9ef0a000231308eae4c765b6a3d3db2cc15a261c74f7366c7352fac7370ca76f9d6f4e851781f1835f9b0f8854fcce6536506f2da1534",
        "623cc0fae13b",
    ),
    (
        "router-2",
        "4109f20102030405060708090a0b0c0d0e0f100a0002",
        "6109f06aa9af8e8ed4d003356f94bfcf4751d30a00023130baa055950ce6d17f4273deae9d0bf2ce08b093dffd691a4789686a0b20ee05de59ed86b56d36d33c3c786e36f3d301fe",
        "623cddeed030",
    ),
)
