#!/usr/bin/env python3
"""Destination-scoped network authority, native TCP, and bounded HTTP under seL4:
the data plane behind it.

Six arms share this checker: authority, external TCP, local TCP, client lifetime,
service fault, and driver reset. The authority arm boots `sel4-io-network`, whose
service is bound to a loopback that performs no link operation, and proves the
exact-destination boundary alone. The tcp arm boots `sel4-io-tcp`, whose
service is bound to the IO3 virtio-net driver behind a frame-level peer on
QEMU's UDP socket backend (`scripts/lib/link_peer.py`). Its packet ledger
independently proves the exact 4096-byte TCP echo, handshake and graceful
close, refused-port reset, absence of forbidden egress, and ARP/ICMP traffic.
The tcp-impairment arm boots `sel4-io-tcp-impairment` behind a scripted peer
(`scripts/lib/tcp_impairment_peer.py`) that reorders, drops, falls silent and
closes windows, and holds the wire to the declared loss, reordering,
retransmission and window bounds; it is selected explicitly, never by ``all``.
The tcp-listener arm boots `sel4-io-tcp-listener` behind a peer
(`scripts/lib/tcp_listener_peer.py`) that connects to one exact external
listener, sends SYNs it must ignore or refuse, and drives half-close,
simultaneous close and close with unread or unsent data; it is also explicit.
The tcp-options arm boots `sel4-io-tcp-options` behind a peer
(`scripts/lib/tcp_options_peer.py`) that holds acknowledgments, drops a
segment, answers keep-alives and falls mute so each binding's declared Nagle,
keep-alive, hop limit and idle timeout shows on the wire; it is also explicit.
The net arm boots `sel4-net`, the product shell beside the network stack, and
types seven Slisp lines into the resident shell one at a time: a spawned
numeric fetch judged against the controlled HTTP peer, and refusals that must
leave no forbidden packet on the captured wire; it is also explicit.
The HTTP arms instead use QEMU user networking and ordinary host TCP/UDP sockets;
public DNS/HTTP remains an explicitly requested smoke, never part of ``all``.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import tempfile
import socket
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple, NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from closure_image import ClosureImageError, build as build_closure_image  # noqa: E402
from harness import sha256_file  # noqa: E402

import link_peer  # noqa: E402
import tcp_impairment_peer  # noqa: E402
import tcp_listener_peer  # noqa: E402
import tcp_options_peer  # noqa: E402
import http_peer  # noqa: E402
import http_capture  # noqa: E402
import network_launch as launch  # noqa: E402
import devloop_observations  # noqa: E402
import zenoh_exchange  # noqa: E402
from sel4_gate_markers import match_marker_contract  # noqa: E402
from sel4_plane import run_plane  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PINS = ROOT / "sel4" / "pins.toml"
# The closure identity names the build's inputs and is re-resolved from repository
# state before building, so stale input is refused instead of silently changing the image.
CLOSURE = "sel4-io-network"
TCP_CLOSURE = "sel4-io-tcp"
IMAGE: Path | None = None
COMPOSITIONS = ROOT / "contracts" / "generation-manifest" / "v1" / "compositions"
FIXTURE = COMPOSITIONS / "sel4-io-network.zti"
TCP_FIXTURE = COMPOSITIONS / "sel4-io-tcp.zti"
IMPAIRMENT_CLOSURE = "sel4-io-tcp-impairment"
IMPAIRMENT_FIXTURE = COMPOSITIONS / "sel4-io-tcp-impairment.zti"
IMPAIRMENT_PROBE = "io-tcp-impairment-probe"
IMPAIRMENT_GENERATION = 161
LISTENER_CLOSURE = "sel4-io-tcp-listener"
LISTENER_FIXTURE = COMPOSITIONS / "sel4-io-tcp-listener.zti"
LISTENER_PROBE = "io-tcp-listener-probe"
LISTENER_HOLDER = "listener-session"
INTRUDER_HOLDER = "intruder-session"
LISTENER_GENERATION = 162
OPTIONS_CLOSURE = "sel4-io-tcp-options"
OPTIONS_FIXTURE = COMPOSITIONS / "sel4-io-tcp-options.zti"
OPTIONS_PROBE = "io-tcp-options-probe"
OPTIONS_HOLDERS = {"baseline": "options-baseline", "tuned": "options-tuned"}
OPTIONS_GENERATION = 163
NET_CLOSURE = "sel4-net"
NET_FIXTURE = COMPOSITIONS / "sel4-net.zti"
NET_GENERATION = 164
NET_PEER = "10.0.2.2"
# Exactly the numeric grants sel4-net gives http-get: the controlled peer, and
# 1.1.1.1:80 for the opt-in manual demonstration. No resolver row exists.
NET_DESTINATIONS = {
    ("http-get", NET_PEER, "ipv4", str(http_peer.HTTP_PORT), "tcp"),
    ("http-get", "1.1.1.1", "ipv4", "80", "tcp"),
}
ZENOH_CLOSURE = zenoh_exchange.CLOSURE
ZENOH_FIXTURE = COMPOSITIONS / "sel4-zenoh.zti"
NETWORK_SERVICE_MANIFEST = ROOT / "components" / "services" / "network-service" / "Cargo.toml"
TIMEOUT = 240
# The MAC the composition declares for the service, which is also the one the
# QEMU device carries: the gate reads it from the fixture so the two cannot drift.
MAC_DECLARATION = re.compile(r'mac\s*=\s*"([0-9a-f:]{17})"')

AUTHORITY_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "admission",
        (
            r"SLIME_ROOT generation admitted number=53 executables=5 instances=5 grants=3 ",
            r"\[network-service\] authority destinations=5 rights=connect,send,recv",
            r"\[network-service\] declared socket_limit=7 listener_limit=0 dns_record_limit=2",
        ),
    ),
    (
        "loopback honesty",
        (r"\[io-link-loopback\] declared endpoint bindings=1 protocol operations=0",),
    ),
    (
        "granted path",
        (
            r"\[io-network-probe\] tcp capabilities=1 rights=connect,send,recv",
            r"\[io-network-probe\] successful capability operations=2",
            r"\[io-network-probe\] exact destination refusals=1",
            r"\[io-network-probe\] dns records=1 budget_refusals=1",
            r"\[io-network-probe\] socket charges=2 budget_refusals=1",
            r"\[io-network-probe\] closed capabilities=4 shutdown=1",
        ),
    ),
    (
        "denials",
        (
            r"\[io-network-intruder\] exact authority refusals=8",
            r"\[io-network-intruder\] guessed capability refusals=4",
            r"\[io-network-intruder\] rights-mask refusals=2",
            r"\[io-network-intruder\] structured denials=14 shutdown=1",
        ),
    ),
    (
        "service close",
        (
            r"\[network-service\] observed requests=33 packets=7 socket_refusals=1 listener_refusals=0 dns_refusals=1 cross_holder_refusals=4",
            r"SLIME_GRAPH HEALTHY generation=53 required=5 live=0 completed=5 failed=0",
        ),
    ),
)
# The data-plane arm. Chains are one component each, in program order, because
# the matcher orders markers only within a chain and the components' startup
# interleaving is the scheduler's: a service line before or after a driver
# line is not a claim the plane makes. Counts that depend on the peer's timing
# (frames, replenishments) are shapes; the rest are exact observed values.
TCP_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "tcp admission",
        (r"SLIME_ROOT generation admitted number=54 executables=5 instances=5 grants=9 ",),
    ),
    (
        "tcp service",
        (
            r"\[network-service\] authority destinations=5 rights=connect,send,recv",
            r"\[network-service\] declared socket_limit=5 listener_limit=0 dns_record_limit=0",
            r"\[network-service\] clock rate=[0-9]+",
            r"\[network-service\] interface addr=10\.0\.0\.1/24 gateway=none mac=52:54:00:53:4c:01",
            r"\[network-service\] link query state=up rx provisioned=4",
            r"\[network-service\] application bytes sent=4096 received=4096",
            r"\[network-service\] application buffers released",
            r"\[network-service\] application connection handles live=0",
            r"\[network-service\] link frames total=[0-9]+ tx=[0-9]+ rx=[0-9]+ arp=[0-9]+ icmp=[0-9]+ tcp=[1-9]\d* other=0",
            r"\[network-service\] link statistics tx=[0-9]+ rx=[0-9]+",
            r"\[network-service\] link released",
            r"\[network-service\] observed requests=20 packets=2 socket_refusals=0 listener_refusals=0 dns_refusals=0 cross_holder_refusals=0",
        ),
    ),
    (
        "tcp driver",
        (
            r"\[virtio-net-driver\] negotiated legacy features=0 queues rx=16 tx=16 epoch=1",
            r"\[virtio-net-driver\] rx drained=[0-9]+ replenished=[0-9]+ stalled=0 tx-stalled=0 device-refused=0",
            r"\[virtio-net-driver\] reset settled tx=[0-9]+ rx=[0-9]+ leases=[0-9]+",
            r"\[virtio-net-driver\] fresh epoch old=1 new=2",
        ),
    ),
    (
        "tcp client",
        (
            r"\[io-tcp-probe\] clock rate=[0-9]+",
            r"\[io-tcp-probe\] tcp established=1 rights=connect,send,recv",
            r"\[io-tcp-probe\] stream sent=4096 received=4096 identical=1 partial_writes=[1-9]\d* would_block=[0-9]+",
            r"\[io-tcp-probe\] tcp close completed=1",
            r"\[io-tcp-probe\] peer refused=1 undeclared address=1 port=1",
            r"\[io-tcp-probe\] held ms=3000",
            r"\[io-tcp-probe\] closed capabilities=1 shutdown=1",
        ),
    ),
    (
        "tcp denials",
        (
            r"\[io-network-intruder\] exact authority refusals=8",
            r"\[io-network-intruder\] guessed capability refusals=4",
            r"\[io-network-intruder\] rights-mask refusals=2",
            r"\[io-network-intruder\] structured denials=14 shutdown=1",
        ),
    ),
    (
        "tcp health",
        (r"SLIME_GRAPH HEALTHY generation=54 required=5 live=0 completed=5 failed=0",),
    ),
)
LOCAL_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("local admission", (r"SLIME_ROOT generation admitted number=155 executables=3 instances=4 grants=5 ",)),
    ("local service", (
        r"\[network-service\] loopback interface=127\.0\.0\.1 external_nic=none",
        r"\[network-service\] wait wakes=[1-9]\d* coalesced=[0-9]+",
        r"\[network-service\] loopback frames=[1-9]\d* rejected=0 handles=0 external_frames=0 resets=0 syns=2 fins=2",
    )),
    ("local publisher", (
        r"\[io-local-network-probe\] role=publisher attached=1",
        r"\[io-local-network-probe\] role=publisher authority_refusals=4",
        r"\[io-local-network-probe\] role=publisher connected=1",
        r"\[io-local-network-probe\] role=publisher timeout_retries=[01]",
        r"\[io-local-network-probe\] role=publisher sent=4096 received=2048 identical=1",
        r"\[io-local-network-probe\] role=publisher connections closed=1",
        r"\[io-local-network-probe\] role=publisher notification_wakes=[1-9]\d*",
        r"\[io-local-network-probe\] role=publisher loans returned=2 shutdown=1",
    )),
    ("local subscriber", (
        r"\[io-local-network-probe\] role=subscriber attached=1",
        r"\[io-local-network-probe\] role=subscriber authority_refusals=3",
        r"\[io-local-network-probe\] role=subscriber listening=1",
        r"\[io-local-network-probe\] role=subscriber accepted=1",
        r"\[io-local-network-probe\] role=subscriber timeout=1 resumed=1",
        r"\[io-local-network-probe\] role=subscriber sent=2048 received=4096 identical=1",
        r"\[io-local-network-probe\] role=subscriber eof=1 connections closed=1 listeners closed=1",
        r"\[io-local-network-probe\] role=subscriber notification_wakes=[1-9]\d*",
        r"\[io-local-network-probe\] role=subscriber loans returned=2 shutdown=1",
    )),
    ("local health", (r"SLIME_GRAPH HEALTHY generation=155 required=4 live=0 completed=4 failed=0",)),
)

LIFETIME_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("lifetime supervisor", (
        r"\[io-network-lifetime-probe\] round=1 victim_fault=1 survivor_exit=1 service_exit=1",
        r"\[io-network-lifetime-probe\] round=2 victim_exit=1 survivor_exit=1 service_exit=1",
        r"\[io-network-lifetime-probe\] rounds=2 reclaimed=1 restarted=1",
    )),
    ("lifetime service", (
        r"\[network-service\] incarnation=1",
        r"\[network-service\] client death handles=1 sockets=1 bytes=4096 sessions_released=1",
        r"\[network-service\] loopback frames=[1-9]\d* rejected=0 handles=0 external_frames=0 resets=[1-9]\d*",
        r"\[network-service\] incarnation=2",
    )),
    ("lifetime stale handles", (
        r"\[io-network-lifetime-probe\] role=victim old_handle_refused=1 fresh_identity=1",
    )),
    ("lifetime accepted stale handle", (
        r"\[io-network-lifetime-probe\] role=survivor old_handle_refused=1 fresh_identity=1",
    )),
    ("lifetime health", (r"SLIME_GRAPH HEALTHY generation=156 required=2 live=0 completed=2 failed=0",)),
    ("lifetime clients", (
        r"\[io-network-lifetime-probe\] role=victim sent=1024 acknowledged=16 faulting=1",
        r"\[io-network-lifetime-probe\] role=survivor received=1024 identical=1 reset=1",
        r"\[io-network-lifetime-probe\] role=survivor received=1024 identical=1 eof=1 fresh=1",
    )),
)

SERVICE_FAULT_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("service fault stale client", (r"\[io-network-lifetime-probe\] role=victim old_handle_refused=1 fresh_identity=1",)),
    ("service fault stale accept", (r"\[io-network-lifetime-probe\] role=survivor old_handle_refused=1 fresh_identity=1",)),
    ("service fault", (
        r"\[network-service\] incarnation=1",
        r"\[network-service\] injected in-flight fault incarnation=1",
        r"SLIME_GRAPH holder reclaimed task=4 charges=12 actions=16",
        r"\[io-network-lifetime-probe\] round=1 service_fault=1 clients_invalidated=2",
        r"\[network-service\] incarnation=2",
        r"\[io-network-lifetime-probe\] service_fault=1 clients_invalidated=2 restarted=1",
        r"SLIME_GRAPH tasks reclaimed live=0 slots=[1-9]\d*",
        r"SLIME_GRAPH HEALTHY generation=157 required=2 live=0 completed=2 failed=0",
    )),
)

DRIVER_RESET_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("driver reset service", (
        r"\[network-service\] incarnation=1",
        r"\[network-service\] driver reset requests=1 handles=1 sockets=1 bytes=4096",
        r"\[network-service\] incarnation=2",
    )),
    ("driver reset client", (
        r"\[io-tcp-probe\] driver reset sent=1024 terminal=reset transferred=0",
        r"\[io-tcp-probe\] driver reset loans returned=2 shutdown=1",
        r"\[io-tcp-probe\] old_handle_refused=1 fresh_identity=1",
        r"\[io-tcp-probe\] stream sent=4096 received=4096 identical=1 partial_writes=[1-9]\d* would_block=[0-9]+",
        r"\[io-tcp-probe\] tcp close completed=1",
    )),
    ("driver reset epoch", (
        r"\[virtio-net-driver\] reset queued tx=[0-9]+ rx=[0-9]+",
        r"\[virtio-net-driver\] reset settled tx=[0-9]+ rx=[0-9]+ leases=[0-9]+",
        r"\[virtio-net-driver\] fresh epoch old=1 new=2",
        r"\[virtio-net-driver\] negotiated legacy features=0 queues rx=16 tx=16 epoch=2",
        r"\[virtio-net-driver\] fresh epoch old=2 new=3",
    )),
    ("driver reset supervisor", (
        r"\[io-network-lifetime-probe\] driver_reset=1 restarted=1 rounds=2",
        r"SLIME_GRAPH HEALTHY generation=158 required=2 live=0 completed=2 failed=0",
    )),
)

HTTP_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("http launch", (r"\[http-launcher\] ready",)),
    ("http client", (
        r"\[http-get\] cleanup close=1 detach=1",
        r"\[http-get\] complete success=1 status=[0-9]+ bytes=[0-9]+ error=none",
    )),
    ("http service cleanup", (
        r"\[network-service\] application buffers released",
        r"\[network-service\] application connection handles live=0",
        r"\[network-service\] link released",
    )),
    ("http graph cleanup", (
        r"SLIME_GRAPH tasks reclaimed live=0 slots=[1-9]\d*",
        r"SLIME_GRAPH loans served=[0-9]+ loans=0 mappings=0 regions=0 orphans=0 quota=0",
        r"SLIME_GRAPH HEALTHY generation=(?:159|160) required=4 live=0 completed=4 failed=0",
    )),
)

# The impairment arm. The service states its declared bounds, the numeric
# reclamation of the silent connection, and receive/transmit high-water marks
# that the window scenarios drive to exactly those bounds; the probe reports
# each scenario in program order.
_BUFFER = tcp_impairment_peer.SOCKET_BUFFER_BYTES
_STREAM = tcp_impairment_peer.STREAM_BYTES
IMPAIRMENT_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("impairment admission", (rf"SLIME_ROOT generation admitted number={IMPAIRMENT_GENERATION} executables=[0-9]+ instances=[0-9]+ grants=[0-9]+ ",)),
    ("impairment bounds", (
        rf"\[network-service\] tcp bounds rx_bytes={_BUFFER} tx_bytes={_BUFFER} assembler_segments={tcp_impairment_peer.ASSEMBLER_SEGMENTS} timeout_ms={int(tcp_impairment_peer.SOCKET_TIMEOUT_SECONDS * 1000)}",
    )),
    ("impairment reclamation", (rf"\[network-service\] tcp timeout handles=1 sockets=1 bytes={2 * _BUFFER}",)),
    ("impairment peaks", (rf"\[network-service\] tcp peaks rx_bytes={_BUFFER} tx_bytes={_BUFFER}",)),
    ("impairment service", (
        r"\[network-service\] application connection handles live=0",
        r"\[network-service\] link released",
    )),
    ("impairment driver", (
        r"\[virtio-net-driver\] negotiated legacy features=0 queues rx=16 tx=16 epoch=1",
        r"\[virtio-net-driver\] rx drained=[0-9]+ replenished=[0-9]+ stalled=0 tx-stalled=0 device-refused=0",
    )),
    ("impairment client", (
        rf"\[io-tcp-impairment-probe\] scenario=reorder sent={_STREAM} received={_STREAM} identical=1",
        rf"\[io-tcp-impairment-probe\] scenario=loss sent={_STREAM} received={_STREAM} identical=1",
        r"\[io-tcp-impairment-probe\] scenario=silent terminal=timeout",
        rf"\[io-tcp-impairment-probe\] scenario=silent fresh sent={_STREAM} received={_STREAM} identical=1",
        rf"\[io-tcp-impairment-probe\] scenario=receive-window stalled_ms={tcp_impairment_peer.RECEIVE_STALL_MS} sent={_STREAM} received={_STREAM} identical=1",
        rf"\[io-tcp-impairment-probe\] scenario=send-window queued={_BUFFER} backpressure=1 sent={_STREAM} received={_STREAM} identical=1",
        r"\[io-tcp-impairment-probe\] scenarios=5 shutdown=1",
    )),
    ("impairment health", (rf"SLIME_GRAPH HEALTHY generation={IMPAIRMENT_GENERATION} required=[0-9]+ live=0 completed=[0-9]+ failed=0",)),
)

# The external-listener arm. The service states the declared listener, settles
# each accepted connection's close with the bytes still unread or unsent when
# the close was requested and the reservation it returned, and counts the SYNs
# it dropped from unadmitted sources and the excess ones it refused; the probe
# reports each scenario in program order.
_LP = tcp_listener_peer
_ACCEPTED_CLOSE = r"\[network-service\] tcp accepted close unread={unread} unsent={unsent} terminal={terminal} handles=1 bytes=" + str(2 * _LP.SOCKET_BUFFER_BYTES)
LISTENER_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("listener admission", (rf"SLIME_ROOT generation admitted number={LISTENER_GENERATION} executables=[0-9]+ instances=[0-9]+ grants=[0-9]+ ",)),
    ("listener declaration", (
        rf"\[network-service\] tcp listener backend=external address=10\.0\.0\.1 port={_LP.LISTEN_PORT} peer=10\.0\.0\.2 backlog={_LP.BACKLOG} accepted_limit={_LP.ACCEPTED_LIMIT} bytes={_LP.LISTENER_BYTE_BUDGET}",
    )),
    ("listener service", (
        _ACCEPTED_CLOSE.format(unread=0, unsent=0, terminal="time-wait"),
        _ACCEPTED_CLOSE.format(unread=0, unsent="[0-9]+", terminal="closed"),
        _ACCEPTED_CLOSE.format(unread=0, unsent=0, terminal="time-wait"),
        _ACCEPTED_CLOSE.format(unread=len(_LP.UNREAD), unsent=0, terminal="reset"),
        _ACCEPTED_CLOSE.format(unread=0, unsent=len(_LP.UNSENT), terminal="time-wait"),
        r"\[network-service\] tcp listener closed children=0",
        r"\[network-service\] tcp listener refusals unadmitted=1 excess=2",
        r"\[network-service\] application connection handles live=0",
        r"\[network-service\] link released",
    )),
    ("listener driver", (
        r"\[virtio-net-driver\] negotiated legacy features=0 queues rx=16 tx=16 epoch=1",
        r"\[virtio-net-driver\] rx drained=[0-9]+ replenished=[0-9]+ stalled=0 tx-stalled=0 device-refused=0",
    )),
    ("listener intruder", (
        r"\[io-tcp-listener-probe\] role=intruder attached=1",
        r"\[io-tcp-listener-probe\] role=intruder listen_refused=1 shutdown=1",
    )),
    ("listener probe", (
        r"\[io-tcp-listener-probe\] role=listener attached=1",
        r"\[io-tcp-listener-probe\] role=listener listen_refusals=2",
        rf"\[io-tcp-listener-probe\] role=listener listening=1 address=10\.0\.0\.1 port={_LP.LISTEN_PORT}",
        rf"\[io-tcp-listener-probe\] role=listener accepted=1 sent={len(_LP.EXCHANGE)} received={len(_LP.EXCHANGE)} identical=1",
        r"\[io-tcp-listener-probe\] role=listener accepted=2 held=1",
        rf"\[io-tcp-listener-probe\] role=listener scenario=local-half-close sent={len(_LP.LOCAL_HALF_GUEST)} received={len(_LP.LOCAL_HALF_PEER)} eof=1 close=success stale_refused=1",
        rf"\[io-tcp-listener-probe\] role=listener scenario=peer-half-close received={len(_LP.PEER_HALF_PEER)} eof=1 sent={len(_LP.PEER_HALF_GUEST)} close=success stale_refused=1",
        r"\[io-tcp-listener-probe\] role=listener scenario=simultaneous-close close=success stale_refused=1",
        rf"\[io-tcp-listener-probe\] role=listener scenario=unread-close unread={len(_LP.UNREAD)} close=success stale_refused=1",
        rf"\[io-tcp-listener-probe\] role=listener scenario=unsent-close queued={len(_LP.UNSENT)} close=success stale_refused=1",
        r"\[io-tcp-listener-probe\] role=listener listener_closed=1 scenarios=5 shutdown=1",
    )),
    ("listener health", (rf"SLIME_GRAPH HEALTHY generation={LISTENER_GENERATION} required=[0-9]+ live=0 completed=[0-9]+ failed=0",)),
)

# The socket-options arm. The service states each binding's applied options
# and its congestion control at activation, reclaims both mute connections by
# typed timeout, and the two probe holders report each scenario in program
# order; the wire evidence is judged by the peer's qualifier.
_OP = tcp_options_peer


def _options_marker(holder: str, options: tcp_options_peer.Options) -> str:
    return rf"\[network-service\] tcp options holder={holder} keepalive_ms={options.keepalive_ms} nagle={int(options.nagle)} hop_limit={options.hop_limit} idle_timeout_ms={options.idle_timeout_ms}"


OPTIONS_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("options admission", (rf"SLIME_ROOT generation admitted number={OPTIONS_GENERATION} executables=[0-9]+ instances=[0-9]+ grants=[0-9]+ ",)),
    ("options declaration", (
        _options_marker(OPTIONS_HOLDERS["baseline"], _OP.BASELINE),
        _options_marker(OPTIONS_HOLDERS["tuned"], _OP.TUNED),
        r"\[network-service\] tcp congestion control=reno",
    )),
    ("options reclamation", (rf"\[network-service\] tcp timeout handles=1 sockets=1 bytes={2 * _OP.SOCKET_BUFFER_BYTES}",)),
    ("options service", (
        r"\[network-service\] application connection handles live=0",
        r"\[network-service\] link released",
    )),
    ("options driver", (
        r"\[virtio-net-driver\] negotiated legacy features=0 queues rx=16 tx=16 epoch=1",
        r"\[virtio-net-driver\] rx drained=[0-9]+ replenished=[0-9]+ stalled=0 tx-stalled=0 device-refused=0",
    )),
    ("options baseline", (
        r"\[io-tcp-options-probe\] role=baseline attached=1 mutation_refused=1",
        rf"\[io-tcp-options-probe\] role=baseline scenario=nagle-on writes={_OP.BURST_WRITES} sent={len(_OP.BURST)} done=1",
        rf"\[io-tcp-options-probe\] role=baseline scenario=loss sent={_OP.STREAM_BYTES} done=1",
        r"\[io-tcp-options-probe\] role=baseline scenario=silent-timeout terminal=timeout",
        r"\[io-tcp-options-probe\] role=baseline scenarios=3 shutdown=1",
    )),
    ("options tuned", (
        r"\[io-tcp-options-probe\] role=tuned attached=1 mutation_refused=1",
        rf"\[io-tcp-options-probe\] role=tuned scenario=nagle-off writes={_OP.BURST_WRITES} sent={len(_OP.BURST)} done=1",
        r"\[io-tcp-options-probe\] role=tuned scenario=keepalive done=1",
        r"\[io-tcp-options-probe\] role=tuned scenario=dead-peer terminal=timeout",
        r"\[io-tcp-options-probe\] role=tuned scenarios=3 shutdown=1",
    )),
    ("options health", (rf"SLIME_GRAPH HEALTHY generation={OPTIONS_GENERATION} required=[0-9]+ live=0 completed=[0-9]+ failed=0",)),
)

# The shell arm. Each case is one line typed into the resident Slisp shell,
# sent only after the previous case's chains and settle marker have all
# matched. A case's chains are ordered within themselves but not against each
# other: a spawned child and the shell's reply to its spawn race on the console.
# A fetch settles on its completion. A failed completion is a shared failure
# marker and a successful one satisfies the HTTP arm's own completion pattern,
# so completions are judged as settle markers and by exact count rather than
# registered as chains.
NET_FETCH = next(case for case in http_peer.cases() if case.name == "numeric-content-length")
_NET_ABORTED = (
    r"\[network-service\] application aborted sessions_released=1",
    r"\[http-get\] cleanup close=0 detach=1 abort=1",
)
_NET_REFUSED = r"\[http-get\] complete success=0 status=0 bytes=0 error=transport"
_NET_FETCHED = rf"\[http-get\] complete success=1 status={NET_FETCH.status} bytes={len(NET_FETCH.body)} error=none"


class NetCase(NamedTuple):
    name: str
    line: str
    chains: tuple[tuple[str, ...], ...]
    settle: str | None = None

    def settle_patterns(self) -> tuple[str, ...]:
        return tuple(chain[-1] for chain in self.chains) + ((self.settle,) if self.settle is not None else ())


NET_CASES: tuple[NetCase, ...] = (
    NetCase("bare-symbol", "echo", ((r"=> spawned echo",), (r"\[echo-agent\] command=echo args=0 ",))),
    NetCase("string-outside-spawn", '"slime"', ((r"! type",),)),
    NetCase("unterminated-string", f"(spawn 'http-get \"http://{NET_PEER}:{http_peer.HTTP_PORT}/", ((r"! syntax",),)),
    NetCase("unbound-command", f"(spawn 'wget \"http://{NET_PEER}:{http_peer.HTTP_PORT}/\")", ((r"! spawn",),)),
    NetCase("undeclared-destination", f"(spawn 'http-get \"http://10.0.2.9:{http_peer.HTTP_PORT}/\")", ((r"=> spawned http-get",), _NET_ABORTED), _NET_REFUSED),
    NetCase("hostname", f"(spawn 'http-get \"http://example.test:{http_peer.HTTP_PORT}/\")", ((r"=> spawned http-get",), _NET_ABORTED), _NET_REFUSED),
    NetCase("numeric-fetch", f"(spawn 'http-get \"{NET_FETCH.url}\")", (
        (r"=> spawned http-get",),
        (r"\[network-service\] application buffers released", r"\[http-get\] cleanup close=1 detach=1"),
    ), _NET_FETCHED),
)
NET_READY: tuple[tuple[str, ...], ...] = (
    (rf"SLIME_ROOT generation admitted number={NET_GENERATION} executables=[0-9]+ instances=[0-9]+ grants=[0-9]+ ", r"\[slisp\] resident input wait"),
)
NET_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("net shell ready", NET_READY[0]),
    *((f"net {case.name}", chain) for case in NET_CASES for chain in case.chains),
)
# Exact totals over the whole session: one spawn per accepted spawn line, one
# completion per http-get instance, and a network service that stays resident.
NET_COUNTS: tuple[tuple[str, str, int], ...] = (
    ("spawned children", r"\[spawn-service\] spawning child", 4),
    ("http-get completions", r"\[http-get\] complete ", 3),
    ("refused http-get completions", _NET_REFUSED, 2),
    ("successful http-get completions", _NET_FETCHED, 1),
    ("aborted sessions", r"\[network-service\] application aborted sessions_released=1", 2),
    ("released sessions", r"\[network-service\] application buffers released", 1),
    ("link releases", r"\[network-service\] link released", 0),
)


ZENOH_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("zenoh admission", (rf"SLIME_ROOT generation admitted number={zenoh_exchange.GENERATION} executables=\d+ instances=4 grants=\d+ ",)),
    ("zenoh service", (
        r"\[network-service\] loopback interface=127\.0\.0\.1 external_nic=none",
        r"\[network-service\] loopback frames=[1-9]\d* rejected=0 handles=0 external_frames=0 resets=0 syns=2 fins=2",
    )),
    ("zenoh sessions", (
        r"\[ros2-demo-subscriber\] session open role=listener initial_sn=0 lease_ms=2000",
        r"\[ros2-demo-publisher\] session open role=connector initial_sn=0 lease_ms=2000",
        r"\[ros2-demo-subscriber\] declared subscriber id=1 key=0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_[0-9a-f]{64}",
        r"\[ros2-demo-publisher\] declaration matched key=0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_[0-9a-f]{64}",
    )),
    ("zenoh samples", (
        r"\[ros2-demo-publisher\] wire sent sample=0 hex=[0-9a-f]+",
        r"\[ros2-demo-subscriber\] sample validated sequence=0 value=10",
        r"\[ros2-demo-publisher\] wire sent sample=1 hex=[0-9a-f]+",
        r"\[ros2-demo-subscriber\] sample validated sequence=1 value=20",
        r"\[ros2-demo-publisher\] wire sent sample=2 hex=[0-9a-f]+",
        r"\[ros2-demo-subscriber\] sample validated sequence=2 value=30",
        r"\[ros2-demo-publisher\] wire sent sample=3 hex=[0-9a-f]+",
        r"\[ros2-demo-subscriber\] sample validated sequence=3 value=40",
        r"\[rpi5-ros2-demo\] received count=4 sequences=0,1,2,3 values=10,20,30,40",
    )),
    ("zenoh teardown", (
        r"\[ros2-demo-subscriber\] undeclared subscriber id=1",
        r"\[ros2-demo-subscriber\] session closing samples=4",
        r"\[ros2-demo-publisher\] session closed samples=4",
    )),
    ("zenoh denials", (
        r"\[ros2-demo-publisher\] denial class=undeclared-endpoint refused=1",
        r"\[ros2-demo-publisher\] denial class=listen refused=1",
        r"\[ros2-demo-publisher\] denial class=scouting refused=1",
        r"\[ros2-demo-subscriber\] denial class=connect refused=1",
    )),
    ("zenoh success", (
        r"\[rpi5-ros2-demo\] success profile=rpi5-ros2-demo-v2 samples=4",
        rf"SLIME_GRAPH HEALTHY generation={zenoh_exchange.GENERATION} required=4 live=0 completed=4 failed=0",
    )),
)

# Every arm participates in the shared missing/reordered/failure controls.
CHAINS = AUTHORITY_CHAINS + TCP_CHAINS + LOCAL_CHAINS + LIFETIME_CHAINS + SERVICE_FAULT_CHAINS + DRIVER_RESET_CHAINS + HTTP_CHAINS + IMPAIRMENT_CHAINS + LISTENER_CHAINS + OPTIONS_CHAINS + NET_CHAINS + ZENOH_CHAINS
FAILURE_MARKERS: tuple[str, ...] = (
    r"SLIME_ROOT FATAL",
    r"SLIME_GRAPH FAIL",
    r"\[network-service\] fail: ",
    r"\[network-service\] link fail: ",
    r"\[io-network-probe\] fail: ",
    r"\[io-network-intruder\] fail: ",
    r"\[io-tcp-probe\] fail: ",
    r"\[io-tcp-impairment-probe\] fail: ",
    r"\[io-tcp-listener-probe\] fail: ",
    r"\[io-tcp-options-probe\] fail: ",
    r"\[io-local-network-probe\] fail: ",
    r"\[ros2-demo-publisher\] fail: ",
    r"\[ros2-demo-subscriber\] fail: ",
    r"\[rpi5-ros2-demo\] failure class=",
    r"\[io-network-lifetime-probe\] fail: ",
    r"\[virtio-net-driver\] fail: ",
    r"\[http-get\] fail: ",
    r"\[http-launcher\] fail: ",
    r"\[http-get\] complete success=0 ",
    r"Caught cap fault",
    r"Caught vm fault",
    r"panicked at ",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"seL4 I/O network plane check: {message}")


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


def check_fixture() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    for pattern in (
        r"generation\s*=\s*53;",
        r"networkDestinations\s*=\s*\[",
        r'name\s*=\s*"network-service"',
        r'name\s*=\s*"io-network-probe"',
        r'name\s*=\s*"io-network-intruder"',
        r'name\s*=\s*"io-link-loopback"',
    ):
        if re.search(pattern, text) is None:
            fail(f"fixture is missing {pattern!r}")


def check_tcp_fixture() -> str:
    text = TCP_FIXTURE.read_text(encoding="utf-8")
    for pattern in (
        r"generation\s*=\s*54;",
        r"networkDestinations\s*=\s*\[",
        r"networkInterfaces\s*=\s*\[",
        r'address\s*=\s*"10\.0\.0\.2"',
        r'name\s*=\s*"network-service"',
        r'name\s*=\s*"io-tcp-probe"',
        r'name\s*=\s*"io-network-intruder"',
        r'name\s*=\s*"virtio-net-driver"',
        r'name\s*=\s*"io-link-tx-request-ready"',
    ):
        if re.search(pattern, text) is None:
            fail(f"tcp fixture is missing {pattern!r}")
    macs = MAC_DECLARATION.findall(text)
    if len(macs) != 1:
        fail(f"tcp fixture declares {len(macs)} interface MACs, expected exactly one")
    return macs[0]


def reserve_udp_port() -> tuple[socket.socket, int]:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(0.05)
    return receiver, int(receiver.getsockname()[1])


def run_authority_arm(image: Path) -> None:
    terminal = re.compile(AUTHORITY_CHAINS[-1][1][-1] + "|" + "|".join(FAILURE_MARKERS))
    transcript = run_plane(
        image=image,
        timeout=TIMEOUT,
        terminal_condition=terminal,
        fail=fail,
        pins_path=PINS,
    )
    match_marker_contract(transcript, AUTHORITY_CHAINS, FAILURE_MARKERS, fail)


def run_with_peer(image: Path, mac: str, serve: Callable[..., None], peer: object, chains: tuple[tuple[str, tuple[str, ...]], ...]) -> str:
    """Boot `image` behind a frame-level peer on QEMU's UDP socket backend.

    The transcript is returned only once the observer has stopped cleanly, so
    no verdict can rest on wire evidence that is still being collected.
    """
    receiver, backend_port = reserve_udp_port()
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    qemu_port = int(probe.getsockname()[1])
    probe.close()
    stop = threading.Event()
    peer_errors: list[BaseException] = []

    def observe() -> None:
        try:
            serve(receiver, qemu_port, stop, peer)
        except BaseException as error:
            peer_errors.append(error)

    thread = threading.Thread(target=observe, daemon=True)
    thread.start()
    terminal = re.compile(chains[-1][1][-1] + "|" + "|".join(FAILURE_MARKERS))
    try:
        transcript = run_plane(
            image=image,
            timeout=TIMEOUT,
            terminal_condition=terminal,
            fail=fail,
            pins_path=PINS,
            additional_arguments=(
                "-netdev",
                f"socket,id=slimelink,udp=127.0.0.1:{backend_port},localaddr=127.0.0.1:{qemu_port}",
                "-device",
                f"virtio-net-device,netdev=slimelink,mac={mac}",
            ),
        )
    finally:
        stop.set()
        thread.join(timeout=2)
        receiver.close()
    if thread.is_alive():
        fail("peer observer did not stop; wire evidence is incomplete")
    if peer_errors:
        fail(f"peer observer failed; wire evidence is incomplete: {peer_errors[0]!r}")
    return transcript


def write_wire_transcript(transcript_path: Path | None, transcript: str, summary: str, directions: tuple[tuple[str, list[object]], ...]) -> None:
    if transcript_path is None:
        return
    packets = "".join(
        f"[peer {direction} {index}] {frame!r}\n"
        for direction, frames in directions
        for index, frame in enumerate(frames)
    )
    transcript_path.write_text(transcript + f"\n[peer] {summary}\n" + packets, encoding="utf-8")


def run_tcp_arm(image: Path, mac: str, transcript_path: Path | None, *, driver_reset: bool = False) -> None:
    peer = link_peer.Peer(hold_first_tcp=driver_reset)
    chains = DRIVER_RESET_CHAINS if driver_reset else TCP_CHAINS
    transcript = run_with_peer(image, mac, link_peer.serve, peer, chains)
    write_wire_transcript(transcript_path, transcript, peer.ledger.summary(), (("received", peer.ledger.received), ("sent", peer.ledger.sent)))
    try:
        match_marker_contract(transcript, chains, FAILURE_MARKERS, fail)
    except SystemExit:
        print(transcript)
        raise
    ledger = peer.ledger
    print(f"[peer] {ledger.summary()}")
    if driver_reset:
        try:
            link_peer.qualify_driver_reset_ledger(ledger, bytes.fromhex(mac.replace(":", "")))
        except ValueError as error:
            fail(f"driver reset peer wire evidence: {error}")
    else:
        check_tcp_ledger(ledger, bytes.fromhex(mac.replace(":", "")))


def fixture_destinations(text: str, section_name: str = "networkDestinations") -> list[dict[str, str]]:
    """The derived manifest's rows of one network section as flat field maps; rights are comma-joined."""
    section = re.search(rf"{section_name}\s*=\s*\[(.*?)\n  \];", text, re.S)
    if section is None:
        fail(f"fixture declares no {section_name}")
    assert section is not None
    rows = []
    for block in re.findall(r"\{(.*?)\n    \};", section.group(1), re.S):
        row = {key: value.strip('"') for key, value in re.findall(r'^\s*(\w+)\s*=\s*("[^"]*"|-?[0-9]+|true|false);', block, re.M)}
        rights = re.search(r"rights\s*=\s*\[(.*?)\];", block, re.S)
        row["rights"] = ",".join(re.findall(r'"([a-z]+)"', rights.group(1))) if rights else ""
        rows.append(row)
    return rows


def check_impairment_fixture() -> tuple[str, dict[int, int]]:
    """Return the interface MAC and the declared per-scenario retry limits."""
    if not IMPAIRMENT_FIXTURE.is_file():
        fail(f"{IMPAIRMENT_FIXTURE.relative_to(ROOT)} does not exist; the impairment composition has not landed")
    text = IMPAIRMENT_FIXTURE.read_text(encoding="utf-8")
    macs = MAC_DECLARATION.findall(text)
    if len(macs) != 1:
        fail(f"impairment fixture declares {len(macs)} interface MACs, expected exactly one")
    for pattern in (rf"generation\s*=\s*{IMPAIRMENT_GENERATION};", r"networkInterfaces\s*=\s*\[", r'address\s*=\s*"10\.0\.0\.1"', r'name\s*=\s*"network-service"', rf'name\s*=\s*"{IMPAIRMENT_PROBE}"', r'name\s*=\s*"virtio-net-driver"'):
        if re.search(pattern, text) is None:
            fail(f"impairment fixture is missing {pattern!r}")
    rows = [row for row in fixture_destinations(text) if row.get("holder") == IMPAIRMENT_PROBE]
    if sorted(int(row.get("port", "0")) for row in rows) != sorted(tcp_impairment_peer.SCENARIOS):
        fail("the impairment probe must hold exactly one destination per scenario port")
    limits: dict[int, int] = {}
    for row in rows:
        port = int(row["port"])
        if (row.get("address"), row.get("addressKind"), row.get("transport")) != ("10.0.0.2", "ipv4", "tcp") or not {"connect", "send", "recv"} <= set(row["rights"].split(",")):
            fail(f"scenario destination {port} is not an exact 10.0.0.2 TCP connect/send/recv grant")
        limits[port] = int(row.get("retryLimit", "-1"))
        if not 1 <= limits[port] <= 16:
            fail(f"scenario destination {port} declares retry limit {limits[port]}, outside the contract's 1..16")
    silent = next(row for row in rows if int(row["port"]) == tcp_impairment_peer.SILENT_PORT)
    if (silent.get("socketLimit"), silent.get("byteBudget")) != ("1", str(2 * tcp_impairment_peer.SOCKET_BUFFER_BYTES)):
        fail("the silent destination must admit one connection's reservation, so its fresh exchange proves reclamation")
    features = re.findall(r"assembler-max-segment-count-([0-9]+)", NETWORK_SERVICE_MANIFEST.read_text(encoding="utf-8"))
    if features != [str(tcp_impairment_peer.ASSEMBLER_SEGMENTS)]:
        fail(f"the network service must select exactly assembler-max-segment-count-{tcp_impairment_peer.ASSEMBLER_SEGMENTS}, found {features}")
    return macs[0], limits


def run_impairment_arm(image: Path, mac: str, retry_limits: dict[int, int], transcript_path: Path | None) -> None:
    peer = tcp_impairment_peer.ImpairmentPeer()
    transcript = run_with_peer(image, mac, tcp_impairment_peer.serve, peer, IMPAIRMENT_CHAINS)
    write_wire_transcript(transcript_path, transcript, peer.ledger.summary(), (("received", peer.ledger.received), ("sent", peer.ledger.sent)))
    try:
        match_marker_contract(transcript, IMPAIRMENT_CHAINS, FAILURE_MARKERS, fail)
    except SystemExit:
        print(transcript)
        raise
    print(f"[impairment-peer] {peer.ledger.summary()}")
    try:
        summaries = tcp_impairment_peer.qualify_impairment_ledger(peer.ledger, bytes.fromhex(mac.replace(":", "")), retry_limits)
    except ValueError as error:
        fail(f"impairment wire evidence: {error}")
    for summary in summaries:
        print(f"[impairment] {summary}")


def check_listener_fixture() -> str:
    """Return the interface MAC once the composition declares exactly the listener the peer scripts."""
    if not LISTENER_FIXTURE.is_file():
        fail(f"{LISTENER_FIXTURE.relative_to(ROOT)} does not exist; the external listener composition has not landed")
    text = LISTENER_FIXTURE.read_text(encoding="utf-8")
    macs = MAC_DECLARATION.findall(text)
    if len(macs) != 1:
        fail(f"listener fixture declares {len(macs)} interface MACs, expected exactly one")
    for pattern in (rf"generation\s*=\s*{LISTENER_GENERATION};", r"networkInterfaces\s*=\s*\[", r'address\s*=\s*"10\.0\.0\.1"', r'name\s*=\s*"network-service"', r'name\s*=\s*"virtio-net-driver"', rf'executable\s*=\s*"{LISTENER_PROBE}"', rf'name\s*=\s*"{LISTENER_HOLDER}"', rf'name\s*=\s*"{INTRUDER_HOLDER}"'):
        if re.search(pattern, text) is None:
            fail(f"listener fixture is missing {pattern!r}")
    applications = {row.get("holder"): row for row in fixture_destinations(text, "networkApplications")}
    listeners = [row for row in applications.values() if row.get("role") == "listener"]
    expected = {
        "holder": LISTENER_HOLDER,
        "backend": "external",
        "localAddress": "10.0.0.1",
        "localPort": str(tcp_listener_peer.LISTEN_PORT),
        "admittedPeer": "",
        "admittedPeerAddress": "10.0.0.2",
        "backlog": str(tcp_listener_peer.BACKLOG),
        "acceptedSocketLimit": str(tcp_listener_peer.ACCEPTED_LIMIT),
        "byteBudget": str(tcp_listener_peer.LISTENER_BYTE_BUDGET),
    }
    if len(listeners) != 1 or any(listeners[0].get(key) != value for key, value in expected.items()):
        fail(f"the composition must declare exactly one external listener {expected}, found {listeners}")
    if set(listeners[0]["rights"].split(",")) != {"listen", "send", "recv"}:
        fail("the external listener must hold exactly listen, send and recv")
    intruder = applications.get(INTRUDER_HOLDER)
    if intruder is None or (intruder.get("role"), intruder.get("backend"), intruder.get("localPort")) != ("client", "external", "0"):
        fail("the intruder must be an external client holding no listener authority")
    destinations = fixture_destinations(text)
    control = [row for row in destinations if row.get("holder") == LISTENER_HOLDER]
    if [(row.get("address"), row.get("port"), row.get("transport")) for row in control] != [("10.0.0.2", str(tcp_listener_peer.CONTROL_PORT), "tcp")] or not {"connect", "send", "recv"} <= set(control[0]["rights"].split(",")):
        fail("the listener holder must hold exactly one 10.0.0.2 control destination with connect, send and recv")
    if any("listen" in row["rights"].split(",") for row in destinations):
        fail("listener authority must come from the application declaration, never a destination row")
    return macs[0]


def check_options_fixture() -> tuple[str, dict[int, int]]:
    """Return the interface MAC and per-port retry limits once the composition declares exactly the options the peer scripts."""
    if not OPTIONS_FIXTURE.is_file():
        fail(f"{OPTIONS_FIXTURE.relative_to(ROOT)} does not exist; the socket-options composition has not landed")
    text = OPTIONS_FIXTURE.read_text(encoding="utf-8")
    macs = MAC_DECLARATION.findall(text)
    if len(macs) != 1:
        fail(f"options fixture declares {len(macs)} interface MACs, expected exactly one")
    for pattern in (rf"generation\s*=\s*{OPTIONS_GENERATION};", r"networkInterfaces\s*=\s*\[", r'address\s*=\s*"10\.0\.0\.1"', r'name\s*=\s*"network-service"', r'name\s*=\s*"virtio-net-driver"', rf'executable\s*=\s*"{OPTIONS_PROBE}"', *(rf'name\s*=\s*"{holder}"' for holder in OPTIONS_HOLDERS.values())):
        if re.search(pattern, text) is None:
            fail(f"options fixture is missing {pattern!r}")
    applications = {row.get("holder"): row for row in fixture_destinations(text, "networkApplications")}
    for role, holder in OPTIONS_HOLDERS.items():
        row = applications.get(holder)
        declared = tcp_options_peer.HOLDERS[role]
        expected = {
            "role": "client",
            "backend": "external",
            "keepaliveMs": str(declared.keepalive_ms),
            "nagle": "true" if declared.nagle else "false",
            "hopLimit": str(declared.hop_limit),
            "idleTimeoutMs": str(declared.idle_timeout_ms),
        }
        if row is None or any(row.get(key) != value for key, value in expected.items()):
            fail(f"the composition must declare {holder} as an external client with options {expected}, found {row}")
    if any(row.get("role") == "listener" for row in applications.values()):
        fail("the options composition declares no listener")
    destinations = fixture_destinations(text)
    limits: dict[int, int] = {}
    for role, holder in OPTIONS_HOLDERS.items():
        rows = [row for row in destinations if row.get("holder") == holder]
        if sorted(int(row.get("port", "0")) for row in rows) != sorted(tcp_options_peer.HOLDER_PORTS[role]):
            fail(f"{holder} must hold exactly one destination per scenario port {tcp_options_peer.HOLDER_PORTS[role]}")
        for row in rows:
            port = int(row["port"])
            if (row.get("address"), row.get("addressKind"), row.get("transport")) != ("10.0.0.2", "ipv4", "tcp") or not {"connect", "send", "recv"} <= set(row["rights"].split(",")):
                fail(f"scenario destination {port} is not an exact 10.0.0.2 TCP connect/send/recv grant")
            limits[port] = int(row.get("retryLimit", "-1"))
            if not 1 <= limits[port] <= 16:
                fail(f"scenario destination {port} declares retry limit {limits[port]}, outside the contract's 1..16")
    if any("listen" in row["rights"].split(",") for row in destinations):
        fail("no destination in the options composition may carry listen")
    manifest = NETWORK_SERVICE_MANIFEST.read_text(encoding="utf-8")
    if "socket-tcp-reno" not in manifest or "socket-tcp-cubic" in manifest:
        fail("the network service must enable exactly socket-tcp-reno and not socket-tcp-cubic")
    return macs[0], limits


def run_options_arm(image: Path, mac: str, retry_limits: dict[int, int], transcript_path: Path | None) -> None:
    peer = tcp_options_peer.OptionsPeer()
    transcript = run_with_peer(image, mac, tcp_options_peer.serve, peer, OPTIONS_CHAINS)
    write_wire_transcript(transcript_path, transcript, peer.ledger.summary(), (("received", peer.ledger.received), ("sent", peer.ledger.sent)))
    try:
        match_marker_contract(transcript, OPTIONS_CHAINS, FAILURE_MARKERS, fail)
    except SystemExit:
        print(transcript)
        raise
    print(f"[options-peer] {peer.ledger.summary()}")
    try:
        summaries = tcp_options_peer.qualify_options_ledger(peer.ledger, bytes.fromhex(mac.replace(":", "")), retry_limits)
    except ValueError as error:
        fail(f"options wire evidence: {error}")
    for summary in summaries:
        print(f"[options] {summary}")


def run_listener_arm(image: Path, mac: str, transcript_path: Path | None) -> None:
    peer = tcp_listener_peer.ListenerPeer()
    transcript = run_with_peer(image, mac, tcp_listener_peer.serve, peer, LISTENER_CHAINS)
    write_wire_transcript(transcript_path, transcript, peer.ledger.summary(), (("received", peer.ledger.received), ("sent", peer.ledger.sent)))
    try:
        match_marker_contract(transcript, LISTENER_CHAINS, FAILURE_MARKERS, fail)
    except SystemExit:
        print(transcript)
        raise
    print(f"[listener-peer] {peer.ledger.summary()}")
    try:
        summaries = tcp_listener_peer.qualify_listener_ledger(peer.ledger, bytes.fromhex(mac.replace(":", "")))
    except ValueError as error:
        fail(f"listener wire evidence: {error}")
    for summary in summaries:
        print(f"[listener] {summary}")


def check_tcp_ledger(ledger: link_peer.Ledger, guest_mac: bytes) -> None:
    try:
        link_peer.qualify_tcp_ledger(ledger, guest_mac)
    except ValueError as error:
        fail(f"peer wire evidence: {error}")


def check_net_fixture() -> str:
    """Return the interface MAC once sel4-net binds http-get as a command and grants exactly the numeric destinations."""
    if not NET_FIXTURE.is_file():
        fail(f"{NET_FIXTURE.relative_to(ROOT)} does not exist; the sel4-net composition has not landed")
    text = NET_FIXTURE.read_text(encoding="utf-8")
    macs = MAC_DECLARATION.findall(text)
    if len(macs) != 1:
        fail(f"sel4-net fixture declares {len(macs)} interface MACs, expected exactly one")
    for pattern in (
        rf"generation\s*=\s*{NET_GENERATION};",
        *(rf'name\s*=\s*"{name}"' for name in ("slisp", "spawn-service", "network-service", "virtio-net-driver", "spawn-service-http-get", "spawn-service-http-get-context")),
    ):
        if re.search(pattern, text) is None:
            fail(f"sel4-net fixture is missing {pattern!r}")
    if "http-launcher" in text:
        fail("sel4-net launches http-get through spawn-service, not through the testkit launcher")
    rows = fixture_destinations(text)
    declared = {(row.get("holder"), row.get("address"), row.get("addressKind"), row.get("port"), row.get("transport")) for row in rows}
    if declared != NET_DESTINATIONS or len(rows) != len(NET_DESTINATIONS):
        fail(f"sel4-net must declare exactly the numeric destinations {sorted(NET_DESTINATIONS)}, found {sorted(map(str, declared))}")
    if any(set(row["rights"].split(",")) != {"connect", "send", "recv"} for row in rows):
        fail("every sel4-net destination is exactly a connect/send/recv grant")
    return macs[0]


class NetRefusal(Exception):
    """A judged sel4-net transcript was refused; raised instead of exiting so controls can count it."""


def _net_reject(message: str) -> NoReturn:
    raise NetRefusal(message)


def judge_net_transcript(transcript: str, reject: Callable[[str], NoReturn]) -> tuple[int, int]:
    """Return (cases observed, body bytes matched) for one shell session, or reject it."""
    failures = tuple(marker for marker in FAILURE_MARKERS if marker != r"\[http-get\] complete success=0 ")
    match_marker_contract(transcript, NET_CHAINS, failures, reject)
    position = 0
    for chain in NET_READY:
        for pattern in chain:
            found = re.compile(pattern).search(transcript, position)
            if found is None:
                reject(f"net shell never became ready: {pattern}")
            position = found.end()
    cases = 0
    for case in NET_CASES:
        end = position
        for chain in case.chains:
            cursor = position
            for pattern in chain:
                found = re.compile(pattern).search(transcript, cursor)
                if found is None:
                    reject(f"net {case.name}: missing or out-of-order marker after the previous case: {pattern}")
                cursor = found.end()
            end = max(end, cursor)
        if case.settle is not None:
            # After the case's final chain marker, so it cannot be an earlier case's.
            found = re.compile(case.settle).search(transcript, position)
            if found is None:
                reject(f"net {case.name}: missing settle marker after the previous case: {case.settle}")
            end = max(end, found.end())
        position = end
        cases += 1
    for label, pattern, expected in NET_COUNTS:
        observed = len(re.findall(pattern, transcript))
        if observed != expected:
            reject(f"net session: {label} observed {observed}, expected exactly {expected}")
    body = bytearray()
    for line in transcript.splitlines():
        if line.startswith("[http-get] body "):
            record = re.fullmatch(r"\[http-get\] body hex=([0-9a-f]{2,128})", line)
            if record is None or len(record[1]) % 2:
                reject("malformed or oversized HTTP body record")
            body.extend(bytes.fromhex(record[1]))
    if bytes(body) != NET_FETCH.body:
        reject(f"spawned fetch body differs from the controlled peer's {len(NET_FETCH.body)} bytes (decoded {len(body)})")
    return cases, len(body)


def net_controls(transcript: str) -> int:
    """Mutate an accepted transcript and require every mutation to be refused; return the count."""
    completion = re.search(_NET_FETCHED, transcript)
    first_body = re.search(r"\[http-get\] body hex=([0-9a-f])", transcript)
    refused_fetch = re.search(_NET_REFUSED, transcript)
    typed_error = re.search(r"! type", transcript)
    syntax_error = re.search(r"! syntax", transcript)
    if completion is None or refused_fetch is None or first_body is None or typed_error is None or syntax_error is None:
        fail("net controls need the accepted transcript's completion, body, type and syntax evidence")
    flipped = "0" if first_body[1] != "0" else "1"
    controls = (
        ("missing fetch completion", transcript[:completion.start()] + transcript[completion.end():]),
        ("missing refused completion", transcript[:refused_fetch.start()] + transcript[refused_fetch.end():]),
        ("reordered shell errors", transcript.replace("! type", "\0").replace("! syntax", "! type").replace("\0", "! syntax")),
        ("explicit failure", transcript + "\n[http-get] fail: injected control"),
        ("altered body byte", transcript[:first_body.start(1)] + flipped + transcript[first_body.end(1):]),
        ("extra spawned child", transcript + "\n[spawn-service] spawning child"),
        ("released link", transcript + "\n[network-service] link released"),
    )
    refused = 0
    for label, mutated in controls:
        try:
            judge_net_transcript(mutated, _net_reject)
        except NetRefusal:
            refused += 1
            continue
        fail(f"net control accepted a mutated transcript: {label}")
    return refused


def run_net_arm(image: Path, mac: str, transcript_path: Path | None) -> None:
    identity = http_identity(image, "sel4-net")
    print(identity, flush=True)
    failures = tuple(marker for marker in FAILURE_MARKERS if marker != r"\[http-get\] complete success=0 ")
    terminal = re.compile(_NET_FETCHED + "|" + "|".join(failures))
    ready = tuple(re.compile(pattern) for pattern in NET_READY[0])
    steps = [(ready, NET_CASES[0].line + "\n")]
    for previous, case in zip(NET_CASES, NET_CASES[1:], strict=False):
        steps.append((tuple(re.compile(pattern) for pattern in previous.settle_patterns()), case.line + "\n"))
    netdev = f"user,id=slimenet,net=10.0.2.0/24,host={NET_PEER},dhcpstart=10.0.2.15,ipv6=off"
    try:
        with http_peer.Peer(NET_FETCH) as peer, tempfile.TemporaryDirectory(prefix="slime-net-capture-") as directory:
            capture = Path(directory) / "network.pcap"
            transcript = run_plane(
                image=image, timeout=TIMEOUT, terminal_condition=terminal, fail=fail, pins_path=PINS,
                additional_arguments=(
                    "-netdev", netdev,
                    "-device", f"virtio-net-device,netdev=slimenet,mac={mac}",
                    "-object", f"filter-dump,id=netcapture,netdev=slimenet,file={capture}",
                ),
                input_steps=steps, input_character_delay=0.005,
            )
            if not capture.is_file():
                fail("QEMU did not produce the sel4-net packet observation")
            packets = capture.read_bytes()
        if transcript_path is not None:
            transcript_path.write_text(identity + "\n" + transcript + "\n", encoding="utf-8")
            transcript_path.with_suffix(".pcap").write_bytes(packets)
        peer.qualify()
        # One capture covers the whole session: any DNS/UDP packet, or a SYN to
        # anything but the controlled peer's declared port, is refused here.
        wire = http_capture.verify_capture(packets, hostname=None, resolver=(NET_PEER, http_peer.DNS_PORT), port=http_peer.HTTP_PORT, expected_destination=NET_PEER)
    except (OSError, RuntimeError, ValueError) as error:
        fail(f"sel4-net controlled peer or wire evidence refused: {error}")
    if wire["dns_queries"] != 0 or wire["tcp_connections"] != 1:
        fail(f"sel4-net wire must hold exactly one TCP connection and no DNS, observed {wire}")
    try:
        cases, count = judge_net_transcript(transcript, _net_reject)
    except NetRefusal as error:
        print(transcript)
        fail(str(error))
    refused = net_controls(transcript)
    print(f"[net-wire] frames={wire['frames']} tcp-connections={wire['tcp_connections']} dns-queries={wire['dns_queries']} tcp-payload-bytes={wire['tcp_payload_bytes']}")
    print(f"[net-shell] cases={cases} body-bytes={count} controls-refused={refused}")
    devloop_observations.record(casesObserved=cases, bytesObserved=count, negativeControlsRefused=refused)


def run_zenoh_arm(transcript_path: Path | None) -> None:
    """Boot the two nodes over loopback and judge the exchange from the guest's reports.

    The composition must exist and grant exactly the demo's authority before QEMU
    starts. The batches the nodes report are judged byte for byte against the host
    wire reference, itself proved against the upstream-encoded corpus first. The
    exchange crosses the service's loopback backend, so there is no packet capture:
    this observes the node codecs and session, not the stack's wire.
    """
    contract = zenoh_exchange.demo()
    if not ZENOH_FIXTURE.is_file():
        fail(f"{ZENOH_FIXTURE.relative_to(ROOT)} does not exist; the sel4-zenoh composition has not landed")
    try:
        facts = zenoh_exchange.check_composition_rows(*zenoh_exchange.composition_from_text(ZENOH_FIXTURE.read_text(encoding="utf-8")), contract)
        zenoh_exchange.reference_self_test(ROOT / "components" / "lib" / "src" / "zenoh_profile0" / "vectors.txt")
    except (zenoh_exchange.ExchangeError, zenoh_exchange.zenoh_wire.WireError) as error:
        fail(str(error))
    image = build_image(ZENOH_CLOSURE)
    terminal = re.compile(ZENOH_CHAINS[-1][1][-1] + "|" + "|".join(FAILURE_MARKERS))
    transcript = run_plane(image=image, timeout=TIMEOUT, terminal_condition=terminal, fail=fail, pins_path=PINS)
    if transcript_path is not None:
        transcript_path.write_text(transcript, encoding="utf-8")
    try:
        match_marker_contract(transcript, ZENOH_CHAINS, FAILURE_MARKERS, fail)
    except SystemExit:
        print(transcript)
        raise
    lines = [line.strip() for line in transcript.splitlines() if re.match(r"\[(ros2-demo-publisher|ros2-demo-subscriber|rpi5-ros2-demo)\] ", line.strip())]
    try:
        samples, wire_bytes, denials = zenoh_exchange.judge_transcript(lines, contract)
        controls = zenoh_exchange.transcript_controls(contract)[1] + zenoh_exchange.composition_controls(contract)[1]
    except zenoh_exchange.ExchangeError as error:
        print(transcript)
        fail(str(error))
    print(f"[zenoh-exchange] samples={samples} wire-bytes={wire_bytes} denials={denials} authority-facts={facts} controls-refused={controls}")
    devloop_observations.record(casesObserved=samples, bytesObserved=wire_bytes, negativeControlsRefused=controls)


def http_launch_text(url: str) -> str:
    """Serialize only through the schema-generated launch binding."""
    encoded = url.encode("ascii")
    if not 0 < len(encoded) <= launch.LAUNCH_URL_BYTES:
        fail("HTTP launch URL exceeds its contract bound")
    records: list[str] = []
    for kind, value in ((launch.LAUNCH_SEED, os.urandom(32)), (launch.LAUNCH_URL, encoded)):
        for offset in range(0, len(value), launch.LAUNCH_PAYLOAD_BYTES):
            chunk = value[offset:offset + launch.LAUNCH_PAYLOAD_BYTES]
            frame = launch.NETWORK_LAUNCH.pack(
                launch.NETWORK_MAGIC, launch.FORMAT_VERSION, kind, 0,
                len(value), offset, len(chunk), b"\0" * 2,
                chunk.ljust(launch.LAUNCH_PAYLOAD_BYTES, b"\0"),
            )
            records.append(frame.hex() + "\n")
    return "".join(records)


def check_http_body(transcript: str, case: http_peer.Case | None) -> tuple[int, int]:
    body = bytearray()
    complete = []
    cleanup = []
    cleanup_record = (
        "[http-get] cleanup close=0 detach=1 abort=1"
        if case is not None and case.error != "none" else "[http-get] cleanup close=1 detach=1"
    )
    for number, line in enumerate(transcript.splitlines()):
        if line.startswith("[http-get] body "):
            match = re.fullmatch(r"\[http-get\] body hex=([0-9a-f]{2,128})", line)
            if match is None or len(match[1]) % 2 or cleanup or complete:
                fail("malformed, oversized, or reordered HTTP body record")
            body.extend(bytes.fromhex(match[1]))
            if len(body) > 1024 * 1024:
                fail("HTTP console body exceeds the client body bound")
        if line.startswith("[http-get] cleanup "):
            if line != cleanup_record or cleanup or complete:
                fail("HTTP cleanup failed, was duplicated, or was reordered")
            cleanup.append(number)
        if line.startswith("[http-get] complete "):
            match = re.fullmatch(r"\[http-get\] complete success=([01]) status=([0-9]+) bytes=([0-9]+) error=([a-z-]+)", line)
            if match is None or complete or not cleanup:
                fail("malformed, duplicate, or premature HTTP completion")
            complete.append(match)
    if len(complete) != 1 or len(cleanup) != 1:
        fail("HTTP completion or cleanup evidence is absent")
    result = complete[0]
    status, count = int(result[2]), int(result[3])
    if count != len(body):
        fail("HTTP byte count disagrees with independently decoded console body")
    expected_error = case.error if case is not None else "none"
    if result[1] != str(int(expected_error == "none")) or result[4] != expected_error:
        fail(f"unexpected HTTP completion: {result[0]}")
    if case is not None and (status != case.status or bytes(body) != case.body):
        fail(f"{case.name}: HTTP status/body differs from the independent server fixture")
    if case is None and not 200 <= status <= 599:
        fail("public HTTP completion has no final response status")
    return status, count


def http_identity(image: Path, case: str) -> str:
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True))
    return (f"[http-observation] target=aarch64-sel4-qemu-virt revision={revision} "
            f"dirty={int(dirty)} image-sha256={sha256_file(image, fail)} case={case}")


def run_http_request(image: Path, url: str, *, expected_failure: bool = False, default_port_forward: bool = False) -> tuple[str, bytes]:
    failures = tuple(marker for marker in FAILURE_MARKERS if marker not in (
        r"\[http-get\] complete success=0 ",
    )) if expected_failure else FAILURE_MARKERS
    terminal = re.compile(r"SLIME_GRAPH HEALTHY generation=(?:159|160) required=4 live=0 completed=4 failed=0|" + "|".join(failures))
    netdev = "user,id=slimehttp,net=10.0.2.0/24,host=10.0.2.2,dhcpstart=10.0.2.15,ipv6=off"
    if default_port_forward:
        # QEMU forwards the byte stream; the guest still performs DNS and HTTP.
        # This controlled-only endpoint avoids privileged host port 80 listeners.
        relay = shlex.join((sys.executable, str(ROOT / "scripts/lib/http_peer.py"), "--relay"))
        netdev += f",guestfwd=tcp:10.0.2.100:80-cmd:{relay}"
    with tempfile.TemporaryDirectory(prefix="slime-http-capture-") as directory:
        capture = Path(directory) / "network.pcap"
        transcript = run_plane(
            image=image, timeout=TIMEOUT, terminal_condition=terminal, fail=fail, pins_path=PINS,
            additional_arguments=(
                "-netdev", netdev,
                "-device", "virtio-net-device,netdev=slimehttp,mac=52:54:00:53:4c:01",
                "-object", f"filter-dump,id=httpcapture,netdev=slimehttp,file={capture}",
            ),
            input_trigger=re.compile(r"\[http-launcher\] ready"), input_text=http_launch_text(url),
        )
        if not capture.is_file():
            fail("QEMU did not produce the HTTP/DNS packet observation")
        packets = capture.read_bytes()
    for pattern in failures:
        if re.search(pattern, transcript):
            print(transcript)
            fail(f"HTTP run contains failure evidence {pattern!r}")
    return transcript, packets


def run_http_arm(image: Path, transcript_path: Path | None, selected_case: str | None) -> None:
    selected = [case for case in http_peer.cases() if selected_case is None or case.name == selected_case]
    if not selected:
        fail(f"unknown HTTP case {selected_case!r}")
    observations: list[str] = []
    for case in selected:
        print(f"[http-check] starting {case.name}", flush=True)
        try:
            with http_peer.Peer(case) as peer:
                transcript, packets = run_http_request(image, case.url, expected_failure=case.error != "none", default_port_forward=case.port == 80)
            identity = http_identity(image, case.name)
            if transcript_path is not None:
                transcript_path.write_text("\n".join(observations + [identity + "\n" + transcript]) + "\n", encoding="utf-8")
                transcript_path.with_suffix(f".{case.name}.pcap").write_bytes(packets)
            peer.qualify()
            wire = http_capture.verify_capture(
                packets, hostname=None if case.host == "10.0.2.2" or not case.attached else case.host,
                resolver=("10.0.2.2", http_peer.DNS_PORT), port=case.port,
                expected_destination=case.destination, expect_connect=case.expect_request,
                expect_no_application_traffic=not case.attached,
            )
        except (OSError, RuntimeError, ValueError) as error:
            fail(f"{case.name}: controlled HTTP/DNS peer unavailable or invalid: {error}")
        status, count = check_http_body(transcript, case)
        if case.error == "none":
            match_marker_contract(transcript, HTTP_CHAINS, FAILURE_MARKERS, fail)
        else:
            failure_chains = tuple(
                (name, tuple(
                    marker.replace("success=1", "success=0")
                    .replace("error=none", f"error={case.error}")
                    .replace("cleanup close=1 detach=1", "cleanup close=0 detach=1 abort=1")
                    .replace("application buffers released", f"application aborted sessions_released={int(case.attached)}")
                    for marker in markers
                )) for name, markers in HTTP_CHAINS
            )
            expected_failures = tuple(marker for marker in FAILURE_MARKERS if marker != r"\[http-get\] complete success=0 ")
            match_marker_contract(transcript, failure_chains, expected_failures, fail)
        identity = http_identity(image, case.name)
        summary = (f"[http-peer] case={case.name} dns-queries={len(peer.queries)} "
                   f"http-requests={len(peer.requests)} status={status} bytes={count} "
                   f"expected-error={case.error} body-identical=1")
        peer_records = "\n".join(
            [f"[http-peer] DNS name={name} id={query_id} source-port={source_port}" for name, query_id, source_port in peer.queries]
            + [f"[http-peer] request={request!r}" for request in peer.requests]
        )
        wire_record = f"[http-wire] frames={wire['frames']} dns-queries={wire['dns_queries']} selected={wire['selected']} tcp-connections={wire['tcp_connections']} tcp-payload-bytes={wire['tcp_payload_bytes']}"
        observations.append(identity + "\n" + transcript + "\n" + peer_records + "\n" + wire_record + "\n" + summary)
        if transcript_path is not None:
            transcript_path.write_text("\n".join(observations) + "\n", encoding="utf-8")
        print(identity)
        print(peer_records)
        print(wire_record)
        print(summary)
    print(f"seL4 HTTP check: {len(selected)} controlled ordinary host-stack cases passed")


def run_http_public_arm(image: Path, transcript_path: Path | None) -> None:
    identity = http_identity(image, "public-example.com")
    print(identity, flush=True)
    transcript, packets = run_http_request(image, "http://example.com/")
    if transcript_path is not None:
        transcript_path.write_text(identity + "\n" + transcript + "\n", encoding="utf-8")
        transcript_path.with_suffix(".pcap").write_bytes(packets)
    match_marker_contract(transcript, HTTP_CHAINS, FAILURE_MARKERS, fail)
    status, count = check_http_body(transcript, None)
    # DNS is performed inside network-service. Public results cannot be supplied
    # by the controlled peer or the host resolver.
    answers = re.findall(r"\[network-service\] DNS name=example\.com answer=([0-9.]+) ttl=[1-9][0-9]*", transcript)
    selected = re.findall(r"\[network-service\] DNS name=example\.com selected=([0-9.]+) port=80 attempt=[1-4]", transcript)
    if not answers or not selected or any(address not in answers for address in selected):
        fail("public HTTP observation lacks validated guest DNS answers and selected-address evidence")
    try:
        wire = http_capture.verify_capture(packets, hostname="example.com", resolver=("1.1.1.1", 53), port=80)
    except ValueError as error:
        fail(str(error))
    if set(selected) != set(wire["selected"]):
        fail("guest-selected DNS addresses differ from independently observed TCP SYN destinations")
    summary = (f"[http-public] name=example.com answers={wire['answers']} selected={wire['selected']} "
               f"dns-queries={wire['dns_queries']} dns-responses={wire['dns_responses']} "
               f"status={status} bytes={count} completion=1 cleanup=1")
    if transcript_path is not None:
        transcript_path.write_text(identity + "\n" + transcript + "\n" + summary + "\n", encoding="utf-8")
    print(transcript)
    print(summary)


def main() -> None:
    parser = argparse.ArgumentParser(description="Boot and check the seL4 I/O network proof planes")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--arm", choices=("authority", "tcp", "local", "lifetime", "service-fault", "driver-reset", "tcp-impairment", "tcp-listener", "tcp-options", "net", "zenoh", "http", "http-public", "all"), default="all")
    parser.add_argument("--allow-public", action="store_true", help="explicitly authorize the opt-in public DNS/HTTP smoke")
    parser.add_argument("--http-case", choices=tuple(case.name for case in http_peer.cases()))
    parser.add_argument(
        "--transcript",
        type=Path,
        help="write the tcp arm's serial transcript and peer summary to this file",
    )
    arguments = parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        fail(f"run from repository root: {ROOT}")
    if arguments.arm == "http-public" and not arguments.allow_public:
        fail("public HTTP requires explicit --allow-public; unavailable public access is not a pass")
    if arguments.http_case is not None and arguments.arm != "http":
        fail("--http-case requires --arm http")
    if arguments.arm == "http":
        run_http_arm(build_image("sel4-http"), arguments.transcript, arguments.http_case)
    if arguments.arm == "http-public":
        run_http_public_arm(build_image("sel4-http-public"), arguments.transcript)
    if arguments.arm == "tcp-impairment":
        mac, retry_limits = check_impairment_fixture()
        run_impairment_arm(build_image(IMPAIRMENT_CLOSURE), mac, retry_limits, arguments.transcript)
        print(
            "seL4 I/O tcp impairment check: reassembly within and refusal beyond the declared out-of-order capacity, "
            "loss and duplicate-ACK recovery within the declared retry limit and time, typed silent-peer timeout "
            "with reclamation and a fresh exchange, and bounded zero-window behavior in both directions proved"
        )
    if arguments.arm == "tcp-listener":
        mac = check_listener_fixture()
        run_listener_arm(build_image(LISTENER_CLOSURE), mac, arguments.transcript)
        print(
            "seL4 I/O tcp listener check: an exact external listener accepting only its admitted peer, "
            "silent unadmitted SYNs, single-reset backlog and accepted-limit refusals, half-close in both "
            "directions, simultaneous close, reset on unread close, FIN after unsent data, and numeric "
            "reclamation proved"
        )
    if arguments.arm == "tcp-options":
        mac, limits = check_options_fixture()
        run_options_arm(build_image(OPTIONS_CLOSURE), mac, limits, arguments.transcript)
        print(
            "seL4 I/O tcp options check: per-binding Nagle, keep-alive, hop limit and idle timeout declared "
            "in generation data and observed on the wire, Reno selected and stated, a client mutation refused, "
            "and both mute connections reclaimed by typed timeout proved"
        )
    if arguments.arm == "net":
        mac = check_net_fixture()
        run_net_arm(build_image(NET_CLOSURE), mac, arguments.transcript)
        print(
            "seL4 net check: the resident shell spawned http-get with a string argument through spawn-service, "
            "the fetched body matched the controlled peer, undeclared destinations, hostnames, stray strings "
            "and unbound commands were refused without forbidden packets, and the network service stayed resident"
        )
    if arguments.arm in ("authority", "all"):
        check_fixture()
        image = build_image(CLOSURE) if not arguments.no_build else IMAGE
        if image is None:
            fail("--no-build needs a previously built image")
        run_authority_arm(image)
        print(
            "seL4 I/O network plane check: exact authority, per-destination budgets, "
            "structured denials, and honest backend absence proved"
        )
    if arguments.arm in ("driver-reset", "all"):
        image = build_image("sel4-io-driver-reset-in-flight")
        run_tcp_arm(image, "52:54:00:53:4c:01", arguments.transcript, driver_reset=True)
        print("seL4 I/O driver reset check: actual in-flight virtio-net reset, typed settlement, supervised restart and fresh external bytes proved")
    if arguments.arm in ("service-fault", "all"):
        image = build_image("sel4-io-service-fault-in-flight")
        terminal = re.compile(r"SLIME_GRAPH HEALTHY generation=157 required=2 live=0 completed=2 failed=0|" + "|".join(FAILURE_MARKERS))
        transcript = run_plane(image=image, timeout=TIMEOUT, terminal_condition=terminal, fail=fail, pins_path=PINS)
        if arguments.transcript is not None:
            arguments.transcript.write_text(transcript, encoding="utf-8")
        try:
            match_marker_contract(transcript, SERVICE_FAULT_CHAINS, FAILURE_MARKERS, fail)
        except SystemExit:
            print(transcript)
            raise
        print("seL4 I/O service fault check: in-flight service fault, client invalidation and fresh-incarnation recovery proved")
    if arguments.arm in ("lifetime", "all"):
        image = build_image("sel4-io-lifetime")
        terminal = re.compile(r"SLIME_GRAPH HEALTHY generation=156 required=2 live=0 completed=2 failed=0|" + "|".join(FAILURE_MARKERS))
        transcript = run_plane(image=image, timeout=TIMEOUT, terminal_condition=terminal, fail=fail, pins_path=PINS)
        if arguments.transcript is not None:
            arguments.transcript.write_text(transcript, encoding="utf-8")
        try:
            match_marker_contract(transcript, LIFETIME_CHAINS, FAILURE_MARKERS, fail)
        except SystemExit:
            print(transcript)
            raise
        print("seL4 I/O lifetime plane check: actual client fault, interrupted receive reset, buffer reclamation and fresh-incarnation traffic proved")
    if arguments.arm in ("local", "all"):
        image = build_image("sel4-io-local")
        terminal = re.compile(LOCAL_CHAINS[-1][1][-1] + "|" + "|".join(FAILURE_MARKERS))
        transcript = run_plane(image=image, timeout=TIMEOUT, terminal_condition=terminal, fail=fail, pins_path=PINS)
        if arguments.transcript is not None:
            arguments.transcript.write_text(transcript, encoding="utf-8")
        try:
            match_marker_contract(transcript, LOCAL_CHAINS, FAILURE_MARKERS, fail)
        except SystemExit:
            print(transcript)
            raise
        print("seL4 I/O local plane check: real TCP listen/connect/accept, independent bidirectional bytes, EOF and normal teardown without a NIC proved")
    if arguments.arm == "zenoh":
        run_zenoh_arm(arguments.transcript)
        print("seL4 zenoh plane check: two nodes exchanged four samples over one Zenoh Profile 0 session, byte-exact against the host reference, with exactly the declared authority and every denial observed")
    if arguments.arm in ("tcp", "all"):
        mac = check_tcp_fixture()
        image = build_image(TCP_CLOSURE)
        run_tcp_arm(image, mac, arguments.transcript)
        print(
            "seL4 I/O tcp plane check: exact 4096-byte TCP echo and graceful close, "
            "refused-port reset, no forbidden egress, ARP/ICMP replies, "
            "and clean virtio-net link release proved"
        )


if __name__ == "__main__":
    main()
