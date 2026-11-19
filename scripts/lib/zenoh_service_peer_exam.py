"""Judge that a peer which subscribes receives what a holder publishes through the Zenoh service, once.

The booted composition `sel4-zenoh-service` runs the service, a peer and two holders. This module judges one claim: the
peer declares a subscriber on the key `alpha` may publish, and each of `alpha`'s four publications crosses to the peer
exactly once. It judges the lines of the service and the lines of the peer, and no other component's lines.

The holders' side of the exchange stays with `zenoh_service_arm`. This judge runs that judge on the service's lines first,
so a holder that is not delivered a sample, or a publication that reaches the wrong number of holders, is refused there.

The facts the files must hold are read by pattern and checked first against a synthetic file set, as in
`zenoh_service_component_exam`. The lines come from the guest, so the judge is trusted only after it refuses a mutation
of an honest transcript.
"""

from __future__ import annotations

import re

import zenoh_facts as facts
import zenoh_service_arm as arm
from harness import ROOT

SYSTEM = "contracts/system-spec/v1/systems/sel4-zenoh-service.zti"
PEER_SPEC = "contracts/component-spec/v1/components/zenoh-peer.zti"
PEER = "components/applications/zenoh-peer/src/main.rs"
KEY = "0/slime_service/exchange"
PEER_NAME = "zenoh-peer"
PAYLOAD_BYTES = 12

OPEN = re.compile(rf"\[{PEER_NAME}\] session open")
DECLARED = re.compile(rf"\[{PEER_NAME}\] declared subscriber key=(\S+)")
RECEIVED = re.compile(rf"\[{PEER_NAME}\] received sequence=(\d+) len=(\d+) first=(\d+)")
CLOSED = re.compile(rf"\[{PEER_NAME}\] session closed")
PEER_KINDS = (OPEN, DECLARED, RECEIVED, CLOSED)

FACTS: tuple[facts.Fact, ...] = (
    ("spec-key", SYSTEM, rf'\bholder = "{arm.PUBLISHER}"; key = "{re.escape(KEY)}"; publish = true;',
     f'    {{ holder = "{arm.PUBLISHER}"; key = "{KEY}"; publish = true; subscribe = false; }};'),
    ("spec-names-peer", SYSTEM, r'^\s*acceptanceCriteria = "[^"\n]*\bpeer\b[^"\n]*\breceives\b',
     '  acceptanceCriteria = "The peer receives each publication of the publisher holder.";'),
    ("peer-declares", PEER, r"\.declare_subscriber\(", "                link.declare_subscriber(handle, 1, KEY)?;"),
    ("peer-reads-sample", PEER, r"\bNotice::SampleDelivered\((?!_)", "                    Notice::SampleDelivered(sample) => {"),
    ("peer-spec-purpose", PEER_SPEC, r'^\s*purpose = "[^"\n]*\bsubscribes to the exchange key\b', '  purpose = "Listens on 127.0.0.1:7447, subscribes to the exchange key, and closes.";'),
    ("peer-prints-receipt", PEER, r'b"\[zenoh-peer\] received sequence="', '    .bytes(b"[zenoh-peer] received sequence=")'),
)


class PeerExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise PeerExamError(message)


def _read(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        raise PeerExamError(f"{path} cannot be read: {error}") from error


def check_facts() -> int:
    try:
        return facts.check(FACTS, _read)
    except facts.FactsError as error:
        raise PeerExamError(str(error)) from error


def fact_controls() -> int:
    try:
        return facts.controls(FACTS)
    except facts.FactsError as error:
        raise PeerExamError(str(error)) from error


def synthesize() -> list[str]:
    """What an honest run prints: the service's lines with the peer's copy sent, and the peer's lines."""
    service = [line.replace("peer=none", "peer=sent") for line in arm.synthesize()]
    peer = [f"[{PEER_NAME}] session open", f"[{PEER_NAME}] declared subscriber key={KEY}"]
    peer += [f"[{PEER_NAME}] received sequence={n} len={PAYLOAD_BYTES} first={n}" for n in range(arm.SAMPLES)]
    peer.append(f"[{PEER_NAME}] session closed")
    return service + peer


def judge(lines: list[str]) -> tuple[int, int]:
    """Check both components' lines. Returns (subscriber declarations, samples the peer received)."""
    service = [line for line in lines if line.startswith(f"[{arm.SERVICE}] ")]
    peer = [line for line in lines if line.startswith(f"[{PEER_NAME}] ")]
    _need(len(service) + len(peer) == len(lines), "a line that belongs to neither the service nor the peer")
    try:
        arm.judge(service)
    except arm.ArmError as error:
        raise PeerExamError(str(error)) from error

    for line in peer:
        _need(any(kind.fullmatch(line) for kind in PEER_KINDS), f"{PEER_NAME}: a line that is not one of the exam's lines: {line!r}")
    opened = [i for i, line in enumerate(peer) if OPEN.fullmatch(line)]
    declared = [i for i, line in enumerate(peer) if DECLARED.fullmatch(line)]
    closed = [i for i, line in enumerate(peer) if CLOSED.fullmatch(line)]
    received = [i for i, line in enumerate(peer) if RECEIVED.fullmatch(line)]
    _need(len(opened) == 1, f"{PEER_NAME}: {len(opened)} session open lines, expected exactly one")
    _need(len(declared) == 1, f"{PEER_NAME}: {len(declared)} subscriber declarations, expected exactly one")
    _need(len(closed) == 1, f"{PEER_NAME}: {len(closed)} session closed lines, expected exactly one")
    _need(opened[0] < declared[0], f"{PEER_NAME}: it declared a subscriber before its session opened")
    _need(all(declared[0] < i < closed[0] for i in received), f"{PEER_NAME}: a sample outside the span between its declaration and its close")
    declared_key = DECLARED.fullmatch(peer[declared[0]]).group(1)
    _need(declared_key == KEY, f"{PEER_NAME}: it declared {declared_key!r}, not the key alpha may publish")

    seen: list[int] = []
    for i in received:
        m = RECEIVED.fullmatch(peer[i])
        sequence, length, first = int(m.group(1)), int(m.group(2)), int(m.group(3))
        _need(length == PAYLOAD_BYTES, f"{PEER_NAME}: sequence {sequence} arrived with {length} bytes, alpha writes {PAYLOAD_BYTES}")
        _need(first == sequence % 256, f"{PEER_NAME}: sequence {sequence} arrived with first byte {first}, alpha writes {sequence % 256}")
        _need(sequence not in seen, f"{PEER_NAME}: sequence {sequence} arrived twice")
        _need(not seen or sequence > seen[-1], f"{PEER_NAME}: sequence {sequence} arrived out of order")
        seen.append(sequence)

    delivered_to = [m.group(1) for line in service if (m := arm.DELIVERED.fullmatch(line))]
    _need(delivered_to == [arm.SUBSCRIBER] * arm.SAMPLES, f"{arm.SERVICE}: deliveries went to {delivered_to}, expected {arm.SAMPLES} to {arm.SUBSCRIBER}")
    published = [m for line in service if (m := arm.PUBLISHED.fullmatch(line)) and m.group(1) == arm.PUBLISHER]
    sequences = [int(m.group(3)) for m in published]
    _need(all(m.group(5) == "sent" for m in published), f"{arm.SERVICE}: a publication by {arm.PUBLISHER} that did not report peer=sent")
    _need(seen == sequences, f"{PEER_NAME}: it received sequences {seen}, and {arm.PUBLISHER} published {sequences}")
    return len(declared), len(received)


def mutations() -> list[tuple[str, list[str]]]:
    good = synthesize()
    first_publication = next(i for i, line in enumerate(good) if "published holder=" in line)
    first_peer = next(i for i, line in enumerate(good) if line.startswith(f"[{PEER_NAME}]"))
    declared = first_peer + 1
    first_receipt = first_peer + 2
    closed = len(good) - 1

    def swapped(a: int, b: int) -> list[str]:
        out = list(good)
        out[a], out[b] = out[b], out[a]
        return out

    def edited(index: int, old: str, new: str) -> list[str]:
        return [line.replace(old, new) if i == index else line for i, line in enumerate(good)]

    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line of another component", [*good, "[zenoh-holder] attached"]),
        ("a peer line the exam does not list", [*good[:closed], f"[{PEER_NAME}] resumed", good[closed]]),
        ("a peer failure line", [*good[:closed], f"[{PEER_NAME}] fail: unexpected sample", good[closed]]),
        ("a second session open", [good[first_peer], *good]),
        ("a subscriber declared twice", [*good[:declared + 1], good[declared], *good[declared + 1:]]),
        ("a subscriber declared before the session opened", swapped(first_peer, declared)),
        ("a subscriber declared on another key", edited(declared, KEY, "0/slime_service/other")),
        ("a subscriber declared on a prefix of the key", edited(declared, KEY, KEY[:-1])),
        ("a sample before the declaration", swapped(declared, first_receipt)),
        ("a sample after the close", swapped(closed, closed - 1)),
        ("a sample received twice", [*good[:first_receipt + 1], good[first_receipt], *good[first_receipt + 1:]]),
        ("a fifth sample", [*good[:closed], f"[{PEER_NAME}] received sequence=4 len={PAYLOAD_BYTES} first=4", good[closed]]),
        ("samples out of order", swapped(first_receipt + 1, first_receipt + 2)),
        ("a sample of a sequence alpha did not publish", edited(first_receipt + 3, "sequence=3 len=12 first=3", "sequence=9 len=12 first=9")),
        ("a sample with the wrong length", edited(first_receipt, "len=12", "len=11")),
        ("a sample with the wrong payload", edited(first_receipt + 1, "first=1", "first=7")),
        ("a peer copy reported as none for one publication", edited(first_publication, "peer=sent", "peer=none")),
        ("a peer copy reported as none for every publication", [line.replace("peer=sent", "peer=none") for line in good]),
        ("one delivery to alpha instead of beta", edited(first_publication + 1, "delivered holder=beta", "delivered holder=alpha")),
        ("every delivery to alpha instead of beta", [line.replace("delivered holder=beta", "delivered holder=alpha") for line in good]),
        ("a delivery to beta missing", [line for line in good if "delivered holder=beta row=0 sequence=2" not in line]),
        ("a publication that reached two holders", edited(first_publication, "reached=1", "reached=2")),
    ]
    for index in range(first_peer, len(good)):
        out.append((f"peer line {index - first_peer + 1} ({good[index][12:60]}) missing", good[:index] + good[index + 1:]))
    return out


def controls() -> int:
    """The honest transcript is accepted. Every mutation of it is refused. Returns the number refused."""
    good = synthesize()
    _need(judge(good) == (1, arm.SAMPLES), f"{PEER_NAME}: the honest transcript was not accepted")
    refused = 0
    for label, lines in mutations():
        _need(lines != good, f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except PeerExamError:
            refused += 1
            continue
        raise PeerExamError(f"control: the peer judge accepted {label}")
    return refused
