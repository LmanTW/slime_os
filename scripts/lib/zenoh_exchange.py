"""Judge the R0 Zenoh Profile 0 exchange from evidence, without trusting the guest's codec.

Two judges share the frozen demo contract (`contracts/rpi5-ros2-demo/v2`):

* `check_composition_rows` decides whether a derived composition grants the demo's
  two nodes exactly the declared authority: one connect destination, one admitted
  loopback listener, nothing else.
* `judge_transcript` decides whether a serial transcript shows the four declared
  samples crossing the session, byte-exact against `zenoh_wire`, the host
  reference written independently of the Rust codec.

Both are pure functions over text and rows, so `synthesize_*` builds the evidence
an honest guest would produce and each control mutates it. A judge is trusted only
after it refuses every mutation.

Limit, stated where it cannot be skipped: the exchange runs over the network
service's loopback backend, so no NIC or packet capture exists. The batches judged
are the ones the nodes report handing to `send` and receiving from `recv`, which is
the application boundary of the service. That observes the node codecs and the
session; it does not observe the loopback stack's bytes.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import zenoh_wire
from harness import ROOT

DEMO_FIXTURE = ROOT / "contracts" / "rpi5-ros2-demo" / "v2" / "fixtures" / "valid.zti"
GENERATION = 168
CLOSURE = "sel4-zenoh"
PUBLISHER = "ros2-demo-publisher"
SUBSCRIBER = "ros2-demo-subscriber"
INSTANCES = ("init", "network-service", PUBLISHER, SUBSCRIBER)
DENIALS = (
    (PUBLISHER, "undeclared-endpoint"),
    (PUBLISHER, "listen"),
    (PUBLISHER, "scouting"),
    (SUBSCRIBER, "connect"),
)
SUCCESS = "[rpi5-ros2-demo] success profile=rpi5-ros2-demo-v2 samples=4"
RECEIVED = "[rpi5-ros2-demo] received count=4 sequences=0,1,2,3 values=10,20,30,40"


class ExchangeError(ValueError):
    """Evidence the judge refuses."""


# --------------------------------------------------------------------- contract


def demo() -> dict:
    """The demo contract values the exchange is judged against."""
    text = DEMO_FIXTURE.read_text()

    def one(pattern: str) -> str:
        found = re.findall(pattern, text)
        if len(found) != 1:
            raise ExchangeError(f"demo contract: {pattern!r} matched {len(found)} times")
        return found[0]

    samples = [
        (int(s), int(v), h)
        for s, v, h in re.findall(r"sequence = (\d+);\s*value = (\d+);\s*cdrHex = \"([0-9a-f]+)\";", text)
    ]
    if [s for s, _, _ in samples] != [0, 1, 2, 3]:
        raise ExchangeError("demo contract no longer declares samples 0 to 3 in order")
    return {
        "key": one(r'dataKeyexpr = "([^"]+)"'),
        "address": one(r'address = "([0-9.]+)";\s*port = \d+;\s*direction = "connect"'),
        "port": int(one(r'address = "[0-9.]+";\s*port = (\d+);\s*direction = "connect"')),
        "samples": samples,
    }


# ------------------------------------------------------------------ composition


def parse_rows(text: str, section: str) -> list[dict]:
    """Records of one top-level list in a derived composition manifest.

    The derived format indents a top-level list's records by four spaces and their
    fields by six, which is the only structure this reads; nested lists are
    returned as text.
    """
    start = re.search(rf"^  {re.escape(section)} = \[\]?;?\s*$", text, re.M)
    if start is None:
        raise ExchangeError(f"composition has no {section} section")
    if text[start.start() : start.end()].rstrip().endswith("[];"):
        return []
    end = text.index("\n  ];", start.end())
    body = text[start.end() : end]
    rows = []
    for record in re.split(r"\n    \};?\n?", body):
        fields: dict[str, object] = {}
        lines = record.split("\n")
        i = 0
        while i < len(lines):
            m = re.match(r"^      (\w+) = (.*)$", lines[i])
            if m:
                key, value = m.groups()
                if value.rstrip(";") == "[]":
                    fields[key] = []
                elif value == "[":
                    items = []
                    i += 1
                    while not lines[i].startswith("      ];"):
                        items.append(lines[i].strip().rstrip(";").strip('"'))
                        i += 1
                    fields[key] = items
                else:
                    value = value.rstrip(";")
                    if value.startswith('"'):
                        fields[key] = value.strip('"')
                    elif value in ("true", "false"):
                        fields[key] = value == "true"
                    elif re.fullmatch(r"-?\d+", value):
                        fields[key] = int(value)
                    else:
                        fields[key] = value
            i += 1
        if fields:
            rows.append(fields)
    return rows


def check_composition_rows(generation: int, instances: list[str], destinations: list[dict], applications: list[dict], contract: dict) -> int:
    """Refuse a composition that grants more or less than the demo declares.

    Returns the number of authority facts verified.
    """
    facts = 0

    def need(condition: bool, message: str) -> None:
        nonlocal facts
        if not condition:
            raise ExchangeError(message)
        facts += 1

    need(generation == GENERATION, f"generation {generation}, the plane pins {GENERATION}")
    need(sorted(instances) == sorted(INSTANCES), f"instances {sorted(instances)}, expected {sorted(INSTANCES)}")
    need(len(destinations) == 1, f"{len(destinations)} destination rows, the demo declares one connect endpoint")
    row = destinations[0]
    need(row.get("holder") == PUBLISHER, "the connect destination is not held by the publisher")
    need((row.get("address"), row.get("port")) == (contract["address"], contract["port"]), "the destination is not the demo's endpoint")
    need(row.get("transport") == "tcp" and row.get("addressKind") == "ipv4", "the destination is not exact IPv4 TCP")
    need(sorted(row.get("rights", [])) == ["connect", "recv", "send"], "the destination rights are not exactly connect, send, recv")
    need(row.get("listenerLimit") == 0 and row.get("dnsRecordLimit") == 0, "the destination grants listen or DNS authority")
    roles = {a.get("holder"): a for a in applications}
    need(sorted(roles) == sorted([PUBLISHER, SUBSCRIBER]) and len(applications) == 2, "applications are not exactly the two nodes")
    pub, sub = roles[PUBLISHER], roles[SUBSCRIBER]
    need(pub.get("role") == "client" and pub.get("rights") == [], "the publisher is not a rightless client")
    need(sub.get("role") == "listener" and sorted(sub.get("rights", [])) == ["listen", "recv", "send"], "the subscriber is not exactly the listener")
    need(sub.get("localAddress") == contract["address"] and sub.get("localPort") == contract["port"], "the listener is not bound to the demo endpoint")
    need(sub.get("localAddress") not in ("0.0.0.0", ""), "the listener is a wildcard bind")
    need(sub.get("admittedPeer") == PUBLISHER and sub.get("admittedPeerAddress") == "", "the listener does not admit exactly the publisher holder")
    need(pub.get("backend") == sub.get("backend") == "loopback", "a node uses a backend other than loopback")
    return facts


def composition_mutations(good: tuple) -> list[tuple[str, Callable[[tuple], tuple]]]:
    def edit(index: int, change: Callable[[object], object]) -> Callable[[tuple], tuple]:
        def run(value: tuple) -> tuple:
            copy = [list(x) if isinstance(x, list) else x for x in value]
            copy[index] = [dict(r) if isinstance(r, dict) else r for r in copy[index]] if isinstance(copy[index], list) else copy[index]
            copy[index] = change(copy[index])
            return tuple(copy)

        return run

    def dest(change: Callable[[dict], None]) -> Callable[[tuple], tuple]:
        def inner(rows: list) -> list:
            change(rows[0])
            return rows

        return edit(2, inner)

    def app(holder: str, change: Callable[[dict], None]) -> Callable[[tuple], tuple]:
        def inner(rows: list) -> list:
            change(next(r for r in rows if r["holder"] == holder))
            return rows

        return edit(3, inner)

    return [
        ("a different generation", edit(0, lambda g: g + 1)),
        ("an extra instance", edit(1, lambda i: i + ["zenoh-router"])),
        ("a missing instance", edit(1, lambda i: i[:-1])),
        ("a second destination", edit(2, lambda d: d + [dict(d[0], port=7448)])),
        ("another port", dest(lambda r: r.update(port=7448))),
        ("another address", dest(lambda r: r.update(address="10.0.0.2"))),
        ("a udp destination", dest(lambda r: r.update(transport="udp"))),
        ("a missing right", dest(lambda r: r.update(rights=["connect", "send"]))),
        ("a listen limit on the destination", dest(lambda r: r.update(listenerLimit=1))),
        ("a resolver record", dest(lambda r: r.update(dnsRecordLimit=1))),
        ("a wildcard listener", app(SUBSCRIBER, lambda r: r.update(localAddress="0.0.0.0"))),
        ("a listener admitting nobody", app(SUBSCRIBER, lambda r: r.update(admittedPeer=""))),
        ("a listener admitting an address", app(SUBSCRIBER, lambda r: r.update(admittedPeerAddress="10.0.0.2"))),
        ("a publisher with rights", app(PUBLISHER, lambda r: r.update(rights=["listen"]))),
        ("an external backend", app(PUBLISHER, lambda r: r.update(backend="external"))),
    ]


def good_composition(contract: dict) -> tuple:
    destinations = [
        {
            "holder": PUBLISHER, "transport": "tcp", "addressKind": "ipv4", "address": contract["address"],
            "port": contract["port"], "rights": ["connect", "send", "recv"], "listenerLimit": 0, "dnsRecordLimit": 0,
        }
    ]
    applications = [
        {"holder": PUBLISHER, "role": "client", "backend": "loopback", "rights": [], "localAddress": "0.0.0.0", "localPort": 0,
         "admittedPeer": "", "admittedPeerAddress": ""},
        {"holder": SUBSCRIBER, "role": "listener", "backend": "loopback", "rights": ["listen", "send", "recv"],
         "localAddress": contract["address"], "localPort": contract["port"], "admittedPeer": PUBLISHER, "admittedPeerAddress": ""},
    ]
    return (GENERATION, list(INSTANCES), destinations, applications)


def composition_controls(contract: dict) -> tuple[int, int]:
    """Judge the honest composition, then refuse every mutation. Returns (facts, refused)."""
    good = good_composition(contract)
    facts = check_composition_rows(*good, contract)
    refused = 0
    for label, mutate in composition_mutations(good):
        try:
            check_composition_rows(*mutate(good), contract)
        except ExchangeError:
            refused += 1
            continue
        raise ExchangeError(f"control: composition judge accepted {label}")
    return facts, refused


def composition_from_text(text: str) -> tuple:
    generation = re.search(r"^  generation = (\d+);", text, re.M)
    if generation is None:
        raise ExchangeError("composition declares no generation")
    names = [row["name"] for row in parse_rows(text, "instances")]
    return (int(generation.group(1)), names, parse_rows(text, "networkDestinations"), parse_rows(text, "networkApplications"))


# ------------------------------------------------------------------- transcript

GID = bytes(range(0xE0, 0xF0))
TIMESTAMP = 1000


def synthesize_transcript(contract: dict) -> list[str]:
    """What an honest pair of nodes prints, with batches from the reference encoder."""
    key = contract["key"]
    lines = [
        f"[{PUBLISHER}] session open role=connector initial_sn=0 lease_ms=2000",
        f"[{SUBSCRIBER}] session open role=listener initial_sn=0 lease_ms=2000",
        f"[{SUBSCRIBER}] declared subscriber id=1 key={key}",
        f"[{PUBLISHER}] declaration matched key={key}",
    ]
    for sequence, value, cdr in contract["samples"]:
        att = zenoh_wire.attachment(sequence + 1, TIMESTAMP, GID)
        batch = zenoh_wire.frame(sequence, zenoh_wire.push_put(key, att, bytes.fromhex(cdr), True)).hex()
        lines.append(f"[{PUBLISHER}] wire sent sample={sequence} hex={batch}")
        lines.append(f"[{SUBSCRIBER}] wire received sample={sequence} hex={batch}")
        lines.append(f"[{SUBSCRIBER}] sample validated sequence={sequence} value={value}")
    lines += [
        RECEIVED,
        *(f"[{who}] denial class={cls} refused=1" for who, cls in DENIALS if who == SUBSCRIBER),
        f"[{SUBSCRIBER}] undeclared subscriber id=1",
        f"[{SUBSCRIBER}] session closing samples=4",
        f"[{PUBLISHER}] session closed samples=4",
        *(f"[{who}] denial class={cls} refused=1" for who, cls in DENIALS if who == PUBLISHER),
        SUCCESS,
    ]
    return lines


def _one(lines: list[str], pattern: str, label: str) -> re.Match:
    found = [m for line in lines if (m := re.fullmatch(pattern, line))]
    if len(found) != 1:
        raise ExchangeError(f"{label}: {len(found)} matching lines, expected exactly one")
    return found[0]


def judge_transcript(lines: list[str], contract: dict) -> tuple[int, int, int]:
    """Judge a transcript. Returns (samples matched, wire bytes judged, denials observed)."""
    key = contract["key"]
    opened = _one(lines, rf"\[{PUBLISHER}\] session open role=connector initial_sn=(\d+) lease_ms=(\d+)", "publisher session")
    _one(lines, rf"\[{SUBSCRIBER}\] session open role=listener initial_sn=(\d+) lease_ms=(\d+)", "subscriber session")
    _one(lines, rf"\[{SUBSCRIBER}\] declared subscriber id=1 key={re.escape(key)}", "subscriber declaration for the demo key")
    _one(lines, rf"\[{PUBLISHER}\] declaration matched key={re.escape(key)}", "publisher declaration match")
    initial_sn = int(opened.group(1))
    sent = {int(m.group(1)): m.group(2) for line in lines if (m := re.fullmatch(rf"\[{PUBLISHER}\] wire sent sample=(\d+) hex=([0-9a-f]+)", line))}
    received = {int(m.group(1)): m.group(2) for line in lines if (m := re.fullmatch(rf"\[{SUBSCRIBER}\] wire received sample=(\d+) hex=([0-9a-f]+)", line))}
    count = len([1 for line in lines if re.fullmatch(rf"\[{PUBLISHER}\] wire sent sample=\d+ hex=[0-9a-f]+", line)])
    if count != 4 or sorted(sent) != [0, 1, 2, 3]:
        raise ExchangeError(f"the publisher reported {count} sent batches covering samples {sorted(sent)}")
    if sorted(received) != [0, 1, 2, 3] or len([1 for line in lines if " wire received " in line]) != 4:
        raise ExchangeError("the subscriber did not report exactly the four sent samples")
    attachments = []
    judged = 0
    for sequence, value, cdr in contract["samples"]:
        if sent[sequence] != received[sequence]:
            raise ExchangeError(f"sample {sequence}: the subscriber received different bytes than the publisher sent")
        batch = bytes.fromhex(sent[sequence])
        try:
            decoded = zenoh_wire.decode_push_frame(batch)
        except zenoh_wire.WireError as error:
            raise ExchangeError(f"sample {sequence}: {error}") from error
        if decoded["key"] != key:
            raise ExchangeError(f"sample {sequence}: key expression {decoded['key']!r} is not the demo's")
        if decoded["sn"] != initial_sn + sequence:
            raise ExchangeError(f"sample {sequence}: frame sn {decoded['sn']} is not initial_sn {initial_sn} + {sequence}")
        if decoded["payload"].hex() != cdr:
            raise ExchangeError(f"sample {sequence}: payload {decoded['payload'].hex()} is not the contract's {cdr}")
        # The batch must be exactly what the reference encodes from the same fields.
        again = zenoh_wire.frame(
            decoded["sn"],
            zenoh_wire.push_put(decoded["key"], zenoh_wire.attachment(decoded["sequence"], decoded["timestamp"], decoded["gid"]), decoded["payload"], True),
        )
        if again != batch:
            raise ExchangeError(f"sample {sequence}: the batch is not the canonical encoding of its own fields")
        attachments.append((decoded["sequence"], decoded["timestamp"], decoded["gid"]))
        validated = _one(lines, rf"\[{SUBSCRIBER}\] sample validated sequence={sequence} value=(-?\d+)", f"sample {sequence} validation")
        if int(validated.group(1)) != value:
            raise ExchangeError(f"sample {sequence}: validated value {validated.group(1)}, contract has {value}")
        judged += len(batch)
    if [a[0] for a in attachments] != list(range(attachments[0][0], attachments[0][0] + 4)):
        raise ExchangeError("attachment sequence numbers do not increase by one")
    if len({a[2] for a in attachments}) != 1 or [a[1] for a in attachments] != sorted(a[1] for a in attachments):
        raise ExchangeError("attachment GID changed or timestamps went backwards")
    _one(lines, re.escape(RECEIVED), "subscriber summary")
    _one(lines, rf"\[{SUBSCRIBER}\] undeclared subscriber id=1", "undeclare before close")
    _one(lines, rf"\[{SUBSCRIBER}\] session closing samples=4", "subscriber close")
    _one(lines, rf"\[{PUBLISHER}\] session closed samples=4", "publisher close")
    undeclared, closing = lines.index(f"[{SUBSCRIBER}] undeclared subscriber id=1"), lines.index(f"[{SUBSCRIBER}] session closing samples=4")
    publisher_closed = lines.index(f"[{PUBLISHER}] session closed samples=4")
    if undeclared > closing:
        raise ExchangeError("the session closed before the subscriber was undeclared")
    if publisher_closed < closing:
        raise ExchangeError("the publisher saw a close the subscriber had not yet sent")
    denials = 0
    for who, cls in DENIALS:
        _one(lines, rf"\[{who}\] denial class={re.escape(cls)} refused=1", f"{who} {cls} denial")
        denials += 1
    extra = [line for line in lines if " denial " in line]
    if len(extra) != denials:
        raise ExchangeError("a denial the exam does not name")
    _one(lines, re.escape(SUCCESS), "success marker")
    # Only causal order is judged: the subscriber's lines precede its CLOSE, the publisher
    # reports its close after receiving it, and success is the publisher's last line.
    for who, cls in DENIALS:
        at = lines.index(f"[{who}] denial class={cls} refused=1")
        if who == SUBSCRIBER and at > closing:
            raise ExchangeError("the subscriber reported a denial after it closed")
        if who == PUBLISHER and at < publisher_closed:
            raise ExchangeError("the publisher reported a denial before its session closed")
    if lines.index(SUCCESS) != len(lines) - 1 or lines.index(SUCCESS) < max(lines.index(f"[{PUBLISHER}] denial class={c} refused=1") for w, c in DENIALS if w == PUBLISHER):
        raise ExchangeError("success was not the publisher's last line after the close and its denials")
    return 4, judged, denials


def transcript_mutations(good: list[str]) -> list[tuple[str, Callable[[list[str]], list[str]]]]:
    def replace_first(needle: str, new: str) -> Callable[[list[str]], list[str]]:
        def run(lines: list[str]) -> list[str]:
            out = list(lines)
            at = next(i for i, line in enumerate(out) if needle in line)
            out[at] = out[at].replace(needle, new, 1) if new is not None else out[at]
            return out

        return run

    def drop(needle: str) -> Callable[[list[str]], list[str]]:
        return lambda lines: [line for line in lines if needle not in line]

    def flip_received(lines: list[str]) -> list[str]:
        out = list(lines)
        at = next(i for i, line in enumerate(out) if " wire received sample=2 " in line)
        head, hexed = out[at].rsplit("hex=", 1)
        out[at] = head + "hex=" + hexed[:-1] + ("0" if hexed[-1] != "0" else "1")
        return out

    def flip_sent_and_received(lines: list[str]) -> list[str]:
        out = list(lines)
        for tag in (" wire sent sample=1 ", " wire received sample=1 "):
            at = next(i for i, line in enumerate(out) if tag in line)
            head, hexed = out[at].rsplit("hex=", 1)
            out[at] = head + "hex=" + hexed[:-2] + ("00" if hexed[-2:] != "00" else "01")
        return out

    def swap(a: str, b: str) -> Callable[[list[str]], list[str]]:
        def run(lines: list[str]) -> list[str]:
            out = list(lines)
            i, j = next(k for k, x in enumerate(out) if a in x), next(k for k, x in enumerate(out) if b in x)
            out[i], out[j] = out[j], out[i]
            return out

        return run

    return [
        ("an empty transcript", lambda lines: []),
        ("a dropped sent batch", drop("wire sent sample=3 ")),
        ("a dropped received batch", drop("wire received sample=0 ")),
        ("a dropped validation", drop("sample validated sequence=2 ")),
        ("a duplicated sent batch", lambda lines: lines + [next(x for x in lines if "wire sent sample=0 " in x)]),
        ("bytes changed in transit", flip_received),
        ("bytes wrong on both sides", flip_sent_and_received),
        ("a wrong key expression", replace_first("slime_demo/counter", "slime_demo/other")),
        ("a wildcard key expression", replace_first("0/slime_demo/counter", "0/slime_demo/*")),
        ("a wrong validated value", replace_first("sequence=1 value=20", "sequence=1 value=21")),
        ("a dropped denial", drop("denial class=scouting")),
        ("an unnamed denial", lambda lines: lines + [f"[{PUBLISHER}] denial class=invented refused=1"]),
        ("a dropped subscriber summary", drop("received count=4")),
        ("no undeclare before close", drop("undeclared subscriber")),
        ("close before undeclare", swap("undeclared subscriber", "session closing samples=4")),
        ("publisher closes before the subscriber does", swap("[ros2-demo-publisher] session closed", "session closing samples=4")),
        ("success before the close", swap(SUCCESS, "[ros2-demo-publisher] session closed")),
        ("success before a publisher denial", swap(SUCCESS, "denial class=listen")),
        ("a subscriber denial after its close", swap("[ros2-demo-subscriber] denial class=connect", "session closing samples=4")),
        ("a dropped success marker", drop("success profile")),
        ("a duplicated success marker", lambda lines: lines + [SUCCESS]),
        ("a wrong initial sequence", replace_first("initial_sn=0 lease_ms=2000", "initial_sn=5 lease_ms=2000")),
    ]


def transcript_controls(contract: dict) -> tuple[int, int]:
    """Judge the honest transcript, then refuse every mutation. Returns (judged samples, refused)."""
    good = synthesize_transcript(contract)
    samples, _, _ = judge_transcript(good, contract)
    refused = 0
    for label, mutate in transcript_mutations(good):
        try:
            judge_transcript(mutate(good), contract)
        except (ExchangeError, StopIteration):
            refused += 1
            continue
        raise ExchangeError(f"control: transcript judge accepted {label}")
    return samples, refused


def reference_self_test(corpus: Path) -> int:
    return zenoh_wire.self_test(corpus)
