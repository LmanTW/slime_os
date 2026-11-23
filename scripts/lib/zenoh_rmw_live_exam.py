"""Judge a live exchange between a client-role Slime link and a ROS node through `rmw_zenohd`.

Every other exam of the client role replays captured bytes. This one judges a run against a real router. The checker
starts `rmw_zenohd` and a ROS node for each direction, runs the host program in `verification/zenoh-live` against them,
and kills each process it started by its recorded PID. The program prints one `[zenoh-live] ...` line for each thing it
did. The checker reads the listener's output itself, stdout and stderr together, and adds one `ros listener ...` line for
each `I heard:` line the listener printed. The program never writes a `ros` line, and the checker fails the run on any
program line that is not a `live` line. This module judges the whole transcript.

Two directions run one after the other, each against its own router:

* `inbound`: a `demo_nodes_cpp talker` publishes on the chatter key. The link subscribes through the router and
  delivers its samples. Every delivered sample carries a sequence number and a `Hello World: N` string that agree,
  the sequence numbers rise by one, and at least 4 arrive.
* `outbound`: a `demo_nodes_cpp listener` subscribes to the chatter key. The link writes 6 Puts, and the listener
  prints each as `I heard: [Hello Slime N]`. Every one of the 6 is heard, in order.

The program also prints what the router sent it before the first sample, so a change in the router's handshake is
seen. The ROS side is read by the checker from the node's own output. That is what makes the outbound direction an
observation and not a claim of the program.

Like the other judges, this one is trusted only after it refuses a mutation of an honest transcript. The controls
cannot show that a router ran. They show that a transcript is judged for the facts above.
"""

from __future__ import annotations

import re

from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-live.zt"

INBOUND_MIN = 4
OUTBOUND = 6
TALKER_TEXT = re.compile(r"Hello World: (\d+)")
LISTENER_TEXT = re.compile(r"I heard: \[Hello Slime (\d+)\]")

class LiveExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise LiveExamError(message)


# ------------------------------------------------------------------------------------------------ the transcript


def good_lines(inbound: int = INBOUND_MIN + 2, first: int = 3) -> list[str]:
    """An honest transcript: `inbound` samples starting at sequence `first`, then the 6 Puts and the 6 echoes."""
    lines = [
        "live router-ready tcp/127.0.0.1:7447",
        "live handshake whatami=0 batch=512 lease_s=60",
        f"live subscribed {1}",
    ]
    for n in range(inbound):
        sequence = first + n
        lines.append(f"live sample inbound sequence={sequence} text=Hello_World:_{sequence}")
    lines.append(f"live inbound-done delivered={inbound}")
    lines.append("live handshake whatami=0 batch=512 lease_s=60")
    for n in range(OUTBOUND):
        lines.append(f"live put outbound number={n}")
    lines.append(f"live outbound-done written={OUTBOUND}")
    for n in range(OUTBOUND):
        lines.append(f"ros listener I_heard:_[Hello_Slime_{n}]")
    lines.append("live closed reason=0")
    return lines


# The fewest space-separated fields of each kind of `live` line, so a short line is the exam's own refusal.
MIN_PARTS = {"router-ready": 3, "handshake": 4, "subscribed": 3, "sample": 5, "inbound-done": 3, "put": 4, "outbound-done": 3, "closed": 3}
# The kinds a run prints exactly once, and the ones it prints for each handshake or each sample.
ONCE = ("router-ready", "subscribed", "inbound-done", "outbound-done", "closed")


def parse(lines: list[str]) -> dict:
    """The facts a transcript states, or an error when a line is not one the exam knows."""
    facts: dict = {"handshakes": [], "samples": [], "puts": [], "heard": [], "subscribed": None, "delivered": None, "written": None, "closed": None, "ready": None}
    for line in lines:
        _need(line == line.strip() and "  " not in line, f"live: a line with stray spaces: {line!r}")
        parts = line.split(" ")
        _need(parts[0] in ("live", "ros"), f"live: a record that is not a live exam line: {line!r}")
        _need(len(parts) >= 2, f"live: a line with no kind: {line!r}")
        if parts[0] == "ros":
            match = LISTENER_TEXT.fullmatch(parts[2].replace("_", " ")) if len(parts) == 3 and parts[1] == "listener" else None
            _need(match is not None, f"live: a ROS line that is not a listener's: {line!r}")
            facts["heard"].append(int(match.group(1)))
            continue
        kind = parts[1]
        _need(len(parts) >= MIN_PARTS.get(kind, 2), f"live: a {kind} line with too few fields: {line!r}")
        if kind == "router-ready":
            facts["ready"] = parts[2]
        elif kind == "handshake":
            facts["handshakes"].append(parts[2:])
        elif kind == "subscribed":
            facts["subscribed"] = int(parts[2])
        elif kind == "sample":
            _need(parts[2] == "inbound" and len(parts) == 5, f"live: a malformed sample line: {line!r}")
            sequence = int(parts[3].split("=", 1)[1])
            text = parts[4].split("=", 1)[1].replace("_", " ")
            facts["samples"].append((sequence, text))
        elif kind == "inbound-done":
            facts["delivered"] = int(parts[2].split("=", 1)[1])
        elif kind == "put":
            facts["puts"].append(int(parts[3].split("=", 1)[1]))
        elif kind == "outbound-done":
            facts["written"] = int(parts[2].split("=", 1)[1])
        elif kind == "closed":
            facts["closed"] = parts[2]
        else:
            raise LiveExamError(f"live: a line the exam does not know: {line!r}")
    return facts


# The kinds of line in the order a run prints them. The two directions run one after the other, each against its own
# router, so the inbound handshake and subscription come first, then the inbound samples, then the outbound handshake,
# the Puts, the `ros` lines the checker read from the listener, and the close.
PHASES = ("router-ready", "handshake", "subscribed", "sample", "inbound-done", "handshake", "put", "outbound-done", "ros", "closed")


def phases(lines: list[str]) -> list[str]:
    """The kind of each line, with a run of one kind folded to one entry."""
    kinds: list[str] = []
    for line in lines:
        parts = line.split(" ")
        kind = parts[0] if parts[0] == "ros" else parts[1]
        if not kinds or kinds[-1] != kind:
            kinds.append(kind)
    return kinds


def judge(lines: list[str]) -> tuple[int, int]:
    """Returns (facts judged, 0). The live transcript has no refusal lines: the link either did the exchange or it did not."""
    facts = parse(lines)
    _need(phases(lines) == list(PHASES), f"live: the lines come in the order {phases(lines)}, a run prints {list(PHASES)}")
    for kind in ONCE:
        count = sum(1 for line in lines if line.split(" ")[1] == kind and line.startswith("live "))
        _need(count == 1, f"live: {count} {kind} lines, a run prints one")
    _need(all(line.split(" ")[2] == "outbound" for line in lines if line.startswith("live put ")), "live: a Put line that is not an outbound one")
    _need(facts["ready"] == "tcp/127.0.0.1:7447", "live: no router was reached on tcp/127.0.0.1:7447")
    _need(len(facts["handshakes"]) == 2, f"live: {len(facts['handshakes'])} handshakes, one for each direction")
    for handshake in facts["handshakes"]:
        _need(handshake[0] == "whatami=0", "live: an INIT_ACK that is not a router's")
        _need(handshake[1] == "batch=512", "live: the router did not announce a 512-byte batch")
    _need(facts["subscribed"] == 1, "live: the link did not subscribe on the chatter key")
    samples = facts["samples"]
    _need(len(samples) >= INBOUND_MIN, f"live: {len(samples)} inbound samples, the item says at least {INBOUND_MIN}")
    _need(facts["delivered"] == len(samples), "live: the delivered count is not the samples printed")
    for sequence, text in samples:
        _need(TALKER_TEXT.fullmatch(text) is not None and int(TALKER_TEXT.fullmatch(text).group(1)) == sequence, f"live: sample {sequence} carries {text!r}")
    _need([s for s, _ in samples] == list(range(samples[0][0], samples[0][0] + len(samples))), "live: the inbound sequence numbers do not rise by one")
    _need(facts["puts"] == list(range(OUTBOUND)), f"live: the link wrote Puts {facts['puts']}, the item says 0 to {OUTBOUND - 1}")
    _need(facts["written"] == OUTBOUND, "live: the written count is not the Puts printed")
    _need(facts["heard"] == list(range(OUTBOUND)), f"live: the listener heard {facts['heard']}, the item says 0 to {OUTBOUND - 1} in order")
    _need(facts["closed"] == "reason=0", "live: the link did not close with reason 0")
    return 8 + len(samples), 0


# ------------------------------------------------------------------------------------------------ the controls


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    index = {kind: [i for i, line in enumerate(good) if line.startswith(f"live {kind} ") or line.startswith(f"{kind} ")] for kind in ("router-ready", "handshake", "subscribed", "sample", "inbound-done", "put", "outbound-done", "closed", "ros")}

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a live exam line", [*good, "link ok router-data-1-whole"]),
        ("a line with a doubled space", [good[0].replace(" ", "  ", 1), *good[1:]]),
        ("a line with trailing space", [good[0] + " ", *good[1:]]),
        ("a line the exam does not know", [*good, "live surprise"]),
        ("no router reached", [good[i].replace("tcp/127.0.0.1:7447", "tcp/127.0.0.1:7448") if i == index["router-ready"][0] else good[i] for i in range(len(good))]),
        ("a handshake with a peer's INIT_ACK", [good[i].replace("whatami=0", "whatami=1", 1) if i == index["handshake"][0] else good[i] for i in range(len(good))]),
        ("a second handshake with a client's INIT_ACK", [good[i].replace("whatami=0", "whatami=2", 1) if i == index["handshake"][1] else good[i] for i in range(len(good))]),
        ("a router that announced a 1024-byte batch", [good[i].replace("batch=512", "batch=1024", 1) if i == index["handshake"][0] else good[i] for i in range(len(good))]),
        ("only one handshake", [line for i, line in enumerate(good) if i != index["handshake"][1]]),
        ("a subscription on another id", [good[i].replace("subscribed 1", "subscribed 2") if i == index["subscribed"][0] else good[i] for i in range(len(good))]),
        ("no subscription", [line for i, line in enumerate(good) if i != index["subscribed"][0]]),
        ("an inbound sample whose string disagrees with its sequence", [good[i].replace("Hello_World:_3", "Hello_World:_9") if i == index["sample"][0] else good[i] for i in range(len(good))]),
        ("inbound sequence numbers that skip one", [good[i].replace("sequence=4 text=Hello_World:_4", "sequence=5 text=Hello_World:_5") if i == index["sample"][1] else good[i] for i in range(len(good))]),
        ("a delivered count that disagrees", [good[i].replace("delivered=6", "delivered=5") if i == index["inbound-done"][0] else good[i] for i in range(len(good))]),
        ("only 3 inbound samples", good_lines(inbound=3)),
        ("no inbound sample", good_lines(inbound=0)),
        ("a Put the link wrote out of order", swapped(index["put"][0], index["put"][1])),
        ("a Put missing", [line for i, line in enumerate(good) if i != index["put"][2]]),
        ("a written count that disagrees", [good[i].replace("written=6", "written=5") if i == index["outbound-done"][0] else good[i] for i in range(len(good))]),
        ("a Put the listener did not print", [line for i, line in enumerate(good) if i != index["ros"][3]]),
        ("a listener that heard the Puts out of order", swapped(index["ros"][0], index["ros"][1])),
        ("a listener that heard a string the link did not write", [good[i].replace("Hello_Slime_5", "Hello_Slime_7") if i == index["ros"][5] else good[i] for i in range(len(good))]),
        ("a ROS line that is not a listener's", [good[i].replace("ros listener", "ros talker", 1) if i == index["ros"][0] else good[i] for i in range(len(good))]),
        ("both handshakes after the outbound direction began", [line for i, line in enumerate(good) if i != index["handshake"][0]] + [good[index["handshake"][0]]]),
        ("a handshake printed twice in a row", [*good[: index["handshake"][0] + 1], good[index["handshake"][0]], *good[index["handshake"][0] + 1 :]]),
        ("the inbound samples after the outbound Puts", [*good[: index["sample"][0]], *good[index["put"][0] : index["outbound-done"][0] + 1], *good[index["sample"][0] : index["put"][0]], *good[index["outbound-done"][0] + 1 :]]),
        ("the ROS lines before the Puts", [*good[: index["put"][0]], *good[index["ros"][0] : index["ros"][-1] + 1], *good[index["put"][0] : index["ros"][0]], *good[index["ros"][-1] + 1 :]]),
        ("a ROS line the program printed after the close", [*good, "ros listener I_heard:_[Hello_Slime_0]"]),
        ("a second close line", [*good, good[index["closed"][0]]]),
        ("a second router-ready line", [good[0], *good]),
        ("a second subscription line", [*good[: index["subscribed"][0] + 1], good[index["subscribed"][0]], *good[index["subscribed"][0] + 1 :]]),
        ("a second inbound-done line", [*good[: index["inbound-done"][0] + 1], good[index["inbound-done"][0]], *good[index["inbound-done"][0] + 1 :]]),
        ("a second outbound-done line", [*good[: index["outbound-done"][0] + 1], good[index["outbound-done"][0]], *good[index["outbound-done"][0] + 1 :]]),
        ("a Put line that names the inbound direction", [good[i].replace("put outbound", "put inbound", 1) if i == index["put"][0] else good[i] for i in range(len(good))]),
        ("a closed line with no reason", [good[i].replace(" reason=0", "", 1) if i == index["closed"][0] else good[i] for i in range(len(good))]),
        ("a close with another reason", [good[i].replace("reason=0", "reason=1") if i == index["closed"][0] else good[i] for i in range(len(good))]),
        ("no close", [line for i, line in enumerate(good) if i != index["closed"][0]]),
    ]
    return out


def transcript_controls() -> int:
    good = good_lines()
    judge(good)
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise LiveExamError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except LiveExamError:
            refused += 1
            continue
        raise LiveExamError(f"control: the live judge accepted {label}")
    return refused


def all_controls() -> int:
    return transcript_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. A live run delivers at least `INBOUND_MIN` samples and may deliver more, so the cases are a floor.
# The controls are exact. While the item is open its stored predicates are compared with these.
MIN_CASES = 12
PINNED_CONTROLS = 38


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.atLeast "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
