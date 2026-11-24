"""Judge whether `ros2` lists a Slime node from the liveliness tokens a client-role link wrote to a live `rmw_zenohd`.

The token exam judges the bytes the link writes. This exam judges what a ROS graph reader makes of them. The checker
starts `rmw_zenohd`, runs the host program in `verification/zenoh-live` with `discover`, and runs `ros2 node list` and
`ros2 topic list` against the router twice: while the program holds its session open, and after the program closed it.
The program prints one `live ...` line for each thing it did. The checker adds one `ros ...` line for each `ros2`
command it ran, with every name that command printed. The program never writes a `ros` line, and the checker fails the
run on any program line that is not a `live` line.

A run prints these lines, in this order:

* `live router-ready tcp/127.0.0.1:7447`, then the `live handshake` of a router (`whatami=0`, a 512-byte batch);
* `live token-declared node id=10` and `live token-declared publisher id=11`;
* `ros nodes held /slime_node` and `ros topics held /chatter,/parameter_events,/rosout`, read while the session is open;
* `live closed reason=0`;
* `ros nodes closed -` and `ros topics closed /parameter_events,/rosout`, read after the close.

A name list is sorted and comma-joined, and `-` is an empty list. The judge reads the whole list, so a second node, a
missing built-in topic or a name `ros2` did not print is refused. The controls cannot show that a router ran. They
show that a transcript is judged for the facts above.
"""

from __future__ import annotations

import re

from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-discover.zt"

NODE = "/slime_node"
TOPIC = "/chatter"
BUILTIN_TOPICS = ("/parameter_events", "/rosout")


class DiscoverExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise DiscoverExamError(message)


def names(items: list[str]) -> str:
    """The name list a `ros` line carries."""
    return ",".join(sorted(items)) if items else "-"


def good_lines() -> list[str]:
    return [
        "live router-ready tcp/127.0.0.1:7447",
        "live handshake whatami=0 batch=512 lease_s=60",
        "live token-declared node id=10",
        "live token-declared publisher id=11",
        f"ros nodes held {names([NODE])}",
        f"ros topics held {names([TOPIC, *BUILTIN_TOPICS])}",
        "live closed reason=0",
        f"ros nodes closed {names([])}",
        f"ros topics closed {names(list(BUILTIN_TOPICS))}",
    ]


# The kind of each line, in the order a run prints them. The listings carry their phase, so a listing read before the
# close cannot stand after it.
PHASES = (
    "live router-ready", "live handshake", "live token-declared", "live token-declared",
    "ros nodes held", "ros topics held", "live closed", "ros nodes closed", "ros topics closed",
)
MIN_PARTS = {"router-ready": 3, "handshake": 4, "token-declared": 4, "closed": 3}
ONCE = ("router-ready", "handshake", "closed")


def parse(lines: list[str]) -> dict:
    facts: dict = {"ready": None, "handshake": None, "declared": [], "closed": None, "ros": {}}
    for line in lines:
        _need(line == line.strip() and "  " not in line, f"discover: a line with stray spaces: {line!r}")
        parts = line.split(" ")
        _need(parts[0] in ("live", "ros"), f"discover: a record that is not a discover exam line: {line!r}")
        _need(len(parts) >= 2, f"discover: a line with no kind: {line!r}")
        if parts[0] == "ros":
            _need(len(parts) == 4 and parts[1] in ("nodes", "topics") and parts[2] in ("held", "closed"), f"discover: a ROS line that is not a node or topic list: {line!r}")
            key = (parts[1], parts[2])
            _need(key not in facts["ros"], f"discover: {parts[1]} listed twice {parts[2]}")
            _need(re.fullmatch(r"-|/[\w/]+(,/[\w/]+)*", parts[3]) is not None, f"discover: a name list that is not names: {line!r}")
            facts["ros"][key] = [] if parts[3] == "-" else parts[3].split(",")
            continue
        kind = parts[1]
        _need(len(parts) >= MIN_PARTS.get(kind, 2), f"discover: a {kind} line with too few fields: {line!r}")
        if kind == "router-ready":
            facts["ready"] = parts[2]
        elif kind == "handshake":
            facts["handshake"] = parts[2:]
        elif kind == "token-declared":
            _need(len(parts) == 4, f"discover: a malformed token line: {line!r}")
            facts["declared"].append((parts[2], parts[3]))
        elif kind == "closed":
            facts["closed"] = parts[2]
        else:
            raise DiscoverExamError(f"discover: a line the exam does not know: {line!r}")
    return facts


def phases(lines: list[str]) -> list[str]:
    """The phase of each line: `live <kind>`, or `ros <nodes|topics> <held|closed>`."""
    return [" ".join(line.split(" ")[:3] if line.startswith("ros ") else line.split(" ")[:2]) for line in lines]


def judge(lines: list[str]) -> tuple[int, int]:
    """Returns (facts judged, 0). The transcript has no refusal lines: `ros2` lists the node or it does not."""
    facts = parse(lines)
    _need(phases(lines) == list(PHASES), f"discover: the lines come in the order {phases(lines)}, a run prints {list(PHASES)}")
    for kind in ONCE:
        count = sum(1 for line in lines if line.startswith(f"live {kind} "))
        _need(count == 1, f"discover: {count} {kind} lines, a run prints one")
    _need(facts["ready"] == "tcp/127.0.0.1:7447", "discover: no router was reached on tcp/127.0.0.1:7447")
    _need(facts["handshake"][:2] == ["whatami=0", "batch=512"], "discover: the router's INIT_ACK is not whatami 0 with a 512-byte batch")
    _need(facts["declared"] == [("node", "id=10"), ("publisher", "id=11")], f"discover: the link declared {facts['declared']}, the item says the node token then the publisher token")
    ros = facts["ros"]
    _need(set(ros) == {("nodes", "held"), ("topics", "held"), ("nodes", "closed"), ("topics", "closed")}, "discover: not every ros2 listing was read")
    _need(ros[("nodes", "held")] == [NODE], f"discover: ros2 listed the nodes {ros[('nodes', 'held')]} while the session was open, the item says only {NODE}")
    _need(sorted(ros[("topics", "held")]) == sorted([TOPIC, *BUILTIN_TOPICS]), f"discover: ros2 listed the topics {ros[('topics', 'held')]} while the session was open")
    _need(facts["closed"] == "reason=0", "discover: the link did not close with reason 0")
    _need(ros[("nodes", "closed")] == [], f"discover: ros2 still listed {ros[('nodes', 'closed')]} after the close")
    _need(sorted(ros[("topics", "closed")]) == sorted(BUILTIN_TOPICS), f"discover: ros2 listed the topics {ros[('topics', 'closed')]} after the close")
    return 8, 0


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()

    def replaced(index: int, old: str, new: str) -> list[str]:
        return [line.replace(old, new, 1) if i == index else line for i, line in enumerate(good)]

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    return [
        ("an empty transcript", []),
        ("a line that is not an exam line", [*good, "link ok router-data-1-whole"]),
        ("a line with a doubled space", [good[0].replace(" ", "  ", 1), *good[1:]]),
        ("a line the exam does not know", [*good, "live surprise"]),
        ("no router reached", replaced(0, "7447", "7448")),
        ("a handshake with a peer's INIT_ACK", replaced(1, "whatami=0", "whatami=1")),
        ("a router that announced a 1024-byte batch", replaced(1, "batch=512", "batch=1024")),
        ("no node token", [line for i, line in enumerate(good) if i != 2]),
        ("no publisher token", [line for i, line in enumerate(good) if i != 3]),
        ("the tokens declared in the other order", swapped(2, 3)),
        ("a node token on another id", replaced(2, "id=10", "id=12")),
        ("ros2 listed no node while the session was open", replaced(4, "/slime_node", "-")),
        ("ros2 listed another node", replaced(4, "/slime_node", "/other_node")),
        ("ros2 listed a second node", replaced(4, "/slime_node", "/other_node,/slime_node")),
        ("ros2 listed no chatter topic", replaced(5, "/chatter,", "")),
        ("ros2 listed no built-in topic", replaced(5, ",/rosout", "")),
        ("ros2 listed another topic", replaced(5, "/chatter", "/other")),
        ("ros2 still listed the node after the close", replaced(7, "-", "/slime_node")),
        ("ros2 still listed the chatter topic after the close", replaced(8, "/parameter_events", "/chatter,/parameter_events")),
        ("ros2 listed no built-in topic after the close", replaced(8, "/parameter_events,", "")),
        ("the node list read only after the close", [line for i, line in enumerate(good) if i != 4]),
        ("the topic list read only after the close", [line for i, line in enumerate(good) if i != 5]),
        ("no listing after the close", good[:7]),
        ("no listing while the session was open", [good[0], good[1], good[2], good[3], *good[6:]]),
        ("a listing before the tokens", [*good[:2], *good[4:6], *good[2:4], *good[6:]]),
        ("a listing before the router was ready", [*good[4:6], *good[:4], *good[6:]]),
        ("a held listing printed after the close", [*good[:4], good[6], *good[4:6], *good[7:]]),
        ("a node list read twice", [*good, good[4]]),
        ("the listings after the close read before it", [*good[:4], *good[7:], good[6], *good[4:6]]),
        ("a listing with an unknown phase", replaced(4, "held", "lost")),
        ("a listing that is not a node or topic list", replaced(5, "topics", "services")),
        ("a listing with a missing field", replaced(4, " held /slime_node", " /slime_node")),
        ("a name list that is not names", replaced(4, "/slime_node", "slime_node")),
        ("a ROS line that is not ros2's", [good[i].replace("ros nodes", "ros node", 1) if i == 4 else good[i] for i in range(len(good))]),
        ("a second close line", [*good[:7], good[6], *good[7:]]),
        ("a second router-ready line", [good[0], *good]),
        ("a closed line with no reason", replaced(6, " reason=0", "")),
        ("a close with another reason", replaced(6, "reason=0", "reason=1")),
        ("no close", [line for i, line in enumerate(good) if i != 6]),
    ]


def transcript_controls() -> int:
    good = good_lines()
    judge(good)
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise DiscoverExamError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except DiscoverExamError:
            refused += 1
            continue
        raise DiscoverExamError(f"control: the discover judge accepted {label}")
    return refused


def all_controls() -> int:
    return transcript_controls()


# What the item fixes, held here as well so the gate stays correct after the item moves to .tasks/terminal.
PINNED_CASES = 8
PINNED_CONTROLS = 39


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
