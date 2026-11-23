"""Judge what the rmw_zenoh node and its native peer print when they exchange a topic under QEMU.

The booted composition runs two components. The node runs a graph link and the peer runs a plain link, and each
prints one line for each thing it did. This module judges those lines and nothing else:

* each component declares its subscription before it publishes or is delivered a sample;
* each component publishes the sequence numbers 1 to 4 once each, in order, and is delivered 1 to 4 once each, in order;
* the peer reports its session open before it declares, and the node reports it is closing only after it has
  published four and received four, which is the whole exchange and not its start;
* each component ends with `session closed` and prints nothing after it;
* neither component prints a `fail:` line.

Each component is a task of its own, so the order of a line of one against a line of the other is not fixed. The boot
plane gate once held eleven lines of separate tasks to one order and failed 2 of 10 boots on it. This judge therefore
holds each component to its own order only, and the honest transcript is accepted when the two components' lines
interleave in any of four ways. Two defects of these components, a missing role and a CLOSE that neither side sent,
would have passed a judge that saw only how the exchange begins. This one requires how it ends.

The lines come from the guest, so the judge is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re
from itertools import zip_longest

import zenoh_facts as facts
from harness import ROOT

NODE = "zenoh-rmw-node"
PEER = "zenoh-rmw-peer"
COMPONENTS = (NODE, PEER)
GENERATION = 173
CLOSURE = "sel4-zenoh-rmw"
SAMPLES = 4

LINE = re.compile(r"\[(zenoh-rmw-node|zenoh-rmw-peer)\] (.+)")
FAIL = re.compile(r"fail: (.+)")
OPEN = "session open"
DECLARED = "subscription declared"
CLOSING = "session closing"
CLOSED = "session closed"
PUBLISHED = re.compile(r"published sequence=(\d+)")
RECEIVED = re.compile(r"received sequence=(\d+)")

INTERLEAVINGS = ("node first", "peer first", "alternating from the node", "alternating from the peer")


SYSTEM = CLOSURE
PLANE = "scripts/check/check-sel4-io-network-plane.py"
SYSTEM_SPEC = f"contracts/system-spec/v1/systems/{SYSTEM}.zti"
MANIFEST = f"contracts/generation-manifest/v1/compositions/{SYSTEM}.zti"

# What the composition's files must hold, read by pattern as `zenoh_service_component_exam` reads the service's. Each fact
# has an example line that its own pattern matches and no other fact's pattern in the same file matches.
COMPOSITION_FACTS: tuple[facts.Fact, ...] = (
    ("spec-name", SYSTEM_SPEC, rf'^\s*name = "{SYSTEM}";$', f'  name = "{SYSTEM}";'),
    ("spec-node", SYSTEM_SPEC, r'\bname = "zenoh-rmw-node";\s+executable = "zenoh-rmw-node";', '      name = "zenoh-rmw-node";\n      executable = "zenoh-rmw-node";'),
    ("spec-peer", SYSTEM_SPEC, r'\bname = "zenoh-rmw-peer";\s+executable = "zenoh-rmw-peer";', '      name = "zenoh-rmw-peer";\n      executable = "zenoh-rmw-peer";'),
    ("spec-node-listens", SYSTEM_SPEC, r'\{ holder = "zenoh-rmw-node";[^\n]*role = "listener";[^\n]*localPort = 7447;', '    { holder = "zenoh-rmw-node"; role = "listener"; localPort = 7447; };'),
    ("spec-peer-dials", SYSTEM_SPEC, r'\{ holder = "zenoh-rmw-peer"; transport = "tcp";[^\n]*address = "127\.0\.0\.1"; port = 7447;', '    { holder = "zenoh-rmw-peer"; transport = "tcp"; address = "127.0.0.1"; port = 7447; };'),
    ("manifest-node", MANIFEST, r'\bname = "zenoh-rmw-node"', '    { name = "zenoh-rmw-node"; };'),
    ("manifest-peer", MANIFEST, r'\bname = "zenoh-rmw-peer"', '    { name = "zenoh-rmw-peer"; };'),
    ("inventory-entry", "contracts/composition-inventory/v1/inventory.zti",
     rf'composition = "{SYSTEM}";(?:(?!\n    \}};)[^}}])*?owningGate = "zenoh_rmw_booted_check";',
     f'    {{\n      composition = "{SYSTEM}";\n      owningGate = "zenoh_rmw_booted_check";\n    }};'),
    ("test-run-record", f"contracts/system-test-run/v2/runs/{SYSTEM}.zti", rf'^\s*imageClosure = "{SYSTEM}";$', f'  imageClosure = "{SYSTEM}";'),
    ("arm-choice", PLANE, r'"zenoh-rmw"', 'choices=("zenoh", "zenoh-rmw")'),
    ("arm-function", PLANE, r"^def run_zenoh_rmw_arm\(", "def run_zenoh_rmw_arm(transcript_path: Path | None) -> None:"),
    ("arm-chains", PLANE, r"^ZENOH_RMW_CHAINS\b", "ZENOH_RMW_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = ("),
    ("arm-node-failure", PLANE, r'zenoh-rmw-node\\\]\s+fail: ', '    r"\\[zenoh-rmw-node\\] fail: ",'),
    ("arm-peer-failure", PLANE, r'zenoh-rmw-peer\\\]\s+fail: ', '    r"\\[zenoh-rmw-peer\\] fail: ",'),
    ("arm-judge", PLANE, r"^import zenoh_rmw_arm\b", "import zenoh_rmw_arm  # noqa: E402"),
    ("recipe", "just/hardware.just", r"^zenoh_rmw_booted_check:$", "zenoh_rmw_booted_check:"),
)


class ArmError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ArmError(message)


def _text(component: str, text: str) -> str:
    return f"[{component}] {text}"


def component_lines(component: str) -> list[str]:
    """What one honest component prints, in its own order."""
    lines: list[str] = []
    if component == PEER:
        lines.append(_text(PEER, OPEN))
    lines.append(_text(component, DECLARED))
    for number in range(1, SAMPLES + 1):
        lines.append(_text(component, f"published sequence={number}"))
        lines.append(_text(component, f"received sequence={number}"))
    if component == NODE:
        lines.append(_text(NODE, CLOSING))
    lines.append(_text(component, CLOSED))
    return lines


def interleave(node: list[str], peer: list[str], how: str) -> list[str]:
    """The two components' lines merged in one of the four ways the exam accepts."""
    if how == "node first":
        return [*node, *peer]
    if how == "peer first":
        return [*peer, *node]
    first, second = (node, peer) if how == "alternating from the node" else (peer, node)
    _need(how in INTERLEAVINGS, f"no interleaving named {how}")
    return [line for pair in zip_longest(first, second) for line in pair if line is not None]


def synthesize(how: str = "node first") -> list[str]:
    """What an honest pair prints."""
    return interleave(component_lines(NODE), component_lines(PEER), how)


def _split(lines: list[str]) -> dict[str, list[str]]:
    by_component: dict[str, list[str]] = {NODE: [], PEER: []}
    for line in lines:
        match = LINE.fullmatch(line)
        _need(match is not None, f"rmw arm: a line that is not one of the exam's lines: {line!r}")
        assert match is not None
        component, text = match.group(1), match.group(2)
        failed = FAIL.fullmatch(text)
        _need(failed is None, f"rmw arm: {component} failed: {failed.group(1) if failed else ''}")
        by_component[component].append(text)
    return by_component


def _check(component: str, texts: list[str]) -> None:
    """One component's lines are the honest ones, in its own order. Names the first thing that is not."""
    expected = [line.split("] ", 1)[1] for line in component_lines(component)]
    _need(bool(texts), f"rmw arm: {component} printed nothing")
    _need(texts[-1] == CLOSED or CLOSED not in texts, f"rmw arm: {component} printed a line after {CLOSED}")
    _need(texts.count(CLOSED) == 1, f"rmw arm: {component} printed {texts.count(CLOSED)} {CLOSED} lines, expected one")
    _need(texts.count(DECLARED) == 1, f"rmw arm: {component} printed {texts.count(DECLARED)} {DECLARED} lines, expected one")
    if component == PEER:
        _need(texts.count(OPEN) == 1, f"rmw arm: {component} printed {texts.count(OPEN)} {OPEN} lines, expected one")
        _need(texts.index(OPEN) < texts.index(DECLARED), f"rmw arm: {component} declared before its session was open")
    if component == NODE:
        _need(texts.count(CLOSING) == 1, f"rmw arm: {component} printed {texts.count(CLOSING)} {CLOSING} lines, expected one")
        done = [i for i, text in enumerate(texts) if PUBLISHED.fullmatch(text) or RECEIVED.fullmatch(text)]
        _need(bool(done), f"rmw arm: {component} printed no sample line before it closed")
        _need(texts.index(CLOSING) > max(done), f"rmw arm: {component} closed before the exchange was done")
    for kind, label in ((PUBLISHED, "published"), (RECEIVED, "received")):
        numbers = [int(m.group(1)) for text in texts if (m := kind.fullmatch(text))]
        _need(numbers == list(range(1, SAMPLES + 1)), f"rmw arm: {component} {label} sequences {numbers}, expected 1 to {SAMPLES} once each in order")
        positions = [i for i, text in enumerate(texts) if kind.fullmatch(text)]
        _need(min(positions) > texts.index(DECLARED), f"rmw arm: {component} {label} a sample before it declared its subscription")
    _need(sorted(texts) == sorted(expected), f"rmw arm: {component} printed a line the exam does not list or too many of one")


def judge(lines: list[str]) -> int:
    """Check the two components' lines. Returns how many lines were accepted."""
    parts = _split(lines)
    for component in COMPONENTS:
        _check(component, parts[component])
    return len(lines)


def mutations() -> list[tuple[str, list[str]]]:
    node, peer = component_lines(NODE), component_lines(PEER)
    good = interleave(node, peer, "node first")

    def swap(lines: list[str], first: str, second: str) -> list[str]:
        out = list(lines)
        i, j = out.index(first), out.index(second)
        out[i], out[j] = out[j], out[i]
        return out

    def replace(lines: list[str], old: str, new: str) -> list[str]:
        out = list(lines)
        out[out.index(old)] = new
        return out

    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line the exam does not list", [*good[: len(node) - 1], _text(NODE, "session resumed"), *good[len(node) - 1 :]]),
        ("a line of another component", [*good, "[zenoh-service] holder attached holder=alpha rows=1"]),
        ("the node's failure", [*good, _text(NODE, "fail: deadline")]),
        ("the peer's failure", [*good, _text(PEER, "fail: connect attempts")]),
        ("a failure in the middle of the exchange", [*good[:6], _text(PEER, "fail: publish"), *good[6:]]),
        ("a line after the node's close", [*good[: len(node)], _text(NODE, "received sequence=5"), *good[len(node) :]]),
        ("a line after the peer's close", [*good, _text(PEER, "subscription declared")]),
        ("a fifth sample published by the node", [*good[: len(node) - 2], _text(NODE, "published sequence=5"), *good[len(node) - 2 :]]),
        ("a fifth sample published by the peer", [*good[:-1], _text(PEER, "published sequence=5"), good[-1]]),
        ("a sample numbered 0", replace(good, _text(NODE, "received sequence=1"), _text(NODE, "received sequence=0"))),
        ("the node's second publication sent twice", replace(good, _text(NODE, "published sequence=3"), _text(NODE, "published sequence=2"))),
        ("the peer's second reception received twice", replace(good, _text(PEER, "received sequence=3"), _text(PEER, "received sequence=2"))),
        ("the node's first two publications swapped", swap(good, _text(NODE, "published sequence=1"), _text(NODE, "published sequence=2"))),
        ("the peer's first two publications swapped", swap(good, _text(PEER, "published sequence=1"), _text(PEER, "published sequence=2"))),
        ("the node's first two receptions swapped", swap(good, _text(NODE, "received sequence=1"), _text(NODE, "received sequence=2"))),
        ("the peer's first two receptions swapped", swap(good, _text(PEER, "received sequence=1"), _text(PEER, "received sequence=2"))),
        ("the node publishing before it declared", swap(good, _text(NODE, DECLARED), _text(NODE, "published sequence=1"))),
        ("the peer publishing before it declared", swap(good, _text(PEER, DECLARED), _text(PEER, "published sequence=1"))),
        ("the peer declaring before its session was open", swap(good, _text(PEER, OPEN), _text(PEER, DECLARED))),
        ("the node closing before its last reception", swap(good, _text(NODE, CLOSING), _text(NODE, "received sequence=4"))),
        ("the node closing before its last publication", swap(good, _text(NODE, CLOSING), _text(NODE, "published sequence=4"))),
        ("the node closed before it was closing", swap(good, _text(NODE, CLOSING), _text(NODE, CLOSED))),
        ("the peer closed before its last reception", swap(good, _text(PEER, CLOSED), _text(PEER, "received sequence=4"))),
        ("a line repeated", [*good[:1], *good]),
        ("a node that closed with no sample line at all", [line for line in good if not ("zenoh-rmw-node" in line and ("published sequence=" in line or "received sequence=" in line))]),
        ("a second close of the node", [*good[: len(node)], _text(NODE, CLOSED), *good[len(node) :]]),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index + 1} ({line[1:40]}) missing", good[:index] + good[index + 1 :]))
    return out


def read_file(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        raise ArmError(f"{path} cannot be read: {error}") from error


def check_composition() -> int:
    """Every fact holds in the repository's files. Returns how many held."""
    try:
        return facts.check(COMPOSITION_FACTS, read_file)
    except facts.FactsError as error:
        raise ArmError(str(error)) from error


def composition_controls() -> int:
    """Each fact removed from a synthetic file set is refused by name. Returns how many were refused."""
    try:
        return facts.controls(COMPOSITION_FACTS)
    except facts.FactsError as error:
        raise ArmError(str(error)) from error


def controls() -> int:
    """The honest transcript is accepted in each interleaving, and every mutation of it is refused. Returns how many
    mutations were refused."""
    for how in INTERLEAVINGS:
        try:
            accepted = judge(synthesize(how))
        except ArmError as error:
            raise ArmError(f"rmw arm: the honest transcript was refused when the components interleave {how}: {error}") from error
        _need(accepted == len(component_lines(NODE)) + len(component_lines(PEER)), f"rmw arm: the honest transcript was {accepted} lines")
    refused = 0
    good = synthesize()
    for label, lines in mutations():
        _need(lines != good, f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except ArmError:
            refused += 1
            continue
        raise ArmError(f"control: the rmw arm judge accepted {label}")
    return refused


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 17
PINNED_CONTROLS = 65
ITEM_PATH = ".tasks/items/zenoh-rmw-booted.zt"


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    from harness import ROOT

    path = ROOT / ITEM_PATH
    if not path.is_file():
        return 0, 0
    text = path.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls_ = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls_.group(1)) if controls_ else 0)
