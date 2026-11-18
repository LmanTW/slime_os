"""Judge what the Zenoh service does with a holder that faults or never detaches.

The service keeps a roster of its holders. A holder is idle until it attaches, attached until it detaches, and settled
once it has detached, died or expired. The service ends when every holder is settled. Death is what the root's
supervision status reports for the holder's task, as `network-service` observes a dead client. A holder that is alive and
has not detached expires when the service has run for `DEADLINE_MS`.

The Rust test `zenoh_service_server_roster::tests::the_holder_fault_exam` replays the scripted events below on the server
half and the roster and prints one `[zenoh-exam] holderfault ...` line for each event. This module holds a reference model
of the rules and writes every expected line from it. Nothing here reads the Rust:

* which holder is reclaimed, by which cause, and which holder only has its death noted;
* that a reclaimed holder is refused every later request and cannot attach again;
* that the other holder is still served: its attach, publish, take and detach answer as before, and a publication reports the core's reach, which a settled holder does not change,
  reports the same reach, the same peer flag and the same sample sequence;
* that the deadline expires exactly at `DEADLINE_MS`, and one millisecond earlier reclaims nothing;
* that a holder is settled once, so a late death report changes nothing;
* when the service is done: only when every holder is settled, whether by detach, death or expiry.

Each wrong rule a service could implement is a flaw of the model. The controls print what that service would print, and
the judge must refuse it. Declarations that files must hold are patterns, and a pattern shows that code exists and not what
it does. This module imports no system spec module and no component spec module.
"""

from __future__ import annotations

import re

import zenoh_facts as facts
from harness import ROOT

TEST = "zenoh_service_server_roster::tests::the_holder_fault_exam"
LINE = re.compile(r"\[zenoh-exam\] (holderfault .*)$")
MARKER = "holderfault"
OK_LINE = "holderfault ok a-faulted-or-silent-holder-is-reclaimed"

DEADLINE_MS = 30000
HOLDERS = 2
RING = 4
SETTLED = ("detached", "dead", "expired")

# Every holder has a row that publishes and subscribes the same key, so a publication reaches both rings.
SCENARIOS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "fault-after-attach",
        (
            "attach0", "attach1", "publish0", "death0", "publish0", "take0", "attach0", "detach0",
            "publish1", "take1", "take1", "take1", "detach1",
        ),
    ),
    ("fault-before-attach", ("death0", "attach0", "attach1", "detach1")),
    (
        "never-detach",
        ("attach0", "attach1", "detach0", f"tick{DEADLINE_MS - 1}", f"tick{DEADLINE_MS}", "detach1"),
    ),
    ("never-attach", ("attach0", "detach0", f"tick{DEADLINE_MS}", "attach1")),
    ("both-fault", ("death0", "death1")),
    ("death-after-detach", ("attach0", "detach0", "death0", "attach1", "detach1")),
    ("death-after-expiry", ("attach0", f"tick{DEADLINE_MS}", "death0", "death1", "detach0")),
    ("silent-live-holder", ("attach0", "attach1", "detach1", "tick100", "publish0", "take0")),
)

FLAWS = (
    "early-deadline",
    "late-deadline",
    "idle-death-reclaimed",
    "dead-attaches",
    "expired-detaches",
    "late-death-unsettles",
    "idle-never-expires",
    "attached-never-expires",
    "reclaimed-before-deadline",
    "done-needs-detach",
    "dead-publishes",
    "dead-takes",
    "survivor-refused",
    "expiry-unlisted",
    "done-on-first-settle",
    "survivor-reach-dropped",
    "reach-follows-sessions",
    "survivor-ring-cleared",
)


class HolderFaultError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise HolderFaultError(message)


def _apply(states: list[str], rings: list, event: str, flaw: str | None) -> str:
    if event.startswith("tick"):
        now = int(event[4:])
        deadline = DEADLINE_MS - 1 if flaw == "early-deadline" else DEADLINE_MS + 1 if flaw == "late-deadline" else DEADLINE_MS
        if flaw == "reclaimed-before-deadline" and now >= 100:
            deadline = 0
        if now < deadline:
            return "expired:none"
        held = [h for h in range(HOLDERS) if states[h] in ("idle", "attached")]
        if flaw == "idle-never-expires":
            held = [h for h in held if states[h] != "idle"]
        if flaw == "attached-never-expires":
            held = [h for h in held if states[h] != "attached"]
        for h in held:
            states[h] = "expired"
        if flaw == "expiry-unlisted":
            return "expired:none"
        return "expired:" + ("+".join(str(h) for h in held) or "none")
    verb, holder = event[:-1], int(event[-1])
    state = states[holder]
    if verb == "attach":
        if state == "idle" or (flaw == "dead-attaches" and state == "dead"):
            states[holder] = "attached"
            return "ok"
        return "denied"
    if verb == "detach":
        if state == "attached" or (flaw == "expired-detaches" and state == "expired"):
            states[holder] = "detached"
            return "ok"
        return "denied"
    if verb == "death":
        if state == "attached":
            states[holder] = "dead"
            return "reclaimed"
        if state == "idle":
            states[holder] = "dead"
            return "reclaimed" if flaw == "idle-death-reclaimed" else "noted"
        if flaw == "late-death-unsettles" and state in ("detached", "expired"):
            states[holder] = "dead"
            return "reclaimed"
        return "ignored"
    if verb == "publish":
        live = state == "attached" or (flaw == "dead-publishes" and state == "dead")
        if flaw == "survivor-refused" and "dead" in states and state == "attached":
            live = False
        if not live:
            return "denied"
        sequence = rings[HOLDERS]
        rings[HOLDERS] = sequence + 1
        # The core counts every holder with a subscribe row, whatever the holder's session. It is outside this
        # item, so the reach does not change when a holder settles.
        live = [h for h in range(HOLDERS) if states[h] == "attached"]
        reached = len([h for h in range(HOLDERS) if states[h] in ("attached", "dead", "expired", "detached", "idle")])
        if flaw == "reach-follows-sessions":
            reached = len(live)
        if flaw == "survivor-reach-dropped":
            reached = max(0, reached - 1)
        for h in range(HOLDERS):
            rings[h] = (rings[h] + [sequence])[-RING:]
        if flaw == "survivor-ring-cleared" and "dead" in states:
            for h in live:
                rings[h] = []
        return f"ok:reached={reached}:peer=none"
    if verb == "take":
        if state != "attached" and not (flaw == "dead-takes" and state == "dead"):
            return "denied"
        if rings[holder]:
            return f"sample:{rings[holder].pop(0)}"
        return "none"
    raise HolderFaultError(f"holder fault model: an event it does not know: {event!r}")


def _done(states: list[str], flaw: str | None) -> bool:
    if flaw == "done-needs-detach":
        return all(s == "detached" for s in states)
    if flaw == "done-on-first-settle":
        return any(s in SETTLED for s in states)
    return all(s in SETTLED for s in states)


def good_lines(flaw: str | None = None) -> list[str]:
    """The transcript of the model, or of the model with one wrong rule, in the order the Rust test prints it."""
    out: list[str] = []
    for name, events in SCENARIOS:
        states = ["idle"] * HOLDERS
        rings: list = [[] for _ in range(HOLDERS)] + [0]
        for number, event in enumerate(events, 1):
            result = _apply(states, rings, event, flaw)
            out.append(f"{MARKER} {name} {number} {event} {result} states {','.join(states)} done {int(_done(states, flaw))}")
    out.append(OK_LINE)
    return out


def _shapes() -> set[int]:
    return {len(line.split()) for line in good_lines()}


def judge(lines: list[str]) -> int:
    """Check a transcript against the model. Returns the number of events judged, which is the lines before the verdict."""
    wanted = good_lines()
    for line in lines:
        _need(line.split()[:1] == [MARKER], f"holder-fault: a record that is not a holder fault line: {line!r}")
        _need(len(line.split()) in _shapes(), f"holder-fault: a line with {len(line.split())} fields: {line}")
    for index, (seen, want) in enumerate(zip(lines, wanted, strict=False)):
        _need(seen == want, f"holder-fault line {index + 1} is {seen!r}, the model requires {want!r}")
    if len(lines) < len(wanted):
        raise HolderFaultError(f"holder-fault: the transcript stops after {len(lines)} of {len(wanted)} lines; the next is {wanted[len(lines)]!r}")
    if len(lines) > len(wanted):
        raise HolderFaultError(f"holder-fault: {len(lines) - len(wanted)} lines beyond the model, the first {lines[len(wanted)]!r}")
    return len(lines) - 1


def exam_lines(stdout: str) -> list[str]:
    return [match.group(1).strip() for line in stdout.splitlines() if (match := LINE.search(line))]


def _change(token: str) -> str:
    return token + "x"


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a holder fault line", [*good, "server ok every-request-is-answered"]),
        ("a line with an extra field", [*good[:-1], good[-1] + " extra"]),
        ("a line repeated", [*good, good[-1]]),
        ("the last two lines swapped", [*good[:-2], good[-1], good[-2]]),
        ("the first two lines swapped", [good[1], good[0], *good[2:]]),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index + 1} ({line[:40]}) missing", good[:index] + good[index + 1 :]))
    for index, line in enumerate(good[:-1]):
        fields = line.split()
        for position, token in enumerate(fields[1:], 2):
            changed = [*fields[:position - 1], _change(token), *fields[position:]]
            out.append((f"line {index + 1} field {position} ({token[:24]}) changed", [*good[:index], " ".join(changed), *good[index + 1 :]]))
    for flaw in FLAWS:
        out.append((f"a service with the flaw {flaw}", good_lines(flaw)))
    return out


def transcript_controls() -> int:
    good = good_lines()
    judge(good)
    refused = 0
    seen: dict[tuple[str, ...], str] = {}
    for label, lines in transcript_mutations():
        if lines == good:
            raise HolderFaultError(f"control: {label} did not change the transcript")
        # Two controls that corrupt the transcript the same way are one control, and the pin counts distinct ones.
        if tuple(lines) in seen:
            raise HolderFaultError(f"control: {label} repeats {seen[tuple(lines)]}")
        seen[tuple(lines)] = label
        try:
            judge(lines)
        except HolderFaultError:
            refused += 1
            continue
        raise HolderFaultError(f"control: the holder fault judge accepted {label}")
    return refused


COMPONENT = "components/services/zenoh-service"
HOLDERS_FILE = f"{COMPONENT}/src/holders.rs"
ROSTER = "components/lib/src/zenoh_service_server_roster.rs"

FACTS: tuple[facts.Fact, ...] = (
    ("roster-export", "components/lib/src/lib.rs", r"^pub mod zenoh_service_server_roster;$", "pub mod zenoh_service_server_roster;"),
    ("roster-test", ROSTER, r"^    fn the_holder_fault_exam\(\) \{$", "    fn the_holder_fault_exam() {"),
    ("server-lose", "components/lib/src/zenoh_service_server.rs", r"^    pub fn lose\(&mut self, holder: usize\)", "    pub fn lose(&mut self, holder: usize) {"),
    ("wait-constant", HOLDERS_FILE, r"^const HOLDER_WAIT_MS: i64 = 30000;$", "const HOLDER_WAIT_MS: i64 = 30000;"),
    ("resolves-supervision", HOLDERS_FILE, r'\bb"minted:"', '    let prefix = b"minted:";'),
    ("polls-supervision", HOLDERS_FILE, r"\bsupervision_status\(", "            match slime_rt::supervision_status(slot) {"),
    ("uses-roster", HOLDERS_FILE, r"\bRoster\b.*::new\(", "    let mut roster = Roster::<{ crate::HOLDERS }>::new(names.count, HOLDER_WAIT_MS);"),
    ("closes-lost-session", HOLDERS_FILE, r"\.lose\(", "            server.lose(index);"),
    ("ends-on-roster", HOLDERS_FILE, r"\broster\.done\(", "    while !roster.done() {"),
    ("prints-reclaim", HOLDERS_FILE, r"\[zenoh-service\] holder reclaimed holder=", '        .bytes(b"[zenoh-service] holder reclaimed holder=")'),
)


def read_file(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        raise HolderFaultError(f"{path} cannot be read: {error}") from error


def check_facts() -> int:
    try:
        return facts.check(FACTS, read_file)
    except facts.FactsError as error:
        raise HolderFaultError(str(error)) from error


def fact_controls() -> int:
    try:
        return facts.controls(FACTS)
    except facts.FactsError as error:
        raise HolderFaultError(str(error)) from error


def all_controls() -> int:
    return transcript_controls() + fact_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 55
PINNED_CONTROLS = 440
ITEM = ROOT / ".tasks" / "items" / "zenoh-holder-fault.zt"


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
