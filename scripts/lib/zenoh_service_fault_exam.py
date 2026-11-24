"""Judge the composition that runs the Zenoh service with a holder that faults under a supervisor.

The composition `sel4-zenoh-service-fault` runs a supervisor, the service, the peer and three holders. `alpha` publishes the
exchange key. `beta` and `victim` subscribe to it. The supervisor owns every other instance and gives the service a supervision
handle for `victim`. `victim` attaches and then writes through a null pointer. The supervisor spawns `alpha` only after it has read
the fault, so the death is on the service's handle before the first publication. This module judges what the service, the
supervisor, the victim and the peer print, and nothing else:

* the victim attaches, faults and is reclaimed once, after it attached, with the cause `dead`;
* a reclaimed holder is never delivered a sample, because each publication is delivered to `beta` alone, and never prints a detach;
* every publication reaches the holders with a subscribe row on its key, a holder that died included, because the core counts
  rows and not sessions. The boot that proved this composition printed `reached=2`, and the judge pins that count;
* the surviving holders attach, take every sample, detach, and exit with status 0;
* the peer receives each sample once, and the service refuses `beta` once.

`zenoh_service_arm` requires every attached holder to detach and a publication's reach to equal the attached subscribers. A death
changes both, so this module states the survivors' rules itself and leaves that judge as merged. The rules are the ones the arm
judge holds for a holder that lives: attach once before any publication or delivery, deliver each sample once on the row that
holds its key, and detach after the last delivery.

The lines come from the guest, so the judge is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re

import zenoh_facts as facts
import zenoh_service_arm as arm
from harness import ROOT

SYSTEM = "sel4-zenoh-service-fault"
GENERATION = 175
SPEC = f"contracts/system-spec/v1/systems/{SYSTEM}.zti"
MANIFEST = f"contracts/generation-manifest/v1/compositions/{SYSTEM}.zti"
PLANE = "scripts/check/check-sel4-io-network-plane.py"
SUPERVISOR_MAIN = "components/applications/zenoh-supervisor/src/main.rs"
VICTIM_MAIN = "components/applications/zenoh-holder-fault/src/main.rs"
EXCHANGE = arm.EXCHANGE
SAMPLES = arm.SAMPLES
SERVICE = arm.SERVICE
PEER = "zenoh-peer"
SUPERVISOR = "zenoh-supervisor"
VICTIM = "victim"
SURVIVORS = ("alpha", "beta")
# The core counts the rows of every holder that subscribes to the key. The victim's row is among them.
REACHED = 2

FACTS: tuple[facts.Fact, ...] = (
    ("spec-name", SPEC, rf'^\s*name = "{SYSTEM}";$', f'  name = "{SYSTEM}";'),
    ("spec-generation", SPEC, rf"^\s*generation = {GENERATION};$", f"  generation = {GENERATION};"),
    ("spec-supervisor", SPEC, r'\bname = "zenoh-supervisor"; executable = "zenoh-supervisor"; dependencies = \[\]; \};',
     '    { name = "zenoh-supervisor"; executable = "zenoh-supervisor"; dependencies = []; };'),
    ("spec-owner-network", SPEC, r'\bname = "network-service"; executable = "network-service"; dependencies = \[\]; owner = "zenoh-supervisor";',
     '    { name = "network-service"; executable = "network-service"; dependencies = []; owner = "zenoh-supervisor"; };'),
    ("spec-owner-service", SPEC, r'\bname = "zenoh-service"; executable = "zenoh-service"; dependencies = \[\]; owner = "zenoh-supervisor";',
     '    { name = "zenoh-service"; executable = "zenoh-service"; dependencies = []; owner = "zenoh-supervisor"; };'),
    ("spec-owner-peer", SPEC, r'\bname = "zenoh-peer"; executable = "zenoh-peer"; dependencies = \[\]; owner = "zenoh-supervisor";',
     '    { name = "zenoh-peer"; executable = "zenoh-peer"; dependencies = []; owner = "zenoh-supervisor"; };'),
    ("spec-owner-alpha", SPEC, r'\bname = "alpha"; executable = "zenoh-holder-publisher"; dependencies = \[\]; owner = "zenoh-supervisor";',
     '    { name = "alpha"; executable = "zenoh-holder-publisher"; dependencies = []; owner = "zenoh-supervisor"; };'),
    ("spec-owner-beta", SPEC, r'\bname = "beta"; executable = "zenoh-holder-subscriber"; dependencies = \[\]; owner = "zenoh-supervisor";',
     '    { name = "beta"; executable = "zenoh-holder-subscriber"; dependencies = []; owner = "zenoh-supervisor"; };'),
    ("spec-victim", SPEC, r'\bname = "victim"; executable = "zenoh-holder-fault"; dependencies = \[\]; owner = "zenoh-supervisor";',
     '    { name = "victim"; executable = "zenoh-holder-fault"; dependencies = []; owner = "zenoh-supervisor"; };'),
    ("spec-supervision", SPEC, r'\{ name = "victim-supervision"; owner = "zenoh-supervisor"; holder = "zenoh-service"; capabilityKind = "supervision";',
     '  mintedBindings = [ { name = "victim-supervision"; owner = "zenoh-supervisor"; holder = "zenoh-service"; capabilityKind = "supervision"; slot = 25; }; ];'),
    ("spec-grants", SPEC, r"^\s*zenohGrants = \[\n(?:\s+\{ holder = \"[\w-]+\"; key[^\n]*\n){3}\s*\];$",
     "  zenohGrants = [\n" + "".join('    { holder = "a"; key = "k"; };\n' for _ in range(3)) + "  ];"),
    ("manifest-generation", MANIFEST, rf"^\s*generation = {GENERATION};$", f"  generation = {GENERATION};"),
    ("inventory", "contracts/composition-inventory/v1/inventory.zti", rf'composition = "{SYSTEM}";(?:(?!\n    \}};)[^}}])*?owningGate = "zenoh_service_fault_check";',
     f'    {{\n      composition = "{SYSTEM}";\n      owningGate = "zenoh_service_fault_check";\n    }};'),
    ("closure-source", f"contracts/system-image-closure/v3/closures/{SYSTEM}.zti", rf'^\s*name = "{SYSTEM}";$', f'  name = "{SYSTEM}";'),
    ("test-run-record", f"contracts/system-test-run/v2/runs/{SYSTEM}.zti", rf'^\s*imageClosure = "{SYSTEM}";$', f'  imageClosure = "{SYSTEM}";'),
    ("arm-choice", PLANE, r'"zenoh-service-fault"', 'choices=("zenoh-service-four", "zenoh-service-fault")'),
    ("arm-function", PLANE, r"^def run_zenoh_service_fault_arm\(", "def run_zenoh_service_fault_arm(transcript_path: Path | None) -> None:"),
    ("supervisor-reads-fault", SUPERVISOR_MAIN, r"matches!\(outcome, Termination::Fault\(_\)\)", "    if !matches!(outcome, Termination::Fault(_)) {"),
    ("supervisor-spawns-alpha-last", SUPERVISOR_MAIN, r'let alpha = spawn\(b"zenoh-alpha-executable", &\[\]\);', '    let alpha = spawn(b"zenoh-alpha-executable", &[]);'),
    ("victim-faults", VICTIM_MAIN, r"null_mut::<u64>\(\)\)\.write_volatile", "    unsafe { (core::ptr::null_mut::<u64>()).write_volatile(0x5a17) }"),
)

SERVICE_ATTACHED = re.compile(rf"\[{SERVICE}\] holder attached holder=([\w-]+) rows=(\d+)")
RECLAIMED = re.compile(rf"\[{SERVICE}\] holder reclaimed holder=([\w-]+) cause=(dead|expired)")
VICTIM_LINE = f"[{VICTIM}] attached, faulting now"
TERMINATED = f"[{SUPERVISOR}] holder {VICTIM} terminated cause=fault"
SURVIVED = f"[{SUPERVISOR}] survivors exited cleanly"
RECEIVED = re.compile(rf"\[{PEER}\] received sequence=(\d+) len=(\d+) first=(\d+)")
PEER_LINES = (f"[{PEER}] session open", f"[{PEER}] declared subscriber key={EXCHANGE}", f"[{PEER}] session closed")


class FaultExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise FaultExamError(message)


def read_file(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        raise FaultExamError(f"{path} cannot be read: {error}") from error


def check_facts() -> int:
    try:
        return facts.check(FACTS, read_file)
    except facts.FactsError as error:
        raise FaultExamError(str(error)) from error


def fact_controls() -> int:
    try:
        return facts.controls(FACTS)
    except facts.FactsError as error:
        raise FaultExamError(str(error)) from error


# The grants of the composition, as the service numbers a holder's rows: by holder name, then key.
GRANTS: arm.Grants = {
    "alpha": [(EXCHANGE, True, False)],
    "beta": [(EXCHANGE, False, True)],
    VICTIM: [(EXCHANGE, False, True)],
}


def synthesize() -> list[str]:
    """What an honest run prints, in the order the boot that proved this composition printed it."""
    s = SERVICE
    lines = [
        f"[{s}] grants rows=3 holders=3",
        f"[{s}] holder attached holder=beta rows=1",
        f"[{s}] holder attached holder={VICTIM} rows=1",
        VICTIM_LINE,
        TERMINATED,
        f"[{s}] holder reclaimed holder={VICTIM} cause=dead",
        f"[{s}] holder attached holder=alpha rows=1",
        PEER_LINES[0],
        PEER_LINES[1],
    ]
    for sequence in range(SAMPLES):
        lines.append(f"[{s}] published holder=alpha row=0 sequence={sequence} reached={REACHED} peer=sent")
        lines.append(f"[{s}] delivered holder=beta row=0 sequence={sequence}")
        lines.append(f"[{PEER}] received sequence={sequence} len=12 first={sequence}")
    lines += [
        f"[{s}] denial class=not-granted holder=beta refused=1",
        f"[{s}] holder detached holder=beta",
        f"[{s}] holder detached holder=alpha",
        PEER_LINES[2],
        SURVIVED,
    ]
    return lines


def judge_survivors(service: list[str]) -> tuple[int, int]:
    """The rules of `zenoh_service_arm` for the holders that did not die. Returns (samples published, refusals made)."""
    for line in service:
        _need(any(kind.fullmatch(line) for kind in (*arm.KINDS, RECLAIMED)), f"{SERVICE}: a line that is not one of the exam's lines: {line!r}")
    _need(service[0] == f"[{SERVICE}] grants rows=3 holders=3", f"{SERVICE}: the grants line is not the first, or does not state 3 rows and 3 holders")
    _need(sum(1 for line in service if arm.GRANTS.fullmatch(line)) == 1, f"{SERVICE}: more than one grants line")
    attached: dict[str, int] = {}
    detached: set[str] = set()
    published: dict[int, str] = {}
    delivered: dict[int, set[str]] = {}
    denials = 0
    for line in service[1:]:
        if m := SERVICE_ATTACHED.fullmatch(line):
            holder = m.group(1)
            _need(holder in GRANTS, f"{SERVICE}: {holder} attached, and the grants of the composition name no such holder")
            _need(holder not in attached, f"{SERVICE}: {holder} attached twice")
            _need(int(m.group(2)) == len(GRANTS[holder]), f"{SERVICE}: {holder} attached with {m.group(2)} rows, its grants hold {len(GRANTS[holder])}")
            attached[holder] = int(m.group(2))
        elif m := arm.PUBLISHED.fullmatch(line):
            holder, row, sequence = m.group(1), int(m.group(2)), int(m.group(3))
            _need(holder in attached and holder not in detached, f"{SERVICE}: {holder} published without a session")
            _need(row < attached[holder] and GRANTS[holder][row][1], f"{SERVICE}: {holder} published on row {row}, which does not publish")
            _need(sequence == len(published), f"{SERVICE}: {holder} published sequence {sequence} out of order")
            _need(m.group(5) == "sent", f"{SERVICE}: sequence {sequence} did not reach the peer")
            published[sequence] = GRANTS[holder][row][0]
        elif m := arm.DELIVERED.fullmatch(line):
            holder, row, sequence = m.group(1), int(m.group(2)), int(m.group(3))
            _need(holder in attached and holder not in detached, f"{SERVICE}: {holder} was delivered a sample without a session")
            _need(sequence in published, f"{SERVICE}: {holder} was delivered sequence {sequence}, which nobody published")
            _need(row < attached[holder] and GRANTS[holder][row][0] == published[sequence] and GRANTS[holder][row][2], f"{SERVICE}: {holder} was delivered sequence {sequence} on row {row}, which does not hold its key")
            _need(holder not in delivered.setdefault(sequence, set()), f"{SERVICE}: {holder} was delivered sequence {sequence} twice")
            delivered[sequence].add(holder)
        elif m := arm.DENIAL.fullmatch(line):
            _need(m.group(1) == "not-granted" and m.group(3) == "1", f"{SERVICE}: a denial that is not a single not-granted refusal: {line!r}")
            _need(m.group(2) == "beta", f"{SERVICE}: the denial names {m.group(2)}, and only beta asks to publish on a row it may not")
            _need(m.group(2) in attached and m.group(2) not in detached, f"{SERVICE}: a denial for {m.group(2)}, which has no session")
            denials += 1
        elif m := arm.DETACHED.fullmatch(line):
            holder = m.group(1)
            _need(holder in attached and holder not in detached, f"{SERVICE}: {holder} detached without a session")
            detached.add(holder)
    _need(set(attached) == {VICTIM, *SURVIVORS}, f"{SERVICE}: the holders that attached are {sorted(attached)}")
    _need(detached == set(SURVIVORS), f"{SERVICE}: the holders that detached are {sorted(detached)}, the survivors are {sorted(SURVIVORS)}")
    _need(len(published) == SAMPLES, f"{SERVICE}: {len(published)} samples published, expected {SAMPLES}")
    for sequence in range(SAMPLES):
        _need(delivered.get(sequence, set()) == {"beta"}, f"{SERVICE}: sequence {sequence} was delivered to {sorted(delivered.get(sequence, set()))}, expected only beta")
    _need(denials == 1, f"{SERVICE}: {denials} denials, expected exactly one")
    return len(published), denials


def judge(lines: list[str]) -> tuple[int, int, int]:
    """Check every component's lines. Returns (samples published, refusals, samples the peer received)."""
    service = [line for line in lines if line.startswith(f"[{SERVICE}] ")]
    peer = [line for line in lines if line.startswith(f"[{PEER}] ")]
    others = [line for line in lines if line not in service and line not in peer]
    _need(sorted(others) == sorted([VICTIM_LINE, TERMINATED, SURVIVED]), f"lines of other components: {others}")

    attached = [i for i, line in enumerate(service) if (m := SERVICE_ATTACHED.fullmatch(line)) and m.group(1) == VICTIM]
    reclaimed = [i for i, line in enumerate(service) if RECLAIMED.fullmatch(line)]
    _need(len(attached) == 1, f"{SERVICE}: the victim attached {len(attached)} times")
    _need(len(reclaimed) == 1, f"{SERVICE}: {len(reclaimed)} holders were reclaimed, expected 1")
    _need(RECLAIMED.fullmatch(service[reclaimed[0]]).group(1) == VICTIM and service[reclaimed[0]].endswith("cause=dead"), f"{SERVICE}: the reclaim is not of the victim with the cause dead")
    # The fault is printed by the victim before its death, and the supervisor reads the death before the service reclaims it.
    index = {line: lines.index(line) for line in (VICTIM_LINE, TERMINATED)}
    position = {i: lines.index(service[i]) for i in (attached[0], reclaimed[0])}
    _need(position[attached[0]] < index[VICTIM_LINE] < index[TERMINATED], "the victim's fault is not between its attach and the supervisor's read of it")
    _need(index[TERMINATED] < position[reclaimed[0]], "the service reclaimed the victim before the supervisor read its fault")

    # `alpha` attaches after the reclaim. It publishes only once attached, so every publication follows the death.
    alpha_attached = [i for i, line in enumerate(service) if (m := SERVICE_ATTACHED.fullmatch(line)) and m.group(1) == "alpha"]
    _need(len(alpha_attached) == 1, f"{SERVICE}: alpha attached {len(alpha_attached)} times")
    _need(reclaimed[0] < alpha_attached[0], f"{SERVICE}: alpha attached before the victim was reclaimed")
    for line in service:
        if (m := arm.PUBLISHED.fullmatch(line)):
            _need(int(m.group(4)) == REACHED, f"{SERVICE}: a publication reached {m.group(4)} holders, the core counts {REACHED} rows")

    published, refusals = judge_survivors(service)
    received = [m for line in peer if (m := RECEIVED.fullmatch(line))]
    _need(len(received) == SAMPLES, f"{PEER}: {len(received)} samples received, expected {SAMPLES}")
    for number, m in enumerate(received):
        _need(int(m.group(1)) == number and m.group(2) == "12" and int(m.group(3)) == number, f"{PEER}: sample {number} arrived as {m.group(0)!r}")
    others_in_peer = [line for line in peer if not RECEIVED.fullmatch(line)]
    _need(others_in_peer == [PEER_LINES[0], PEER_LINES[1], PEER_LINES[2]], f"{PEER}: lines that are not the exam's: {others_in_peer}")
    _need(lines[-1] == SURVIVED, "the supervisor's report of the survivors is not the last line")
    return published, refusals, len(received)


def _alpha_early(good: list[str]) -> list[str]:
    """`alpha` attaches between the victim's attach and its fault."""
    line = f"[{SERVICE}] holder attached holder=alpha rows=1"
    rest = [x for x in good if x != line]
    return [*rest[:3], line, *rest[3:]]


def _exchange_early(good: list[str]) -> list[str]:
    """The attach of `alpha`, every publication, delivery and peer receipt come before the victim's fault."""
    attach = f"[{SERVICE}] holder attached holder=alpha rows=1"
    moved = [attach] + [x for x in good if "published holder=alpha" in x or "delivered holder=beta" in x or "received sequence=" in x]
    rest = [x for x in good if x not in moved]
    return [*rest[:3], *moved, *rest[3:]]


def mutations() -> list[tuple[str, list[str]]]:
    good = synthesize()
    first_publication = next(i for i, line in enumerate(good) if "published holder=alpha" in line)

    def edited(index: int, old: str, new: str) -> list[str]:
        return [line.replace(old, new) if i == index else line for i, line in enumerate(good)]

    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line of another component", [*good[:-1], "[zenoh-holder] attached", good[-1]]),
        ("the victim reclaimed with the cause expired", [line.replace("cause=dead", "cause=expired") for line in good]),
        ("the victim reclaimed twice", [*good[:6], good[5], *good[6:]]),
        ("a publication that reached 1 holder", edited(first_publication, f"reached={REACHED}", "reached=1")),
        ("a publication that reached 3 holders", edited(first_publication, f"reached={REACHED}", "reached=3")),
        ("the victim delivered a sample", [*good[: first_publication + 2], f"[{SERVICE}] delivered holder={VICTIM} row=0 sequence=0", *good[first_publication + 2 :]]),
        ("the victim detached", [*good[:-3], f"[{SERVICE}] holder detached holder={VICTIM}", *good[-3:]]),
        ("the victim attached twice", [*good[:3], good[2], *good[3:]]),
        ("the victim's fault line before its attach", [good[0], good[1], good[3], good[2], good[4], *good[5:]]),
        ("the reclaim before the supervisor read the fault", [*good[:4], good[5], good[4], *good[6:]]),
        ("the reclaim before the victim attached", [good[0], good[5], *good[1:5], *good[6:]]),
        ("a publication before the reclaim", [*good[:5], good[first_publication], *good[5:first_publication], *good[first_publication + 1 :]]),
        ("a peer sample with the wrong payload", [line.replace("first=1", "first=7") for line in good]),
        ("alpha attached before the victim's fault", _alpha_early(good)),
        ("the whole exchange before the victim's fault", _exchange_early(good)),
        ("the denial naming the victim", [line.replace("holder=beta refused=1", f"holder={VICTIM} refused=1") for line in good]),
        ("the denial naming alpha", [line.replace("holder=beta refused=1", "holder=alpha refused=1") for line in good]),
        ("a second denial", [*good[:-4], f"[{SERVICE}] denial class=not-granted holder=beta refused=1", *good[-4:]]),
        ("the supervisor's report before the peer closed", [*good[:-2], good[-1], good[-2]]),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index + 1} ({line[1:40]}) missing", good[:index] + good[index + 1 :]))
    return out


def controls() -> int:
    """The honest transcript is accepted and every mutation of it is refused. Returns the number refused."""
    good = synthesize()
    _need(judge(good) == (SAMPLES, 1, SAMPLES), "zenoh-service-fault: the honest transcript was not accepted")
    refused = 0
    seen: dict[tuple[str, ...], str] = {}
    for label, lines in mutations():
        _need(lines != good, f"control: {label} did not change the transcript")
        _need(tuple(lines) not in seen, f"control: {label} repeats {seen.get(tuple(lines))}")
        seen[tuple(lines)] = label
        try:
            judge(lines)
        except FaultExamError:
            refused += 1
            continue
        raise FaultExamError(f"control: the zenoh-service-fault judge accepted {label}")
    return refused
