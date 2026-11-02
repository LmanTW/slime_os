"""Judge what the Zenoh service prints when holders exchange samples through it under QEMU.

The booted composition `sel4-zenoh-service` runs the service and two holders. The service prints one line for each thing it
did, and every line names the holder it concerns. This module judges those lines and nothing else, so it names no holder
and no component but the service:

* every holder attaches once, before it publishes or is delivered a sample;
* a publication is delivered to exactly as many holders as it says it reached, and to no others;
* a holder that publishes does so in increasing sequence order;
* the service refuses a key a holder lacks, once, with the class `not-granted`;
* every holder detaches after its last publication or delivery.

The lines come from the guest, so the judge is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re

GENERATION = 171
CLOSURE = "sel4-zenoh-service"
SERVICE = "zenoh-service"
SAMPLES = 4
PUBLISHER = "alpha"
SUBSCRIBER = "beta"

GRANTS = re.compile(rf"\[{SERVICE}\] grants rows=(\d+) holders=(\d+)")
ATTACHED = re.compile(rf"\[{SERVICE}\] holder attached holder=([\w-]+) rows=(\d+)")
PUBLISHED = re.compile(rf"\[{SERVICE}\] published holder=([\w-]+) row=(\d+) sequence=(\d+) reached=(\d+) peer=(none|sent)")
DELIVERED = re.compile(rf"\[{SERVICE}\] delivered holder=([\w-]+) row=(\d+) sequence=(\d+)")
DENIAL = re.compile(rf"\[{SERVICE}\] denial class=([\w-]+) holder=([\w-]+) refused=(\d+)")
DETACHED = re.compile(rf"\[{SERVICE}\] holder detached holder=([\w-]+)")
KINDS = (GRANTS, ATTACHED, PUBLISHED, DELIVERED, DENIAL, DETACHED)


class ArmError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ArmError(message)


def synthesize() -> list[str]:
    """What an honest service prints for one publisher and one subscriber of the same key."""
    lines = [
        f"[{SERVICE}] grants rows=2 holders=2",
        f"[{SERVICE}] holder attached holder={PUBLISHER} rows=1",
        f"[{SERVICE}] holder attached holder={SUBSCRIBER} rows=1",
    ]
    for sequence in range(SAMPLES):
        lines.append(f"[{SERVICE}] published holder={PUBLISHER} row=0 sequence={sequence} reached=1 peer=none")
        lines.append(f"[{SERVICE}] delivered holder={SUBSCRIBER} row=0 sequence={sequence}")
    lines += [
        f"[{SERVICE}] denial class=not-granted holder={SUBSCRIBER} refused=1",
        f"[{SERVICE}] holder detached holder={PUBLISHER}",
        f"[{SERVICE}] holder detached holder={SUBSCRIBER}",
    ]
    return lines


def judge(lines: list[str]) -> tuple[int, int]:
    """Check the service's lines. Returns (samples published, refusals the service made)."""
    for line in lines:
        _need(any(kind.fullmatch(line) for kind in KINDS), f"zenoh-service: a line that is not one of the exam's lines: {line!r}")
    grants = [m for line in lines if (m := GRANTS.fullmatch(line))]
    _need(len(grants) == 1, f"zenoh-service: {len(grants)} grants lines, expected exactly one")
    _need(lines[0] == grants[0].string, "zenoh-service: the grants line is not the first")
    declared_rows, declared_holders = int(grants[0].group(1)), int(grants[0].group(2))

    attached: dict[str, int] = {}
    detached: set[str] = set()
    published: dict[tuple[str, int], tuple[int, int, int]] = {}
    delivered: dict[tuple[str, int], int] = {}
    last_sequence: dict[str, int] = {}
    denials = 0
    for line in lines[1:]:
        if m := ATTACHED.fullmatch(line):
            holder, rows = m.group(1), int(m.group(2))
            _need(holder not in attached, f"zenoh-service: {holder} attached twice")
            _need(rows > 0, f"zenoh-service: {holder} attached with no rows")
            attached[holder] = rows
        elif m := PUBLISHED.fullmatch(line):
            holder, row, sequence, reached = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
            _need(holder in attached and holder not in detached, f"zenoh-service: {holder} published without a session")
            _need(row < attached[holder], f"zenoh-service: {holder} published row {row} of {attached[holder]}")
            _need(sequence > last_sequence.get(holder, -1), f"zenoh-service: {holder} published sequence {sequence} out of order")
            _need((holder, sequence) not in published, f"zenoh-service: {holder} published sequence {sequence} twice")
            last_sequence[holder] = sequence
            published[(holder, sequence)] = (row, reached, 0)
        elif m := DELIVERED.fullmatch(line):
            holder, row, sequence = m.group(1), int(m.group(2)), int(m.group(3))
            _need(holder in attached and holder not in detached, f"zenoh-service: {holder} was delivered a sample without a session")
            sources = [key for key in published if key[1] == sequence]
            _need(len(sources) == 1, f"zenoh-service: {holder} was delivered sequence {sequence}, which {len(sources)} holders published before")
            _need(published[sources[0]][0] == row, f"zenoh-service: {holder} was delivered sequence {sequence} on row {row}, not the published row")
            delivered[sources[0]] = delivered.get(sources[0], 0) + 1
            _need(delivered[sources[0]] <= published[sources[0]][1], f"zenoh-service: sequence {sequence} was delivered to more holders than it reached")
        elif m := DENIAL.fullmatch(line):
            _need(m.group(1) == "not-granted" and m.group(3) == "1", f"zenoh-service: a denial that is not a single not-granted refusal: {line!r}")
            _need(m.group(2) in attached, f"zenoh-service: a denial for {m.group(2)}, which never attached")
            denials += 1
        elif m := DETACHED.fullmatch(line):
            holder = m.group(1)
            _need(holder in attached and holder not in detached, f"zenoh-service: {holder} detached without a session")
            detached.add(holder)
    _need(len(attached) == declared_holders, f"zenoh-service: {len(attached)} holders attached, the grants line says {declared_holders}")
    _need(sum(attached.values()) == declared_rows, f"zenoh-service: the holders attached with {sum(attached.values())} rows, the grants line says {declared_rows}")
    _need(detached == set(attached), "zenoh-service: a holder did not detach")
    _need(len(published) == SAMPLES, f"zenoh-service: {len(published)} samples published, expected {SAMPLES}")
    for key, (_row, reached, _) in published.items():
        _need(delivered.get(key, 0) == reached, f"zenoh-service: sequence {key[1]} reached {reached} holders and was delivered to {delivered.get(key, 0)}")
    _need(denials == 1, f"zenoh-service: {denials} denials, expected exactly one")
    return len(published), denials


def mutations() -> list[tuple[str, list[str]]]:
    good = synthesize()
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line the exam does not list", [*good, f"[{SERVICE}] holder resumed holder={PUBLISHER}"]),
        ("a line repeated", [*good, good[-1]]),
        ("the grants line second", [good[1], good[0], *good[2:]]),
        ("a second grants line", [good[0], *good]),
        ("a holder attached twice", [*good[:2], good[1], *good[2:]]),
        ("a holder with no rows", [good[0], good[1].replace("rows=1", "rows=0"), *good[2:]]),
        ("a publication before the attach", [good[0], good[3], good[1], good[2], *good[4:]]),
        ("a publication on a row the holder lacks", [good[3].replace("row=0", "row=1") if i == 3 else line for i, line in enumerate(good)]),
        ("a sequence published twice", [*good[:5], good[3], *good[5:]]),
        ("a sequence published out of order", [*good[:3], good[5], good[6], good[3], good[4], *good[7:]]),
        ("a delivery with no publication", [*good[:3], good[4], good[3], *good[5:]]),
        ("a delivery on another row", [line.replace("delivered holder=beta row=0", "delivered holder=beta row=1") if i == 4 else line for i, line in enumerate(good)]),
        ("a delivery twice", [*good[:5], good[4], *good[5:]]),
        ("a reach of zero with a delivery", [line.replace("reached=1", "reached=0") if i == 3 else line for i, line in enumerate(good)]),
        ("a reach of two with one delivery", [line.replace("reached=1", "reached=2") if i == 3 else line for i, line in enumerate(good)]),
        ("a delivery to a holder that never attached", [line.replace("holder=beta row=0", "holder=gamma row=0") if i == 4 else line for i, line in enumerate(good)]),
        ("a delivery after the holder detached", [*good[:3], good[3], good[-1], good[4], *good[5:-1]]),
        ("no denial", [line for line in good if "denial" not in line]),
        ("two denials", [*good[:-2], good[-3], *good[-2:]]),
        ("a denial of another class", [line.replace("not-granted", "unknown") for line in good]),
        ("a denial that refused nothing", [line.replace("refused=1", "refused=0") for line in good]),
        ("a denial for a holder that never attached", [line.replace("holder=beta refused", "holder=gamma refused") for line in good]),
        ("a holder that never detached", good[:-1]),
        ("a holder detached twice", [*good, good[-1]]),
        ("one sample fewer", [line for line in good if "sequence=3" not in line]),
        ("a peer that is neither none nor sent", [line.replace("peer=none", "peer=maybe") if i == 3 else line for i, line in enumerate(good)]),
        ("a rows count the grants line does not give", [line.replace("rows=2", "rows=3") if i == 0 else line for i, line in enumerate(good)]),
        ("a holders count the grants line does not give", [line.replace("holders=2", "holders=3") if i == 0 else line for i, line in enumerate(good)]),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index + 1} ({line[15:60]}) missing", good[:index] + good[index + 1 :]))
    return out


def controls() -> int:
    """The honest transcript is accepted. Every mutation of it is refused. Returns the number refused."""
    good = synthesize()
    _need(judge(good) == (SAMPLES, 1), "zenoh-service: the honest transcript was not accepted")
    refused = 0
    for label, lines in mutations():
        _need(lines != good, f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except ArmError:
            refused += 1
            continue
        raise ArmError(f"control: the zenoh-service judge accepted {label}")
    return refused
