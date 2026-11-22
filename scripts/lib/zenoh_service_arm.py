"""Judge what the Zenoh service prints when holders exchange samples through it under QEMU.

The booted composition `sel4-zenoh-service` runs the service and two holders. The service prints one line for each thing it
did, and every line names the holder it concerns. This module judges those lines and nothing else, so it names no holder
and no component but the service:

* every holder attaches once, before it publishes or is delivered a sample;
* a publication is delivered to exactly as many holders as it says it reached, and to no others;
* a holder that publishes does so in increasing sequence order;
* the service refuses a key a holder lacks, once, with the class `not-granted`;
* every holder detaches after its last publication or delivery.

* a delivery names the receiving holder's own row, and that row holds the key of the publication it answers. The service
  prints each holder's own row index, so the judge reads the rows of each holder from the system spec of the composition and
  resolves an index to a key with them.

The lines come from the guest, so the judge is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re

from harness import ROOT

GENERATION = 171
CLOSURE = "sel4-zenoh-service"
SPEC_ROOT = ROOT / "contracts" / "system-spec" / "v1" / "systems"
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


ROW = re.compile(r'\{ holder = "([\w-]+)"; key = "([^"]+)"; publish = (true|false); subscribe = (true|false); \}')


class ArmError(Exception):
    pass


Grants = dict[str, list[tuple[str, bool, bool]]]


def read_grants(text: str | None = None, closure: str = CLOSURE) -> Grants:
    """Each holder's rows as (key, publish, subscribe), in the order the grants table sorts them: by holder name, then key.

    The rows come from the `zenohGrants` of the composition's system spec. The service numbers a holder's rows in that
    order, so an index in a transcript names the row at that place in this list."""
    body = text if text is not None else (SPEC_ROOT / f"{closure}.zti").read_text(encoding="utf-8")
    found = ROW.findall(body)
    _need(bool(found), f"{closure}: the system spec declares no zenohGrants rows")
    rows = sorted(((h.encode("ascii"), k.encode("ascii"), p == "true", s == "true") for h, k, p, s in found))
    grants: Grants = {}
    for holder, key, publish, subscribe in rows:
        grants.setdefault(holder.decode(), []).append((key.decode(), publish, subscribe))
    return grants


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


EXCHANGE = "0/slime_service/exchange"
COMMAND = "0/slime_service/command"
# alpha publishes the exchange key. beta subscribes to the command key (row 0) and the exchange key (row 1). gamma subscribes to
# the exchange key (row 0). delta publishes the command key and holds no subscribe row. Rows are in the table's sort order.
RICH: Grants = {
    "alpha": [(EXCHANGE, True, False)],
    "beta": [(COMMAND, False, True), (EXCHANGE, False, True)],
    "delta": [(COMMAND, True, False)],
    "gamma": [(EXCHANGE, False, True)],
}


def synthesize_rich() -> list[str]:
    """What an honest service prints for RICH: alpha's four publications reach beta on its row 1 and gamma on its row 0."""
    rows = sum(len(r) for r in RICH.values())
    lines = [f"[{SERVICE}] grants rows={rows} holders={len(RICH)}"]
    lines += [f"[{SERVICE}] holder attached holder={h} rows={len(RICH[h])}" for h in sorted(RICH)]
    for sequence in range(SAMPLES):
        lines.append(f"[{SERVICE}] published holder=alpha row=0 sequence={sequence} reached=2 peer=none")
        lines.append(f"[{SERVICE}] delivered holder=beta row=1 sequence={sequence}")
        lines.append(f"[{SERVICE}] delivered holder=gamma row=0 sequence={sequence}")
    lines.append(f"[{SERVICE}] denial class=not-granted holder=gamma refused=1")
    lines += [f"[{SERVICE}] holder detached holder={h}" for h in sorted(RICH)]
    return lines


def judge(lines: list[str], grants: Grants | None = None) -> tuple[int, int]:
    """Check the service's lines against the grants of the composition. Returns (samples published, refusals made)."""
    held = read_grants() if grants is None else grants
    for line in lines:
        _need(any(kind.fullmatch(line) for kind in KINDS), f"zenoh-service: a line that is not one of the exam's lines: {line!r}")
    grants = [m for line in lines if (m := GRANTS.fullmatch(line))]
    _need(len(grants) == 1, f"zenoh-service: {len(grants)} grants lines, expected exactly one")
    _need(lines[0] == grants[0].string, "zenoh-service: the grants line is not the first")
    declared_rows, declared_holders = int(grants[0].group(1)), int(grants[0].group(2))

    attached: dict[str, int] = {}
    detached: set[str] = set()
    published: dict[tuple[str, int], tuple[int, int, int]] = {}
    keys: dict[tuple[str, int], str] = {}
    delivered: dict[tuple[str, int], set[str]] = {}
    last_sequence: dict[str, int] = {}
    denials = 0
    for line in lines[1:]:
        if m := ATTACHED.fullmatch(line):
            holder, rows = m.group(1), int(m.group(2))
            _need(holder not in attached, f"zenoh-service: {holder} attached twice")
            _need(rows > 0, f"zenoh-service: {holder} attached with no rows")
            _need(holder in held, f"zenoh-service: {holder} attached, and the grants of the composition name no such holder")
            attached[holder] = rows
        elif m := PUBLISHED.fullmatch(line):
            holder, row, sequence, reached = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
            _need(holder in attached and holder not in detached, f"zenoh-service: {holder} published without a session")
            _need(row < attached[holder], f"zenoh-service: {holder} published row {row} of {attached[holder]}")
            _need(held[holder][row][1], f"zenoh-service: {holder} published on row {row}, which only subscribes")
            _need(sequence > last_sequence.get(holder, -1), f"zenoh-service: {holder} published sequence {sequence} out of order")
            _need((holder, sequence) not in published, f"zenoh-service: {holder} published sequence {sequence} twice")
            last_sequence[holder] = sequence
            published[(holder, sequence)] = (row, reached, 0)
            keys[(holder, sequence)] = held[holder][row][0]
        elif m := DELIVERED.fullmatch(line):
            holder, row, sequence = m.group(1), int(m.group(2)), int(m.group(3))
            _need(holder in attached and holder not in detached, f"zenoh-service: {holder} was delivered a sample without a session")
            sources = [key for key in published if key[1] == sequence]
            _need(len(sources) == 1, f"zenoh-service: {holder} was delivered sequence {sequence}, which {len(sources)} holders published before")
            _need(row < attached[holder], f"zenoh-service: {holder} was delivered on row {row} of {attached[holder]}")
            _need(held[holder][row][0] == keys[sources[0]], f"zenoh-service: {holder} was delivered sequence {sequence} on row {row}, which holds {held[holder][row][0]}, not {keys[sources[0]]}")
            reached_by = delivered.setdefault(sources[0], set())
            _need(holder not in reached_by, f"zenoh-service: {holder} was delivered sequence {sequence} twice")
            reached_by.add(holder)
            _need(len(reached_by) <= published[sources[0]][1], f"zenoh-service: sequence {sequence} was delivered to more holders than it reached")
        elif m := DENIAL.fullmatch(line):
            _need(m.group(1) == "not-granted" and m.group(3) == "1", f"zenoh-service: a denial that is not a single not-granted refusal: {line!r}")
            _need(m.group(2) in attached, f"zenoh-service: a denial for {m.group(2)}, which never attached")
            _need(m.group(2) not in detached, f"zenoh-service: a denial for {m.group(2)}, whose session had ended")
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
        _need(len(delivered.get(key, set())) == reached, f"zenoh-service: sequence {key[1]} reached {reached} holders and was delivered to {len(delivered.get(key, set()))}")
        subscribers = {h for h, rows in held.items() if h in attached and any(k == keys[key] and sub for k, _p, sub in rows)}
        _need(reached == len(subscribers), f"zenoh-service: sequence {key[1]} reached {reached} holders, {len(subscribers)} attached holders subscribe to {keys[key]}")
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
        ("one holder delivered twice for a reach of two", [good[0], good[1], good[2], good[3].replace("reached=1", "reached=2"), good[4], good[4], *good[5:]]),
        ("a reach of zero with a delivery", [line.replace("reached=1", "reached=0") if i == 3 else line for i, line in enumerate(good)]),
        ("a reach of two with one delivery", [line.replace("reached=1", "reached=2") if i == 3 else line for i, line in enumerate(good)]),
        ("a delivery to a holder that never attached", [line.replace("holder=beta row=0", "holder=gamma row=0") if i == 4 else line for i, line in enumerate(good)]),
        ("a delivery after the holder detached", [*good[:3], good[3], good[-1], good[4], *good[5:-1]]),
        ("no denial", [line for line in good if "denial" not in line]),
        ("two denials", [*good[:-2], good[-3], *good[-2:]]),
        ("a denial of another class", [line.replace("not-granted", "unknown") for line in good]),
        ("a denial that refused nothing", [line.replace("refused=1", "refused=0") for line in good]),
        ("a denial after the denied holder detached", [*good[:-3], good[-1], good[-3], good[-2]]),
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


# The grants of the control that judges the honest RICH transcript against two of its four holders.
TWO_HOLDERS: Grants = {holder: RICH[holder] for holder in ("alpha", "beta")}


def rich_mutations() -> list[tuple[str, list[str], Grants]]:
    """(label, transcript, grants) for the corruptions of RICH that only the grants can refuse. The merged judge took each."""
    good = synthesize_rich()
    first_delivery = next(i for i, line in enumerate(good) if "delivered holder=beta" in line)
    first_publication = next(i for i, line in enumerate(good) if "published holder=alpha" in line)

    def edited(index: int, old: str, new: str) -> list[str]:
        return [line.replace(old, new) if i == index else line for i, line in enumerate(good)]

    out: list[tuple[str, list[str]]] = [
        ("a delivery on a row that holds another key", edited(first_delivery, "row=1", "row=0")),
        ("a delivery on a row past the receiver's rows", edited(first_delivery, "row=1", "row=2")),
        ("a publication on a row that only subscribes", edited(first_publication, "holder=alpha row=0", "holder=beta row=1")),
        # The reach and the deliveries agree, so only the count of attached subscribers can refuse it: gamma subscribes and is
        # attached, and sequence 0 is not delivered to it. A reach above the subscribers is refused by the deliveries rule.
        ("a reach below the attached holders that subscribe, with the deliveries to match", [line.replace("reached=2", "reached=1") if i == first_publication else line for i, line in enumerate(good) if "delivered holder=gamma row=0 sequence=0" not in line]),
        ("an attach with a row count the grants line does not sum to, on a holder that is never delivered to", edited(next(i for i, line in enumerate(good) if "attached holder=delta" in line), "rows=1", "rows=2")),
        ("an attach of a holder the grants do not name, in place of a named one", [line.replace("holder=delta", "holder=zeta") for line in good]),
        ("a transcript of four holders judged against the grants of two, which names the first holder it does not know", good),
    ]
    return [(label, lines, TWO_HOLDERS if "grants of two" in label else RICH) for label, lines in out]


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
    rich = synthesize_rich()
    _need(judge(rich, RICH) == (SAMPLES, 1), "zenoh-service: the honest transcript of the richer composition was not accepted")
    for label, lines, grants in rich_mutations():
        # A control changes the transcript or the grants it is judged against, and one of them at least.
        _need(lines != rich or grants is not RICH, f"control: {label} changed neither the transcript nor the grants")
        try:
            judge(lines, grants)
        except ArmError:
            refused += 1
            continue
        raise ArmError(f"control: the zenoh-service judge accepted {label}")
    return refused
