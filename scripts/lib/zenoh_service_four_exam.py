"""Judge the composition that runs the Zenoh service with four holders and six rows.

The component is built for four holders and six rows. The composition `sel4-zenoh-service-four` runs the service, the peer and
four holders. `alpha` publishes the exchange key and `beta` subscribes to it. `gamma` and `delta` each hold two subscribe rows,
the command key as row 0 and the exchange key as row 1, so a delivery to them arrives on a row that differs from the row of its
publication. That is six rows in four holders. This module judges what the component and the composition declare, and what
they print under QEMU. The service's own lines go through `zenoh_service_arm` with the grants of this composition.

The facts the files hold are read by pattern and checked first against a synthetic file set, as in
`zenoh_service_component_exam`. A pattern shows that a declaration exists and not what the code does. The booted exchange
shows what the code does. The lines come from the guest, so the judge is trusted only after it refuses a mutation of an honest
transcript. Nothing here reads the Rust of a holder.
"""

from __future__ import annotations

import re

import zenoh_facts as facts
import zenoh_service_arm as arm
from harness import ROOT

SYSTEM = arm.FOUR_CLOSURE
SPEC = f"contracts/system-spec/v1/systems/{SYSTEM}.zti"
MANIFEST = f"contracts/generation-manifest/v1/compositions/{SYSTEM}.zti"
MAIN = "components/services/zenoh-service/src/main.rs"
PLANE = "scripts/check/check-sel4-io-network-plane.py"
HOLDERS = ("alpha", "beta", "delta", "gamma")
EXCHANGE = arm.EXCHANGE
COMMAND = arm.COMMAND
SAMPLES = arm.SAMPLES

FACTS: tuple[facts.Fact, ...] = (
    ("component-holders", MAIN, r"^pub const HOLDERS: usize = 4;$", "pub const HOLDERS: usize = 4;"),
    ("component-rows", MAIN, r"^pub const ROWS: usize = 6;$", "pub const ROWS: usize = 6;"),
    ("spec-name", SPEC, rf'^\s*name = "{SYSTEM}";$', f'  name = "{SYSTEM}";'),
    ("spec-generation", SPEC, rf"^\s*generation = {arm.FOUR_GENERATION};$", f"  generation = {arm.FOUR_GENERATION};"),
    ("spec-limits", SPEC, r"\bzenohLimits = \{ holders = 4; ringSlots = 4; sampleBytes = 12; keyBytes = 129; localSubscriptions = 3; stackBytes = 32768; \}",
     '    { name = "zenoh-service"; zenohLimits = { holders = 4; ringSlots = 4; sampleBytes = 12; keyBytes = 129; localSubscriptions = 3; stackBytes = 32768; }; };'),
    ("spec-pages", SPEC, r"\bbufferBytePages = 8; bufferCount = 8; mappingCount = 10; loanCount = 8;",
     '    { name = "zenoh-service"; bufferBytePages = 8; bufferCount = 8; mappingCount = 10; loanCount = 8; };'),
    ("spec-gamma", SPEC, r'\bname = "gamma"; executable = "zenoh-holder-gamma";', '    { name = "gamma"; executable = "zenoh-holder-gamma"; };'),
    ("spec-delta", SPEC, r'\bname = "delta"; executable = "zenoh-holder-delta";', '    { name = "delta"; executable = "zenoh-holder-delta"; };'),
    ("spec-provision-pins", SPEC, r'grant = "delta-zenoh-provision"; slot = 28;(?:.|\n)*?grant = "gamma-zenoh-provision"; slot = 27;',
     '    { grant = "delta-zenoh-provision"; slot = 28; };\n    { grant = "gamma-zenoh-provision"; slot = 27; };'),
    ("spec-grants", SPEC, r"^\s*zenohGrants = \[\n(?:\s+\{ holder = \"[\w-]+\"; key[^\n]*\n){6}\s*\];$",
     "  zenohGrants = [\n" + "".join('    { holder = "a"; key = "k"; };\n' for _ in range(6)) + "  ];"),
    ("manifest-generation", MANIFEST, rf"^\s*generation = {arm.FOUR_GENERATION};$", f"  generation = {arm.FOUR_GENERATION};"),
    ("manifest-grants", MANIFEST, r"^\s*zenohGrants = \[$", "  zenohGrants = ["),
    ("inventory", "contracts/composition-inventory/v1/inventory.zti", rf'composition = "{SYSTEM}";(?:(?!\n    \}};)[^}}])*?owningGate = "zenoh_service_four_check";',
     f'    {{\n      composition = "{SYSTEM}";\n      owningGate = "zenoh_service_four_check";\n    }};'),
    ("closure-source", f"contracts/system-image-closure/v3/closures/{SYSTEM}.zti", rf'^\s*name = "{SYSTEM}";$', f'  name = "{SYSTEM}";'),
    ("test-run-record", f"contracts/system-test-run/v2/runs/{SYSTEM}.zti", rf'^\s*imageClosure = "{SYSTEM}";$', f'  imageClosure = "{SYSTEM}";'),
    ("arm-choice", PLANE, r'"zenoh-service-four"', 'choices=("zenoh-service", "zenoh-service-four")'),
    ("arm-function", PLANE, r"^def run_zenoh_service_four_arm\(", "def run_zenoh_service_four_arm(transcript_path: Path | None) -> None:"),
    ("arm-chains", PLANE, r"^ZENOH_SERVICE_FOUR_CHAINS\b", "ZENOH_SERVICE_FOUR_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = ("),
    ("peer-link", "components/applications/zenoh-peer/src/main.rs", r"\bper_side: 3,", "            per_side: 3,"),
    ("holder-gamma", "components/applications/zenoh-holder-gamma/src/main.rs", r"^const EXCHANGE_ROW: usize = 1;$", "const EXCHANGE_ROW: usize = 1;"),
    ("holder-delta", "components/applications/zenoh-holder-delta/src/main.rs", r"^const EXCHANGE_ROW: usize = 1;$", "const EXCHANGE_ROW: usize = 1;"),
)

PEER = "zenoh-peer"
RECEIVED = re.compile(rf"\[{PEER}\] received sequence=(\d+) len=(\d+) first=(\d+)")


class FourExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise FourExamError(message)


def read_file(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        raise FourExamError(f"{path} cannot be read: {error}") from error


def check_facts() -> int:
    try:
        return facts.check(FACTS, read_file)
    except facts.FactsError as error:
        raise FourExamError(str(error)) from error


def fact_controls() -> int:
    try:
        return facts.controls(FACTS)
    except facts.FactsError as error:
        raise FourExamError(str(error)) from error


# The grants of the composition, as the service numbers a holder's rows: by holder name, then key.
GRANTS: arm.Grants = {
    "alpha": [(EXCHANGE, True, False)],
    "beta": [(EXCHANGE, False, True)],
    "delta": [(COMMAND, False, True), (EXCHANGE, False, True)],
    "gamma": [(COMMAND, False, True), (EXCHANGE, False, True)],
}
# Where each subscriber receives the exchange key: the row that holds it.
EXCHANGE_ROW = {"beta": 0, "delta": 1, "gamma": 1}
# The order holders detach in under the boot that proved this composition. The judge holds no order between detaches.
DETACH = ("delta", "gamma", "beta", "alpha")


def synthesize() -> list[str]:
    """What an honest run prints: the service's lines, and the peer's lines in the places the boot printed them."""
    s = arm.SERVICE
    rows = sum(len(r) for r in GRANTS.values())
    lines = [f"[{s}] grants rows={rows} holders={len(GRANTS)}"]
    lines += [f"[{s}] holder attached holder={h} rows={len(GRANTS[h])}" for h in sorted(GRANTS)]
    lines += [f"[{PEER}] session open", f"[{PEER}] declared subscriber key={EXCHANGE}"]
    for sequence in range(SAMPLES):
        lines.append(f"[{s}] published holder=alpha row=0 sequence={sequence} reached=3 peer=sent")
        lines += [f"[{s}] delivered holder={h} row={EXCHANGE_ROW[h]} sequence={sequence}" for h in ("beta", "delta", "gamma")]
        lines.append(f"[{PEER}] received sequence={sequence} len=12 first={sequence}")
    lines.append(f"[{s}] denial class=not-granted holder=beta refused=1")
    lines += [f"[{s}] holder detached holder={h}" for h in DETACH]
    lines.append(f"[{PEER}] session closed")
    return lines


def judge(lines: list[str]) -> tuple[int, int, int]:
    """Check both components' lines. Returns (samples published, refusals, samples the peer received)."""
    service = [line for line in lines if line.startswith(f"[{arm.SERVICE}] ")]
    peer = [line for line in lines if line.startswith(f"[{PEER}] ")]
    _need(len(service) + len(peer) == len(lines), "a line that belongs to neither the service nor the peer")
    try:
        published, refusals = arm.judge(service, GRANTS)
    except arm.ArmError as error:
        raise FourExamError(str(error)) from error
    received = [m for line in peer if (m := RECEIVED.fullmatch(line))]
    _need(len(received) == SAMPLES, f"{PEER}: {len(received)} samples received, expected {SAMPLES}")
    for number, m in enumerate(received):
        _need(int(m.group(1)) == number and m.group(2) == "12" and int(m.group(3)) == number, f"{PEER}: sample {number} arrived as {m.group(0)!r}")
    sent = [m.group(5) for line in service if (m := arm.PUBLISHED.fullmatch(line))]
    _need(sent == ["sent"] * SAMPLES, f"{arm.SERVICE}: peer flags {sent}, expected sent for each")
    opened = [i for i, line in enumerate(peer) if line == f"[{PEER}] session open"]
    declared = [i for i, line in enumerate(peer) if line == f"[{PEER}] declared subscriber key={EXCHANGE}"]
    closed = [i for i, line in enumerate(peer) if line == f"[{PEER}] session closed"]
    _need(len(opened) == 1 and len(closed) == 1 and opened[0] < closed[0], f"{PEER}: the session did not open once and close once")
    _need(len(declared) == 1, f"{PEER}: {len(declared)} subscriber declarations on {EXCHANGE}, expected exactly one")
    _need(opened[0] < declared[0] < closed[0], f"{PEER}: the declaration is not between the session's open and close")
    unknown = [line for line in peer if not (RECEIVED.fullmatch(line) or line in (peer[opened[0]], peer[declared[0]], peer[closed[0]]))]
    _need(not unknown, f"{PEER}: a line that is not one of the exam's lines: {unknown[:1]!r}")
    return published, refusals, len(received)


def mutations() -> list[tuple[str, list[str]]]:
    good = synthesize()
    first_publication = next(i for i, line in enumerate(good) if "published holder=alpha" in line)

    def edited(index: int, old: str, new: str) -> list[str]:
        return [line.replace(old, new) if i == index else line for i, line in enumerate(good)]

    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line of another component", [*good, "[zenoh-holder] attached"]),
        ("a fifth holder", [*good[:5], f"[{arm.SERVICE}] holder attached holder=epsilon rows=1", *good[5:]]),
        ("gamma delivered on the command row", [line.replace("holder=gamma row=1", "holder=gamma row=0") if i == good.index(next(x for x in good if "delivered holder=gamma" in x)) else line for i, line in enumerate(good)]),
        ("delta delivered on the command row", [line.replace("holder=delta row=1", "holder=delta row=0") if i == good.index(next(x for x in good if "delivered holder=delta" in x)) else line for i, line in enumerate(good)]),
        ("beta delivered on a second row it does not hold", [line.replace("holder=beta row=0", "holder=beta row=1") if i == good.index(next(x for x in good if "delivered holder=beta" in x)) else line for i, line in enumerate(good)]),
        ("a reach of two with three deliveries", edited(first_publication, "reached=3", "reached=2")),
        ("a reach of four", edited(first_publication, "reached=3", "reached=4")),
        # The peer's order: the declaration follows the session's open, and no other line is the peer's.
        ("the peer's declaration before its session opens", [*good[:5], good[6], good[5], *good[7:]]),
        ("a peer line the exam does not list", [*good[:6], f"[{PEER}] resumed", *good[6:]]),
        ("a delivery repeated", [*good[: first_publication + 2], good[first_publication + 1], *good[first_publication + 2 :]]),
        ("a peer copy reported as none", edited(first_publication, "peer=sent", "peer=none")),
        ("a peer sample with the wrong payload", [line.replace("first=1", "first=7") for line in good]),
        ("a second denial", [*good[:-5], f"[{arm.SERVICE}] denial class=not-granted holder=beta refused=1", *good[-5:]]),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index + 1} ({line[1:40]}) missing", good[:index] + good[index + 1 :]))
    return out


def controls() -> int:
    """The honest transcript is accepted and every mutation of it is refused. Returns the number refused."""
    good = synthesize()
    _need(judge(good) == (SAMPLES, 1, SAMPLES), "zenoh-service-four: the honest transcript was not accepted")
    refused = 0
    seen: dict[tuple[str, ...], str] = {}
    for label, lines in mutations():
        _need(lines != good, f"control: {label} did not change the transcript")
        _need(tuple(lines) not in seen, f"control: {label} repeats {seen.get(tuple(lines))}")
        seen[tuple(lines)] = label
        try:
            judge(lines)
        except FourExamError:
            refused += 1
            continue
        raise FourExamError(f"control: the zenoh-service-four judge accepted {label}")
    return refused


PINNED_CASES = len(FACTS)
