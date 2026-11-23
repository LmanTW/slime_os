"""Judge the Put path of a client-role link from what the Rust tests print.

A router declares no subscription to a client, and a session refuses a Put on a key its peer did not declare as
`undeclared-key`. A client-role link that opened a session with a router could therefore subscribe and receive, and never
publish. This exam judges the opt-in that changes that: a link with the client role writes a Put on a valid key with no
declaration from its peer, and every other link still refuses one.

The Rust tests under `zenoh_link::put_tests` drive a client-role link through the handshake of the two runs of
`zenoh_rmw_router_data`, fed three ways, and then publish four Puts on the chatter key. They print one
`[zenoh-exam] clientput ...` line for each thing they did. This module builds the whole transcript from the captured
handshakes and `zenoh_wire`, and the Rust must print it, line for line:

* the bytes the link wrote: the client INIT_SYN, the OPEN_SYN that echoes the router's cookie, and one FRAME for each
  Put, each equal to what `zenoh_wire.push_put` writes in the peer form with the sender mapping;
* the CLOSE the link wrote when the owner closed it, and that the link then holds no subscription;
* five refusals, each with the class it is refused as.

The router is not in this exam. It judges what the link writes, and a router's acceptance of those bytes is the live
run's to show. Like the other judges, this one is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re

import zenoh_rmw_router_data as router
import zenoh_rmw_router_link_exam as link
import zenoh_wire
from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-client-put.zt"

MODES = link.MODES
PUTS = 4
INITIAL_SN = link.INITIAL_SN
GID = bytes(range(16))
PAYLOAD_BOUND = 32

REFUSALS = (
    ("no-role-link-puts-on-an-undeclared-key", "undeclared-key"),
    ("client-put-before-the-session-is-open", "not-open"),
    ("client-put-over-the-payload-bound", "encode"),
    ("client-put-with-a-short-attachment", "encode"),
    ("client-put-while-the-send-slot-is-busy", "send-busy"),
)


class ClientPutExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ClientPutExamError(message)


def hexed(data: bytes) -> str:
    return data.hex() if data else "-"


def framed(batch: bytes) -> bytes:
    return zenoh_wire.stream(batch)


# ----------------------------------------------------------------------------------------------- the capture


def check_runs() -> None:
    """What the handshakes say, so the transcript is about the router and not about the exam's own bytes."""
    _need(len(router.RUNS) == 2, f"{len(router.RUNS)} router runs, the item says 2")
    for name, syn, ack, open_ack, _forwarded in router.RUNS:
        got = bytes.fromhex(ack)
        _need(bytes.fromhex(syn) == link.client_syn(), f"{name}: the client INIT_SYN is not the peer form with whatami 2")
        _need(got[2] & 3 == 0, f"{name}: the router did not announce whatami 0")
        _need(len(link.init_ack_cookie(got)) <= 64, f"{name}: the cookie is over the 64 bytes a session holds")
        done = bytes.fromhex(open_ack)
        _need(done[0] & 0x1F == 0x02 and done[0] & 0x20 != 0, f"{name}: the last handshake batch is not an OPEN_ACK")
    _need(router.RUNS[0][2] != router.RUNS[1][2], "the two runs carry the same cookie")
    _need(len(cdr(text(PUTS - 1))) <= PAYLOAD_BOUND, "a Put's payload is over the bound the link is declared with")
    _need(len(cdr("x" * PAYLOAD_BOUND)) > PAYLOAD_BOUND, "the oversize payload fits the bound")


# ----------------------------------------------------------------------------------------------- the bytes


def cdr(string: str) -> bytes:
    body = string.encode() + b"\x00"
    return bytes([0, 1, 0, 0]) + len(body).to_bytes(4, "little") + body


def text(number: int) -> str:
    return f"Hello Slime {number}"


def put_frame(number: int) -> bytes:
    """The FRAME for the Put numbered `number` from 0: the peer form of PUSH, with the sender mapping."""
    attachment = zenoh_wire.attachment(number + 1, 1_000_000_000 + number, GID)
    return zenoh_wire.frame(INITIAL_SN + number, zenoh_wire.push_put(router.KEY, attachment, cdr(text(number)), True))


def written(ack_hex: str) -> bytes:
    """Everything the link wrote before it was closed."""
    return (
        framed(link.client_syn())
        + framed(link.open_syn(bytes.fromhex(ack_hex)))
        + b"".join(framed(put_frame(number)) for number in range(PUTS))
    )


def close_bytes() -> bytes:
    return framed(zenoh_wire.close(0, True))


def refusal_state(name: str) -> str:
    _need(name in {n for n, _ in REFUSALS}, f"no refusal named {name}")
    return name


# -------------------------------------------------------------------------------------------- the transcript


def good_lines() -> list[str]:
    check_runs()
    lines: list[str] = []
    for name, _syn, ack, open_ack, _forwarded in router.RUNS:
        lines.append(f"clientput fed {name} {ack} {open_ack}")
        for mode in MODES:
            lines.append(f"clientput sent {name} {mode} {hexed(written(ack))}")
            lines.append(f"clientput closed {name} {mode} reason=0 wrote={hexed(close_bytes())} subscription=none")
            lines.append(f"clientput ok {name}-{mode}")
    for refused, cls in REFUSALS:
        lines.append(f"clientput refused {refused} {cls}")
    return lines


def judge(lines: list[str]) -> tuple[int, int]:
    """The printed transcript must equal the one built here, line for line. Returns (cases, refusals)."""
    wanted = good_lines()
    for line in lines:
        _need(line.startswith("clientput "), f"clientput: a record that is not a client put exam line: {line!r}")
        _need(line == line.strip() and "  " not in line, f"clientput: a line with stray spaces: {line!r}")
    missing = [line for line in wanted if line not in lines]
    extra = [line for line in lines if line not in wanted]
    _need(not missing, f"clientput lines missing: {[m[:90] for m in missing[:3]]}")
    _need(not extra, f"clientput lines the exam does not build: {[e[:90] for e in extra[:3]]}")
    _need(len(lines) == len(wanted), f"clientput: {len(lines)} lines, the exam builds {len(wanted)}; a line is repeated")
    _need(lines == wanted, "clientput: the lines are not in the order the exam runs them")
    refusals = sum(1 for line in wanted if line.startswith("clientput refused "))
    return len(wanted) - refusals, refusals


# ------------------------------------------------------------------------------------------------ the controls


def reference_controls() -> int:
    check_runs()
    saved = router.RUNS
    name, syn, ack, open_ack, forwarded = saved[0]
    cases: list[tuple[str, tuple, str]] = [
        ("a client INIT_SYN written as a peer", (((name, zenoh_wire.init(router.CLIENT_ZID, batch=router.CLIENT_BATCH).hex(), ack, open_ack, forwarded)), saved[1]), "peer form with whatami 2"),
        ("an answer that announces a peer", (((name, syn, "6109" + "f1" + ack[6:], open_ack, forwarded)), saved[1]), "did not announce whatami 0"),
        ("a last batch that is not an OPEN_ACK", (((name, syn, ack, "43" + open_ack[2:], forwarded)), saved[1]), "is not an OPEN_ACK"),
        ("one run only", (saved[0],), "the item says 2"),
        ("the same run twice", (saved[0], (saved[1][0], *saved[0][1:])), "the same cookie"),
    ]
    refused = 0
    try:
        for label, runs, reason in cases:
            router.RUNS = tuple(runs)
            try:
                check_runs()
            except (ClientPutExamError, IndexError, ValueError) as error:
                _need(isinstance(error, ClientPutExamError) and reason in str(error), f"control: {label} was refused for another reason: {error!r}")
                refused += 1
                continue
            raise ClientPutExamError(f"control: the reference check accepted {label}")
    finally:
        router.RUNS = saved
    return refused


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    kinds = {kind: [i for i, line in enumerate(good) if line.startswith(f"clientput {kind} ")] for kind in ("fed", "sent", "closed", "ok", "refused")}
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a client put exam line", [*good, "routerlink ok router-data-1-whole"]),
        ("a line repeated", [*good, good[0]]),
        ("a line with a doubled space", [good[1].replace(" ", "  ", 1), good[0], *good[2:]]),
        ("a line with trailing space", [good[1] + " ", good[0], *good[2:]]),
        ("the first two lines swapped", swapped(0, 1)),
        ("the first and last lines swapped", swapped(0, len(good) - 1)),
        ("two modes of one run swapped", swapped(kinds["sent"][0], kinds["sent"][1])),
        ("the first two refusals swapped", swapped(kinds["refused"][0], kinds["refused"][1])),
        ("a refusal moved ahead of the runs", swapped(kinds["fed"][0], kinds["refused"][0])),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index} missing ({line[:44]})", [*good[:index], *good[index + 1 :]]))
    for kind in ("fed", "sent", "closed"):
        for index in kinds[kind]:
            fields = good[index].split(" ")
            last = fields[-1]
            changed = last[:-1] + ("0" if last[-1] != "0" else "1")
            out.append((f"{kind} line {index} with a changed last field", [*good[:index], " ".join([*fields[:-1], changed]), *good[index + 1 :]]))
    classes = sorted({line.split(" ")[3] for line in good if line.startswith("clientput refused ")})
    for cls in classes:
        index = next(i for i in kinds["refused"] if good[i].split(" ")[3] == cls)
        other = next(c for c in classes if c != cls)
        out.append((f"the {good[index].split(' ')[2]} refusal reported as {other}", [*good[:index], good[index].replace(f" {cls}", f" {other}", 1), *good[index + 1 :]]))
    first = kinds["sent"][0]
    out.append(("a Put written with the receiver mapping", [good[i].replace("077d006e", "073d006e", 1) if i == first else good[i] for i in range(len(good))]))
    out.append(("a Put written with the timestamp flag", [good[i].replace(framed(put_frame(0)).hex(), framed(put_frame(0)).hex().replace("8143", "a143", 1), 1) if i == first else good[i] for i in range(len(good))]))
    out.append(("a Put on another key", [good[i].replace(router.KEY.encode().hex()[:40], "00" * 20, 1) if i == first else good[i] for i in range(len(good))]))
    first_put = framed(put_frame(0)).hex()
    skipped = first_put.replace(first_put[6:8], f"{INITIAL_SN + 1:02x}", 1)
    out.append(("a Put that skips a sequence number", [good[i].replace(first_put, skipped, 1) if i == first else good[i] for i in range(len(good))]))
    out.append(("a link that wrote only three Puts", [good[i][: -len(framed(put_frame(PUTS - 1)).hex())] if i == first else good[i] for i in range(len(good))]))
    out.append(("a subscription kept after the close", [good[i].replace("subscription=none", "subscription=1", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]))
    out.append(("a close with another reason", [good[i].replace("reason=0", "reason=1", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]))
    out.append(("a local close that wrote nothing", [good[i].replace("wrote=02002300", "wrote=-", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (PINNED_CASES - PINNED_REFUSALS, PINNED_REFUSALS), f"clientput: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise ClientPutExamError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except ClientPutExamError:
            refused += 1
            continue
        raise ClientPutExamError(f"control: the client put judge accepted {label}")
    return refused


def all_controls() -> int:
    return transcript_controls() + reference_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 25
PINNED_REFUSALS = len(REFUSALS)
PINNED_CONTROLS = 66


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text_ = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text_)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text_)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
