"""Judge the Profile 0 client role from what the Rust tests print.

A Profile 0 session announces itself as a peer, and it refuses an INIT whose `whatami` is a client or a router.
`rmw_zenohd` answers a client INIT with an INIT_ACK of `whatami` 0, so a session built as it is today cannot
connect to a router. This exam judges the opt-in client role that changes that, and the default that stays as it is.

The Rust tests under `zenoh_profile0::client_tests` drive a connector with the client role against the two
captured handshakes of `zenoh_rmw_router`, one batch at a time, and print one `[zenoh-exam] client ...` line for
each thing they did. This module builds the whole transcript from the captured bytes and `zenoh_wire`, and the
Rust must print it, line for line:

* the INIT_SYN the client wrote, which is the peer form with `whatami` 2 and nothing else different;
* the OPEN_SYN it wrote on the router's INIT_ACK, which echoes the cookie, and that the session is open after
  the router's OPEN_ACK;
* the INIT_SYN a connector with no client role writes, which equals what it wrote before this item;
* the captured bytes the test was given, one line for each run, so the transcript binds what the Rust fed;
* four refusals, each with the class it is refused as, the state the session was left in and the bytes it had
  written. A refused batch changes no state, so a connector that refused an INIT_ACK is still awaiting one.

The captured OPEN_SYN is not a fixture, because the router did not write it. Like the other judges, this one is
trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re

import zenoh_rmw_router as router
import zenoh_wire
from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-client.zt"

WHATAMI_ROUTER = 0
WHATAMI_PEER = 1
WHATAMI_CLIENT = 2

REFUSALS = (
    ("default-session-takes-a-router-ack", "unsupported-whatami"),
    ("client-takes-a-peer-ack", "unsupported-whatami"),
    ("client-takes-a-client-ack", "unsupported-whatami"),
    ("client-as-a-listener", "invalid-config"),
)


class ClientExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ClientExamError(message)


def hexed(data: bytes) -> str:
    return data.hex() if data else "-"


# ------------------------------------------------------------------------------------------ the bytes it writes


def with_whatami(init: bytes, whatami: int) -> bytes:
    """An INIT with the low two bits of its packed byte set to `whatami`, which is all that differs between forms."""
    out = bytearray(init)
    out[2] = (out[2] & ~3) | whatami
    return bytes(out)


def peer_syn() -> bytes:
    return zenoh_wire.init(router.CLIENT_ZID, batch=router.CLIENT_BATCH)


def client_syn() -> bytes:
    return with_whatami(peer_syn(), WHATAMI_CLIENT)


def init_ack_cookie(ack: bytes) -> bytes:
    """The cookie of an INIT_ACK that carries a resolution and a batch size and no extension."""
    at = 3 + (ack[2] >> 4) + 1 + 3
    length = ack[at]
    cookie = ack[at + 1 : at + 1 + length]
    _need(len(cookie) == length and at + 1 + length == len(ack), "an INIT_ACK whose cookie does not end the batch")
    return cookie


def open_syn(ack: bytes) -> bytes:
    return zenoh_wire.open_(router.CLIENT_LEASE_MS, router.CLIENT_INITIAL_SN, cookie=init_ack_cookie(ack))


def check_runs() -> None:
    """What the captures say, so the transcript is about the router and not about the exam's own bytes."""
    _need(len(router.RUNS) == 2, f"{len(router.RUNS)} router runs, the item says 2")
    for name, syn, ack, open_ack in router.RUNS:
        sent, got, done = bytes.fromhex(syn), bytes.fromhex(ack), bytes.fromhex(open_ack)
        _need(sent == client_syn(), f"{name}: the client INIT_SYN is not the peer form with whatami 2")
        _need(sent[2] & 3 == WHATAMI_CLIENT and peer_syn()[2] & 3 == WHATAMI_PEER, f"{name}: the forms do not differ in whatami")
        _need(got[0] & 0x1F == 0x01 and got[0] & 0x20 != 0, f"{name}: the answer is not an INIT_ACK")
        _need(got[2] & 3 == WHATAMI_ROUTER, f"{name}: the router did not announce whatami 0")
        _need(len(init_ack_cookie(got)) <= 64, f"{name}: the cookie is over the 64 bytes a session holds")
        _need(int.from_bytes(got[3 + (got[2] >> 4) + 1 + 1 : 3 + (got[2] >> 4) + 1 + 3], "little") == router.CLIENT_BATCH, f"{name}: the router did not announce a 512-byte batch")
        _need(len(open_syn(got)) + 2 <= router.CLIENT_BATCH, f"{name}: the OPEN_SYN does not fit the router's batch")
        _need(done[0] & 0x1F == 0x02 and done[0] & 0x20 != 0, f"{name}: the last batch is not an OPEN_ACK")
        lease, at = zenoh_wire.read_leb128(done, 1)
        _need(lease * 1000 == router.ROUTER_LEASE_MS and done[0] & 0x40 != 0, f"{name}: the router's lease is not 60 s")
        _, end = zenoh_wire.read_leb128(done, at)
        _need(end == len(done), f"{name}: the OPEN_ACK has bytes after its sequence number")
    _need(router.RUNS[0][2] != router.RUNS[1][2], "the two runs carry the same cookie")


def refusal_state(name: str) -> str:
    """The state a refusal leaves: a connector that had written its INIT_SYN is still waiting for an INIT_ACK, and a
    client built as a listener has no session."""
    _need(name in {n for n, _ in REFUSALS}, f"no refusal named {name}")
    return "none" if name == "client-as-a-listener" else "await-init-ack"


def refusal_written(name: str) -> bytes:
    """What the session had written when it refused: its INIT_SYN, in the form its configuration gives, or nothing."""
    if name == "default-session-takes-a-router-ack":
        return peer_syn()
    if name == "client-as-a-listener":
        return b""
    _need(name in {n for n, _ in REFUSALS}, f"no refusal named {name}")
    return client_syn()


# -------------------------------------------------------------------------------------------- the transcript


def good_lines() -> list[str]:
    check_runs()
    lines: list[str] = []
    for name, _syn, ack, open_ack in router.RUNS:
        lines.append(f"client fed {name} {ack} {open_ack}")
        lines.append(f"client syn {name} {hexed(client_syn())}")
        lines.append(f"client open-syn {name} {hexed(open_syn(bytes.fromhex(ack)))}")
        lines.append(f"client opened {name} state=open")
    lines.append(f"client default-syn {hexed(peer_syn())}")
    for name, cls in REFUSALS:
        lines.append(f"client refused {name} {cls} state={refusal_state(name)} {hexed(refusal_written(name))}")
    return lines


def judge(lines: list[str]) -> tuple[int, int]:
    """The printed transcript must equal the one built here, line for line. Returns (cases, refusals)."""
    wanted = good_lines()
    for line in lines:
        _need(line.startswith("client "), f"client: a record that is not a client exam line: {line!r}")
        _need(line == line.strip() and "  " not in line, f"client: a line with stray spaces: {line!r}")
    missing = [line for line in wanted if line not in lines]
    extra = [line for line in lines if line not in wanted]
    _need(not missing, f"client lines missing: {[m[:90] for m in missing[:3]]}")
    _need(not extra, f"client lines the exam does not build: {[e[:90] for e in extra[:3]]}")
    _need(len(lines) == len(wanted), f"client: {len(lines)} lines, the exam builds {len(wanted)}; a line is repeated")
    _need(lines == wanted, "client: the lines are not in the order the exam runs them")
    refusals = sum(1 for line in wanted if line.startswith("client refused "))
    return len(wanted) - refusals, refusals


# ------------------------------------------------------------------------------------------------ the controls


def reference_controls() -> int:
    check_runs()
    saved = router.RUNS
    cases: list[tuple[str, tuple, str]] = [
        ("a client INIT_SYN written as a peer", ((saved[0][0], peer_syn().hex(), saved[0][2], saved[0][3]), saved[1]), "the peer form with whatami 2"),
        ("an answer that announces a peer", ((saved[0][0], saved[0][1], with_whatami(bytes.fromhex(saved[0][2]), WHATAMI_PEER).hex(), saved[0][3]), saved[1]), "did not announce whatami 0"),
        ("an answer that is not an INIT_ACK", ((saved[0][0], saved[0][1], "4" + saved[0][2][1:], saved[0][3]), saved[1]), "is not an INIT_ACK"),
        ("an answer with a trailing byte", ((saved[0][0], saved[0][1], saved[0][2] + "00", saved[0][3]), saved[1]), "does not end the batch"),
        ("a last batch that is not an OPEN_ACK", ((saved[0][0], saved[0][1], saved[0][2], "43" + saved[0][3][2:]), saved[1]), "is not an OPEN_ACK"),
        ("a router lease of 10 s", ((saved[0][0], saved[0][1], saved[0][2], "620a" + saved[0][3][4:]), saved[1]), "is not 60 s"),
        ("one run only", (saved[0],), "the item says 2"),
        ("the same run twice", (saved[0], (saved[1][0], *saved[0][1:])), "the same cookie"),
    ]
    refused = 0
    try:
        for label, runs, reason in cases:
            router.RUNS = tuple(runs)
            try:
                check_runs()
            except (ClientExamError, IndexError, ValueError) as error:
                _need(isinstance(error, ClientExamError) and reason in str(error), f"control: {label} was refused for another reason: {error!r}")
                refused += 1
                continue
            raise ClientExamError(f"control: the reference check accepted {label}")
    finally:
        router.RUNS = saved
    return refused


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    kinds = {kind: [i for i, line in enumerate(good) if line.startswith(f"client {kind} ")] for kind in ("fed", "syn", "open-syn", "opened", "default-syn", "refused")}
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a client exam line", [*good, "link ok something"]),
        ("a line repeated", [*good, good[0]]),
        ("a line with a doubled space", [good[0].replace(" ", "  ", 1), *good[1:]]),
        ("a line with trailing space", [good[0] + " ", *good[1:]]),
        ("the first two lines swapped", swapped(0, 1)),
        ("the first and last lines swapped", swapped(0, len(good) - 1)),
        ("the two runs swapped", swapped(kinds["syn"][0], kinds["syn"][1])),
        ("the first two refusals swapped", swapped(kinds["refused"][0], kinds["refused"][1])),
        ("a refusal moved ahead of the handshakes", swapped(kinds["syn"][0], kinds["refused"][0])),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index} missing ({line[:44]})", [*good[:index], *good[index + 1 :]]))
    for kind in ("fed", "syn", "open-syn", "default-syn", "refused"):
        for index in kinds[kind]:
            fields = good[index].split(" ")
            last = fields[-1]
            changed = last[:-1] + ("0" if last[-1] != "0" else "1")
            out.append((f"{kind} line {index} with a changed last field", [*good[:index], " ".join([*fields[:-1], changed]), *good[index + 1 :]]))
    classes = sorted({line.split(" ")[3] for line in good if line.startswith("client refused ")})
    for cls in classes:
        index = next(i for i in kinds["refused"] if good[i].split(" ")[3] == cls)
        other = next(c for c in classes if c != cls)
        out.append((f"the {good[index].split(' ')[2]} refusal reported as {other}", [*good[:index], good[index].replace(f" {cls} ", f" {other} ", 1), *good[index + 1 :]]))
    out.append(("a client INIT_SYN written in the peer form", [good[i].replace(client_syn().hex(), peer_syn().hex(), 1) if i == kinds["syn"][0] else good[i] for i in range(len(good))]))
    out.append(("a default INIT_SYN written in the client form", [good[i].replace(peer_syn().hex(), client_syn().hex(), 1) if i == kinds["default-syn"][0] else good[i] for i in range(len(good))]))
    out.append(("a session left in another state", [good[i].replace("state=open", "state=await-open-ack", 1) if i == kinds["opened"][0] else good[i] for i in range(len(good))]))
    out.append(("a refusal that closed the session", [good[i].replace("state=await-init-ack", "state=closed", 1) if i == kinds["refused"][0] else good[i] for i in range(len(good))]))
    out.append(("a refusal that left the session idle", [good[i].replace("state=await-init-ack", "state=idle", 1) if i == kinds["refused"][1] else good[i] for i in range(len(good))]))
    out.append(("a client built as a listener that kept a session", [good[i].replace("state=none", "state=idle", 1) if i == kinds["refused"][3] else good[i] for i in range(len(good))]))
    out.append(("a capture the test was not given", [good[i].replace(router.RUNS[0][2], router.RUNS[1][2], 1) if i == kinds["fed"][0] else good[i] for i in range(len(good))]))
    out.append(("an OPEN_SYN without the cookie", [good[i].replace(init_ack_cookie(bytes.fromhex(router.RUNS[0][2])).hex(), "", 1) if i == kinds["open-syn"][0] else good[i] for i in range(len(good))]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (PINNED_CASES - PINNED_REFUSALS, PINNED_REFUSALS), f"client: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise ClientExamError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except ClientExamError:
            refused += 1
            continue
        raise ClientExamError(f"control: the client judge accepted {label}")
    return refused


def all_controls() -> int:
    return transcript_controls() + reference_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 13
PINNED_REFUSALS = len(REFUSALS)
PINNED_CONTROLS = 52


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
