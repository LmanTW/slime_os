"""Judge the liveliness tokens a client-role link writes from what the Rust tests print.

`ros2 node list` and `ros2 topic list` build their graph from liveliness tokens under `@ros2_lv`. A client-role link that
writes none is invisible to them, although a ROS node still hears its Puts. This exam judges the call that changes that: a
link with the client role declares a token, withdraws it, and keeps the session open meanwhile.

The Rust tests under `zenoh_link::token_tests` drive a client-role link through the handshake of the two runs of
`zenoh_rmw_router_data`, fed three ways, and then declare the node token and the publisher token of `slime_node`, withdraw
the publisher token and close. They print one `[zenoh-exam] clienttoken ...` line for each thing they did. This module builds
the whole transcript from the captured handshakes, `zenoh_rmw_graph.build_token` and `zenoh_rmw_wire`, and the Rust must
print it, line for line:

* the bytes the link wrote: the client INIT_SYN, the OPEN_SYN that echoes the router's cookie, a FRAME for each token
  declaration with the key written in full, and a FRAME that withdraws the publisher token;
* the CLOSE the link wrote when the owner closed it, and that the link then holds no token;
* six refusals, each with the class it is refused as.

The bytes are the plain form: a DECLARE with no QoS extension, a named token with the sender mapping, and an UNDECLARE_TOKEN
with the extension a real peer writes. Live probes showed `rmw_zenohd` and `ros2` take that form. The router also took a
withdrawal without the extension, so the extension follows the capture and not the router. The router is not in the exam. Like the other judges, this one is trusted only after it refuses a
mutation of an honest transcript.
"""

from __future__ import annotations

import re

import zenoh_rmw_client_put_exam as put
import zenoh_rmw_graph as graph
import zenoh_rmw_router_data as router
import zenoh_rmw_router_link_exam as link
import zenoh_rmw_wire as wire
import zenoh_wire
from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-token.zt"

MODES = link.MODES
INITIAL_SN = link.INITIAL_SN
DOMAIN = 0
NODE_NAME = "slime_node"
NODE_ID = 10
PUBLISHER_ID = 11
TYPE_NAME = "std_msgs::msg::dds_::String_"
TOPIC = "/chatter"
UNTOKEN_EXTENSION = wire.Extension(15, True, 2, b"\x00\x00")

REFUSALS = (
    ("no-role-link-declares-a-token", "invalid-config"),
    ("token-before-the-session-is-open", "not-open"),
    ("token-with-an-id-already-declared", "token-limit"),
    ("token-over-the-key-bound", "encode"),
    ("withdraw-an-id-never-declared", "unknown-token"),
    ("token-while-the-send-slot-is-busy", "send-busy"),
)


class TokenExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise TokenExamError(message)


def hexed(data: bytes) -> str:
    return data.hex() if data else "-"


def framed(batch: bytes) -> bytes:
    return zenoh_wire.stream(batch)


# ------------------------------------------------------------------------------------------------ the tokens


def zid_hex() -> str:
    return router.CLIENT_ZID.hex()


def node_key() -> str:
    return graph.build_token(graph.Entity(domain=DOMAIN, zid=zid_hex(), nid=0, ident=0, kind="NN", enclave="/", namespace="/", node=NODE_NAME))


def publisher_key() -> str:
    return graph.build_token(
        graph.Entity(domain=DOMAIN, zid=zid_hex(), nid=0, ident=1, kind="MP", enclave="/", namespace="/", node=NODE_NAME, topic=TOPIC, type_name=TYPE_NAME, type_hash=link.router.KEY.split("/")[-1], qos=graph.DEFAULT_QOS)
    )


def declare_bytes(ident: int, key: str) -> bytes:
    return wire.encode(wire.Message("token", ident=ident, scope=0, suffix=key, sender=True))


def withdraw_bytes(ident: int) -> bytes:
    return wire.encode(wire.Message("untoken", ident=ident, inner=(UNTOKEN_EXTENSION,)))


def check_shapes() -> None:
    """The plain form is the captured one with the QoS wrapper removed, so the exam is about the captures and not its own bytes."""
    captured = None
    import zenoh_rmw_peer as peer

    for group in (peer.TALKER, peer.LISTS):
        for _name, hexed_batch in group:
            batch = bytes.fromhex(hexed_batch)
            if not batch or batch[0] & 0x1F != 5:
                continue
            try:
                _sn, messages = wire.frame(batch)
            except Exception:  # noqa: BLE001
                continue
            for message in messages:
                if message.kind in ("token", "untoken") and message.kind not in (captured or {}):
                    captured = {**(captured or {}), message.kind: message}
    _need(captured is not None and "token" in captured and "untoken" in captured, "the captures hold no token and no withdrawal")
    token, untoken = captured["token"], captured["untoken"]
    _need(token.qos is not None and token.sender and token.suffix is None, "the captured token is not a QoS-wrapped, sender-mapped alias reference")
    _need(untoken.qos is not None and untoken.inner == (UNTOKEN_EXTENSION,), "the captured withdrawal does not carry the extension this exam writes")
    plain = declare_bytes(NODE_ID, node_key())
    _need(plain[0] == 0x1E and plain[1] == 0x66, "the plain token declaration is not a DECLARE with a named, sender-mapped token")
    _need(withdraw_bytes(PUBLISHER_ID)[:2] == bytes([0x1E, 0x87]), "the plain withdrawal is not a DECLARE with an UNDECLARE_TOKEN")


def check_runs() -> None:
    try:
        put.check_runs()
    except put.ClientPutExamError as error:
        raise TokenExamError(str(error)) from error
    _need(len(node_key().encode()) <= 253 and len(publisher_key().encode()) <= 253, "a token key is over the 253 bytes the link is declared with")
    _need(len(publisher_key().encode()) > 129, "the publisher key fits the first release's key bound, so the key-bound refusal tests nothing")


def frames(number: int, key: str) -> bytes:
    """The FRAME for the declaration `number` after the OPEN_SYN, with the key in full."""
    return zenoh_wire.frame(INITIAL_SN + number, declare_bytes(NODE_ID + number, key))


def written(ack_hex: str) -> bytes:
    """Everything the link wrote before it was closed."""
    withdraw = zenoh_wire.frame(INITIAL_SN + 2, withdraw_bytes(PUBLISHER_ID))
    return (
        framed(link.client_syn())
        + framed(link.open_syn(bytes.fromhex(ack_hex)))
        + framed(frames(0, node_key()))
        + framed(frames(1, publisher_key()))
        + framed(withdraw)
    )


def close_bytes() -> bytes:
    return framed(zenoh_wire.close(0, True))


# -------------------------------------------------------------------------------------------- the transcript


def good_lines() -> list[str]:
    check_shapes()
    check_runs()
    lines: list[str] = []
    for name, _syn, ack, open_ack, _forwarded in router.RUNS:
        lines.append(f"clienttoken fed {name} {ack} {open_ack}")
        for mode in MODES:
            lines.append(f"clienttoken sent {name} {mode} {hexed(written(ack))}")
            lines.append(f"clienttoken closed {name} {mode} reason=0 wrote={hexed(close_bytes())} tokens=none")
            lines.append(f"clienttoken ok {name}-{mode}")
    for refused, cls in REFUSALS:
        lines.append(f"clienttoken refused {refused} {cls}")
    return lines


def judge(lines: list[str]) -> tuple[int, int]:
    """The printed transcript must equal the one built here, line for line. Returns (cases, refusals)."""
    wanted = good_lines()
    for line in lines:
        _need(line.startswith("clienttoken "), f"clienttoken: a record that is not a client token exam line: {line!r}")
        _need(line == line.strip() and "  " not in line, f"clienttoken: a line with stray spaces: {line!r}")
    missing = [line for line in wanted if line not in lines]
    extra = [line for line in lines if line not in wanted]
    _need(not missing, f"clienttoken lines missing: {[m[:90] for m in missing[:3]]}")
    _need(not extra, f"clienttoken lines the exam does not build: {[e[:90] for e in extra[:3]]}")
    _need(len(lines) == len(wanted), f"clienttoken: {len(lines)} lines, the exam builds {len(wanted)}; a line is repeated")
    _need(lines == wanted, "clienttoken: the lines are not in the order the exam runs them")
    refusals = sum(1 for line in wanted if line.startswith("clienttoken refused "))
    return len(wanted) - refusals, refusals


# ------------------------------------------------------------------------------------------------ the controls


def reference_controls() -> int:
    """The handshake controls of the Put exam, which this exam builds on, and the controls on the token shapes."""
    try:
        return put.reference_controls()
    except put.ClientPutExamError as error:
        raise TokenExamError(f"control: the handshake controls failed: {error}") from error


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    kinds = {kind: [i for i, line in enumerate(good) if line.startswith(f"clienttoken {kind} ")] for kind in ("fed", "sent", "closed", "ok", "refused")}
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a client token exam line", [*good, "clientput ok router-data-1-whole"]),
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
    classes = sorted({line.split(" ")[3] for line in good if line.startswith("clienttoken refused ")})
    for cls in classes:
        index = next(i for i in kinds["refused"] if good[i].split(" ")[3] == cls)
        other = next(c for c in classes if c != cls)
        out.append((f"the {good[index].split(' ')[2]} refusal reported as {other}", [*good[:index], good[index].replace(f" {cls}", f" {other}", 1), *good[index + 1 :]]))

    first = kinds["sent"][0]
    sent = written(router.RUNS[0][2]).hex()
    node = framed(frames(0, node_key())).hex()
    publisher = framed(frames(1, publisher_key())).hex()
    withdraw = framed(zenoh_wire.frame(INITIAL_SN + 2, withdraw_bytes(PUBLISHER_ID))).hex()

    def sent_with(change) -> list[str]:
        return [good[i].replace(sent, change(sent), 1) if i == first else good[i] for i in range(len(good))]

    out += [
        ("a node token declared as a wildcard key", sent_with(lambda s: s.replace(node, node.replace(b"slime_node".hex(), b"slime_*ode".hex(), 1), 1))),
        ("a node token without the sender mapping", sent_with(lambda s: s.replace(node, node.replace("1e66", "1e26", 1), 1))),
        ("a publisher token under another domain", sent_with(lambda s: s.replace(publisher, publisher.replace(b"@ros2_lv/0/".hex(), b"@ros2_lv/1/".hex(), 1), 1))),
        ("a publisher token with the QoS substring dropped", sent_with(lambda s: s.replace(publisher, publisher.replace(b"::".hex(), b";;".hex(), 1), 1))),
        ("a withdrawal that names the node token", sent_with(lambda s: s.replace(withdraw, withdraw.replace("870b5f", "870a5f", 1), 1))),
        ("a withdrawal without its extension", sent_with(lambda s: s.replace(withdraw, withdraw.replace("5f020000", "", 1), 1))),
        ("a withdrawal that was never written", sent_with(lambda s: s.replace(withdraw, "", 1))),
        ("the publisher token written before the node token", sent_with(lambda s: s.replace(node + publisher, publisher + node, 1))),
        ("a declaration frame that skips a sequence number", sent_with(lambda s: s.replace(publisher, publisher.replace(f"{INITIAL_SN + 1:02x}", f"{INITIAL_SN + 5:02x}", 1), 1))),
        ("a link that still holds a token after the close", [good[i].replace("tokens=none", "tokens=1", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]),
        ("a close with another reason", [good[i].replace("reason=0", "reason=1", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]),
        ("a local close that wrote nothing", [good[i].replace("wrote=02002300", "wrote=-", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]),
    ]
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (PINNED_CASES - PINNED_REFUSALS, PINNED_REFUSALS), f"clienttoken: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise TokenExamError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except TokenExamError:
            refused += 1
            continue
        raise TokenExamError(f"control: the client token judge accepted {label}")
    return refused


def all_controls() -> int:
    return transcript_controls() + reference_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 26
PINNED_REFUSALS = len(REFUSALS)
PINNED_CONTROLS = 73


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
