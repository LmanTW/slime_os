"""Judge the liveliness tokens of every entity kind a client-role link writes, from what the Rust tests print.

`zenoh_rmw_token_exam` judges a node token and a publisher token. `ros2 topic info` also lists a subscription, and `ros2
node info` lists a service server and a service client, and each comes from a token of its own kind: `MS`, `SS` and `SC`.
A live probe with the Python wire library and a probe with this Rust link showed that `rmw_zenohd` and `ros2` take all
three in the plain form the node token and the publisher token use. This exam judges the bytes.

The Rust tests under `zenoh_link::entity_tests` drive a client-role link through the handshake of the two runs of
`zenoh_rmw_router_data`, fed three ways. The link declares five tokens, the node, the publisher, a subscription, a service
server and a service client of `slime_node`, withdraws the subscription token and closes. They print one `[zenoh-exam]
cliententity ...` line for each thing they did. This module builds the whole transcript from the captured handshakes,
`zenoh_rmw_graph.build_token` and `zenoh_rmw_wire`, and the Rust must print it, line for line:

* the bytes the link wrote: the client INIT_SYN, the OPEN_SYN that echoes the router's cookie, a FRAME for each token
  declaration with the key in full, and a FRAME that withdraws the subscription token;
* the tokens the link held after the withdrawal, which are the four other tokens, read from the link's own token set;
* the CLOSE the link wrote when its owner closed it, and that the link then holds no token;
* seven refusals, each with the class it is refused as.

Like the other judges, this one is trusted only after it refuses a mutation of an honest transcript. The router is not in
the exam, and a live run of `ros2` against these tokens is a separate item.
"""

from __future__ import annotations

import re

import zenoh_rmw_graph as graph
import zenoh_rmw_router_data as router
import zenoh_rmw_token_exam as token
import zenoh_wire
from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-parity-tokens.zt"

MODES = token.MODES
INITIAL_SN = token.INITIAL_SN
DOMAIN = token.DOMAIN
NODE_NAME = token.NODE_NAME
TYPE_NAME = token.TYPE_NAME
TOPIC = token.TOPIC
SERVICE = "/add_two_ints"
SERVICE_TYPE = "example_interfaces::srv::dds_::AddTwoInts_"
SERVICE_HASH = "RIHS01_e118de6bf5eeb66a2491b5bda11202e7b68f198d6f67922cf30364858239c81a"
SUBSCRIPTION_QOS = graph.Qos(graph.DEFAULT_RELIABILITY, graph.DEFAULT_DURABILITY, graph.DEFAULT_HISTORY, 10, graph.INFINITE, graph.INFINITE, graph.DEFAULT_LIVELINESS, graph.INFINITE)

# The token ids the link declares, in the order it declares them. The wire id is not the entity id inside the key.
NODE_ID, PUBLISHER_ID, SUBSCRIPTION_ID, SERVER_ID, CLIENT_ID = 10, 11, 12, 13, 14
DECLARED = (NODE_ID, PUBLISHER_ID, SUBSCRIPTION_ID, SERVER_ID, CLIENT_ID)
WITHDRAWN = SUBSCRIPTION_ID
HELD = tuple(ident for ident in DECLARED if ident != WITHDRAWN)
# The session holds this many token ids at once. The exam declares five and one more fits.
CAP = 6

REFUSALS = (
    ("no-role-link-declares-a-subscription-token", "invalid-config"),
    ("token-before-the-session-is-open", "not-open"),
    ("token-with-an-id-already-declared", "token-limit"),
    ("seventh-token-over-the-cap", "token-limit"),
    ("token-over-the-key-bound", "encode"),
    ("withdraw-an-id-never-declared", "unknown-token"),
    ("token-while-the-send-slot-is-busy", "send-busy"),
)


class EntityExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise EntityExamError(message)


def _entity(ident: int, kind: str, topic: str | None, type_name: str | None, type_hash: str | None, qos: graph.Qos | None) -> str:
    return graph.build_token(
        graph.Entity(domain=DOMAIN, zid=token.zid_hex(), nid=0, ident=ident, kind=kind, enclave="/", namespace="/", node=NODE_NAME, topic=topic, type_name=type_name, type_hash=type_hash, qos=qos)
    )


def keys() -> dict[int, str]:
    """The key of each declared token, by wire id."""
    chatter_hash = router.KEY.split("/")[-1]
    return {
        NODE_ID: token.node_key(),
        PUBLISHER_ID: token.publisher_key(),
        SUBSCRIPTION_ID: _entity(2, "MS", TOPIC, TYPE_NAME, chatter_hash, SUBSCRIPTION_QOS),
        SERVER_ID: _entity(3, "SS", SERVICE, SERVICE_TYPE, SERVICE_HASH, graph.DEFAULT_QOS),
        CLIENT_ID: _entity(4, "SC", SERVICE, SERVICE_TYPE, SERVICE_HASH, graph.DEFAULT_QOS),
    }


def check_shapes() -> None:
    """Each key parses back to the entity it was built from, and the kinds are the three this exam adds."""
    for ident, kind in ((SUBSCRIPTION_ID, "MS"), (SERVER_ID, "SS"), (CLIENT_ID, "SC")):
        key = keys()[ident]
        entity = graph.parse_token(key, DOMAIN)
        _need(entity is not None and entity.kind == kind, f"the key of token {ident} does not parse as a {kind} entity")
        _need(len(key.encode()) <= 253, f"the key of token {ident} is over the 253 bytes the link is declared with")
    _need(len(keys()[SERVER_ID].encode()) > 129, "a service key fits the first release's key bound, so the key-bound refusal tests nothing")


def check_runs() -> None:
    token.check_shapes()
    token.check_runs()
    check_shapes()


def frame_of(number: int, ident: int) -> bytes:
    """The FRAME for the declaration `number` after the OPEN_SYN, with the key in full."""
    return zenoh_wire.frame(INITIAL_SN + number, token.declare_bytes(ident, keys()[ident]))


def withdraw_frame() -> bytes:
    return zenoh_wire.frame(INITIAL_SN + len(DECLARED), token.withdraw_bytes(WITHDRAWN))


def written(ack_hex: str) -> bytes:
    """Everything the link wrote before it was closed."""
    out = token.framed(token.link.client_syn()) + token.framed(token.link.open_syn(bytes.fromhex(ack_hex)))
    for number, ident in enumerate(DECLARED):
        out += token.framed(frame_of(number, ident))
    return out + token.framed(withdraw_frame())


def held_text(ids: tuple[int, ...]) -> str:
    return f"tokens={len(ids)} ids={','.join(str(i) for i in ids)}" if ids else "tokens=0 ids=-"


def good_lines() -> list[str]:
    check_runs()
    lines: list[str] = []
    for name, _syn, ack, open_ack, _forwarded in router.RUNS:
        lines.append(f"cliententity fed {name} {ack} {open_ack}")
        for mode in MODES:
            lines.append(f"cliententity sent {name} {mode} {token.hexed(written(ack))}")
            lines.append(f"cliententity held {name} {mode} {held_text(HELD)}")
            lines.append(f"cliententity closed {name} {mode} reason=0 wrote={token.hexed(token.close_bytes())} tokens=none")
            lines.append(f"cliententity ok {name}-{mode}")
    for refused, cls in REFUSALS:
        lines.append(f"cliententity refused {refused} {cls}")
    return lines


def judge(lines: list[str]) -> tuple[int, int]:
    """The printed transcript must equal the one built here, line for line. Returns (cases, refusals)."""
    wanted = good_lines()
    for line in lines:
        _need(line.startswith("cliententity "), f"cliententity: a record that is not an entity exam line: {line!r}")
        _need(line == line.strip() and "  " not in line, f"cliententity: a line with stray spaces: {line!r}")
    missing = [line for line in wanted if line not in lines]
    extra = [line for line in lines if line not in wanted]
    _need(not missing, f"cliententity lines missing: {[m[:90] for m in missing[:3]]}")
    _need(not extra, f"cliententity lines the exam does not build: {[e[:90] for e in extra[:3]]}")
    _need(len(lines) == len(wanted), f"cliententity: {len(lines)} lines, the exam builds {len(wanted)}; a line is repeated")
    _need(lines == wanted, "cliententity: the lines are not in the order the exam runs them")
    refusals = sum(1 for line in wanted if line.startswith("cliententity refused "))
    return len(wanted) - refusals, refusals


# ------------------------------------------------------------------------------------------------ the controls


def reference_controls() -> int:
    return token.reference_controls()


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    kinds = {kind: [i for i, line in enumerate(good) if line.startswith(f"cliententity {kind} ")] for kind in ("fed", "sent", "held", "closed", "ok", "refused")}
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not an entity exam line", [*good, "clienttoken ok router-data-1-whole"]),
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
    for kind in ("fed", "sent", "held", "closed"):
        for index in kinds[kind]:
            fields = good[index].split(" ")
            last = fields[-1]
            changed = last[:-1] + ("0" if last[-1] != "0" else "1")
            out.append((f"{kind} line {index} with a changed last field", [*good[:index], " ".join([*fields[:-1], changed]), *good[index + 1 :]]))
    classes = sorted({line.split(" ")[3] for line in good if line.startswith("cliententity refused ")})
    for cls in classes:
        index = next(i for i in kinds["refused"] if good[i].split(" ")[3] == cls)
        other = next(c for c in classes if c != cls)
        out.append((f"the {good[index].split(' ')[2]} refusal reported as {other}", [*good[:index], good[index].replace(f" {cls}", f" {other}", 1), *good[index + 1 :]]))

    first = kinds["sent"][0]
    sent = written(router.RUNS[0][2]).hex()
    frames = {ident: token.framed(frame_of(number, ident)).hex() for number, ident in enumerate(DECLARED)}
    withdraw = token.framed(withdraw_frame()).hex()

    def sent_with(change) -> list[str]:
        return [good[i].replace(sent, change(sent), 1) if i == first else good[i] for i in range(len(good))]

    def in_frame(ident: int, old: str, new: str):
        return lambda s: s.replace(frames[ident], frames[ident].replace(old.encode().hex(), new.encode().hex(), 1), 1)

    out += [
        ("a subscription token of the publisher kind", sent_with(in_frame(SUBSCRIPTION_ID, "/MS/", "/MP/"))),
        ("a subscription token on another topic", sent_with(in_frame(SUBSCRIPTION_ID, "%chatter", "%chatterx"))),
        ("a subscription token with the publisher's QoS", sent_with(in_frame(SUBSCRIPTION_ID, "::,10:,:,:,,", "::,42:,:,:,,"))),
        ("a subscription token under another domain", sent_with(in_frame(SUBSCRIPTION_ID, "@ros2_lv/0/", "@ros2_lv/1/"))),
        ("a service server token of the client kind", sent_with(in_frame(SERVER_ID, "/SS/", "/SC/"))),
        ("a service client token of the server kind", sent_with(in_frame(CLIENT_ID, "/SC/", "/SS/"))),
        ("a service token with another service type", sent_with(in_frame(SERVER_ID, "AddTwoInts_", "AddTwoInts"))),
        ("a service token with another type hash", sent_with(in_frame(CLIENT_ID, "RIHS01_e118", "RIHS01_e119"))),
        ("a service token on another service", sent_with(in_frame(SERVER_ID, "%add_two_ints", "%add_three_ints"))),
        ("a service token as a wildcard key", sent_with(in_frame(SERVER_ID, "slime_node", "slime_*ode"))),
        ("a service token without the sender mapping", sent_with(lambda s: s.replace(frames[SERVER_ID], frames[SERVER_ID].replace("1e66", "1e26", 1), 1))),
        ("the service client token written before the server token", sent_with(lambda s: s.replace(frames[SERVER_ID] + frames[CLIENT_ID], frames[CLIENT_ID] + frames[SERVER_ID], 1))),
        ("the subscription token written before the publisher token", sent_with(lambda s: s.replace(frames[PUBLISHER_ID] + frames[SUBSCRIPTION_ID], frames[SUBSCRIPTION_ID] + frames[PUBLISHER_ID], 1))),
        ("a declaration frame that skips a sequence number", sent_with(lambda s: s.replace(frames[SERVER_ID], frames[SERVER_ID].replace(f"{INITIAL_SN + 3:02x}", f"{INITIAL_SN + 9:02x}", 1), 1))),
        ("a withdrawal that names the node token", sent_with(lambda s: s.replace(withdraw, withdraw.replace("870c5f", "870a5f", 1), 1))),
        ("a withdrawal that names the service server token", sent_with(lambda s: s.replace(withdraw, withdraw.replace("870c5f", "870d5f", 1), 1))),
        ("a withdrawal without its extension", sent_with(lambda s: s.replace(withdraw, withdraw.replace("5f020000", "", 1), 1))),
        ("a withdrawal that was never written", sent_with(lambda s: s.replace(withdraw, "", 1))),
        ("a link that holds the withdrawn subscription token", [good[i].replace(held_text(HELD), held_text(DECLARED), 1) if i == kinds["held"][0] else good[i] for i in range(len(good))]),
        ("a link that dropped a service token with the subscription", [good[i].replace(held_text(HELD), held_text(tuple(x for x in HELD if x != SERVER_ID)), 1) if i == kinds["held"][0] else good[i] for i in range(len(good))]),
        ("a link that holds no token after the withdrawal", [good[i].replace(held_text(HELD), held_text(()), 1) if i == kinds["held"][0] else good[i] for i in range(len(good))]),
        ("a link that holds the tokens in another order", [good[i].replace(held_text(HELD), held_text(tuple(reversed(HELD))), 1) if i == kinds["held"][0] else good[i] for i in range(len(good))]),
        ("a link that still holds a token after the close", [good[i].replace("tokens=none", "tokens=1", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]),
        ("a close with another reason", [good[i].replace("reason=0", "reason=1", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]),
        ("a local close that wrote nothing", [good[i].replace("wrote=02002300", "wrote=-", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]),
    ]
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (PINNED_CASES - PINNED_REFUSALS, PINNED_REFUSALS), f"cliententity: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise EntityExamError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except EntityExamError:
            refused += 1
            continue
        raise EntityExamError(f"control: the entity judge accepted {label}")
    return refused


def all_controls() -> int:
    return transcript_controls() + reference_controls()


# What the item fixes, held here as well so the gate stays correct after the item moves to .tasks/terminal.
PINNED_CASES = 33
PINNED_REFUSALS = len(REFUSALS)
PINNED_CONTROLS = 99


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
