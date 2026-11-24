"""Judge the Zenoh Profile 0 exam for queries against stock peers, from what the Rust tests print.

A stock eclipse-zenoh 1.0.0 peer that declares a queryable and answers a query, and a stock peer that asks
that query, each put a short session on a TCP link. `QUERYABLE_PEER` is the first, captured once with a
Profile 0 connector asking one query on the demo's `slime_demo/query` key; `GETTER_PEER` is the second,
captured once with a Profile 0 listener that had declared a queryable on that key. The stock-peer exam did not
capture either, and refuses a queryable declaration, a request and a response as `unsupported-message`.

The Rust tests under `zenoh_queries::` print one `[zenoh-exam] queries ...` line for each thing they did. This
module owns what those lines must be, and nothing here reads the Rust:

* the eight batches the queryable peer sent and the six the getter peer sent, each replayed in order into a
  session of ours;
* three scenarios: our query answered by a stock queryable, a stock peer's query answered by ours, and a
  queryable ended by id;
* the fifteen variants the profile keeps refusing, each with the class it is refused as;
* the decoder's properties on each captured batch.

The messages are also encoded here, by hand from the field layouts, and must equal the captured bytes, so the
capture is not taken on trust from the peer that wrote it. Like the other judges, this one is trusted only
after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

import zenoh_wire
import zutai_cli
from harness import ROOT

SCHEMA = ROOT / "contracts" / "zenoh-stock-queries" / "v1" / "schema.zt"

KEY = "slime_demo/query"
QUERYABLE_ID = 1
ALIAS = 1
REQUEST_ID = 1
TIMEOUT_MS = 3000
REPLIES = (b"answer-1", b"answer-2")

ID_REQUEST, ID_RESPONSE, ID_RESPONSE_FINAL = 28, 27, 26
ID_D_QUERYABLE, ID_U_QUERYABLE, ID_D_TOKEN = 4, 5, 6
ID_REPLY, ID_ERR = 4, 5
EXT_QOS = 0x21
EXT_TIMEOUT = 0x26
EXT_RESPONDER = 0x43
QUERY_HEADER = 0x23
CONSOLIDATION_LATEST = 3

# The batch bodies, without the two-byte stream length. The queryable peer is the one that answered: its
# INIT_ACK and OPEN_ACK, an OAM with the declaration of the key, of the queryable through the alias and a
# DeclareFinal, two replies and the final one of a single query, an UndeclareQueryable that names the
# queryable by id and a wire-expression extension, and a KEEP_ALIVE.
QUERYABLE_PEER = (
    (
        "answers-01-init-ack",
        "6109f10d13da794f4e7c93e3c3d66bd645deee0a00c0313033f13e28fedf752799584ebc051d2ef694a32e88b539b02caf600c50f201f0b0f1fa970be04050ceb127e8bf7a957787",
    ),
    ("answers-02-open-ack", "620ad7b0dc76"),
    (
        "answers-03-oam-declare-queryable-final",
        "25d7b0dc76df0121082d02030002100d13da794f4e7c93e3c3d66bd645deee020003010010aaf1cbe2537cb562ff7222c24a43b69202009e210820010010736c696d655f64656d6f2f71756572799e21084401013e001a",
    ),
    (
        "answers-04-response-1",
        "25d8b0dc76fb010010736c696d655f64656d6f2f7175657279a10d4312f00d13da794f4e7c93e3c3d66bd645deee02040108616e737765722d31",
    ),
    (
        "answers-05-response-2",
        "25d9b0dc76fb010010736c696d655f64656d6f2f7175657279a10d4312f00d13da794f4e7c93e3c3d66bd645deee02040108616e737765722d32",
    ),
    ("answers-06-response-final", "25dab0dc769a01210d"),
    ("answers-07-undeclare-queryable", "25dbb0dc769e210885015f020000"),
    ("answers-08-keep-alive", "04"),
)
# The getter peer is the one that asked: its INIT_SYN and OPEN_SYN, an OAM with a DeclareFinal, the request
# for the alias the other peer declared, a KEEP_ALIVE and a CLOSE.
GETTER_PEER = (
    ("asks-01-init-syn", "4109f1aaf1cbe2537cb562ff7222c24a43b6920ac8ff"),
    (
        "asks-02-open-syn",
        "420aeefdd34c313033f13e28fedf752799584ebc051d2ef694a32e88b539b02caf600c50f201f0b0f1fa970be04050ceb127e8bf7a957787",
    ),
    (
        "asks-03-oam-declare-final",
        "25eefdd34cdf0121082d0203000210aaf1cbe2537cb562ff7222c24a43b6920200030100100d13da794f4e7c93e3c3d66bd645deee02003e001a",
    ),
    ("asks-04-request", "25effdd34c9c0101a10d26b8172303"),
    ("asks-05-keep-alive", "04"),
    ("asks-06-close", "0300"),
)
REQUEST = "asks-04-request"
RESPONSE_1 = "answers-04-response-1"
RESPONSE_2 = "answers-05-response-2"
RESPONSE_FINAL = "answers-06-response-final"
DECLARE = "answers-03-oam-declare-queryable-final"
UNDECLARE = "answers-07-undeclare-queryable"

OK_SCENARIOS = (
    "stock-queryable-answers-our-query",
    "stock-peer-queries-our-queryable",
    "queryable-undeclared-by-id",
)


class QueriesError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise QueriesError(message)


def _sn_of(batch: bytes) -> int:
    _need(
        batch[0] == zenoh_wire.ID_FRAME | zenoh_wire.FLAG_R,
        "a captured batch is not a reliable FRAME",
    )
    sn, _at = zenoh_wire.read_leb128(batch, 1)
    return sn


def _frame_of(name: str, group: tuple[tuple[str, str], ...]) -> bytes:
    return bytes.fromhex(dict(group)[name])


QOS_REQUEST = bytes([EXT_QOS | zenoh_wire.FLAG_Z, 0x0D])


def request(
    request_id: int = REQUEST_ID,
    scope: int = ALIAS,
    suffix: bytes | None = None,
    extensions: bytes | None = None,
    query: bytes | None = None,
    request_id_bytes: bytes | None = None,
) -> bytes:
    """A REQUEST for one alias, as the stock peer sends it: the network QoS extension, a timeout, and a Query
    that asks for the latest consolidation and carries no parameters. The alias is the receiver's, so the
    mapping flag is clear."""
    header = ID_REQUEST | zenoh_wire.FLAG_Z | (zenoh_wire.FLAG_N if suffix is not None else 0)
    out = (
        bytes([header])
        + (zenoh_wire.leb128(request_id) if request_id_bytes is None else request_id_bytes)
        + zenoh_wire.leb128(scope)
    )
    if suffix is not None:
        out += zenoh_wire.prefixed(suffix)
    if extensions is None:
        extensions = QOS_REQUEST + bytes([EXT_TIMEOUT]) + zenoh_wire.leb128(TIMEOUT_MS)
    return (
        out + extensions + (bytes([QUERY_HEADER, CONSOLIDATION_LATEST]) if query is None else query)
    )


def declare_queryable(queryable_id: int = QUERYABLE_ID, alias: int = ALIAS) -> bytes:
    """What a stock peer sends: the DECLARE carries the network QoS extension, and the queryable is declared
    through the alias, with no suffix and no queryable-info extension."""
    return (
        bytes(
            [
                zenoh_wire.ID_DECLARE | zenoh_wire.FLAG_Z,
                zenoh_wire.EXT_QOS_NETWORK,
                zenoh_wire.QOS_NETWORK_DEFAULT,
                ID_D_QUERYABLE | zenoh_wire.FLAG_M,
            ]
        )
        + zenoh_wire.leb128(queryable_id)
        + zenoh_wire.leb128(alias)
    )


def undeclare_queryable(queryable_id: int = QUERYABLE_ID) -> bytes:
    return (
        bytes(
            [
                zenoh_wire.ID_DECLARE | zenoh_wire.FLAG_Z,
                zenoh_wire.EXT_QOS_NETWORK,
                zenoh_wire.QOS_NETWORK_DEFAULT,
                ID_U_QUERYABLE | zenoh_wire.FLAG_Z,
            ]
        )
        + zenoh_wire.leb128(queryable_id)
        + bytes([zenoh_wire.EXT_WIRE_EXPR])
        + zenoh_wire.prefixed(bytes([0]) + zenoh_wire.leb128(0))
    )


def response(
    request_id: int,
    key: str,
    zid: bytes,
    payload: bytes,
    reply: int = ID_REPLY,
    body: int = zenoh_wire.ID_PUT,
) -> bytes:
    """A RESPONSE carrying a Reply with a Put, as the stock queryable sends it: the key in full, the network
    QoS extension, and the responder identity extension of a zenoh id and an entity id."""
    responder = bytes([0xF0]) + zid + bytes([2])
    return (
        bytes([ID_RESPONSE | zenoh_wire.FLAG_N | zenoh_wire.FLAG_M | zenoh_wire.FLAG_Z])
        + zenoh_wire.leb128(request_id)
        + zenoh_wire.leb128(0)
        + zenoh_wire.prefixed(key.encode())
        + bytes([0xA1, 0x0D, EXT_RESPONDER])
        + zenoh_wire.prefixed(responder)
        + bytes([reply, body])
        + zenoh_wire.prefixed(payload)
    )


def response_final(request_id: int = REQUEST_ID) -> bytes:
    return (
        bytes([ID_RESPONSE_FINAL | zenoh_wire.FLAG_Z])
        + zenoh_wire.leb128(request_id)
        + bytes([EXT_QOS, 0x0D])
    )


def _responder_zid() -> bytes:
    """The queryable peer's zenoh id, read from its INIT_ACK, because the responder extension names it."""
    ack = _frame_of("answers-01-init-ack", QUERYABLE_PEER)
    return ack[3:19]


def reference_agrees(
    queryable: tuple[tuple[str, str], ...] = QUERYABLE_PEER,
    getter: tuple[tuple[str, str], ...] = GETTER_PEER,
    build: Callable[[], bytes] = request,
) -> None:
    """The hand-written encoders reproduce each captured message, and the capture is what it claims to be.

    The inputs are parameters so that `reference_controls` can corrupt each one in turn.
    """
    _need(
        len({name for name, _ in queryable}) == len(queryable),
        "a queryable-peer batch name is used twice",
    )
    _need(
        len({name for name, _ in getter}) == len(getter), "a getter-peer batch name is used twice"
    )
    asked = _frame_of(REQUEST, getter)
    built = zenoh_wire.frame(_sn_of(asked), build())
    _need(
        built == asked,
        f"the reference builds {built.hex()} for the request, the peer sent {asked.hex()}",
    )
    zid = _responder_zid()
    for name, payload in ((RESPONSE_1, REPLIES[0]), (RESPONSE_2, REPLIES[1])):
        captured = _frame_of(name, queryable)
        built = zenoh_wire.frame(_sn_of(captured), response(REQUEST_ID, KEY, zid, payload))
        _need(
            built == captured,
            f"the reference builds {built.hex()} for {name}, the peer sent {captured.hex()}",
        )
    captured = _frame_of(RESPONSE_FINAL, queryable)
    built = zenoh_wire.frame(_sn_of(captured), response_final())
    _need(
        built == captured,
        f"the reference builds {built.hex()} for the final response, the peer sent {captured.hex()}",
    )
    captured = _frame_of(UNDECLARE, queryable)
    built = zenoh_wire.frame(_sn_of(captured), undeclare_queryable())
    _need(
        built == captured,
        f"the reference builds {built.hex()} for the undeclaration, the peer sent {captured.hex()}",
    )
    declared = _frame_of(DECLARE, queryable)
    _need(
        declared.endswith(declare_queryable() + bytes.fromhex("3e001a")),
        "the captured declaration is not queryable 1 through alias 1",
    )
    _need(declared.count(KEY.encode()) == 1, "the captured declaration does not name the key once")
    captured_set = {hexed for _name, hexed in (*queryable, *getter)}
    for name, batch in refuse():
        if name in REPLAYED_REFUSALS:
            _need(
                batch in captured_set,
                f"{name} is meant to replay a batch a peer sent, and is not one",
            )
        else:
            _need(batch not in captured_set, f"{name} is a batch a peer sent")


def _refusals() -> tuple[tuple[str, str, str], ...]:
    """(name, batch, class): a captured message with one named change, and the class it is refused as.

    The first twelve are refused by the decoder before the session looks at them. The last three reach the
    session: a request when no queryable is declared, a response nobody asked for, and a second final.
    """
    sn = _sn_of(_frame_of(REQUEST, GETTER_PEER))
    reply_sn = _sn_of(_frame_of(RESPONSE_1, QUERYABLE_PEER))
    zid = _responder_zid()

    def frame(number: int, *messages: bytes) -> str:
        return zenoh_wire.frame(number, *messages).hex()

    timeout = bytes([EXT_TIMEOUT]) + zenoh_wire.leb128(TIMEOUT_MS)
    return (
        ("refuse-request-wildcard-suffix", frame(sn, request(suffix=b"*")), "wildcard-keyexpr"),
        ("refuse-request-unknown-alias", frame(sn, request(scope=9)), "invalid-keyexpr"),
        (
            "refuse-request-with-parameters",
            frame(
                sn,
                request(
                    query=bytes([QUERY_HEADER | 0x40, CONSOLIDATION_LATEST])
                    + zenoh_wire.prefixed(b"a=1")
                ),
            ),
            "unsupported-message",
        ),
        (
            "refuse-request-target-extension",
            frame(sn, request(extensions=bytes([0xA1, 0x0D, 0xA4, 0x01]) + timeout)),
            "unsupported-extension",
        ),
        (
            "refuse-request-mandatory-qos",
            frame(sn, request(extensions=bytes([0xA1 | 0x10, 0x0D]) + timeout)),
            "unsupported-extension",
        ),
        (
            "refuse-request-id-over-32-bits",
            frame(sn, request(request_id_bytes=bytes.fromhex("ffffffff1f"))),
            "leb128-overflow",
        ),
        (
            "refuse-request-truncated",
            frame(sn, bytes([ID_REQUEST | zenoh_wire.FLAG_Z, REQUEST_ID])),
            "truncated",
        ),
        (
            "refuse-response-error-reply",
            frame(reply_sn, response(REQUEST_ID, KEY, zid, REPLIES[0], reply=ID_ERR)),
            "unsupported-message",
        ),
        (
            "refuse-response-delete",
            frame(reply_sn, response(REQUEST_ID, KEY, zid, REPLIES[0], body=2)),
            "unsupported-message",
        ),
        (
            "refuse-response-wildcard-key",
            frame(reply_sn, response(REQUEST_ID, "slime_demo/*", zid, REPLIES[0])),
            "wildcard-keyexpr",
        ),
        (
            "refuse-queryable-wildcard-suffix",
            frame(
                reply_sn,
                bytes([zenoh_wire.ID_DECLARE, ID_D_QUERYABLE | zenoh_wire.FLAG_N])
                + zenoh_wire.leb128(QUERYABLE_ID)
                + zenoh_wire.leb128(0)
                + zenoh_wire.prefixed(b"slime_demo/*"),
            ),
            "wildcard-keyexpr",
        ),
        (
            "refuse-token-declaration",
            frame(
                reply_sn,
                bytes([zenoh_wire.ID_DECLARE, ID_D_TOKEN | zenoh_wire.FLAG_N])
                + zenoh_wire.leb128(QUERYABLE_ID)
                + zenoh_wire.leb128(0)
                + zenoh_wire.prefixed(b"a/b"),
            ),
            "unsupported-message",
        ),
        (
            "refuse-request-without-queryable",
            _frame_of(REQUEST, GETTER_PEER).hex(),
            "undeclared-key",
        ),
        (
            "refuse-response-nobody-asked-for",
            _frame_of(RESPONSE_1, QUERYABLE_PEER).hex(),
            "unexpected-message",
        ),
        (
            "refuse-response-final-repeated",
            frame(reply_sn + 3, response_final()),
            "unexpected-message",
        ),
    )


# These two are refused because of the session's state and not the batch: each replays a batch a peer sent.
REPLAYED_REFUSALS = ("refuse-request-without-queryable", "refuse-response-nobody-asked-for")
REFUSED_SCENARIOS = tuple((name, cls) for name, _batch, cls in _refusals())


def refuse() -> tuple[tuple[str, str], ...]:
    return tuple((name, batch) for name, batch, _cls in _refusals())


def reference_controls() -> int:
    """Each input `reference_agrees` guards is corrupted in turn, and must be refused for its own reason."""
    reference_agrees()

    def swap(
        group: tuple[tuple[str, str], ...], name: str, old: str, new: str
    ) -> tuple[tuple[str, str], ...]:
        return tuple((n, h.replace(old, new) if n == name else h) for n, h in group)

    cases: list[tuple[str, dict, str]] = [
        (
            "a reference that asks with another request id",
            {"build": lambda: request(request_id=2)},
            "the reference builds",
        ),
        (
            "a reference that asks for another alias",
            {"build": lambda: request(scope=2)},
            "the reference builds",
        ),
        (
            "a captured request with another timeout",
            {"getter": swap(GETTER_PEER, REQUEST, "b817", "b917")},
            "the reference builds",
        ),
        (
            "a captured reply with another payload",
            {"queryable": swap(QUERYABLE_PEER, RESPONSE_1, "616e737765722d31", "616e737765722d39")},
            "the reference builds",
        ),
        (
            "a captured final for another request",
            {"queryable": swap(QUERYABLE_PEER, RESPONSE_FINAL, "9a01", "9a02")},
            "the final response",
        ),
        (
            "a captured undeclaration of another queryable",
            {"queryable": swap(QUERYABLE_PEER, UNDECLARE, "85015f", "85025f")},
            "the undeclaration",
        ),
        (
            "a captured queryable that is id 2",
            {"queryable": swap(QUERYABLE_PEER, DECLARE, "44010 1".replace(" ", ""), "440201")},
            "queryable 1 through alias 1",
        ),
        (
            "a captured queryable through alias 2",
            {"queryable": swap(QUERYABLE_PEER, DECLARE, "440101", "440102")},
            "queryable 1 through alias 1",
        ),
        (
            "a queryable-peer batch name used twice",
            {"queryable": (*QUERYABLE_PEER[:-1], (QUERYABLE_PEER[0][0], QUERYABLE_PEER[-1][1]))},
            "queryable-peer batch name is used twice",
        ),
        (
            "a getter-peer batch name used twice",
            {"getter": (*GETTER_PEER[:-1], (GETTER_PEER[0][0], GETTER_PEER[-1][1]))},
            "getter-peer batch name is used twice",
        ),
    ]
    for label, changes, reason in cases:
        try:
            reference_agrees(**changes)
        except QueriesError as error:
            _need(reason in str(error), f"control: {label} was refused for another reason: {error}")
            continue
        raise QueriesError(f"control: the reference check accepted {label}")
    return len(cases)


def good_lines() -> list[str]:
    reference_agrees()
    names = [name for name, _ in (*QUERYABLE_PEER, *GETTER_PEER)]
    return (
        [f"queries replay {name} ok" for name in names]
        + [f"queries ok {name}" for name in OK_SCENARIOS]
        + [
            f"queries delivered {number} {payload.hex()}"
            for number, payload in enumerate(REPLIES, 1)
        ]
        + [f"queries property {name} ok" for name in names]
        + [f"queries refused {name} {cls}" for name, cls in REFUSED_SCENARIOS]
    )


def _exactly(label: str, wanted: tuple[str, ...], seen: list[str]) -> None:
    missing = [name for name in wanted if name not in seen]
    extra = [name for name in seen if name not in wanted]
    repeated = sorted({name for name in seen if seen.count(name) > 1})
    _need(not missing, f"queries {label} missing: {', '.join(missing[:4])}")
    _need(not extra, f"queries {label} not in the exam: {', '.join(extra[:4])}")
    _need(not repeated, f"queries {label} reported more than once: {', '.join(repeated[:4])}")


def judge(lines: list[str]) -> tuple[int, int]:
    """Check a transcript against the exam; returns (cases, refusals), a case being a scenario or a replay."""
    shapes = {
        ("queries", "ok"): 3,
        ("queries", "delivered"): 4,
        ("queries", "replay"): 4,
        ("queries", "property"): 4,
        ("queries", "refused"): 4,
    }
    split = [line.split() for line in lines]
    for line, fields in zip(lines, split, strict=True):
        _need(
            fields[:1] == ["queries"],
            f"queries: a record that is not a queries exam line: {line!r}",
        )
        kind = tuple(fields[:2])
        _need(kind in shapes, f"queries: unrecognised line: {line}")
        _need(
            len(fields) == shapes[kind],
            f"queries: a {kind[1]} line has {len(fields)} fields, expected {shapes[kind]}: {line}",
        )
        if kind in (("queries", "replay"), ("queries", "property")):
            _need(fields[3] == "ok", f"queries: a {kind[1]} line must end in ok: {line}")
    names = [name for name, _ in (*QUERYABLE_PEER, *GETTER_PEER)]
    done = [f[2] for f in split if f[:2] == ["queries", "ok"]]
    replays = [f[2] for f in split if f[:2] == ["queries", "replay"]]
    properties = [f[2] for f in split if f[:2] == ["queries", "property"]]
    delivered = [(f[2], f[3]) for f in split if f[:2] == ["queries", "delivered"]]
    wanted_delivered = [(str(number), payload.hex()) for number, payload in enumerate(REPLIES, 1)]
    _need(
        delivered == wanted_delivered,
        f"queries delivered {delivered}, the stock queryable answered {wanted_delivered}",
    )
    refused = [(f[2], f[3]) for f in split if f[:2] == ["queries", "refused"]]
    _exactly("scenarios", OK_SCENARIOS, done)
    _need(
        done == list(OK_SCENARIOS),
        f"queries scenarios are out of order: {done}, the exam runs them as {list(OK_SCENARIOS)}",
    )
    _exactly("replays", tuple(names), replays)
    _need(replays == names, f"queries replays are out of order: {replays}, the peers sent {names}")
    _exactly("properties", tuple(names), properties)
    _need(
        properties == names,
        f"queries properties held for {properties}, the exam requires every captured batch in capture order",
    )
    _exactly(
        "refusals", tuple(name for name, _ in REFUSED_SCENARIOS), [name for name, _ in refused]
    )
    wrong = [
        f"{name}={cls} (expected {dict(REFUSED_SCENARIOS)[name]})"
        for name, cls in refused
        if cls != dict(REFUSED_SCENARIOS)[name]
    ]
    _need(not wrong, f"queries refusal classes differ: {', '.join(wrong)}")
    _need(
        [name for name, _ in refused] == [name for name, _ in REFUSED_SCENARIOS],
        "queries refusals are out of order",
    )
    return len(done) + len(replays) + len(delivered), len(refused)


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    names = [name for name, _ in (*QUERYABLE_PEER, *GETTER_PEER)]
    first_replay = good.index(f"queries replay {names[0]} ok")
    at_response = good.index(f"queries replay {RESPONSE_1} ok")
    at_final = good.index(f"queries replay {RESPONSE_FINAL} ok")

    def without(line: str) -> list[str]:
        return [other for other in good if other != line]

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a queries exam line", [*good, "undeclare ok stock-undeclares-by-id"]),
        ("an unrecognised kind of line", [*good, "queries delivered 1 00 00"]),
        (
            "a replay line with an extra field",
            [good[first_replay] + " extra", *good[first_replay + 1 :]],
        ),
        (
            "a replay of a batch the peers did not send",
            [*good, "queries replay answers-09-extra ok"],
        ),
        ("the query replayed twice", [*good, f"queries replay {REQUEST} ok"]),
        ("the first two replays swapped", swapped(first_replay, first_replay + 1)),
        ("a response and the final response swapped", swapped(at_response, at_final)),
        (
            "a replay that did not end in ok",
            [
                *good[:first_replay],
                good[first_replay].replace(" ok", " failed"),
                *good[first_replay + 1 :],
            ],
        ),
        (
            "the scenarios swapped",
            swapped(
                good.index(f"queries ok {OK_SCENARIOS[0]}"),
                good.index(f"queries ok {OK_SCENARIOS[1]}"),
            ),
        ),
        (
            "a property that failed",
            [line.replace(f"property {REQUEST} ok", f"property {REQUEST} FAILED") for line in good],
        ),
        ("a refusal reported twice", [*good, good[-1]]),
        (
            "a refusal reported with a class it does not have",
            [*good, "queries refused refuse-query-elsewhere truncated"],
        ),
    ]
    for name in names:
        out.append((f"the replay of {name} missing", without(f"queries replay {name} ok")))
        out.append((f"the property of {name} missing", without(f"queries property {name} ok")))
    for name in OK_SCENARIOS:
        out.append((f"the scenario {name} missing", without(f"queries ok {name}")))
    first, second = (
        f"queries delivered {number} {payload.hex()}" for number, payload in enumerate(REPLIES, 1)
    )
    out.extend(
        [
            ("the first delivered payload missing", without(first)),
            ("the second delivered payload missing", without(second)),
            (
                "every delivered payload missing",
                [line for line in good if not line.startswith("queries delivered ")],
            ),
            (
                "a delivered payload that is not the reply",
                [
                    line.replace(REPLIES[0].hex(), REPLIES[1].hex(), 1) if line == first else line
                    for line in good
                ],
            ),
            ("the delivered payloads swapped", swapped(good.index(first), good.index(second))),
            ("a delivered payload reported twice", [*good, first]),
            ("a third delivered payload", [*good, f"queries delivered 3 {REPLIES[0].hex()}"]),
            (
                "a delivered line with an extra field",
                [line + " extra" if line == first else line for line in good],
            ),
        ]
    )
    classes = sorted({cls for _name, cls in REFUSED_SCENARIOS})
    for name, cls in REFUSED_SCENARIOS:
        out.append((f"{name} missing", without(f"queries refused {name} {cls}")))
        other = next(candidate for candidate in classes if candidate != cls)
        out.append(
            (
                f"{name} refused as {other}",
                [line.replace(f"refused {name} {cls}", f"refused {name} {other}") for line in good],
            )
        )
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need(
        (cases, refusals)
        == (
            len(OK_SCENARIOS) + len(QUERYABLE_PEER) + len(GETTER_PEER) + len(REPLIES),
            len(REFUSED_SCENARIOS),
        ),
        f"queries: the honest transcript is {cases} cases and {refusals} refusals",
    )
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise QueriesError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except QueriesError:
            refused += 1
            continue
        raise QueriesError(f"control: the queries judge accepted {label}")
    return refused


# ---------------------------------------------------------------------------- the hand-off record

DECODED_ENTRY = re.compile(r'\s*\{ hex = "([^"\\]*)";\s+name = "([^"\\]*)" \}\s*')
GROUPS = (("queryablePeer", 8), ("getterPeer", 6), ("refuse", 15))


def fixture_zti() -> str:
    """The captured batches and the refused variants as one `contracts/zenoh-stock-queries/v1` record."""

    def rows(group: tuple[tuple[str, str], ...]) -> str:
        return "".join(f'    {{ name = "{name}"; hex = "{hexed}"; }};\n' for name, hexed in group)

    return (
        f"{{\n  formatVersion = 1;\n  queryablePeer = [\n{rows(QUERYABLE_PEER)}  ];\n"
        f"  getterPeer = [\n{rows(GETTER_PEER)}  ];\n  refuse = [\n{rows(refuse())}  ];\n}}\n"
    )


def _decoded_rows(decoded: str, group: str) -> list[tuple[str, str]]:
    """The (name, hex) entries of one group in the decoder's own output, which spells every entry one way
    however the source wrote it. The whole group is consumed: an entry the reader cannot parse is refused."""
    start = re.search(rf"\b{group} = \[", decoded)
    _need(start is not None, f"queries hand-off: the decoded record has no {group} group")
    assert start is not None
    position, rows = start.end(), []
    if decoded[position : position + 1] == "]":
        return rows
    while True:
        entry = DECODED_ENTRY.match(decoded, position)
        _need(
            entry is not None,
            f"queries hand-off: {group} holds an entry the checker cannot read at offset {position}",
        )
        assert entry is not None
        rows.append((entry.group(2), entry.group(1)))
        position = entry.end()
        if decoded[position : position + 1] == "]":
            return rows
        _need(
            decoded[position : position + 1] == ";",
            f"queries hand-off: {group} is not a list of entries at offset {position}",
        )
        position += 1


def validate_handoff(text: str) -> None:
    """Decode a hand-off with the contract's own decoder, then hold the values the schema names."""
    (ROOT / "build").mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="zenoh-queries-", dir=ROOT / "build"))
    try:
        shutil.copyfile(SCHEMA, scratch / "schema.zt")
        (scratch / "decode.zt").write_text(
            's ::= import "schema.zt"; env ::= import stdlib.env; load ::= import stdlib.load; '
            "main :: { env : Env; load : Load; } -> Validation DecodeIssue s.Session ! { * env.GetEffects; * load.ZtiEffects; } "
            '= caps => [ path := env.get caps.env "SLIME_ZENOH_QUERIES_FIXTURES_PATH" ?? ""; s.decodeSession (load.zti caps.load path) ]; main\n'
        )
        record = scratch / "fixtures.zti"
        record.write_text(text)
        try:
            decoded = zutai_cli.evaluate(
                "run",
                scratch / "decode.zt",
                input_path=record,
                env_var="SLIME_ZENOH_QUERIES_FIXTURES_PATH",
            )
        except zutai_cli.ZutaiError as error:
            raise QueriesError(
                f"queries hand-off does not decode under contracts/zenoh-stock-queries/v1: {error}"
            ) from error
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    _need(
        decoded.startswith("#valid"),
        f"queries hand-off is refused by contracts/zenoh-stock-queries/v1: {decoded[:200]}",
    )
    version = re.search(r"\bformatVersion = (\d+)", decoded)
    _need(
        version is not None and int(version.group(1)) == 1,
        "queries hand-off: formatVersion is not 1",
    )
    for group, count in GROUPS:
        rows = _decoded_rows(decoded, group)
        _need(
            len(rows) == count,
            f"queries hand-off: {group} has {len(rows)} rows, the contract fixes {count}",
        )
        for name, hexed in rows:
            _need(
                len(name.encode("utf-8")) <= 64
                and len(hexed) % 2 == 0
                and len(hexed) // 2 <= 512
                and re.fullmatch(r"[0-9a-f]*", hexed) is not None,
                f"queries hand-off: {group}/{name} breaks the contract's bounds or is not lowercase hexadecimal",
            )


def handoff_controls() -> int:
    """The contract's decoder accepts the honest hand-off, spelled either way, and refuses each corrupted one."""
    honest = fixture_zti()
    last = f'    {{ name = "{GETTER_PEER[-1][0]}"; hex = "{GETTER_PEER[-1][1]}"; }};\n'
    first_refusal = f'    {{ name = "{refuse()[0][0]}"; hex = "{refuse()[0][1]}"; }};\n'
    respelled = honest.replace(
        last,
        f'    {{\n      name = "{GETTER_PEER[-1][0]}";\n      hex = "{GETTER_PEER[-1][1]}";\n    }};\n',
        1,
    ).replace("formatVersion = 1;", "formatVersion =\n    1;", 1)
    _need(respelled != honest, "control: the respelled honest hand-off equals the original")
    validate_handoff(honest)
    validate_handoff(respelled)
    close_hex = GETTER_PEER[-1][1]
    extra = '    {\n      name = "extra";\n      hex = "00";\n    };\n'
    mutations = [
        ("a missing group", honest.replace("  refuse = [", "  refuze = [")),
        ("a missing getter group", honest.replace("  getterPeer = [", "  getterPeers = [")),
        ("a wrong format version", honest.replace("formatVersion = 1;", "formatVersion = 2;")),
        ("a getter group of the wrong size", honest.replace(last, "", 1)),
        (
            "a queryable group of the wrong size",
            honest.replace(
                f'    {{ name = "{QUERYABLE_PEER[-1][0]}"; hex = "{QUERYABLE_PEER[-1][1]}"; }};\n',
                "",
                1,
            ),
        ),
        ("a refuse group of the wrong size", honest.replace(first_refusal, "", 1)),
        (
            "a name of 64 two-byte characters, 128 bytes",
            honest.replace(f'"{GETTER_PEER[-1][0]}"', '"' + "\u00e9" * 64 + '"', 1),
        ),
        (
            "a hex string with an odd length",
            honest.replace(f'hex = "{close_hex}"', f'hex = "{close_hex[:-1]}"', 1),
        ),
        ("a hex string in capitals", honest.replace(f'hex = "{close_hex}"', 'hex = "03AB"', 1)),
        (
            "a batch of 513 bytes",
            honest.replace(f'hex = "{close_hex}"', 'hex = "' + "00" * 513 + '"', 1),
        ),
        ("a row with no hex", honest.replace('hex = "', 'hxx = "', 1)),
        ("a hex that is not text", honest.replace('hex = "', 'hex = 7; zz = "', 1)),
        (
            "an unknown extra field",
            honest.replace("formatVersion = 1;", "formatVersion = 1;\n  surprise = 1;"),
        ),
        (
            "an unknown extra field on the same line as a known one",
            honest.replace("formatVersion = 1;", "formatVersion = 1; surprise = 1;", 1),
        ),
        (
            "an unknown extra field on the opening line",
            honest.replace("{\n  formatVersion", "{ surprise = 1;\n  formatVersion", 1),
        ),
        (
            "an unknown extra field inside an entry",
            honest.replace(
                last,
                f'    {{ name = "{GETTER_PEER[-1][0]}"; hex = "{close_hex}"; extra = 1; }};\n',
                1,
            ),
        ),
        (
            "an unknown extra field written over several lines",
            honest.replace("formatVersion = 1;", "formatVersion = 1;\n  surprise =\n    1;", 1),
        ),
        (
            "a wrong format version written over several lines",
            honest.replace("formatVersion = 1;", "formatVersion =\n    2;", 1),
        ),
        (
            "a ninth queryable entry written over several lines",
            honest.replace("  queryablePeer = [\n", "  queryablePeer = [\n" + extra, 1),
        ),
        (
            "a seventh getter entry written over several lines",
            honest.replace("  getterPeer = [\n", "  getterPeer = [\n" + extra, 1),
        ),
        (
            "a sixteenth refuse entry written over several lines",
            honest.replace("  refuse = [\n", "  refuse = [\n" + extra, 1),
        ),
    ]
    for label, text in mutations:
        if text == honest:
            raise QueriesError(f"control: {label} did not change the hand-off")
        try:
            validate_handoff(text)
        except QueriesError:
            continue
        raise QueriesError(f"control: {label} was accepted by the queries fixture contract")
    return len(mutations)


def all_controls() -> int:
    return transcript_controls() + handoff_controls() + reference_controls()


# What the admitted item fixes, held here as well so the gate stays correct after the item is completed
# and retired to .tasks/terminal. While the item is open its stored body is compared with these; once it is
# gone these still bind. Both counts are exact.
PINNED_CASES = 34
PINNED_CONTROLS = 113
ITEM_SLUG = "zenoh-queryables"


def item_pins() -> tuple[int, int]:
    """The case count and the control count the open item fixes, read from its file, or (0, 0)."""
    path = ROOT / ".tasks" / "items" / f"{ITEM_SLUG}.zt"
    if not path.is_file():
        return 0, 0
    text = path.read_text(encoding="utf-8")
    cases = re.search(r'"zenoh_queries_check" \{ h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'"zenoh_queries_check" \{ h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
