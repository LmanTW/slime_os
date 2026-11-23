"""Bytes a stock eclipse-zenoh 1.0.0 peer put on a TCP link, captured once.

These are the batch bodies (without the 2-byte stream length) that a real Zenoh peer sent
to, and accepted from, an endpoint running this repository's Profile 0 encoder. They are
the independent bytes the stock-peer exam judges against: this repository did not write
them, and no Slime code produced the stock side of any batch.

Provenance, all on one x86_64 Linux host, one run each:

* peer: `eclipse-zenoh==1.0.0` Python wheel
  `eclipse_zenoh-1.0.0-cp38-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`,
  sha256 `1763912951ecd2a3706f668faf0541245387096b37a4fefb73af7848dadd46ff`, `mode=peer`,
  multicast scouting and gossip disabled, one TCP endpoint, loopback.
* our side: the Profile 0 encoder at `65244f8d` (`INIT_ACK`/`OPEN_ACK` as listener, `INIT_SYN`/
  `OPEN_SYN` and `Put` frames as connector), answering and publishing the demo key and the
  four demo samples with their 33-byte attachments. Our side's batches are not fixtures.
* `connects`: the stock peer connected to us, declared a subscriber and a publisher on the
  demo key, and published the four samples with attachments. We listened.
* `listens`: the stock peer listened with a subscriber on the demo key. We connected, waited
  for its subscriber declaration, and published the four samples.
* `refuse`: batches a stock peer sent that a bounded profile must keep refusing: a client and
  a router `INIT_SYN`, a queryable declaration, a `get` request, a wildcard key declaration,
  and a wildcard declared as a suffix of a declared alias. Six more are built from captured
  batches (and, for the last, an accepted corpus row) by `wrong_position_qos`: the QoS extension the peer sends on an OAM or declaration,
  added to a FRAME header, a PUSH, a Put, the inner header of a subscriber declaration, a
  DeclareFinal and an UndeclareSubscriber, where it was never seen. (The captured QoS sits on
  the outer DECLARE, `9e 21 08`, that wraps a DeclareKeyExpr or DeclareSubscriber; the inner
  declaration header is a different position.)

Fields that vary between runs are the Zenoh IDs, the frame sequence numbers, the cookie and
the initial sequence number. The batches replay as bytes, so a run is deterministic.

What this does not cover: `rmw_zenoh` itself, liveliness tokens (the 1.0.0 Python binding has
no liveliness API, so none was observed), a router actually forwarding, and any peer other
than this one. See docs/decisions/zenoh-stock-peer.md.
"""

CONNECTS = (
    ("connects-01-init-syn", "c109f1c80817ffa75448d9eec5b0cf34c6059e0ac8ff01"),
    ("connects-02-open-syn", "420ae9f6ef561d736c696d652d73746f636b2d636170747572652d636f6f6b69652d3031"),
    ("connects-03-oam-declare-final", "25e9f6ef56df012108250203000210c80817ffa75448d9eec5b0cf34c6059e020003010008b2b2b2b2b2b2b2b202003e001a"),
    ("connects-04-declare-keyexpr-declare-subscriber", "25eaf6ef569e21082001008101302f736c696d655f64656d6f2f636f756e7465722f736c696d655f64656d6f5f6d7367733a3a6d73673a3a6464735f3a3a436f756e7465725f2f5249485330315f613832666435666663623936643061313937613561643336383064316334653662613433613936323932386563643539326662353635656238313239353935629e2108420101"),
    ("connects-05-push-1", "25ebf6ef565d018143210000000000000000e80300000000000010e0e1e2e3e4e5e6e7e8e9eaebecedeeef0c00010000000000000a000000"),
    ("connects-06-push-2", "25ecf6ef565d018143210100000000000000e90300000000000010e0e1e2e3e4e5e6e7e8e9eaebecedeeef0c000100000100000014000000"),
    ("connects-07-push-3", "25edf6ef565d018143210200000000000000ea0300000000000010e0e1e2e3e4e5e6e7e8e9eaebecedeeef0c00010000020000001e000000"),
    ("connects-08-push-4", "25eef6ef565d018143210300000000000000eb0300000000000010e0e1e2e3e4e5e6e7e8e9eaebecedeeef0c000100000300000028000000"),
    ("connects-09-keep-alive-1", "04"),
    ("connects-10-keep-alive-2", "04"),
    ("connects-11-close", "0300"),
)

LISTENS = (
    ("listens-01-init-ack", "6109f1ea220ec0a35d4de9b4618ecd68ccbbaa0a00022120d424560bc9b22a8dbed0918e284fe09529b5461465b69d0178a79fe7124f1763"),
    ("listens-02-open-ack", "620ab8be9957"),
    ("listens-03-oam", "25b8be9957df012108250203000210ea220ec0a35d4de9b4618ecd68ccbbaa020003010008a1a1a1a1a1a1a1a10200"),
    ("listens-04-declare-keyexpr", "25b9be99579e21082001008101302f736c696d655f64656d6f2f636f756e7465722f736c696d655f64656d6f5f6d7367733a3a6d73673a3a6464735f3a3a436f756e7465725f2f5249485330315f61383266643566666362393664306131393761356164333638306431633465366261343361393632393238656364353932666235363565623831323935393562"),
    ("listens-05-declare-subscriber-declare-final", "25babe99579e21084201013e001a"),
    ("listens-06-keep-alive-1", "04"),
    ("listens-07-keep-alive-2", "04"),
    ("listens-08-close", "0300"),
)

REFUSE = (
    ("refuse-client", "c109f2d374f022dce5bb49582e20fdeb66f66e0ac8ff01"),
    ("refuse-router", "c109f071a611afd4989829c8c12c53be70316e0ac8ff01"),
    ("refuse-queryable", "25e8ebfe5d9e21082001000c736c696d652f64656d6f2f719e2108440101"),
    ("refuse-request", "25e9d19c12fc01000c736c696d652f64656d6f2f71a10d26f4032303"),
    ("refuse-wildcard", "25c9f4bb679e21082001000a736c696d652f64656d6f9e2108620101032f2a2a"),
)



def _varint_end(body: bytes, index: int) -> int:
    while body[index] & 0x80:
        index += 1
    return index + 1


def wrong_position_qos(position: str) -> str:
    """A captured batch with the per-message QoS extension (`21 08`, optional, as the stock peer
    sends it on an OAM or a declaration) added where no capture has one: after the sequence number
    of a FRAME header, after the key of a PUSH, on the inner header of a DeclareSubscriber body (the captured extension is on the outer
    DECLARE that wraps it, not here), after the
    interest id of a DeclareFinal, on an UndeclareSubscriber's DECLARE, and in front of the
    attachment in a Put's extension chain. The extension flag is set on the header it follows,
    except for the Put, whose header already has it. The upstream 1.0.0 decoder reads all six, so each is a valid
    batch for a stock peer's codec; Profile 0 takes the extension only where it was observed and
    must refuse these as `unsupported-extension`, except the PUSH: the extension belongs on a PUSH after its key,
    which is where this builds it, so Profile 0 takes that batch (`qos-on-push-is-taken`)."""
    extension = bytes.fromhex("2108")
    if position in ("frame", "push"):
        body = bytearray.fromhex(dict(CONNECTS)["connects-05-push-1"])
        sequence_end = _varint_end(body, 1)
        if position == "frame":
            body[0] |= 0x80
            body[sequence_end:sequence_end] = extension
        else:
            assert body[sequence_end] == 0x5D
            body[sequence_end] |= 0x80
            key_end = _varint_end(body, sequence_end + 1)
            body[key_end:key_end] = extension
    elif position == "subscriber":
        body = bytearray.fromhex(dict(LISTENS)["listens-05-declare-subscriber-declare-final"])
        start = _varint_end(body, 1)
        assert body[start : start + 3].hex() == "9e2108" and body[start + 3] == 0x42
        header_at = start + 3
        end = _varint_end(body, _varint_end(body, header_at + 1))
        body[header_at] |= 0x80
        body[end:end] = extension
    elif position == "put":
        body = bytearray.fromhex(dict(CONNECTS)["connects-05-push-1"])
        sequence_end = _varint_end(body, 1)
        assert body[sequence_end] == 0x5D
        put_at = _varint_end(body, sequence_end + 1)
        assert body[put_at] == 0x81
        # The Put header already has its extension flag (the attachment); the QoS extension goes
        # first in the chain with its own "more extensions" flag set, so no header byte changes.
        body[put_at + 1 : put_at + 1] = bytes.fromhex("a108")
    elif position == "final":
        body = bytearray.fromhex(dict(LISTENS)["listens-05-declare-subscriber-declare-final"])
        header_at = len(body) - 3
        assert body[header_at:].hex() == "3e001a"
        body[header_at] |= 0x80
        body[header_at + 2 : header_at + 2] = extension
    elif position == "undeclare":
        body = bytearray.fromhex(UNDECLARE_SOURCE)
        assert body[2] == 0x1E
        body[2] |= 0x80
        body[3:3] = extension
    else:
        raise ValueError(position)
    return body.hex()


# The source of the UndeclareSubscriber case is not a capture: no run of the stock peer undeclared
# a subscriber. It is the accepted corpus row frame_undeclare_subscriber_sn7, which the upstream
# encoder produced and the checker pins by name and digest; judge_stock_corpus ties this constant to it.
UNDECLARE_SOURCE = "25071e83015f83010300302f736c696d655f64656d6f2f636f756e7465722f736c696d655f64656d6f5f6d7367733a3a6d73673a3a6464735f3a3a436f756e7465725f2f5249485330315f61383266643566666362393664306131393761356164333638306431633465366261343361393632393238656364353932666235363565623831323935393562"
def oversized_alias_key() -> str:
    """The captured DeclareKeyExpr with its key one byte over the 129-byte bound.

    The captured declaration carries the 129-byte demo key (`81 01` is the varint 129). This one
    lengthens the key by a byte and the length to 130 (`82 01`), so it is the same message shape,
    which the upstream 1.0.0 decoder reads, and Profile 0 must refuse it as `over-bound` once it
    parses a DeclareKeyExpr, as it refuses the 130-byte keys of a subscriber declaration and a PUSH."""
    body = bytearray.fromhex(dict(CONNECTS)["connects-04-declare-keyexpr-declare-subscriber"])
    marker = bytes.fromhex("2001008101")
    assert body.count(marker) == 1
    at = body.index(marker)
    body[at + 3 : at + 5] = bytes.fromhex("8201")
    body.insert(at + 5 + 129, ord("a"))
    return body.hex()


def suffixed_alias_batch(path: str) -> str:
    """A captured batch addressing the declared alias with a one-byte suffix `a`.

    The captures address alias 1 with no suffix. These keep scope 1 and set the wire expression's
    N flag with the suffix after the scope: the subscriber body `42 01 01` becomes `62 01 01 01 61`,
    and the PUSH header `5d` becomes `7d` with `01 61` after the scope. The upstream 1.0.0 decoder
    reads both (scope 1, suffix "a"), so a stock codec can produce them; the alias resolves to the
    declared key and no other, so Profile 0 must refuse a suffix on it."""
    suffix = bytes.fromhex("0161")
    if path == "subscriber":
        body = bytearray.fromhex(dict(LISTENS)["listens-05-declare-subscriber-declare-final"])
        at = body.index(bytes.fromhex("9e210842" + "0101")) + 3
        assert body[at : at + 3].hex() == "420101"
        body[at] = 0x62
        body[at + 3 : at + 3] = suffix
    elif path == "put":
        body = bytearray.fromhex(dict(CONNECTS)["connects-05-push-1"])
        header_at = _varint_end(body, 1)
        assert body[header_at : header_at + 3].hex() == "5d0181"
        body[header_at] = 0x7D
        body[header_at + 2 : header_at + 2] = suffix
    else:
        raise ValueError(path)
    return body.hex()


def undeclare_on_alias() -> str:
    """An UndeclareSubscriber addressing the declared alias with an empty suffix.

    The alias resolves a DeclareSubscriber and a Put to the declared key, and nothing else: the
    undeclaration path keeps naming its subscriber by the key it was declared with. This is the
    accepted corpus row frame_undeclare_subscriber_sn7 with its wire expression changed to scope 1,
    no suffix (`02 02 01` after the extension header). The upstream 1.0.0 decoder reads it (scope 1,
    empty suffix), and Profile 0 must refuse it rather than resolve the alias there."""
    return "25071e83015f" + "020201"


WRONG_POSITION_QOS = ("frame", "push", "put", "subscriber", "final", "undeclare")
WRONG_POSITION_NAMES = {
    "frame": "frame",
    "push": "push",
    "put": "put",
    "subscriber": "inner-subscriber-header",
    "final": "declare-final",
    "undeclare": "undeclare-subscriber",
}
REFUSE = REFUSE + (
    ("refuse-alias-key-130-bytes", oversized_alias_key()),
    ("refuse-alias-suffix-on-subscriber", suffixed_alias_batch("subscriber")),
    ("refuse-alias-suffix-on-put", suffixed_alias_batch("put")),
    ("refuse-alias-on-undeclare", undeclare_on_alias()),
) + tuple(
    (f"refuse-qos-on-{WRONG_POSITION_NAMES[position]}", wrong_position_qos(position))
    for position in WRONG_POSITION_QOS
)

# The stock peer's keep-alive is the single byte 0x04. On a 10 s lease it sent one every 2.5 s
# and on a 2 s lease every 0.5 s, so every lease/4. A peer that heard nothing from us closed the
# connection one lease after our last transmission: 2.002 s after it on a 2 s lease and 10.002 s
# on a 10 s lease. Sending its own keep-alives every 0.7 s kept a 2 s-lease session open for the
# whole 9 s run.
KEEP_ALIVE_BODY = "04"

# The cookie our side issued in the `connects` capture. The stock peer echoed it in its
# OPEN_SYN, so a listener replaying the capture must be configured with it. 29 bytes.
COOKIE = "slime-stock-capture-cookie-01"

# The exam, by name. A Rust test prints `[zenoh-exam] stock ok <name>` for each of OK and
# `[zenoh-exam] stock refused <name> <class>` for each of REFUSED; the checker owns both lists.
OK_SCENARIOS = (
    "stock-connects-open-and-deliver",
    "stock-listens-open-and-publish",
    "alias-resolves-to-declared-key",
    "keep-alive-renews-lease",
    "keep-alive-sent-lease-2000",
    "keep-alive-sent-lease-10000",
    "silence-past-lease-closes",
    # A tick sends nothing before OPEN. Link::pump ticks the session in every state that is not
    # closed, so an implementation that schedules keep-alives from the local lease could otherwise
    # put 0x04 into a stalled handshake. Each case ticks at times between a quarter lease and the
    # lease, and expects no output and no state change.
    "tick-silent-in-idle",
    "tick-silent-while-awaiting-init-ack",
    "tick-silent-while-awaiting-open-syn",
    "tick-silent-while-awaiting-open-ack",
    # A keep-alive is for a link that has sent nothing else. At the quarter-lease boundary with an
    # ordinary batch pending or just sent, no KEEP_ALIVE is added: the batch goes out whole, the
    # cadence restarts from it, and the link stays open. This is also the case where a keep-alive
    # and the link's single send slot would collide.
    "keep-alive-suppressed-by-traffic",
    # The `refuse` group still holds refuse-qos-on-push, a captured PUSH with the network QoS extension
    # `21 08` after its key. The extension is valid on a PUSH (eclipse-zenoh 1.0.0 writes it whenever the
    # value is not the PUSH default), so a session takes the batch and delivers its sample. The row keeps
    # its name and bytes because the fixtures contract fixes the group at 15 rows.
    "qos-on-push-is-taken",
)
REFUSED_SCENARIOS = (
    ("refuse-client", "unsupported-whatami"),
    ("refuse-router", "unsupported-whatami"),
    ("refuse-queryable", "unsupported-message"),
    ("refuse-request", "unsupported-message"),
    ("refuse-wildcard", "wildcard-keyexpr"),
    ("alias-undeclared", "invalid-keyexpr"),
    ("alias-second", "over-bound"),
    ("alias-redeclared-to-other-key", "invalid-keyexpr"),
    # The alias is declared once: the same DeclareKeyExpr repeated for alias 1 with the same key is
    # refused as well, not accepted as a no-op.
    ("alias-redeclared-same-key", "invalid-keyexpr"),
    # The session's single subscriber slot, enforced twice: a second declaration received from the
    # peer, and a second one sent by this side. The class is the session error, not a decoder class.
    ("second-subscriber-received", "subscriber-limit"),
    ("second-subscriber-sent", "subscriber-limit"),
    # The session reports at most MAX_EVENTS (4) events from one FRAME: five valid aliased PUSHes in
    # one frame are refused, and none is dropped silently.
    ("frame-five-events", "too-many-messages"),
    # A KEEP_ALIVE is traffic only on an open session. In each of the four states before OPEN the
    # session refuses it as an unexpected message and stays exactly as it was; the Rust test
    # compares the session's state and sequence numbers before and after.
    ("keep-alive-in-idle", "unexpected-message"),
    # A KEEP_ALIVE is exactly the one byte 0x04. Today `04 00` is refused as unsupported-message; once
    # the decoder knows message id 4 it must still refuse a batch that is not exactly that byte, as
    # the corpus refuses a trailing byte on a CLOSE and an INIT_SYN: `trailing-bytes`.
    ("keep-alive-trailing-byte", "trailing-bytes"),
    # The alias key keeps the existing 129-byte bound, as a subscriber declaration's and a PUSH's do.
    ("refuse-alias-key-130-bytes", "over-bound"),
    # Alias 1 resolves to the declared key and no other: a suffix after the alias is refused, on a
    # subscriber declaration and on a Put, so the session cannot accept, concatenate or ignore it.
    ("refuse-alias-suffix-on-subscriber", "invalid-keyexpr"),
    ("refuse-alias-suffix-on-put", "invalid-keyexpr"),
    # Aliases resolve a DeclareSubscriber and a Put only: an UndeclareSubscriber naming scope 1 is
    # refused, so the resolver does not reach the undeclaration path.
    ("refuse-alias-on-undeclare", "invalid-keyexpr"),
    # Undeclaring a subscriber the session does not hold, or with another id or key, is refused in
    # both directions and leaves the held subscriber in place. The Rust test compares the session's
    # state, held subscriber and sequence numbers before and after.
    ("unknown-subscriber-received", "unknown-subscriber"),
    ("unknown-subscriber-sent", "unknown-subscriber"),
    ("keep-alive-while-awaiting-init-ack", "unexpected-message"),
    ("keep-alive-while-awaiting-open-syn", "unexpected-message"),
    ("keep-alive-while-awaiting-open-ack", "unexpected-message"),
    ("extension-other-than-qos", "unsupported-extension"),
    ("transport-qos-marked-mandatory", "unsupported-extension"),
    ("network-qos-marked-mandatory", "unsupported-extension"),
    ("qos-extension-on-open", "unsupported-extension"),
    # The same valid extension where no capture has one; the batches are in REFUSE, built from captures.
    ("refuse-qos-on-frame", "unsupported-extension"),
    ("refuse-qos-on-put", "unsupported-extension"),
    ("refuse-qos-on-inner-subscriber-header", "unsupported-extension"),
    ("refuse-qos-on-declare-final", "unsupported-extension"),
    ("refuse-qos-on-undeclare-subscriber", "unsupported-extension"),
    ("qos-extension-on-init-ack", "unsupported-extension"),
)


def replay_names() -> tuple[str, ...]:
    """`replay:<fixture>` for every batch the stock peer sent while connecting or listening."""
    return tuple(f"replay:{name}" for group in ("connects", "listens") for name, _ in batches(group))


def batches(group: str) -> tuple[tuple[str, str], ...]:
    return {"connects": CONNECTS, "listens": LISTENS, "refuse": REFUSE}[group]


def fixture_zti() -> str:
    """The captured batches as one `contracts/zenoh-stock-fixtures/v1` record, in capture order.

    This is the hand-off to the Rust exam. The record is validated against the contract's
    schema before the tests see it, so a reader never parses a bespoke text format.
    """

    def rows(group: str) -> str:
        return "".join(f'    {{ name = "{name}"; hex = "{hexed}"; }};\n' for name, hexed in batches(group))

    return (
        "{\n"
        "  formatVersion = 1;\n"
        f'  cookieHex = "{COOKIE.encode().hex()}";\n'
        f"  connects = [\n{rows('connects')}  ];\n"
        f"  listens = [\n{rows('listens')}  ];\n"
        f"  refuse = [\n{rows('refuse')}  ];\n"
        "}\n"
    )
