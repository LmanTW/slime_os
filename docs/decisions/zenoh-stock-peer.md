# Zenoh Profile 0 and a stock Zenoh peer

**Status:** Proposed
**Related work items:** `01a12f13-a343-7924-af20-18148fc1b0d9` (this decision's exam and
implementation); Zenoh Profile 0 epic `01a0f5fa-f2c4-71cf-962b-c62cbea2ef68`; R1
`01a0724c-5400-7206-ae86-ad13584c8530` (deferred). R0 is `01a00b4d-2400-7987-93d6-19201c397dff`.

## Context

[Zenoh Profile 0](zenoh-profile0-transport.md) was designed against a decoder corpus
the upstream encoder produced, and it is checked against the real upstream codec
(`verification/zenoh-xcheck`). Neither shows what a Zenoh peer does on a link. The
transport decision named that gap: R1 "needs a capture of a real link".

A stock `eclipse-zenoh==1.0.0` peer (the Python wheel, `mode=peer`, scouting and
gossip off, loopback TCP) was run against a listener and a connector built on this
repository's encoder. What it sent is in `scripts/lib/zenoh_stock_peer.py`, with the
wheel hash and the way each batch was obtained.

## What was observed

Of the 19 batches the peer sent while connecting or listening, Profile 0's decoder
takes 5. The rest are refused for four reasons:

| The peer sends | Profile 0 today |
| --- | --- |
| an optional QoS unit extension (id 1) on `INIT_SYN`, and a per-message QoS extension (id 1, priority, congestion, express) on every `OAM`, `DeclareKeyExpr` and `DeclareSubscriber` inside a `FRAME`; its `PUSH`, `Put` and `DeclareFinal` carry none (the declaration header before a `DeclareFinal` is `0x3e`, with no extension flag) | `unsupported-extension` |
| an `OAM` and a `DeclareFinal` straight after `OPEN` | `unsupported-message` |
| the demo key as a numeric alias (`DeclareKeyExpr`), then `DeclareSubscriber` and `Put` addressed through that alias, with an empty suffix | `unsupported-extension`, then `invalid-keyexpr` |
| a one-byte `KEEP_ALIVE` every quarter of its lease (every 2.5 s on 10 s, every 0.5 s on 2 s) | `unsupported-message` |

What the peer accepted from our encoder: our `INIT_ACK` and `OPEN_ACK` completed the
handshake; our `DeclareSubscriber` and `Put` frames with the 33-byte attachment were
delivered to its subscriber with the demo key, payload and attachment intact; and a
`Put` we sent to the peer's declared key arrived four of four times. A peer that
heard nothing from us closed the link one lease after our last transmission
(2.002 s on a 2 s lease, 10.002 s on a 10 s lease), and one we sent keep-alives to
every 0.7 s stayed connected for the whole 9 s run on a 2 s lease.

A stock peer in `client` or `router` mode sends an `INIT_SYN` with that role. The
decoder refuses it as `unsupported-whatami`, and those refusals are Profile 0's own and
stay. In the one run where our responder answered a router's `INIT_SYN` using the
upstream codec to read it, the router completed the handshake and reported one peer, so
the refusal is ours and does not come from the peer.

## Decision

Profile 0 takes a stock peer for the plain demo topic, and nothing wider. The session
and link, not the node components, change:

1. **QoS extensions.** Two optional, non-mandatory id 1 extensions are accepted and
   ignored, and only where they were observed: the unit extension on `INIT_SYN`, and the
   per-message extension on the `OAM` network message and on the outer `DECLARE` network message (header `0x9e`, extension `21 08`) that wraps a `DeclareKeyExpr` or a `DeclareSubscriber` body, inside a `FRAME`. The outer `DECLARE` that wraps a `DeclareFinal` (header `0x3e`) does not carry it. A `PUSH` carried none: its header is `0x5d`, and the `QoS` that the upstream decoder prints for it is the default it fills in. Any other extension,
   and either QoS extension marked mandatory, stays `unsupported-extension`. So does the
   optional per-message QoS extension itself on a `FRAME` header, a `PUSH`, a `Put`, the
   inner header of a `DeclareSubscriber` body (the capture has the extension on the outer
   `DECLARE` around it, `9e 21 08 42 ...`; a second one after the inner `42`, as `c2 ... 21 08`,
   is a different position), the outer `DECLARE` around a `DeclareFinal`, or an
   `UndeclareSubscriber`, where no capture has one: six batches built from captured ones (the undeclaration from the accepted corpus row
   `frame_undeclare_subscriber_sn7`) by adding the two bytes `21 08` and the extension flag (for the `Put`, whose header
   already carries the flag for its attachment, the extension goes first in the chain as
   `a1 08`), which the upstream decoder reads and the exam pins as refused. No
   extension is accepted on `INIT_ACK`, `OPEN_SYN` or `OPEN_ACK`: the stock peer sent
   none there, so there is nothing to replay and no claim.
2. **OAM and DeclareFinal.** Accepted and ignored after `OPEN`. Nothing is sent in
   reply, because the peer needed no reply in any run.
3. **Key-expression alias.** One alias, declared once with `DeclareKeyExpr`, resolves
   a `DeclareSubscriber` or a `Put` to the declared key. A second alias is `over-bound`,
   an undeclared alias, a redeclaration to another key and a repeat of the same declaration are
   `invalid-keyexpr`: the alias is declared once, and a repeat is not a no-op. The
   key itself keeps every bound it has, and that includes the key of a `DeclareKeyExpr`, and the alias resolves to the declared
   key and no other, so a suffix on it is `invalid-keyexpr`, on a subscriber declaration and on
   a `Put`, rather than accepted, concatenated or ignored. It resolves a `DeclareSubscriber`
   and a `Put` only: an `UndeclareSubscriber` that names scope 1 is `invalid-keyexpr` too,
   because an undeclaration keeps naming the subscriber by the key it was declared with. The key of a `DeclareKeyExpr`: a
   130-byte alias key, the captured declaration with one byte added, is `over-bound`, as
   the 130-byte keys of a subscriber declaration and a `PUSH` already are. The session still holds one subscriber: a second
   declaration, received or sent, is `subscriber-limit` and leaves the first in place, and an
   undeclaration that does not name the held subscriber, received or sent, is
   `unknown-subscriber` and leaves it in place too. A FRAME yields at most four events
   (`MAX_EVENTS`): once an alias makes PUSHes small enough to coalesce, five in one FRAME is
   `too-many-messages`, not a dropped fifth.
4. **Keep-alive.** An open session sends `KEEP_ALIVE` every quarter of the lease it
   announced itself when it has sent nothing else, because that is the lease the peer
   expires it on, accepts the peer's as traffic, and
   closes with the expiry reason after one lease of silence, the peer's announced lease. Before `OPEN` nothing is
   sent on a tick: in the idle state and while awaiting `INIT_ACK`, `OPEN_SYN` or
   `OPEN_ACK`, a tick between a quarter lease and the lease produces no output and changes
   nothing, because the link ticks the session in every state that is not closed. A `KEEP_ALIVE` is traffic only
   on an open session: in the idle state and while awaiting `INIT_ACK`, `OPEN_SYN` or
   `OPEN_ACK` it is `unexpected-message` and the session is unchanged, so a keep-alive
   cannot refresh a handshake. When the link has sent an ordinary batch, or still holds one pending, at a quarter-lease
   boundary, no `KEEP_ALIVE` is added: the batch goes out whole, the cadence restarts from it
   and the link stays open, which also keeps the keep-alive from colliding with the link's
   single send slot. A `KEEP_ALIVE` is the single byte `04`; a batch with another
   byte after it stays refused, as `trailing-bytes`, like a trailing byte on a `CLOSE`.

Everything else the profile refuses stays refused with its class.

## Alternatives

- **Capture an `rmw_zenoh` peer instead.** It is what R1 targets, but it needs the
  `@ros2_lv` liveliness tokens, and the 1.0.0 Python binding cannot declare one, so
  no token was observed. A plain topic over a stock peer is the part that was.
- **Write a new profile.** The four changes are small and bounded, and a second profile
  would duplicate the decoder. They are added to Profile 0 under the same exam.
- **A text hand-off to the Rust tests.** The checker gives the tests the captured bytes
  through a file. A bespoke `<name> <hex>` format would be a second serialized format
  crossing a process boundary, so it is a versioned contract,
  `contracts/zenoh-stock-fixtures/v1`, validated before the tests read it.
- **Fix the node components.** The refusals are in the decoder and session; the nodes
  only see their notices.
- **Leave the profile closed and write a host adaptor.** An adaptor in front of the
  guest would have to speak the same stock behaviour, and would hide it from the exam.

## Consequences

- A stock Zenoh 1.0 peer can complete a session with the Profile 0 session and link
  and exchange the demo topic, as listener or connector, in a replay of captured bytes.
- Profile 0 is no longer "refuses what it does not implement" for these four things.
  Of the 102 refused vectors in `vectors.txt`, one may change: `transport_keep_alive`, the
  single byte `0x04`, which the stock peer sent four times. It may be removed or stay
  refused, but not become an accepted row: every accepted row is read by the encoder gate
  (which rebuilds each from its summary), by the cross-check harness and by a Rust test that
  counts them, none of which the implementation PR can change. The other 101 keep their
  name, class and bytes. I had first allowed
  nine, on the strength of their names, and checking them byte for byte against the capture
  showed that eight do not match anything the stock peer sent: the existing vectors for an
  extension flag, an alias, a scope, a suffix and an `OAM` are different shapes from the
  stock peer's (it attaches a QoS extension and a body they lack). The implementation
  accepts the stock shapes, and the 19 replays prove it; no accepted row is added to the
  corpus for them, and the stock tests run the decoder's properties on each batch
  themselves. Every
  extension position no captured batch used (a frame header, a subscriber declaration, a
  Put header) and the undeclare forms stay refused. The accepted rows are exactly the 17, with their name, bytes and summary, and so are the 14
  stream-framing rows (ten accepted and four refused), which carry the 512-byte stream
  bound and the reassembly rules and none of which a stock peer exercised. The exam pins
  the lists and a digest of each in `scripts/check/check-zenoh-profile0.py`, so the
  implementation cannot widen the profile by editing the corpus it is judged against. The
  digests prove the corpus text is unchanged, not that the decoder still agrees with it, so
  the recipe also runs the 11 tests of `zenoh_profile0::tests` (the corpus, every prefix of
  every accepted batch, byte flips, every two-chunk split and the framer bounds, which probe
  inputs the pinned rows do not list), the 14 tests of
  `zenoh_profile0::session::tests`, the 9 of `zenoh_profile0::encode::tests` and the 13 of
  `zenoh_link::tests`, and requires each to pass by name. The decoder's property tests walk only the accepted rows of the corpus, so they never see a stock batch; the stock tests run the same three properties (no proper prefix is accepted unless it is a shorter frame, a flipped bit never panics or exceeds a bound, every two-chunk split reassembles) on each captured batch and print a line for each, which the exam requires. The batches are not added to `vectors.txt` for this: `zenoh_encoder_check` and the cross-check harness read every accepted row, and neither knows a keep-alive, an OAM or a QoS extension. They run in a second `cargo test`
  process, apart from the stock tests: they print `[zenoh-exam]` lines for the recipes that
  own them, and none of those lines may reach the stock transcript. While
  `transport_keep_alive` exists it stays refused as `unsupported-message` with its captured byte `04`; it may be
  removed, but it cannot become an accepted row, which the encoder gate and the
  cross-check harness could not read. The encoder tests hold the key, payload, cookie and batch bounds, and the link
  tests hold send after close, stale handles, a full receive queue and stream handling,
  which the keep-alive and alias change edits. The session tests
  hold the handshakes, delivery, teardown and lease expiry and the refusals of a router
  peer, a version mismatch, a wildcard declaration, a push to an undeclared key, a replayed
  sequence number, a frame before open and a cookie mismatch; none is a stock scenario, and
  a `zenoh_stock::` filter alone would not run them. Two of them assert today's lease
  behaviour without keep-alives, which the implementation changes in its own diff.
- The closure digests change with the Rust change, as with any product edit.

## Limits

- The QoS extension was seen only where it is listed above. The stock peer's `INIT_ACK`
  carried none, but our `INIT_SYN` carried none either, so whether it would attach one
  when answering a QoS-bearing `INIT_SYN` was not tested.
- One peer, one wheel, one machine, one run each. The batch bytes replay
  deterministically; the peer's behaviour was not measured beyond what is stated here.
- The peer never undeclared its subscriber in these runs, so the undeclaration refusals above are
  built from the accepted corpus row and not from a capture. The external-listener exam later
  captured the peer's own: a bare `03 <id>` behind the network QoS extension, which is not any
  of the six batches built here. It is taken, and its variants refused, by
  [Zenoh Profile 0 taking a stock peer's undeclaration](zenoh-stock-undeclare.md).
- Python binding only. It wraps the Rust implementation, but `rmw_zenoh` and its
  liveliness tokens were not run.
- The exchange never leaves the machine: no QEMU, no NIC, no external listener. Reaching
  a service in the guest from outside needs the virtio-net backend, an external
  listener row and a host-reachable port, and is a separate item.
- Which lease sets the cadence was measured once, on loopback, in a separate probe that is
  not part of the exam: a session that announced 2 s to a stock peer announcing its default
  10 s was closed by the peer at 2.004 s when it sent no keep-alive, and stayed connected for
  a 9 s run when it sent one every 0.5 s. So the cadence is a quarter of the lease this side
  announced, not of the peer's. The exam's cadence cases use equal leases and cannot tell the
  two apart. Whether a cadence slower than 0.5 s on a 2 s lease also keeps the peer
  connected was not measured.

## Revisit when

- the external backend carries a Zenoh session, which would let the capture be taken
  across a NIC;
- liveliness tokens are captured from an `rmw_zenoh` peer, which is R1.

## References

- [`zenoh-profile0-transport.md`](zenoh-profile0-transport.md)
- [`../../contracts/zenoh-stock-fixtures/README.md`](../../contracts/zenoh-stock-fixtures/README.md)
- [`../architecture/zenoh-transport.md`](../architecture/zenoh-transport.md)
- [`../plans/ros2-wire-compatibility.md`](../plans/ros2-wire-compatibility.md)
- [`../plans/ros2-wire-compatibility.md`](../plans/ros2-wire-compatibility.md#r1-broader-ros-2-topic-wire-profile)
