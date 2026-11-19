# Zenoh Profile 0 transport

The bounded Zenoh subset two ROS 2 demo nodes use to exchange one topic: the
wire codec, a pure session machine, a runtime that carries a session over a byte
stream, and the two node components that run it on `sel4-zenoh`. It is a
userspace consumer of the [network service](network-service.md): the service
carries bytes and parses nothing, and every Zenoh concept lives in these
modules.

Owners:

- wire vocabulary and bounds: `contracts/zenoh-profile/v1/` (generated
  `components/proto/src/zenoh_profile.rs`); the wire records themselves belong
  to eclipse-zenoh wire version `0x09` and are not declared here;
- decoder and `StreamFramerOf`: `components/lib/src/zenoh_profile0.rs`; encoder:
  `zenoh_profile0/encode.rs`; session machine: `zenoh_profile0/session.rs`;
- graph session: `zenoh_profile0/graph.rs`; the graph its liveliness tokens build:
  `components/lib/src/zenoh_rmw_graph.rs`; the link that carries them:
  `components/lib/src/zenoh_rmw_link.rs`; their exam fixtures:
  `contracts/zenoh-rmw-session/v1/`, `contracts/zenoh-rmw-graph/v1/` and, for the samples,
  `contracts/zenoh-rmw-data/v1/`;
- link configurations: `contracts/zenoh-link-limits/v1/` judges a named configuration, and
  `zenoh_profile0/limits.rs` states the same arithmetic in Rust; FRAGMENT:
  `zenoh_profile0/fragment.rs`; reassembly into storage the component lends:
  `zenoh_profile0/reassembly.rs`; slot tables: `zenoh_profile0/tables.rs`;
- classic CDR for `Counter`: `components/lib/src/ros_cdr.rs`;
- transport runtime: `components/lib/src/zenoh_link.rs`;
- the nodes' shared exchange logic: `components/lib/src/zenoh_node.rs`;
- nodes: `components/applications/ros2-demo-publisher` and
  `components/applications/ros2-demo-subscriber`;
- composition: `contracts/system-spec/v1/systems/sel4-zenoh.zti` (generation 168),
  from which `contracts/generation-manifest/v1/compositions/sel4-zenoh.zti` is
  derived;
- the external variant: `contracts/system-spec/v1/systems/sel4-zenoh-external.zti`
  (generation 169) and the nodes `components/applications/ros2-demo-publisher-external`
  and `ros2-demo-subscriber-external` (see [External listener](#external-listener));
- the demo it serves: [`contracts/rpi5-ros2-demo/v2`](../../contracts/rpi5-ros2-demo/v2/README.md);
- plan and decision: [`../plans/ros2-wire-compatibility.md`](../plans/ros2-wire-compatibility.md),
  [`../decisions/zenoh-profile0-transport.md`](../decisions/zenoh-profile0-transport.md).

## Boundary

Profile 0 admits one static peer link over one TCP connection: the
`INIT`/`OPEN` handshake as connector or listener, reliable `FRAME` batches
carrying `DECLARE_SUBSCRIBER`, `UNDECLARE_SUBSCRIBER` and a `PUSH` with a `Put`
body and the 33-byte `rmw_zenoh` attachment, `KEEP_ALIVE`, and `CLOSE`. A stock
eclipse-zenoh 1.0.0 peer on the plain demo topic is also taken
([decision](../decisions/zenoh-stock-peer.md)): the optional QoS extension on
`INIT_SYN` and, only where it was observed, on `OAM` and on the outer `DECLARE`; an
`OAM` and a `DeclareFinal` after `OPEN`; and one numeric key-expression alias for the
demo key, in the declaring peer's mapping only (a reference in the receiver's mapping
names an alias this side declared, and it declares none, so it is `invalid-keyexpr`); and its
`UndeclareSubscriber`, which names the subscriber by id alone behind the network QoS extension
(`9e 21 08 03 <id>`, [decision](../decisions/zenoh-stock-undeclare.md)). The session removes the
remote subscriber it holds under that id, and an id it does not hold is `unknown-subscriber`; the
full form still matches on id and key, and the bare form without the QoS extension stays
`malformed-message`. Everything else is refused with a class from the closed vocabulary in
`contracts/zenoh-profile/v1`, never tolerated: routers and clients, wildcard key
expressions, other resolutions, unknown extensions and messages. A second alias is
refused as over-bound and an undeclared one as `invalid-keyexpr`.

Bounds are enforced before any byte is taken. The first release's are the demo
contract's: a 512-byte batch, 129-byte key expression, 33-byte attachment, 12-byte
payload, 64-byte cookie, one subscriber, four outstanding samples and three retries,
and `Link`, `Session` and `decode_batch` still mean exactly that. A link may instead
be built from a named configuration that `contracts/zenoh-link-limits/v1` judges
(batch, key, payload, key and subscriber counts, outstanding samples, stack and heap),
in one of two modes. The arrays of a link and its session equal what the configuration
declares: storage larger or smaller than that is refused at construction as
`InvalidConfig`.

- **fixed**: no heap, every buffer an array sized from the configuration, and a message
  must fit one batch. A Put that does not fit is refused as `over-bound`, and a
  FRAGMENT is refused as `unsupported-message` whatever its form;
- **heap**: the owning component lends the storage a fragmented message is joined into
  (`LinkOf::pump_with`), and a Put larger than a batch is sent and received as reliable
  `FRAGMENT`s. One message is reassembled at a time, a run's first fragment must be the
  session's next expected sequence number, a gap is `fragment-sequence`, a run that
  outlives its declared timeout is `reassembly-timeout`, and the joined message is held
  to what a whole-frame Put is held to. Best-effort fragments and fragments with
  extensions are still refused.

What a link sends is bounded by the smaller of its own batch and the one the peer
announced in its `INIT`. Nothing in these modules allocates.

`limits::LIDAR` is the heap configuration `lidar-publisher` uses. Its batch is 4096
bytes including the stream length, one network-service data operation. It admits a
payload of 512 KiB, so a 494,889-byte PointCloud2 frame crosses as 121 fragments.

`tools/foxglove-bridge/bridge.py` is the host side of that topic. It listens as a stock eclipse-zenoh
peer on `127.0.0.1`, forwards each sample on a frame store's data key unchanged to one channel of a
foxglove-sdk server (`foxglove.sdk.v1`). It subscribes that key in full: the guest's Profile 0 session
refuses a wildcard key declaration. A sample's log time
is its rmw_zenoh attachment timestamp. Both dependencies are hash-pinned wheels it reinstalls on every
start; it refuses a host with no pin, a pin pip refuses, and an invalid store before it listens.

## Layers

| Layer | What it owns | What it does not own |
| --- | --- | --- |
| Decoder, encoder | Bytes to and from `Message`, under the `Bounds` they are given; every length checked against its bound first; decoded values borrow from the batch | Session state, time, the link |
| Fragment codec, reassembly | Cutting a message into FRAGMENT bodies, reading one, joining a run into lent storage with a deadline measured from its first fragment | The session's sequence number, any clock, any memory of its own |
| Session machine | Handshake, cookie, frame sequence numbers, lease, subscriber and alias tables, delivery, the effective batch; time is an argument | I/O, allocation, any clock capability |
| `Link` over `ByteLink` | One framed batch awaiting send, partial writes, backpressure, the retry limit, reassembly, notices, generation-checked handles | A socket or a capability: the node passes it the connection the generation granted |
| Node exchange (`zenoh_node`) | The publisher and subscriber control flow as steppable state machines, the console lines, the service-reply-to-error mapping, the denied requests | Bindings, the connection, the console: those are the component's |
| Node components | Their bindings, the service connection, the clock and the console, handed to `zenoh_node` through two small traits | Any control flow worth testing |
| Service core (`zenoh_service`) | The grant rows, one ring of samples for each holder, the subscriptions it declares to the peer, and the routing of a publication and of a peer's sample by the rows | A session of its own (the caller lends one on each call), a link, a clock, network authority |

The session keeps slot tables of the sizes its type states (`SessionOf<K, S, B, E>`:
`K` key aliases, `S` subscribers of both sides, keys of up to `B` bytes, and `E`
events one batch can yield; `Session` is the first release's one alias and one
subscriber of each side). A subscriber *this side* declared is delivered to: a
received `PUSH` reaches only its key. A subscriber *the peer* declared is published
to: a `Put` this side sends must name its key. A `FRAME`'s changes to the tables are
journaled and undone if a later message in it is refused, and a frame that changes
more than the journal holds is refused before it changes anything. A publisher therefore learns the subscriber's key from its
declaration before it may publish, and a subscriber never accepts a `Put` for a
key it did not declare. Frames the session sends use the sender key mapping,
as the upstream encoder writes them.

`Params::local` is the number of subscriptions this side may declare, and the table
holds `per_side + local` slots. `Params::DEMO` and `Params::from_limits` set it to 1, so
the first release and every link built from `contracts/zenoh-link-limits/v1` keep one.
A side that declares a subscription beyond `local`, or one under an id it already
holds, is refused as `subscriber-limit`. A `local` below 1, or a table of any other
size, is refused at construction as `InvalidConfig`. Two subscriptions on one key
deliver a `Put` once, and the `Put` is refused as `undeclared-key` once the last
subscription on that key is undeclared. A link configuration cannot yet declare more
than one; that needs a new version of the limits contract.

An open session sends a one-byte `KEEP_ALIVE` (message id 4) every quarter of the
lease this side announced when it has sent nothing else, floored at one millisecond,
and takes the peer's as traffic that renews the lease. Before `OPEN` a `KEEP_ALIVE`
is `unexpected-message` and changes nothing, and it is exactly the one byte: a
trailing byte is `trailing-bytes`. The peer expires a link on the lease announced to it,
so that lease sets the send cadence; the lease the peer announced bounds the silence
tolerated from it. A link quiet for longer than the peer's lease is
closed by `tick` with the expiry reason. The demo exchanges its samples well inside
the 2 s lease. A link whose send slot is occupied runs only the expiry half
(`tick_lease`), so a keep-alive never collides with a batch waiting there.

A refused call leaves the session unchanged. The only transitions into
`Closed` are a received `CLOSE`, a local `close()` and lease expiry; a caller
that wants the link gone after a refusal says so.

## rmw_zenoh graph

A ROS 2 node that uses `rmw_zenoh_cpp` declares its graph before it publishes. The graph session
(`zenoh_profile0/graph.rs`) takes those declarations. Its type is `GraphSessionOf<A, D, B>`, and
`Params::GRAPH` configures it. `Params::graph` is `false` in every other constructor. `SessionOf::with_params`
refuses a configuration that sets it. The plain decoder, `Network`, `Event` and
`SessionError` gain no variant, so the stock-peer, undeclare and subscribers exams keep every pinned
refusal.

A graph session takes these, and the plain session refuses each of them:

| The peer sends | The graph session |
| --- | --- |
| Key aliases | Holds up to `A` aliases of up to `B` bytes. A repeated id or a scope on an alias is `invalid-keyexpr`. `UndeclareKeyExpr` is `unsupported-message`. |
| `DeclareSubscriber`, `DeclareQueryable` and `DeclareToken`, and the undeclaration of a queryable or a token | Records each declaration in a table of `D` slots. An undeclaration of one it does not hold is `unknown-declaration`. `UndeclareSubscriber` is `unsupported-message`. |
| The INIT extensions: a unit extension with id 1, then optionally id 7 with a value of at most 1 | Accepts that chain only. Any other extension, or a mandatory one, is `unsupported-extension`. |
| A `Put` with a timestamp, and the source-info and attachment extensions | Parses it. A Put on the session's own subscription is a `Sample`. Every other push whose key is valid is dropped and counted. |
| An `INTEREST` of mode 1 (current) with options `0x79` over `@ros2_lv/<domain>/**` | Takes it and writes one `FRAME` for it: a `DECLARE` with the interest flag, the interest id and a `DeclareFinal`. |

A subscriber or a queryable may name a wildcard key, as the peer's `@/<zid>/peer/config/**` does. A token
key or the key of a push may not, and is `wildcard-keyexpr`.

The session announces a 512-byte batch in its `INIT_ACK`. It bounds keys at 253 bytes, the longest alias
an rmw_zenoh peer declared. It answers no query and declares no token. A `FRAME` applies whole or not at
all, as in the plain session.

### Samples and the INTEREST

A graph session holds at most one subscription of its own, declared with `send_declare_subscriber`. A Put
that names that key reaches the owner through `on_batch_samples` as a `Sample` with its subscription id,
sequence number, timestamp and payload. The Put must carry the 33-byte attachment. Without a readable
attachment the whole `FRAME` is refused. The session stays open, and the graph link ends on a refusal.
A second subscription is `subscriber-limit`.

`send_put` writes a Put with the sender mapping and the attachment. The peer must have declared a subscriber
on that key. Without one the Put is `undeclared-key`, and a payload over the bound is `over-bound`. The
graph session holds the peer's subscribers in its own table, and the inner session's table holds none.
`session.rs` therefore gains a method that writes the Put after the graph session made that check.

A peer sends one `INTEREST` for `@ros2_lv/<domain>/**` before it sends data. A peer that gets no answer
holds its first publication for about 10 s. The session answers it with a `DeclareFinal` that
carries the interest id and declares no token, queryable or key alias in reply. The answer is written
before the `FRAME` that asked for it is committed, so a `FRAME` whose answer cannot be written is undone.
The answer restarts the keep-alive cadence from the time of that `FRAME`. The session takes one
`INTEREST`. Any other mode, any other options byte, a key that is not `@ros2_lv/<domain>/**` and a second
`INTEREST` are `unsupported-message`. A peer that reconnects opens a new session. In one run, a reconnecting
peer sent no second `INTEREST`.

`zenoh_rmw_graph.rs` reads each `@ros2_lv` token into an `Entity` and holds the live ones in
`Graph<N>`. A token is `@ros2_lv/<domain>/<zid>/<nid>/<id>/<kind>/<enclave>/<namespace>/<node>`, and a
node, publisher, subscription, service server or service client token adds
`/<topic>/<type>/<hash>/<qos>`. A `%` in a name field reads as `/`. An empty field of the QoS
substring is rmw_zenoh's default. The graph refuses the `N + 1`th entity as `graph-full` and never evicts.

The rules are those of `rmw_zenoh_cpp` 0.6.10, with one difference. Upstream reads three things loosely,
and the graph refuses each. A token may not have more or fewer parts than its kind. A number must be
canonical decimal. A Zenoh ID must be 1 to 32 lowercase hexadecimal digits. A graph serves one domain and
refuses another as `wrong-domain`. A key outside `@ros2_lv` is ignored and counted.

### Graph link

`zenoh_rmw_link.rs` carries a graph session over a `ByteLink`. Its type is
`GraphLinkOf<L, FRAMED, A, D, B, N>`. The parameters are the batch with its stream length, the aliases and
declarations of its session, the longest key, and the entities of its graph.

The plain link matches `Event` exhaustively, so the graph link is a separate type. It reuses the plain
link's `ByteLink`, `PumpReport`, stream framer, encoder and retry limit.

A pump flushes the single send slot and reads whatever chunks the stream gives. It decodes each complete
batch and feeds every token the batch carries into the graph. Then it checks the lease.

The link writes the handshake, a `KEEP_ALIVE` a quarter of its own lease after it last sent, and a `CLOSE`.
It declares nothing and answers no query. It does not deliver a sample, because it drives `on_batch_visit`,
which has no sample callback. A frame the session writes in answer to an `INTEREST` is queued as any other
reply, and no test here holds that.

| Event | What the link does |
| --- | --- |
| A token the graph refuses, or has no room for | Counts it in `refused_tokens` and stays open. |
| A bad length prefix, an unreadable batch, a full buffer with no whole batch or a session refusal | Ends and empties the graph. It queues a `CLOSE` of reason 0 into a free send slot. |
| A receive error, or the end of the stream at a batch boundary | Ends and empties the graph. It queues a `CLOSE` of reason 0 into a free slot, and a stream that takes no byte never writes it. |
| A send that stalls more than `MAX_RETRIES` times in a row, or a send error | Ends as `retry-limit` or a link error and empties the graph. The slot still holds the unsent batch, so no `CLOSE` is queued. |
| The peer's `CLOSE`, a local `close`, or the peer's lease running out | Ends, with that reason or `CLOSE_EXPIRED`, and empties the graph. `close_reason` says which. |

A link that ends has an empty graph: a graph of a session that ended describes nothing. A link whose single
send slot is occupied when it ends writes no `CLOSE`, and the peer finds out by its own lease. The plain
link has the same limit, and no test here holds that.

## Service core

The service core (`components/lib/src/zenoh_service.rs`) serves one session to several local holders by
the rows of `contracts/zenoh-service-grants/v1`. A row names a holder, one exact key and the rights to
publish and to subscribe, and a key in a request grants nothing. The core is declared with its rows and
the session's parameters. It does not own the session. The caller lends one on each call, and the core
refuses a session declared with other parameters, so its size is its own and stays under the overheads
the contract states.

After the session opens, the core declares one subscription for each distinct subscribe key, numbered
from 1 in the order the keys first appear in the rows. A publication needs a row that grants the holder
the right to publish the key. It reaches every holder with a subscribe row on the key, the publisher
included, and it is written to the peer only if the peer declared a subscriber on the key. Otherwise the
core reports the peer's copy as not subscribed and the local copies still arrive. A refused publication
reaches no ring and writes nothing. A peer's sample reaches every holder with a subscribe row on the
subscription that matched, and `Event::SampleDelivered` names that subscription. A Put for a key no
subscription holds is refused as `undeclared-key`.

Each holder has a ring of fixed slots. A holder that does not take never blocks another. A full ring
keeps its newest samples and counts what it dropped, and the next take reports the count once. The core
serves whole-frame samples only, so a session that reassembles fragments is refused.

## Grants path and the service component

The grants reach the service in four steps. A system spec declares them with the keys `zenohGrants` and `zenohGrantsObject`,
at most `maxZenohGrants` of 64 rows. The generation builder encodes them as the resource object `zenoh-grants`, in the
layout of `contracts/zenoh-service-grants-table/v1`. The root reads that object on the label `ZENOH_GRANTS_READ`, 75. The
reader serves 168-byte rows, at most six for one call, from a row cursor, and only to the instance named `zenoh-service`.
The root decides no grant. It copies authenticated bytes. The runtime wrapper `zenoh_grants_read` makes the call.

The same read serves a second record at one cursor value, 4294967295. A system spec declares the service's six limits as
`zenohLimits` on the instance named `zenoh-service`, and the spec refuses them on any other instance. The spec derives the
object `zenoh-limits` from that declaration, so it has no flag. The builder encodes the object in the 48-byte layout of
`contracts/zenoh-service-limits/v1`. A read at that cursor returns the record and no row, so its count is 48 bytes and not
a number of rows. `graph_runtime/services.rs` has its own branch for it, because the row branch would slice a count of
168-byte rows. The caller gate and the record's own checks are the same as for rows, and a record that does not decode is
not served. The service reads the record before the rows and refuses to start when a limit is above what it was built to
hold, or when the ring depth or the sample size is below it, because the core fixes both in its types and cannot enforce a
smaller declaration. The builder checks each limit against its bound and does not check the stack against the rows. The service checks the
declared stack against its own, and `zenoh-service-grants/v1` is not a generation input.

The server half (`components/lib/src/zenoh_service_server.rs`) answers the client protocol of
`contracts/zenoh-service-client/v1`. It takes one request, the payload that travelled with it and the time, and returns the
completion the client checks. It makes no runtime call, so a host test drives it. A request must be exactly 32 bytes. It
names a grant row by an index below the holder's own row count and never a key. The holder is the one whose endpoint the
request arrived on. A refused request changes no ring and writes nothing to the peer. A publication pumps the link and settles
up to eight times, and a link that has not flushed by then is reported as closed.

The component (`components/services/zenoh-service`) reads its grants, attaches to the network service and opens the link. It
lends each holder a ring and a data page as shared-buffer loans, and serves them with the server half. A detach or an abort counts
only when the server accepted it. A holder whose buffers could not be created is put back to having no session. The service
ends when every holder the grants name has attached and detached. It then closes the link, gives the link bounded pumps to flush
its CLOSE, and closes its connection through the network service.

The service prints one line for a publication, a taken sample and a publication refused for a row the holder may not publish.
`exchange_line` in the server half builds them from the request and the answer, and a host test drives it. The booted exchange is
judged on these lines.

The composition `sel4-zenoh-service` (generation 171) runs the service, a peer, and two holders named `alpha` and `beta`. The
peer listens on 127.0.0.1:7447 over the network service's loopback backend and declares no subscriber, so a publication reaches
the holders and not the peer. `alpha` may publish the key and `beta` may subscribe to it. `beta` then asks to publish and is refused.
The grants-table contract and encoder are release inputs of every closure, so a change to either changes each closure identity.

What is shown: one boot of this composition under QEMU, in which `alpha` published four samples, `beta` was delivered all four,
the service refused `beta`'s publish, and every instance exited with status 0. What is not shown: a second boot, a malformed
request, a link that stalls, or any sample crossing to a peer that subscribes. The peer in this composition declares no
subscriber.

Known limits of the component:

- It is built for at most two holders and two rows. It refuses a table above that, and it serves a table below it.
- No gate grades a holder that faults or a holder that never detaches. The service ends only when every holder has attached and
  detached.
- Nobody has computed the stack and memory sizes at real sizes. The composition runs at two holders and two rows.
- A configuration judged by `contracts/zenoh-link-limits/v1` cannot declare more than one local subscription. A second
  declaration needs a new version of that contract. The component does not use that path: it opens its link with
  `Params { local: 3 }`.
- A publisher receives its own publications, and a holder cannot exclude them. Lazy declaration and reliable delivery with
  credits are not implemented. [The decision record](../decisions/zenoh-service.md) gives the reasons.

## Link behaviour

- `Link::pump` flushes the pending send, reads, decodes and replies, then checks
  the lease. A send that accepts nothing counts as a stall; more than
  `MAX_RETRIES` consecutive stalls end the link with `RetryLimit`, and any
  progress resets the count.
- Reassembly takes a length prefix as soon as both bytes arrive, so a zero or
  oversized prefix is refused before its body. A received batch is never dropped:
  while the send slot or the notice queue is full the batch stays in the
  framer, and a full buffer with no complete batch is `ReceiveQueueFull`.
- A heap link takes its storage on every `pump_with`, cut into cells of one message
  each. A sample, whole or fragmented, stays in its cell until its notice is taken, so
  a batch waits until the queue has room for every notice it can raise and, for each
  sample, a free cell. `LinkOf` sizes its buffers and notice queue from its type; a Put
  larger than one frame is sent a fragment per `publish_part`, resuming where the last
  call left off.
- A pass that raised notices ends there, so `last_received_batch` names the batch
  behind the notices the owner is about to take; `last_sent_batch` names the
  batch most recently queued. Nodes print both as evidence.
- A `LinkHandle` carries the generation of the link that issued it. A restart
  builds a new link under the next generation, and an operation through an old
  handle is `StaleHandle`.

## Node exchange

The nodes are thin. Everything that decides what a node does lives in
`components/lib/src/zenoh_node.rs`, which builds on the host: `Publisher` and
`Subscriber` are steppable state machines over a `Link`, and a component supplies
only a `Host` (clock, yield, console) and a `Connection` (non-blocking send and
receive on one service connection). The host tests run the real publisher and
subscriber against each other over a scripted stream, so the order a node acts in
and every line it prints are judged without QEMU.

`Line` collects a console line in a fixed buffer and emits it by a single write. A
line that does not fit is refused whole and never truncated, so a clipped hex line
cannot reach the judge. The demo's frames are 184 bytes (368 hex digits); a full
512-byte batch would clip and is refused.

## Node authority

`sel4-zenoh` contains `init`, `network-service` and the two nodes over the
loopback backend. The publisher holds one destination, exact IPv4 TCP to
`127.0.0.1:7447` with `connect`, `send` and `recv` and no listener or DNS
authority. The subscriber is the one loopback listener on that endpoint with
`listen`, `send` and `recv`, admitting exactly the publisher's holder. Each
node attempts requests it was not granted, checks that each reply is a denial
(status `denied`, nothing moved, no capability), and only then reports it by name.
The publisher attempts an undeclared host, a port the endpoint does not name, a
listen, and a *scouting* request: a well-formed UDP connect to Zenoh's multicast
scouting group, which no destination row names. The subscriber attempts a connect.
Profile 0 has no scouting message, so the denial is the service refusing the
request, not the codec; a refusal of a malformed request would prove nothing about
authority.
Each console line is written in one `debug_write`, because the two nodes run
concurrently and a line built from several writes can be interleaved.

## External listener

`sel4-zenoh-external` (generation 169) is the same demo with the publisher dialling a
stock `eclipse-zenoh` 1.0.0 listener on the host through a virtio NIC, so a packet
leaves the VM and can be captured. It contains `init`, `network-service`,
`virtio-net-driver`, `ros2-demo-publisher` and `ros2-demo-subscriber` and one network
interface (`10.0.2.15/24`, gateway `10.0.2.2`, MAC `52:54:00:53:4c:01`). The publisher
holds one destination, exact IPv4 TCP to `10.0.2.2:17447` with `connect`, `send` and
`recv`, and is a rightless client on the `external` backend. The subscriber holds no
network authority and its executable exits at once.

The instance names stay `ros2-demo-publisher` and `ros2-demo-subscriber`, which the exam
pins; only their `executable` differs (`ros2-demo-publisher-external`,
`ros2-demo-subscriber-external`). The publisher reuses `zenoh_node` and `zenoh_link`
unchanged; the subscriber links only `slime-rt` and exits at once, so no Zenoh code runs
on its side. The publisher's endpoint is a compile-time constant; the network service enforces the real
destination row, so a wrong constant is refused there and grants nothing. The publisher
still sends its four refused requests. The scouting probe, a UDP connect, is refused by
the external backend as `unsupported` and not `denied`, because its TCP-only engine
checks the transport before the destination table; the publisher accepts that reply for
that probe only and prints the same `denial class=scouting` line.

`just zenoh_external_check` judges one run from three witnesses held against each other:
the derived composition, a QEMU `filter-dump` capture at the virtio-net device (one TCP
connection to `10.0.2.2:17447`, ARP only besides it), and the record the stock listener
wrote of what its own subscriber delivered. The guest's batches are held to
`scripts/lib/zenoh_wire.py`. The listener is a hash-pinned wheel from a registry, so the
recipe is explicit and in no aggregate. See the
[decision](../decisions/zenoh-external-listener.md).

## rmw_zenoh node and native peer

Two components exercise the graph link and the data path in one composition, `sel4-zenoh-rmw`. The
composition holds the network service, the node and the peer. It has no Zenoh service, grants table or limits.

| Component | Link | Role |
| --- | --- | --- |
| `zenoh-rmw-node` | Graph link, 512-byte batch | Listens on 127.0.0.1:7447, declares one subscription and publishes four Puts. |
| `zenoh-rmw-peer` | Plain Profile 0 link | Dials the node, declares one subscription and publishes four Puts. |

Both links are built for a key of at most 253 bytes and a payload of at most 32 bytes. The chatter key is 110 bytes, and a sample is at most 22 bytes.
The graph session answers an `rmw_zenoh` peer's one `INTEREST` with a `DeclareFinal`, because that peer waits about 10 seconds without it.
The native peer is a plain link and sends no `INTEREST`, so this boot does not perform that answer.

Each component prints `published sequence=N` and `received sequence=N` for N from 1 to 4. The node
closes the session after it has published 4 and received 4. One side's close ends the session for both, and the node's link
empties its sample queue when the peer closes. The peer does not close.

The two components are separate tasks. A component's publications and receptions have no fixed order, and the boot gate
holds no order between the two components' lines. `scripts/lib/zenoh_rmw_arm.py` judges each component's lines against its own order only.

Known limits:

- The composition has no row in `check-sel4-boot-layout.py`, so its initial capability layout is not frozen.
- The node drops samples that arrive in the same pump as a peer `CLOSE`. The boot closes after four of each, so it does not reach that case.
- No live `rmw_zenoh` peer runs in this composition. The exchange is between two Slime components over loopback.

## Limitations

- `sel4-zenoh` crosses the loopback backend, so there is no packet capture there. The
  nodes' reported batches observe their codecs and session at the service's
  application boundary, not the stack's wire, and the guest chooses what it
  prints. `sel4-zenoh-external` is the composition with a capture.
- `sel4-zenoh`'s evidence is the nodes' own reports at the service boundary. Under
  QEMU the corrected exam accepts the booted guest; see the plan for what was
  observed and on which image.
- The external exam runs on QEMU user networking, not a physical NIC. Its translation
  of the guest's connection to the host's loopback is not the wire a real network
  shows. It covers one peer: `eclipse-zenoh` 1.0.0, peer mode, scouting and gossip off.
- A Zenoh ID ending in `0x00`, or all zero, is refused: upstream holds it as a
  little-endian integer, drops trailing zero bytes and refuses zero, so the bytes
  would not round-trip.
- The graph session and graph are observed by replaying three captured sessions of one peer, `rmw_zenoh_cpp`
  0.6.10 on zenoh 1.10.1, on one host. No live rmw_zenoh peer runs in CI. The captured peer's graph was
  visible over one direct link with no router and no gossip, in one run.
- The plain link, `zenoh_link.rs`, cannot carry a graph session, because it matches `Event` exhaustively.
  The graph link does. No component, composition or QEMU gate runs it, so it is judged on the host over a
  scripted byte stream.
- The graph holds each entity's QoS and does not match a publisher to a subscription. The session and
  the link answer no query and declare no token. In one run, `ros2 topic list` and `ros2 node list` showed
  no Slime node, and `ros2 topic echo` received the Puts of a Slime publisher.
- The data session is observed by replaying two captured sessions, one talker and one listener, of
  `std_msgs/String` over a direct link. Live probes on one host showed more, with no CI evidence. A
  best-effort subscriber received the Puts. A peer that reconnected sent no second `INTEREST`. A Slime
  peer that dialed `rmw_zenohd` as a peer got no sample through, and one that announced itself as a client
  got all 12. The encoder writes no client `INIT`.
- A peer waits about 10 s for the answer to its `INTEREST`. A `FRAME` whose answer the session cannot write
  is refused whole. `ZENOH_ROUTER_CHECK_ATTEMPTS=0` stopped the one peer from exchanging data in the probes, and a
  value of 1 did not.
- No router, scouting, service or action interoperability, or transport security, and no Raspberry Pi 5
  claim. The ROSIDL importer and RIHS01 generator are not here: the demo contract's checker derives
  those values.

## Verification

- `just zenoh_encoder_check` — all 17 upstream-encoded corpus batches
  reproduced byte for byte, after the host reference `scripts/lib/zenoh_wire.py`
  reproduces them; 7 named refusals;
- `just zenoh_session_check` — 5 scenarios and 7 refusals;
- `just zenoh_cdr_check` — the demo fixture's 4 samples and 7 malformed inputs;
- `just zenoh_transport_check` — 6 scenarios and 7 refusals over a scripted link;
- `just zenoh_composition_check` — 15 authority facts on the derived manifest;
- `just zenoh_stock_check` — the session against the batches a stock eclipse-zenoh
  1.0.0 peer put on a TCP stream;
- `just zenoh_links_check` — a link built from each named configuration: the stock
  peer's fragments reproduced byte for byte, payloads up to 256 MiB reassembled, the
  tables and notice queue filled to their limits at 9, 256, 65535 and 65536, and 94
  refusals by name and class, each judged on a link and on its session;
- `just zenoh_undeclare_check` — the whole session a stock eclipse-zenoh 1.0.0 peer sent,
  including its `UndeclareSubscriber` that names the subscriber by id alone behind the
  network QoS extension, which the host reference reproduces byte for byte, and ten
  variants of it refused by name and class;
- `just zenoh_rmw_check` — 60 batches from three sessions of an `rmw_zenoh_cpp` peer, replayed into a graph
  session. The host reference `scripts/lib/zenoh_rmw_wire.py` writes every captured frame again byte for
  byte. The session's `INIT_ACK` and its silence after the handshake are judged. 11 variants are
  refused. It records 75 cases and 182 negative controls;
- `just zenoh_rmw_graph_check` — the 26 liveliness tokens of those sessions, read into a graph. The
  transcript is built from `scripts/lib/zenoh_rmw_graph.py`. It covers 12 QoS substrings, 8 synthetic
  tokens, 25 refused keys and a graph filled to its capacity. It records 106 cases and 196 negative
  controls;
- `just zenoh_rmw_link_check` — the same three sessions written to a graph link three ways: whole batches,
  one byte at a time and all at once. The bytes the link writes are judged to the byte. They are an
  `INIT_ACK` of 512 bytes, an `OPEN_ACK`, a `KEEP_ALIVE` at each quarter lease from 7500 ms, and a
  `CLOSE` of reason 5 at 60001 ms. A refused token is counted and the link stays open. A stream fault ends it, and every ending
  leaves 0 entities. It records 133 cases and 236 negative controls;
- `just zenoh_rmw_data_check` — two captured data sessions replayed into a graph session that holds one
  subscription. A talker's 11 samples are delivered and 28 other pushes are dropped. The `INTEREST` is
  answered with a `DeclareFinal`, and the 8 Puts a listener asks for equal what `scripts/lib/zenoh_wire.py`
  writes. 7 variants are refused. The captured batches reach the Rust through
  `contracts/zenoh-rmw-data/v1`. It records 140 cases and 208 negative controls;
- `just zenoh_xcheck_check` — the codec and session against the real eclipse-zenoh 1.0.0
  crates: the 17 corpus batches as upstream's encoder produces them, a 6000-case sweep
  (5993 compared, 7 refused as a non-canonical Zenoh ID, none differing), our decoder
  reading what upstream encodes, upstream reading and re-encoding ours, one 11-batch
  session, and eight Zenoh ID probes; 17 mutations of an honest transcript refused first.
  The harness is `verification/zenoh-xcheck`, a standalone crate outside the root
  workspace, so the upstream crates stay out of `Cargo.lock`, `just deny` and the
  closures. It fetches them from a registry, so the recipe is explicit and not in CI;
  `cargo deny` run on that crate reports `paste` as unmaintained (RUSTSEC-2024-0436) and
  Zlib-licensed transitive crates, which the root `deny.toml` does not allow;
- `just zenoh_rmw_booted_check` — the `sel4-zenoh-rmw` boot: 17 cases and 65 controls, and the arm under QEMU;
  explicit, not part of `all`;
- `just rpi5_ros2_zenoh_check` — the QEMU exchange; explicit, not part of `all`;
- `just zenoh_external_check` — the guest connecting out to a stock listener, judged
  from the composition, a packet capture and the listener's record; explicit, not part
  of `all`.
