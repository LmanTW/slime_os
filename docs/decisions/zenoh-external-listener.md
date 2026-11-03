# Zenoh Profile 0 guest connecting out to a stock listener

**Status:** Proposed
**Related work items:** `01a1514d-caa7-74ff-8fca-c4fcda87aba1` (this decision's exam and
implementation, which replaces `01a13948-fc94-7359-ae7d-31c029147cf7` once the stock peer's
undeclaration is taken: see [Zenoh Profile 0 taking a stock peer's
undeclaration](zenoh-stock-undeclare.md)); Zenoh Profile 0 epic `01a0f5fa-f2c4-71cf-962b-c62cbea2ef68`; the stock-peer
session work `01a12f13-a343-7924-af20-18148fc1b0d9`; R0 `01a00b4d-2400-7987-93d6-19201c397dff`.

## Context

The Profile 0 demo has exchanged its four samples only between its own two nodes, over the
network service's loopback backend. That backend has no NIC, so no packet exists to capture,
and the `sel4-zenoh` composition (generation 168) grants one destination, `127.0.0.1:7447`,
which the demo hard-codes. The [stock-peer decision](zenoh-stock-peer.md) showed that the
session takes a stock `eclipse-zenoh==1.0.0` peer, but only from replayed bytes. Nothing
shows the guest opening a TCP connection out of the VM to a Zenoh peer this repository did
not write.

## What was observed

On the host, with no guest involved:

- The pinned wheel (`eclipse_zenoh-1.0.0-cp38-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`,
  sha256 `1763912951ecd2a3706f668faf0541245387096b37a4fefb73af7848dadd46ff`) installs with
  `pip --require-hashes --no-deps` into a fresh virtual environment, and the listener in
  `scripts/lib/zenoh_listener_peer.py` reports ready about 3 s later.
- A second stock peer, from a separate environment, connected to it, put four samples with
  attachments, and the listener wrote a record with those four samples and one remote peer.
  `contracts/zenoh-external-receipt/v1` decoded that record as valid.
- The judges in `scripts/lib/zenoh_capture.py` accept an honest synthetic exchange and eight
  honest variants of it, and refuse each of their corrupted forms. This proves the judges
  against evidence this repository built. It is not an observation of a guest.

Not observed: the guest, a QEMU NIC carrying Zenoh, the route from the guest to
`10.0.2.2:17447`, or the stock listener receiving anything the guest sent.

## Decision

Land the exam first. It judges one run from three witnesses that are held against each other:

1. **The composition.** `sel4-zenoh-external` at generation 169: five instances (`init`,
   `network-service`, `virtio-net-driver`, `ros2-demo-publisher`, `ros2-demo-subscriber`), one
   interface (`10.0.2.15`, gateway `10.0.2.2`, MAC `52:54:00:53:4c:01`, prefix 24), and one
   destination row held by the publisher: exact IPv4 TCP to `10.0.2.2:17447`, rights connect,
   send and recv. The subscriber holds no network row. A system spec is product, so this PR
   does not contain it, and the arm fails until the implementation PR adds it.
2. **The packet capture.** QEMU `filter-dump` at the virtio-net device. Each TCP direction is
   reassembled from the sender's own sequence numbers and split into batches by the two-byte
   stream length. Only ARP and TCP between the guest and the peer are admitted: no DNS, UDP,
   ICMP, second connection, other address or port, or reset.
3. **The listener's record.** The stock peer writes what its own subscriber delivered, as a
   record of `contracts/zenoh-external-receipt/v1`. It never reads the wire the capture holds.

The guest's batches are held to `scripts/lib/zenoh_wire.py`, which is proved against the
upstream-encoded corpus. The announced lease is exactly 2000 ms. The port, 17447, is outside
the Zenoh default so the demo's loopback 7447 stays distinct.

## Alternatives

- **Judge the guest's transcript only.** That is what the loopback arm does. It cannot show
  that a packet left the VM, so it is not enough here.
- **Judge the listener's record only.** It shows delivery but not that no DNS, UDP or second
  connection happened.
- **Reuse `http_capture.verify_capture`.** It counts TCP payload and does not interpret it,
  and it admits DNS. A stream reassembler checked against the sender's sequence numbers is new.
- **A publisher-only composition.** Smaller authority, but the subscriber would then not be
  exercised as a node without network authority. Both nodes stay, and what the idle subscriber
  prints is not judged.
- **Run the listener in CI.** The wheel comes from a registry. The recipe is explicit.

## Consequences

- `just zenoh_external_check` fails until the composition and the guest land, with
  `sel4-zenoh-external.zti does not exist; the sel4-zenoh-external composition has not landed`.
- The exam pins 4 cases and 291 corrupted records (246 + 15 + 30), exactly, and compares them
  with the admitted item while it is active. A change to either is a re-admission.
- Adding a recipe to `just/hardware.just` changes a closure input, so the system-image
  closures and test-run records must be regenerated before this lands. That is done as its
  own commit, and only when asked.

## Limits

- One peer, one x86_64 Linux machine. Work item `01a19cdb-5986-7d5f-a948-0d23122f52e5` adds
  a second pin of the same release for macOS on Apple silicon
  (`eclipse_zenoh-1.0.0-cp38-abi3-macosx_10_12_x86_64.macosx_11_0_arm64.macosx_10_12_universal2.whl`,
  sha256 `08b0871119786a1432864af8aa0cf42019a4b7bc8cfe725588cbc15f7d007f90`). The listener
  installs the pin for its host and refuses a host with none. QEMU user networking is not a physical NIC,
  and its translation of the guest's connection to the host's loopback is not the wire a real
  network shows.
- Outbound only. No inbound connection, listener on a NIC, DNS or scouting.
- The idle subscriber's output is not judged.
- The judges are proved on synthetic evidence. They have not yet seen a real capture.
- The stock listener's behaviour on a connector that announces a 2000 ms lease is not observed
  with the guest, only with another stock peer.

## Revisit

When the guest has run once against the listener: replace the synthetic-only claim with the
observed capture, and re-derive the counts. When a second peer, a second wheel or a physical
NIC is wanted: that is a new item.

## References

- [`zenoh-stock-peer.md`](zenoh-stock-peer.md), [`zenoh-profile0-transport.md`](zenoh-profile0-transport.md)
- `scripts/lib/zenoh_capture.py`, `scripts/lib/zenoh_listener_peer.py`,
  `scripts/check/check-sel4-io-network-plane.py --arm zenoh-external`
- `contracts/zenoh-external-receipt/v1`
