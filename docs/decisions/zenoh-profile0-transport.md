# Zenoh Profile 0 transport

**Status:** Proposed
**Related work items:** epic `01a0f5fa-f2c4-71cf-962b-c62cbea2ef68`; encoder
`01a0f5fa-f704-73e0-b3a1-cd2debc429e9`; session machine
`01a0f5fa-fb06-7cbd-9a39-1539785433b7`; classic-CDR codec
`01a0f5fa-ff13-7667-8c59-6f4c6d312535`; transport runtime
`01a0f5fb-0344-7bb5-9d5b-2b79bc0339a8`; nodes and composition
`01a0f5fb-0780-754f-b2f4-e7513c86b63c`; QEMU gate
`01a0f5fb-0bb3-7612-9f87-30a7e8dae710`. R0 is
`01a00b4d-2400-7987-93d6-19201c397dff`.

## Context

R0's exit condition is two node components exchanging the declared topic over a
minimal Zenoh session under AArch64 QEMU. The decoder, the wire vocabulary in
`contracts/zenoh-profile/v1` and the frozen demo contract exist. Nothing encodes
a message, runs a session, serializes CDR, owns the link, or is granted authority
by a composition, and no gate judges Zenoh bytes.

R0 is a pre-cutoff prose item, so it cannot carry a devloop record and cannot bind
evidence. A spec-driven epic owns the remaining work and R0 is closed by hand when
the epic's acceptance holds.

## Decision

Build the exchange as six slices, each with its own recipe, and judge every slice
from evidence that its implementation did not write.

| Slice | Where it lives | What judges it |
| --- | --- | --- |
| Encoder | `components/lib/src/zenoh_profile0*` | Corpus batches produced by the upstream eclipse-zenoh 1.0.0 encoder |
| Session machine | `components/lib/src/zenoh_profile0*` | Named scenarios and refusals over a pure state machine with injected time |
| CDR codec | `components/lib/src/ros_cdr*` | The demo fixture's samples, recomputed from field values |
| Transport runtime | `components/lib/src/zenoh_link*` | Scenarios over a scripted byte link, so no QEMU is needed |
| Nodes and composition | `components/applications/ros2-demo-*`, `sel4-zenoh` system spec | The derived manifest's authority rows |
| QEMU arm | `check-sel4-io-network-plane.py --arm zenoh` | Seven marker chains and the guest's reported batches |

**The Rust tests report; the checker judges.** Each Rust slice prints one
`[zenoh-exam]` line per case. `scripts/check/check-zenoh-profile0.py` holds the
expectation, requires exactly the names it lists, and compares reported bytes with
bytes from an independent source. A test that asserts its own counts cannot pass a
slice, because the count is not the test's to state.

**An independent wire reference.** `scripts/lib/zenoh_wire.py` encodes the admitted
subset from the values a corpus summary names. Before it judges anything it
reproduces all 17 accepted corpus batches, whose bytes the upstream encoder
produced. The corpus, the reference and the Rust encoder must therefore agree, and
a Rust encoder that merely agrees with the Rust decoder fails.

**A judge is trusted after it refuses its mutations.** Every judge runs first on an
honest synthetic transcript, then on mutations of it, and the gate fails if any
mutation is accepted. The mutation pass found a real hole while this was written: the
first transcript judge let success precede the publisher's close. The exchange arm
runs 22 transcript and 15 composition mutations (37) before it reads the guest.

**One composition, exact authority.** `sel4-zenoh` (generation 168) contains
`init`, `network-service` and the two nodes over the loopback backend. The
publisher holds one destination, exact IPv4 TCP to `127.0.0.1:7447` with connect,
send and recv; the subscriber is the one loopback listener on that endpoint,
admitting exactly the publisher holder. Rights, wildcard binds, resolver records,
a UDP destination and an external backend are each a refused mutation.

**The QEMU arm lives in the network plane checker.** It is the owner of the
network planes, and the shared mechanism in `scripts/lib/sel4_plane.py` and
`scripts/lib/sel4_gate_markers.py` is reused. The arm's 25 markers join the plane's
gate-control pin (193 to 218), so the existing missing, reordered and
failure-marker mutations cover it.

## Alternatives

- **Round-trip the Rust encoder against the Rust decoder.** Cheapest, and
  worthless as evidence: both can share one misreading of the wire.
- **Have the Rust tests assert the golden bytes.** The pass would then say only
  that the test agreed with itself. The checker reads the bytes instead.
- **Match the nodes' success marker in QEMU.** Passes if the nodes agree with each
  other on wrong bytes.
- **A new top-level checker.** `AGENTS.md` reserves one for a genuinely new
  mechanism; the host slices share one checker and the QEMU arm joins the network
  plane's.
- **A new epic child for the ROSIDL importer and RIHS01 generator.** Excluded: the
  demo contract's checker derives those values and this work consumes them as
  frozen constants.

## Consequences

- The exchange crosses the service's loopback backend, so there is no packet
  capture. The arm judges the batches the nodes report handing to `send` and
  receiving from `recv`, which observes the node codecs and session at the
  service's application boundary and not the stack's own bytes.
- The checker depends on `components/lib/src/zenoh_profile0/vectors.txt`, which is
  not on `main` until the decoder lands. Until then the encoder, session, transport
  and QEMU recipes fail on its absence, which is the intended state of a grader
  landed ahead of its implementation.
- The Rust slices must use the module paths the recipes filter on:
  `zenoh_profile0::`, `ros_cdr::` and `zenoh_link::`. A runtime placed elsewhere
  runs no test and fails rather than reporting zero.
- Under `just devloop gate` every recipe in the aggregate inherits the observation
  target. The arm runs last and replaces any earlier report, so the arm's counts
  are the ones recorded.

## Revisit when

- the decoder lands and the corpus is on `main`;
- the network service reports bytes per connection, which would let the arm check
  the loopback stack as well as the nodes;
- R1 admits an external `rmw_zenoh` peer, which needs a capture of a real link.

## References

- [`../plans/ros2-wire-compatibility.md`](../plans/ros2-wire-compatibility.md)
- [`../../contracts/rpi5-ros2-demo/v2/README.md`](../../contracts/rpi5-ros2-demo/v2/README.md)
