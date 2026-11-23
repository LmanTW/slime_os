# Zenoh links over TLS and over a serial line

**Status:** Proposed
**Related work items:** none yet. The planning PR that lands the items and their exams follows this record.
Zenoh Profile 0 epic: `01a0f5fa-f2c4-71cf-962b-c62cbea2ef68`.

## Context

[Zenoh Profile 0](zenoh-profile0-transport.md) carries one session over one TCP connection that the
[network service](../architecture/network-service.md) grants. `Link` in `components/lib/src/zenoh_link.rs` reads and
writes a `ByteLink`, and `StreamFramerOf` cuts the 2-byte length prefix. The
[architecture page](../architecture/zenoh-transport.md) lists transport security as not implemented.

Two facts about the repository bound this decision.

- **A serial driver exists, and it only writes.** `components/services/uart16550-driver` and
  `components/lib/src/uart16550.rs` drive a 16550 UART with bounded polled transmit. The `serial-device/v1` contract has
  one operation, `OP_WRITE`, with at most 52 payload bytes. Nothing reads a byte from a line.
- **No TLS stack exists.** [`network-data-plane.md`](../plans/network-data-plane.md) states that its obligations do not qualify TLS.

## What upstream eclipse-zenoh 1.0.0 does

The observations below come from the upstream sources at tag `1.0.0` and from `z-serial` 0.2.3.

| Link | Framing on the line | Frame bound | Feature in the default wheel build |
| --- | --- | --- | --- |
| `tcp` | Zenoh's 2-byte length prefix | 65535 bytes | yes |
| `tls` | The same prefix inside a TLS stream | 65535 bytes | yes (`transport_tls`) |
| `serial` | `z-serial`: COBS with sentinel `0x00`, a length field, the data, a CRC32 | 1500 bytes (`MAX_MTU`) | no |

The pinned `eclipse-zenoh==1.0.0` wheel that the existing exams use lists `transport_quic`, `transport_tcp`,
`transport_tls`, `transport_udp`, `transport_unixsock-stream` and `transport_ws` in its `default` features. It does not
list `transport_serial`. That feature exists in `zenoh` 1.0.0 and must be built in.

A serial line is not a byte stream for Zenoh. The `z-serial` frame replaces the length prefix. A serial link therefore
needs its own framer beside `StreamFramerOf`, and the framer must be judged against `z-serial` bytes.

## Decision

Add two link transports, in this order. Each is its own slice with its own exam.

1. **TLS over TCP first, as a client.** The guest connects out as a TLS client to a stock listener and carries the
   same Profile 0 session inside the stream. The session and `Link` do not change.
2. **Serial second, one line, one peer.** A new `ByteLink` over a serial line carries one Profile 0 session. A new framer
   implements the `z-serial` frame: COBS with sentinel `0x00`, a length field, the data and a CRC32, at most 1500 data
   bytes. A frame with a bad CRC, a bad COBS run or a wrong length is dropped and counted, never delivered.

The owner chose TLS first. The first TLS work item settles the dependency risk. The serial slice does not wait on a
failed TLS check. The owner dropped vsock: this record plans no vsock link.

### TLS over TCP

- **The stack is a pinned dependency.** The candidate is `rustls` with a `no_std`-capable provider, as upstream 1.0.0 uses
  `rustls` 0.23.13. The work item must show that the dependency builds `no_std` on the target and passes `just deny`. It must
  also show that the dependency stays out of every closure that does not use it. If any of these fails, this slice
  stops and the record is revised.
- **Entropy comes from a granted capability.** The handshake needs random bytes. It takes them from `entropy-service`. A
  holder with no entropy grant cannot open a TLS link.
- **The validation time is fixed by the generation.** The repository has no calendar-time source. `clock-authority/v2`
  grants timers and simulated time, and a monotonic read measures time since boot. The generation therefore declares one
  time, and the link checks each certificate's validity window against it. A certificate that expired after that time is
  still accepted until a new generation declares a later time. A calendar-time source is the proper fix, and it is a
  separate decision.
- **Trust is declared by the generation.** The generation names the trust anchor and, for mutual TLS, the client
  certificate and key. The key crosses a process boundary only as a granted object, never as a path. The record format is a
  Zutai schema under `contracts/`.
- **The server name is checked.** The link refuses a certificate whose name does not match the destination row. Upstream
  checks it by default (`verify_name_on_connect`), and so does this link.
- **TLS 1.3 only.** The link refuses older versions. One version keeps the exam's refusal set small.
- **The stock peer is the pinned wheel.** `transport_tls` is in the wheel's default features. The exam keeps one stock
  listener on a host TLS endpoint, with a certificate that the exam generates and discards.

### Serial

- **The read path is new.** The UART driver must receive bytes into a bounded ring. A receive overrun is counted and the
  affected frame is dropped by the framer. The driver never waits without a deadline, as `uart16550.rs` already holds for transmit.
- **The line is a capability, not ambient.** A composition grants one holder one serial device with `read` and `write`
  rights. The grant follows `serial-device/v1` and extends it in a new version. The wire contract stays a Zutai schema.
  An existing `serial-device/v1` operation does not change.
- **The console and the link do not share a line.** A composition that grants the line to the Zenoh holder grants it to no
  console writer.
- **The framer is judged from upstream bytes.** The exam reproduces frames that `z-serial` 0.2.3 wrote, byte for byte,
  and decodes frames the Rust framer wrote with `z-serial`. A host reference in Python reproduces the same bytes first,
  as `scripts/lib/zenoh_wire.py` does for the codec.
- **The stock peer is built from source.** The peer is `zenoh` 1.0.0 built with `transport_serial`, pinned by hash. It lives
  in a standalone crate outside the root workspace, as `verification/zenoh-xcheck` does. QEMU exposes the guest's UART
  as a host pseudo-terminal for that peer.
- **Fixed mode only.** A serial frame holds at most 1500 bytes. A link on a serial line takes the fixed mode of
  `zenoh-link-limits/v1`, with a batch of at most 1500 bytes. The heap mode and FRAGMENT stay refused on that link.

### Both slices

- **The session is unchanged.** The session machine takes no I/O and holds no transport. A new transport adds a
  `ByteLink` and, for serial, a framer. A change to `zenoh_profile0/session.rs` is out of scope.
- **Authority is exact.** Each transport has its own grant row shape in the system spec. The derived manifest is judged
  before QEMU starts, as `sel4-zenoh-external` is.
- **Every positive assertion has a negative control.** The verification rules require it for a product judge.
- **The architecture page changes with the implementation.** `docs/architecture/zenoh-transport.md` states one TCP
  connection today. The implementation PR for each slice updates its boundary and its limitations.

## Alternatives

- **Serial as a plain byte stream with the 2-byte prefix.** It needs no new framer. A stock `z-serial` peer cannot read it,
  and one lost byte desynchronizes the stream with no way to recover. Rejected.
- **vsock.** It reuses `StreamFramerOf` but needs a new virtio driver. The owner dropped it.
- **TLS terminated in a separate service.** The guest holds no key and speaks plain TCP to a TLS terminator. This moves
  the trust boundary to a new component and leaves the wire between the two unprotected. Rejected for the first slice.
- **QUIC and UDP.** Each needs UDP in the network service, which its page lists as not implemented. Out of scope.
- **Change the pinned wheel.** A new wheel hash re-stales every closure that names it, and no 1.0.0 wheel contains the
  serial feature. Rejected.

## Consequences

- The TLS slice may not be possible without a new dependency. Its first work item decides that, before any other TLS work.
- The serial slice needs three new things: a UART receive path, a framer, and a source-built stock peer. Only the
  framer is Rust codec work.
- If the TLS dependency check fails, the serial slice still proceeds, because the two slices share no code.
- The two slices share no code beyond `ByteLink`, so either can land alone.
- A TLS link carries Zenoh keys and samples under a confidentiality claim for the first time. The exam must judge from a
  capture that the stream holds no Zenoh plaintext.

## Not observed

- No exam has run for either slice.
- The `is_reliable` value that upstream returns for `serial` was not read, so the effect of a lossy line on `FRAME`
  reliability is unresolved. The serial work item must settle it before any claim about delivery.
- Whether `zenoh` 1.0.0 with `transport_serial` accepts a pseudo-terminal that QEMU exposes was not tried.
- Whether `rustls` builds `no_std` for the seL4 target was not tried.

## Revisit when

- the network service carries UDP, which reopens QUIC and a datagram Zenoh link;
- a calendar-time source lands, which replaces the fixed validation time;
- the TLS dependency check fails, which stops the TLS slice and leaves serial as the only slice.

## References

- [`zenoh-profile0-transport.md`](zenoh-profile0-transport.md), [`zenoh-link-limits.md`](zenoh-link-limits.md),
  [`zenoh-external-listener.md`](zenoh-external-listener.md)
- [`../architecture/zenoh-transport.md`](../architecture/zenoh-transport.md)
- [`../../components/lib/src/uart16550.rs`](../../components/lib/src/uart16550.rs),
  [`../../components/proto/src/serial_device.rs`](../../components/proto/src/serial_device.rs)
