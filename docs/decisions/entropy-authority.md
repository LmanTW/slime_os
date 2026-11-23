# Entropy authority

**Status:** Accepted
**Related work items:** `01a0ec3a-a91f-7349-a28a-26a60d8d7f4e`,
`01a0724c-5400-76b9-a691-989205b9a2a4` (D3)

## Context

No component can obtain entropy through a capability. The network service's
resolver needs 32 bytes of fresh launch entropy for DNS query identifiers and
source ports, and today those bytes are typed into the serial input by the host
checker (`scripts/check/check-sel4-io-network-plane.py`, `http_launch_text`).
Hostname resolution therefore cannot be offered on a product composition.

D3's [deterministic-component authority](../plans/native-development.md#deterministic-component-authority)
left the mechanism open: a kernel-pool entropy object, or a per-spawn seeded
stream minted by the spawner. It also required that a seeded fixture use the
same rights as a real source, so a test generation changes wiring rather than
component bytes.

Platform facts:

- The pinned AArch64 QEMU CPU is `cortex-a53` (`sel4/pins.toml`), which has no
  `RNDR`. Changing the CPU pin would move every plane.
- QEMU `virt` offers `virtio-rng-device` on a virtio-mmio transport (device
  id 4). `components/lib/src/virtio_mmio.rs` already provides the mediated
  transport, and the io-resource authority that `virtio-net-driver` holds
  covers such a driver.
- pc99 QEMU (`virtio_mmio_count = 0`) and the Framework 13 have `RDRAND`, but no
  device path is qualified there.

## Decision

Entropy is a userspace service with generation-declared authority, split like
the network path into a driver and a service.

- **`virtio-rng-driver`** holds io-resource authority for one virtio-rng
  transport and hands raw bytes to exactly one declared consumer through
  `entropy-source/v1`. It knows nothing about holders.
- **`entropy-service`** is that consumer. It reads the generation's
  `entropy-authority/v1` table through a root-served, read-only query, the same
  shape as the network destination and application tables. A row names a
  holder, a source (`hardware` or `seeded`), a byte budget, and for a seeded
  row a 32-byte seed. Omission is denial.
- **Holders** draw 1–32 bytes per request through `entropy-service/v1` on a
  per-holder endpoint that the generation declares non-transferable. Hardware
  and seeded holders use one operation and one set of rights.
- **Output** is HMAC-DRBG over SHA-256 (NIST SP 800-90A), with one instance per
  holder personalised by `slime-entropy/v1:` plus the holder name.
  - A hardware instance is seeded with 32 bytes of device entropy and a 16-byte
    device nonce, and reseeds from the device at least every 64 draws.
  - A seeded instance uses the declared seed and an empty nonce and never
    reseeds, so its stream is reproducible from generation data alone.
  - Raw device bytes never reach a holder.
- **Failure is closed.** Without the device, hardware draws answer
  `unavailable`. They are never replaced by a seeded, constant or cached
  stream, and seeded holders keep being served.

`slime-root` gains only the table query. The driver/service split keeps device
semantics out of the root, and a later `RDRAND` or physical source replaces the
driver without changing the service or its holders.

The binding rule is fixed by the generation builder: a holder's endpoint is the
grant `<holder>-entropy` from the holder to `entropy-service`, with exactly
`send` and `recv`, not transferable, and every row has exactly one. An endpoint
to `entropy-service` from an instance without a row, or under another name, is
refused at admission, so a component with no row cannot resolve an entropy
binding. The root serves the table through `CAPABILITY ENTROPY AUTHORITY READ`
(label 74) only to the instance named `entropy-service`. Since PR 1117 the
builder states that name in the generation's reader table, and the root holds
none ([declared table readers](../architecture/runtime-authority.md#declared-table-readers)).

Residency is a placement fact ([instance lifetime](instance-lifetime.md)), not
part of this decision. The `sel4-entropy` qualification composition declares
every instance bounded: the service exits once every holder has closed and then
releases the driver, so the graph reaches `live=0`. A product composition that
needs a standing service declares it `resident`.

## Alternatives and trade-offs

- **A root-served entropy object kind**, like clock authority. The root would
  own the device or the instruction, and the capability matrix would gain a
  kind and rights. Rejected: the root would take on device semantics that
  `io-substrate.md` keeps in userspace, and a seeded fixture would still need
  a second mechanism.
- **A per-spawn seeded stream minted by the spawner.** This is deterministic and
  replay-friendly, but it only moves the question of where the spawner's
  entropy comes from, and the stream would be tied to spawn-service instead of
  to generation authority.
- **Passing raw device bytes to hardware holders**, with a DRBG only for seeded
  holders. Simpler, but the two sources would behave differently, holders would
  see the device's raw output, and the host could not reproduce a seeded holder
  through the same algorithm.
- **Changing the QEMU CPU pin to one with `RNDR`.** Rejected: it moves every
  plane's CPU for one feature and still leaves physical targets unqualified.
- **Keeping the checker-typed launch seed.** Rejected as a product answer: it
  makes the host the entropy source and cannot serve a resident shell.

## Consequences

- The seed for a seeded holder is generation data. It is not secret, and a
  composition that uses one for a production purpose is broken by construction.
  Only test and fixture compositions should declare seeded rows.
- D3 keeps the rule that a component declared deterministic receives no real
  source, including through later transfer, and keeps replay recording of
  drawn entropy. This decision supplies what that rule governs:
  non-transferable endpoints and table-declared rows.
- Moving the network service's resolver from the launch seed to an entropy
  grant is separate work. Until it lands, hostname URLs stay unavailable on
  `sel4-net`.
- The quality of QEMU's backend is the host's. Qualification proves authority,
  isolation, budgets, fail-closed behaviour and reproducibility, not
  cryptographic strength.

## Revisit conditions

Revisit if a qualified physical target offers an instruction source that would
make a driver component pure overhead, or if D3's replay design needs drawn
bytes recorded at the service rather than at each holder. Also revisit if the
per-holder DRBG state or the 32-byte request bound proves too small for a real
consumer.

## References

- `contracts/entropy-authority/v1/`, `contracts/entropy-source/v1/`,
  `contracts/entropy-service/v1/`, `boot-contracts/src/entropy_authority.rs`
- `components/services/virtio-rng-driver/`,
  `components/services/entropy-service/`, `components/lib/src/hmac_drbg.rs`,
  `components/testkit/entropy-probe/`
- `scripts/build/generation_resources.py` (`build_entropy_authority`),
  `contracts/system-spec/v1/systems/sel4-entropy.zti`,
  `scripts/check/check-sel4-entropy-plane.py`
- `components/lib/src/virtio_mmio.rs`,
  `components/services/virtio-net-driver/`,
  `components/services/network-service/src/resolver.rs`
- `contracts/io-resource/v1/`, `contracts/clock-authority/v1/`,
  `contracts/network-destination/v1/`
- [`../architecture/io-substrate.md`](../architecture/io-substrate.md)
- [`../plans/network-data-plane.md`](../plans/network-data-plane.md)
- `sel4/pins.toml`
