# I/O substrate retained requirements

This plan owns the IO2 and IO3 requirements that their gates do not establish,
and the boundary between the substrate and later device services.
[I/O substrate architecture](../architecture/io-substrate.md) owns current
behavior, including IO0 and IO1.
[Network data plane](network-data-plane.md) owns the open IO4 requirements.
Work-item state lives in `.tasks/items/`.

## IO2 — Userspace virtio-blk and asynchronous BlockDevice plane

**Depends on:** IO0, IO1, and the existing M5/P5 block behavior and QEMU storage gates.

### Deliverables

- preserve the existing schema-first `BlockDevice` semantics — geometry query, read, write, and flush with explicit rights — while extending the protocol only where asynchronous multi-block requests require bounded slices, request identities, epochs, and completions;
- move virtio-blk feature negotiation, queue setup, descriptors, notification/interrupt handling, timeout, reset, and stale-completion logic from `slime-root` into one supervised userspace driver component holding IO1 resources;
- use IO0 request/completion rings and buffer leases for multi-sector operations instead of growing the transfer-window RPC or accepting caller physical addresses;
- preserve capability-selected device identity and the userspace object-store/generation/recovery layers above `BlockDevice`; clients receive no virtio, MMIO, DMA, or IRQ authority;
- retain the current root-mediated one-sector path only during the migration as a behavioral oracle; after read/write/flush, denial, durability, fault, and restart parity are observed, remove the root's virtio-blk command/descriptor implementation from the product path;
- define reset and cancellation so every submitted request reaches one terminal state, every DMA/lease charge returns, and completions from a prior driver epoch are refused;
- preserve deterministic disposable-image tests and the no-physical-safety-claim boundary: IO2 proves QEMU mechanism, not Framework NVMe or internal-storage promotion.

### Required checks

- the plane observes read, write, flush, geometry, rights denial, out-of-range LBA, malformed request, short buffer, unsupported opcode, and same-boot write/flush/readback; fresh-boot durability remains unproved by this gate;
- multiple queued requests complete without overwrite or identity confusion, and a full ring backpressures the caller;
- descriptor failure, timeout, cancellation, reset, interrupt loss/coalescing, driver crash, peer death, supervised restart, and stale-completion injection remain required follow-up evidence rather than completed IO2 claims;
- filesystem, object-store, generation, rollback, and recovery clients still reach storage only through their declared `BlockDevice` capability;
- the product root contains no virtio-blk opcode or descriptor parsing after cutover.

### Planned verification target

```sh
just io_block_check
```

### Exit condition

A userspace virtio-blk driver provides capability-gated block operations through asynchronous bounded buffers and completions, and every block-holding composition uses it; the IO2 plane directly establishes operation/refusal behavior, identity-safe queueing, and backpressure, but does not yet establish the fault/restart/stale-epoch portion of the original exit condition.

## IO3 — Userspace virtio-net and LinkDevice validation

**Depends on:** IO0, IO1, and IO2 as the first complete substrate proof.

### Deliverables

- define a versioned `LinkDevice` service for bounded frame transmit, receive-buffer provisioning, link state, statistics, reset, and close; Ethernet frame meaning remains here rather than in the common queue envelope;
- implement a supervised userspace virtio-net driver over IO1 resources with separate bounded TX/RX queues, replenished RX leases, interrupt/readiness Notifications, feature negotiation, reset, and fresh epochs;
- keep raw link authority confined to the network service and explicit diagnostics; an application with a future `TcpConnection` or `UdpEndpoint` cannot submit arbitrary frames;
- apply IO0 backpressure and lifetime rules to duplex traffic, including RX buffers owned by the device until completion and TX buffers retained through completion/cancellation;
- prove that the same substrate supports continuous readiness and receive replenishment without adding block-only or network-only operations to `slime-root` or IO0/IO1;
- expose backend-independent `LinkDevice` behavior so Framework USB Ethernet and Wi-Fi can attach later without changing the network-service client ABI.

### Required checks

- a component without `LinkDevice` authority cannot transmit, receive, query link state, or obtain raw frames;
- malformed virtio descriptors, oversized/short frames, exhausted RX replenishment, TX saturation, interrupt coalescing, link reset, and driver crash remain within declared bounds;
- full TX queues backpressure, exhausted RX buffers drop or pause according to the declared policy, and neither path overwrites live data;
- restart returns every DMA/lease charge, creates a fresh epoch, and rejects stale TX/RX completions;
- deterministic QEMU fixtures transmit allowed frames and prove denied/raw access produces no packet;
- no IP, DNS, UDP, TCP, or destination-authority policy enters the driver or root.

### Planned verification target

```sh
just io_link_check
```

### Exit condition

A userspace virtio-net driver exposes one bounded `LinkDevice` with duplex queueing, readiness, reset, and restart behavior over the same IO0/IO1 substrate as virtio-blk, without widening raw-packet authority or introducing device-specific root logic.

## Consumption by later subsystems

Later milestones reuse the substrate but retain their own semantics:

```text
BlockDevice   = typed block control + IO0 buffers/completions
TcpConnection = typed stream control + bounded stream queues/readiness
UsbEndpoint   = typed USB transfer/completion payloads over IO0
AudioStream   = typed format/control + PCM ring + period/xrun events
DisplaySurface = typed surface/presentation + bounded shared images
GpuQueue      = typed GPU submits + buffer objects + fences
```

This table is a boundary, not a promise that the protocols are interchangeable. USB descriptors remain H3/USB-service work; input/seat semantics remain H3/H11; audio formats and mixer policy remain H11; surface/focus/presentation remain H8; Radeon command validation remains H13; general accelerator compute authority remains A3.
