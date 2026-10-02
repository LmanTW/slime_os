# Decisions

This directory owns important long-lived cross-module choices whose rationale
must survive any one implementation or review system. It is not a tracker and
not a per-PR diary; canonical work identity, state, hierarchy, dependencies, and
observed exit conditions remain in `.tasks/items/`.

Each decision record states:

- status: `proposed`, `accepted`, or `superseded`;
- context and the decision;
- alternatives and trade-offs;
- consequences and revisit conditions;
- relevant canonical work-item UUIDs and code or contract references.

Moving an old proposal here does not make it accepted. Superseded records remain
readable and link to the decision that replaced them.

## Records

- [Development record ownership](development-record-ownership.md) — accepted;
  separates current knowledge, work state, change evidence, durable rationale,
  and retained history during the repository split.
- [Spec-driven work-item bodies](spec-driven-work-item-bodies.md) — accepted;
  what Slime OS owns once MyQue, devloop, and myque-gh publish the envelope,
  requirements, evidence, and projection contracts it pins.
- [Mandatory spec-driven work items](mandatory-spec-driven-work-items.md) —
  accepted; makes a devloop body compulsory for items created after a fixed
  UUIDv7 cutoff, and scales gate identities through a generic target gate.
- [Adaptive memory guarantee reservation](adaptive-memory-guarantee-reservation.md)
  — accepted; physical reservation ownership, guaranteed mapping, and safe
  admission before adaptive task publication. The record lists the required
  observations; the private-memory adaptive planes are where they are observed.
- [MCS and conserved CPU budgets](mcs-cpu-budgets.md) — proposed; keep
  `KernelIsMCS OFF` (as every pinned profile is today) until one
  target-specific cutover covers API, resources, admission, and assurance.
- [BootState partition layouts](bootstate-partition-layouts.md) — accepted;
  boot-store v1 is the only product BootState layout, and the userspace
  planes' LBA 1024/1025 object-store layout is test scaffolding until the
  manager stages into a boot store.
- [Entropy authority](entropy-authority.md) — proposed; a userspace
  entropy-service over a virtio-rng driver, with generation-declared holders,
  per-holder HMAC-DRBG output and reproducible seeded fixtures.
- [AMD IOMMU ownership on x86-64](amd-iommu-ownership.md) — proposed; seL4
  supports only Intel VT-d, so `slime-root` programs the AMD IOMMU behind IO1's
  existing DMA mediation instead of extending the kernel.
- [Instance lifetime](instance-lifetime.md) — accepted; a composition declares
  an instance `resident` or `bounded`, and the root treats a resident
  instance's exit as a failure rather than as completion.
- [Zenoh Profile 0 transport](zenoh-profile0-transport.md) — proposed; R0's
  two-node exchange as six slices, each judged from evidence its implementation
  did not write: an independent wire reference proved against the upstream
  corpus, mutation-tested judges, and a QEMU arm in the network plane checker.
