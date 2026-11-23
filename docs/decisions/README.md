# Decisions

This directory owns important long-lived cross-module choices whose rationale
must survive any one implementation or review system. It is not a tracker and
not a per-PR diary; canonical work identity, state, hierarchy, dependencies, and
observed exit conditions remain in `.tasks/items/` and on the `evidence` branch.

Each decision record states:

- status: `proposed`, `accepted`, or `superseded`;
- context and the decision;
- alternatives and trade-offs;
- consequences and revisit conditions;
- relevant canonical work-item UUIDs and code or contract references.

Moving an old proposal here does not make it accepted. Superseded records remain
readable and link to the decision that replaced them.

## Records

- [Large component image bounds](large-image-bounds.md) — accepted; retain
  component v2 and generation v5 layouts while widening bounded embedded images
  on the exact aarch64 QEMU target.

- [Development record ownership](development-record-ownership.md) — accepted;
  separates current knowledge, work state, change evidence, durable rationale,
  and retained history during the repository split.
- [Spec-driven work-item bodies](spec-driven-work-item-bodies.md) —
  superseded by [Work-item devloop v1.5](work-item-devloop.md); what Slime OS
  owned while MyQue, devloop, and myque-gh published the envelope,
  requirements, evidence, and projection contracts it pinned.
- [Work items are not projected into GitHub Issues](no-github-issue-projection.md)
  — accepted; `.tasks/` is the only work-item surface, and the Issue projection
  workflow is retired after it duplicated 468 Issues during a GitHub outage.
- [Work-item devloop v1.5](work-item-devloop.md) — accepted; keeps V1's
  stages and pull-request classes, moves evidence to a signed `evidence`
  branch keyed by closure digests, judges pull requests from the base
  commit, and supersedes the two spec-driven records.
- [Mandatory spec-driven work items](mandatory-spec-driven-work-items.md) —
  superseded by [Work-item devloop v1.5](work-item-devloop.md); made a devloop
  body compulsory for items created after a fixed UUIDv7 cutoff, and scaled
  gate identities through a generic target gate.
- [Negative controls for product judges](negative-controls-for-product-judges.md)
  — accepted; a negative control is required for every assertion about Slime OS
  itself, and not for assertions about verification or process tooling.
- [Planning PRs may fix the Zutai schema a grader binds to](planning-pr-schema-contracts.md)
  — proposed; a new `contracts/<name>/v<N>/schema.zt` is an interface a
  planning pull request may land with its exam, while generators, bindings,
  system specs, and modified schemas stay product.
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
- [Monotonic clock reads are ambient](ambient-clock-reads.md) — accepted;
  `clock-authority/v2` retires the monotonic read right, and AArch64
  components read the counter without a root round trip.
- [Entropy authority](entropy-authority.md) — accepted; a userspace
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
- [Zenoh Profile 0 and a stock Zenoh peer](zenoh-stock-peer.md) — proposed;
  what a captured eclipse-zenoh 1.0.0 peer sends that Profile 0 refuses (an optional
  QoS extension, OAM and DeclareFinal, a key-expression alias, keep-alives), the four
  bounded changes that would take it, and what the capture did not cover.
- [Zenoh Profile 0 links declared by a named configuration](zenoh-link-limits.md) — proposed;
  a link declared in a fixed mode with no heap or a heap mode where the component supplies the
  storage a fragmented message is reassembled into, judged by a contract that sets no size of its
  own, against the fragments a stock eclipse-zenoh 1.0.0 peer wrote.
- [Zenoh Profile 0 guest connecting out to a stock listener](zenoh-external-listener.md) —
  proposed; the guest opens one TCP connection over a NIC to a stock eclipse-zenoh 1.0.0
  listener on the host, judged from the listener's own record, a packet capture and the host
  wire reference, with the composition and guest left to the implementation.
- [A shared Zenoh service component](zenoh-service.md) — proposed; one component owns the Zenoh
  link and session and serves local holders through per-holder key grants. It does not depend on
  the fabric. The session's limit of one subscription of its own is the first obstacle.
- [Zenoh Profile 0 taking a stock peer's undeclaration](zenoh-stock-undeclare.md) — proposed;
  the one batch the stock-peer exam did not capture, an `UndeclareSubscriber` that names the
  subscriber by id alone behind the network QoS extension, taken by the session by id and
  nothing wider, with ten variants it keeps refusing by name and class.
- [Zenoh links over TLS and over a serial line](zenoh-link-transports.md) — proposed;
  a TLS 1.3 client link over TCP first, then a `z-serial` framed link over a UART, each judged
  against a stock peer, with the session left unchanged and vsock dropped.
- [System-image closures commit sources, not in-tree digests](system-image-closures-as-derivations.md) —
  proposed; closures record locators, each checkout computes their identities, and attestations
  live in git notes.
- [Root task scope](root-task-scope.md) — accepted; the root keeps a role only
  for authority no component may hold or for work before the first component.
  The policy and timer roles stay since the amendment of 2026-11-22, and the
  console dispatcher stays until a design moves it. The ioResource and
  sharedBuffer roles stay since the amendment of 2026-11-23: stage two is
  withdrawn, and the gate's ceilings replace the target in lines.
- [Verified kernel profile](verified-kernel-profile.md) — accepted; no target
  profile claims the verified kernel configuration today, and only a new
  `bcm2712-rpi5-verified` profile may, under three gates and one wording.
- [Independent review](independent-review.md) — accepted, not yet implemented;
  every pull request but a closeout needs an approval from another owner or a
  review-agent verdict with no blocking finding, the same review satisfies V4,
  and nobody merges over a red judge.
