# M5 and M6 retained requirements

This plan owns the M5 and M6 milestone requirements that are not confirmed as
covered by a gate. M5.7 is not implemented. It needs a physical Framework
observation. Each other section names a milestone whose gate exists. This page
keeps the section because one or more of its required checks is not confirmed
against that gate. `docs/architecture/` and the owning contracts state current
behavior. Work-item state lives in `.tasks/items/`.

## Invariants carried forward

- The kernel supplies privileged mechanism, not service policy: address spaces, memory objects, capability enforcement, IPC, scheduling, interrupts, timers, and minimal platform control.
- Components receive only manifest-declared capabilities. Transfers and derivations can narrow authority but never widen it.
- Protocols and persistent formats are versioned, bounded, deterministically encoded, and reject unknown required versions or flags.
- Executable objects are immutable and content-verified before execution. Boot state, generation roots, and state roots remain separate concepts.
- QEMU establishes deterministic logic, bounded error handling, and fault recovery. It does **not** establish physical firmware behavior, DMA containment, device identity, power-loss behavior, or absence of writes on any named hardware target. Milk-V Duo evidence is likewise target-specific and cannot establish Framework storage behavior.
- **Internal Framework NVMe writes remain disabled.** Neither recovery media nor a storage-aware generation receives internal-NVMe write authority by default. No such write path may be enabled until all M5.7 promotion gates and the later Framework hardware reliability gate have physical evidence; Duo storage or component evidence cannot substitute.

## M5 — Storage and generations

**Depends on:** M1–M4.

**Authority and safety boundary:** Storage clients use a block-service endpoint plus bounded shared memory. A trusted driver receives explicit PCI-function, DMA-memory, interrupt, and shared-memory capabilities. The kernel enforces rights, mappings, DMA-buffer lifetime, and interrupt delivery; the userspace service owns partition policy, retries, and access control. There are no ambient block syscalls or guessed global device names. Before IOMMU enforcement, DMA-capable drivers remain trusted and writes are restricted to deterministic QEMU fixtures or dedicated replaceable test devices.

### M5.1 — Storage capability foundation

**Depends on:** M2 and M4 platform/capability foundations.

**Required checks:** Reject missing, widened, duplicate, stale, out-of-range, and wrong-kind capabilities; prevent reclaim of in-flight DMA buffers; reject malformed PCI metadata without hanging.

**Exit condition:** An isolated driver receives only explicitly granted generic resources, and an unprivileged component cannot acquire device rights.

### M5.2a — Typed IPC schemas

**Depends on:** M5.1's block protocol.

**Required checks:** Round-trip every message type byte-identically on both ends and reject stale bindings and out-of-bounds fields.

**Exit condition:** The M5.2 block protocol has one schema-first layout under `contracts/`, with no disagreeing hand-written representation.

### M5.2 — Read-only virtio block vertical slice

**Depends on:** M5.1 and M5.2a.

**Required checks:** Verify the known sector through the full component/capability path; reject writes, out-of-range LBAs, short buffers, invalid descriptors, unsupported features, and timeouts with structured errors; contain driver failure; keep the generation slice healthy.

**Exit condition:** A userspace component reads and verifies a read-only QEMU virtio device without ambient storage authority.

### M5.3 — Durable virtio writes and fault handling

**Depends on:** M5.2.

**Required checks:** Verify write/read-back and fresh-boot persistence; leave images unchanged on out-of-bounds writes; reclaim descriptors and pins after errors; never report failed flush as durable; never reuse stale completions after reset.

**Exit condition:** Disposable QEMU images provide bounded, explicitly authorized durable writes and deterministic recovery from injected failures.

### M5.4 — GPT and integrity-checked object store

**Depends on:** M5.3.

**Required checks:** Validate GPT bounds and CRCs; resolve copy damage without accepting conflicting valid copies; prevent malformed metadata from causing out-of-bounds I/O; verify complete payload hashes before use; preserve the previous root at every append/commit interruption; reject overlap, overflow, truncation, bad hashes, conflicting identities, and unsupported versions.

**Exit condition:** QEMU retrieves immutable content-addressed objects from a bounded GPT partition while malformed and partial commits fail closed.

### M5.6 — Pending, known-good, rollback, state policy, and GC

**Depends on:** M5.6a and M5.6b; their semantics are the implementation contract.

**Required checks:** Inject interruption before pending metadata, during either slot write, after pending commit, after attempt commit/before candidate read, during promotion, rollback update, state snapshot, and GC. Every reboot selects either pending with the correct reduced attempt count or verified known-good, never zero roots. Distinguish component exit, fault, timeout, peer loss, and explicit unhealthy status; deny health confirmation to unprivileged components.

**Exit condition:** A failing pending generation automatically returns to verified known-good with persistent state and roots matching declared policy.

### M5.7 — Framework NVMe transport and safety promotion

**Depends on:** M5.1–M5.6c, M4's historical removable-media safety invariant, the [Framework CPU-boot observation and current image-binding limitation](../architecture/targets-and-portability.md#automated-and-physical-evidence), H1's observed inventory, H2's exact PCI binding, and H4's AMD-IOMMU containment.

**Still required:** After P6.6 has proven the no-storage product boot, implement the NVMe transport behind the seL4 userspace-driver boundary using H1's observed controller/namespace identity, H2-bound PCI/MMIO/IRQ resources, H4 DMA containment, and IO2's `BlockDevice` contract; then observe a storage-aware removable-media Framework boot without modifying internal NVMe. Destructive writes and interruption experiments may run only on a dedicated replaceable external test device.

**Promotion gates before any internal NVMe write may be enabled:** deterministic bounds and malformed-command tests; DMA isolation suitable for the physical target; timeout/reset recovery; flush ordering and durable-write tests; interrupted metadata and generation-transition tests; malformed GPT/object-store/generation/BootState tests; an explicit write capability held only by the intended service; and an operator-visible distinction between removable test media and internal NVMe. Production IOMMU enforcement and internal-disk promotion remain a later hardware reliability gate.

QEMU, Milk-V Duo, or another board cannot replace the required Framework observation.

**Exit condition:** Starting from the P6.6/H1-proven no-write boot path, a physical Framework runs the storage-aware isolated slice over the common protocol while internal NVMe writes remain disabled unless every physical promotion gate has been observed.

### M5.9 — Recovery, scrub, and BootState reconstruction

**Depends on:** M5.4–M5.8.

**Required checks:** Never execute an unverified object after dual-slot corruption; reconstruct one disposable QEMU disk while a second ungranted disk remains byte-identical; reject missing state, broken closure, unauthorized releases, and interrupted incomplete reconstruction; retain the Framework removable-media no-write gate.

**Exit condition:** Signed removable recovery reconstructs a verified bootable root without modifying any device not named by an explicit capability.

M5 closes only after M5.7's physical observation. At that point all executable content must verify before execution; staging must preserve running/known-good; attempts must commit before candidate bytes are read, decoded, or launched; confirmation must apply only to the running pending generation; interruption must preserve a valid slot; checked traces must match the state/GC models; failure must return to known-good; GC must preserve every retained root; every state policy must have upgrade/rollback evidence; read/write authority must be explicit; malformed metadata must fail before out-of-bounds I/O or execution; releases and recovery must preserve local rollback and capability isolation; and the Framework storage-aware observation must show no unauthorized internal-NVMe write.

## M6 — Native interactive environment

**Depends on:** M1–M5 storage, object-store, generation, state-policy, rollback, release-trust, and recovery mechanisms. M6 acceptance is QEMU/removable-media evidence and remains independent of pending M5.7 physical verification. Internal NVMe writes remain disabled.

### M6.2 — Spawn service and command profile

**Depends on:** M6.1.

**Required checks:** Byte-identical schema round trips and bounded-version rejection; deny undeclared executables, budget excess, and code injection; deterministic resolution; contain spawn-service failure.

**Exit condition:** A client resolves a profile command and launches it with exactly the declared grants.

### M6.3 — Filesystem service and directory capabilities

**Depends on:** M6.1 and M5.4.

**Required checks:** Deny name access without a directory capability; restrict derivation by subdirectory and rights; preserve the previous root across interruption; enforce path, entry-count, and depth bounds before store I/O.

**Exit condition:** Components browse and mutate namespaces only through explicit directory capabilities with store-verified metadata.

### M6.4 — Minimal Dango implementation and core runtime

Slisp is the resident shell today
([README](../../README.md#slisp-native-interactive-language)). `slime-root` and the
system-spec schema describe Dango as retired. `just dango_check` is a
compatibility alias of `just slisp_core_check`. No record states whether the
M6.4 checks now bind Slisp. A human decides whether M6.4 applies to Slisp or
closes.

**Depends on:** M6.2 and M6.3.

Full Hindley–Milner, row-polymorphism, and effect inference are outside this slice.

**Required checks:** Trace each launch to profile resolution and a spawn request; leak no ambient context; preserve termination distinctions at the language boundary; reproduce scripted sessions deterministically.

**Exit condition:** Native console commands run through Dango with capability-resolved authority and structured failures.

### M6.5 — Generation inspection and update commands

**Depends on:** M5.6c, M5.8, and M6.1–M6.2.

**Required checks:** Match deterministic manifest/store inspection; fail before BootState changes on missing objects or invalid release; validate select/rollback traces against M5.6 models; deny update operations to unprivileged components.

**Exit condition:** Native components inspect, stage, select, and roll back generations using only manifest-declared authority.
