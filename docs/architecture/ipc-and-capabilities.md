# IPC and capability movement

## Ownership

seL4 owns Endpoint and Notification rendezvous, blocking, badges, reply pairing,
and kernel capability transfer. `slime-root` creates the generation-declared
objects, installs narrowed capabilities, authenticates root-service callers by
endpoint badge, validates operations, and reclaims root-owned resources. It does
not broker ordinary component-to-component messages.

Current owners:

- native endpoints and lifetime: `slime-root/src/peer_endpoint.rs`;
- root operation dispatch and the 64-byte message bound:
  `slime-root/src/ipc.rs` and `components/runtime/src/syscall/`;
- authority and slot installation: `slime-root/src/generation.rs`,
  `slime-root/src/graph.rs`, and `slime-root/src/graph_runtime.rs`;
- kinds, rights, and gates: [`../capability-matrix.md`](../capability-matrix.md);
- operation numbers and packing: [`../syscall-abi.md`](../syscall-abi.md).

## Two communication paths

### Native component IPC

A `SystemSpec` declares an authority edge; generation construction turns that
edge into a native Endpoint and gives each participant only its declared side.
Send-only, receive-only, and bidirectional grants remain distinct. A component
cannot discover or create a new peer edge at runtime, and names in payload bytes
grant nothing.

The root leaves the data path after construction. Kernel rendezvous supplies
backpressure, and one message carries at most one capability. The current
payload limit is 64 bytes per message. Larger payloads use a descriptor plus a
shared-buffer loan rather than widening IPC.

### Root-served mechanism calls

Lifecycle, spawn, supervision, transfer bookkeeping, shared-buffer operations,
clock operations, hardware-resource mediation, input, directories, and debug
output are bounded root calls. The root authenticates the caller from the badged
service endpoint before reading caller-controlled operands. Storage and network
payloads are not root protocols: their userspace drivers and services use the I/O
substrate described in [`io-substrate.md`](io-substrate.md).

Unknown operation labels are refused. Missing capability, wrong kind, and
insufficient rights intentionally share a coarse denial so a caller cannot map
authority by comparing detailed errors.

## Capability movement

Derivation and spawn grants retain their source and may only narrow rights.
Consuming transfer differs by capability representation:

- For a root-owned logical capability, export reserves the receiver-bound move,
  finalize commits it **before** descriptor rendezvous, and receiver import
  installs the finalized authority. Import refuses an unfinalized export.
- For a native Endpoint, the message carries a real kernel capability ticket;
  the sender finalizes after successful rendezvous, and the receiver needs no
  logical import.
- Cancel is allowed only before finalize. For a consuming logical export it
  returns the reserved capability at its exported (possibly narrowed) rights
  into a free sender slot; it does not restore the original slot or wider rights.

The ordering is implemented by `capability_delegate` in
`components/runtime/src/syscall/sel4_transport.rs` and the export/import/cancel
handlers in `slime-root/src/graph_runtime/services/capability.rs`. These owners
take precedence over the retained capability matrix's older cancellation prose.

The root authenticates object kind and rights from call operands, never from the
descriptor bytes. Only `Endpoint`, `SharedBuffer`, `Loan`, `Supervision`, and
`Directory` are transferable. Executables and factories reach children only
through generation or spawn grants.

The capability-transfer protocol is declared under
`contracts/capability-transfer/v1/`. Transferability and every rights ceiling are
checked against the vocabulary generated from `contracts/generation/v5/`.

## Checked rights algebra

The normative [bounded model](../../contracts/capability-rights/model/capability-rights.zt)
covers `derive`, `spawnGrant`, `export`, `finalize`, `import`, and `cancel`.
Derive and spawn grants share a non-consuming narrow-only rule; consuming
transfer stages rights no wider than its source and permits cancellation only
before finalization. Cancellation restores the exported rights, not a wider grant.

Its state-safety properties are `DeriveOnlyNarrows`, `TransferOnlyNarrows`,
`TransferRequiresTransferRight`, `TransferFollowsDeclaredEdge`,
`RightsValidForKind`, `NoTransferDuplication`, and `NoAuthorityWidening`.
The last is a weaker edge-scoped closure corollary, not a substitute for the
per-operation conservation laws. Six mutation scenarios require violations of
the first six properties: widening derive/transfer, missing transfer authority,
undeclared edges, kind-blind derivation, and duplicate installation at finalize.
`just capability_rights_model_check` checks the model and is included in
generation-contract validation; this is a bounded specification, not a runtime
refinement proof.

The boundary is three components, one object, and four symbolic rights:
transfer authority, two independently narrowable same-kind rights, and a
foreign-kind right. These are equivalence classes, not a second copy of the
[canonical rights vocabulary](../../contracts/generation/v5/vocab/rights.zt).
The abstraction is documented rather than machine-checked. In particular:

- `retain=true` non-consuming exports are outside the model;
- descriptor and native-endpoint ticket movement is collapsed into a pending
  record, not a model of the two runtime rendezvous orderings above;
- native Endpoint transferability is held in `PeerEndpointTable`, not endpoint
  rights bits; the model abstracts it as retaining or dropping `#transfer`.

Changes to `rightBits`, `capability_rights_valid`, or a `rights_type!` `VALID`
mask must land in the same commit as resulting model and capability-matrix
updates. The vocabulary partition in `boot-contracts/src/generation.rs` checks
manifest admission and rejection against `capability_rights_valid` and requires
their union to equal `RIGHT_ALL`, so a new unclassified bit cannot silently drift.
The [capability matrix](../capability-matrix.md) owns the current enforcement
classification; historical vocabulary counts and ungated-right lists are not
current authority.

Original measurements, counterexample discovery, and promotion evidence live in
[archived direction 24](https://git.justaslime.dev/iceice666/slime_os-history/src/commit/45ed1745907b2d0a13fdf70c8b34eb635bed5f23/docs/directions/24-rights-algebra-model.md),
not in this current boundary.

## Shared buffers and loans

`slime-root/src/shared_buffer.rs` owns a bounded table of page-backed shared
objects, mappings, and receiver-bound loans. Creation requires a
`SharedBufferFactory` grant and a per-holder generation budget. Mapping and loan
charges are separate. Mappings request data-page attributes; execute-never is enforced
on AArch64/RISC-V, but not expressible through the current x86-64 seL4 mapping
API. See [target limitations](targets-and-portability.md).

Mapping accepts only page-aligned exact-frame ranges wholly within the buffer or
loan. Invalid base, offset, length, arithmetic overflow, and lifecycle misuse are
rejected before any page-table entry changes; a partial installation is fully
unwound. Sealing downgrades every live writable page-table entry before publishing
the irreversible read-only state; it cannot be bypassed to recover write access.

A loan names an exact subrange and receiver. Releasing a creator cannot free
pages still retained by a live loan; final return settles the last reference.
Task death, supervised restart, release, and revocation reclaim the affected
subtree's mappings, pages, and charges without disturbing another holder.

Shared-buffer admission checks current page/count charges and descriptor space
before acquiring physical frames. Ordinary backing is acquired on demand as
independent untyped extents; free sibling extents can split or coalesce only
within their recorded parent. Revoke/retype supplies fresh zeroed frames, while
retained parent capabilities and reusable backing remain explicitly accounted.
Unrelated physical extents are never merged by address arithmetic alone.

The live adapter quarantines released frame anchors until the entire logical
teardown commits. Retrying an earlier action cannot revoke a newly allocated
buffer through a recycled CSlot. Failed unpublished allocation cleanup remains
owned and is retried before subsequent allocation.

Dynamic mapping tables are owned by the task arena and track shared-buffer,
DMA, and MMIO mapping dependencies by VSpace lifetime and address. Empty owned
tables are collected bottom-up; loader-owned tables are not reclaimed by this
path. Completed per-page teardown is remembered before any later fallible
cleanup, so retries do not target an alias's owner mapping or a recycled slot.
The owning mechanisms are `slime-root/src/object_allocator/shared_backing.rs`,
`slime-root/src/object_allocator/mapping_tables.rs`, and
`slime-root/src/buffer_adapter.rs`. These rules do not raise the declared shared
payload limits or qualify a physical machine.

Shared buffers move data between components. They are not component heap memory;
private allocation has no object identity or transfer semantics. See
[`private-memory.md`](private-memory.md).

## Bounds and verification

The authoritative numbers remain in the capability matrix. Key current limits
are one capability and 64 payload bytes per IPC message, 64 logical capability
slots per task, 32 live shared buffers, 256 shared-buffer pages, 64 mappings, and
64 loans.

Narrow behavior gates include `just sel4_channel_check`,
`just sel4_crossing_check`, `just sel4_sample_check`, and
`just fabric_authority_check`. `just sel4_gate_control_check` proves that the
marker gates reject missing, reordered, and explicit failure evidence.
