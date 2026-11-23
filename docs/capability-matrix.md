# Slime OS capability matrix

The canonical object-by-rights surface, the rules for extending it, and the
planned-but-undecided authority horizon. Update this file in the same change
that adds an object kind or right; a row without a gate is a bug, not a plan.

Rights numbering is generated-contract truth, not prose. The vocabulary — every
named right and its bit — is declared once in
`contracts/generation/v5/schema.zt` and generated into
`boot-contracts/src/generated/generation.rs`, which every consumer imports.
`RIGHT_ALL` is the union of those named bits rather than a bit-width mask, so a
gap in the numbering is refused rather than admitted (B57). Before B59 this
paragraph was aspirational: 23 rights names were hand-declared across 97 sites
in the root, `boot-contracts`, and roughly fourteen userspace components.

What still lives in more than one place, by design, is *enforcement*: the rights
types the root builds from those bits in `slime-root/src/graph.rs`, and the
operations that check them in the dispatcher,
`slime-root/src/graph_runtime/services.rs`, and the owning mechanism module. Those are predicates over one vocabulary, not copies of
it.

## Grammar

Every new object kind or right must satisfy these rules before it ships:

1. One rights bit names exactly one root-checked operation, never a policy
   concept. Policy — who may hold the capability — belongs in the generation
   manifest and userspace services.
2. A new right ships with at least one gate: an operation site that checks it.
3. Every transfer path checks transferability on each moved capability. The
   current paths are the capability-export protocol (`CAPABILITY EXPORT` /
   `IMPORT` / `EXPORT_CANCEL` / `EXPORT_FINALIZE`) and `SPAWN` grants
   (`task::preflight_spawn_grant`). Any future path inherits the rule.
4. `capability_rights_valid` rejects rights meaningless for the kind, and
   requires each kind's mandatory bits. `narrow` narrows only and never widens;
   a `rights_type!` refuses bits outside its own `VALID` mask.
5. Object creation authority is root-only. Native Endpoints and Notifications
   are seL4 objects the root creates while decoding the generation; userspace
   cannot forge object identities and can only hold, derive, and transfer. The
   one runtime mint is `SHARED BUFFER CREATE` through a `SharedBufferFactory`,
   and it is bounded by a declared budget as well as gated by a right.
6. Every resource table has a hard bound (see Bounds). "Unbounded" is not an
   error-handling strategy.
7. Rights constants are named `RIGHT_<OBJECT>_<OPERATION>`.
8. Generation v5 maps manifest grant rights strings 1:1 to bit names and
   `transferable` to `RIGHT_TRANSFER`. Every generation this repository builds
   is v5; `just contracts_check` proves it by building each fixture and reading
   the magic.

## Capability kinds

The twelve declared kinds are `CapabilityKind` in `boot-contracts/src/generation.rs`,
numbered by `boot-contracts/src/generated/generation.rs`. Discriminant 4 was
`Block` until B90 retired it; the number stays reserved rather than reassigned,
because a discriminant is wire identity.

| Kind | Number | What it names | Where its operations are served |
| --- | --- | --- | --- |
| `Endpoint` | 1 | one side of a declared native seL4 Endpoint edge | the kernel; no root mediation |
| `Executable` | 2 | generation-module bytes verified at boot | root service `SPAWN` |
| `SharedBufferFactory` | 3 | authority to mint shared buffers | root service `SHARED BUFFER CREATE` |
| `Directory` | 5 | a namespace root, possibly scoped | console service inspect/commit, root service derive |
| `Input` | 6 | the decoded key source | console service `INPUT READ` |
| `Supervision` | 7 | one spawned task's outcome | root service `SUPERVISION STATUS` / `DERIVE` |
| `SharedBuffer` | 8 | one allocated buffer | root service shared-buffer operations |
| `Loan` | 9 | a receiver-bound loan of a subrange | root service loan operations |
| `Device` | 10 | one enumerated hardware device assigned to a driver | root service `IO RESOURCE` |
| `MmioRegion` | 11 | one bounded register region of the device | root service `IO RESOURCE` |
| `InterruptSource` | 12 | one declared interrupt source | root service `IO RESOURCE` |
| `DmaAccount` | 13 | one driver's bounded DMA authority and accounting | root service `IO RESOURCE` |

## Current matrix

Rights are a flat `u64`. `RIGHT_ALL` is the union of the named bits through bit
33, excluding the reserved gaps at bits 10, 11, and 17; bits 34–63 are free.
Bits 10 and 11 were `BLOCK_READ`/`BLOCK_WRITE` until B90 retired them.

| Object | Right (bit) | Gated operation | Creation authority | Gate status |
| --- | --- | --- | --- | --- |
| Endpoint | SEND (0) | `seL4_Send`/`seL4_Call`/`seL4_NBSend` on the declared edge; the root mints the child's cap at send-only rights | root, from the generation's declared edges (`slime-root/src/peer_endpoint.rs`) | gated |
| Endpoint | RECV (1) | `seL4_Recv` on the declared edge; the root mints at receive-only rights | same | gated |
| *(meta, most kinds)* | TRANSFER (2) | `CAPABILITY EXPORT` and transferable derived spawn grants | — | gated on both paths |
| Executable | EXEC (3) | executable slot validation in `SPAWN` | generation module only, hash-verified at boot | gated |
| Device / MmioRegion | MAP_MMIO (4) | map only the capability's bounded subrange at its declared access mode, and bound each `IO RESOURCE MMIO READ32` / `WRITE32` to the exact declared subrange. Both capabilities must carry the bit: `MAP MMIO` and the two register accessors each check the device *and* the region (`slime-root/src/graph_runtime/services/io_resource.rs`) | root bootstrap from the generation's device assignment | gated (IO1) |
| DmaAccount | DMA_PIN (5) | `IO RESOURCE DMA MAP`, `QUEUE MAP`, and `REQUEST BEGIN`; creates one direction-scoped DMA mapping for a live shared-buffer lease and returns only an opaque IOVA | generation `io-resource/v1`; a shared-buffer capability alone grants no DMA authority | gated (IO1) |
| DmaAccount | DMA_RELEASE (6) | `IO RESOURCE DMA RELEASE` and `REQUEST SETTLE`; destroys an idle DMA mapping, and memory remains charged while a hardware request owns it | same | gated (IO1) |
| InterruptSource | IRQ_ACK (7) | `IO RESOURCE IRQ ACK` for the holder's pending, declared interrupt source and epoch only | root bootstrap from the generation's device assignment | gated (IO1) |
| SharedBuffer | BUFFER_WRITE (8) | writable `SHARED BUFFER MAP`; irreversible `SHARED BUFFER SEAL` | `SHARED BUFFER CREATE` via a `SharedBufferFactory`; root-assigned identity | gated (C7.4) |
| SharedBuffer | BUFFER_MAP (9) | read-only `SHARED BUFFER MAP`; exact `SHARED BUFFER UNMAP` | same | gated (C7.4) |
| Executable | SPAWN (16) | instance launch in `SPAWN`; always travels with EXEC | generation manifest | gated (M6.1) |
| Supervision | SUPERVISE (18) | `SUPERVISION STATUS` and `SUPERVISION DERIVE` | returned by a successful `SPAWN` | gated (M6.1/B25) |
| Directory | DIRECTORY_READ (19) | `DIRECTORY INSPECT` before filesystem reads | root bootstrap from the generation's declared root | gated (M6.3) |
| Directory | DIRECTORY_WRITE (20) | `DIRECTORY INSPECT` before mutation and `DIRECTORY COMMIT` for atomic root swap | same | gated (M6.3) |
| Directory | DIRECTORY_LIST (21) | `DIRECTORY INSPECT` before bounded enumeration | same | gated (M6.3) |
| Directory | DIRECTORY_DERIVE (22) | `DIRECTORY DERIVE` for a subdirectory-scoped, narrow-rights copy | same; powerbox minting needs only this operation | gated (M6.3) |
| Input | INPUT_READ (23) | `INPUT READ` drains one decoded key event | root bootstrap, only through a generation grant | gated (M6.4) |
| SharedBufferFactory | BUFFER_CREATE (24) | `SHARED BUFFER CREATE` mints a root-identified `SharedBuffer` under fixed global byte/object bounds; `SHARED BUFFER RELEASE` reclaims it | generation manifest | gated (C7.2) |
| SharedBuffer | BUFFER_LOAN (25) | `SHARED BUFFER LOAN` mints an exact loan for a named receiver; `SHARED BUFFER REVOKE` settles it as lender | same | gated (C7.5) |
| Loan | BUFFER_MAP (9) / BUFFER_WRITE (8) | receiver-bound `SHARED BUFFER LOAN MAP` within the loaned subrange at the loan's own protection; `SHARED BUFFER RETURN` settles it once | root-created by `SHARED BUFFER LOAN`; delivered to the named receiver only | gated (C7.5) |
| Clock service | none (bit 26 retired) | `CLOCK MONOTONIC READ` and `CLOCK RATE READ` for every task on RISC-V and x86_64; AArch64 components read the counter directly | gated on `lifecycle` only | ambient (`clock-authority/v2`) |
| Clock service | CLOCK_TIMER_USE (27) | `CLOCK TIMER ARM` / `CLOCK TIMER CANCEL`, bounded by the holder's declared live-timer quota and delivered on its declared Notification; gates the root service, but cannot prevent hostile native code from writing globally enabled `CNTP_*` control registers on current AArch64 profiles | same | gated (C9.1; register-integrity wall documented by `clock-authority/v2`) |
| Clock service | CLOCK_SIMULATED_READ (28) | `CLOCK SIMULATED READ` | same | gated (C9.1) |
| Clock service | CLOCK_SIMULATED_ADVANCE (29) | `CLOCK SIMULATED ADVANCE`; independently grantable from simulated read | same | gated (C9.1) |
| Scheduling service | SCHEDULING_PROMOTE (30) | `SCHEDULING CLASS PROMOTE` for a subject the caller holds a supervision capability over, bounded by the promotion edge's declared ceiling and refused when the caller names itself. `SCHEDULING CLASS READ` appears in no row: it is self-scoped and grants nothing, so it is gated by nothing | generation `scheduling-class/v1`; root-brokered state keyed by task, no new seL4 object kind | gated (C9.3) |
| Lifecycle service | LIFECYCLE_RESTART (31) | `SUPERVISION RESTART ADMIT` for a subject the caller holds a supervision capability over, charging the generation's declared attempt budget and answering its declared backoff instant. `LIFECYCLE STATE READ` and `LIFECYCLE STATE ADVANCE` appear in no row: both are self-scoped by badge, `STATE_READ` grants nothing, and `STATE_ADVANCE` moves only the caller's own state along an edge the generation admits — so the transition graph is the bound rather than any right | generation `lifecycle-policy/v1`; the bit rides on the supervision handle the root mints for a spawner exactly where the policy declares a restart bound for that child, so the right and the policy are one fact with one source | gated (C9.4) |
| Lifecycle service | PARAMETER_READ (32) | `SUPERVISION PARAMETER READ` for a subject the caller holds a supervision capability over, or for the caller's own instance through `PARAMETER_SELF_SLOT`. A declared parameter edge carrying read must also exist, and its absence is refused distinguishably from an unset key | generation `lifecycle-policy/v1`; the bit rides on the spawn-minted supervision handle where the policy declares the edge | gated (C9.4) |
| Lifecycle service | PARAMETER_WRITE (33) | `SUPERVISION PARAMETER WRITE`, gated independently of read: a supervisor that must observe a component's configuration to decide a restart does not thereby get to change it | same | gated (C9.4) |

`CAPABILITY RESOLVE BINDING` (label 37) appears in no row above, and its absence
is the statement: it is gated by *nothing*, because it grants nothing. It answers
which of the caller's own slots holds a binding the caller's own instance
declares, resolved from that instance's binding list and from no other — the same
self-scoping the two `OCCUPANCY` operations use. A name the instance does not
bind is refused rather than answered, so the reply is a fact the component
already knew at compile time and could not otherwise learn at runtime. Requiring
a right to ask would mean minting a capability whose only power is to read one's
own layout (CP2). The `executable:`/`channel:` prefixes reach
`contracts/boot-layout/v1`'s two identity domains for the bootstrap instance and
disclose no more: that table describes exactly that component's CSpace. The
`notification:` and `minted:` prefixes reach `notificationBindings` and
`mintedBindings` for the caller's own holder index, which is the same disclosure
bound in two further separate tables.

Bits 4–7 (`mapMmio`, `dmaPin`, `dmaRelease`, `irqAck`) were named-but-ungated
until IO1, and are neither now. `capability_rights_valid` admits them on
`Device`/`MmioRegion`, `DmaAccount`, and `InterruptSource`
(`boot-contracts/src/generation.rs`); `slime-root/src/graph.rs` carries the four
matching `rights_type!` declarations; and each of the ten `IO RESOURCE`
operations checks the bit its row above names. They are declared on real
manifest grants — every seL4 composition with a driver spells them out, for
example `contracts/generation-manifest/v1/compositions/sel4-storage.zti`.

Bits 12–15 (`storeRead`, `storeWrite`, `healthConfirm`, `bootUpdate`) are the
four that remain named but ungated: inside `RIGHT_ALL`, admitted by no
`CapabilityKind` mask, carried by no `rights_type!`, and checked by no
operation. They are residue of the retired custom kernel's `ObjectStore` and
`GenerationControl` kinds; those mechanisms are now userspace components
(`components/services/sel4-generation-manager/`,
`components/testkit/sel4-{store,rollback,recovery}-probe/`,
`boot-contracts/src/object_store.rs`) reaching storage over the IO0 rings B83
cut them over to, so nothing is waiting on these bits. This is the one shape
Grammar rule 2 forbids for a *new* right, and a condition these four predate.
Reassign them deliberately; do not assume they still mean what a pre-cutover
document says.

Bits 10 and 11 were a fifth and sixth such bit until B90. They were
`blockRead`/`blockWrite` on a `Block` kind whose only operation, `BLOCK
TRANSACT`, B83 had already deleted — so the kind was admitted at decode,
materialized into a typed root entry, and resolvable by nothing. B90 deleted the
kind, both bits, `BlockRights`, `resolve_block`, `SERVICE_BLOCK`, and the
launch-order ordinal that numbered `Block` grants. Storage authority is declared
per ring in `contracts/block-authority/v1`, whose `rightRead`/`rightWrite` are an
independent two-bit `u16` vocabulary that never shared these positions. Bits 10,
11, and discriminants 4 (kind) and 8 (service) are reserved, never reassigned:
each is an ABI a component may still name.

`boot-contracts`'s
`declared_rights_partition_into_manifest_declarable_and_root_only` enumerates all
twelve declared kinds, so its two classes partition the vocabulary rather than an
arbitrary subset of it. Until B90 its `BASELINES` named nine — the four IO kinds
were absent — and `NOT_MANIFEST_DECLARABLE` therefore meant "rejected for those
nine" rather than "declarable by no manifest": bits 4–7 sat in that list while
real manifest grants declared them, on kinds the test did not enumerate. They are
now in `MANIFEST_DECLARABLE`, where the grants that spell them always implied they
belonged. Bits 27–33 remain in the rejected class for the opposite reason: no
grant names them because their source is a declared resource
(`clock-authority/v2`, `lifecycle-policy/v1`, `scheduling-class/v1`) that the root
reads to mint the bit onto a service or supervision handle. Wiring one of bits
12–15 to any declared kind fails the test, and a *new* kind must still be added to
`BASELINES` in the same change — that is what keeps the partition total.

Semantics not visible in the table:

- Receiving a capability costs the receiver no rights bit; it arrives with
  exactly the rights the sender named and root authenticated.
- `derive` and spawn grants are non-consuming and narrow-only. A derived copy
  that retains TRANSFER requires that meta-right on its source.
- The capability-transfer protocol is the *consuming* movement path, and it is
  four messages rather than one: `EXPORT` reserves a receiver-bound export and,
  for a native Endpoint, mints the real kernel ticket the message will carry;
  the descriptor and (for an Endpoint) that ticket cross the declared native
  edge; `EXPORT_FINALIZE` commits and `EXPORT_CANCEL` restores the source at its
  original rights. Root authenticates the declared object kind and the nonzero
  rights mask from the request registers, never from the descriptor bytes.
- A native Endpoint is the one kind with a kernel object to travel in the
  message; it lands in the receiver's receive slot and is relocated into its
  transferred-handle region. Every other kind is a root-owned logical capability
  with nothing for the kernel to carry, so the descriptor arrives alone and the
  receiver takes up the authority behind it with `CAPABILITY IMPORT`.
- Only `Endpoint`, `SharedBuffer`, `Loan`, `Supervision`, and `Directory` are
  nameable by a transfer (`capability_kind` in
  `slime-root/src/graph_runtime/services/capability.rs`). No
  other kind can move; an `Executable` or a factory reaches a child as a spawn
  grant or a declared binding, never as a transfer.
- C9.5 narrows `CAPABILITY IMPORT` for one class of receiver, and only that one:
  an import carrying a right `contracts/generation/v5` classifies `unrecorded` is
  refused when the generation's recording resource declares the receiver
  *deterministic*. Admission certifies that claim against the authority a
  generation declares at launch, so without this an import could widen the
  instance past what any recording captures and the claim would stay
  authenticated while ceasing to be true. A receiver with no determinism claim —
  every component in every generation before C9.5 — is unaffected, and the
  refusal is on the import rather than the export because the export installs
  nothing.
- The 64-byte `capability-transfer/v1` descriptor is opaque to the root:
  `route_identity` and `direction` are bytes a userspace fabric uses to bind the
  move to a declared edge, and `FLAG_RETAIN_TRANSFER` is the descriptor's own
  record of a disposition the request registers already carried.
- Private memory is a generation-declared quota, not a capability or a
  transferable object. An absent or zero `private-memory-budget/v1` quota
  denies growth. A task can grow only its own fixed-base reserved window;
  private pages cannot be shared, loaned, sealed, or mapped into another task.
  Shared-buffer and received-loan mappings cannot overlap any part of that
  window, including its unbacked reservation. Private mappings are writable
  and execute-never on AArch64 and RV64; the x86-64 mapping API currently does
  not enforce execute prevention. See [private component memory](architecture/private-memory.md)
  for the mapping, reclamation, and qualification boundaries.
- Shared-buffer mappings are page-aligned, non-executable, charged one unit per
  live map to the mapper's generation quota, and never overwrite an existing
  user page. `SHARED BUFFER SEAL` downgrades every live writable mapping before
  publishing the irreversible read-only state; release and subtree teardown
  remove PTEs before returning frames.
- Subdirectory-scoped capabilities may browse and derive further but cannot
  commit the namespace root. Root transitions require an unscoped WRITE
  capability; scoped writes are rejected before object-store I/O.
- Spawn retains the executable and all grant sources. It returns one supervision
  handle and is bounded independently per spawner by the manifest's `spawnBudget`
  plus the global live-task ceiling.
- Spawned code cannot be injected: `Executable` objects reference only
  generation-module bytes verified at boot. Spawn composes known components with
  gifted authority; it cannot introduce new code.
- Shared-buffer allocation is charged to the creating component's
  supervision-subtree account against its generation-declared per-holder quota
  (`shared-buffer-budget/v1`). A component absent from the budget holds the
  deny-by-default quota and cannot allocate. Release, peer death, supervised
  restart, and revocation reclaim every page and charge in that subtree without
  disturbing another subtree's account (C7.3/C7.5). Mapping quota is consumed
  and reclaimed by `SharedBufferTable::map` (C7.4); loan quota by
  `SharedBufferTable::loan`, and a released creator's pages and buffer charge
  stay retained until the final single-return loan settles.
- The reference generation declares that budget in practice, not only in
  principle: `contracts/generation-manifest/v1/fixtures/valid.zti` carries a
  `shared-buffer-budget` `KIND_RESOURCE` object with eleven holder quotas and
  seven `bufferCreate` grants. The grant authorizes the operation and the budget
  bounds it: a component with a grant but no budget entry still allocates
  nothing, and a budget entry without a grant authorizes nothing.
- `SHARED BUFFER OCCUPANCY` (label 30, C8.13.1) is the one shared-buffer
  operation gated by no rights bit, so no row above can express it. It is
  read-only and reports only the caller's own four live charges, and the holder
  it reports on is the endpoint badge the root already authenticated — the
  request carries no holder argument, so there is nothing to forge and no other
  holder it can name. Its gate is the budget declaration itself: a holder whose
  quota is the deny-by-default one is refused, which is why the answer is not
  four zeros. Requiring a `SharedBufferFactory` instead would couple a
  self-query to mint authority and deny a loan receiver that legitimately holds
  mappings but was never granted a factory.
- `CAPABILITY SLOT OCCUPANCY` (label 31, C8.13.3) is likewise gated by no
  rights bit, and by no table either. It reports how many slots the caller's
  own CSpace holds, and the CSpace it counts is the one belonging to the badge
  the root authenticated, so there is no task argument to forge and no other
  CSpace it can reach. Nothing above can express it because there is nothing to
  authorize: the answer describes only the caller's own CSpace, and knowing how
  full that CSpace is grants no access to anything in it. The root answers
  because it is the only party that can: a `RootOnly` task holds no capability
  to its own CNode at all — `CHILD_SLOT_CNODE` is installed only under
  `Supervision::SelfManaged` (`slime-root/src/task.rs`) — so for most components
  this is not a convenience over self-probing, it is the only way to learn the
  number.
- The reply reports occupancy twice, because a child's slots are counted by two
  different bounds. `declared` is the component's own logical slot numbering
  from 0 — the space `capabilitySlots` budgets, which the builder derives as
  `FABRIC_FIRST_CONTROL_SLOT + control endpoints + buffers` and which
  `fabric_graph_is_satisfiable` validates against `graph::MAX_TASK_CAPS`.
  `populated` and `capacity` are the physical CNode, where logical index 3
  resolves to slot 36. Comparing either count to the other's ceiling would
  compare unrelated quantities, so each is checked against its own.
  `declared` is credited (every install into it is a root operation) while
  `populated` is a *census*: a component fills physical slots the root never
  mediates, since the receiving runtime moves a transferred Endpoint out of the
  receive slot itself, so an accumulated count would understate every holder
  that has accepted a transfer.
- The reply deliberately omits the generation's declared `capabilitySlots`. That
  limit is graph-wide rather than a property of the caller's CSpace, and
  `SERVICE_CAPABILITY_TRANSFER` is required of any instance holding an
  `Endpoint` or transferable grant — which in the fabric fixtures includes the
  ungranted `fabric-probe` intruder. Shipping it would have handed a graph fact
  to a component the graph grants nothing, for no caller that reads it. The root
  keeps the ceiling and reports a breach on serial instead.
- A C7.6 sample descriptor is a userspace control message
  (`sample-descriptor/v1`), not a root object: it references an exact
  transferred `Loan` by its unforgeable identity plus a page-aligned
  offset/length, type identity, sequence, and known flags. It carries no rights
  bit and mints no authority — the receiver still needs the loan capability to
  map. The descriptor fits one message (`DESCRIPTOR_LEN == MAX_MSG == 64`), so a
  sample larger than the message bound crosses as descriptor plus shared buffer
  without copying payload bytes through IPC or widening `MAX_MSG`.
- C8.3 makes the C8.2 fabric graph load-bearing without teaching the root about
  it. A userspace `fabric-service` receives both halves of each declared route
  as generation-declared native Endpoint edges and delegates each participant
  one role: SEND to the publisher, RECV to the subscriber, TRANSFER to neither.
  A client is authenticated by the generation-provisioned control endpoint its
  request arrived on — a binding init establishes at spawn and no component can
  forge — never by the route name, direction, or type identity the request
  carries. Ignoring those fields is a tested property:
  `just fabric_authority_check` boots a component that supplies byte-identical
  route strings for an edge the graph never declared and observes a denial with
  no capability attached.
- A `mintedBindings` entry authorizes a holder to *receive* a named capability at
  a declared slot with an exact rights ceiling, deferring only the object
  identity to the owner that creates it. It is admission, not authority: nothing
  arrives until a real delegation crosses.

## Bounds

| Resource | Bound | Enforcement |
| --- | --- | --- |
| Logical capabilities per task | `MAX_TASK_CAPS = 64` | `slime-root/src/graph.rs` |
| Capabilities per IPC message | `MAX_CAPS_PER_MSG = 1` | seL4 carries one per IPC; checked in `sel4_transport` and `slime-root/src/ipc.rs` |
| Payload bytes per message | `MAX_MESSAGE_BYTES = 64` | `slime-root/src/ipc.rs` |
| Live tasks | `MAX_TASKS = 48` | `slime-root/src/task.rs`; `SpawnError::TooManyTasks` |
| Supervised task records | `MAX_SUPERVISED_TASKS = 64`, `MAX_RECORDS = MAX_TASKS` | `slime-root/src/{fault,supervision}.rs` |
| Live children per spawner | manifest `spawnBudget <= 32` | `MAX_SPAWN_BUDGET`; `SpawnError::BudgetExhausted` |
| Declared native Endpoints per task | `CHILD_NATIVE_REGION_SLOTS = 31` | child CSpace regions in `slime-root/src/task.rs` |
| Peer endpoints / notifications | `MAX_PEER_ENDPOINTS = 48`, `MAX_NOTIFICATIONS = 31` | `slime-root/src/{peer_endpoint,notification}.rs` |
| Clock-authority holders / live timers | `MAX_HOLDERS = 48`, `MAX_LIVE_TIMERS_PER_HOLDER = 4`, `MAX_LIVE_TIMERS = 64` | `clock-authority/v2` decode plus `ClockService::arm`; omission denies every timer and simulated-clock operation |
| Threads per component | `MAX_CHILD_THREADS = 2` | `slime-root/src/child_vspace.rs` (B47) |
| Task arenas / root CSlots | `MAX_TASK_ARENAS = 48`; root CSpace has no fixed width. The kernel's initial CNode is installed under a four-bit root, further ten-bit leaves are installed from admitted ordinary memory, and a generation's plan is funded before admission judges it. A refusal names the resource that ran out (`SLIME_MEM qualification … limit=`); kernels narrower than 2^19 initial slots keep the small descriptor envelope | `slime-root/src/{root_cspace,object_allocator}.rs` |
| Private-memory pages per holder / aggregate | `private-memory-budget/v1`: 65,536 / 262,144 pages (256 MiB / 1 GiB) only on `aarch64-sel4-qemu-virt` and `riscv64-sel4-qemu-virt`; all other targets retain 512 / 2,048 pages (2 MiB / 8 MiB). Declared holder quotas must individually and collectively fit the target envelope; omission denies growth. These QEMU results qualify no physical machine | `contracts/private-memory-budget/v1/schema.zt`; target-bound admission in `boot-contracts/src/private_memory_budget.rs` and `slime-root/src/generation.rs`; growth accounting in `slime-root/src/private_memory.rs` |
| Live shared buffers | `MAX_SHARED_BUFFERS = 32` | `SharedBufferError::ObjectsExhausted` |
| Shared-buffer total pages | `MAX_TOTAL_PAGES = 256` (1 MiB) | `SharedBufferError::BytesExhausted` |
| Pages per shared buffer | `MAX_BUFFER_PAGES = 64` | `SharedBufferError::BadSize` |
| Per-holder shared-buffer quota | generation `shared-buffer-budget/v1` (`byte_pages`, `buffer_count`, `mapping_count`, `loan_count`); deny by default; declared totals must also fit the root ceilings, so a validating budget can be honoured with every holder at its ceiling at once | `SharedBufferTable::create`; `SharedBufferError::QuotaExceeded`; aggregate over-commit fails at generation decode |
| Live shared-buffer mappings | `MAX_MAPPINGS = 64` | `SharedBufferTable::map`; `MappingsExhausted` |
| Live shared-buffer loans | `MAX_LOANS = 64` plus generation `loan_count` per lender | `SharedBufferTable::loan`; `LoansExhausted` / `QuotaExceeded` |
| Declared holders per budget | `MAX_HOLDERS = 32` | `SharedBufferBudget::decode` |
| Driver hardware-resource quota | generation `io-resource/v1`: MMIO bytes/mappings, DMA pages/mappings, IRQ sources, outstanding requests, and buffer loans; omission denies all | `ResourceTable` prepare/effect/commit transitions and `IoResourceBudget::validate_against` |
| Live IO resource tables | drivers 32, MMIO regions/mappings 64, DMA mappings 64, IRQ sources 64, live leases/requests 128 | `slime-root/src/io_resource.rs` |
| IO0 ring geometry / outstanding requests | `contracts/io-queue/v1`: `minQueueSlots = 2`, `maxQueueSlots = 256`, `maxOutstanding = 256`, with the 128-byte header, 128-byte request slot, and 64-byte completion slot fixed by the schema | generated `components/proto/src/io_queue.rs` and the ring library's slot arithmetic, proved over every value of the declared types by `just kani_io_proofs` (IO6) |
| Per-ring block rights and sector ceiling | generation `block-authority/v1` per (holder, device, ring): `blockRead`/`blockWrite` plus `sectorLimit`; omission denies the ring | `boot-contracts/src/block_authority.rs` decode plus `virtio-blk-driver`'s refusal. The root copies the authenticated table and enforces no block right of its own, because which sector a ring may touch is device policy |
| Directory path bytes / depth | `MAX_DIRECTORY_PATH = 128`, `MAX_DIRECTORY_DEPTH = 8` root-side; the userspace ABI and filesystem schema admit 48 bytes and depth 4 | `slime-root/src/directory.rs`; `components/runtime/src/syscall.rs`; `components/proto/src/fs.rs` |
| Directory scopes | `MAX_SCOPES = 64` | `slime-root/src/directory.rs` |
| Directory entries per snapshot | `MAX_ENTRIES = 16` | filesystem protocol and snapshot decoder |
| Boot-layout entries | `MAX_ENTRIES = 64` | `boot-contracts/src/generated/boot_layout.rs` |
| Admitted executables / instances | `MAX_ADMITTED_EXECUTABLES = 48`, `MAX_ADMITTED_INSTANCES = 48` | `slime-root/src/generation.rs` |
| Graph service iterations | `MAX_GRAPH_ITERATIONS = 131072` for a finite plane; a resident product graph reports a checkpoint at 32768 and has no limit | `slime-root/src/graph_runtime.rs` (B28); bounds a livelock rather than the gate timeout |

A task's kernel objects are allocated from a per-task arena, so termination
reclaims its TCBs, CNode, VSpace, IPC buffers, and frames rather than leaking
them until reboot; `just sel4_reclamation_check` and `just sel4_stress_check`
observe the graph returning to zero live tasks.

## Horizon (claimed directions, not decisions)

| Candidate object | Candidate rights | Trigger | Open questions |
| --- | --- | --- | --- |
| Generation-update authority as an object | possibly STAGE_PENDING | a generation service that must not hold raw block write | Boundary between userspace staging and immutable selector-owned slot writes, now that management is a component reaching storage over an IO0 ring whose write right is declared per ring in `contracts/block-authority/v1` |
| NetworkDestination | CONNECT / SEND / RECV / LISTEN | the RPi5 transport route ([RP5](plans/rpi5-ros2-demo.md#rp5--node-and-transport-runtime-envelope)) and [Hardware H6](plans/framework-hardware.md#slice-acceptance) | IO4 answered the shape question *without* a capability kind: exact (protocol, address, port) tuples are a declared resource (`contracts/network-destination/v1`) that the root copies to the declared `network-service` through `CAPABILITY NETWORK DESTINATIONS READ` (and its own static interface through `CAPABILITY NETWORK INTERFACE READ`, `contracts/network-interface/v1`), with tuple matching in userspace. Whether a per-connection object and rights bits are ever needed is now the open question, and IO4's unfinished data plane is what would decide it |
| EnergyAccount | READ? | [Hardware H track](plans/framework-hardware.md#slice-acceptance) | Whether accounting is authority at all or read-only telemetry |

M6.1 landed non-consuming narrow derive-copy spawn grants, per-spawner
accounting, and supervision handles; B39–B50 moved endpoint creation from a
userspace factory syscall to generation-declared native seL4 objects. Future
resource factories follow the same named-capability and hard-bound rules that
`SharedBufferFactory` does: a right to ask, a declared budget to bound it, and a
root-assigned identity userspace cannot forge.
