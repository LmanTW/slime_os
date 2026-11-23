# Native development, live update, and on-device build

This plan owns the D1–D7 design and acceptance requirements for authoring,
building, admitting, and live-switching native programs inside Slime OS.
D1–D7 are not implemented. A planned recipe named below does not exist yet.
Work-item state lives in `.tasks/items/`.

**Purpose:** Let a user author source inside Slime OS, compile a native program directly into the admitted component-image format, execute it without rebooting under explicit development authority, turn tested artifacts into release-authorized generations, switch compatible userspace components at runtime, and eventually reproduce a complete generation on-device.

**Decision:** Slisp is both the interactive language and the first non-Rust application language. Zutai remains Slime's only schema/configuration language. Slisp owns syntax, evaluator/compiler behavior, and its standard library; Slime owns executable-image, target, syscall, capability, build, admission, generation, activation, and verification contracts.

**Source directions:** [archived direction 3](https://git.justaslime.dev/iceice666/slime_os-history/src/commit/45ed1745907b2d0a13fdf70c8b34eb635bed5f23/docs/directions/03-nondeterminism-as-capabilities.md), [archived direction 23](https://git.justaslime.dev/iceice666/slime_os-history/src/commit/45ed1745907b2d0a13fdf70c8b34eb635bed5f23/docs/directions/23-build-provenance.md), and [archived direction 30](https://git.justaslime.dev/iceice666/slime_os-history/src/commit/45ed1745907b2d0a13fdf70c8b34eb635bed5f23/docs/directions/30-deterministic-on-device-builds.md).

**Dependencies:** M5's content-addressed object store, deterministic generations, state policies, release authorization, health promotion, and rollback; M6's directory, spawn, generation-management, input, and transfer mechanisms; Slisp's verified non-Rust component path; [target-qualified executable admission](../architecture/targets-and-portability.md); and [C9](../architecture/runtime-authority.md) for explicit time and lifecycle control.

## Boundaries

- **Zutai remains the only schema language.** Every project/build/admission/update message or persistent format is a versioned Zutai schema under `contracts/` with generated bindings. The new language may import generated protocol bindings; it does not define a second wire, manifest, build-request, or persistence schema language.
- **There is one native executable format.** A compiler may emit the P0-admitted `SLIMECME` component-image revision — the ELF-carrying revision `boot-contracts/src/component_image.rs` validates — directly instead of going through the workspace build, but direct output receives no alternate loader, relaxed validation, or language-specific admission path. The retired `SLIMECMP` (component/v1) revision is refused, not a target.
- **Images contain mapping, not authority.** Source annotations and compiler output cannot declare capabilities, grants, command-profile membership, release authorization, resource accounts, or activation policy. Those remain generation/admission inputs enforced outside the image.
- **Writing bytes never grants execution.** A file or object that decodes as a component image is still data until an explicitly authorized admission service creates an `Executable` capability. Spawn continues to require `EXEC | SPAWN` and narrow-only grants.
- **Build, test, install, and switch are separate transitions.** An unsigned local artifact may be admitted only to a bounded ephemeral development session. A persistent boot or live-generation activation still requires the existing release authorization and generation closure checks.
- **No writable-executable path.** D1–D7 add neither JIT authority nor a dynamic linker. Compilation finishes into a sealed immutable image before admission; mapped tasks retain W^X and the normal component-image bounds.
- **No ambient development environment.** Source roots, toolchains, standard libraries, target profiles, parameters, diagnostics, scratch space, clocks, entropy, network destinations, and output stores are explicit capabilities or content identities. A missing input fails rather than falling back to a host path, global package index, inherited environment, or network download.
- **Provenance and authorization stay distinct.** Build provenance answers how bytes were produced. M5.8 release metadata answers whether those bytes may become a persistent or live-active generation. Neither substitutes for the other.
- **Live activation is side-by-side, never in-place mutation.** A replacement component starts with fresh mappings and capabilities; a bounded readiness/cutover transaction moves traffic only after health succeeds, then retires the old instance.
- **The first live-update class is intentionally narrow.** D5 admits only generations with the same target, kernel, bootstrap, component graph, interface identities, grants, state bindings, resource budgets, and scheduling classes. Kernel/bootstrap/ABI changes, state-schema changes, grant or graph changes, and exclusive-device authority changes are reboot-required until separately modeled.

## Ownership contract for the new language

The language project owns:

- grammar, parser, type/effect system, compiler implementation, language package rules, and standard-library source;
- deterministic lowering from a normalized source/toolchain closure to one exact P0 target profile;
- direct emission of the admitted `SLIMECME` revision, plus detached diagnostics/debug data when requested;
- a pinned compiler/toolchain identity consumable by host and Slime build services.

Slime OS owns:

- the `SLIMECME` component-image, root-operation, target-profile, capability, and generated IPC binding contracts;
- validation, content identity, storage, executable admission, spawn, supervision, and resource accounting;
- generation construction, authority diff/classification, release authorization, live/boot activation, health, and rollback;
- conformance fixtures proving that a producer cannot bypass target, ABI, W^X, bounds, or authority rules.

The producer boundary is therefore neutral:

```text
normalized source closure
+ exact compiler/toolchain identity
+ exact target/profile and build parameters
    -> compiler
    -> SLIMECME bytes + diagnostics/debug objects
    -> Slime structural validation and content identity
    -> ephemeral admission OR generation construction
```

## D1 — In-system source workspace and script loop

**Depends on:** M6.3 directory capabilities, the spawn service, and the resident Slisp REPL.

### Deliverables

- define a bounded versioned Zutai source-workspace/project contract naming language identity, source entries, toolchain identity, exact target profile, entry unit, normalized build parameters, and output kind without host paths or inherited environment;
- add a minimal native editor capable of creating, editing, saving, reopening, and atomically replacing bounded UTF-8 source files under one explicitly granted project directory;
- extend Slisp with bounded project/source functions and stored program execution under explicit directory, stream, environment, and service grants; these are ordinary Lisp functions, not reader syntax;
- preserve source roots as immutable directory snapshots with explicit commit, so interrupted saves retain the prior readable root and build inputs name one exact snapshot;
- define generated structured diagnostic/source-span bindings for editor and later compiler use; diagnostics are bounded data, not unstructured access to a terminal or filesystem.

### Required checks

- an editor without the project `Directory` capability cannot enumerate, read, modify, or infer another namespace;
- oversized files, invalid UTF-8 where text is required, excessive entries/depth, stale roots, and interrupted saves fail before replacing the prior root;
- reopening a committed project returns byte-identical source and normalized project metadata;
- a stored Slisp program launches only commands in its granted profile, cannot acquire an undeclared cwd/stream/environment/capability, and leaves source data intact after parse or child failure.

### Planned verification target

The planned recipe is `authoring_check`.

### Exit condition

Inside QEMU, a user creates a project, edits and commits source, reopens the identical snapshot, and runs a stored Slisp program; an ungranted editor/program cannot observe or modify another directory or launch a command outside its profile.

## D2 — Producer-neutral image contract and direct language backend

**Depends on:** D1's normalized project identity and P0's exact architecture/ABI/page-profile executable-artifact contract. The language compiler may initially run on the development host, but its emitted image is the same object later consumed on-device.

### Deliverables

- make P0's component-image conformance producer-neutral: the existing workspace ELF build path and a direct image emitter both target the same versioned `SLIMECME` schema and the identical `boot-contracts` validator;
- pin the new language compiler, standard library, generated Slime syscall/IPC bindings, optimization profile, and backend parameters as one content-addressed toolchain closure;
- implement a deterministic backend that emits the exact target-qualified component image directly, including entry, stack requirement, bounded segments, zero-fill, and per-segment R/W/X flags, with no relocation, dynamic-link, authority, signature, or ambient-runtime metadata;
- keep source maps, symbols, compiler diagnostics, and build provenance in detached bounded objects unread by the loader in `slime-root/src/child_vspace.rs`; changing or omitting them cannot change executable semantics accidentally;
- publish language-owned conformance fixtures for a returning component, a typed-IPC client/server pair, a faulting component, and malformed output classes; Slime owns the acceptance oracle and target mismatch corpus;
- keep every cross-component protocol in Zutai-generated bindings. Language-native data layouts are in-memory only unless backed by a versioned Zutai contract.

### Required checks

- two clean builds with identical normalized source, toolchain, target, and parameters emit byte-identical component images and object identities;
- changing source, compiler identity, target, ABI, page profile, or normalized parameter changes the build key and cannot reuse a stale image;
- unknown image revisions, target/ABI mismatch, invalid entry/stack/segments, overlap, overflow, W+X, and over-bound output are rejected by the same corpus regardless of producer;
- a direct-emitted component boots in an ordinary generation and performs typed IPC under only its declared grants; it receives no authority from source annotations or image contents;
- no ELF-beyond-the-admitted-revision parsing, language runtime, type metadata, or compiler-specific policy enters `slime-root`, and none enters seL4;

### Planned verification target

The planned recipe is `language_image_check`.

### Exit condition

A pinned compiler for the new language directly emits a byte-deterministic target-qualified `SLIMECME` component that runs in the ordinary QEMU graph through generated Zutai IPC bindings, while every malformed, mismatched, widened-authority, and nondeterministic fixture fails at its owning boundary.

## D3 — Hermetic on-device build service and provenance

**Depends on:** D1–D2, [C9.1](../architecture/runtime-authority.md#clock-and-timers)'s explicit time and [C9.4](../architecture/runtime-authority.md#lifecycle-and-supervised-restart)'s lifecycle authority, M5.4 object storage, and M5.8's separation of release authorization. This milestone absorbs the build-relevant mechanism from directions 3, 23, and 30. It does not depend on a conserved CPU account: see the track dependencies above.

### Deterministic-component authority

This is the shared, unimplemented clock/entropy design promoted from direction 3,
not a build-only contract. [Replay](../directions/11-flight-recorder-replay.md),
[hermetic testing](../directions/26-hermetic-testing.md), migrations, and
foreign workloads consume the same authority boundary. Typed IPC supplies a
meaningful input boundary, but recording IPC alone cannot reproduce a component
that also reads an unrecorded clock or entropy source.

- Define clock/entropy object kinds, rights strings, and sealing rules through
  the capability-matrix amendment discipline, coordinated with C9 Clock authority.
  Whether clock reads use one READ right or separate MONOTONIC / WALL rights
  remains open: timeouts need not authorize learning the date.
- Resolve kernel-pool Entropy authority versus a per-spawn seeded deterministic
  stream minted by the spawner. A seeded fixture is an explicit input; decide
  whether its seed belongs in the generation, replay trace, or both. Evaluate
  replay composition before proposing the entropy mechanism's kernel work.
  [Entropy authority](../decisions/entropy-authority.md) proposes a
  userspace service with generation-declared hardware and seeded holders
  instead of either; the deterministic-component sealing rule and replay
  recording remain here.
- A manifest declares absence of real clock/entropy grants so the builder can
  check it statically and grant-graph tooling can audit it. Preserve that negative
  declaration under `derive` and later peer transfers: the sealing mechanism
  remains a choice between schemas forbidding transfer of those object kinds and
  a manifest flag forbidding their receipt.
- Virtual fixture clocks and seeded entropy must use the same applicable rights
  as their real-source counterparts, allowing test generations to change wiring
  without changing component bytes.
- State the determinism claim formally and decide whether identical ordered IPC
  inputs suffice, or scheduler timing/preemption and IPC ordering require further
  modeling. Absence of clock/entropy grants alone does not settle that scope.
  Evaluate which existing components qualify unchanged; the proposed check is
  byte-identical output across two boots given identical IPC inputs and declared
  fixture inputs.

### Detached provenance design

D3 owns one canonical normalized source/toolchain/target/parameter closure and
detached provenance schema for host and on-device builds; D7 applies it to every
input/output edge of full-generation reproduction, not a separate provenance model.
The deterministic, versioned document binds source revision, builder identity and
version, build type, normalized parameters, resolved dependency digests, and the
resulting generation identity (or component outputs for the D3 build service).
The [SLSA build-provenance model](https://slsa.dev/spec/v1.2/build-provenance)
informs the distinction from release authorization, not wholesale framework adoption.

Verification stays outside the immutable selector: developers, auditors, or CI
check consistency of the subject with the generation identity and reject altered
inputs, dependency digests, builder identity, or output identity. Reproduction
separately rebuilds the named input closure and compares identities byte-for-byte.
The dependency list must support incident-response lookup by scanning attestations:
which generations include dependency X at digest Y, including a compromised
toolchain or library? D7 carries this requirement across the complete generation.

Open design questions remain whether to reuse an M5.8 release signer identity or
authorize a separate builder identity, and whether attestations live alongside
generations in the M5.4 object store or only host-side. The schema/consistency-verifier
design must resolve those conventions, exercise the accept and four rejection
classes above, and measure verification cost; no implementation or cost is claimed.

### Deliverables

- define versioned Zutai build-request, build-result, diagnostic, and detached build-provenance schemas naming the exact source snapshot, toolchain closure, target, parameters, resource account, output identities, and builder identity;
- run the compiler as a bounded component whose only inputs are content-addressed source/toolchain objects and normalized request data, whose scratch/output directories are explicit capabilities, and whose successful outputs become sealed immutable objects;
- complete the deterministic-component authority rule: C9 Clock authority and an object-specific Entropy authority are explicit; a manifest-declared deterministic builder receives neither real source and cannot receive one later through capability transfer; a seeded fixture is a distinct declared input rather than ambient randomness;
- charge memory, task count, shared-buffer pages, private-memory pages, scratch bytes, output bytes, diagnostic bytes, and child count to a manifest-declared build account, with structured exhaustion and full cleanup on exit, fault, timeout, cancellation, or supervisor restart. CPU is bounded as elapsed wall-clock time against a declared deadline rather than as a conserved account, because the pinned kernel is built `KernelIsMCS OFF` and has no budget to charge;
- key caching on the entire normalized input closure, never a mutable path or timestamp; validate a cached object's digest and producer contract before reuse;
- emit detached provenance binding source, toolchain, target, parameters, builder identity, and outputs. The immutable selector does not parse provenance, and provenance never grants release authorization;
- support the new language compiler as the first native build component while keeping the request/result protocol language-neutral for later Rust or other admitted toolchains.

### Required checks

- the host and Slime build services compile the same fixture from the same normalized closure to the same component-image identity;
- attempts to read wall time, draw undeclared entropy, fetch a package, inspect an ambient directory/environment, or receive a prohibited nondeterminism capability fail structurally;
- each resource class exhausts at its declared bound without committing a partial output or disturbing another build account;
- changing any provenance field or output identity fails verification, while release authorization remains independently required;
- cache hits reproduce validated identities and cache misses cannot alias after source, toolchain, target, or parameter changes;
- compiler crash, malformed output, cancellation, and supervisor restart reclaim scratch space, buffers, children, and account charges.

### Planned verification target

The planned recipe is `hermetic_build_check`.

### Exit condition

A native build service inside QEMU consumes one content-addressed source/toolchain closure and emits the same sealed component identity as the host build, with enforceable absence of ambient nondeterminism/authority, bounded resource use, and independently verifiable provenance.

## D4 — Ephemeral executable admission and sandboxed run

**Depends on:** D3, M6 spawn/supervision, and [C9.4](../architecture/runtime-authority.md#lifecycle-and-supervised-restart)'s lifecycle transitions. The session's resource bounds are the existing per-supervision-subtree limits this milestone declares below, not a conserved CPU account.

### Deliverables

- define a versioned Zutai executable-admission protocol and add a distinct `ExecutableFactory`/`EXECUTABLE_ADMIT` authority; update the capability matrix in the same change as the root operation and service gate that serve it;
- admit only a sealed content-identified component object through bounded transfer, recompute identity, re-run the P0/component decoder, and create an immutable root-tracked `Executable` record only after all checks pass;
- impose fixed root-wide and per-supervision-subtree limits for admitted image bytes, executable objects, mappings, tasks, and lifetime; admission policy, not source/image data, supplies the child's spawn budget and resource account, defaulting to no children and no external grants;
- return the admitted executable only to a development-run service. It spawns the child with an explicit user-selected grant set, fresh endpoints/mappings, separate stdout/stderr/diagnostics, and a supervision handle;
- permit unsigned local images only on this ephemeral path. They cannot enter a command profile, BootState, known-good/pending roots, or persistent generation without D6's release-authorized transition;
- terminate and reclaim the entire development session on completion, cancellation, timeout, compiler/run-service fault, or explicit lifecycle action; stale executable handles and backing bytes become unusable;
- preserve W^X and immutable code. Admission does not add JIT, dynamic loading, self-modifying code, or executable mappings derived from ordinary writable buffers.

### Required checks

- a component without `EXECUTABLE_ADMIT` cannot turn file, store, or shared-buffer bytes into an executable capability;
- malformed, mismatched, over-bound, hash-inconsistent, writable-executable, or changed-after-seal images fail before an executable object or task exists;
- a valid image receives exactly the selected grants, cannot inherit builder/editor/run-service authority, and cannot spawn children unless admission policy explicitly budgets and grants it;
- an infinite loop can be bounded and terminated; exit, fault, timeout, cancellation, and run-service loss remain distinct and reclaim all executable/image/task/account state;
- an unsigned admitted image runs ephemerally but select/boot/live-activation paths reject it without valid release metadata;
- an unrelated component and development session remain live when the test program or compiler faults.

### Planned verification target

The planned recipe is `dev_exec_check`.

### Exit condition

Within one QEMU boot, a user edits new-language source, compiles it on-device, admits the sealed image, and runs it under a selected minimal capability set; malformed or unauthorized code never becomes executable, and session teardown reclaims every code and authority object without changing the active generation.

## D5 — Transactional live component cutover

**Depends on:** C8 typed route/interposition services, C9 lifecycle/health/restart authority, M5.6 checked state/rollback semantics, M5.8 release authorization, and M6.5 generation management.

### Deliverables

- define versioned Zutai runtime-generation diff, compatibility classification, cutover plan, readiness, drain, commit, abort, and observation schemas; policy stays in a userspace lifecycle/update service;
- deterministically classify a signed staged generation as `live-compatible` or `reboot-required` before spawning anything. The first live class requires identical target, kernel, bootstrap, component graph, interface identities, grants, state bindings, resource budgets, and scheduling classes; only selected executable identities and explicitly admitted non-authority parameters may differ;
- treat kernel/bootstrap/ABI changes, graph or grant changes, state-schema/policy changes, interface identity changes, resource/scheduling changes, and exclusive device-authority changes as reboot-required with a structured reason, never a best-effort live attempt;
- compute the affected component closure and start replacements side-by-side with fresh endpoints, buffers, timers, mappings, device handles, supervision, and resource accounts; source components cannot retain or transfer stale authority into replacements;
- route long-lived services through C8/interposition endpoints, perform bounded readiness and in-flight drain, atomically commit route ownership, and terminate the old closure only after the new closure is healthy;
- keep the old closure and routes authoritative until commit. Any pre-commit fault/timeout/cancellation aborts the replacement and leaves unrelated components and the old service live; post-commit health failure follows a bounded reverse cutover while the old closure is retained;
- persist the new generation as ordinary pending BootState before live cutover, but do not promote it to known-good solely from a live userspace switch. The next boot still exercises immutable selector/root pending admission and health before M5.6 promotion; power loss at any live-cutover boundary boots either verified known-good or the intact pending generation, never a persisted hybrid graph;
- report booted-generation identity, live userspace-generation identity, cutover state, and pending/known-good status distinctly so an observer cannot mistake a live-qualified graph for a boot-qualified generation.

### Required checks

- a signed generation changing one compatible service executable switches requests to the new instance without rebooting while an unrelated service retains task identity and uninterrupted traffic;
- injected decode, spawn, readiness, drain, commit, old-service-exit, reverse-cutover, and update-service faults produce one bounded old-or-new routing result with no duplicated authority or persisted hybrid graph;
- stale endpoints, buffers, timers, mappings, supervision handles, and device capabilities from the old instance fail after commit and all associated resource charges are reclaimed;
- every excluded difference is classified reboot-required before replacement spawn, and removing an authority edge can never create reachability;
- unsigned or closure-invalid generations fail before BootState or runtime graph changes;
- after a successful live switch, reboot still treats the generation as pending and promotes it only through the ordinary boot health path; a failing pending boot returns to the prior known-good generation.

### Planned verification target

The planned recipe is `live_update_check`.

### Exit condition

A release-authorized generation differing only in one live-compatible component switches that service in QEMU without reboot or unrelated-task restart, preserves old service on every pre-commit failure, reverses a bounded post-commit failure, rejects every reboot-required diff before spawn, and still requires an ordinary pending boot before known-good promotion.

## D6 — On-device generation construction and authorized activation

**Depends on:** D4–D5 and completed M5/M6 generation, transfer, release, state, health, and rollback mechanisms.

### Deliverables

- run a userspace generation builder over normalized Zutai system intent and sealed component/resource objects, producing the same bounded canonical generation, closure, object identities, target binding, state policies, grants, health policy, and detached release subject as the host builder;
- expose Slisp build, inspect, test, authority-diff, stage, live-switch, next-boot select, and rollback functions through explicit service capabilities rather than global commands with ambient boot/store authority;
- keep ephemeral test and installation distinct: D4 may test an unsigned image, but D5 live switch and M6 next-boot selection require a complete M5.8-authorized release; no developer mode silently weakens immutable selector/root admission;
- make the initial local authorization workflow import valid detached release metadata for the exact generation identity. On-device private-key custody is not introduced here and may later consume A2/A4 without blocking deterministic local builds;
- select D5 only when its exact compatibility classifier accepts the generation; otherwise report reboot-required and use the ordinary pending-attempt path without mutating the running graph;
- store and transfer only content identities missing from the destination closure, preserving state policies and source/toolchain/build-provenance objects only when the generation declares them retained;
- present normalized component, object, authority, state, resource, target, and activation differences before the caller exercises the separately granted update capability.

### Required checks

- an on-device and host build from the same normalized system/object closure produce byte-identical generation bytes and identity;
- an unsigned or wrong-target/wrong-parent/stale-sequence/incomplete-closure result remains inspectable as data but cannot change BootState or the live graph;
- importing valid release metadata for the exact identity allows staging; altered metadata or any post-signing object/authority change fails before activation;
- a one-component live-compatible update uses D5, while a kernel, ABI, graph, grant, state-schema, resource, or exclusive-device change is deterministically routed to next-boot activation;
- next-boot failure consumes attempts and returns to known-good with declared state policy; live failure retains or restores the old route as D5 specifies;
- unchanged objects are not recopied, and no ungranted block device or directory is modified.

### Planned verification target

The planned recipe is `on_device_generation_check`.

### Exit condition

Inside Slime, a user builds and ephemerally tests a changed component, constructs the byte-identical canonical generation, imports authorization for that exact identity, observes its full diff, and activates it through either the proven live-compatible path or the ordinary pending-boot path; every invalid or unauthorized result remains inert data.

## D7 — Independent full-generation reproduction

**Depends on:** D6 and one D3-conforming on-device toolchain route for every language in the reference generation. The initial current-tree route uses X1 for a pinned confined Rust compiler/linker unless a native Rust toolchain independently passes the same contract; the new language continues to use its direct native image backend.

### Deliverables

- represent the complete reference system source, generated Zutai bindings, Rust and new-language toolchains, link/image producers, build parameters, kernel/bootstrap/components, resources, and generation builder as one content-addressed normalized build closure;
- execute every step under D3 build accounts with no ambient source, package index, network, clock, entropy, host filesystem, or inherited environment; an X1 toolchain personality receives only the exact project/toolchain/scratch/output capabilities;
- rebuild from a clean object-store namespace and compare every kernel, component, resource, manifest, authority view, provenance subject, and final generation identity with the host build;
- retain detached provenance sufficient to answer which source/toolchain closure produced each object and to locate all generations affected by a changed compiler or dependency digest;
- prove cache correctness by rebuilding unchanged inputs without output mutation and by changing one source/toolchain input so exactly the reachable product closure changes;
- keep compiler bootstrapping separate from this exit condition: the pinned compiler may be an input object. A future compiler-self-host gate must name its bootstrap chain explicitly rather than relabeling on-device execution as source bootstrap.

### Required checks

- two clean host builds and one clean on-device build of the same normalized closure produce byte-identical object and generation identities;
- changing one source, generated binding, compiler, linker, target, or parameter changes the expected reachable outputs and never reuses a stale cache entry;
- a missing dependency, undeclared filesystem/network/time/entropy access, resource exhaustion, compiler fault, or malformed producer output fails without publishing a partial generation;
- provenance identifies every input/output edge and rejects altered builder, dependency, parameter, or subject identity while remaining distinct from release authorization;
- an authorized reproduced generation stages and follows the same live-compatible or pending-boot classification and rollback path as a host-built generation.

### Planned verification target

The planned recipe is `self_host_check`.

### Exit condition

A clean Slime build environment reproduces the complete reference generation byte-for-byte from the same normalized mixed-language source/toolchain closure as the host, with bounded hermetic execution and verifiable provenance; the resulting generation is admitted or rejected solely by ordinary artifact, release, authority, activation, health, and rollback contracts, not by where it was built.

No D milestone claims a physical Framework development environment from QEMU evidence. Physical promotion additionally requires the owning storage, input, display, network, IOMMU, suspend/resume, and internal-write safety gates; until then on-device build/write scenarios use disposable QEMU or explicitly replaceable external storage.
