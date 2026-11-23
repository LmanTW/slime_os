# Raspberry Pi 5 ROS 2 two-node demo

## Goal

Run two local Slime-hosted ROS 2 nodes on the named Raspberry Pi 5, exchanging a
bounded typed topic through a real admitted middleware wire profile. QEMU is
required regression coverage but cannot satisfy the board claim.

## Fixed boundary

- Raspberry Pi 5 is an exact target, not generic Arm support.
- ROS concepts stay in userspace. The kernel and root gain no node, topic,
  discovery, executor, or middleware policy.
- Native fabric may carry internal delivery, but the acceptance path must include
  a real bounded middleware transport session and CDR payload mapping.
- Names, domains, types, sessions, destinations, files, devices, clocks, and
  parameters grant nothing without explicit capabilities.
- The initial profile uses static generation-declared peers, fixed endpoints and
  key expressions, one bounded message type and topic, and ROS 2
  Kilted-compatible type/name/QoS behavior for the admitted subset. Session,
  link, publisher/subscriber, sequence, and teardown bounds are fixed by the
  [format-2 demo contract](../../contracts/rpi5-ros2-demo/v2/README.md).
- Transport family is generation data: the contract uses a closed discriminator
  and one optional profile record per admitted family. Zenoh is selected;
  replacing it with DDSI-RTPS or the reverse changes the fixture, not the contract.
- The initial profile excludes arbitrary LAN discovery, Zenoh routers, gossip,
  multicast scouting, liveliness tokens, transport security, graph introspection,
  multiple middleware vendors, unrestricted LAN access, services/actions,
  unmodified desktop ROS packages, Python, dynamic plugins, package indexes,
  Gazebo, compositor support, GPU acceleration, Wi-Fi, an on-device ROS build
  toolchain, and Framework support. No component holds router, gossip, scouting,
  multicast, or discovery authority; loopback, TCP ports, and peer locators grant
  nothing implicitly.
- Storage begins on reproducible removable media, with no internal-device write
  claim. Any persistent demo state is generation-declared and rollbackable.

## Required sequence

The two-node demo release requires RP0–RP8 and the IO slices RP5 consumes. Only
a physical Raspberry Pi 5 run satisfies the board claim.

1. retain the existing demo contract and target-qualified build/admission path;
2. obtain physical serial boot evidence for the named board and required minimum
   board services;
3. prove the component data path under AArch64 QEMU and then the board;
4. implement the node/runtime envelope using clock, wait-set, lifecycle,
   parameter, private-memory, and exact network-destination authority;
5. implement the bounded transport/topic profile and two node components;
6. observe physical data transfer, then repeatability, malformed input,
   disconnect, restart, and bounded-resource behavior.

The [RP3–RP8 track](#rp3--raspberry-pi-5-serial-boot-and-minimum-board-services)
retains the detailed runtime, trace, fault, repeatability, and board acceptance;
[R0–R3](ros2-wire-compatibility.md#compatibility-layers) owns broader
ROS compatibility. Neither sequence grants unimplemented runtime support.

The network path uses the bounded TCP stream the
[network service](../architecture/network-service.md) provides. The `sel4-zenoh`
composition runs Zenoh Profile 0 over loopback TCP without a NIC under AArch64
QEMU. [`network-data-plane.md`](network-data-plane.md) owns the remaining
transport requirements. No physical Raspberry Pi 5 link is qualified.

## Physical evidence rule

The current Raspberry Pi 5 kernel, loader, and removable-media files build
reproducibly, but the board boot remains unobserved because the available UART
path produced no serial record. Milk-V Duo, Framework, and QEMU evidence cannot
substitute. A different evidence channel requires its own bounded implementation
and identity binding; documentation does not weaken the serial exit condition.

The boot path is not settled. `just rpi5_boot_check` judges UART10 after the
operator copies `build/rpi5-media/` to FAT32 removable media. The `rpi5-board`
area in `specs/rpi5-board.zt` lists removable-medium boot as a non-goal. That
area records that an rpiboot gate landed and was rolled back, and that its
requirements return with a later work item. P4 and RP3 below still specify
removable media. A human decides which boot path P4 and RP3 require.

## Later compatibility

Broader external topic interoperability, ROS services/actions, and existing ROS
workload personalities remain later plans. The minimal demo neither implies nor
requires them.

## P4 and RP3–RP8 requirements

The P4 and RP3–RP8 sections below are requirements. No Raspberry Pi 5 board
observation is recorded. A planned recipe named below does not exist yet.

## P4: Raspberry Pi 5 physical architecture qualification

**Depends on:** P5, which supplies the kernel this board runs. P2's custom-kernel AArch64 slice is superseded and is not a prerequisite.

### Why serial is the only evidence path

Recorded here because "just use HDMI" is the obvious question, and the answer is
structural rather than a missing feature.

seL4 ships exactly three driver families — `deps/sel4/src/drivers/{serial,timer,smmu}`.
There is no display, framebuffer, HDMI, storage, or network driver anywhere in
the kernel, and that is the design: everything except the mechanism needed to
*be* a microkernel lives in userspace. A grep for framebuffer or HDMI output in
`src/`/`include/` finds only x86 `boot_sys.c` and an unrelated `.dts`.

Even the serial driver is not really an exception. It exists only to implement
`printf`/`seL4_DebugPutChar` for debugging, is selected by device-tree
`compatible` string (`arm,pl011` → `pl011.c` for this board), and is compiled
out entirely in the verified configuration — `AARCH64_bcm2712_verified.cmake`
sets `KernelVerificationBuild ON`, which forces `KernelPrinting OFF`. So the
kernel's console is a debug facility that the proof configuration deliberately
removes, not a supported output device.

That leaves three ways a Pi 5 could ever show output, and only one is available
now:

1. **Debug UART** (current): `seL4_DebugPutChar` over UART10, which the board's
   own `overlay-rpi5.dts` designates through `seL4,elfloader-devices`. Needs a
   working USB-UART adapter. This is what P4 is blocked on.
2. **A userspace display driver**: real work, and much larger than it sounds on
   this SoC — the Pi 5's video output sits behind the RP1 southbridge across
   PCIe, so it needs PCIe enumeration, address translation, and HDMI/VC
   bring-up before a single pixel, all as generation-declared device authority.
   [Archived roadmap](https://git.justaslime.dev/iceice666/slime_os-history/src/commit/45ed1745907b2d0a13fdf70c8b34eb635bed5f23/roadmap/README.md) invariant 2 puts it in userspace, and
   invariant 4 requires a real gate. It is also the wrong shape for boot evidence: a framebuffer cannot
   report a fault that happens before it is mapped.
3. **JTAG/SWD** over the same 3-pin header: needs a debug probe and gives
   register state rather than a transcript, so it diagnoses a wedge but does not
   produce the ordered marker evidence P4's exit condition asks for.

[Archived roadmap](https://git.justaslime.dev/iceice666/slime_os-history/src/commit/45ed1745907b2d0a13fdf70c8b34eb635bed5f23/roadmap/README.md) invariant: framebuffer output alone is never milestone completion. That
rule already anticipated this — a display would not close P4 even if it existed.
The cheap unblock is a different USB-UART adapter.

### Deliverables

- select one exact Raspberry Pi 5 board revision or accepted revision set, firmware version, boot path, removable storage medium, interrupt topology, timer, serial path, and minimum device set;
- build the `bcm2712` upstream seL4 kernel and loader image from the existing pins and platform configuration, alongside the current `sel4/config/qemu-arm-virt.cmake`, and pin its artifact hashes the same way;
- source the board's memory map, UART, GIC, and timer facts from seL4's BootInfo and its platform configuration rather than from any Slime-side board table;
- record reproducible removable-media images, generation/release identities, firmware and board identities, normalized device tree/topology, serial evidence, storage-integrity boundaries, and every granted device capability;
- qualify DMA, storage writes, networking, sensors, and actuators only through their owning IO, demo, or hardware milestones; a CPU boot does not promote an untested peripheral or backend;
- replay the AArch64 QEMU semantic corpus on the board where physically meaningful, labeling hardware-only differences instead of hiding them;
- provide the board evidence consumed by RP3, RP4, RP7, and RP8.

### Required checks

- the named Raspberry Pi 5 runs the isolated native vertical slice from reproducible media and preserves every declared no-write or exact-device storage boundary;
- firmware changes, wrong board revisions, unsupported page/interrupt profiles, and missing required devices fail with bounded diagnostics rather than silently selecting a nearby profile;
- physical timer, interrupt, reset, serial, and storage behavior is recorded separately from inherited QEMU evidence;
- the board can run at least two isolated components and report a bounded data-path transcript before any ROS layer is claimed.

### Planned verification target

```sh
just rpi5_boot_check
```

### Exit condition

One named Raspberry Pi 5 profile runs the verified isolated Slime vertical slice with reproducible firmware/media evidence and no unqualified device or storage claim; this physical evidence is available to the RPi5 ROS 2 demo track.

## RP3 — Raspberry Pi 5 serial boot and minimum board services

**Depends on:** RP2 and P4's Raspberry Pi 5 qualification slice.

### Deliverables

- retain the existing `bcm2712` seL4 kernel/loader build route selecting
  `sel4/config/bcm2712-rpi5.cmake`, with pinned artifact digests as for
  `qemu-arm-virt`; qualify the resulting image on the named physical board;
- select and document the Raspberry Pi 5 firmware/boot handoff path, image load
  address rules, device-tree source, serial console, and removable media image
  format;
- identify the board's memory regions, reserved regions, UART, GIC, generic
  timer, and any storage or datagram path the demo uses, taking them from seL4's
  bootinfo and its platform configuration rather than re-deriving a device-tree
  parser in the root;
- bring up early serial diagnostics through the root, exception reporting via
  seL4's fault messages, timer interrupts, and an operator-visible stop behavior
  on physical hardware;
- preserve the no-ambient-storage boundary: the first board demos boot from
  reproducible removable media and do not claim unqualified writes to other
  devices;
- record board revision, firmware version, image identity, generation identity,
  serial output, and the resolved platform/device identity.

### Required checks

- wrong board revision, an unsupported page/interrupt/timer profile, or an
  incompatible firmware handoff fails with bounded diagnostics rather than a hang;
- timer interrupts and serial logging continue after the root activates the
  component graph;
- a faulting early component is reported on serial without wedging the board;
- pre/post storage evidence shows no write to any device not explicitly granted by the demo image;
- QEMU AArch64 success is cited only as inherited architecture evidence and not as physical board completion.

### Planned verification target

```sh
just rpi5_boot_check
```

### Exit condition

A named Raspberry Pi 5 boots a verified Slime generation from reproducible media, reaches the scheduler with serial diagnostics and timer/interrupt handling live, and records enough evidence to distinguish this board claim from generic AArch64 QEMU support.

## RP4 — Arm component data path on QEMU and Raspberry Pi 5

**Depends on:** RP2, RP3, C7, the C8 stream/fabric slices consumed by the transport runtime, and [CP5](../../contracts/component-sdk-release/v1/) from the Component platform track.

### Deliverables

- run two isolated AArch64 components that exchange bounded typed data through the same C7/C8 path the ROS nodes will use behind their publisher/subscriber roles;
- author and build both components entirely outside this repository through CP5's out-of-tree component SDK path, not as in-tree component crates; this requirement is scoped to RP4's two components only and does not extend to RP6's ROS 2 node components;
- exercise inline samples and, if the demo message can exceed the IPC control bound, a shared-buffer-backed sample descriptor;
- prove endpoint, buffer, mapping, loan, event, and queue accounting on Arm rather than inheriting x86-only evidence;
- record the same scenario under `aarch64-qemu-virt` and on Raspberry Pi 5, with physical traces labeled separately;
- keep this probe below the transport layer so architecture/data-path failures remain separable from transport/RMW failures.

### Required checks

- the publisher component cannot receive or re-delegate subscriber authority, and the subscriber cannot publish unless explicitly granted;
- malformed descriptors, wrong type tags, quota exhaustion, peer death, and route denial fail closed and reclaim resources;
- the Raspberry Pi 5 run observes the same semantic data-transfer records as the AArch64 QEMU run, excluding architecture-specific register and address detail;
- the board remains responsive after the exchange and emits an operator-visible completion marker;
- CP5's own required checks pass for these two components specifically: their build uses only the published/vendored SDK with no path reference into this repository's `components/` directory, and removing their out-of-tree checkout and rebuilding from in-tree fallback components still passes every other check in this list.

### Planned verification target

The planned recipe is `rpi5_data_path_check`.

### Exit condition

Before the transport and ROS layers are introduced, two isolated components — authored and built entirely outside this repository against the CP5 component SDK — exchange the demo-shaped bounded data path on AArch64 QEMU and on Raspberry Pi 5 with explicit route authority and resource reclamation.

## RP5 — Node and transport runtime envelope

**Depends on:** RP4, C10's private memory, [IO0](../architecture/io-substrate.md#queue-request-and-lease-semantics), and [IO4](network-data-plane.md). The clock/timer and executor halves are [C9.1](../architecture/runtime-authority.md#clock-and-timers) and [C9.2](../architecture/runtime-authority.md#wait-sets).

### Deliverables

- provide the minimum allocator, startup, argument/configuration, clock/timer, logging, executor/wait-set, and lifecycle hooks required by the two ROS 2 nodes and the minimal transport runtime;
- consume the exact IO4 bounded byte-stream path the transport needs — for Zenoh Profile 0, one TCP connection carrying length-prefixed batches — without granting raw packets, arbitrary DNS, listen authority, or wildcard destinations;
- package node and session configuration as deterministic generation data rather than environment variables, global paths, package indexes, or host filesystem state;
- map every needed clock, parameter, filesystem/object, graph, session, endpoint, and logging operation to an explicit capability or a stable structured denial;
- bound heap pages, executor queues, timers, log bytes, parameter bytes, transport receive queues, publisher/subscriber history, batches, retries, and outstanding messages before activation;
- keep unsupported POSIX, dynamic loading, package discovery, router or scouting-based discovery, plugin behavior, or vendor-specific ambient middleware configuration visibly unsupported rather than accidentally ambient.

There is still no async runtime anywhere in `components/`, and that remains deliberate — a transport implementation assuming `async fn` and a reactor is out of scope for RP5, while one assuming a heap is a declared quota and one assuming multi-source blocking is now a declared source table. Profile 0's blocking, fixed-buffer shape is chosen to need neither.

### Required checks

- a node can allocate, initialize, spin, publish/subscribe through the transport runtime, log, and exit within its declared resource budget;
- missing clock, route, session, endpoint, stream/network, parameter, file, or logging authority fails with a named error rather than fallback state;
- an allocation, receive queue, batch buffer, or retry beyond the declared quota leaves the node/runtime alive enough to report the failure when the selected API permits it;
- two node instances receive distinct endpoint, session, publisher/subscriber, IO request/connection epochs, and resource authority on restart and cannot reuse stale handles or completions.

### Planned verification target

The planned recipe is `rpi5_node_runtime_check`.

### Exit condition

The minimal ROS 2 node route has a bounded Slime runtime envelope sufficient for two local nodes, with no hidden dependency on ambient filesystem, environment, network, package-discovery, clock, or middleware discovery authority.

## RP6 — Minimal transport topic profile and two ROS 2 nodes

**Depends on:** RP5 and R0 from [ROS 2 compatibility](ros2-wire-compatibility.md#compatibility-layers).

### Deliverables

- define the local ROS 2 transport profile for nodes, names, topic mapping, admitted message type, QoS subset, type identity, CDR representation, session/publisher/subscriber identities, key expressions, endpoints, and static declaration;
- package the publisher node and subscriber node as target-qualified generation components with explicit startup configuration and grants;
- map their publisher/subscriber roles onto the C8 fabric and bounded stream service without giving either node ambient discovery, graph mutation, filesystem, wildcard network, or broader route authority;
- expose enough ROS 2-visible node behavior to justify calling them ROS 2 nodes under the RMW boundary, and document every unsupported ROS and transport feature outside the demo profile;
- add host or QEMU fixtures that compare ROS name mapping, key-expression composition, CDR bytes, message attachment bytes, session and declaration framing, message field values, ordering, and QoS behavior against the pinned RP0 contract.

### Required checks

- the publisher sends only the declared topic/type through its declared key expression and endpoint; the subscriber receives only through its declared key expression and endpoint;
- alternate domain, session, endpoint, topic name, type, type hash, node name, QoS, direction, or undeclared graph operation fails without exposing protected graph metadata;
- a wildcard key expression, a router endpoint, and a scouting attempt are each rejected with a named denial;
- message serialization and transport framing are deterministic and bounded;
- repeated node/runtime restart does not retain stale sessions, endpoints, loans, buffers, timers, batches, retries, or parameters;
- the same node generation boots and passes the R0 transport profile under AArch64 QEMU before being promoted to Raspberry Pi 5.

### Planned verification target

The planned recipe is `rpi5_ros2_zenoh_nodes_check`.

### Exit condition

Two target-qualified local ROS 2 node components exchange the declared bounded topic through the minimal bounded Zenoh profile with classic CDR payloads under AArch64 QEMU, with every unsupported ROS and transport feature denied explicitly.

## RP7 — Observed Raspberry Pi 5 ROS 2 data-transfer demo

**Depends on:** RP6 and RP3/RP4 physical board evidence.

### Deliverables

- build one reproducible Raspberry Pi 5 demo image containing the verified kernel, runtime services, transport runtime, publisher node, subscriber node, generation graph, stream/network grants, and demo trace sink;
- boot the image on the named board and run the middleware-backed two-node exchange without manual patching after boot;
- record serial output, semantic trace, transport wire trace records, generation/release identity, node/component identities, board/firmware/media identity, and storage/no-write evidence;
- normalize the evidence so success can be compared across repeated runs without depending on raw physical addresses, task ids, or timing jitter;
- include negative markers for wrong target, wrong route, wrong transport, wrong session/endpoint, timeout, malformed wire framing, malformed payload, denied grant, and node failure so absence of success is not silent.

### Required checks

- the publisher emits the declared number or sequence of topic samples and the subscriber observes the expected values/order within declared bounds;
- the run reaches a single operator-visible success marker only after the subscriber has validated the data and the trace includes the expected session and publisher/subscriber events;
- no component holds a capability outside the RP0 manifest contract;
- the board remains in a known state after success or failure and does not write ungranted storage;
- the captured evidence is sufficient for a reviewer to distinguish actual middleware-backed node data transfer from a boot-only, print-only, or C8-only demo.

### Planned verification target

The planned recipe is `rpi5_ros2_demo_check`.

### Exit condition

A Raspberry Pi 5 physically runs Slime OS with two local ROS 2 nodes exchanging the declared data through the minimal bounded Zenoh profile, and the repository contains reproducible evidence of the board, image, generation, capabilities, semantic/wire trace, and serial success marker.

## RP8 — Repeatability, bounds, and demo baseline hardening

**Depends on:** RP7.

### Deliverables

- repeat the physical demo across cold boots and warm restarts, recording normalized semantic/wire traces and resource high-water marks;
- inject or simulate denied route, denied endpoint, malformed batch length, malformed declaration, malformed CDR payload, malformed attachment, subscriber restart, publisher restart, queue exhaustion, retry exhaustion, timer delay, and peer-loss cases relevant to the demo profile;
- verify every endpoint, buffer, mapping, loan, timer, heap page, queue entry, fragment, retry record, writer/reader history entry, and trace record returns to its declared baseline after normal completion or restart;
- make the demo gate reproducible enough that later roadmap work can use it as a regression target;
- record the repeated observations, exact image and generation identities, evidence class, scope, and limits in the PR and canonical work item before declaring the near-term release closed.

### Required checks

- repeated runs produce the same normalized success trace and bounded resource highs;
- each injected failure has a distinct structured failure marker and does not wedge the board or corrupt unrelated state;
- supervised restart gives each node and transport session fresh authority and replays no stale samples;
- the demo remains insensitive to host environment, file paths, unrelated network state, and unrelated devices;
- every physical run records enough provenance to reproduce the image and generation.

### Planned verification target

The planned recipe is `rpi5_ros2_demo_stress_check`.

### Exit condition

The Raspberry Pi 5 two-node ROS 2 demo is repeatable, bounded, and reviewable: normal runs match their normalized trace, failure cases are distinguishable, resources are reclaimed, and the physical evidence is strong enough to become the new baseline for subsequent roadmap work.

## Owning references

- `contracts/rpi5-ros2-demo/v2/`
- `contracts/target-profile/v1/`
- [`../architecture/typed-data-fabric.md`](../architecture/typed-data-fabric.md)
- [`../architecture/runtime-authority.md`](../architecture/runtime-authority.md)
- [`../architecture/targets-and-portability.md`](../architecture/targets-and-portability.md)
- the RPi5/ROS work items under `.tasks/items/`
