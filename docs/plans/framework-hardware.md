# Framework hardware qualification

## Goal and boundary

Qualify the named Framework Laptop 13's actual firmware and devices after the
upstream-seL4 CPU/product boot. The existing removable-media observation proves
only that the resident product graph reached readiness without internal-storage
write authority. It proves no device support.

Work-item identity, dependencies, state, and per-slice exit conditions remain in
`.tasks/items/`. This plan owns the stable delivery and qualification boundary.

## Required sequence

1. **Inventory:** produce a bounded, versioned physical report for ACPI tables,
   MCFG functions, BARs, interrupt routes, framebuffer, IOMMU presence, NVMe
   identity, and input-controller stages; preserve the internal-NVMe comparison
   region and fail closed without a fresh exact-image observation.
2. **PCI binding:** project validated platform facts into exact IO1 device, MMIO,
   IRQ, and DMA capabilities without ambient enumeration or portable-ABI leakage.
3. **USB/input logic:** implement xHCI, USB core, HID, and a transport-neutral seat
   service under deterministic checks before physical DMA promotion.
4. **DMA containment:** establish one AMD-IOMMU domain per driver, map only live
   IO0 leases, report faults, and enable bus mastering only after containment.
   seL4 supports only Intel VT-d, so this is new Slime mechanism rather than
   kernel configuration; the [AMD IOMMU ownership](../decisions/amd-iommu-ownership.md)
   decision (proposed) places it in `slime-root`.
5. **Device services:** qualify disposable USB storage and Ethernet before
   internal NVMe, then display/compositor, platform power, suspend/resume,
   touchpad, audio, Wi-Fi, Bluetooth, and Radeon paths through typed services.
6. **Integrated promotion:** observe the complete target under removable-media
   recovery and no unauthorized internal-storage modification.

## Invariants

- PCI identities, ACPI routes, BARs, APIC vectors, IOMMU aliases, and firmware
  methods remain exact Framework profile data.
- Drivers hold hardware authority; ordinary clients hold semantic service
  capabilities only.
- Before IOMMU qualification, DMA-capable physical work is restricted to
  approved disposable/read-only probes and makes no containment claim.
- Restart and rollback create fresh resource bindings and IO0 epochs; stale
  MMIO, IRQ, DMA, and completions are refused and reclaimed.
- Internal NVMe writes remain disabled until identity, bounds, reset/timeout,
  flush ordering, interrupted writes, malformed metadata, rollback, recovery,
  and containment are observed on disposable hardware first.
- QEMU and other boards validate portable mechanism only. Every Framework device
  promotion needs physical evidence for the exact image and generation.

## Completion boundary

The daily-driver release requires H1–H14 plus the common IO slices each H
milestone consumes; M5.7 separately gates the storage-aware boot. No P6, Duo,
QEMU, or CPU-only evidence satisfies a Framework device gate.

The Hardware track is complete only when all of the following are observed on
the named Framework and backed by deterministic IO and device checks. Evidence
from Milk-V Duo, Raspberry Pi 5, or QEMU validates portable mechanisms only:

- every DMA-capable physical driver consumes IO1 resources bound by H2 and runs
  in an H4 AMD-IOMMU domain mapping only live IO0 leases, with fault isolation
  and supervised restart;
- built-in or attached keyboard, touchpad, pointer, display, audio, USB storage,
  USB Ethernet, Wi-Fi, and Bluetooth are usable through typed services;
- applications receive input, display surfaces, audio streams, files, and IO4
  network destinations only through explicit capabilities; the manifest shows
  which component can reach each device or remote endpoint;
- internal NVMe writes pass the [M5.7](foundations-m5-m6.md#m57--framework-nvme-transport-and-safety-promotion), IO2,
  and H7 bounds, reset, flush, interruption, malformed-metadata, device-identity,
  rollback, and recovery gates on disposable hardware before target promotion;
- compositor and Radeon survive client faults, stale completions, driver reset,
  and suspend/resume with a software-rendered fallback;
- battery, charger, brightness, lid, and thermal state are observable, controls
  explicitly authorized, and policy owned by userspace;
- repeated suspend/resume quiesces and restores storage, IOMMU, USB, input,
  display, network, wireless, and audio with fresh mappings/epochs and no
  BootState corruption;
- per-component resource and energy accounting is visible and bounded without
  silently introducing [C9 scheduling authority](../architecture/runtime-authority.md)
  or [A1 revocation](authority-and-trust.md#revocation-and-leases);
- a busy-looping background component is throttled past its generation-declared
  energy budget, with accounting readable per component;
- an interactive foreground component keeps its declared latency while a
  background container saturates every CPU; the container cannot claim ungranted
  foreground scheduling share, and each component's class is visible in the
  manifest. This requires physical qualification; QEMU ordering evidence cannot
  close it;
- integrated physical qualification has no unauthorized internal-storage
  modification or unbounded resource growth, and retains a bootable signed
  removable recovery path.

Every permanent hardware change requires its narrow deterministic device/service
scenario and applicable IO gate. Physical promotion additionally requires an
exact-image removable-media Framework run. Detailed H1–H14 acceptance, including
the integrated session and suspend-cycle thresholds, is in
[slice acceptance](#slice-acceptance). Partial CPU boot,
framebuffer output, or one driver cannot satisfy completion.

## Current first step

The next qualification surface is the evidence-backed hardware inventory. The
historical CPU boot remains observed; whenever the rebuilt image no longer
matches the retained record, an operator boot per the
[runbook](../operations/framework-cpu-boot-runbook.md) is required to rebind
it. Documentation cannot re-stamp the record.

## Slice acceptance

Each slice states its deliverables, required checks, and exit condition.
These slices are requirements. They grant no device support.
A planned verification target names a `just` recipe that does not exist yet.

### H1: Framework evidence harness and hardware inventory

Deliverables:

- extend the P6.6 identity/readiness output into one bounded, versioned hardware report over GOP and every actually available debug channel, without requiring keyboard input: ACPI table identities and checksums, MCFG functions, validated BARs, interrupt routes, framebuffer geometry, IOMMU-table presence, NVMe identity, and every input-controller initialization stage; do not assume a Framework COM1 exists because QEMU used one;
- add an append-only host-side evidence record containing image identity, machine identity, firmware version, report output, and pre/post hashes for every storage device whose immutability is being asserted;
- keep the report free of raw memory, firmware secrets, storage payloads, and unbounded descriptor dumps;
- preserve the removable-image no-internal-write rule and provide a non-interactive timeout or shutdown path so a failed input driver cannot strand the test.

Required checks:

- malformed ACPI, PCI, BAR, interrupt, and descriptor fixtures fail with a typed bounded error rather than a hang;
- two boots on unchanged firmware produce the same normalized topology report, excluding explicitly named volatile fields;
- the Framework report identifies whether the keyboard path is i8042, USB HID, or another firmware-described controller and records the exact initialization failure;
- the internal NVMe comparison region remains byte-identical across the inventory boot.

Exit condition: the repository contains reproducible evidence for the target Framework's actual controller topology and localizes the current keyboard path to a named initialization stage while preserving the no-internal-write boundary.

### H2: Framework PCI binding for userspace drivers

Deliverables:

- project H1's validated PCI functions, BAR ranges, interrupt routes, and device identities into bounded Framework profile resources that IO1 can construct without ambient PCI enumeration;
- bind one granted PCI function to its exact MMIO subranges, APIC interrupt source, DMA account, shared-data endpoints, and supervision handle; deny undeclared functions and resources before mapping or binding;
- keep PCI BDFs, BAR attributes, ACPI routes, APIC vectors, and later AMD-IOMMU aliases in the Framework profile while exposing only IO1's architecture-neutral resource capabilities to driver code;
- define the Framework trusted-DMA bring-up profile explicitly: before H4, only deterministic QEMU fixtures or read-only physical probes on approved disposable paths may enable DMA-capable drivers, and no such run claims containment;
- integrate driver restart and generation rollback with the Framework profile so every new instance receives freshly constructed resources and a fresh IO0 epoch, never stale MMIO, IRQ, or DMA authority;
- remove the six ungated device-right exceptions from the capability matrix as the corresponding IO1/H2 gates land; device protocols remain schema-first and userspace-owned.

Required checks:

- a driver granted one Framework PCI function cannot enumerate or map another function, BAR, interrupt route, or DMA account;
- malformed or conflicting MCFG/ACPI/PCI/BAR/interrupt profile data fails before any mapping, interrupt binding, or bus mastering;
- exact BAR offsets, mapping lengths, access modes, interrupt acknowledgements, and DMA/account bounds are validated by IO1 and cannot be widened by Framework profile data;
- restart, rollback, and wrong-profile admission revoke the old bindings, return every charge, create a fresh epoch, and leave hardware authority unavailable when the retained generation lacks the new resource classes;
- the P1/P6 source-boundary guard rejects new x86 privileged mechanisms outside admitted architecture/platform files, while H2 tests may exercise the Framework PCI profile explicitly;
- ordinary service clients see only typed semantic capabilities and never PCI identities, MMIO mappings, APIC vectors, DMA addresses, or global device enumeration.

Planned verification target: `framework_driver_binding_check`.

Exit condition: one manifest-declared Framework userspace driver is bound to exactly one validated PCI function and its IO1 MMIO/DMA/interrupt resources, restart/rollback fails closed with fresh authority, and no Framework identifier leaks into the portable I/O ABI.

### H3: xHCI, USB core, and HID under QEMU

This slice implements the Framework xHCI/USB/HID stack over IO0/IO1 and the H2 PCI binding before physical DMA promotion. It proves the device-specific logic and transport-independent seat service under deterministic checks; it does not yet claim safe Framework xHCI operation.

Deliverables:

- implement a userspace xHCI driver over IO0 request/completion, lease, epoch, and cancellation rules plus H2-bound IO1 resources, with bounded command, event, and transfer rings and explicit controller reset/timeout handling;
- implement root-hub and bounded hub enumeration, descriptor validation, address/configuration selection, endpoint lifecycle, disconnect cancellation, and per-device incarnation identities so reconnect cannot satisfy an old transfer;
- implement USB HID keyboard and pointer boot protocols, key rollover bounds, press/release events, and hotplug;
- route i8042 and USB HID through one versioned seat/input service so Slisp and later compositor clients do not depend on the physical transport;
- keep xHCI commands, descriptors, endpoint policy, and HID semantics out of IO0/IO1 and `slime-root`, and keep physical xHCI bus mastering disabled until H4 supplies an IOMMU domain.

Required checks:

- malformed, cyclic, oversized, short, or inconsistent USB descriptors are rejected before ring or buffer allocation;
- transfer timeout, controller reset, endpoint stall, surprise removal, and event-ring overflow leave no pinned buffer or permanently wedged input service;
- one client holding seat input authority receives events while an ungranted component cannot read or inject them;
- scripted QEMU keyboard input drives the native Slisp REPL through the same seat protocol used by physical HID;
- repeated attach/detach remains within fixed device, endpoint, transfer, and queue bounds.

Planned verification target: `usb_hid_check`.

Exit condition: QEMU xHCI keyboard and pointer input survive malformed devices, hotplug, timeout, and reset through a transport-independent input service.

### H4: AMD IOMMU containment and Framework USB HID promotion

**Kernel boundary:** seL4 has no AMD IOMMU support. `KernelIOMMU` drives Intel VT-d only, found through ACPI DMAR, in both the pinned fork (`fea36b2`) and upstream master (`0f10829`, 2026-09-22). On the Framework it finds no IOMMU, and DMA is untranslated. Where AMD-Vi programming lives is the open [AMD IOMMU ownership](../decisions/amd-iommu-ownership.md) decision, not a kernel configuration choice. Interrupt remapping is absent under either option.

Deliverables:

- parse the target's ACPI IVRS data with strict bounds and identify the AMD IOMMU and device aliases from H1 evidence;
- create one IOMMU domain per DMA-capable driver, map only its live IO1 DMA mappings for IO0 buffer leases with the requested direction, invalidate translations before reuse, and enable PCI bus mastering only after the domain is active;
- report IOMMU faults with device identity, access type, and bounded address detail; quarantine the offending driver and complete its supervision handle with a distinct failure;
- boot the Framework xHCI driver inside an enforced domain and bring up the actual built-in or attached USB keyboard identified by H1;
- retain an emergency removable image that does not enable bus mastering and can reproduce the inventory report if IOMMU setup fails.

Required checks:

- a synthetic driver DMA outside its mapped region faults and cannot modify the guard region or another component's memory;
- stale translations are unusable after buffer release, driver restart, device reset, and generation transition;
- unsupported or malformed IVRS data fails closed before bus mastering;
- IOMMU fault storms are bounded and cannot livelock the kernel or suppress unrelated device interrupts;
- on the Framework, the keyboard can type a Slisp capability-bearing system-information call, receive its structured success result, use Backspace and Shift punctuation, and close with Escape while internal NVMe comparison hashes remain unchanged;

Planned verification targets: `iommu_check` and `usb_hid_check`.

Exit condition: the Framework has observable keyboard input through the common seat service, and xHCI DMA is confined to generation-declared buffers by the AMD IOMMU.

### H5: USB mass storage and removable-device identity

Deliverables:

- implement one standards-based USB mass-storage transport proven by the target test device, with bounded command/data/status phases, sense decoding, timeout, reset, surprise-removal handling, and IO0 terminal request/lease behavior;
- expose USB media through [IO2's `BlockDevice` contract](io-substrate-qualification.md#io2--userspace-virtio-blk-and-asynchronous-blockdevice-plane) so filesystem, object-store, recovery, and generation services receive no USB-specific authority;
- identify media by USB topology plus validated device identity and render an operator-visible distinction between removable test media and the internal NVMe;
- require an exact `BlockDevice` capability for all reads and writes; default Framework generations grant removable media read-only and grant writes only to an explicitly selected disposable device;
- make removal during an outstanding write settle the IO0 request, release its lease/DMA mapping, return a structured block error, and preserve the last committed filesystem/object-store root.

Required checks:

- malformed capacity, short transfer, failed sense, timeout, reset, and unplug paths release every DMA mapping and return a structured block error;
- a writable grant for one USB disk cannot address a second USB disk or internal NVMe;
- removing media at every tested commit boundary preserves the previous committed root;
- repeated enumerate/read/write/flush/remove cycles stay within fixed resource bounds;
- a Framework run writes and verifies a disposable external device while pre/post internal-NVMe hashes remain identical.

Planned verification target: `usb_storage_check`.

Exit condition: Slime OS has a capability-selected disposable physical storage target suitable for destructive reliability work without granting internal NVMe write authority.

### H6: Framework USB Ethernet qualification

H6 consumes [IO3's `LinkDevice`](io-substrate-qualification.md#io3--userspace-virtio-net-and-linkdevice-validation), [IO4's network service and exact destination authority](network-data-plane.md), H1's observed USB descriptors, H3's USB bus, and H4 containment. IO4—not H6—owns the link/IP/DNS/UDP/TCP protocols, `NetworkDestination`, socket/resource bounds, and deterministic virtio-net reference backend. H6 qualifies one Framework USB-Ethernet backend and its physical failure envelope.

Deliverables:

- select one USB-Ethernet class/device from H1 evidence and implement its bounded USB transport as an IO3 `LinkDevice` backend without changing IO4's client ABI;
- run the backend inside the H4 AMD-IOMMU domain, with IO0 request/lease epochs across unplug, USB reset, driver crash, and re-enumeration;
- obtain link state and DHCP/SLAAC configuration through IO4, then reach only exact generation-declared destinations; the driver receives no DNS, socket, or ROS policy;
- record Framework link identity, address assignment, allowed endpoint, unplug/replug behavior, driver restart, IOMMU state, and storage-integrity evidence;
- after R1/R2 deterministic conformance passes, run a dedicated wired Framework ↔ 64-bit Raspberry Pi 4/5 peer fixture with the same pinned upstream probes, packet capture, link/peer restart behavior, and Framework storage-integrity evidence; this proves the Pi only as an external peer, not as a Slime-supported board.

Required checks:

- malformed descriptors/frames, short transfers, RX exhaustion, TX saturation, unplug, USB reset, and driver crash stay within IO0/IO3 bounds and return every DMA/lease charge;
- replacing or moving the USB adapter changes its declared device identity and cannot silently inherit the old backend authority;
- the Framework obtains a lease/address, reaches one IO4-declared endpoint, and emits no packet to a simultaneous denied endpoint;
- unplug/replug and supervised restart create fresh device/link epochs, reject stale completions/connections, and restore only the destinations still declared by the generation;
- the USB-Ethernet driver cannot resolve names, open sockets, listen, or access raw packets outside the `LinkDevice` operations it serves;
- pre/post internal-NVMe comparison evidence remains identical throughout the physical run.

Planned verification target: `framework_usb_ethernet_check`.

Exit condition: the Framework reaches one exact IO4 destination through a physically observed, H4-contained USB-Ethernet `LinkDevice` that survives unplug and supervised restart without widening network authority or modifying internal storage.

### H7: Native NVMe reliability and internal-storage promotion

Internal NVMe writes remain prohibited until this slice's physical evidence is recorded.

Deliverables:

- implement the target NVMe transport over IO0 request/lease/completion semantics, H2-bound IO1 resources, H4's IOMMU domain, and IO2's common `BlockDevice` contract;
- add bounded interrupt-driven read, write, flush, timeout, abort/reset, and reinitialization paths for the exact target controller and namespace;
- exercise destructive native-NVMe tests only with a dedicated replaceable NVMe installed for testing; the personal internal device is absent during those tests;
- validate flush ordering, forced reset, abrupt power loss, torn metadata, malformed GPT/object-store/generation/BootState records, and recovery across the M5 commit boundaries;
- introduce a separately named internal-storage promotion profile requiring the exact controller/namespace identity and an explicit operator-visible arming step; ordinary Framework and recovery images remain unable to write it;
- record pre/post full metadata-region hashes and rollback/recovery results before promoting any internal write grant.

Required checks:

- IOMMU containment, queue bounds, LBA bounds, timeout/reset, flush ordering, interrupted writes, and malformed metadata pass under QEMU fault injection and on the sacrificial physical NVMe;
- reset or power loss at every recorded commit boundary leaves a bootable known-good generation or signed removable recovery path;
- a wrong controller, namespace identity, capacity, firmware-reported block size, or missing operator arm fails before the first write command;
- the internal-storage profile grants BLOCK_WRITE and BOOT_UPDATE only to the declared storage/generation service and cannot be selected by an unprivileged component;
- the first write-enabled run on the target Framework is observed separately and preserves the retained known-good and recovery roots.

Planned verification target: `storage_reliability_check`.

Exit condition: internal NVMe writes are enabled only after deterministic and physical reliability evidence, IOMMU confinement, exact device identity, and rollbackable recovery are all observed.

### H8: Software compositor and desktop shell over GOP

Deliverables:

- move visible output from the global debug stream to a userspace compositor holding the sole framebuffer capability; retain serial as diagnostics rather than the interactive UI path;
- declare versioned surface, damage, presentation, seat-focus, clipboard, and dialog protocols; clients render only into IO0-bounded shared-buffer leases and cannot map the physical framebuffer;
- implement software composition, double buffering, damage tracking, cursor rendering, focus, keyboard/pointer routing, and a terminal surface hosting the native Slisp session;
- render the M6 powerbox as a compositor-owned modal dialog while preserving its user-gesture capability mint and IO0 cancellation semantics;
- make display dimensions, pixel format, surface count, buffer bytes, damage rectangles, and event queues explicit bounds; display semantics remain H8-specific rather than generic I/O opcodes.

Required checks:

- an ungranted client cannot read input, capture another surface, map the framebuffer, steal focus, or bypass a powerbox dialog;
- malformed dimensions, overflowed strides, out-of-bounds damage, stalled clients, and compositor restart cannot write outside granted buffers;
- deterministic scene fixtures produce byte-identical software-composited frame hashes under QEMU;
- Slisp remains usable while another client faults or floods damage/events within its quota;
- on the Framework, terminal text, pointer movement, focus changes, and powerbox selection are visible and survive a compositor restart.

Planned verification target: `compositor_check`.

Exit condition: the Framework has an isolated, capability-routed graphical session over GOP without granting applications ambient framebuffer or input access.

### H9: Battery, charger, brightness, lid, and thermal service

Deliverables:

- consume H1 ACPI/EC evidence through a bounded target-specific ACPI resource evaluator; unsupported AML constructs fail closed rather than growing an implicit general interpreter;
- expose versioned battery charge/rate/health, AC/charger state, lid state, thermal readings/trips, and panel brightness through a userspace platform service;
- keep mechanism in the kernel and policy in userspace: a generation-declared power-policy component decides brightness and thermal responses through explicit control endpoints;
- distinguish read-only telemetry from control authority in the capability matrix and give ordinary applications neither EC register access nor charger/thermal control;
- emit bounded state-change events and provenance for user brightness changes and thermal emergency actions.

Required checks:

- malformed AML/resource data, EC timeout, implausible sensor values, event storms, and missing methods produce typed degraded states without hangs;
- a telemetry-only client cannot change brightness, charger behavior, thermal policy, reset, shutdown, or sleep state;
- brightness remains within firmware-advertised bounds and a thermal emergency cannot be masked by an unprivileged component;
- QEMU fixtures cover AC attach/detach, charge/discharge, lid transitions, and thermal thresholds;
- Framework readings agree with firmware-visible state and brightness/lid events are observed without storage modification.

Planned verification target: `platform_service_check`.

Exit condition: the Framework reports and controls its basic power state through explicit service capabilities while platform policy remains outside the kernel.

### H10: Suspend/resume lifecycle and device reinitialization

The target sleep state is selected from H1 firmware evidence; the slice does not claim both S3 and modern standby when the machine exposes only one supported route.

Deliverables:

- define a checked suspend state machine covering request, service quiesce, storage flush, device stop, IOMMU teardown, platform entry, resume, IOMMU restore, device reinitialization, and userspace thaw;
- require explicit acknowledgements from storage, compositor, input, network, audio, and generation services before entering sleep; timeout aborts suspend and leaves the system running;
- restore monotonic time, interrupt routing, xHCI, network, NVMe, display, and later audio/wireless devices without reusing stale DMA mappings or capabilities;
- preserve pending-generation attempt semantics across sleep and never treat resume as a fresh successful boot or health confirmation;
- expose lid-close and user-request policy in userspace, with an emergency kernel path only for thermal safety.

Required checks:

- failure or timeout at every quiesce/resume stage either aborts to a working session or enters signed recovery on next boot; it never silently advances BootState;
- no device can DMA while its IOMMU domain is torn down, and all post-resume DMA buffers are freshly mapped;
- network reconnect, USB re-enumeration, input, compositor, storage, and audio recover without duplicating capabilities or leaking bounded resources;
- QEMU fault injection covers every transition edge and repeated cycles;
- the Framework completes at least 50 lid/user suspend-resume cycles, including cycles with active network and audio, without data corruption or loss of Slisp control;

Planned verification target: `suspend_check`.

Exit condition: the Framework repeatedly suspends and resumes through a checked, rollback-safe lifecycle with all active device services re-confined and usable.

### H11: I2C touchpad and audio service

Touchpad and audio are independent implementations and may proceed in parallel after their H2/H9 bus and resource descriptions and the applicable IO0/IO1 contracts are available.

Touchpad deliverables and checks:

- implement the Framework's firmware-described I2C controller and HID-over-I2C touchpad path with bounded reports, interrupt handling, IO0 epochs/cancellation, reset, and resume;
- route pointer contacts through the common seat service; gesture recognition, acceleration, palm rejection, and tap policy live in userspace;
- reject malformed descriptors/reports and prove an ungranted component cannot read raw contacts or inject pointer events;
- physically verify pointer movement, click, two-finger scroll, palm rejection, hot reset, and resume.

Audio deliverables and checks:

- select the HDA or ACP route from observed hardware/codec evidence rather than implementing an unused backend by assumption;
- declare a versioned PCM service with bounded shared rings, playback/capture stream capabilities, volume/mute control, device routing, underrun/overrun reporting, and resume; reuse IO0 queue/lease/Notification mechanics without treating PCM periods as generic device opcodes;
- give the mixer sole hardware authority through H2-bound IO1 resources; clients cannot map audio DMA or read microphone samples without an explicit capture grant;
- verify deterministic virtual-backend mixing, client fault isolation, bounded latency, underrun recovery, speaker/headphone output, microphone capture, mute indication, and repeated suspend/resume on the Framework.

Planned verification targets: `touchpad_check` and `audio_check`.

Exit condition: the Framework has daily-usable touchpad input and capability-isolated playback/capture through services that survive reset and suspend.

### H12: MT7925 Wi-Fi and Bluetooth

Deliverables:

- package required device firmware as content-addressed, release-authorized generation objects; drivers never search a global firmware path;
- implement the MT7925/RZ717 Wi-Fi path inside an H4 IOMMU domain and attach it as another IO3 `LinkDevice` backend to the IO4 network service;
- support scan, association, WPA2/WPA3 personal authentication, reconnect, regulatory constraints, and suspend/resume with bounded stations, frames, retries, and key material lifetime;
- accept Wi-Fi credentials through an explicit interactive service and keep them scoped to the network service; [A2](authority-and-trust.md#secrets-as-capabilities) generalizes non-readable and revocable secrets rather than being bypassed here;
- implement the combo device's observed Bluetooth transport, bounded HCI, pairing state, and the HID and audio profiles required for keyboard/pointer and headset use through the existing input/audio services.

Required checks:

- malformed firmware, frames, scan results, association responses, HCI events, pairing messages, and retry storms remain bounded and fail closed;
- Wi-Fi traffic remains subject to the same `NetworkDestination` grants as Ethernet; switching links does not widen reachable destinations;
- ungranted components cannot read credentials, link keys, raw wireless frames, Bluetooth HID events, or microphone audio;
- disconnect, radio reset, driver restart, and suspend/resume clear transient keys and reconnect without stale DMA mappings;
- on the Framework, Wi-Fi reaches one declared destination and Bluetooth keyboard/pointer plus headset audio work after repeated reconnect and resume cycles.

Planned verification targets: `wifi_check` and `bluetooth_check`.

Exit condition: the Framework has capability-preserving wireless networking and the Bluetooth input/audio paths needed for daily use.

### H13: Radeon display control and graphics acceleration

Deliverables:

- package Radeon firmware as release-authorized generation objects and run the display driver with H2-bound PCI/interrupt authority, IO1 DMA mappings, and H4 IOMMU containment;
- take over the internal panel from GOP, set its validated native mode, page-flip compositor buffers, control the hardware cursor, recover from display/GPU faults, and restore the panel after suspend;
- accelerate compositor-owned copy, fill, scaling, and composition operations while retaining the H8 software renderer as the correctness oracle and fallback; reuse IO0 queue/lease/completion mechanics where appropriate without making GPU commands generic;
- keep command submission private to the compositor/display service in the Hardware track; general application or compute queues and accelerator authority remain [A3](authority-and-trust.md#accelerator-compute-authority) scope;
- integrate panel brightness and thermal limits with H9 without moving policy into the driver.

Required checks:

- command buffers, relocations, dimensions, pitches, addresses, and synchronization waits are validated before submission and remain within IOMMU-mapped compositor buffers;
- a faulting or timed-out queue resets to the software compositor without exposing stale frames or wedging input;
- accelerated output matches the software renderer's deterministic frame hashes for the supported operations;
- applications cannot submit GPU commands, map scanout buffers they do not own, or bypass compositor focus/powerbox rules;
- the Framework internal panel runs at its validated native mode, remains stable during interactive use, and recovers through repeated suspend/resume and forced driver reset.

Planned verification target: `radeon_display_check`.

Exit condition: the Framework compositor owns a stable, IOMMU-contained Radeon display path with verified software fallback and no general ambient GPU authority.

### H14: Energy accounting and integrated daily-driver qualification

Deliverables:

- attribute scheduler-active time and bounded service work (IPC, storage, network, audio, and graphics bytes/events) to components and supervision subtrees;
- combine those counters with H9 battery/platform telemetry into readable per-component energy estimates and declare their schema in the generation;
- keep Hardware-track accounting as telemetry and threshold events, not hidden scheduler authority; [A1 revocation](authority-and-trust.md#revocation-and-leases) and [C9 scheduling-class authority](../architecture/runtime-authority.md) arrive explicitly in their owning tracks;
- provide an operator-visible hardware status and authority view covering current generation, device drivers, IOMMU domains/faults, storage identity, network destinations, power state, and per-component resource/energy use;
- define and record one reproducible Framework qualification run covering interactive console/compositor use, wired and wireless networking, external removable storage, internal rollbackable storage, audio, touchpad, Bluetooth, display acceleration, suspend/resume, and recovery media.

Required checks:

- accounting totals are monotonic within the declared window, bounded, attributable, and cannot be reset or forged by the measured component;
- shared-service charging rules are fixed and tested so repeated forwarding cannot create or erase usage;
- an eight-hour Framework session with concurrent interactive, network, audio, storage, and background load retains input/display responsiveness and shows no unbounded task, capability, DMA, queue, or buffer growth;
- the qualification run includes at least 50 suspend/resume cycles, repeated USB and network hotplug, forced driver restarts, a failed pending generation, and signed recovery without unauthorized storage writes;
- every physical test records image/generation identity, firmware version, hardware identities, authority manifest, observed output, and storage-integrity evidence.

Planned verification target: `daily_driver_check`.

Exit condition: the Framework target sustains the complete native daily-driver workload with explicit hardware and network authority, IOMMU-contained DMA, rollbackable storage, observable power/resource use, and repeatable physical evidence.

## Owning references

- [`../architecture/targets-and-portability.md`](../architecture/targets-and-portability.md)
- [`../architecture/io-substrate.md`](../architecture/io-substrate.md)
- `evidence/framework-cpu-boot/`
- `scripts/check/check-framework-cpu-boot.py`
- the Framework-tagged work items under `.tasks/items/`
