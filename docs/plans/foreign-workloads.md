# Foreign workloads

This plan owns the design and acceptance requirements for two routes that run
selected Linux workloads: the X1 userspace personality and the X2 AMD-V guest.
Neither route is implemented. Current substrate boundaries are in
[architecture](../architecture/README.md), not in the proposed interfaces below.
Work-item state lives in `.tasks/items/`.

| | |
| --- | --- |
| **Purpose** | Run selected Linux workloads without changing Slime's native ABI or importing Linux's ambient authority model. |
| **Dependencies** | X1 consumes the completed M5.4 content-addressed store and M6 spawn, endpoint-minting, and userspace-filesystem machinery in [Foundations](foundations-m5-m6.md), plus the [IO4 network-service contract](network-data-plane.md) for networked workloads and P0/P1 target/artifact boundaries in [targets and portability](../architecture/targets-and-portability.md). X2 additionally consumes IO2/IO4 service contracts; as an x86-64 Framework AMD-V route it still requires H4 AMD-IOMMU containment and an observed virtualization-enablement gate. [ROS 2 compatibility](ros2-wire-compatibility.md#r3-existing-ros-workload-route) R3 may consume a route only on a target for which that route and executable closure are admitted. |

Linux compatibility remains a userspace facility. Native Slime components continue to use the capability-based Slime ABI; neither track adds Linux syscalls, FHS paths, process-global environment state, or ambient filesystem and network lookup to that ABI. A foreign workload is still one generation-declared component contract: a content-addressed image, a selected compatibility backend, bounded configuration, and an explicit grant set.

Foreign compatibility is architecture-qualified. X1's syscall-to-service semantics may be ported across admitted Slime targets, but each Linux executable, loader ABI, and personality build is validated for one exact architecture profile. X2 does not exist on AArch64 or RV64: a future hardware-virtualization route there would require a separately named milestone and target-specific containment evidence rather than reusing the AMD-V claim.

## X1: Linux userspace personality

### Deliverables

- Implement a userspace personality component that loads a selected Linux binary from a content-addressed M5.4 object. Image identity and integrity use the existing generation verification path; the personality never searches an executable path or global image registry.
- validate the Linux executable architecture, ABI, endianness, loader profile, and complete dependency closure against the generation target before mapping it; wrong-target binaries fail closed rather than entering the personality;
- Define a fixed, versioned, audited syscall-to-service table for a minimal real workload. Each admitted syscall names its Slime IPC service, required grant, argument and resource bounds, result mapping, and Linux errno when the grant or operation is unavailable. Unsupported or ungranted calls fail closed with the appropriate ordinary Linux error; they never widen the table or mint authority dynamically.
- Translate `open`, `read`, and `write` into object-store or filesystem-service transactions bounded by explicit directory or object grants. There is no implicit root, current directory, home directory, descriptor, or path-search authority.
- Translate socket operations through IO4's network service and exact `NetworkDestination` grants. Name resolution remains inside that service and does not imply arbitrary resolver, raw-packet, listen, or destination authority.
- Translate time and randomness requests through explicit clock and entropy grants. Absence of either grant is reported to the guest program rather than substituted with an ambient source.
- Map `fork` and `exec` assumptions onto the M6 spawn service. Every child receives an explicit subset of the personality's held endpoints and can never acquire more authority than its parent. Process counts, descriptors, argument and environment bytes, IPC payloads, queues, and outstanding operations are deterministically bounded.
- Treat environment entries and other startup values as bounded, immutable generation inputs, not inherited host state. Undeclared variables are absent; they cannot convey paths, credentials, endpoints, or other hidden authority.
- Declare the image, personality version, syscall profile, startup data, resource bounds, and complete service-grant set in the generation. The resulting authority is auditable, diffable, and rollbackable like that of every native component.

### Required checks

- A declared container reads and writes only the files covered by its directory or object grants; attempts outside those grants fail with the mapped Linux error and do not issue an unauthorized service operation.
- It reaches only its declared network destinations. Undeclared names, addresses, ports, transports, listen rights, and raw network access are denied with a normal Linux error.
- Every unsupported syscall and every syscall lacking its required filesystem, network, clock, entropy, spawn, or other service grant fails with its specified errno rather than escalating or discovering ambient state.
- A spawned child holds no grant absent from its explicit child grant set and no authority exceeding the parent.
- Changing host filesystem state, process environment, working directory, or network configuration cannot add authority to an unchanged generation.
- The manifest exposes the container's image identity, compatibility profile, bounded startup data, and complete grant set, and the existing authority-diff path reports changes to any of them.
- replaying X1 on AArch64 or RV64 uses the same syscall/service/grant semantics but separately proves that target's loader, executable closure, signal/register translation if admitted, and error mapping;

**Exit condition:** A Linux binary declared as a container in the generation runs under the personality, confined to its declared directory, network, time, randomness, process, and other service grants; everything else is denied with a normal Linux errno, and its complete authority is visible and diffable in the manifest.

### Remaining personality design questions

The fixed, versioned syscall subset and content-addressed image are selected
above; they are no longer alternatives to best-effort coverage or path lookup.
Size that subset against a minimal real workload, such as a static
busybox-class binary, with each syscall's service, required grant, and absent-grant
errno tabulated. Coverage determines when a workload needs X2 instead.

Still decide whether filesystem authority is a directory into the shared store
or a private writable state binding, and how its quota composes with the
[resource-account proposal](../directions/25-resource-accounts.md). Also
choose the first admitted process shape (one process or a bounded tree) and the
exact `fork`/`exec` translation within the explicit-subset spawn rule above.
Clock and randomness mapping consumes [D3's explicit clock/entropy authority](native-development.md#deterministic-component-authority).

The [archived direction 31](https://git.justaslime.dev/iceice666/slime_os-history/src/commit/45ed1745907b2d0a13fdf70c8b34eb635bed5f23/docs/directions/31-compat-personality.md)
preserves the personality-first/VM-later design origin; neither route becomes
implemented by extracting it here.

## X2: Isolated AMD-V guest VM

X2 MUST NOT begin hardware-backed guest execution until H4 IOMMU containment and AMD-V enablement have been observed on the target.

**Kernel prerequisite:** seL4 has no AMD SVM support. x86 virtualization is `KernelVTX`, which is Intel VMX, VMCS, and EPT only, in both the pinned fork (`fea36b2`) and upstream master (`0f10829`, 2026-09-22). No public SVM port was found. X2 therefore first needs an AMD SVM kernel extension (VMCB, nested paging, VM-exit handling) carried outside every verified configuration. It also needs a Slime-written VMM, since rust-sel4 has no x86 VMM and any existing seL4 x86 VMM can only build on `KernelVTX`, plus H4's AMD IOMMU containment, which the kernel also lacks ([AMD IOMMU ownership](../decisions/amd-iommu-ownership.md)). Without interrupt remapping, passing a physical device such as the GPU to a guest stays out of scope.

**Architecture boundary:** X2 applies only to the x86-64 Framework/AMD-V profile. It is not a generic `X2` release dependency for AArch64 or RV64.

X2 reuses X1's generation-level foreign-workload contract rather than creating another authority model. The backend choice may change fidelity and cost, but never the workload's grants.

### Deliverables

- Add a bounded hypervisor route for a full Linux guest under AMD-V, with explicit guest-memory ownership, nested-page mappings, virtual-CPU and VM-exit bounds, and fail-closed handling of unsupported virtualization features. Do not claim Framework AMD-V support until firmware/CPU availability and the enablement path are physically observed.
- Present only a fixed audited virtio subset backed by Slime userspace services. Virtual block and network devices consume IO2 `BlockDevice` and IO4 network capabilities; clock, entropy, console, and every other admitted endpoint likewise require the corresponding generation grant. Absent devices are not discoverable as usable authority.
- Bind virtual block devices to named content-addressed image/state objects and virtual network devices to the declared IO4 rights and `NetworkDestination` grants. The guest receives no host filesystem, host environment, raw device, or unrestricted network access.
- Keep every physical DMA-capable backend behind H4's active AMD-IOMMU domain before bus mastering. Guest memory and virtio buffers use only IO1-bounded mappings required for the current operation, and mappings are invalidated before reuse.
- Declare the guest image, VM/backend version, bounded virtual hardware configuration, resource limits, and complete virtio/service grant set in the generation, using the same audit, diff, verification, and rollback paths as X1.

### Required checks

- Deterministic QEMU checks exercise the VM state machine, bounds, malformed descriptors, denied and absent virtio devices, and service-error mapping; a QEMU pass is architecture evidence only and does not satisfy the physical AMD-V or IOMMU gate.
- On the named Framework target, AMD-V enablement is observed before a guest starts, and attempted startup fails closed when virtualization is unavailable or unsupported.
- No DMA-capable backend starts bus mastering before its H4 domain is active; malformed or out-of-range guest descriptors cannot address guest memory outside the declared mapping or any unrelated host memory.
- The guest can access only the content-addressed disks, declared destinations, time, entropy, console, and other virtio-backed services present in its generation grant set. Removing a grant removes the corresponding usable authority without exposing a host fallback.
- Host paths, working directory, process environment, network configuration, and undeclared devices cannot affect the authority of an unchanged guest generation.
- The manifest and authority diff expose the same complete workload grant contract whether its selected backend is X1 or X2.

**Exit condition:** After the physical AMD-V and H4 IOMMU gates pass, a generation-declared Linux guest runs under AMD-V with bounded guest memory and an audited virtio surface; it can use only its declared service-backed devices and destinations, all physical DMA remains IOMMU-contained, and its complete authority is visible and diffable in the manifest. QEMU verification alone cannot complete X2.

### Remaining guest design questions

Choose the initial audited virtio device subset and whether guest memory is
charged to the spawner's resource account; bounded VM memory alone does not
settle account ownership. Workloads requiring custom kernels or syscalls outside
X1's translation profile motivate this route. The device-model design remains
paper work until the X2 and H4 physical-enablement prerequisites permit execution.

## ROS 2 relationship

[R3](ros2-wire-compatibility.md#r3-existing-ros-workload-route) may run an existing ROS workload through X1 when its required Linux syscall profile is supported on the exact generation target, or through X2 only on the admitted x86-64 AMD-V profile when it needs a full guest kernel. In either case, its image, filesystem, network, discovery, time, randomness, process, device, and other authority remain generation-declared explicit grants.

R1 and R2 do not depend on X1, X2, Linux, or existing ROS binaries. They establish ROS 2 topic, service, and action interoperability as userspace protocol profiles over native Slime contracts; existing ROS binaries become a requirement only for R3's existing-workload checks.
