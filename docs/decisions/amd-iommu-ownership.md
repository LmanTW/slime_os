# AMD IOMMU ownership on x86-64

**Status:** Proposed
**Related work items:** `01a0e3c4-3a96-7031-9a7a-67b31343e52a`,
`01a0724c-5400-70c8-9990-21edd1694e5f` (H4),
`01a0724c-5400-75d8-b84d-a0695ac0e37a` (X2),
`01a0724c-5400-77c5-ac41-9997b462ad22` (H13)

## Context

H4 requires one AMD-IOMMU domain per DMA-capable driver on the Framework 13
before bus mastering. X2 requires the same containment for every physical
backend of an AMD-V guest. The kernel provides neither.

This comes from reading the pinned fork (`sel4/pins.toml`, `fea36b2`, 16.0.0)
and upstream `seL4/seL4` master at `0f10829` (2026-09-22):

- `KernelIOMMU` is described as "IOMMU support for VT-d enabled chipset". Its
  only driver is `src/plat/pc99/machine/intel-vtd.c`, which is discovered through
  the ACPI DMAR table. No code parses IVRS or programs an AMD-Vi device table,
  command buffer, or event log. An AMD machine has no DMAR, so
  `acpi_dmar_scan` reports zero IOMMUs and the kernel runs with no DMA
  translation.
- `KernelIOMMU` depends on `NOT KernelVerificationBuild`. Even the VT-d path is
  outside every verified configuration.
- Upstream `CAVEATS.md` states that the kernel has no interrupt remapping, so a
  device cannot safely be passed through to an untrusted guest.
- x86 virtualization is `KernelVTX`: Intel VMX, VMCS, and EPT only. The pinned
  QEMU and Framework profile sets it off (`sel4/config/qemu-pc99.cmake`).
  AMD SVM has no kernel support; that gap belongs to X2, not to this record.

IO1 DMA mappings are already root-mediated: a driver asks `slime-root` for a
mapping (`slime-root/src/io_resource.rs`, `create_dma_mapping` and
`destroy_dma_mapping`). The driver never holds a kernel IOSpace capability. Every
Framework DMA-capable device therefore runs uncontained today, which is why
`docs/plans/framework-hardware.md` restricts physical DMA work to disposable
probes.

## Proposed decision

`slime-root` programs the AMD IOMMU directly as a platform device. The kernel is
not extended.

- The root parses IVRS with strict bounds, maps the IOMMU MMIO registers from a
  device untyped, and allocates the device table, per-domain I/O page tables,
  command buffer, and event log from memory it never grants or reuses while
  they are live.
- Every device starts in a blocking domain. An IO1 DMA mapping becomes an entry
  in its driver's domain, and `destroy_dma_mapping`, driver restart, and epoch
  change invalidate and complete (`COMPLETION_WAIT`) before the root reclaims
  or reuses the frames.
- Bus mastering for a device is enabled only after its domain is active, as H4
  already requires.
- Event-log faults are reported through the driver's supervision handle with
  device identity and bounded address detail.

This keeps DMA containment where IO1 already keeps DMA authority. It adds no
kernel object types, and it introduces no second capability model beside
`io_resource.rs`.

## Alternatives and trade-offs

- **Extend the kernel with AMD-Vi IOSpace support**, mirroring `intel-vtd.c` and
  `src/arch/x86/object/iospace.c` (about 540 and 510 lines upstream). DMA
  mappings would become kernel capabilities, with revocation through capability
  derivation, and the same object model would serve both vendors. The costs:
  Slime would carry a substantive, unverified kernel feature in its fork rather
  than the current boot-only patches. Upstream interest in x86 maintenance is
  low (seL4 issue #1108), so the fork would likely stay private. The mapping
  capabilities would also duplicate what `io_resource.rs` already mediates.
- **Configure the IOMMU once before seL4 starts**, a route upstream
  master's `CAVEATS.md` mentions for static systems; the pinned fork's copy
  predates that text. Rejected: IO1 mappings, leases,
  restarts, and epochs are dynamic, and a boot-time table cannot follow them.
- **Run drivers without an IOMMU.** Rejected: it contradicts H4 and the
  Framework plan's containment invariant.

## Consequences

- The root's IOMMU code becomes part of the trusted base in the same way as the
  root allocator. Its correctness is Slime's, with no kernel proof behind it.
  The kernel never touches the IOMMU, so there is no ownership conflict.
- The IOMMU register frame and translation memory must never be reachable
  through any grant. The declared inventory must refuse a composition that would
  expose them.
- Interrupt remapping is unsolved by this decision. The kernel still owns MSI
  and IOAPIC routing without remapping. That keeps device passthrough to an
  untrusted guest (an X2 driver domain or a GPU passthrough) blocked, and a
  later decision must reconcile the IOMMU interrupt remapping table with the
  kernel's IRQ path.
- A device that firmware left bus-mastering, such as the GPU scanning out the GOP
  framebuffer, can lose its DMA the moment a blocking domain activates. This is
  an inference, not an observation: activation must either map the framebuffer
  for that device or leave it untranslated until H13 owns it. H1 inventory
  evidence decides which devices this affects.
- Nothing here depends on AMD SVM. X2 still needs its own kernel work.

## Revisit conditions

Revisit if upstream seL4, or a maintained fork the project is willing to pin,
gains AMD-Vi IOSpace support. Revisit if interrupt remapping turns out to need
kernel changes large enough that owning the whole IOMMU in the kernel is
cheaper. Revisit if a verified x86-64 configuration including an IOMMU becomes a
release requirement.

## References

- `sel4/pins.toml`, `sel4/config/qemu-pc99.cmake`
- `deps/sel4/src/arch/x86/config.cmake` (`KernelIOMMU`, `KernelVTX`)
- `deps/sel4/src/plat/pc99/machine/intel-vtd.c`,
  `deps/sel4/src/plat/pc99/machine/acpi.c`, `deps/sel4/CAVEATS.md`
- `slime-root/src/io_resource.rs`
- [`../plans/framework-hardware.md`](../plans/framework-hardware.md)
- [`../architecture/io-substrate.md`](../architecture/io-substrate.md)
- [H4](../plans/framework-hardware.md#h4-amd-iommu-containment-and-framework-usb-hid-promotion)
  and [X2](../plans/foreign-workloads.md#x2-isolated-amd-v-guest-vm)
