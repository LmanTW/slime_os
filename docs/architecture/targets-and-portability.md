# Architecture and target profiles

## Portable contract versus platform mechanism

Portable semantics include capability kinds and rights, channels, generation
selection, rollback, component and protocol schemas, shared buffers, fabric
routes, wait-set behavior, lifecycle policy, I/O queue/epoch/lease rules, and
semantic block/link/network services.

Platform mechanism includes register frames, page tables, interrupt controllers,
timers, idle and QEMU-exit paths, firmware handoff, device-tree or ACPI parsing,
MMIO addresses, PCI functions and BARs, interrupt routes, IOMMU identifiers, and
early boot mappings. These facts stay in the platform profile and owning source;
they do not enter a portable service ABI.

One logical syscall operation has one semantic contract and error model, but each
architecture has an explicit calling convention. Architecture ports preserve
observable capability, fault, wait/wake, reclamation, generation, and rollback
semantics; they need not have byte-identical register or page-table evidence.

Architecture-neutral resource objects may be shared across targets only when
their schemas and identity bytes are byte-identical; executable-object
portability is never assumed.

The implementation uses small explicit architecture modules rather than a broad
trait framework for isolated call sites, with device and scheduling policy kept
out of the kernel.

## Admitted profiles

`contracts/target-profile/v1/schema.zt` declares nine profiles. Three are
retired custom-kernel QEMU identities retained to classify old artifacts:
`x86_64-qemu-virtio`, `aarch64-qemu-virt`, and `riscv64-qemu-virt`.
`aarch64-rpi5` also retains its custom-kernel ABI declaration, although the
seL4 builder selects that name for the Raspberry Pi 5 platform. Do not read
that build route as a newly admitted seL4 ABI or observed board execution.
The five explicitly seL4-qualified identities are:

| Profile | Current role |
| --- | --- |
| `aarch64-sel4-qemu-virt` | primary automated product and complete plane corpus |
| `riscv64-sel4-qemu-virt` | RV64 QEMU architecture reference |
| `riscv64-sel4-milkv-duo` | qualified named Milk-V Duo physical architecture/product path |
| `x86_64-sel4-qemu-pc99` | x86-64 QEMU pc99 product reference |
| `x86_64-sel4-framework13-ai300` | exact named Framework removable-media CPU/product-boot profile |

The build platform table in `scripts/build/build-sel4.py` selects the three QEMU
platforms, the Raspberry Pi 5 build platform, the Milk-V Duo platform, and the
Framework profile over the pc99 kernel inputs. A profile identifies a complete
architecture/ABI/page-feature/platform contract, not just an ISA.

Exact construction inputs belong to [`sel4/pins.toml`](../../sel4/pins.toml),
[`sel4/config/`](../../sel4/config/), [`sel4/targets/`](../../sel4/targets/), and
the [build platform table](../../scripts/build/build-sel4.py), not archived
milestone measurements. Wrong architecture, ABI, page/ISA feature, firmware,
interrupt profile, or executable/kernel pairing must fail before execution.
The [pc99 configuration](../../sel4/config/qemu-pc99.cmake) explicitly sets
`KernelFSGSBase "inst"`, requiring boot-time `CR4.FSGSBASE` for userspace
`rdfsbase`, and owns its pinned proof-profile divergences; the boot pins bind
the shared GRUB Multiboot2 tree and OVMF inputs.

For Duo construction, the `[cv1800b_duo]` pins and pinned seL4/rust-sel4 forks
own DRAM/reservation placement, the PLIC S-mode layout, and C906 MAEE page-table
encoding. Requalification must account for the entire kernel, loader, root,
generation, boot structures, and initial objects within the admitted memory
window, without silently shrinking the product contract. The
[physical gate](../../scripts/check/check-duo-sel4.py) requires evidence that
MAEE-encoded loader mappings become active and RTC/PLIC interrupts arrive both
before and after graph activation, alongside bounded fault, identity, and recovery
evidence. PLIC S-mode layout must be qualified against SoC documentation and
C906 memory-attribute state established before trusting page tables; neither
generic Sv39 nor QEMU establishes those board facts.

## Automated and physical evidence

`aarch64-sel4-qemu-virt` is the default development target. The cross-target
corpus also exercises RV64 QEMU and selected x86-64 pc99 paths. QEMU establishes
deterministic behavior for its exact image and profile only.
The selected x86-64 corpus covers the resident product, root-boot, wait-set,
sample, and boot-layout paths, not generation, rollback, or capability-layout
plane replay. Those omissions are not passing results.

The named Milk-V Duo has retained physical evidence for its upstream-seL4
architecture and product path. The Raspberry Pi 5 kernel, loader, and media build
path exists, but no board boot was observed; its gate fails closed without serial
evidence.

Raspberry Pi construction uses `sel4/config/bcm2712-rpi5.cmake`, the
`bcm2712_rpi5`/`observed_prefix_bcm2712_rpi5` pins, and a separate platform
prefix, target directories, generation, image and identity manifest. The pinned
loader supplies a PL011 UART10 console selected by seL4's `overlay-rpi5.dts`.
`scripts/build/build-rpi5-media.py` constructs `kernel8.img`/`config.txt` by
flattening PT_LOAD segments at physical addresses: section-only `objcopy`
output omits the loader payload and is not a valid replacement.

The board image deliberately enables printing outside the verified kernel
configuration: upstream `AARCH64_bcm2712_verified.cmake` enables
`KernelVerificationBuild`, which forces `KernelPrinting` off and removes the
serial debug facility needed for this qualification. It is not a verified-profile
boot claim. The platform exposes 1019 MiB because upstream supplies no RPi5
overlay above the VideoCore base. Memory, GIC-400/GICv2, the 54 MHz generic timer
and UART10 at `0x107d001000` come from seL4's platform description and BootInfo,
not a Slime-side board table. The physical gate binds media to the built image
and fails closed without serial evidence; it never substitutes QEMU. P4's
[serial rationale](../plans/rpi5-ros2-demo.md#why-serial-is-the-only-evidence-path)
explains why display output or a debugger cannot replace its ordered transcript.

The named Framework 13 cold-booted the exact P6 removable image twice on
2026-09-13 and rendered the resident readiness record through the firmware
framebuffer without internal-storage write authority. That observation qualifies
the CPU/product boot path only, for the image identified in the retained record.
The [observation contract](../../contracts/cpu-boot-observation/v1/schema.zt) and
[gate](../../scripts/check/check-framework-cpu-boot.py) bind the exact medium,
generation, machine, firmware, USB device, and protected internal-NVMe comparison
region, so any change to the root, the product composition, or the pinned kernel
unbinds the record until an operator repeats the
[runbook](../operations/framework-cpu-boot-runbook.md) on the rebuilt image;
neither QEMU nor re-stamping the record can. Whether the gate currently passes
or refuses is a fact about the working tree, reported by
`just framework_cpu_boot_check`, not a fact this page records. No device
inventory, NVMe, USB, input, network, display, audio, suspend, IOMMU, or
daily-driver claim follows.

## Target-specific non-equivalence

- AArch64 and RISC-V mappings can express execute-never for component data.
  x86-64 seL4's mapping attributes expose no NX bit, so data-page W^X is
  currently unenforced there.
  [`vm_attributes.rs`](../../slime-root/src/vm_attributes.rs) owns the mapping
  distinction: the x86 execute probe is absent, not vacuously passing, and its
  evidence is `wx_execute=unenforced probes=1`, versus `refused probes=2` on
  AArch64 and RISC-V.
- AArch64 QEMU exposes EL0 physical counter/timer registers globally because the
  root uses that timer path; clock service authority does not make those raw
  registers inaccessible to hostile native code.
- QEMU DMA is trusted. Physical containment requires the exact platform's
  IOMMU/SMMU evidence.
- A CPU boot qualifies no device. Evidence from one physical target completes
  no other target's gate.

## Safety boundary

Physical development boots from removable media and must not write internal
NVMe. Internal storage promotion waits for target-specific identity, bounds,
DMA containment, timeout/reset, flush ordering, interruption, malformed metadata,
rollback, and recovery evidence. Destructive work belongs on an approved external
device.
The CPU-boot medium has no writable product/state partition, requires no input,
and grants no PCI bus mastering or internal-storage read/write authority.
Its guarded removable-media writer requires full read-back verification.

Current unimplemented target qualifications live in
[`../plans/framework-hardware.md`](../plans/framework-hardware.md) and
[`../plans/rpi5-ros2-demo.md`](../plans/rpi5-ros2-demo.md).

## Verification

- `just sel4_pin_check`
- `just x86_64_sel4_image_check`
- `just x86_64_sel4_root_boot_check`
- `just x86_64_qemu_check`
- `just framework_media_check`
- `just framework_cpu_boot_check` — judges the retained observation against the
  current image; refuses, never manufactures, when the image has moved
- the Milk-V Duo and Raspberry Pi 5 targets in `just/hardware.just`
