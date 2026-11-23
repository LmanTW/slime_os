# One target profile may claim the verified kernel configuration

**Status:** Accepted
**Decided by:** the project's human owner, 2026-11-17
**Related work item:** `root-size-budget`, UUID
`01a1e925-f21f-7c7b-8c45-b6b46bcefd1e`
**Related decisions:** [`ambient-clock-reads.md`](ambient-clock-reads.md),
[`mcs-cpu-budgets.md`](mcs-cpu-budgets.md)

## Context

The seL4 proofs hold for the configurations under
`deps/sel4/configs/*_verified.cmake`. `deps/sel4/CAVEATS.md` states that the
proofs break if a configuration parameter changes.

| Target profile | seL4 platform | On the verified platform list | Differences today |
|---|---|---|---|
| `bcm2712-rpi5` | `bcm2712` | yes | 5 options |
| `qemu-pc99`, also the Framework 13 | `pc99` | yes | see below |
| `qemu-arm-virt` | `qemu-arm-virt` | no | not applicable |
| `qemu-riscv-virt` | `qemu-riscv-virt` | no | not applicable |
| `cv1800b-duo` | `cv1800b` | no | not applicable |

`sel4/config/bcm2712-rpi5.cmake` includes `AARCH64_bcm2712_verified.cmake` and
then changes five options: `KernelVerificationBuild`, `KernelDebugBuild`,
`KernelPrinting`, `KernelArmExportPCNTUser` and `KernelArmExportPTMRUser`. The
first three give the board a serial transcript through `seL4_DebugPutChar`.
The last two let the root program `CNTP_*` from EL0 and let a component read
`CNTPCT_EL0`.

`sel4/config/qemu-pc99.cmake` includes `X64_verified.cmake` and differs in more
than options. It sets the same three printing options. It sets
`KernelMaxNumBootinfoUntypedCaps` to 230 against 50 and
`KernelRootCNodeSizeBits` to 12 against 19. It turns `KernelSupportPCID` off.
It selects a linear framebuffer mode, which needs the fork's change to
`src/arch/x86/multiboot.S`.

The kernel pin is a fork of seL4 16.0.0. `sel4/pins.toml` records that its
changes are in RISC-V, the `cv1800b` platform and `src/arch/x86/multiboot.S`.

## Decision

1. No target profile claims the verified kernel configuration today.
2. One new target profile, `bcm2712-rpi5-verified`, may claim it.
   `bcm2712-rpi5` stays as the debug profile and claims nothing.
3. The claim holds for one image when three gates pass:
   - The CMake file of the profile holds one line, the include of
     `AARCH64_bcm2712_verified.cmake`.
   - The preprocessed kernel source, `kernel_all_pp.c`, equals the one that
     upstream seL4 16.0.0 produces under the same configuration.
   - An operator boots the image on the named board, and the signed record
     names the profile.
4. The claim has one wording. The kernel in this image is built from the C
   source and the configuration that the seL4 proofs for AArch64 with
   hypervisor extensions cover. Those proofs are functional correctness and
   integrity.
5. The claim covers nothing else. It does not cover confidentiality or
   non-interference, machine code, the compiler, the linker, boot code, cache
   or TLB management, the kernel loader, `rust-sel4`, `slime-root`, any
   component, firmware or hardware.
6. `qemu-arm-virt` may use the same option values. It claims nothing, because
   its platform is not on the list.
7. `qemu-pc99`, `qemu-riscv-virt` and `cv1800b-duo` claim nothing.
8. The verified profile has two prerequisites:
   - The root writes its diagnostics to a UART it owns, not through
     `seL4_DebugPutChar`.
   - No EL0 code reads or writes a generic-timer register. The root programs
     a device timer. A component reads time from a read-only mapping of that
     timer's counter page.
9. The kernel stays non-MCS and single-core on this profile. The realtime goal
   of the project is soft realtime, so neither limit blocks it.

## Alternatives

- **Change `bcm2712-rpi5` in place.** Development then loses kernel fault
  messages on the board.
- **Keep the counter readable from EL0 and remove only the timer export.** The
  configuration is still not the verified one, and seL4 documents the counter
  export as a timing channel.
- **Serve every clock read from the root.** `ambient-clock-reads.md` records
  the cost: one plane spent 0.75 s of root time on 23453 reads under QEMU TCG.
- **Re-run the proofs for a changed `pc99` configuration.** That is an l4v
  project, not a configuration edit.

## Consequences

- The repository builds and pins two Pi 5 kernels. `sel4/pins.toml` and
  `scripts/check/check-sel4-pins.py` change with a V4 approval.
- `specs/rpi5-board.zt` lists the verified kernel configuration as a non-goal.
  That entry changes with an approval.
- The verified kernel prints nothing. The root must report a component fault
  itself. A fault of the root leaves no output unless a later design adds one.
- QEMU `virt` has no memory-mapped timer. Only an operator run on the board
  exercises the device-timer path.
- A component's clock has a resolution of 1 µs on the verified profile. The
  54 MHz generic timer gives about 18.5 ns.
- A read-only mapping of the counter page also shows the comparator registers
  of that timer. A component can read them and cannot write them.
- `ambient-clock-reads.md` needs an amendment for this profile when the timer
  change lands. Its revisit condition names this case.
- `docs/architecture/targets-and-portability.md`, `trust-model.md` and
  `runtime-authority.md` state the claim when the profile lands.

## Revisit when

- The seL4 pin moves. The owner then checks the platform list and the
  configuration again.
- The fork changes a file that an AArch64 build compiles. The claim lapses
  until upstream has the change.
- The BCM2835 system timer at `timer@7c003000` does not work on the board.
  Prerequisite 8 then needs another time source. PR 1118 added the root's
  backend for that timer behind `--system-timer`; no observation on the board
  exists yet.
- The AArch64 MCS proofs are complete.
